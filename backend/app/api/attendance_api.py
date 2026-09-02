"""Attendance certificates, calendar invites and the board pack (P6)."""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import attendance, audit, models, pdf
from ..audit import client_ip
from ..database import get_db
from ..engine import reporting
from ..membership import require_member
from ..security import get_current_user, require_evaluator, require_staff, scope_or_404
from ..throttle import throttle
from .certificates import VERIFY_MAX_PER_WINDOW, _existing

router = APIRouter(tags=["attendance"])


def _base(request: Request) -> str:
    return f"{request.base_url.scheme}://{request.base_url.netloc}"


def _cert_or_409(db: Session, s: models.Session) -> models.Certificate:
    cert = _existing(db, s.id)
    if cert is None:
        raise HTTPException(409, "issue the exercise certificate first")
    return cert


def _bk(db: Session, org_id: int) -> dict:
    from .. import branding  # L2
    b = branding.pdf_args(db, org_id)
    return {"brand": b["brand"], "accent": b["accent"], "footer": b["footer"]}


def _pdf(content: bytes, filename: str) -> Response:
    return Response(content=content, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@router.get("/api/sessions/{session_id}/attendance")
def list_attendance(session_id: int, user: models.User = Depends(require_staff), db: Session = Depends(get_db)):
    s = scope_or_404(db.get(models.Session, session_id), user)
    cert = _cert_or_409(db, s)
    rows = db.execute(select(models.SessionJoin).where(models.SessionJoin.session_id == s.id)
                      .order_by(models.SessionJoin.joined_at)).scalars().all()
    return {"session_id": s.id, "serial": cert.serial, "hours": attendance.hours(s),
            "attendees": [attendance.record(db, s, cert, j) for j in rows]}


@router.get("/api/sessions/{session_id}/attendance/{join_id}.pdf")
def attendance_pdf(session_id: int, join_id: int, request: Request,
                   user: models.User = Depends(require_evaluator), db: Session = Depends(get_db)):
    s = scope_or_404(db.get(models.Session, session_id), user)
    cert = _cert_or_409(db, s)
    join = db.get(models.SessionJoin, join_id)
    if join is None or join.session_id != s.id:
        raise HTTPException(404, "no such participant")
    rec = attendance.record(db, s, cert, join)
    audit.record(db, "attendance.export", request=request, user=user,
                 detail={"session_id": s.id, "join_id": join.id})
    return _pdf(attendance.render_attendance_pdf(rec, **_bk(db, s.org_id), verify_path=f"{_base(request)}/verify.html?serial={cert.serial}&attendee={rec['attendee_code']}"),
                f"attendance-{rec['attendee_code']}.pdf")


@router.get("/api/sessions/{session_id}/my-attendance.pdf")
def my_attendance_pdf(session_id: int, request: Request,
                      user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    """A participant's own certificate (staff who joined by code get theirs too)."""
    s = scope_or_404(db.get(models.Session, session_id), user)
    cert = _cert_or_409(db, s)
    join = db.execute(select(models.SessionJoin).where(models.SessionJoin.session_id == s.id,
                                                       models.SessionJoin.user_id == user.id)).scalars().first()
    if join is None:
        raise HTTPException(404, "you did not join this exercise by code")
    rec = attendance.record(db, s, cert, join)
    audit.record(db, "attendance.export", request=request, user=user, detail={"session_id": s.id, "join_id": join.id, "self": True})
    return _pdf(attendance.render_attendance_pdf(rec, **_bk(db, s.org_id), verify_path=f"{_base(request)}/verify.html?serial={cert.serial}&attendee={rec['attendee_code']}"),
                f"attendance-{rec['attendee_code']}.pdf")


@router.get("/api/certificates/{serial}/attendance/{code}")
def verify_attendee(serial: str, code: str, request: Request, db: Session = Depends(get_db)):
    """Public: does this attendee code belong to this exercise certificate? Throttled."""
    key = f"cert|{client_ip(request)}"
    if throttle.retry_after(key) > 0:
        raise HTTPException(429, "too many verification requests; try again later")
    throttle.record_failure(key, limit=VERIFY_MAX_PER_WINDOW)
    serial = serial.strip().upper()[:32]
    cert = db.execute(select(models.Certificate).where(models.Certificate.serial == serial)).scalars().first()
    if cert is None or cert.revoked_at is not None:
        return {"valid": False, "reason": "no live certificate with this serial", "record": {}}
    s = db.get(models.Session, cert.session_id)
    rec = attendance.verify_attendee(db, s, cert, code)
    if rec is None:
        return {"valid": False, "reason": "no attendee with this code on this exercise", "record": {}}
    return {"valid": True, "reason": "ok", "record": attendance.public_record(rec)}


@router.get("/api/sessions/{session_id}/board-pack.pdf")
def board_pack(session_id: int, request: Request,
               user: models.User = Depends(require_evaluator), db: Session = Depends(get_db)):
    s = scope_or_404(db.get(models.Session, session_id), user)
    cert = _cert_or_409(db, s)
    scenario = db.get(models.Scenario, s.scenario_id)
    env = db.get(models.Environment, scenario.environment_id)
    _, md = reporting.build_report(s, scenario, env, list(s.events), list(s.observations), "executive")
    verify_path = f"{_base(request)}/verify.html?serial={cert.serial}"
    audit.record(db, "boardpack.export", request=request, user=user, detail={"session_id": s.id, "serial": cert.serial})
    return _pdf(pdf.render(f"Board pack — {s.name}", attendance.board_pack_markdown(cert, md, verify_path), **_bk(db, s.org_id)),
                f"board-pack-{cert.serial}.pdf")


@router.get("/api/schedules/{schedule_id}/invite.ics")
def schedule_ics(schedule_id: int, user: models.User = Depends(require_staff), db: Session = Depends(get_db),
                 hours: float = 2.0):
    sch = scope_or_404(db.get(models.ExerciseSchedule, schedule_id), user)
    scenario = db.get(models.Scenario, sch.scenario_id)
    body = attendance.ics(uid=f"schedule-{sch.id}@gauntlet", title=f"Exercise: {sch.name}", start=sch.next_run_at, hours_=hours,
                          description=f"Facilitated cyber exercise ({scenario.name if scenario else ''}). Join by code on the day.")
    return Response(content=body, media_type="text/calendar",
                    headers={"Content-Disposition": f'attachment; filename="exercise-{sch.id}.ics"'})


@router.get("/api/sessions/{session_id}/invite.ics")
def session_ics(session_id: int, start: str, request: Request, user: models.User = Depends(require_staff),
                db: Session = Depends(get_db), hours: float = 2.0, location: str = ""):
    """A calendar file for a planned session: pass the start time (ISO 8601)."""
    s = scope_or_404(db.get(models.Session, session_id), user)
    try:
        start_dt = datetime.fromisoformat(start.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(422, "start must be an ISO 8601 datetime")
    desc = f"Facilitated cyber exercise: {s.name}. Join by code at {_base(request)}/join.html" + (f" — code {s.join_code}" if s.join_code else "")
    body = attendance.ics(uid=f"session-{s.id}@gauntlet", title=f"Exercise: {s.name}", start=start_dt, hours_=hours,
                          description=desc, location=location)
    return Response(content=body, media_type="text/calendar",
                    headers={"Content-Disposition": f'attachment; filename="exercise-{s.id}.ics"'})
