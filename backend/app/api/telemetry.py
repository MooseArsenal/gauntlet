"""Telemetry loop (M4): record what the tools actually saw, compare with the ruling."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .. import audit, intake, models, schemas, telemetry, ws
from ..database import get_db
from ..entitlements import require_feature
from ..security import require_evaluator, scope_or_404
from ..timeline import append_event

router = APIRouter(prefix="/api/sessions", tags=["telemetry"])

MAX_ALERTS_PER_IMPORT = 2000


def _session(db: Session, session_id: int, user: models.User) -> models.Session:
    s = scope_or_404(db.get(models.Session, session_id), user)
    if s.status == "setup":
        raise HTTPException(409, "start the exercise before recording telemetry")
    return s


def _record(db: Session, s: models.Session, alert: dict, user: models.User) -> models.TimelineEvent:
    payload = {
        "alert": alert.get("alert", "")[:300],
        "techniques": list(alert.get("techniques") or []),
        "asset": (alert.get("asset") or "")[:120],
        "source": (alert.get("source") or "manual")[:40],
        "severity": (alert.get("severity") or "")[:20],
        "observed_at": (alert.get("observed_at") or "")[:40],
        "external_ref": (alert.get("external_ref") or "")[:120],
        "note": (alert.get("note") or "")[:2000],
        "recorded_by": user.email,
    }
    return append_event(db, s.id, kind="telemetry", ref=s.current_inject_code or "", payload=payload)


@router.post("/{session_id}/telemetry", response_model=schemas.TimelineEventOut, status_code=201)
def record_alert(session_id: int, payload: schemas.TelemetryIn, request: Request,
                 user: models.User = Depends(require_evaluator), db: Session = Depends(get_db),
                 _feature: models.User = Depends(require_feature("telemetry_loop"))):
    """Record one real alert (from the SOC's tools, or by hand) on the timeline."""
    s = _session(db, session_id, user)
    ev = _record(db, s, payload.model_dump(), user)
    audit.record(db, "telemetry.record", request=request, user=user,
                 detail={"session_id": s.id, "seq": ev.seq}, commit=False)
    db.commit()
    db.refresh(ev)
    ws.manager.notify(s.id)
    return ev


@router.post("/{session_id}/telemetry/import", response_model=schemas.TelemetryImportOut, status_code=201)
def import_alerts(session_id: int, payload: schemas.TelemetryImportIn, request: Request,
                  user: models.User = Depends(require_evaluator), db: Session = Depends(get_db),
                 _feature: models.User = Depends(require_feature("telemetry_loop"))):
    """Import a SIEM/EDR alert export (JSON or CSV) for this exercise."""
    s = _session(db, session_id, user)
    try:
        rows = intake.parse(payload.format, payload.data)
    except intake.IntakeError as e:
        raise HTTPException(422, str(e))
    if len(rows) > MAX_ALERTS_PER_IMPORT:
        raise HTTPException(413, f"at most {MAX_ALERTS_PER_IMPORT} alerts per import")
    alerts = telemetry.map_alerts(rows)
    n = 0
    for a in alerts:
        _record(db, s, a, user)
        n += 1
    audit.record(db, "telemetry.import", request=request, user=user,
                 detail={"session_id": s.id, "alerts": n, "rows": len(rows)}, commit=False)
    db.commit()
    ws.manager.notify(s.id)
    return schemas.TelemetryImportOut(recorded=n, skipped=len(rows) - n)


@router.get("/{session_id}/telemetry", response_model=list[schemas.TimelineEventOut])
def list_alerts(session_id: int, user: models.User = Depends(require_evaluator), db: Session = Depends(get_db)):
    s = scope_or_404(db.get(models.Session, session_id), user)
    return [schemas.TimelineEventOut.model_validate(e) for e in telemetry.alerts_of(s)]


@router.get("/{session_id}/telemetry/compare", response_model=schemas.TelemetryCompareOut)
def compare(session_id: int, user: models.User = Depends(require_evaluator), db: Session = Depends(get_db)):
    """Expected (adjudicated) versus observed (recorded) detections, per action and per technique."""
    s = scope_or_404(db.get(models.Session, session_id), user)
    return telemetry.compare(s)
