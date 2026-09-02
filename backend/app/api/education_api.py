"""Education edition endpoints (L4). Gated by the ``education`` feature."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import audit, education, entitlements, models, schemas
from ..audit import client_ip
from ..database import get_db
from ..security import (
    create_token, get_current_user, hash_password, issue_refresh_token, password_problems, require_facilitator,
    scope_or_404,
)
from ..throttle import throttle

router = APIRouter(prefix="/api/cohorts", tags=["education"])
_gate = entitlements.require_feature("education")
ENROL_MAX_PER_WINDOW = 40


def _cohort(db: Session, cohort_id: int, user: models.User) -> models.Cohort:
    c = scope_or_404(db.get(models.Cohort, cohort_id), user)
    if c.archived_at is not None:
        raise HTTPException(404, "that cohort is archived")
    return c


def _out(db: Session, c: models.Cohort) -> dict:
    n = db.execute(select(func.count(models.CohortMember.id)).where(models.CohortMember.cohort_id == c.id)).scalar() or 0
    runs = education.sessions(db, c)
    return {"id": c.id, "name": c.name, "code": c.code, "anonymous": c.anonymous, "open": c.open,
            "instructor_user_id": c.instructor_user_id, "students": n, "created_at": c.created_at,
            "sessions": [{"id": s.id, "name": s.name, "status": s.status, "scenario_id": s.scenario_id} for s in runs]}


@router.get("")
def list_cohorts(user: models.User = Depends(require_facilitator), db: Session = Depends(get_db), _f=Depends(_gate)):
    rows = db.execute(select(models.Cohort).where(
        models.Cohort.org_id == user.org_id, models.Cohort.archived_at.is_(None)).order_by(models.Cohort.id.desc())).scalars().all()
    return [_out(db, c) for c in rows]


@router.post("", status_code=201)
def create_cohort(payload: schemas.CohortIn, request: Request, user: models.User = Depends(require_facilitator),
                  db: Session = Depends(get_db), _f=Depends(_gate)):
    c = education.create(db, user, payload.name, payload.anonymous)
    audit.record(db, "cohort.create", request=request, user=user, detail={"cohort": c.name}, commit=False)
    db.commit()
    return _out(db, c)


@router.get("/mine")
def my_cohorts(user: models.User = Depends(get_current_user), db: Session = Depends(get_db), _f=Depends(_gate)):
    """A student's own cohorts and their own rows — never a classmate's."""
    return education.my_view(db, user)


@router.post("/join")
def join_cohort(payload: schemas.CohortJoinIn, user: models.User = Depends(get_current_user),
                db: Session = Depends(get_db), _f=Depends(_gate)):
    """An existing member joins a cohort by its code."""
    c = education.by_code(db, payload.code)
    m = education.add_member(db, c, user)
    db.commit()
    return {"cohort": {"id": c.id, "name": c.name, "anonymous": c.anonymous}, "alias": m.alias}


@router.post("/enrol", response_model=schemas.TokenOut, status_code=201)
def enrol(payload: schemas.CohortEnrolIn, request: Request, db: Session = Depends(get_db)):
    """A student with no account creates one from the cohort code alone. The
    account is a participant in the cohort's organisation: it sees only the
    sessions it is seated in and never counts as a seat."""
    st = entitlements.status(db)
    if "education" not in st["features"]:
        raise HTTPException(402, "the education edition is not included in this deployment's tier")
    key = f"enrol|{client_ip(request)}"
    if throttle.retry_after(key) > 0:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "too many enrolments from this address; try again later")
    c = education.by_code(db, payload.code)
    problems = password_problems(payload.password)
    if problems:
        raise HTTPException(422, {"password": problems})
    email = payload.email.lower()
    if db.execute(select(models.User).where(func.lower(models.User.email) == email)).scalar_one_or_none() is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "that email already has an account: sign in, then join the cohort with its code")
    user = models.User(org_id=c.org_id, email=email, name=payload.name.strip(), password_hash=hash_password(payload.password),
                       role="participant")
    db.add(user)
    db.flush()
    m = education.add_member(db, c, user)
    audit.record(db, "cohort.enrol", request=request, user=user, detail={"cohort": c.name, "alias": m.alias}, commit=False)
    out = schemas.TokenOut(access_token=create_token(user), refresh_token=issue_refresh_token(db, user), user=user)
    db.commit()
    throttle.record_failure(key, limit=ENROL_MAX_PER_WINDOW)
    return out


@router.get("/{cohort_id}")
def get_cohort(cohort_id: int, user: models.User = Depends(require_facilitator), db: Session = Depends(get_db), _f=Depends(_gate)):
    c = _cohort(db, cohort_id, user)
    out = _out(db, c)
    out["members"] = [{"user_id": u.id, "alias": m.alias, "name": (u.name or u.email) if not c.anonymous else m.alias,
                       "email": u.email if not c.anonymous else "", "active": u.is_active, "joined_at": m.joined_at}
                      for m, u in education.members(db, c)]
    return out


@router.patch("/{cohort_id}")
def update_cohort(cohort_id: int, payload: schemas.CohortUpdateIn, user: models.User = Depends(require_facilitator),
                  db: Session = Depends(get_db), _f=Depends(_gate)):
    c = _cohort(db, cohort_id, user)
    if payload.name is not None:
        c.name = payload.name.strip() or c.name
    if payload.anonymous is not None:
        c.anonymous = payload.anonymous
    if payload.open is not None:
        c.open = payload.open
    db.commit()
    return _out(db, c)


@router.post("/{cohort_id}/rotate-code")
def rotate_code(cohort_id: int, user: models.User = Depends(require_facilitator), db: Session = Depends(get_db), _f=Depends(_gate)):
    c = _cohort(db, cohort_id, user)
    c.code = education.new_code(db)
    db.commit()
    return {"code": c.code}


@router.delete("/{cohort_id}", status_code=204)
def archive_cohort(cohort_id: int, request: Request, user: models.User = Depends(require_facilitator),
                   db: Session = Depends(get_db), _f=Depends(_gate)):
    c = _cohort(db, cohort_id, user)
    c.archived_at = education.now()
    c.open = False
    audit.record(db, "cohort.archive", request=request, user=user, detail={"cohort": c.name}, commit=False)
    db.commit()
    return Response(status_code=204)


@router.delete("/{cohort_id}/members/{user_id}", status_code=204)
def remove_member(cohort_id: int, user_id: int, user: models.User = Depends(require_facilitator),
                  db: Session = Depends(get_db), _f=Depends(_gate)):
    c = _cohort(db, cohort_id, user)
    row = db.execute(select(models.CohortMember).where(
        models.CohortMember.cohort_id == c.id, models.CohortMember.user_id == user_id)).scalar_one_or_none()
    if row is None:
        raise HTTPException(404, "not a member of this cohort")
    db.delete(row)
    db.commit()
    return Response(status_code=204)


@router.put("/{cohort_id}/sessions/{session_id}")
def attach_session(cohort_id: int, session_id: int, user: models.User = Depends(require_facilitator),
                   db: Session = Depends(get_db), _f=Depends(_gate)):
    """Make a session a classroom run of this cohort."""
    c = _cohort(db, cohort_id, user)
    s = scope_or_404(db.get(models.Session, session_id), user)
    s.cohort_id = c.id
    db.commit()
    return _out(db, c)


@router.post("/{cohort_id}/sessions/{session_id}/seat")
def seat_students(cohort_id: int, session_id: int, payload: schemas.CohortSeatIn | None = None,
                  user: models.User = Depends(require_facilitator), db: Session = Depends(get_db), _f=Depends(_gate)):
    """Seat every student in the run — no join code to read aloud."""
    c = _cohort(db, cohort_id, user)
    s = scope_or_404(db.get(models.Session, session_id), user)
    if s.cohort_id != c.id:
        raise HTTPException(status.HTTP_409_CONFLICT, "attach the session to this cohort first")
    if s.status == "complete":
        raise HTTPException(status.HTTP_409_CONFLICT, "that exercise has already finished")
    out = education.seat_all(db, c, s, (payload.cell if payload else "auto") or "auto")
    db.commit()
    return out


@router.get("/{cohort_id}/gradebook")
def gradebook(cohort_id: int, reveal: bool = False, user: models.User = Depends(require_facilitator),
              db: Session = Depends(get_db), _f=Depends(_gate)):
    c = _cohort(db, cohort_id, user)
    return education.gradebook(db, c, reveal=reveal)


@router.get("/{cohort_id}/gradebook.csv")
def gradebook_csv(cohort_id: int, reveal: bool = False, request: Request = None,
                  user: models.User = Depends(require_facilitator), db: Session = Depends(get_db), _f=Depends(_gate)):
    c = _cohort(db, cohort_id, user)
    book = education.gradebook(db, c, reveal=reveal)
    audit.record(db, "cohort.gradebook.export", request=request, user=user,
                 detail={"cohort": c.name, "revealed": book["cohort"]["revealed"]})
    return Response(content=education.gradebook_csv(book), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="gradebook-{c.id}.csv"'})
