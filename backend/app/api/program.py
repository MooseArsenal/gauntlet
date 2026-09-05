"""Program-level analytics (M4): coverage and improvement tracking."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import models
from ..database import get_db
from ..engine import program
from ..security import require_staff

router = APIRouter(prefix="/api/program", tags=["program"])


def _all(db: Session, user: models.User):
    """Every scenario and session belonging to the caller's organisation."""
    scenarios = db.execute(
        select(models.Scenario).where(models.Scenario.org_id == user.org_id)
    ).scalars().all()
    sessions = db.execute(
        select(models.Session).where(models.Session.org_id == user.org_id, models.Session.mode != "solo")
    ).scalars().all()
    return scenarios, sessions


@router.get("/coverage")
def program_coverage(user: models.User = Depends(require_staff), db: Session = Depends(get_db)):
    return program.build_program_coverage(*_all(db, user))


@router.get("/improvements")
def program_improvements(user: models.User = Depends(require_staff), db: Session = Depends(get_db)):
    return program.build_improvements(*_all(db, user))
