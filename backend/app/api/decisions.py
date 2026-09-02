"""Participant decisions (P1): answer the live inject; the proctor sees the tally."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import decisions, models, schemas, ws
from ..database import get_db
from ..membership import require_member
from ..security import get_current_user, is_staff, require_staff, scope_or_404
from .sessions import ACTIVE, require_status

router = APIRouter(prefix="/api/sessions", tags=["decisions"])


@router.post("/{session_id}/respond", response_model=schemas.TimelineEventOut, status_code=201)
def respond(session_id: int, payload: schemas.RespondIn,
            user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    """A participant answers the current (or a named, fired) inject for their
    cell. Staff may answer too, through the cell they name (default white)."""
    s = scope_or_404(db.get(models.Session, session_id), user)
    require_status(s, *ACTIVE)
    scenario = db.get(models.Scenario, s.scenario_id)
    row = require_member(db, s, user)
    if row is not None:
        cell, name = row.cell, row.display_name
    else:
        cell, name = (payload.cell or "white_cell"), (user.name or user.email)
    ev = decisions.record(db, s, scenario, user, cell, name, payload.inject_code, payload.option, payload.text)
    db.commit()
    db.refresh(ev)
    ws.manager.notify(s.id)
    return ev


@router.get("/{session_id}/responses")
def responses(session_id: int, inject: str | None = None,
              user: models.User = Depends(require_staff), db: Session = Depends(get_db)):
    """The proctor's tally for one inject (default: the current one), with scores."""
    s = scope_or_404(db.get(models.Session, session_id), user)
    scenario = db.get(models.Scenario, s.scenario_id)
    return decisions.tally(db, s, scenario, inject)


@router.get("/{session_id}/participants/scores")
def scores(session_id: int, user: models.User = Depends(require_staff), db: Session = Depends(get_db)):
    s = scope_or_404(db.get(models.Session, session_id), user)
    return {"session_id": s.id, "summary": decisions.summary(list(s.events)),
            "participants": decisions.participant_scores(db, s)}
