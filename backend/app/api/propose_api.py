"""Propose the next inject (P5)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .. import audit, models, propose, schemas, session_ops, ws
from ..authoring import assist
from ..database import get_db
from ..engine import technique
from ..security import require_facilitator, scope_or_404
from .sessions import _current_inject, _get_session, _state, ACTIVE, require_status

router = APIRouter(prefix="/api/sessions", tags=["propose"])


@router.post("/{session_id}/propose")
def propose_next(session_id: int, payload: schemas.ProposeIn, request: Request,
                 user: models.User = Depends(require_facilitator), db: Session = Depends(get_db)):
    """Draft the next scene from the live session. Nothing is saved."""
    s = _get_session(db, session_id, user)
    require_status(s, *ACTIVE)
    scenario = db.get(models.Scenario, s.scenario_id)
    env = db.get(models.Environment, scenario.environment_id)
    current = _current_inject(db, s)
    try:
        out = propose.draft(db, s, scenario, env, current, brief=payload.brief)
    except assist.GuardrailError as exc:
        raise HTTPException(422, str(exc))
    audit.record(db, "session.propose", request=request, user=user,
                 detail={"session_id": s.id, "generator": out["generator"], "phase": out["context"]["phase"]})
    return out


@router.post("/{session_id}/propose/accept", response_model=schemas.SessionState)
def accept_proposal(session_id: int, payload: schemas.ProposalAcceptIn, request: Request,
                    user: models.User = Depends(require_facilitator), db: Session = Depends(get_db)):
    """Add the reviewed draft as a branch from the current scene; fire it now if asked."""
    s = _get_session(db, session_id, user)
    require_status(s, *ACTIVE)
    scenario = db.get(models.Scenario, s.scenario_id)
    current = _current_inject(db, s)
    data = payload.inject
    try:
        data["attack_techniques"] = technique.validate_list(data.get("attack_techniques") or [])
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    inject = propose.accept(db, s, scenario, current, data)
    audit.record(db, "session.propose.accept", request=request, user=user,
                 detail={"session_id": s.id, "inject": inject.code, "fire": payload.fire}, commit=False)
    if payload.fire and current is not None:
        if s.status != "running":
            raise HTTPException(409, f"session is {s.status}, not running")
        from .. import scheduler
        scheduler.cancel(s.id)
        session_ops.advance(db, s, current, when="proctor_choice", goto=inject.code, note="proposed scene accepted")
    db.commit()
    db.refresh(s)
    ws.manager.notify(s.id)
    return _state(db, s)
