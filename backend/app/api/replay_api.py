"""Session replay + rewind-to-branch (L4). Gated by the ``replay`` feature."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from .. import audit, entitlements, models, replay, scheduler, schemas, ws
from ..database import get_db
from ..membership import require_member
from ..security import get_current_user, require_facilitator, scope_or_404

router = APIRouter(prefix="/api/sessions", tags=["replay"])
_gate = entitlements.require_feature("replay")


@router.get("/{session_id}/replay")
def get_replay(session_id: int, user: models.User = Depends(get_current_user), db: Session = Depends(get_db), _f=Depends(_gate)):
    """The exercise as scenes. Staff see everything; a seated participant sees
    the scenes addressed to their cell, with rulings and impact but not the
    proctor's notes or other cells' answers."""
    s = scope_or_404(db.get(models.Session, session_id), user)
    row = require_member(db, s, user)
    scenario = db.get(models.Scenario, s.scenario_id)
    out = replay.build(db, s, scenario)
    if row is not None:
        from ..engine import visibility
        cell = row.cell
        keep = []
        for sc in out["scenes"]:
            if not visibility.inject_visible_to(sc["visible_to"], cell):
                continue
            sc = dict(sc)
            sc["responses"] = [r for r in sc["responses"] if r.get("cell") == cell]
            sc["notes"] = []
            sc["state_before"] = {}
            sc["red_actions"] = []
            keep.append(sc)
        out["scenes"] = keep
        out["session"]["state"] = {}
    return out


@router.post("/{session_id}/rewind", response_model=schemas.SessionSummary, status_code=201)
def rewind(session_id: int, payload: schemas.RewindIn, request: Request,
           user: models.User = Depends(require_facilitator), db: Session = Depends(get_db), _f=Depends(_gate)):
    """Fork a new running session from the moment a scene began."""
    src = scope_or_404(db.get(models.Session, session_id), user)
    scenario = db.get(models.Scenario, src.scenario_id)
    s = replay.fork(db, src, scenario, payload.seq, user, payload.name)
    audit.record(db, "session.rewind", request=request, user=user,
                 detail={"from": src.id, "seq": payload.seq, "into": s.id}, commit=False)
    db.commit()
    db.refresh(s)
    scheduler.arm(s, __import__("app.session_ops", fromlist=["current_inject"]).current_inject(db, s))
    ws.manager.notify(src.id)
    return s
