"""MITRE ATT&CK Navigator layer export endpoints (D1)."""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session

from .. import attack_layer, audit, models
from ..database import get_db
from ..security import get_current_user, require_evaluator, scope_or_404

router = APIRouter(tags=["attack-navigator"])


def _json_attach(payload: dict, filename: str) -> Response:
    return Response(
        content=json.dumps(payload, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/api/scenarios/{scenario_id}/attack-layer.json")
def scenario_attack_layer(
    scenario_id: int,
    request: Request,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """The scenario's ATT&CK technique spread as a Navigator layer."""
    scenario = scope_or_404(db.get(models.Scenario, scenario_id), user)
    audit.record(db, "attack.layer.export", request=request, user=user,
                 detail={"scenario_id": scenario.id, "kind": "scenario"})
    return _json_attach(attack_layer.scenario_layer(scenario),
                        f"attack-scenario-{scenario.id}.json")


@router.get("/api/sessions/{session_id}/attack-layer.json")
def session_attack_layer(
    session_id: int,
    request: Request,
    user: models.User = Depends(require_evaluator),
    db: Session = Depends(get_db),
):
    """The session's live detection coverage as a Navigator layer."""
    s = scope_or_404(db.get(models.Session, session_id), user)
    scenario = db.get(models.Scenario, s.scenario_id)
    audit.record(db, "attack.layer.export", request=request, user=user,
                 detail={"session_id": s.id, "kind": "session-detection"})
    return _json_attach(attack_layer.session_layer(s, scenario),
                        f"attack-session-{s.id}.json")
