"""Scenario authoring — objectives, the narrative, and the MSEL of injects."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import models, schemas
from ..database import get_db
from ..security import get_current_user, require_facilitator, scope_or_404

router = APIRouter(prefix="/api/scenarios", tags=["scenarios"])


@router.post("", response_model=schemas.ScenarioOut, status_code=201)
def create_scenario(
    payload: schemas.ScenarioCreate,
    user: models.User = Depends(require_facilitator),
    db: Session = Depends(get_db),
):
    # The environment must exist and belong to the caller's organisation.
    scope_or_404(db.get(models.Environment, payload.environment_id), user)

    scenario = models.Scenario(
        org_id=user.org_id,
        environment_id=payload.environment_id,
        name=payload.name,
        threat_actor=payload.threat_actor,
        narrative=payload.narrative,
        scope=payload.scope,
        rules_of_engagement=payload.rules_of_engagement,
        cells=payload.cells,
        exercise_type=payload.exercise_type,
    )
    scenario.objectives = [models.Objective(**o.model_dump()) for o in payload.objectives]
    scenario.injects = [models.Inject(**i.model_dump()) for i in payload.injects]
    db.add(scenario)
    db.commit()
    db.refresh(scenario)
    return scenario


@router.get("", response_model=list[schemas.ScenarioSummary])
def list_scenarios(
    user: models.User = Depends(get_current_user), db: Session = Depends(get_db)
):
    return (
        db.execute(
            select(models.Scenario)
            .where(models.Scenario.org_id == user.org_id)
            .order_by(models.Scenario.id)
        )
        .scalars()
        .all()
    )


@router.get("/{scenario_id}", response_model=schemas.ScenarioOut)
def get_scenario(
    scenario_id: int, user: models.User = Depends(get_current_user), db: Session = Depends(get_db)
):
    scenario = scope_or_404(db.get(models.Scenario, scenario_id), user)
    # Present injects in play order.
    scenario.injects.sort(key=lambda i: i.sequence)
    return scenario
