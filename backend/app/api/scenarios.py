"""Scenario authoring — objectives, the narrative, and the MSEL of injects."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import models, scenario_io, schemas
from ..config import MAX_INJECTS
from ..database import get_db
from ..security import require_staff, require_facilitator, scope_or_404

router = APIRouter(prefix="/api/scenarios", tags=["scenarios"])


def _enforce_inject_cap(injects) -> None:
    """Same anti-DoS cap the YAML-import path enforces (scenario_io) — the
    editor/graph and direct-create paths must not bypass it."""
    if len(injects) > MAX_INJECTS:
        raise HTTPException(413, f"too many injects ({len(injects)} > {MAX_INJECTS})")


@router.post("", response_model=schemas.ScenarioOut, status_code=201)
def create_scenario(
    payload: schemas.ScenarioCreate,
    user: models.User = Depends(require_facilitator),
    db: Session = Depends(get_db),
):
    # The environment must exist and belong to the caller's organisation.
    scope_or_404(db.get(models.Environment, payload.environment_id), user)
    _enforce_inject_cap(payload.injects)
    # A scenario with injects must be a runnable graph (F-3): one start, unique
    # codes, every branch resolves, a terminal exists. An inject-less draft is
    # allowed — the editor fills it in and the graph save validates again.
    if payload.injects:
        problems = scenario_io.validate(payload.model_dump())["errors"]
        if problems:
            raise HTTPException(422, {"graph": problems})

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
        variables=dict(payload.variables or {}),
    )
    scenario.objectives = [models.Objective(**o.model_dump()) for o in payload.objectives]
    scenario.injects = [models.Inject(**i.model_dump()) for i in payload.injects]
    db.add(scenario)
    db.commit()
    db.refresh(scenario)
    return scenario


@router.get("", response_model=list[schemas.ScenarioSummary])
def list_scenarios(
    include_archived: bool = False,
    limit: int = 100, offset: int = 0,
    user: models.User = Depends(require_staff), db: Session = Depends(get_db)
):
    return (
        db.execute(
            select(models.Scenario)
            .where(models.Scenario.org_id == user.org_id, models.Scenario.exercise_type != "solo",
                   *([] if include_archived else [models.Scenario.archived_at.is_(None)]))
            .order_by(models.Scenario.id)
            .limit(max(1, min(limit, 500))).offset(max(0, offset))
        )
        .scalars()
        .all()
    )


@router.get("/{scenario_id}", response_model=schemas.ScenarioOut)
def get_scenario(
    scenario_id: int, user: models.User = Depends(require_staff), db: Session = Depends(get_db)
):
    scenario = scope_or_404(db.get(models.Scenario, scenario_id), user)
    # Present injects in play order.
    scenario.injects.sort(key=lambda i: i.sequence)
    return scenario


@router.put("/{scenario_id}/graph", response_model=schemas.ScenarioOut)
def replace_graph(
    scenario_id: int,
    payload: schemas.ScenarioGraphIn,
    user: models.User = Depends(require_facilitator),
    db: Session = Depends(get_db),
):
    """Replace a scenario's whole inject graph — the visual editor's save.

    Validates the graph is coherent (unique codes, exactly one start, every
    branch ``goto`` resolves) before committing, then swaps the injects
    atomically (delete-orphan handles the removals)."""
    scenario = scope_or_404(db.get(models.Scenario, scenario_id), user)

    codes = [i.code for i in payload.injects]
    problems: list[str] = []
    if len(payload.injects) > MAX_INJECTS:
        problems.append(f"too many injects ({len(payload.injects)} > {MAX_INJECTS})")
    if len(codes) != len(set(codes)):
        problems.append("inject codes must be unique")
    starts = [i.code for i in payload.injects if i.is_start]
    if payload.injects and len(starts) != 1:
        problems.append(f"exactly one start inject is required (found {len(starts)})")
    known = set(codes)
    for inj in payload.injects:
        for br in inj.branches or []:
            goto = (br or {}).get("goto")
            if goto and goto not in known:
                problems.append(f"branch from '{inj.code}' points to unknown inject '{goto}'")
    if payload.injects and not problems:
        # The same structural checks the YAML path runs (terminal inject,
        # branch conditions, objective references) — one rulebook (F-3).
        problems.extend(scenario_io.validate({
            "name": scenario.name,
            "objectives": [{"code": o.code} for o in scenario.objectives],
            "injects": [i.model_dump() for i in payload.injects],
            "variables": payload.variables if payload.variables is not None else (scenario.variables or {}),
        })["errors"])
    if problems:
        raise HTTPException(422, {"graph": problems})

    scenario.injects = [models.Inject(**i.model_dump()) for i in payload.injects]
    if payload.variables is not None:
        scenario.variables = payload.variables
    db.commit()
    db.refresh(scenario)
    scenario.injects.sort(key=lambda i: i.sequence)
    return scenario
