"""Multi-cell & parallel (M3): fog-of-war views and cross-session roll-up.

H1: the cell a caller may look through is decided on the server. Staff may
view any cell; a participant is shown the cell on their join row, never a
control cell, and never another cell's view.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import models, schemas
from ..database import get_db
from ..engine import rollup, visibility
from ..membership import resolve_cell, resolve_cell_for_scenario
from ..security import get_current_user, is_staff, require_staff, scope_or_404

router = APIRouter(tags=["multicell"])


def _cell_name(scenario, cell_key: str) -> str:
    for c in scenario.cells or []:
        if c.get("key") == cell_key:
            return c.get("name", cell_key)
    return cell_key


@router.get("/api/sessions/{session_id}/cell/{cell_key}", response_model=schemas.CellSessionView)
def cell_session_view(
    session_id: int,
    cell_key: str,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """The session as one cell may see it — injects addressed to it only, no
    White Cell machinery (unless the cell is itself a control cell)."""
    s = scope_or_404(db.get(models.Session, session_id), user)
    scenario = db.get(models.Scenario, s.scenario_id)
    cell_key = resolve_cell(db, s, scenario, user, cell_key)

    current = None
    if s.current_inject_code:
        current = db.execute(
            select(models.Inject).where(
                models.Inject.scenario_id == s.scenario_id,
                models.Inject.code == s.current_inject_code,
            )
        ).scalar_one_or_none()

    visible_current = visibility.current_inject_for_cell(current, scenario, cell_key)
    visible_events = visibility.filter_timeline(s.events, scenario, cell_key)

    from .. import decisions  # P1
    spec = decisions.spec_for(visible_current) if visible_current else None
    inject_out = schemas.InjectOut.model_validate(visible_current) if visible_current else None
    if inject_out is not None and not visibility.is_control_cell(scenario, cell_key):
        # Fog of war: a participant sees the scene, never the proctor's machinery —
        # the scored decision spec and the branches that name what comes next.
        inject_out = inject_out.model_copy(update={
            "meta": {k: v for k, v in (inject_out.meta or {}).items() if k != "decision"},
            "branches": [],
        })
    return schemas.CellSessionView(
        cell_key=cell_key,
        cell_name=_cell_name(scenario, cell_key),
        can_see_all=is_staff(user) and visibility.is_control_cell(scenario, cell_key),
        session=schemas.SessionSummary.model_validate(s),
        current_inject=inject_out,
        timeline=[schemas.TimelineEventOut.model_validate(e) for e in visible_events],
        objectives=[schemas.ObjectiveOut.model_validate(o) for o in scenario.objectives],
        decision=decisions.public_spec(spec),
        my_response=decisions.my_response(s, user.id, visible_current.code) if visible_current else None,
    )


@router.get("/api/environments/{env_id}/view/{cell_key}")
def environment_cell_view(
    env_id: int,
    cell_key: str,
    scenario_id: int,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """A per-cell redacted environment — the white/grey/black-box view. The
    ``scenario_id`` query param supplies the cell roster used to resolve the
    cell's control status."""
    env = scope_or_404(db.get(models.Environment, env_id), user)
    scenario = scope_or_404(db.get(models.Scenario, scenario_id), user)
    cell_key = resolve_cell_for_scenario(db, scenario, user, cell_key)
    return visibility.filter_environment(env, scenario, cell_key)


@router.get("/api/scenarios/{scenario_id}/rollup", response_model=schemas.RollupOut)
def scenario_rollup(
    scenario_id: int, user: models.User = Depends(require_staff), db: Session = Depends(get_db)
):
    """Compare every run of a scenario — the parallel / program view."""
    scenario = scope_or_404(db.get(models.Scenario, scenario_id), user)
    sessions = (
        db.execute(
            select(models.Session)
            .where(models.Session.scenario_id == scenario_id)
            .order_by(models.Session.id)
        )
        .scalars()
        .all()
    )
    return rollup.build_rollup(scenario, sessions)
