"""Session membership (H1): the server-side answer to "which cell is this user?"

Fog-of-war used to be a browser convention — any authenticated user could ask
for any cell's view, including the White Cell's. Now the cell a participant
sees is the one recorded when they joined the session by its code, resolved
here on every request. Staff (admin / facilitator / evaluator) may look through
any cell; participants may look only through their own, and never through a
control cell.
"""
from __future__ import annotations

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import models
from .engine import visibility
from .security import is_staff

# Cells every scenario has unless it declares its own roster.
DEFAULT_CELLS = ("blue_cell", "red_cell", "white_cell")


def scenario_cell_keys(scenario: models.Scenario) -> list[str]:
    keys = [c.get("key") for c in (scenario.cells or []) if c.get("key")]
    return keys or list(DEFAULT_CELLS)


def join_row(db: Session, session_id: int, user_id: int) -> models.SessionJoin | None:
    return db.execute(
        select(models.SessionJoin).where(
            models.SessionJoin.session_id == session_id,
            models.SessionJoin.user_id == user_id,
        )
    ).scalars().first()


def require_member(db: Session, session: models.Session, user: models.User) -> models.SessionJoin | None:
    """Staff pass; a participant must have joined this session. Returns the
    participant's join row (None for staff)."""
    if is_staff(user):
        return None
    row = join_row(db, session.id, user.id)
    if row is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "join this session with its join code first")
    return row


def require_red_cell(db: Session, session: models.Session, user: models.User) -> None:
    """Red-cell moves: staff, or a participant who joined as the red cell."""
    row = require_member(db, session, user)
    if row is not None and row.cell != "red_cell":
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            f"you joined as '{row.cell}'; only the red cell submits moves")


def resolve_cell(db: Session, session: models.Session, scenario: models.Scenario,
                 user: models.User, requested: str | None) -> str:
    """The cell this user may view the session through.

    Staff: whatever they asked for (default White Cell). Participants: the cell
    on their join row — asking for another is refused, and a control cell is
    never available to a participant even if a join row somehow names one.
    """
    if is_staff(user):
        return requested or "white_cell"
    row = require_member(db, session, user)
    if requested and requested != row.cell:
        raise HTTPException(status.HTTP_403_FORBIDDEN, f"you are in '{row.cell}'")
    if visibility.is_control_cell(scenario, row.cell):
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "participants cannot view through a control cell")
    return row.cell


def resolve_cell_for_scenario(db: Session, scenario: models.Scenario,
                              user: models.User, requested: str) -> str:
    """Same rule for per-cell environment views, which are addressed by scenario
    rather than session: a participant qualifies through any session of that
    scenario they have joined in the requested cell."""
    if is_staff(user):
        return requested
    rows = db.execute(
        select(models.SessionJoin)
        .join(models.Session, models.Session.id == models.SessionJoin.session_id)
        .where(models.SessionJoin.user_id == user.id,
               models.Session.scenario_id == scenario.id)
    ).scalars().all()
    if not rows:
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "join a session of this scenario with its join code first")
    if requested not in {r.cell for r in rows}:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "that is not your cell")
    if visibility.is_control_cell(scenario, requested):
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "participants cannot view through a control cell")
    return requested


def validate_join_cell(scenario: models.Scenario, user: models.User, cell: str) -> str:
    """A join must name a cell the scenario actually has; participants may not
    take a control cell."""
    if cell not in scenario_cell_keys(scenario) and cell not in ("white_cell", "control"):
        raise HTTPException(422,
                            f"unknown cell '{cell}'; choose one of {scenario_cell_keys(scenario)}")
    if not is_staff(user) and visibility.is_control_cell(scenario, cell):
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "participants cannot join as the control cell")
    return cell
