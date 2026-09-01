"""Shared session-advance logic used by both the HTTP API and the auto-advance
timer, so a proctor decision and a timeout take exactly the same path."""
from __future__ import annotations

import re

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import models
from .engine import msel
from .timeline import append_event

# ISO-8601-ish duration: PT10M, PT30S, PT1M30S.
_DUR = re.compile(r"^PT(?:(\d+)M)?(?:(\d+)S)?$")


def parse_duration_minutes(spec: str) -> float:
    """Return the branch ``after`` duration in game-minutes (0 if unparseable)."""
    m = _DUR.match(spec or "")
    if not m:
        return 0.0
    minutes = int(m.group(1) or 0)
    seconds = int(m.group(2) or 0)
    return minutes + seconds / 60.0


def timeout_branch(inject) -> dict | None:
    for b in inject.branches or []:
        if b.get("when") == msel.WHEN_TIMEOUT:
            return b
    return None


def current_inject(db: Session, s: models.Session):
    if not s.current_inject_code:
        return None
    return db.execute(
        select(models.Inject).where(
            models.Inject.scenario_id == s.scenario_id,
            models.Inject.code == s.current_inject_code,
        )
    ).scalar_one_or_none()


def fire_inject(db: Session, s: models.Session, inject: models.Inject) -> None:
    s.current_inject_code = inject.code
    append_event(
        db, s.id, kind="inject_fired", ref=inject.code, game_clock=inject.clock,
        payload={
            "title": inject.title, "channel": inject.channel, "narrative": inject.narrative,
            "techniques": inject.attack_techniques, "objective_code": inject.objective_code,
            "expected_actions": inject.expected_actions, "visible_to": inject.visible_to,
        },
    )


def advance(db: Session, s: models.Session, current, when: str, trigger=None, goto=None, note=""):
    """Resolve a branch and fire the next inject. Returns the next inject.

    Raises ``LookupError`` if no branch matches, ``ValueError`` if the branch
    points at an unknown inject.
    """
    branch = msel.resolve_branch(current, when=when, trigger=trigger, explicit_goto=goto)
    if not branch:
        raise LookupError("no branch matched this decision")

    append_event(
        db, s.id, kind="decision", ref=current.code, game_clock=current.clock,
        payload={"when": when, "trigger": trigger, "goto": branch.get("goto"),
                 "label": branch.get("label", ""), "note": note},
    )
    nxt = db.execute(
        select(models.Inject).where(
            models.Inject.scenario_id == s.scenario_id, models.Inject.code == branch.get("goto")
        )
    ).scalar_one_or_none()
    if not nxt:
        raise ValueError(f"branch points to unknown inject '{branch.get('goto')}'")
    fire_inject(db, s, nxt)
    return nxt
