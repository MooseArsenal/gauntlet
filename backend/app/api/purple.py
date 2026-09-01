"""Purple-team interactive mode (F5).

Runs red and blue together in one live loop. The **red cell** submits an action
(ATT&CK techniques against a target); Gauntlet **adjudicates it live** against
the environment's controls and deception — the same deterministic engine the
proctor uses — writes it to the tamper-evident timeline, and pings every surface
so the **blue cell** sees the move land in real time. A running **scoreboard**
turns the exchange into feedback: how many red actions were caught, how fast,
and where the detection gaps are.

Red actions are recorded as timeline events (``kind="red_action"``), so they
inherit the hash-chain and need no separate store.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import models, schemas, ws
from ..database import get_db
from ..engine import adjudication
from ..security import get_current_user, require_evaluator, scope_or_404
from ..timeline import append_event

router = APIRouter(prefix="/api/sessions", tags=["purple-team"])


def _session(db: Session, session_id: int, user: models.User) -> models.Session:
    return scope_or_404(db.get(models.Session, session_id), user)


def _red_events(session: models.Session) -> list[models.TimelineEvent]:
    return [e for e in session.events if e.kind == "red_action"]


# The scoreboard reflects every *adjudicated* red move, whichever surface ruled
# it: an explicit red-cell submission (``red_action``) or the proctor's console
# adjudication (``adjudication``). Both carry the same ruling payload shape.
def _scored_actions(session: models.Session) -> list[models.TimelineEvent]:
    return [e for e in session.events if e.kind in ("red_action", "adjudication")]


@router.post("/{session_id}/red-actions", response_model=schemas.RedActionOut, status_code=201)
def submit_red_action(session_id: int, payload: schemas.RedActionIn,
                      user: models.User = Depends(require_evaluator),
                      db: Session = Depends(get_db)):
    """Red cell submits a move; it is adjudicated live and lands on the timeline."""
    s = _session(db, session_id, user)
    scenario = db.get(models.Scenario, s.scenario_id)
    env = db.get(models.Environment, scenario.environment_id)

    ruling = adjudication.adjudicate(env, payload.techniques, payload.target)
    event = append_event(db, s.id, kind="red_action", ref=s.current_inject_code or "",
                         payload={**ruling, "action": payload.action, "actor": user.email})
    db.commit()
    db.refresh(event)
    ws.manager.notify(s.id)
    return schemas.RedActionOut(ruling=ruling,
                                event=schemas.TimelineEventOut.model_validate(event))


@router.get("/{session_id}/red-actions", response_model=list[schemas.TimelineEventOut])
def list_red_actions(session_id: int, user: models.User = Depends(get_current_user),
                     db: Session = Depends(get_db)):
    s = _session(db, session_id, user)
    return [schemas.TimelineEventOut.model_validate(e)
            for e in sorted(_red_events(s), key=lambda e: e.seq)]


@router.get("/{session_id}/scoreboard", response_model=schemas.Scoreboard)
def scoreboard(session_id: int, user: models.User = Depends(get_current_user),
               db: Session = Depends(get_db)):
    """Live purple-team tally over the session's adjudicated red moves."""
    s = _session(db, session_id, user)
    events = _scored_actions(s)

    detected = sum(1 for e in events if e.payload.get("detected"))
    missed = len(events) - detected
    deceptions = sum(1 for e in events if e.payload.get("deception_tripped"))
    ttds = [e.payload.get("time_to_detect_min") for e in events
            if e.payload.get("detected") and e.payload.get("time_to_detect_min") is not None]

    # Per-technique attempt/detect tally.
    per: dict[str, dict] = {}
    for e in events:
        hit = bool(e.payload.get("detected"))
        for t in (e.payload.get("techniques") or []) or ["(unspecified)"]:
            row = per.setdefault(t, {"attempts": 0, "detected": 0})
            row["attempts"] += 1
            row["detected"] += 1 if hit else 0

    return schemas.Scoreboard(
        session_id=s.id,
        red_actions=len(events),
        detected=detected,
        missed=missed,
        detection_rate=round(detected / len(events), 3) if events else None,
        mean_time_to_detect_min=round(sum(ttds) / len(ttds), 1) if ttds else None,
        deceptions_tripped=deceptions,
        by_technique=[schemas.TechniqueScore(technique=t, **v)
                      for t, v in sorted(per.items())],
    )
