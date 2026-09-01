"""Session conduct — the engine behind the facilitator console.

A session is one run of a scenario. These endpoints start it, present the
current inject and its branches, adjudicate player actions, capture
observations, and drive the branching MSEL forward — writing every step to the
tamper-evident timeline. Every endpoint is scoped to the caller's organisation.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import models, schemas, scheduler, session_ops, ws
from ..database import get_db
from ..ws_ticket import tickets as ws_tickets
from ..engine import adjudication, msel
from ..security import get_current_user, require_evaluator, require_facilitator, scope_or_404
from ..timeline import append_event, verify_chain

router = APIRouter(prefix="/api/sessions", tags=["sessions"])


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _get_session(db: Session, session_id: int, user: models.User) -> models.Session:
    return scope_or_404(db.get(models.Session, session_id), user)


@router.post("/{session_id}/ws-ticket", response_model=schemas.WsTicketOut)
def ws_ticket(
    session_id: int,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Mint a short-lived, single-use ticket for the session's WebSocket.

    Keeps the bearer token out of the ``ws://`` URL: the client authenticates
    this HTTPS call with its header, then connects with ``?ticket=<t>``.
    """
    _get_session(db, session_id, user)  # 404 unless it's in the caller's org
    value, ttl = ws_tickets.issue(user.id, session_id)
    return schemas.WsTicketOut(ticket=value, expires_in=ttl)


def _injects(db: Session, scenario_id: int) -> list[models.Inject]:
    return (
        db.execute(
            select(models.Inject)
            .where(models.Inject.scenario_id == scenario_id)
            .order_by(models.Inject.sequence)
        )
        .scalars()
        .all()
    )


def _current_inject(db: Session, s: models.Session):
    if not s.current_inject_code:
        return None
    return db.execute(
        select(models.Inject).where(
            models.Inject.scenario_id == s.scenario_id,
            models.Inject.code == s.current_inject_code,
        )
    ).scalar_one_or_none()


def _state(db: Session, s: models.Session) -> schemas.SessionState:
    scenario = db.get(models.Scenario, s.scenario_id)
    current = _current_inject(db, s)
    return schemas.SessionState(
        session=schemas.SessionSummary.model_validate(s),
        scenario=schemas.ScenarioSummary.model_validate(scenario),
        current_inject=schemas.InjectOut.model_validate(current) if current else None,
        available_branches=msel.available_branches(current, s.state) if current else [],
        timeline=[schemas.TimelineEventOut.model_validate(e) for e in s.events],
        observations=[schemas.ObservationOut.model_validate(o) for o in s.observations],
        state=dict(s.state or {}),
        terminal=(not msel.available_branches(current, s.state)) if current else False,
    )


def _fire_inject(db: Session, s: models.Session, inject: models.Inject) -> None:
    session_ops.fire_inject(db, s, inject)
    scheduler.arm(s, inject)


# --------------------------------------------------------------------------- #
# lifecycle
# --------------------------------------------------------------------------- #
@router.post("", response_model=schemas.SessionSummary, status_code=201)
def create_session(
    payload: schemas.SessionCreate,
    user: models.User = Depends(require_facilitator),
    db: Session = Depends(get_db),
):
    scope_or_404(db.get(models.Scenario, payload.scenario_id), user)
    s = models.Session(
        org_id=user.org_id, scenario_id=payload.scenario_id, name=payload.name,
        clock_mode=payload.clock_mode, mode=payload.mode, auto_advance=payload.auto_advance,
    )
    db.add(s)
    db.commit()
    db.refresh(s)
    return s


@router.get("", response_model=list[schemas.SessionSummary])
def list_sessions(user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    return (
        db.execute(
            select(models.Session)
            .where(models.Session.org_id == user.org_id)
            .order_by(models.Session.id.desc())
        )
        .scalars()
        .all()
    )


@router.get("/{session_id}", response_model=schemas.SessionState)
def get_session_state(
    session_id: int, user: models.User = Depends(get_current_user), db: Session = Depends(get_db)
):
    return _state(db, _get_session(db, session_id, user))


@router.post("/{session_id}/start", response_model=schemas.SessionState)
def start_session(
    session_id: int, user: models.User = Depends(require_facilitator), db: Session = Depends(get_db)
):
    s = _get_session(db, session_id, user)
    if s.status == "complete":
        raise HTTPException(409, "session already complete")
    injects = _injects(db, s.scenario_id)
    start = msel.get_start_inject(injects)
    if not start:
        raise HTTPException(400, "scenario has no injects")
    scenario = db.get(models.Scenario, s.scenario_id)
    s.state = dict(scenario.variables or {})  # initialise live state from the scenario
    s.status = "running"
    s.started_at = datetime.now(timezone.utc)
    append_event(db, s.id, kind="status", payload={"status": "running"})
    _fire_inject(db, s, start)
    db.commit()
    db.refresh(s)
    ws.manager.notify(s.id)
    return _state(db, s)


@router.post("/{session_id}/advance", response_model=schemas.SessionState)
def advance_session(
    session_id: int,
    decision: schemas.DecisionIn,
    user: models.User = Depends(require_facilitator),
    db: Session = Depends(get_db),
):
    s = _get_session(db, session_id, user)
    if s.status != "running":
        raise HTTPException(409, f"session is {s.status}, not running")
    current = _current_inject(db, s)
    if not current:
        raise HTTPException(409, "session has no current inject; start it first")

    # A proctor decision cancels any pending auto-advance timer for this inject.
    scheduler.cancel(s.id)
    try:
        nxt = session_ops.advance(
            db, s, current, when=decision.when, trigger=decision.trigger,
            goto=decision.goto, note=decision.note,
        )
    except LookupError:
        raise HTTPException(
            422,
            "no branch matched this decision — pick a branch, or pass an explicit "
            "'goto' to override as proctor",
        )
    except ValueError as e:
        raise HTTPException(422, str(e))

    scheduler.arm(s, nxt)
    db.commit()
    db.refresh(s)
    ws.manager.notify(s.id)
    return _state(db, s)


@router.post("/{session_id}/adjudicate", response_model=schemas.AdjudicationOut)
def adjudicate_action(
    session_id: int,
    payload: schemas.AdjudicateIn,
    user: models.User = Depends(require_facilitator),
    db: Session = Depends(get_db),
):
    s = _get_session(db, session_id, user)
    scenario = db.get(models.Scenario, s.scenario_id)
    env = db.get(models.Environment, scenario.environment_id)
    current = _current_inject(db, s)

    target = payload.target_asset or (current.target_asset if current else "")
    techniques = payload.techniques or (current.attack_techniques if current else [])
    ruling = adjudication.adjudicate(env, techniques, target)

    event = append_event(
        db,
        s.id,
        kind="adjudication",
        ref=current.code if current else "",
        game_clock=current.clock if current else "",
        payload={**ruling, "description": payload.description},
    )
    db.commit()
    db.refresh(event)
    ws.manager.notify(s.id)
    return schemas.AdjudicationOut(
        ruling=ruling, event=schemas.TimelineEventOut.model_validate(event)
    )


@router.post("/{session_id}/observe", response_model=schemas.ObservationOut, status_code=201)
def add_observation(
    session_id: int,
    payload: schemas.ObservationIn,
    user: models.User = Depends(require_evaluator),
    db: Session = Depends(get_db),
):
    s = _get_session(db, session_id, user)
    obs = models.Observation(session_id=s.id, **payload.model_dump())
    db.add(obs)
    db.flush()
    append_event(
        db,
        s.id,
        kind="observation",
        ref=payload.objective_code,
        payload={"rating": payload.rating, "note": payload.note, "observation_id": obs.id},
    )
    db.commit()
    db.refresh(obs)
    ws.manager.notify(s.id)
    return obs


@router.post("/{session_id}/note", response_model=schemas.TimelineEventOut, status_code=201)
def add_note(
    session_id: int,
    payload: schemas.NoteIn,
    user: models.User = Depends(require_evaluator),
    db: Session = Depends(get_db),
):
    s = _get_session(db, session_id, user)
    current = _current_inject(db, s)
    event = append_event(
        db,
        s.id,
        kind="note",
        ref=current.code if current else "",
        game_clock=current.clock if current else "",
        payload={"text": payload.text},
    )
    db.commit()
    db.refresh(event)
    ws.manager.notify(s.id)
    return event


@router.post("/{session_id}/pause", response_model=schemas.SessionState)
def pause_session(
    session_id: int, user: models.User = Depends(require_facilitator), db: Session = Depends(get_db)
):
    s = _get_session(db, session_id, user)
    scheduler.cancel(s.id)
    s.status = "paused"
    append_event(db, s.id, kind="status", payload={"status": "paused"})
    db.commit()
    db.refresh(s)
    ws.manager.notify(s.id)
    return _state(db, s)


@router.post("/{session_id}/resume", response_model=schemas.SessionState)
def resume_session(
    session_id: int, user: models.User = Depends(require_facilitator), db: Session = Depends(get_db)
):
    s = _get_session(db, session_id, user)
    if s.status == "complete":
        raise HTTPException(409, "session already complete")
    s.status = "running"
    append_event(db, s.id, kind="status", payload={"status": "running"})
    db.commit()
    db.refresh(s)
    current = _current_inject(db, s)
    if current:
        scheduler.arm(s, current)  # resume any pending auto-advance
    ws.manager.notify(s.id)
    return _state(db, s)


@router.post("/{session_id}/complete", response_model=schemas.SessionState)
def complete_session(
    session_id: int, user: models.User = Depends(require_facilitator), db: Session = Depends(get_db)
):
    s = _get_session(db, session_id, user)
    scheduler.cancel(s.id)
    s.status = "complete"
    s.completed_at = datetime.now(timezone.utc)
    append_event(db, s.id, kind="status", payload={"status": "complete"})
    db.commit()
    db.refresh(s)
    ws.manager.notify(s.id)
    return _state(db, s)


@router.get("/{session_id}/verify")
def verify_timeline(
    session_id: int, user: models.User = Depends(get_current_user), db: Session = Depends(get_db)
):
    s = _get_session(db, session_id, user)
    valid = verify_chain(list(s.events))
    return {"session_id": s.id, "events": len(s.events), "chain_valid": valid}
