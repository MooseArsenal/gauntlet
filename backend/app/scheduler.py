"""Auto-advance timers (M6).

For a running session with ``auto_advance`` set, an inject that has a timeout
branch is scheduled to fire that branch after its (clock-scaled) duration,
unless a proctor advances first. Timers run in-process via ``threading.Timer``
— fine for a single instance; a multi-worker deployment would move this to a
shared scheduler (e.g. Celery beat), which is why the logic lives behind this
small module.
"""
from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from .config import SECONDS_PER_GAME_MINUTE
from .database import SessionLocal
from . import models, session_ops, ws

# One live timer per session.
_timers: dict[int, threading.Timer] = {}
_lock = threading.Lock()


def cancel(session_id: int) -> None:
    with _lock:
        t = _timers.pop(session_id, None)
    if t:
        t.cancel()


def arm(session: models.Session, inject) -> None:
    """Schedule the timeout branch of ``inject`` if the session auto-advances."""
    cancel(session.id)
    session.due_at = None
    if not session.auto_advance or session.status != "running":
        return
    branch = session_ops.timeout_branch(inject)
    if not branch:
        return
    minutes = session_ops.parse_duration_minutes(branch.get("after", ""))
    delay = max(1.0, minutes * SECONDS_PER_GAME_MINUTE)
    # Persisted so a restart can pick the timer back up (F-5).
    session.due_at = datetime.now(timezone.utc) + timedelta(seconds=delay)
    _start(session.id, inject.code, delay)


def _start(session_id: int, code: str, delay: float) -> None:
    t = threading.Timer(delay, _fire, args=(session_id, code))
    t.daemon = True
    with _lock:
        _timers[session_id] = t
    t.start()


def rearm_all() -> int:
    """On startup, re-arm every running auto-advance session whose timer was
    lost with the previous process (F-5). Overdue timers fire within a second.
    Returns the number re-armed."""
    db = SessionLocal()
    n = 0
    try:
        now = datetime.now(timezone.utc)
        for s in db.execute(
            select(models.Session).where(
                models.Session.status == "running",
                models.Session.auto_advance.is_(True),
                models.Session.due_at.isnot(None),
            )
        ).scalars():
            due = s.due_at if s.due_at.tzinfo else s.due_at.replace(tzinfo=timezone.utc)
            delay = max(1.0, (due - now).total_seconds())
            if s.current_inject_code:
                _start(s.id, s.current_inject_code, delay)
                n += 1
    finally:
        db.close()
    return n


def _fire(session_id: int, expected_code: str) -> None:
    """Timer callback: auto-advance the session on timeout, then re-arm."""
    with _lock:
        _timers.pop(session_id, None)
    db = SessionLocal()
    try:
        s = db.get(models.Session, session_id)
        if not s or s.status != "running" or s.current_inject_code != expected_code:
            return  # a proctor already moved on
        current = session_ops.current_inject(db, s)
        if current is None:
            return
        try:
            nxt = session_ops.advance(db, s, current, when="timeout")
        except (LookupError, ValueError):
            return
        db.commit()
        ws.manager.notify(session_id)
        # Chain: the next inject may itself time out.
        arm(s, nxt)
    finally:
        db.close()
