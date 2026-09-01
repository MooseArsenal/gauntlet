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
    if not session.auto_advance or session.status != "running":
        return
    branch = session_ops.timeout_branch(inject)
    if not branch:
        return
    minutes = session_ops.parse_duration_minutes(branch.get("after", ""))
    delay = max(1.0, minutes * SECONDS_PER_GAME_MINUTE)

    t = threading.Timer(delay, _fire, args=(session.id, inject.code))
    t.daemon = True
    with _lock:
        _timers[session.id] = t
    t.start()


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
