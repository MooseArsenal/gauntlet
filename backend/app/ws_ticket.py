"""Short-lived, single-use WebSocket connection tickets (M9).

The browser cannot set Authorization headers on a WebSocket handshake, so the
old design put the bearer JWT in the query string (``?token=<jwt>``). A URL is
the wrong place for a long-lived credential — it lands in proxy logs, browser
history, and Referer headers.

Instead the client authenticates a normal HTTPS ``POST /api/ws-ticket`` (bearer
header), receives an opaque ticket bound to one session, and connects with
``?ticket=<t>``. Tickets are single-use and expire in seconds, so a leaked one
is worthless.
"""
from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass

from .config import WS_TICKET_TTL_SEC


@dataclass
class _Ticket:
    user_id: int
    session_id: int
    expires_at: float


class _TicketStore:
    """In-memory, single-process. A multi-worker deployment should back this
    with Redis; the API is intentionally tiny so that swap is trivial."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_value: dict[str, _Ticket] = {}

    def issue(self, user_id: int, session_id: int) -> tuple[str, int]:
        value = secrets.token_urlsafe(24)
        ttl = WS_TICKET_TTL_SEC
        with self._lock:
            self._sweep_locked()
            self._by_value[value] = _Ticket(user_id, session_id, time.time() + ttl)
        return value, ttl

    def consume(self, value: str, session_id: int) -> int | None:
        """Return the user id if the ticket is valid for this session, else None.
        The ticket is removed whether or not it matched (single use)."""
        with self._lock:
            rec = self._by_value.pop(value, None)
        if rec is None or rec.expires_at < time.time() or rec.session_id != session_id:
            return None
        return rec.user_id

    def _sweep_locked(self) -> None:
        now = time.time()
        expired = [v for v, r in self._by_value.items() if r.expires_at < now]
        for v in expired:
            self._by_value.pop(v, None)


tickets = _TicketStore()
