"""In-memory login throttling and account lockout (M8).

Keyed by (client IP, email). After ``LOGIN_MAX_ATTEMPTS`` failures within
``LOGIN_WINDOW_SEC`` the key is locked for ``LOGIN_LOCKOUT_SEC``.

This is per-process — fine for a single instance. A multi-instance deployment
should back this with a shared store (Redis); the interface stays the same.
"""
from __future__ import annotations

import threading
import time

from .config import LOGIN_LOCKOUT_SEC, LOGIN_MAX_ATTEMPTS, LOGIN_WINDOW_SEC


class LoginThrottle:
    def __init__(self) -> None:
        self._fails: dict[str, list[float]] = {}
        self._locked_until: dict[str, float] = {}
        self._lock = threading.Lock()

    def retry_after(self, key: str) -> int:
        """Seconds remaining on a lockout, or 0 if not locked."""
        with self._lock:
            until = self._locked_until.get(key, 0)
            return max(0, int(until - time.time()))

    def record_failure(self, key: str) -> None:
        now = time.time()
        with self._lock:
            window = [t for t in self._fails.get(key, []) if now - t < LOGIN_WINDOW_SEC]
            window.append(now)
            self._fails[key] = window
            if len(window) >= LOGIN_MAX_ATTEMPTS:
                self._locked_until[key] = now + LOGIN_LOCKOUT_SEC
                self._fails[key] = []

    def reset(self, key: str) -> None:
        with self._lock:
            self._fails.pop(key, None)
            self._locked_until.pop(key, None)


throttle = LoginThrottle()
