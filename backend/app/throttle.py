"""In-memory login throttling and account lockout (M8).

Keyed by (client IP, email). After ``LOGIN_MAX_ATTEMPTS`` failures within
``LOGIN_WINDOW_SEC`` the key is locked for ``LOGIN_LOCKOUT_SEC``.

This is per-process — fine for a single instance. A multi-instance deployment
should back this with a shared store (Redis); the interface stays the same.
"""
from __future__ import annotations

import threading
import time

from .config import LOGIN_LOCKOUT_SEC, LOGIN_MAX_ATTEMPTS, LOGIN_WINDOW_SEC, REDIS_URL


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

    def record_failure(self, key: str, limit: int | None = None) -> None:
        now = time.time()
        limit = limit or LOGIN_MAX_ATTEMPTS
        with self._lock:
            window = [t for t in self._fails.get(key, []) if now - t < LOGIN_WINDOW_SEC]
            window.append(now)
            self._fails[key] = window
            if len(window) >= limit:
                self._locked_until[key] = now + LOGIN_LOCKOUT_SEC
                self._fails[key] = []

    def reset(self, key: str) -> None:
        with self._lock:
            self._fails.pop(key, None)
            self._locked_until.pop(key, None)

    def reset_email(self, email: str) -> None:
        """Clear every lockout for an account, whatever address it came from
        (an admin unlocking a member)."""
        suffix = f"|{email.lower()}"
        with self._lock:
            for store in (self._fails, self._locked_until):
                for k in [k for k in store if k.endswith(suffix)]:
                    store.pop(k, None)


class RedisThrottle:
    """The same interface on a shared store (M5), so lockouts hold across
    processes and restarts. ``client`` is any redis-py compatible client
    (``incr``, ``expire``, ``ttl``, ``set``, ``delete``, ``scan_iter``)."""

    PREFIX = "gauntlet:throttle:"

    def __init__(self, client) -> None:
        self._r = client

    def _k(self, key: str, kind: str) -> str:
        return f"{self.PREFIX}{kind}:{key}"

    def retry_after(self, key: str) -> int:
        ttl = self._r.ttl(self._k(key, "lock"))
        return max(0, int(ttl)) if ttl is not None and int(ttl) > 0 else 0

    def record_failure(self, key: str, limit: int | None = None) -> None:
        limit = limit or LOGIN_MAX_ATTEMPTS
        fails = self._k(key, "fail")
        n = int(self._r.incr(fails))
        if n == 1:
            self._r.expire(fails, LOGIN_WINDOW_SEC)
        if n >= limit:
            self._r.set(self._k(key, "lock"), "1", ex=LOGIN_LOCKOUT_SEC)
            self._r.delete(fails)

    def reset(self, key: str) -> None:
        self._r.delete(self._k(key, "fail"), self._k(key, "lock"))

    def reset_email(self, email: str) -> None:
        suffix = f"|{email.lower()}"
        for k in list(self._r.scan_iter(match=f"{self.PREFIX}*{suffix}")):
            self._r.delete(k)


def _build():
    if REDIS_URL:
        import redis  # optional dependency, only imported when configured

        return RedisThrottle(redis.Redis.from_url(REDIS_URL, decode_responses=True))
    return LoginThrottle()


throttle = _build()
