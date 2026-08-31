"""Authentication and authorization.

Passwords are stored as salted PBKDF2-SHA256 (stdlib, no native build needed).
Sessions are stateless JWTs signed with the server ``SECRET_KEY``. Route
handlers depend on :func:`get_current_user` for authentication and
:func:`require_role` for authorization, and scope every query to the caller's
organisation.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import models
from .config import AUTH_OPTIONAL, SECRET_KEY, TOKEN_TTL_MIN
from .database import get_db

_PBKDF2_ROUNDS = 240_000
_bearer = HTTPBearer(auto_error=False)


# --------------------------------------------------------------------------- #
# passwords
# --------------------------------------------------------------------------- #
def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ROUNDS)
    return f"pbkdf2_sha256${_PBKDF2_ROUNDS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, rounds, salt_hex, hash_hex = stored.split("$")
        assert algo == "pbkdf2_sha256"
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(rounds))
        return hmac.compare_digest(dk.hex(), hash_hex)
    except (ValueError, AssertionError):
        return False


# --------------------------------------------------------------------------- #
# tokens
# --------------------------------------------------------------------------- #
def create_token(user: models.User) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user.id),
        "org": user.org_id,
        "role": user.role,
        "iat": now,
        "exp": now + timedelta(minutes=TOKEN_TTL_MIN),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def _decode(token: str) -> dict:
    return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])


# --------------------------------------------------------------------------- #
# dependencies
# --------------------------------------------------------------------------- #
def _default_user(db: Session) -> models.User | None:
    """The seeded org's admin, used only when AUTH_OPTIONAL is on (dev/test)."""
    return db.execute(
        select(models.User).order_by(models.User.id).limit(1)
    ).scalar_one_or_none()


def get_current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
) -> models.User:
    if creds is None or not creds.credentials:
        if AUTH_OPTIONAL and (u := _default_user(db)):
            return u
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "authentication required")
    try:
        payload = _decode(creds.credentials)
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or expired token")
    user = db.get(models.User, int(payload.get("sub", 0)))
    if not user or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "user not found or inactive")
    return user


def require_role(*roles: str):
    """Dependency factory: allow only users whose role is in ``roles``."""

    def _dep(user: models.User = Depends(get_current_user)) -> models.User:
        if user.role not in roles:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"role '{user.role}' is not permitted here (need one of {list(roles)})",
            )
        return user

    return _dep


# Facilitators and admins design and run exercises; evaluators additionally may
# log observations; everyone authenticated may read.
require_facilitator = require_role("admin", "facilitator")
require_evaluator = require_role("admin", "facilitator", "evaluator")


def scope_or_404(entity, user: models.User):
    """Return ``entity`` only if it belongs to the caller's organisation.

    Raises 404 (not 403) for a missing entity or one owned by another tenant, so
    the API never reveals that an out-of-tenant id exists.
    """
    if entity is None or getattr(entity, "org_id", None) != user.org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
    return entity
