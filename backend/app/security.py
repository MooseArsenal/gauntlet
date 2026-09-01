"""Authentication and authorization.

Passwords are stored as salted PBKDF2-SHA256 (stdlib, no native build needed).
Sessions are stateless JWTs signed with the server ``SECRET_KEY``. Route
handlers depend on :func:`get_current_user` for authentication and
:func:`require_role` for authorization, and scope every query to the caller's
organisation.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import struct
import time
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import models
from .config import (
    ACCESS_TTL_MIN,
    AUTH_OPTIONAL,
    MFA_ISSUER,
    PASSWORD_MIN_LEN,
    REFRESH_TTL_DAYS,
)
from .database import get_db
from .keys import jwt_key

_PBKDF2_ROUNDS = 240_000
_bearer = HTTPBearer(auto_error=False)


# --------------------------------------------------------------------------- #
# password policy
# --------------------------------------------------------------------------- #
_COMMON_PASSWORDS = {
    "password", "password1", "password123", "12345678", "123456789", "qwerty",
    "letmein", "changeme", "admin123", "welcome1", "iloveyou", "abc12345",
}


def password_problems(pw: str) -> list[str]:
    problems = []
    if len(pw) < PASSWORD_MIN_LEN:
        problems.append(f"must be at least {PASSWORD_MIN_LEN} characters")
    if pw.isdigit():
        problems.append("must not be all digits")
    if pw.lower() in _COMMON_PASSWORDS:
        problems.append("is too common")
    return problems


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
    """Short-lived access token (JWT). Refresh tokens are opaque (see below)."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user.id),
        "org": user.org_id,
        "role": user.role,
        "type": "access",
        "iat": now,
        "exp": now + timedelta(minutes=ACCESS_TTL_MIN),
    }
    return jwt.encode(payload, jwt_key(), algorithm="HS256")


def _decode(token: str) -> dict:
    return jwt.decode(token, jwt_key(), algorithms=["HS256"])


# --------------------------------------------------------------------------- #
# refresh tokens (opaque, rotating, revocable)
# --------------------------------------------------------------------------- #
def _hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def issue_refresh_token(db: Session, user: models.User, family_id: str | None = None) -> str:
    """Create and store a refresh token; return the plaintext (shown once)."""
    raw = secrets.token_urlsafe(32)
    rec = models.RefreshToken(
        user_id=user.id,
        family_id=family_id or secrets.token_hex(16),
        token_hash=_hash_token(raw),
        expires_at=datetime.now(timezone.utc) + timedelta(days=REFRESH_TTL_DAYS),
    )
    db.add(rec)
    db.flush()
    return raw


def _revoke_family(db: Session, family_id: str) -> None:
    for rec in db.execute(
        select(models.RefreshToken).where(models.RefreshToken.family_id == family_id)
    ).scalars():
        rec.revoked = True


def rotate_refresh_token(db: Session, raw: str) -> tuple[models.User, str]:
    """Validate + rotate a refresh token. Returns (user, new_raw).

    Reuse of a revoked token revokes the whole family (compromise response).
    """
    rec = db.execute(
        select(models.RefreshToken).where(models.RefreshToken.token_hash == _hash_token(raw))
    ).scalar_one_or_none()
    if rec is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid refresh token")
    if rec.revoked:
        # Reuse of a burned token = likely theft. Kill the whole family and
        # commit that now, since the caller aborts (no commit) on the raise.
        _revoke_family(db, rec.family_id)
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "refresh token reuse detected")
    exp = rec.expires_at
    if exp.tzinfo is None:  # SQLite returns naive UTC
        exp = exp.replace(tzinfo=timezone.utc)
    if exp < datetime.now(timezone.utc):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "refresh token expired")

    user = db.get(models.User, rec.user_id)
    if not user or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "user not found or inactive")

    rec.revoked = True  # rotate: burn the presented token
    new_raw = issue_refresh_token(db, user, family_id=rec.family_id)
    return user, new_raw


def revoke_all_refresh(db: Session, user_id: int) -> None:
    for rec in db.execute(
        select(models.RefreshToken).where(
            models.RefreshToken.user_id == user_id, models.RefreshToken.revoked.is_(False)
        )
    ).scalars():
        rec.revoked = True


def revoke_refresh_token(db: Session, raw: str) -> None:
    rec = db.execute(
        select(models.RefreshToken).where(models.RefreshToken.token_hash == _hash_token(raw))
    ).scalar_one_or_none()
    if rec:
        rec.revoked = True


# --------------------------------------------------------------------------- #
# TOTP (RFC 6238) — stdlib, no external dependency
# --------------------------------------------------------------------------- #
def new_totp_secret() -> str:
    return base64.b32encode(os.urandom(20)).decode().rstrip("=")


def _totp_at(secret_b32: str, counter: int, digits: int = 6) -> str:
    pad = "=" * ((8 - len(secret_b32) % 8) % 8)
    key = base64.b32decode(secret_b32 + pad, casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def totp_verify(secret_b32: str, code: str, step: int = 30, window: int = 1) -> bool:
    if not code or not code.isdigit():
        return False
    counter = int(time.time() // step)
    return any(
        hmac.compare_digest(_totp_at(secret_b32, counter + drift), code)
        for drift in range(-window, window + 1)
    )


def totp_uri(secret_b32: str, email: str) -> str:
    from urllib.parse import quote

    label = quote(f"{MFA_ISSUER}:{email}")
    return f"otpauth://totp/{label}?secret={secret_b32}&issuer={quote(MFA_ISSUER)}"


def create_mfa_challenge(user: models.User) -> str:
    """A short-lived token proving the first factor passed; exchanged for real
    tokens once the TOTP code is supplied."""
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {"sub": str(user.id), "type": "mfa_challenge", "iat": now,
         "exp": now + timedelta(minutes=5)},
        jwt_key(), algorithm="HS256",
    )


def read_mfa_challenge(token: str) -> int:
    try:
        payload = _decode(token)
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or expired challenge")
    if payload.get("type") != "mfa_challenge":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "not an MFA challenge")
    return int(payload.get("sub", 0))


# --------------------------------------------------------------------------- #
# dependencies
# --------------------------------------------------------------------------- #
def _default_user(db: Session) -> models.User | None:
    """The seeded org's admin, used only when AUTH_OPTIONAL is on (dev/test)."""
    return db.execute(
        select(models.User).order_by(models.User.id).limit(1)
    ).scalar_one_or_none()


def _bind_tenant(db: Session, org_id: int) -> None:
    """Bind this request's connection to the caller's tenant for Postgres RLS.
    A no-op off Postgres or when RLS is disabled (imported lazily to keep the
    auth module free of a hard dependency)."""
    from .rls import set_tenant

    set_tenant(db, org_id)


def get_current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
) -> models.User:
    if creds is None or not creds.credentials:
        if AUTH_OPTIONAL and (u := _default_user(db)):
            _bind_tenant(db, u.org_id)
            return u
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "authentication required")
    try:
        payload = _decode(creds.credentials)
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or expired token")
    if payload.get("type", "access") != "access":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "not an access token")
    user = db.get(models.User, int(payload.get("sub", 0)))
    if not user or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "user not found or inactive")
    _bind_tenant(db, user.org_id)
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

# Staff (H1): the people who design, run and evaluate exercises. Participants
# are everyone else — they see only their own cell's view of a session they
# have joined, resolved server-side (see membership.py), never a full object.
STAFF_ROLES = ("admin", "facilitator", "evaluator")
require_staff = require_role(*STAFF_ROLES)


def is_staff(user: models.User) -> bool:
    return user.role in STAFF_ROLES


def scope_or_404(entity, user: models.User):
    """Return ``entity`` only if it belongs to the caller's organisation.

    Raises 404 (not 403) for a missing entity or one owned by another tenant, so
    the API never reveals that an out-of-tenant id exists.
    """
    if entity is None or getattr(entity, "org_id", None) != user.org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
    return entity
