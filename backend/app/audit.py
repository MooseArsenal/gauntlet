"""Security audit logging (M8)."""
from __future__ import annotations

from fastapi import Request
from sqlalchemy.orm import Session

from . import models
from .config import TRUST_PROXY


def client_ip(request: Request | None) -> str:
    """Best-effort client IP. Honours X-Forwarded-For only behind a trusted proxy."""
    if request is None:
        return ""
    if TRUST_PROXY:
        fwd = request.headers.get("x-forwarded-for", "")
        if fwd:
            return fwd.split(",")[0].strip()
    return request.client.host if request.client else ""


def record(
    db: Session,
    action: str,
    *,
    request: Request | None = None,
    user: "models.User | None" = None,
    org_id: int | None = None,
    actor_email: str = "",
    detail: dict | None = None,
    commit: bool = True,
) -> None:
    """Write one audit entry. Never raises into the caller's request path."""
    try:
        entry = models.AuditLog(
            org_id=org_id if org_id is not None else (user.org_id if user else None),
            actor_user_id=user.id if user else None,
            actor_email=actor_email or (user.email if user else ""),
            action=action,
            detail=detail or {},
            ip=client_ip(request),
        )
        db.add(entry)
        if commit:
            db.commit()
    except Exception:
        db.rollback()
