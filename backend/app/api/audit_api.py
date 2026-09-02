"""Security audit log — admin-only, scoped to the caller's organisation (M8)."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import models, schemas
from ..database import get_db
from ..security import require_role

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("", response_model=list[schemas.AuditLogOut])
def list_audit(
    limit: int = 100,
    offset: int = 0,
    admin: models.User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    limit = max(1, min(limit, 500))
    return (
        db.execute(
            select(models.AuditLog)
            .where(models.AuditLog.org_id == admin.org_id)
            .order_by(models.AuditLog.id.desc())
            .limit(limit).offset(max(0, offset))
        )
        .scalars()
        .all()
    )
