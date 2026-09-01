"""Longitudinal maturity analytics endpoint (D3)."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import analytics, models
from ..database import get_db
from ..security import require_evaluator

router = APIRouter(prefix="/api/analytics", tags=["analytics"])


@router.get("/maturity")
def maturity(user: models.User = Depends(require_evaluator), db: Session = Depends(get_db)):
    """Readiness trended across the org's exercises over time."""
    sessions = db.execute(
        select(models.Session).where(models.Session.org_id == user.org_id)
    ).scalars().all()
    return analytics.maturity(list(sessions))
