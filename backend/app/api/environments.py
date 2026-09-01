"""Environment intake — the 'feed it what you know' surface."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import models, schemas
from ..database import get_db
from ..security import get_current_user, require_facilitator, scope_or_404

router = APIRouter(prefix="/api/environments", tags=["environments"])


@router.post("", response_model=schemas.EnvironmentOut, status_code=201)
def create_environment(
    payload: schemas.EnvironmentCreate,
    user: models.User = Depends(require_facilitator),
    db: Session = Depends(get_db),
):
    env = models.Environment(org_id=user.org_id, **payload.model_dump())
    db.add(env)
    db.commit()
    db.refresh(env)
    return env


@router.get("", response_model=list[schemas.EnvironmentSummary])
def list_environments(
    user: models.User = Depends(get_current_user), db: Session = Depends(get_db)
):
    return (
        db.execute(
            select(models.Environment)
            .where(models.Environment.org_id == user.org_id)
            .order_by(models.Environment.id)
        )
        .scalars()
        .all()
    )


@router.get("/{env_id}", response_model=schemas.EnvironmentOut)
def get_environment(
    env_id: int, user: models.User = Depends(get_current_user), db: Session = Depends(get_db)
):
    return scope_or_404(db.get(models.Environment, env_id), user)
