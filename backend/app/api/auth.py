"""Authentication & organisation management (M5)."""
from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import audit, models, schemas
from ..audit import client_ip
from ..database import get_db
from ..security import (
    create_token,
    get_current_user,
    hash_password,
    require_role,
    verify_password,
)
from ..throttle import throttle

router = APIRouter(prefix="/api/auth", tags=["auth"])


def _slugify(name: str, db: Session) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "org"
    slug, n = base, 1
    while db.execute(select(models.Organization).where(models.Organization.slug == slug)).scalar_one_or_none():
        n += 1
        slug = f"{base}-{n}"
    return slug


def _email_taken(db: Session, email: str) -> bool:
    return db.execute(
        select(models.User).where(func.lower(models.User.email) == email.lower())
    ).scalar_one_or_none() is not None


@router.post("/register", response_model=schemas.TokenOut, status_code=201)
def register(payload: schemas.RegisterIn, request: Request, db: Session = Depends(get_db)):
    """Create a new organisation and its first user (an admin)."""
    if _email_taken(db, payload.email):
        raise HTTPException(status.HTTP_409_CONFLICT, "email already registered")

    org = models.Organization(name=payload.org_name, slug=_slugify(payload.org_name, db))
    db.add(org)
    db.flush()
    user = models.User(
        org_id=org.id, email=payload.email.lower(), name=payload.name,
        password_hash=hash_password(payload.password), role="admin",
    )
    db.add(user)
    db.flush()
    audit.record(db, "auth.register", request=request, user=user,
                 detail={"org": org.name}, commit=False)
    db.commit()
    db.refresh(user)
    return schemas.TokenOut(access_token=create_token(user), user=user)


@router.post("/login", response_model=schemas.TokenOut)
def login(payload: schemas.LoginIn, request: Request, db: Session = Depends(get_db)):
    email = payload.email.lower()
    key = f"{client_ip(request)}|{email}"
    wait = throttle.retry_after(key)
    if wait > 0:
        audit.record(db, "auth.login.locked", request=request, actor_email=email,
                     detail={"retry_after": wait})
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                            f"too many attempts; retry in {wait}s")

    user = db.execute(
        select(models.User).where(func.lower(models.User.email) == email)
    ).scalar_one_or_none()
    if not user or not verify_password(payload.password, user.password_hash) or not user.is_active:
        throttle.record_failure(key)
        audit.record(db, "auth.login.failure", request=request, actor_email=email)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")

    throttle.reset(key)
    audit.record(db, "auth.login.success", request=request, user=user)
    return schemas.TokenOut(access_token=create_token(user), user=user)


@router.get("/me", response_model=schemas.UserOut)
def me(user: models.User = Depends(get_current_user)):
    return user


@router.post("/users", response_model=schemas.UserOut, status_code=201)
def create_user(
    payload: schemas.CreateUserIn,
    request: Request,
    admin: models.User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Admins add users to their own organisation."""
    if payload.role not in models.ROLES:
        raise HTTPException(422, f"role must be one of {list(models.ROLES)}")
    if _email_taken(db, payload.email):
        raise HTTPException(status.HTTP_409_CONFLICT, "email already registered")
    user = models.User(
        org_id=admin.org_id, email=payload.email.lower(), name=payload.name,
        password_hash=hash_password(payload.password), role=payload.role,
    )
    db.add(user)
    db.flush()
    audit.record(db, "auth.user.create", request=request, user=admin,
                 detail={"new_user": user.email, "role": user.role}, commit=False)
    db.commit()
    db.refresh(user)
    return user
