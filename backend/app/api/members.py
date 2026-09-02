"""Member lifecycle (U-1): the admin's view of who is in the organisation.

Until now the only way to change a role, deactivate a leaver, reset a lost
authenticator or clear a lockout was a database shell. Every action here is
admin-only, scoped to the admin's own organisation, audit-logged, and guarded
against the two ways an admin can lock themselves out (deactivating or
demoting the last admin, or themselves).
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import audit, models, schemas, security
from ..database import get_db
from ..security import require_role
from ..throttle import throttle

router = APIRouter(prefix="/api/members", tags=["members"])


def _member(db: Session, member_id: int, admin: models.User) -> models.User:
    u = db.get(models.User, member_id)
    if u is None or u.org_id != admin.org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
    return u


def _admin_count(db: Session, org_id: int) -> int:
    return db.execute(
        select(func.count()).select_from(models.User).where(
            models.User.org_id == org_id, models.User.role == "admin", models.User.is_active.is_(True))
    ).scalar_one()


def _guard_last_admin(db: Session, target: models.User, admin: models.User, losing_admin: bool) -> None:
    if losing_admin and target.role == "admin" and target.is_active and _admin_count(db, admin.org_id) <= 1:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "this is the organisation's only active admin; promote someone else first")


@router.get("", response_model=list[schemas.MemberOut])
def list_members(admin: models.User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    rows = db.execute(
        select(models.User).where(models.User.org_id == admin.org_id).order_by(models.User.id)
    ).scalars().all()
    return [schemas.MemberOut.from_user(u) for u in rows]


@router.patch("/{member_id}", response_model=schemas.MemberOut)
def update_member(member_id: int, payload: schemas.MemberUpdateIn, request: Request,
                  admin: models.User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    """Change a member's role, display name, or active state."""
    u = _member(db, member_id, admin)
    changes = payload.model_dump(exclude_unset=True)
    if "role" in changes and changes["role"] not in models.ROLES:
        raise HTTPException(422, f"role must be one of {list(models.ROLES)}")
    if "role" in changes and changes["role"] in ("admin", "facilitator") and u.role not in ("admin", "facilitator"):
        from .. import entitlements  # L1
        entitlements.check_seats(db, admin.org_id, changes["role"])
    demoting = "role" in changes and changes["role"] != "admin"
    deactivating = "is_active" in changes and changes["is_active"] is False
    if u.id == admin.id and (demoting or deactivating):
        raise HTTPException(status.HTTP_409_CONFLICT, "you cannot demote or deactivate yourself")
    _guard_last_admin(db, u, admin, demoting or deactivating)
    for k, v in changes.items():
        setattr(u, k, v)
    if deactivating:
        security.revoke_all_refresh(db, u.id)  # a leaver's sessions end now, not at token expiry
    audit.record(db, "members.update", request=request, user=admin,
                 detail={"member": u.email, **changes}, commit=False)
    db.commit()
    db.refresh(u)
    return schemas.MemberOut.from_user(u)


@router.post("/{member_id}/reset-mfa", response_model=schemas.MemberOut)
def reset_mfa(member_id: int, request: Request,
              admin: models.User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    """Clear a member's second factor (lost authenticator) and sign them out
    everywhere so the next login re-enrols."""
    u = _member(db, member_id, admin)
    u.mfa_enabled = False
    u.mfa_secret = None
    u.mfa_pending_secret = None
    security.revoke_all_refresh(db, u.id)
    audit.record(db, "members.reset_mfa", request=request, user=admin,
                 detail={"member": u.email}, commit=False)
    db.commit()
    db.refresh(u)
    return schemas.MemberOut.from_user(u)


@router.post("/{member_id}/set-password", status_code=204)
def set_password(member_id: int, payload: schemas.MemberPasswordIn, request: Request,
                 admin: models.User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    """Set a temporary password for a member who is locked out, and sign them
    out everywhere."""
    u = _member(db, member_id, admin)
    problems = security.password_problems(payload.password)
    if problems:
        raise HTTPException(422, {"password": problems})
    u.password_hash = security.hash_password(payload.password)
    security.revoke_all_refresh(db, u.id)
    audit.record(db, "members.set_password", request=request, user=admin,
                 detail={"member": u.email}, commit=False)
    db.commit()


@router.post("/{member_id}/revoke-sessions", status_code=204)
def revoke_sessions(member_id: int, request: Request,
                    admin: models.User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    """Sign a member out of every device (refresh tokens revoked; access
    tokens lapse within their short lifetime)."""
    u = _member(db, member_id, admin)
    security.revoke_all_refresh(db, u.id)
    audit.record(db, "members.revoke_sessions", request=request, user=admin,
                 detail={"member": u.email}, commit=False)
    db.commit()


@router.post("/{member_id}/unlock", status_code=204)
def unlock(member_id: int, request: Request,
           admin: models.User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    """Clear a login lockout for the member's account."""
    u = _member(db, member_id, admin)
    throttle.reset_email(u.email)
    audit.record(db, "members.unlock", request=request, user=admin, detail={"member": u.email})
