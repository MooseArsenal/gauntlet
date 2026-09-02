"""Licence status and management (L1)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .. import audit, entitlements, models, schemas
from ..database import get_db
from ..security import get_current_user, require_role

router = APIRouter(tags=["license"])


@router.get("/api/license")
def license_status(user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    """What this deployment is entitled to. Any signed-in user may read it so
    the console can show what is locked and why."""
    st = entitlements.status(db)
    return {**st, "labels": entitlements.FEATURE_LABELS, "all_features": entitlements.ALL_FEATURES}


@router.post("/api/admin/license")
def install_license(payload: schemas.LicenseIn, request: Request,
                    admin: models.User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    try:
        p = entitlements.parse(payload.token)
    except entitlements.LicenseError as exc:
        raise HTTPException(422, str(exc))
    entitlements.store_token(db, payload.token.strip())
    audit.record(db, "license.install", request=request, user=admin,
                 detail={"tier": p["tier"], "customer": p.get("customer"), "exp": p["exp"]}, commit=False)
    db.commit()
    return entitlements.status(db)


@router.delete("/api/admin/license", status_code=204)
def remove_license(request: Request, admin: models.User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    entitlements.store_token(db, None)
    audit.record(db, "license.remove", request=request, user=admin, commit=False)
    db.commit()
    return None
