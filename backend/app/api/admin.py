"""Tenant data-protection administration (M10).

Admin-only, always scoped to the caller's own organisation:

* ``POST /api/admin/reencrypt`` — re-seal the org's environments under the
  current primary data key (used after a key rotation).
* ``POST /api/admin/retention/purge`` — delete completed sessions and audit
  entries older than the retention window.
* ``GET  /api/admin/export`` — download a full JSON snapshot (GDPR portability).
* ``DELETE /api/admin/org`` — erase the org and everything it owns (right to
  erasure); guarded by a slug confirmation.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from .. import audit, keys, models, retention, schemas
from ..config import RETENTION_DAYS
from ..database import get_db
from ..security import require_role

router = APIRouter(prefix="/api/admin", tags=["admin"])

_ENCRYPTED_COLUMNS = (
    "assets", "controls", "detections", "playbooks", "policies",
    "personnel", "deception_assets", "crown_jewels", "visibility",
)


@router.post("/reencrypt", response_model=schemas.ReencryptOut)
def reencrypt(
    request: Request,
    admin: models.User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Rewrite every environment so its sensitive fields are sealed under the
    current primary key. A no-op payload-wise, but it re-encrypts on flush."""
    if not keys.encryption_enabled():
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "encryption at rest is not enabled")
    envs = list(db.execute(
        select(models.Environment).where(models.Environment.org_id == admin.org_id)
    ).scalars())
    for env in envs:
        for col in _ENCRYPTED_COLUMNS:
            flag_modified(env, col)  # force a re-write even without a value change
    audit.record(db, "admin.reencrypt", request=request, user=admin,
                 detail={"environments": len(envs)}, commit=False)
    db.commit()
    return schemas.ReencryptOut(encryption_enabled=True, reencrypted=len(envs))


@router.post("/retention/purge", response_model=schemas.PurgeOut)
def purge(
    payload: schemas.PurgeIn,
    request: Request,
    admin: models.User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    days = payload.days if payload.days is not None else RETENTION_DAYS
    result = retention.purge_org(db, admin.org_id, days)
    audit.record(db, "admin.retention.purge", request=request, user=admin,
                 detail={**result, "days": days}, commit=False)
    db.commit()
    return schemas.PurgeOut(days=days, **result)


@router.get("/export")
def export_org(
    request: Request,
    admin: models.User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    data = retention.export_org(db, admin.org_id)
    audit.record(db, "admin.export", request=request, user=admin,
                 detail={"counts": {k: len(v) for k, v in data.items() if isinstance(v, list)}})
    return data


@router.delete("/org", response_model=schemas.EraseOut)
def erase_org(
    payload: schemas.EraseIn,
    request: Request,
    admin: models.User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Irreversibly delete the caller's organisation and all its data.

    Requires ``confirm`` to equal the org slug — a deliberate speed bump on an
    unrecoverable action."""
    org = db.get(models.Organization, admin.org_id)
    if org is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
    if payload.confirm != org.slug:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "confirmation does not match the organisation slug")
    # Record the erasure to the app log before the org's own audit rows go with it.
    audit.record(db, "admin.org.erase", request=request, user=admin,
                 detail={"org": org.slug}, commit=True)
    counts = retention.erase_org(db, admin.org_id)
    db.commit()
    return schemas.EraseOut(erased=counts)


# --------------------------------------------------------------------------- #
# SCIM provisioning token (M5)
# --------------------------------------------------------------------------- #
@router.post("/scim-token", response_model=schemas.ScimTokenOut)
def mint_scim_token(request: Request, admin: models.User = Depends(require_role("admin")),
                    db: Session = Depends(get_db)):
    """Mint (or rotate) the organisation's SCIM bearer token. Shown once;
    only its hash is stored. Configure it in the identity provider with the
    base URL ``<host>/scim/v2``."""
    from .scim import hash_token, mint_token
    raw = mint_token()
    org = db.get(models.Organization, admin.org_id)
    org.scim_token_hash = hash_token(raw)
    audit.record(db, "scim.token.mint", request=request, user=admin, detail={"org_id": org.id}, commit=False)
    db.commit()
    base = f"{request.base_url.scheme}://{request.base_url.netloc}/scim/v2"
    return schemas.ScimTokenOut(token=raw, base_url=base)


@router.delete("/scim-token", status_code=204)
def revoke_scim_token(request: Request, admin: models.User = Depends(require_role("admin")),
                      db: Session = Depends(get_db)):
    org = db.get(models.Organization, admin.org_id)
    org.scim_token_hash = None
    audit.record(db, "scim.token.revoke", request=request, user=admin, detail={"org_id": org.id}, commit=False)
    db.commit()
