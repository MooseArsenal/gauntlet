"""White-label branding and partner mode (L2)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from .. import audit, branding, entitlements, models, partner, schemas, security
from ..database import get_db
from ..security import get_current_user, require_role

router = APIRouter(tags=["partner"])


# ---- branding -------------------------------------------------------------- #
@router.get("/api/branding")
def get_branding(user: models.User | None = Depends(security.get_current_user_optional), db: Session = Depends(get_db)):
    """Effective branding for the caller's organisation (deployment defaults when signed out)."""
    return branding.for_org(db, user.org_id if user else None)


@router.put("/api/admin/branding")
def set_branding(payload: schemas.BrandingIn, request: Request,
                 admin: models.User = Depends(require_role("admin")), db: Session = Depends(get_db),
                 _f: models.User = Depends(entitlements.require_feature("white_label"))):
    org = db.get(models.Organization, admin.org_id)
    org.branding = branding.validate(payload.model_dump())
    flag_modified(org, "branding")
    audit.record(db, "branding.update", request=request, user=admin,
                 detail={k: v for k, v in org.branding.items() if k != "logo"} | {"logo": bool(org.branding.get("logo"))}, commit=False)
    db.commit()
    return branding.for_org(db, org.id)


@router.delete("/api/admin/branding", status_code=204)
def clear_branding(request: Request, admin: models.User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    org = db.get(models.Organization, admin.org_id)
    org.branding = {}
    flag_modified(org, "branding")
    audit.record(db, "branding.clear", request=request, user=admin, commit=False)
    db.commit()
    return None


# ---- partner mode ---------------------------------------------------------- #
@router.get("/api/partner/clients")
def list_clients(admin: models.User = Depends(require_role("admin")), db: Session = Depends(get_db),
                 _f: models.User = Depends(entitlements.require_feature("partner_mode"))):
    return {"partner": admin.organization.name,
            "clients": [{"id": o.id, "name": o.name, "slug": o.slug, "created_at": o.created_at} for o in partner.clients(db, admin.org_id)]}


@router.post("/api/partner/clients", status_code=201)
def create_client(payload: schemas.ClientIn, request: Request,
                  admin: models.User = Depends(require_role("admin")), db: Session = Depends(get_db),
                  _f: models.User = Depends(entitlements.require_feature("partner_mode"))):
    org = partner.create_client(db, admin.org_id, payload.name, admin)
    audit.record(db, "partner.client.create", request=request, user=admin, detail={"client_org_id": org.id, "name": org.name}, commit=False)
    db.commit()
    return {"id": org.id, "name": org.name, "slug": org.slug}


@router.post("/api/partner/clients/{client_id}/enter", response_model=schemas.TokenOut)
def enter_client(client_id: int, request: Request,
                 admin: models.User = Depends(require_role("admin")), db: Session = Depends(get_db),
                 _f: models.User = Depends(entitlements.require_feature("partner_mode"))):
    """Issue a session inside the client organisation for this partner admin's
    shadow account. Recorded in both organisations' audit logs."""
    client = db.get(models.Organization, client_id)
    if client is None:
        raise HTTPException(404, "not a client of your organisation")
    shadow = partner.shadow_for(db, admin, client)
    access = security.create_token(shadow)
    refresh = security.issue_refresh_token(db, shadow)
    audit.record(db, "partner.enter", request=request, user=admin, detail={"client_org_id": client.id, "as": shadow.email}, commit=False)
    audit.record(db, "partner.enter", request=request, user=shadow, org_id=client.id,
                 detail={"partner_org_id": admin.org_id, "partner_user": admin.email}, commit=False)
    db.commit()
    return schemas.TokenOut(access_token=access, refresh_token=refresh, user=schemas.UserOut.model_validate(shadow))


@router.delete("/api/partner/clients/{client_id}", status_code=204)
def unlink_client(client_id: int, request: Request,
                  admin: models.User = Depends(require_role("admin")), db: Session = Depends(get_db),
                  _f: models.User = Depends(entitlements.require_feature("partner_mode"))):
    partner.unlink(db, admin.org_id, client_id)
    audit.record(db, "partner.client.unlink", request=request, user=admin, detail={"client_org_id": client_id}, commit=False)
    db.commit()
    return None
