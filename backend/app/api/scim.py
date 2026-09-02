"""SCIM 2.0 user provisioning (M5).

Enterprise identity providers (Okta, Entra ID, OneLogin, JumpCloud) create,
update and deactivate users over SCIM. This is the subset they actually call:
ServiceProviderConfig, ResourceTypes, Schemas, and Users with filter, create,
read, replace, patch and delete. Deprovisioning deactivates (never deletes)
so the audit trail and the exercise record keep their author.

Authentication is a per-organisation bearer token an admin mints at
``POST /api/admin/scim-token``; only its SHA-256 is stored. Provisioned users
have no usable password — they sign in through SSO (OIDC) or an admin sets one.
"""
from __future__ import annotations

import hashlib
import re
import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import audit, models, security
from ..database import get_db

router = APIRouter(prefix="/scim/v2", tags=["scim"])

SCIM_USER = "urn:ietf:params:scim:schemas:core:2.0:User"
SCIM_LIST = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
SCIM_PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
SCIM_ERROR = "urn:ietf:params:scim:api:messages:2.0:Error"
MIME = "application/scim+json"
_FILTER = re.compile(r'^\s*(userName|externalId)\s+eq\s+"([^"]*)"\s*$', re.I)


def hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def mint_token() -> str:
    return "gscim_" + secrets.token_urlsafe(32)


class ScimError(HTTPException):
    def __init__(self, status: int, detail: str, scim_type: str | None = None):
        super().__init__(status, detail)
        self.scim_type = scim_type


def _error(exc: ScimError) -> JSONResponse:
    body = {"schemas": [SCIM_ERROR], "status": str(exc.status_code), "detail": exc.detail}
    if exc.scim_type:
        body["scimType"] = exc.scim_type
    return JSONResponse(body, status_code=exc.status_code, media_type=MIME)


def scim_org(request: Request, db: Session = Depends(get_db)) -> models.Organization:
    from .. import entitlements  # L1: SCIM is an Enterprise feature
    if not entitlements.has(db, "scim"):
        raise ScimError(402, "SCIM provisioning is not included in this deployment's licence tier")
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise ScimError(401, "bearer token required")
    raw = auth[7:].strip()
    org = db.execute(
        select(models.Organization).where(models.Organization.scim_token_hash == hash_token(raw))
    ).scalars().first() if raw else None
    if org is None:
        raise ScimError(401, "invalid SCIM token")
    security._bind_tenant(db, org.id)
    return org


def _resource(u: models.User, request: Request) -> dict:
    first, _, last = (u.name or "").partition(" ")
    base = str(request.base_url).rstrip("/")
    return {
        "schemas": [SCIM_USER],
        "id": str(u.id),
        "externalId": u.scim_external_id,
        "userName": u.email,
        "name": {"formatted": u.name or "", "givenName": first, "familyName": last},
        "displayName": u.name or "",
        "emails": [{"value": u.email, "primary": True, "type": "work"}],
        "active": bool(u.is_active),
        "roles": [{"value": u.role, "primary": True}],
        "meta": {"resourceType": "User",
                 "created": (u.created_at or datetime.now(timezone.utc)).isoformat(),
                 "location": f"{base}/scim/v2/Users/{u.id}"},
    }


def _json(body: dict, status: int = 200) -> JSONResponse:
    return JSONResponse(body, status_code=status, media_type=MIME)


def _user(db: Session, org: models.Organization, user_id: str) -> models.User:
    try:
        uid = int(user_id)
    except ValueError:
        raise ScimError(404, "user not found")
    u = db.get(models.User, uid)
    if u is None or u.org_id != org.id:
        raise ScimError(404, "user not found")
    return u


def _role_of(body: dict, default: str = "participant") -> str:
    roles = body.get("roles") or []
    for r in roles:
        v = (r.get("value") if isinstance(r, dict) else r) or ""
        if v in models.ROLES:
            return v
    return default


def _name_of(body: dict) -> str:
    n = body.get("name") or {}
    if isinstance(n, dict):
        formatted = n.get("formatted") or " ".join(x for x in (n.get("givenName"), n.get("familyName")) if x)
        if formatted:
            return formatted[:160]
    return (body.get("displayName") or "")[:160]


def _email_of(body: dict) -> str:
    email = (body.get("userName") or "").strip().lower()
    if not email:
        for e in body.get("emails") or []:
            v = (e.get("value") if isinstance(e, dict) else e) or ""
            if v:
                email = v.strip().lower()
                break
    if not email or "@" not in email or len(email) > 200:
        raise ScimError(400, "userName must be an email address", "invalidValue")
    return email


def _admin_count(db: Session, org_id: int) -> int:
    return db.execute(select(func.count()).select_from(models.User).where(
        models.User.org_id == org_id, models.User.role == "admin", models.User.is_active.is_(True))).scalar_one()


def _deactivate(db: Session, org: models.Organization, u: models.User) -> None:
    if u.is_active and u.role == "admin" and _admin_count(db, org.id) <= 1:
        raise ScimError(409, "this is the organisation's only active admin", "mutability")
    u.is_active = False
    security.revoke_all_refresh(db, u.id)


@router.get("/ServiceProviderConfig")
def service_provider_config(org: models.Organization = Depends(scim_org)):
    return _json({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "patch": {"supported": True}, "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": 200}, "changePassword": {"supported": False},
        "sort": {"supported": False}, "etag": {"supported": False},
        "authenticationSchemes": [{"type": "oauthbearertoken", "name": "Bearer token",
                                   "description": "Per-organisation token minted by an admin"}],
    })


@router.get("/ResourceTypes")
def resource_types(org: models.Organization = Depends(scim_org)):
    return _json({"schemas": [SCIM_LIST], "totalResults": 1, "Resources": [
        {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"], "id": "User", "name": "User",
         "endpoint": "/Users", "schema": SCIM_USER}]})


@router.get("/Schemas")
def schemas_(org: models.Organization = Depends(scim_org)):
    return _json({"schemas": [SCIM_LIST], "totalResults": 1, "Resources": [
        {"id": SCIM_USER, "name": "User", "attributes": [
            {"name": "userName", "type": "string", "required": True, "uniqueness": "server"},
            {"name": "name", "type": "complex"}, {"name": "active", "type": "boolean"},
            {"name": "emails", "type": "complex", "multiValued": True},
            {"name": "roles", "type": "complex", "multiValued": True},
            {"name": "externalId", "type": "string"}]}]})


@router.get("/Users")
def list_users(request: Request, filter: str | None = None, startIndex: int = 1, count: int = 100,
               org: models.Organization = Depends(scim_org), db: Session = Depends(get_db)):
    q = select(models.User).where(models.User.org_id == org.id).order_by(models.User.id)
    if filter:
        m = _FILTER.match(filter)
        if not m:
            raise ScimError(400, "only 'userName eq \"…\"' and 'externalId eq \"…\"' filters are supported", "invalidFilter")
        attr, value = m.group(1).lower(), m.group(2)
        q = q.where(models.User.email == value.lower()) if attr == "username" else q.where(models.User.scim_external_id == value)
    rows = db.execute(q).scalars().all()
    start = max(startIndex, 1)
    page = rows[start - 1:start - 1 + max(min(count, 200), 0)]
    return _json({"schemas": [SCIM_LIST], "totalResults": len(rows), "startIndex": start,
                  "itemsPerPage": len(page), "Resources": [_resource(u, request) for u in page]})


@router.post("/Users")
async def create_user(request: Request, org: models.Organization = Depends(scim_org), db: Session = Depends(get_db)):
    body = await request.json()
    email = _email_of(body)
    if db.execute(select(models.User).where(models.User.email == email)).scalars().first() is not None:
        raise ScimError(409, "userName already exists", "uniqueness")
    from .. import entitlements  # L1: facilitator seats
    entitlements.check_seats(db, org.id, _role_of(body))
    u = models.User(org_id=org.id, email=email, name=_name_of(body), role=_role_of(body),
                    is_active=bool(body.get("active", True)), scim_external_id=(body.get("externalId") or None),
                    password_hash=security.hash_password(secrets.token_urlsafe(24)))
    db.add(u)
    db.flush()
    audit.record(db, "scim.user.create", request=request, user=None, org_id=org.id, actor_email="scim",
                 detail={"member": u.email, "role": u.role}, commit=False)
    db.commit()
    db.refresh(u)
    return _json(_resource(u, request), 201)


@router.get("/Users/{user_id}")
def get_user(user_id: str, request: Request, org: models.Organization = Depends(scim_org), db: Session = Depends(get_db)):
    return _json(_resource(_user(db, org, user_id), request))


def _apply(db: Session, org: models.Organization, u: models.User, body: dict, request: Request, action: str) -> None:
    changes = {}
    if "userName" in body or "emails" in body:
        email = _email_of(body)
        if email != u.email:
            if db.execute(select(models.User).where(models.User.email == email)).scalars().first() is not None:
                raise ScimError(409, "userName already exists", "uniqueness")
            u.email = email; changes["email"] = email
    if "name" in body or "displayName" in body:
        u.name = _name_of(body); changes["name"] = u.name
    if "roles" in body:
        role = _role_of(body, u.role)
        if role != u.role:
            if u.role == "admin" and u.is_active and _admin_count(db, org.id) <= 1:
                raise ScimError(409, "this is the organisation's only active admin", "mutability")
            u.role = role; changes["role"] = role
    if "externalId" in body:
        u.scim_external_id = body.get("externalId") or None
    if "active" in body:
        active = body["active"] in (True, "true", "True")
        if active != u.is_active:
            if active:
                u.is_active = True
            else:
                _deactivate(db, org, u)
            changes["is_active"] = active
    audit.record(db, action, request=request, user=None, org_id=org.id, actor_email="scim",
                 detail={"member": u.email, **changes}, commit=False)
    db.commit()
    db.refresh(u)


@router.put("/Users/{user_id}")
async def replace_user(user_id: str, request: Request, org: models.Organization = Depends(scim_org), db: Session = Depends(get_db)):
    u = _user(db, org, user_id)
    body = await request.json()
    _apply(db, org, u, body, request, "scim.user.replace")
    return _json(_resource(u, request))


@router.patch("/Users/{user_id}")
async def patch_user(user_id: str, request: Request, org: models.Organization = Depends(scim_org), db: Session = Depends(get_db)):
    u = _user(db, org, user_id)
    body = await request.json()
    merged: dict = {}
    for op in body.get("Operations") or []:
        kind = (op.get("op") or "").lower()
        path = (op.get("path") or "").strip()
        value = op.get("value")
        if kind not in ("replace", "add"):
            raise ScimError(400, f"unsupported op '{kind}'", "invalidValue")
        if not path and isinstance(value, dict):
            merged.update(value)
        elif path.lower() == "active":
            merged["active"] = value
        elif path.lower() in ("username", "externalid", "displayname"):
            merged[{"username": "userName", "externalid": "externalId", "displayname": "displayName"}[path.lower()]] = value
        elif path.lower().startswith("name."):
            merged.setdefault("name", dict(merged.get("name") or {}))[path.split(".", 1)[1]] = value
        elif path.lower() == "name" and isinstance(value, dict):
            merged["name"] = value
        elif path.lower() == "roles":
            merged["roles"] = value if isinstance(value, list) else [value]
        else:
            raise ScimError(400, f"unsupported path '{path}'", "invalidPath")
    if "name" in merged and isinstance(merged["name"], dict) and "formatted" not in merged["name"]:
        merged["name"] = {**{"givenName": (u.name or "").partition(" ")[0], "familyName": (u.name or "").partition(" ")[2]}, **merged["name"]}
    _apply(db, org, u, merged, request, "scim.user.patch")
    return _json(_resource(u, request))


@router.delete("/Users/{user_id}", status_code=204)
def delete_user(user_id: str, request: Request, org: models.Organization = Depends(scim_org), db: Session = Depends(get_db)):
    """Deprovision = deactivate. The record stays for the audit trail."""
    u = _user(db, org, user_id)
    if u.is_active:
        _deactivate(db, org, u)
        audit.record(db, "scim.user.deactivate", request=request, user=None, org_id=org.id, actor_email="scim",
                     detail={"member": u.email}, commit=False)
        db.commit()
    return Response(status_code=204)
