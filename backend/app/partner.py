"""Partner mode (L2): one login, many client organisations, isolation kept.

A consultancy or managed security provider runs exercises for its clients. A
partner organisation creates client organisations and links to them; a partner
admin "enters" a client, which issues an ordinary session for a shadow admin
account that lives inside the client organisation. Every existing scope check
therefore still sees a user of the client org — nothing is widened — and the
client's audit log shows exactly who acted, marked as acting via the partner.
Removing the link deactivates the shadows. Enterprise feature.
"""
from __future__ import annotations

import re
import secrets

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import entitlements, models
from .security import hash_password


def _slug(name: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:60] or "client"
    return f"{base}-{secrets.token_hex(2)}"


def clients(db: Session, partner_org_id: int) -> list[models.Organization]:
    rows = db.execute(select(models.OrgLink).where(models.OrgLink.partner_org_id == partner_org_id)
                      .order_by(models.OrgLink.id)).scalars().all()
    out = []
    for link in rows:
        org = db.get(models.Organization, link.client_org_id)
        if org is not None:
            out.append(org)
    return out


def link_for(db: Session, partner_org_id: int, client_org_id: int) -> models.OrgLink | None:
    return db.execute(select(models.OrgLink).where(models.OrgLink.partner_org_id == partner_org_id,
                                                   models.OrgLink.client_org_id == client_org_id)).scalars().first()


def create_client(db: Session, partner_org_id: int, name: str, created_by: models.User) -> models.Organization:
    name = (name or "").strip()
    if not name:
        raise HTTPException(422, "name the client organisation")
    entitlements.check_client_seats(db, partner_org_id)
    org = models.Organization(name=name[:200], slug=_slug(name))
    db.add(org)
    db.flush()
    db.add(models.OrgLink(partner_org_id=partner_org_id, client_org_id=org.id, created_by=created_by.email))
    db.flush()
    return org


def shadow_email(user: models.User, client: models.Organization) -> str:
    local, _, domain = user.email.partition("@")
    return f"{local}+{client.slug}@{domain or 'partner.invalid'}"


def shadow_for(db: Session, user: models.User, client: models.Organization) -> models.User:
    """The partner user's admin account inside the client organisation, created on first entry."""
    if link_for(db, user.org_id, client.id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not a client of your organisation")
    if user.role != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "only partner admins may enter a client organisation")
    row = db.execute(select(models.User).where(models.User.partner_user_id == user.id,
                                               models.User.org_id == client.id)).scalars().first()
    if row is None:
        row = models.User(org_id=client.id, email=shadow_email(user, client), name=f"{user.name or user.email} (via {user.organization.name})",
                          role="admin", password_hash=hash_password(secrets.token_urlsafe(32)),
                          partner_user_id=user.id, is_active=True, email_verified_at=models._utcnow())
        db.add(row)
        db.flush()
    elif not row.is_active:
        row.is_active = True
    return row


def unlink(db: Session, partner_org_id: int, client_org_id: int) -> None:
    link = link_for(db, partner_org_id, client_org_id)
    if link is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not a client of your organisation")
    partner_user_ids = [u.id for u in db.execute(select(models.User).where(models.User.org_id == partner_org_id)).scalars()]
    for shadow in db.execute(select(models.User).where(models.User.org_id == client_org_id,
                                                        models.User.partner_user_id.in_(partner_user_ids))).scalars():
        shadow.is_active = False
    db.delete(link)
