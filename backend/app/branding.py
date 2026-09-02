"""White-label branding (L2): the console and every PDF in the customer's name.

Branding lives on the organisation (name, accent colour, tagline, a small
logo, a report footer) and is a Team-tier feature. Without it, or without a
licence, the deployment defaults apply (GAUNTLET_BRAND_NAME / _ACCENT). The
banner strip's safety line ("no production access") is never rebranded away.
"""
from __future__ import annotations

import re

from fastapi import HTTPException
from sqlalchemy.orm import Session

from . import models
from .config import BRAND_ACCENT, BRAND_NAME

MAX_LOGO_BYTES = 64 * 1024
_HEX = re.compile(r"^#?([0-9a-fA-F]{6})$")
_DATA_URL = re.compile(r"^data:image/(png|jpeg|webp|svg\+xml);base64,[A-Za-z0-9+/=]+$")


def _accent_rgb(value: str | None) -> tuple[int, int, int]:
    if not value:
        return tuple(int(x) for x in BRAND_ACCENT.split(",")[:3])  # type: ignore[return-value]
    m = _HEX.match(value.strip())
    if not m:
        return tuple(int(x) for x in BRAND_ACCENT.split(",")[:3])  # type: ignore[return-value]
    h = m.group(1)
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def defaults() -> dict:
    r, g, b = _accent_rgb(None)
    return {"name": BRAND_NAME, "accent": "#%02x%02x%02x" % (r, g, b), "tagline": "Exercise control",
            "logo": "", "footer": "", "custom": False}


def validate(data: dict) -> dict:
    out = {}
    name = str(data.get("name") or "").strip()
    if len(name) > 60:
        raise HTTPException(422, "name is at most 60 characters")
    out["name"] = name
    accent = str(data.get("accent") or "").strip()
    if accent and not _HEX.match(accent):
        raise HTTPException(422, "accent must be a hex colour like #2F5D7C")
    out["accent"] = ("#" + _HEX.match(accent).group(1).lower()) if accent else ""
    tagline = str(data.get("tagline") or "").strip()
    if len(tagline) > 80:
        raise HTTPException(422, "tagline is at most 80 characters")
    out["tagline"] = tagline
    logo = str(data.get("logo") or "").strip()
    if logo:
        if not _DATA_URL.match(logo):
            raise HTTPException(422, "logo must be a data URL of a PNG, JPEG, WebP or SVG image")
        if len(logo) > MAX_LOGO_BYTES * 4 // 3 + 64:
            raise HTTPException(413, f"logo is capped at {MAX_LOGO_BYTES} bytes")
    out["logo"] = logo
    footer = str(data.get("footer") or "").strip()
    if len(footer) > 200:
        raise HTTPException(422, "footer is at most 200 characters")
    out["footer"] = footer
    return out


def for_org(db: Session, org_id: int | None) -> dict:
    """Effective branding for an organisation: its own when licensed, else defaults."""
    base = defaults()
    if org_id is None:
        return base
    from . import entitlements
    org = db.get(models.Organization, org_id)
    custom = (org.branding if org else None) or {}
    if not custom or not entitlements.has(db, "white_label"):
        return base
    out = dict(base)
    for k in ("name", "accent", "tagline", "logo", "footer"):
        if custom.get(k):
            out[k] = custom[k]
    out["custom"] = True
    return out


def pdf_args(db: Session, org_id: int | None) -> dict:
    """What the PDF renderer needs: brand name and accent RGB."""
    b = for_org(db, org_id)
    return {"brand": b["name"], "accent": _accent_rgb(b["accent"]), "footer": b.get("footer", "")}
