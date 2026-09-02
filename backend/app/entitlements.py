"""Licence and entitlements (L1): what this deployment may do, offline.

A licence is a compact signed token::

    GL1.<base64url(payload json)>.<base64url(ed25519 signature)>

signed by the vendor's private key and verified here with the vendor's public
key, so it works air-gapped and cannot be forged by editing a file. The
payload names a tier, optional extra features, seat limits, the customer, and
an expiry. After expiry there is a grace period during which everything keeps
working with a warning; after that the deployment degrades to the Community
tier. Data is never hidden by an expired licence — only paid features close.

Tiers and what they include are the product's pricing decision; the code only
enforces them. Community is what runs with no licence at all.
"""
from __future__ import annotations

import base64
import json
import os
from datetime import date, datetime, timedelta, timezone

from fastapi import Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import models
from .database import get_db
from .security import get_current_user

TIERS = ("community", "team", "education", "enterprise")

# Features by tier. A licence may add features beyond its tier.
TIER_FEATURES: dict[str, set[str]] = {
    "community": set(),
    "team": {"white_label", "content_packs", "telemetry_loop", "tracker_push"},
    "education": {"white_label", "content_packs", "telemetry_loop", "tracker_push", "education", "replay"},
    "enterprise": {"white_label", "content_packs", "telemetry_loop", "tracker_push", "education", "replay",
                   "partner_mode", "scim", "benchmark_cohort", "intel_feed"},
}
ALL_FEATURES = sorted(set().union(*TIER_FEATURES.values()))
FEATURE_LABELS = {
    "white_label": "White-label branding", "content_packs": "Content subscription", "telemetry_loop": "Telemetry loop",
    "tracker_push": "Jira / ServiceNow push", "education": "Education edition", "replay": "Session replay", "partner_mode": "Partner mode",
    "scim": "SCIM provisioning", "benchmark_cohort": "Instance benchmark cohort", "intel_feed": "Adversary intel feed",
}
GRACE_DAYS = 30
SETTING_KEY = "license"

# The vendor's Ed25519 public key (raw, base64url). Override for self-issued
# licences in development with GAUNTLET_LICENSE_PUBKEY.
VENDOR_PUBKEY_B64 = os.environ.get("GAUNTLET_LICENSE_PUBKEY", "")


class LicenseError(ValueError):
    pass


def _b64d(s: str) -> bytes:
    s = s.strip()
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _pubkey():
    b64 = os.environ.get("GAUNTLET_LICENSE_PUBKEY", VENDOR_PUBKEY_B64)
    if not b64:
        return None
    from cryptography.hazmat.primitives.asymmetric import ed25519
    return ed25519.Ed25519PublicKey.from_public_bytes(_b64d(b64))


def parse(token: str) -> dict:
    """Verify a licence token and return its payload. Raises LicenseError."""
    token = (token or "").strip()
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != "GL1":
        raise LicenseError("not a Gauntlet licence")
    pub = _pubkey()
    if pub is None:
        raise LicenseError("no licence public key is configured on this deployment")
    try:
        body, sig = _b64d(parts[1]), _b64d(parts[2])
        pub.verify(sig, body)
        payload = json.loads(body)
    except Exception as exc:  # noqa: BLE001 - any failure is "invalid"
        raise LicenseError("licence signature does not verify") from exc
    if payload.get("v") != 1 or payload.get("tier") not in TIERS:
        raise LicenseError("unsupported licence version or tier")
    try:
        date.fromisoformat(payload.get("exp", ""))
    except ValueError:
        raise LicenseError("licence has no valid expiry")
    return payload


def issue(private_key_b64: str, *, tier: str, customer: str, exp: str, features: list[str] | None = None,
          seats: dict | None = None, org: str = "*") -> str:
    """Vendor side: mint a licence. Used by tools/issue_license.py and tests."""
    from cryptography.hazmat.primitives.asymmetric import ed25519
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(_b64d(private_key_b64))
    payload = {"v": 1, "tier": tier, "customer": customer, "org": org, "exp": exp,
               "features": sorted(set(features or [])), "seats": seats or {},
               "issued": date.today().isoformat()}
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return f"GL1.{_b64e(body)}.{_b64e(priv.sign(body))}"


def keygen() -> tuple[str, str]:
    """Vendor side: a new Ed25519 keypair as (private_b64, public_b64)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    priv = ed25519.Ed25519PrivateKey.generate()
    pb = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    pu = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return _b64e(pb), _b64e(pu)


# --------------------------------------------------------------------------- #
# the active licence
# --------------------------------------------------------------------------- #
def stored_token(db: Session) -> str:
    row = db.get(models.InstanceSetting, SETTING_KEY)
    if row and row.value:
        return row.value
    return os.environ.get("GAUNTLET_LICENSE", "")


def store_token(db: Session, token: str | None) -> None:
    row = db.get(models.InstanceSetting, SETTING_KEY)
    if token is None:
        if row:
            db.delete(row)
        return
    if row is None:
        db.add(models.InstanceSetting(key=SETTING_KEY, value=token))
    else:
        row.value = token


def status(db: Session, today: date | None = None) -> dict:
    """The effective entitlement: tier, features, expiry state, seats."""
    today = today or datetime.now(timezone.utc).date()
    token = stored_token(db)
    base = {"tier": "community", "features": sorted(TIER_FEATURES["community"]), "licensed": False,
            "customer": "", "exp": None, "state": "community", "days_left": None, "seats": {}, "error": None}
    if not token:
        return base
    try:
        p = parse(token)
    except LicenseError as exc:
        return {**base, "error": str(exc), "state": "invalid"}
    exp = date.fromisoformat(p["exp"])
    days_left = (exp - today).days
    tier = p["tier"]
    features = set(TIER_FEATURES[tier]) | {f for f in (p.get("features") or []) if f in ALL_FEATURES}
    if days_left >= 0:
        state = "active"
    elif days_left >= -GRACE_DAYS:
        state = "grace"
    else:
        state, tier, features = "expired", "community", set(TIER_FEATURES["community"])
    return {"tier": tier, "features": sorted(features), "licensed": state in ("active", "grace"),
            "customer": p.get("customer", ""), "exp": p["exp"], "state": state, "days_left": days_left,
            "seats": p.get("seats") or {}, "error": None, "grace_days": GRACE_DAYS}


def has(db: Session, feature: str) -> bool:
    return feature in status(db)["features"]


def require_feature(feature: str):
    """Dependency: 402 with a plain message when the deployment lacks a feature."""
    label = FEATURE_LABELS.get(feature, feature)

    def _dep(user: models.User = Depends(get_current_user), db: Session = Depends(get_db)) -> models.User:
        st = status(db)
        if feature not in st["features"]:
            raise HTTPException(402, f"{label} is not included in this deployment's {st['tier']} tier; "
                                     f"see /api/license for what is enabled")
        return user
    return _dep


def seat_limit(db: Session, kind: str) -> int | None:
    seats = status(db).get("seats") or {}
    v = seats.get(kind)
    return int(v) if isinstance(v, (int, float)) and v > 0 else None


def check_seats(db: Session, org_id: int, role: str, adding: int = 1) -> None:
    """Facilitator seats are the unit of sale: refuse to exceed them."""
    if role not in ("admin", "facilitator"):
        return
    limit = seat_limit(db, "facilitators")
    if limit is None:
        return
    from sqlalchemy import func
    used = db.execute(select(func.count()).select_from(models.User).where(
        models.User.org_id == org_id, models.User.is_active.is_(True),
        models.User.partner_user_id.is_(None),  # a partner's shadows are the partner's seats, not the client's
        models.User.role.in_(("admin", "facilitator")))).scalar_one()
    if used + adding > limit:
        raise HTTPException(402, f"this licence allows {limit} facilitator seat(s); {used} are in use")
