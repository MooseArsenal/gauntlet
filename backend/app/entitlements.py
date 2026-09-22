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

import json
import os
import secrets
from datetime import date, datetime, timedelta, timezone

from fastapi import Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import models, signing
from .database import get_db
from .security import get_current_user

TIERS = ("community", "team", "education", "enterprise")

# Features by tier. A licence may add features beyond its tier.
#
# Education is a classroom product, not a discounted Team: it carries the
# education edition, replay and white-label, and none of the programme
# features (telemetry loop, tracker push, content subscription). Enterprise
# is Team and Education together plus the enterprise-only features.
TIER_FEATURES: dict[str, set[str]] = {
    "community": set(),
    "team": {"white_label", "content_packs", "telemetry_loop", "tracker_push"},
    "education": {"white_label", "education", "replay"},
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
# Seat kinds a licence may cap. "facilitators" counts admins and facilitators
# (instructors, on Education); "clients" counts the client organisations a
# partner may link (Enterprise includes five; more are sold per client).
SEAT_KINDS = ("facilitators", "clients")
PARTNER_CLIENTS_INCLUDED = 5

# Trust anchors (which vendor public keys are trusted, and key rotation) live
# in signing.py; the deployment never trusts a key an environment variable
# names in production unless GAUNTLET_TRUST_ENV_KEYS=1 is chosen on purpose.
REVOCATION_KEY = "license_revocations"
MAX_TOKEN_CHARS = 8000


class LicenseError(ValueError):
    pass


_b64d = signing.b64d
_b64e = signing.b64e
keygen = signing.keygen


def _unverified_payload(part: str) -> dict:
    """Read the payload before verifying — only to learn which key to use."""
    try:
        p = json.loads(_b64d(part))
    except Exception as exc:  # noqa: BLE001
        raise LicenseError("licence payload is not readable") from exc
    return p if isinstance(p, dict) else {}


def parse(token: str) -> dict:
    """Verify a licence token and return its payload. Raises LicenseError."""
    token = (token or "").strip()
    if len(token) > MAX_TOKEN_CHARS:
        raise LicenseError("licence token is too long")
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != "GL1":
        raise LicenseError("not a Gauntlet licence")
    hint = _unverified_payload(parts[1])
    try:
        body, sig = _b64d(parts[1]), _b64d(parts[2])
        kid = signing.verify("license", body, sig, hint.get("kid"))
        payload = json.loads(body)
    except ValueError as exc:
        raise LicenseError(f"licence signature does not verify: {exc}") from exc
    except Exception as exc:  # noqa: BLE001 - any failure is "invalid"
        raise LicenseError("licence signature does not verify") from exc
    if payload.get("v") not in (1, 2) or payload.get("tier") not in TIERS:
        raise LicenseError("unsupported licence version or tier")
    try:
        date.fromisoformat(payload.get("exp", ""))
    except ValueError:
        raise LicenseError("licence has no valid expiry")
    payload["kid"] = kid
    payload.setdefault("serial", "")
    return payload


def issue(private_key_b64: str, *, tier: str, customer: str, exp: str, features: list[str] | None = None,
          seats: dict | None = None, org: str = "*", serial: str | None = None) -> str:
    """Vendor side: mint a licence. Used by tools/issue_license.py and tests.
    Every licence carries a random serial (for revocation) and the key id."""
    pub = signing.public_of(private_key_b64)
    payload = {"v": 2, "kid": signing.kid_for(pub), "serial": serial or secrets.token_hex(8),
               "tier": tier, "customer": customer, "org": org, "exp": exp,
               "features": sorted(set(features or [])), "seats": seats or {},
               "issued": date.today().isoformat()}
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return f"GL1.{_b64e(body)}.{_b64e(signing.sign(private_key_b64, body))}"


# --------------------------------------------------------------------------- #
# revocation lists: GR1.<payload>.<sig>, {"v":1,"kid":..,"issued":..,"revoked":[serials]}
# --------------------------------------------------------------------------- #
def issue_revocations(private_key_b64: str, serials: list[str], *, issued: str | None = None) -> str:
    pub = signing.public_of(private_key_b64)
    payload = {"v": 1, "kid": signing.kid_for(pub), "issued": issued or date.today().isoformat(),
               "revoked": sorted({s.strip() for s in serials if s.strip()})}
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return f"GR1.{_b64e(body)}.{_b64e(signing.sign(private_key_b64, body))}"


def parse_revocations(token: str) -> dict:
    token = (token or "").strip()
    if len(token) > 64 * 1024:
        raise LicenseError("revocation list is too long")
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != "GR1":
        raise LicenseError("not a Gauntlet revocation list")
    hint = _unverified_payload(parts[1])
    try:
        body, sig = _b64d(parts[1]), _b64d(parts[2])
        signing.verify("license", body, sig, hint.get("kid"))
        payload = json.loads(body)
    except ValueError as exc:
        raise LicenseError(f"revocation list does not verify: {exc}") from exc
    except Exception as exc:  # noqa: BLE001
        raise LicenseError("revocation list does not verify") from exc
    if payload.get("v") != 1 or not isinstance(payload.get("revoked"), list):
        raise LicenseError("unsupported revocation list")
    return payload


def stored_revocations(db: Session) -> str:
    row = db.get(models.InstanceSetting, REVOCATION_KEY)
    if row and row.value:
        return row.value
    return os.environ.get("GAUNTLET_LICENSE_REVOCATIONS", "")


def store_revocations(db: Session, token: str | None) -> None:
    row = db.get(models.InstanceSetting, REVOCATION_KEY)
    if token is None:
        if row:
            db.delete(row)
        return
    if row is None:
        db.add(models.InstanceSetting(key=REVOCATION_KEY, value=token))
    else:
        row.value = token


def revocations(db: Session) -> dict:
    """The installed revocation list, or an empty one; a list that no longer
    verifies is reported and ignored."""
    tok = stored_revocations(db)
    if not tok:
        return {"revoked": [], "issued": None, "error": None}
    try:
        p = parse_revocations(tok)
        return {"revoked": p["revoked"], "issued": p.get("issued"), "error": None}
    except LicenseError as exc:
        return {"revoked": [], "issued": None, "error": str(exc)}


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
    rev = revocations(db)
    if p.get("serial") and p["serial"] in rev["revoked"]:
        return {**base, "customer": p.get("customer", ""), "exp": p["exp"], "serial": p["serial"], "kid": p["kid"],
                "state": "revoked", "error": "this licence has been revoked", "revocations": rev}
    if days_left >= 0:
        state = "active"
    elif days_left >= -GRACE_DAYS:
        state = "grace"
    else:
        state, tier, features = "expired", "community", set(TIER_FEATURES["community"])
    return {"tier": tier, "features": sorted(features), "licensed": state in ("active", "grace"),
            "customer": p.get("customer", ""), "exp": p["exp"], "state": state, "days_left": days_left,
            "seats": p.get("seats") or {}, "error": None, "grace_days": GRACE_DAYS,
            "serial": p.get("serial", ""), "kid": p["kid"], "revocations": rev}


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


def check_client_seats(db: Session, partner_org_id: int, adding: int = 1) -> None:
    """Partner mode: the number of client organisations a partner may link is
    a seat in the licence (``seats.clients``). A licence without the cap is
    unlimited, as before; the packaging page says what Enterprise includes."""
    limit = seat_limit(db, "clients")
    if limit is None:
        return
    from sqlalchemy import func
    used = db.execute(select(func.count()).select_from(models.OrgLink).where(
        models.OrgLink.partner_org_id == partner_org_id)).scalar_one()
    if used + adding > limit:
        raise HTTPException(402, f"this licence allows {limit} client organisation(s) in partner mode; {used} are linked. "
                                 "Additional clients are added to the licence per client.")
