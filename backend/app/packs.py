"""Signed content packs (L5): scenario packs and the adversary intel feed.

A pack is one compact signed token::

    GP1.<base64url(zlib(manifest json))>.<base64url(ed25519 signature)>

signed by the publisher's private key and verified here with the pack public
key (``GAUNTLET_PACK_PUBKEY``, defaulting to the licence key), so a pack can
travel on a USB stick into an air-gapped deployment and still be trusted —
and cannot be altered on the way. Two kinds:

* ``scenarios`` — items are scenario documents in the same shape as the YAML
  export, each naming the library environment it was written for (or bound
  to an environment the installer chooses). Feature ``content_packs``.
* ``intel`` — items are adversary profiles with notes, techniques, sectors and
  a kill chain; they become custom adversaries (upserted by key, so a newer
  pack updates them) and a dated feed the console shows. Feature
  ``intel_feed``.

Installing records the pack (id, version, digest, what it carried) per
organisation; installing the same version twice is refused, a newer version
updates the record and its content. Removing the record never deletes the
scenarios or adversaries it created — they are the organisation's now.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import zlib
from datetime import date, datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import entitlements, models, scenario_io
from .authoring import designer
from .authoring import environments as env_library
from .authoring.catalog import THREAT_ACTORS
from .entitlements import _b64d, _b64e

FORMAT = "GP1"
KINDS = ("scenarios", "intel")
FEATURE_FOR = {"scenarios": "content_packs", "intel": "intel_feed"}
MAX_TOKEN_BYTES = 4 * 1024 * 1024
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_ITEMS = 200
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,79}$")


class PackError(ValueError):
    pass


def _pubkey():
    b64 = os.environ.get("GAUNTLET_PACK_PUBKEY", "")
    if not b64:
        return entitlements._pubkey()
    from cryptography.hazmat.primitives.asymmetric import ed25519
    return ed25519.Ed25519PublicKey.from_public_bytes(_b64d(b64))


def sign(private_key_b64: str, manifest: dict) -> str:
    """Publisher side: sign a manifest. Used by tools/build_pack.py and tests."""
    from cryptography.hazmat.primitives.asymmetric import ed25519
    check_manifest(manifest)
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(_b64d(private_key_b64))
    body = zlib.compress(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode(), 9)
    return f"{FORMAT}.{_b64e(body)}.{_b64e(priv.sign(body))}"


def check_manifest(m: dict) -> None:
    if not isinstance(m, dict) or m.get("v") != 1:
        raise PackError("unsupported pack version")
    if m.get("kind") not in KINDS:
        raise PackError(f"pack kind must be one of {list(KINDS)}")
    if not isinstance(m.get("id"), str) or not _ID_RE.match(m["id"]):
        raise PackError("pack id must be a short lowercase slug")
    for k in ("name", "version", "publisher"):
        if not isinstance(m.get(k), str) or not m[k].strip() or len(m[k]) > 200:
            raise PackError(f"pack {k} is missing")
    try:
        date.fromisoformat(m.get("issued", ""))
    except (TypeError, ValueError):
        raise PackError("pack has no valid issue date")
    items = m.get("items")
    if not isinstance(items, list) or not items:
        raise PackError("pack has no items")
    if len(items) > MAX_ITEMS:
        raise PackError(f"pack has too many items ({len(items)} > {MAX_ITEMS})")
    for i, it in enumerate(items):
        if not isinstance(it, dict):
            raise PackError(f"item {i} is not an object")
        if m["kind"] == "scenarios":
            sc = it.get("scenario")
            if not isinstance(sc, dict):
                raise PackError(f"item {i} has no scenario")
            errs = scenario_io.validate(sc)["errors"]
            if errs:
                raise PackError(f"item {i} ({sc.get('name', '?')}): " + "; ".join(errs))
        else:
            if not isinstance(it.get("key"), str) or not _ID_RE.match(it["key"]):
                raise PackError(f"item {i} needs a slug key")
            if not isinstance(it.get("name"), str) or not it["name"].strip():
                raise PackError(f"item {i} needs a name")


def verify(token: str) -> tuple[dict, str]:
    """Verify a token; return (manifest, digest). Raises PackError."""
    token = (token or "").strip()
    if len(token) > MAX_TOKEN_BYTES:
        raise PackError("pack is too large")
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != FORMAT:
        raise PackError("not a Gauntlet content pack")
    pub = _pubkey()
    if pub is None:
        raise PackError("no pack public key is configured on this deployment")
    try:
        body, sig = _b64d(parts[1]), _b64d(parts[2])
        pub.verify(sig, body)
    except Exception as exc:  # noqa: BLE001 - any failure is "invalid"
        raise PackError("pack signature does not verify") from exc
    try:
        raw = zlib.decompressobj().decompress(body, MAX_MANIFEST_BYTES + 1)
        if len(raw) > MAX_MANIFEST_BYTES:
            raise PackError("pack manifest is too large")
        manifest = json.loads(raw)
    except PackError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise PackError("pack manifest is not readable") from exc
    check_manifest(manifest)
    return manifest, hashlib.sha256(body).hexdigest()


def summary(manifest: dict, digest: str = "") -> dict:
    """What the installer sees before saying yes."""
    items = []
    for it in manifest["items"]:
        if manifest["kind"] == "scenarios":
            sc = it["scenario"]
            items.append({"title": sc.get("name", ""), "threat_actor": sc.get("threat_actor", ""),
                          "injects": len(sc.get("injects") or []), "objectives": len(sc.get("objectives") or []),
                          "environment_key": it.get("environment_key") or ""})
        else:
            items.append({"key": it["key"], "title": it["name"], "headline": str(it.get("headline") or "")[:300],
                          "notes": str(it.get("notes") or "")[:4000], "published": str(it.get("published") or ""),
                          "sectors": list(it.get("sectors") or [])[:20], "techniques": list(it.get("techniques") or [])[:60],
                          "references": [str(r)[:300] for r in (it.get("references") or [])][:10]})
    return {"id": manifest["id"], "kind": manifest["kind"], "name": manifest["name"], "version": manifest["version"],
            "publisher": manifest["publisher"], "issued": manifest["issued"], "count": len(items),
            "feature": FEATURE_FOR[manifest["kind"]], "digest": digest, "items": items}


def _require(db: Session, kind: str) -> None:
    feature = FEATURE_FOR[kind]
    if not entitlements.has(db, feature):
        raise HTTPException(402, f"{entitlements.FEATURE_LABELS[feature]} is not included in this deployment's "
                                 f"{entitlements.status(db)['tier']} tier")


def _resolve_env(db: Session, user: models.User, item: dict, environment_id: int | None) -> models.Environment:
    if environment_id is not None:
        env = db.get(models.Environment, environment_id)
        if env is None or env.org_id != user.org_id or env.archived_at is not None:
            raise HTTPException(404, "environment not found")
        return env
    key = item.get("environment_key") or ""
    if key not in env_library.ENVIRONMENT_TEMPLATES:
        raise HTTPException(400, f"scenario '{item['scenario'].get('name', '?')}' names no library environment; "
                                 "choose an environment to bind it to")
    tpl_name = env_library.ENVIRONMENT_TEMPLATES[key]["name"]
    env = db.execute(select(models.Environment).where(
        models.Environment.org_id == user.org_id, models.Environment.name == tpl_name,
        models.Environment.archived_at.is_(None))).scalars().first()
    if env is None:
        env = env_library.build_from_template(key)
        env.org_id = user.org_id
        db.add(env)
        db.flush()
    return env


def _upsert_adversary(db: Session, org_id: int, it: dict) -> tuple[models.CustomAdversary, str, list[str]]:
    key = it["key"]
    warnings: list[str] = []
    if key in THREAT_ACTORS:
        key = f"{key}-intel"
    kill_chain = [str(k) for k in (it.get("kill_chain") or [])]
    if kill_chain and designer.validate_kill_chain(kill_chain):
        warnings.append(f"{it['name']}: kill chain names scenes this build does not know; left empty")
        kill_chain = []
    objectives = [{"title": str(o.get("title", "")), "success_criteria": str(o.get("success_criteria", ""))}
                  for o in (it.get("objectives") or []) if isinstance(o, dict) and o.get("title")]
    if not objectives and kill_chain:
        objectives = [{"title": t, "success_criteria": c} for t, c in designer.default_objectives(kill_chain)]
    row = db.execute(select(models.CustomAdversary).where(
        models.CustomAdversary.org_id == org_id, models.CustomAdversary.key == key)).scalar_one_or_none()
    action = "updated" if row else "created"
    if row is None:
        row = models.CustomAdversary(org_id=org_id, key=key)
        db.add(row)
    row.name = str(it["name"])[:120]
    row.label = str(it.get("headline") or it.get("label") or it["name"])[:240]
    row.description = str(it.get("description") or it.get("notes") or "")
    row.motivation = str(it.get("motivation") or "")[:60]
    row.is_fictitious = bool(it.get("is_fictitious", False))
    row.sectors = [str(s) for s in (it.get("sectors") or [])][:20]
    row.techniques = [str(t) for t in (it.get("techniques") or [])][:60]
    row.kill_chain = kill_chain
    row.objectives = objectives
    db.flush()
    return row, action, warnings


def install(db: Session, user: models.User, token: str, environment_id: int | None = None) -> dict:
    try:
        manifest, digest = verify(token)
    except PackError as e:
        raise HTTPException(422, str(e))
    _require(db, manifest["kind"])
    existing = db.execute(select(models.ContentPack).where(
        models.ContentPack.org_id == user.org_id, models.ContentPack.pack_id == manifest["id"])).scalar_one_or_none()
    if existing and existing.version == manifest["version"] and existing.digest == digest:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"{manifest['name']} {manifest['version']} is already installed")
    created, warnings = [], []
    if manifest["kind"] == "scenarios":
        for it in manifest["items"]:
            env = _resolve_env(db, user, it, environment_id)
            try:
                scenario = scenario_io.to_models(it["scenario"], env.id, user.org_id)
            except scenario_io.ScenarioError as e:
                raise HTTPException(422, {"errors": e.errors})
            db.add(scenario)
            db.flush()
            created.append({"scenario_id": scenario.id, "name": scenario.name, "environment_id": env.id, "action": "created"})
    else:
        for it in manifest["items"]:
            row, action, w = _upsert_adversary(db, user.org_id, it)
            warnings += w
            created.append({"adversary_id": row.id, "key": row.key, "name": row.name, "action": action})
    summ = summary(manifest, digest)
    now = datetime.now(timezone.utc)
    if existing is None:
        existing = models.ContentPack(org_id=user.org_id, pack_id=manifest["id"], installed_by=user.email, installed_at=now)
        db.add(existing)
    existing.kind = manifest["kind"]
    existing.name = manifest["name"]
    existing.version = manifest["version"]
    existing.publisher = manifest["publisher"]
    existing.issued = manifest["issued"]
    existing.digest = digest
    existing.items = summ["count"]
    existing.manifest = {"items": summ["items"]}
    existing.updated_at = now
    db.flush()
    return {"pack": pack_out(existing), "created": created, "warnings": warnings}


def pack_out(p: models.ContentPack) -> dict:
    return {"id": p.id, "pack_id": p.pack_id, "kind": p.kind, "name": p.name, "version": p.version,
            "publisher": p.publisher, "issued": p.issued, "digest": p.digest, "items": p.items,
            "installed_by": p.installed_by, "installed_at": p.installed_at, "updated_at": p.updated_at}


def installed(db: Session, org_id: int) -> list[models.ContentPack]:
    return db.execute(select(models.ContentPack).where(models.ContentPack.org_id == org_id)
                      .order_by(models.ContentPack.updated_at.desc())).scalars().all()


def feed(db: Session, org_id: int) -> list[dict]:
    """The adversary intel feed: every entry from every installed intel pack,
    newest first, ready to render."""
    out = []
    for p in installed(db, org_id):
        if p.kind != "intel":
            continue
        for it in (p.manifest or {}).get("items", []):
            out.append({**it, "pack": p.name, "pack_version": p.version, "publisher": p.publisher,
                        "published": it.get("published") or p.issued})
    out.sort(key=lambda e: (e.get("published") or "", e.get("title") or ""), reverse=True)
    return out
