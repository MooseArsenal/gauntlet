"""Trust anchors and signing keys (L6).

Licences and content packs are Ed25519-signed by the vendor. This module owns
*which public keys a deployment trusts* and *how the vendor's private keys are
kept*:

* ``VENDOR_KEYS`` — the vendor's public keys, by key id, compiled into the
  product. This is the trust anchor in production: a customer cannot make a
  deployment trust a key of their own by setting an environment variable.
* Environment keys (``GAUNTLET_LICENSE_PUBKEYS`` / ``GAUNTLET_PACK_PUBKEYS``,
  ``kid=base64url,...``; or the bare single-key forms) are honoured outside
  production, and in production only with ``GAUNTLET_TRUST_ENV_KEYS=1`` — for
  self-hosters who fork the product and issue their own licences, knowingly.
* Key ids let keys rotate: a new key is added here and shipped, tokens start
  carrying its ``kid``, the old key stays trusted until nothing signed by it is
  in service. A token without a ``kid`` is checked against every trusted key.
* Private keys never live in the repository or a CI secret. The tools keep them
  in a passphrase-encrypted PEM file (``save_private_key`` /
  ``load_private_key``); see docs/KEY_MANAGEMENT.md for the ceremony.
"""
from __future__ import annotations

import base64
import hashlib
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from . import config

# kid -> base64url(raw 32-byte Ed25519 public key). Filled by the vendor at
# release time (tools/issue_license.py keygen prints both). Empty means: no
# built-in anchor — production trusts nothing until this is set or
# GAUNTLET_TRUST_ENV_KEYS=1 is deliberately chosen.
VENDOR_KEYS: dict[str, str] = {
    "57ad1f1b7780": "bAmy5BZtr5XyCz6dmzyRj_O3AsqeNEOcGoj1pM40RcM",  # vendor licence key, 2026
}

ENV_VARS = {
    "license": ("GAUNTLET_LICENSE_PUBKEYS", "GAUNTLET_LICENSE_PUBKEY"),
    "pack": ("GAUNTLET_PACK_PUBKEYS", "GAUNTLET_PACK_PUBKEY"),
}


def b64d(s: str) -> bytes:
    s = s.strip()
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def kid_for(pub_b64: str) -> str:
    """A stable short id for a public key: the first 12 hex of its SHA-256."""
    return hashlib.sha256(b64d(pub_b64)).hexdigest()[:12]


def env_keys_allowed() -> bool:
    return (not config.IS_PROD) or os.environ.get("GAUNTLET_TRUST_ENV_KEYS", "").lower() in ("1", "true", "yes")


def _parse_env(value: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in (value or "").split(","):
        part = part.strip()
        if not part:
            continue
        kid, _, b64 = part.rpartition("=") if "=" in part.rstrip("=") else ("", "", part)
        b64 = b64.strip()
        out[(kid.strip() or kid_for(b64))] = b64
    return out


def trusted_keys(purpose: str = "license") -> dict[str, ed25519.Ed25519PublicKey]:
    """kid -> public key. Packs fall back to the licence keys when no
    pack-specific keys are configured."""
    raw: dict[str, str] = dict(VENDOR_KEYS)
    if env_keys_allowed():
        purposes = (purpose, "license") if purpose == "pack" else (purpose,)
        for p in purposes:
            env_raw: dict[str, str] = {}
            for var in ENV_VARS[p]:
                v = os.environ.get(var, "")
                if v:
                    env_raw.update(_parse_env(v))
            if env_raw:
                raw.update(env_raw)
                break  # pack-specific keys, else the licence keys; not both
    keys = {}
    for kid, b64 in raw.items():
        try:
            keys[kid] = ed25519.Ed25519PublicKey.from_public_bytes(b64d(b64))
        except Exception:  # noqa: BLE001 - a malformed key is simply not trusted
            continue
    return keys


def verify(purpose: str, body: bytes, sig: bytes, kid: str | None) -> str:
    """Verify ``sig`` over ``body`` with the trusted key named by ``kid`` (or,
    for a token without one, any trusted key). Returns the kid that verified.
    Raises ValueError otherwise."""
    keys = trusted_keys(purpose)
    if not keys:
        raise ValueError("no trusted signing key is configured on this deployment")
    candidates = [(kid, keys[kid])] if kid and kid in keys else ([] if kid else list(keys.items()))
    for k, pub in candidates:
        try:
            pub.verify(sig, body)
            return k
        except Exception:  # noqa: BLE001
            continue
    raise ValueError("signature does not verify against a trusted key" + (f" (kid {kid} is not trusted)" if kid and kid not in keys else ""))


# --------------------------------------------------------------------------- #
# vendor side: keypairs and encrypted key files
# --------------------------------------------------------------------------- #
def keygen() -> tuple[str, str]:
    priv = ed25519.Ed25519PrivateKey.generate()
    pb = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    pu = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return b64e(pb), b64e(pu)


def public_of(priv_b64: str) -> str:
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(b64d(priv_b64))
    return b64e(priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))


def sign(priv_b64: str, body: bytes) -> bytes:
    return ed25519.Ed25519PrivateKey.from_private_bytes(b64d(priv_b64)).sign(body)


def save_private_key(path: str, priv_b64: str, passphrase: str) -> None:
    """Write a passphrase-encrypted PKCS#8 PEM (owner-read-only)."""
    if len(passphrase or "") < 12:
        raise ValueError("use a passphrase of at least 12 characters")
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(b64d(priv_b64))
    pem = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.BestAvailableEncryption(passphrase.encode()))
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)


def load_private_key(path: str, passphrase: str) -> str:
    with open(path, "rb") as f:
        pem = f.read()
    try:
        priv = serialization.load_pem_private_key(pem, password=(passphrase or "").encode() or None)
    except (ValueError, TypeError) as exc:
        raise ValueError("could not unlock the key file: wrong passphrase or not an encrypted Ed25519 key") from exc
    if not isinstance(priv, ed25519.Ed25519PrivateKey):
        raise ValueError("the key file is not an Ed25519 key")
    return b64e(priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()))
