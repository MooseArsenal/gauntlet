"""Key management (M10): domain separation, key rotation, and a data keyring.

Two weaknesses M10 closes:

1. **Key reuse across purposes.** Before M10 the same ``SECRET_KEY`` signed both
   JWTs and the tamper-evident timeline. One key with two jobs means a leak in
   either context compromises both. Here each purpose gets its **own** key,
   derived from the master with HKDF and a purpose label, so the JWT key and the
   timeline key are cryptographically unrelated even from a single master secret.

2. **No path to rotate.** Data-at-rest keys are held in a **versioned keyring**:
   new data is sealed under the primary (newest) key while any prior key can
   still open old data, so a key can be rotated without a flag-day re-encrypt.

Everything derives from ``GAUNTLET_SECRET_KEY`` by default, so a single-secret
deployment keeps working; explicit per-purpose keys override the derivation.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os

from .config import SECRET_KEY

_MASTER = SECRET_KEY.encode("utf-8")


# --------------------------------------------------------------------------- #
# HKDF (RFC 5869) — stdlib only
# --------------------------------------------------------------------------- #
def _hkdf(ikm: bytes, info: bytes, length: int = 32, salt: bytes = b"gauntlet") -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, block, counter = b"", b"", 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def _derive(purpose: str) -> bytes:
    return _hkdf(_MASTER, f"gauntlet/{purpose}/v1".encode())


def _parse_keyring(spec: str) -> list[tuple[str, bytes]]:
    """Parse ``v2:<b64>,v1:<b64>`` into [(version, key_bytes), ...], newest first."""
    ring: list[tuple[str, bytes]] = []
    for item in spec.split(","):
        item = item.strip()
        if not item or ":" not in item:
            continue
        version, b64 = item.split(":", 1)
        ring.append((version.strip(), base64.urlsafe_b64decode(_pad(b64.strip()))))
    return ring


def _pad(b64: str) -> str:
    return b64 + "=" * ((4 - len(b64) % 4) % 4)


# --------------------------------------------------------------------------- #
# JWT signing key (domain-separated)
# --------------------------------------------------------------------------- #
def jwt_key() -> bytes:
    explicit = os.environ.get("GAUNTLET_JWT_KEY", "")
    return explicit.encode("utf-8") if explicit else _derive("jwt")


# --------------------------------------------------------------------------- #
# Timeline HMAC key (domain-separated, with a legacy verify fallback)
# --------------------------------------------------------------------------- #
def timeline_sign_key() -> bytes:
    """Key used to sign new timeline events."""
    explicit = os.environ.get("GAUNTLET_TIMELINE_KEY", "")
    return explicit.encode("utf-8") if explicit else _derive("timeline")


def timeline_verify_keys() -> list[bytes]:
    """Keys accepted when verifying an existing chain. Includes the raw master
    so chains signed before domain separation still verify (smooth upgrade)."""
    keys = [timeline_sign_key()]
    if _MASTER not in keys:
        keys.append(_MASTER)  # legacy: pre-M10 events signed with SECRET_KEY
    return keys


# --------------------------------------------------------------------------- #
# Exercise-certificate key (M1): signs the numbers a certificate attests to
# --------------------------------------------------------------------------- #
def certificate_key() -> bytes:
    explicit = os.environ.get("GAUNTLET_CERTIFICATE_KEY", "")
    return explicit.encode("utf-8") if explicit else _derive("certificate")


# --------------------------------------------------------------------------- #
# Data-at-rest keyring (versioned, rotatable)
# --------------------------------------------------------------------------- #
def data_keyring() -> list[tuple[str, bytes]]:
    """Ordered [(version, 32-byte key), ...], primary (newest) first.

    Sources, in order:
      * ``GAUNTLET_DATA_KEYS="v2:<b64>,v1:<b64>"`` — explicit, rotatable ring;
      * else, if ``GAUNTLET_ENCRYPT_AT_REST`` is on, a single key derived from
        the master (version ``d1``);
      * else empty — encryption at rest is disabled and data is stored as-is.
    """
    spec = os.environ.get("GAUNTLET_DATA_KEYS", "").strip()
    if spec:
        return [(v, _fit32(k)) for v, k in _parse_keyring(spec)]
    if _flag("GAUNTLET_ENCRYPT_AT_REST"):
        return [("d1", _derive("data"))]
    return []


def _fit32(key: bytes) -> bytes:
    """AES-256 needs exactly 32 bytes; stretch/truncate deterministically."""
    return key if len(key) == 32 else hashlib.sha256(key).digest()


def primary_data_key() -> tuple[str, bytes] | None:
    ring = data_keyring()
    return ring[0] if ring else None


def data_key_for(version: str) -> bytes | None:
    for v, k in data_keyring():
        if v == version:
            return k
    return None


def encryption_enabled() -> bool:
    return bool(data_keyring())


def _flag(name: str) -> bool:
    return os.environ.get(name, "0") not in ("0", "false", "False", "")
