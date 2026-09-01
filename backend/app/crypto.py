"""Application-level encryption at rest (M10).

Gauntlet's environment records are the crown jewels of the crown jewels — asset
inventories, control gaps, deception placements, named personnel. Disk-level
encryption (LUKS, cloud KMS volumes) protects a stolen disk but not a leaked
database dump or a compromised DB account. So the most sensitive fields are
sealed **in the application** with AES-256-GCM before they ever reach the
database, and opened only in process.

Portable by design: this works identically on SQLite and Postgres, needs no DB
extension, and is **opt-in** — with no data key configured (the default), values
are stored as ordinary JSON and nothing changes.

Ciphertext envelope: ``enc:<key-version>:<b64 nonce>:<b64 ciphertext+tag>``. The
key version lets a value sealed under an old key still be opened after the key
is rotated (see :mod:`app.keys`).
"""
from __future__ import annotations

import base64
import json

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import JSON
from sqlalchemy.types import TypeDecorator

from . import keys

_PREFIX = "enc:"


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s)


def encrypt_bytes(plaintext: bytes) -> str:
    """Seal bytes under the primary data key. Requires encryption to be enabled."""
    primary = keys.primary_data_key()
    if primary is None:
        raise RuntimeError("encryption requested but no data key is configured")
    version, key = primary
    nonce = _random_nonce()
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return f"{_PREFIX}{version}:{_b64e(nonce)}:{_b64e(ct)}"


def decrypt_to_bytes(token: str) -> bytes:
    """Open an ``enc:`` envelope, selecting the key by its embedded version."""
    try:
        _, version, nonce_b64, ct_b64 = token.split(":", 3)
    except ValueError as exc:
        raise ValueError("malformed ciphertext envelope") from exc
    key = keys.data_key_for(version)
    if key is None:
        raise RuntimeError(f"no data key for version {version!r} (rotated out?)")
    return AESGCM(key).decrypt(_b64d(nonce_b64), _b64d(ct_b64), None)


def is_ciphertext(value) -> bool:
    return isinstance(value, str) and value.startswith(_PREFIX)


def _random_nonce() -> bytes:
    import os

    return os.urandom(12)  # 96-bit GCM nonce


class EncryptedJSON(TypeDecorator):
    """A JSON column whose value is transparently encrypted at rest when a data
    key is configured.

    - **Enabled** (a data key is set): the Python value is JSON-serialised and
      sealed; the column holds an ``enc:`` string.
    - **Disabled** (default): the value is stored as ordinary JSON — identical to
      a plain ``JSON`` column, so dev/test and un-keyed deployments are unaffected.

    Reads handle both shapes, so a database that predates encryption (or was
    written with the key off) keeps working, and turning the key on encrypts
    each row the next time it is written. ``cache_ok`` is safe because behaviour
    depends only on runtime config, not on instance state.
    """

    impl = JSON
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None or not keys.encryption_enabled():
            return value
        return encrypt_bytes(json.dumps(value, separators=(",", ":")).encode("utf-8"))

    def process_result_value(self, value, dialect):
        if is_ciphertext(value):
            return json.loads(decrypt_to_bytes(value))
        return value  # legacy / un-keyed plaintext JSON
