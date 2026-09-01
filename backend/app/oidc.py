"""OpenID Connect SSO (M9), authorization-code flow.

Config-gated: inert unless ``GAUNTLET_OIDC_ISSUER`` and ``GAUNTLET_OIDC_CLIENT_ID``
are set. The provider's discovery document supplies the authorization, token, and
JWKS endpoints; the returned ``id_token`` is verified against the provider's
public keys (signature, issuer, audience, expiry, and nonce).

SSO **links to an existing Gauntlet account** — it does not auto-create users,
because an org and role can't be inferred from an external identity. The first
successful SSO login for an email links that account's ``oidc_subject``; later
logins match on the subject directly.

Network access is funnelled through three thin helpers (``_get_json``,
``_post_form``) so tests can exercise the flow without a live IdP.
"""
from __future__ import annotations

import json
import secrets
import threading
import time

import httpx
import jwt
from jwt import PyJWKSet

from .config import (
    OIDC_CLIENT_ID,
    OIDC_CLIENT_SECRET,
    OIDC_ENABLED,
    OIDC_ISSUER,
    OIDC_REDIRECT_URI,
)

_HTTP_TIMEOUT = 10.0


class OidcError(Exception):
    """Any failure in the SSO exchange (config, network, or verification)."""


# --------------------------------------------------------------------------- #
# network seams (monkeypatched in tests)
# --------------------------------------------------------------------------- #
def _get_json(url: str) -> dict:
    resp = httpx.get(url, timeout=_HTTP_TIMEOUT)
    resp.raise_for_status()
    return resp.json()


def _post_form(url: str, data: dict) -> dict:
    resp = httpx.post(url, data=data, timeout=_HTTP_TIMEOUT,
                      headers={"Accept": "application/json"})
    resp.raise_for_status()
    return resp.json()


# --------------------------------------------------------------------------- #
# discovery (cached)
# --------------------------------------------------------------------------- #
_disco_lock = threading.Lock()
_disco_cache: dict | None = None


def discovery() -> dict:
    global _disco_cache
    with _disco_lock:
        if _disco_cache is None:
            url = OIDC_ISSUER.rstrip("/") + "/.well-known/openid-configuration"
            try:
                _disco_cache = _get_json(url)
            except Exception as exc:  # noqa: BLE001 - surfaced as OidcError
                raise OidcError(f"OIDC discovery failed: {exc}") from exc
        return _disco_cache


def _reset_discovery_cache() -> None:  # test helper
    global _disco_cache
    with _disco_lock:
        _disco_cache = None


# --------------------------------------------------------------------------- #
# transient login state (state -> nonce), short-lived, single-process
# --------------------------------------------------------------------------- #
_STATE_TTL = 600.0
_states: dict[str, tuple[str, float]] = {}
_state_lock = threading.Lock()


def _remember_state(state: str, nonce: str) -> None:
    now = time.time()
    with _state_lock:
        for k, (_, exp) in list(_states.items()):
            if exp < now:
                _states.pop(k, None)
        _states[state] = (nonce, now + _STATE_TTL)


def _take_state(state: str) -> str | None:
    with _state_lock:
        rec = _states.pop(state, None)
    if rec is None or rec[1] < time.time():
        return None
    return rec[0]


# --------------------------------------------------------------------------- #
# flow
# --------------------------------------------------------------------------- #
def authorization_url() -> str:
    """Build the provider authorization URL and stash the CSRF state + nonce."""
    if not OIDC_ENABLED:
        raise OidcError("OIDC SSO is not configured")
    from urllib.parse import urlencode

    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    _remember_state(state, nonce)
    params = {
        "response_type": "code",
        "client_id": OIDC_CLIENT_ID,
        "redirect_uri": OIDC_REDIRECT_URI,
        "scope": "openid email profile",
        "state": state,
        "nonce": nonce,
    }
    return discovery()["authorization_endpoint"] + "?" + urlencode(params)


def exchange_code(code: str) -> dict:
    """Swap an authorization code for the token response (with id_token)."""
    token_endpoint = discovery()["token_endpoint"]
    try:
        return _post_form(token_endpoint, {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": OIDC_REDIRECT_URI,
            "client_id": OIDC_CLIENT_ID,
            "client_secret": OIDC_CLIENT_SECRET,
        })
    except Exception as exc:  # noqa: BLE001
        raise OidcError(f"token exchange failed: {exc}") from exc


def _signing_key(id_token: str, jwks: dict):
    try:
        kid = jwt.get_unverified_header(id_token).get("kid")
        key_set = PyJWKSet.from_dict(jwks)
    except Exception as exc:  # noqa: BLE001
        raise OidcError(f"could not read token header or JWKS: {exc}") from exc
    for key in key_set.keys:
        if kid is None or key.key_id == kid:
            return key.key
    raise OidcError("no matching signing key for id_token")


def verify_id_token(id_token: str, jwks: dict, nonce: str | None = None) -> dict:
    """Verify signature, issuer, audience, expiry, and (if given) nonce."""
    key = _signing_key(id_token, jwks)
    try:
        claims = jwt.decode(
            id_token, key,
            algorithms=["RS256", "RS384", "RS512", "ES256"],
            audience=OIDC_CLIENT_ID,
            issuer=OIDC_ISSUER,
            options={"require": ["exp", "iat", "sub"]},
        )
    except jwt.PyJWTError as exc:
        raise OidcError(f"id_token verification failed: {exc}") from exc
    if nonce is not None and claims.get("nonce") != nonce:
        raise OidcError("id_token nonce mismatch")
    return claims


def complete_login(code: str, state: str) -> dict:
    """Full callback: validate state, exchange code, verify id_token.

    Returns the verified claims (with ``sub`` and, usually, ``email``).
    """
    if not OIDC_ENABLED:
        raise OidcError("OIDC SSO is not configured")
    nonce = _take_state(state)
    if nonce is None:
        raise OidcError("unknown or expired login state")
    token_response = exchange_code(code)
    id_token = token_response.get("id_token")
    if not id_token:
        raise OidcError("no id_token in provider response")
    jwks = _get_json(discovery()["jwks_uri"])
    return verify_id_token(id_token, jwks, nonce=nonce)
