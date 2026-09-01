"""M9 — identity & sessions: password policy, refresh-token rotation, TOTP MFA,
WebSocket connection tickets, and OIDC SSO."""
import json
import time

import jwt
import pytest
from fastapi.testclient import TestClient

from app import oidc, security
from app.main import app
from app.ws_ticket import tickets


def _register(client, org, email, password="Str0ngPass!9"):
    r = client.post("/api/auth/register",
                    json={"org_name": org, "email": email, "password": password, "name": "A"})
    assert r.status_code == 201, r.text
    return r.json()


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


# --------------------------------------------------------------------------- #
# password policy
# --------------------------------------------------------------------------- #
def test_password_policy_rejects_weak():
    with TestClient(app) as client:
        # Too short.
        r = client.post("/api/auth/register",
                        json={"org_name": "P", "email": "p1@example.com", "password": "short"})
        assert r.status_code == 422
        # A common password of adequate length is still refused.
        r = client.post("/api/auth/register",
                        json={"org_name": "P", "email": "p2@example.com", "password": "password123"})
        assert r.status_code == 422
        # All-digits refused even when long.
        r = client.post("/api/auth/register",
                        json={"org_name": "P", "email": "p3@example.com", "password": "1234567890123"})
        assert r.status_code == 422
        # A strong password is accepted.
        assert client.post("/api/auth/register",
                           json={"org_name": "P", "email": "p4@example.com",
                                 "password": "Str0ngPass!9"}).status_code == 201


# --------------------------------------------------------------------------- #
# refresh-token rotation, reuse detection, revocation
# --------------------------------------------------------------------------- #
def test_refresh_rotation_and_reuse_detection():
    with TestClient(app) as client:
        tok = _register(client, "R", "r@example.com")
        rt0 = tok["refresh_token"]
        assert rt0

        # Rotating returns a fresh access + refresh pair.
        r1 = client.post("/api/auth/refresh", json={"refresh_token": rt0})
        assert r1.status_code == 200, r1.text
        rt1 = r1.json()["refresh_token"]
        assert rt1 and rt1 != rt0

        # The rotated-away token is now dead...
        reused = client.post("/api/auth/refresh", json={"refresh_token": rt0})
        assert reused.status_code == 401
        # ...and reuse trips family revocation, so the successor dies too.
        assert client.post("/api/auth/refresh", json={"refresh_token": rt1}).status_code == 401


def test_logout_revokes_refresh():
    with TestClient(app) as client:
        tok = _register(client, "L", "l@example.com")
        rt = tok["refresh_token"]
        assert client.post("/api/auth/logout", json={"refresh_token": rt}).status_code == 204
        assert client.post("/api/auth/refresh", json={"refresh_token": rt}).status_code == 401


def test_change_password_flow_and_revocation():
    with TestClient(app) as client:
        tok = _register(client, "C", "c@example.com")
        access, rt = tok["access_token"], tok["refresh_token"]

        # Wrong current password is refused.
        assert client.post("/api/auth/change-password", headers=_auth(access),
                           json={"old_password": "nope", "new_password": "An0therGood!1"}
                           ).status_code == 401
        # New password must satisfy the policy.
        assert client.post("/api/auth/change-password", headers=_auth(access),
                           json={"old_password": "Str0ngPass!9", "new_password": "weak"}
                           ).status_code == 422
        # Success.
        assert client.post("/api/auth/change-password", headers=_auth(access),
                           json={"old_password": "Str0ngPass!9", "new_password": "An0therGood!1"}
                           ).status_code == 204
        # Changing the password revokes existing refresh tokens.
        assert client.post("/api/auth/refresh", json={"refresh_token": rt}).status_code == 401
        # And the new password logs in.
        assert client.post("/api/auth/login",
                           json={"email": "c@example.com", "password": "An0therGood!1"}
                           ).status_code == 200


# --------------------------------------------------------------------------- #
# access-token type separation
# --------------------------------------------------------------------------- #
def test_mfa_challenge_is_not_an_access_token():
    with TestClient(app) as client:
        _register(client, "T", "t@example.com")
        # Build a challenge token and try to use it as a bearer.
        from app import models
        from app.database import SessionLocal
        db = SessionLocal()
        try:
            user = db.query(models.User).filter_by(email="t@example.com").one()
            challenge = security.create_mfa_challenge(user)
        finally:
            db.close()
        r = client.get("/api/auth/me", headers=_auth(challenge))
        assert r.status_code == 401


# --------------------------------------------------------------------------- #
# TOTP MFA enrolment + login
# --------------------------------------------------------------------------- #
def _totp_now(secret):
    return security._totp_at(secret, int(time.time() // 30))


def test_mfa_setup_enable_and_login():
    with TestClient(app) as client:
        tok = _register(client, "M", "m@example.com")
        access = tok["access_token"]

        # Enrol.
        setup = client.post("/api/auth/mfa/setup", headers=_auth(access))
        assert setup.status_code == 200
        secret = setup.json()["secret"]
        assert setup.json()["uri"].startswith("otpauth://totp/")

        # A wrong code does not enable.
        assert client.post("/api/auth/mfa/enable", headers=_auth(access),
                           json={"code": "000000"}).status_code == 401
        # The right code enables MFA.
        enabled = client.post("/api/auth/mfa/enable", headers=_auth(access),
                              json={"code": _totp_now(secret)})
        assert enabled.status_code == 200 and enabled.json()["mfa_enabled"] is True

        # Login now returns a challenge, not tokens.
        login = client.post("/api/auth/login",
                            json={"email": "m@example.com", "password": "Str0ngPass!9"})
        assert login.status_code == 200
        body = login.json()
        assert body["mfa_required"] is True and body.get("access_token") in (None, "")
        challenge = body["challenge"]

        # Second factor with a bad code fails; with the right code yields tokens.
        assert client.post("/api/auth/login/mfa",
                           json={"challenge": challenge, "code": "000000"}).status_code == 401
        done = client.post("/api/auth/login/mfa",
                           json={"challenge": challenge, "code": _totp_now(secret)})
        assert done.status_code == 200 and done.json()["access_token"]

        # Disabling with a valid code clears it.
        off = client.post("/api/auth/mfa/disable", headers=_auth(access),
                          json={"code": _totp_now(secret)})
        assert off.status_code == 200 and off.json()["mfa_enabled"] is False


# --------------------------------------------------------------------------- #
# WebSocket connection tickets
# --------------------------------------------------------------------------- #
def _make_session(client, token):
    env = client.post("/api/environments", headers=_auth(token),
                      json={"name": "ws-env"}).json()["id"]
    scn = client.post("/api/scenarios", headers=_auth(token), json={
        "environment_id": env, "name": "ws-scn",
        "injects": [{"code": "INJ-01", "title": "start", "is_start": True}],
    }).json()["id"]
    return client.post("/api/sessions", headers=_auth(token),
                       json={"scenario_id": scn, "name": "run"}).json()["id"]


def test_ws_ticket_scoped_and_single_use():
    with TestClient(app) as client:
        a = _register(client, "WsA", "wsa@example.com")["access_token"]
        b = _register(client, "WsB", "wsb@example.com")["access_token"]
        sid = _make_session(client, a)

        # Owner mints a ticket.
        r = client.post(f"/api/sessions/{sid}/ws-ticket", headers=_auth(a))
        assert r.status_code == 200
        ticket = r.json()["ticket"]

        # Another tenant cannot (session is hidden → 404).
        assert client.post(f"/api/sessions/{sid}/ws-ticket", headers=_auth(b)).status_code == 404

        # The ticket resolves to a user for the right session, and only once.
        assert tickets.consume(ticket, sid) is not None
        assert tickets.consume(ticket, sid) is None  # single use

        # A ticket is bound to its session.
        t2 = client.post(f"/api/sessions/{sid}/ws-ticket", headers=_auth(a)).json()["ticket"]
        assert tickets.consume(t2, sid + 999) is None


def test_ws_connect_requires_valid_ticket():
    from starlette.websockets import WebSocketDisconnect

    with TestClient(app) as client:
        a = _register(client, "WsC", "wsc@example.com")["access_token"]
        sid = _make_session(client, a)

        # A bad ticket is rejected at the handshake.
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(f"/ws/sessions/{sid}?ticket=bogus"):
                pass

        # A freshly minted ticket connects.
        ticket = client.post(f"/api/sessions/{sid}/ws-ticket", headers=_auth(a)).json()["ticket"]
        with client.websocket_connect(f"/ws/sessions/{sid}?ticket={ticket}") as ws:
            assert ws is not None  # accepted


# --------------------------------------------------------------------------- #
# OIDC SSO
# --------------------------------------------------------------------------- #
def _rsa_keypair():
    from cryptography.hazmat.primitives.asymmetric import rsa
    from jwt.algorithms import RSAAlgorithm

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": "test-key", "alg": "RS256", "use": "sig"})
    return key, {"keys": [jwk]}


def _configure_oidc(monkeypatch, issuer="https://idp.example", client_id="gauntlet-client"):
    for mod in (oidc,):
        monkeypatch.setattr(mod, "OIDC_ENABLED", True)
        monkeypatch.setattr(mod, "OIDC_ISSUER", issuer)
        monkeypatch.setattr(mod, "OIDC_CLIENT_ID", client_id)
        monkeypatch.setattr(mod, "OIDC_CLIENT_SECRET", "secret")
        monkeypatch.setattr(mod, "OIDC_REDIRECT_URI", "https://app.example/api/auth/oidc/callback")
    import app.api.auth as auth_mod
    monkeypatch.setattr(auth_mod, "OIDC_ENABLED", True)
    oidc._reset_discovery_cache()


def test_verify_id_token_checks_signature_aud_and_nonce(monkeypatch):
    _configure_oidc(monkeypatch)
    key, jwks = _rsa_keypair()
    now = int(time.time())
    base = {"iss": "https://idp.example", "aud": "gauntlet-client",
            "sub": "abc", "email": "sso@example.com", "iat": now, "exp": now + 300,
            "nonce": "n1"}
    good = jwt.encode(base, key, algorithm="RS256", headers={"kid": "test-key"})
    claims = oidc.verify_id_token(good, jwks, nonce="n1")
    assert claims["sub"] == "abc"

    # Wrong nonce.
    with pytest.raises(oidc.OidcError):
        oidc.verify_id_token(good, jwks, nonce="other")
    # Wrong audience.
    bad_aud = jwt.encode({**base, "aud": "someone-else"}, key,
                         algorithm="RS256", headers={"kid": "test-key"})
    with pytest.raises(oidc.OidcError):
        oidc.verify_id_token(bad_aud, jwks, nonce="n1")
    # Tampered signature (signed by a different key).
    other_key, _ = _rsa_keypair()
    forged = jwt.encode(base, other_key, algorithm="RS256", headers={"kid": "test-key"})
    with pytest.raises(oidc.OidcError):
        oidc.verify_id_token(forged, jwks, nonce="n1")


def test_oidc_callback_links_existing_user(monkeypatch):
    _configure_oidc(monkeypatch)
    key, jwks = _rsa_keypair()

    disco = {
        "authorization_endpoint": "https://idp.example/authorize",
        "token_endpoint": "https://idp.example/token",
        "jwks_uri": "https://idp.example/jwks",
    }

    def fake_get_json(url):
        if url.endswith("/jwks"):
            return jwks
        return disco

    monkeypatch.setattr(oidc, "_get_json", fake_get_json)

    with TestClient(app) as client:
        _register(client, "SsoOrg", "sso@example.com")

        # Kick off login to seed a valid state+nonce, then read them back.
        url = oidc.authorization_url()
        from urllib.parse import parse_qs, urlparse
        q = parse_qs(urlparse(url).query)
        state, nonce = q["state"][0], q["nonce"][0]

        now = int(time.time())
        id_token = jwt.encode(
            {"iss": "https://idp.example", "aud": "gauntlet-client", "sub": "sso-sub-1",
             "email": "sso@example.com", "iat": now, "exp": now + 300, "nonce": nonce},
            key, algorithm="RS256", headers={"kid": "test-key"})
        monkeypatch.setattr(oidc, "_post_form", lambda u, d: {"id_token": id_token})

        # The callback should link the identity and redirect with tokens.
        r = client.get(f"/api/auth/oidc/callback?code=xyz&state={state}",
                       follow_redirects=False)
        assert r.status_code == 302
        assert "sso_access=" in r.headers["location"]

        # A second login for the same sub still resolves (linked by subject now).
        url2 = oidc.authorization_url()
        q2 = parse_qs(urlparse(url2).query)
        st2, nc2 = q2["state"][0], q2["nonce"][0]
        id_token2 = jwt.encode(
            {"iss": "https://idp.example", "aud": "gauntlet-client", "sub": "sso-sub-1",
             "email": "changed@example.com", "iat": now, "exp": now + 300, "nonce": nc2},
            key, algorithm="RS256", headers={"kid": "test-key"})
        monkeypatch.setattr(oidc, "_post_form", lambda u, d: {"id_token": id_token2})
        r2 = client.get(f"/api/auth/oidc/callback?code=xyz&state={st2}", follow_redirects=False)
        assert r2.status_code == 302


def test_oidc_callback_rejects_unknown_identity(monkeypatch):
    _configure_oidc(monkeypatch)
    key, jwks = _rsa_keypair()
    disco = {
        "authorization_endpoint": "https://idp.example/authorize",
        "token_endpoint": "https://idp.example/token",
        "jwks_uri": "https://idp.example/jwks",
    }
    monkeypatch.setattr(oidc, "_get_json",
                        lambda url: jwks if url.endswith("/jwks") else disco)

    with TestClient(app) as client:
        url = oidc.authorization_url()
        from urllib.parse import parse_qs, urlparse
        q = parse_qs(urlparse(url).query)
        state, nonce = q["state"][0], q["nonce"][0]
        now = int(time.time())
        id_token = jwt.encode(
            {"iss": "https://idp.example", "aud": "gauntlet-client", "sub": "nobody",
             "email": "nobody@example.com", "iat": now, "exp": now + 300, "nonce": nonce},
            key, algorithm="RS256", headers={"kid": "test-key"})
        monkeypatch.setattr(oidc, "_post_form", lambda u, d: {"id_token": id_token})
        r = client.get(f"/api/auth/oidc/callback?code=xyz&state={state}", follow_redirects=False)
        assert r.status_code == 403


def test_oidc_disabled_by_default():
    with TestClient(app) as client:
        assert client.get("/api/auth/oidc/config").json()["enabled"] is False
        assert client.get("/api/auth/oidc/login", follow_redirects=False).status_code == 404
