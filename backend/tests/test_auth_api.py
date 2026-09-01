"""Auth, multi-tenancy, and RBAC (M5).

These tests always send tokens, so they exercise the real authenticated paths
even though the suite runs with GAUNTLET_AUTH_OPTIONAL=1 for the older tests.
"""
from fastapi.testclient import TestClient

from app import security
from app.main import app


def _register(client, org, email, password="Str0ngPass!9"):
    r = client.post("/api/auth/register",
                    json={"org_name": org, "email": email, "password": password, "name": "A"})
    assert r.status_code == 201, r.text
    return r.json()["access_token"]


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def test_register_login_me():
    with TestClient(app) as client:
        token = _register(client, "Acme", "acme-admin@example.com")

        # Wrong password is rejected.
        bad = client.post("/api/auth/login",
                          json={"email": "acme-admin@example.com", "password": "nope"})
        assert bad.status_code == 401

        # Correct login, then /me reflects the identity.
        ok = client.post("/api/auth/login",
                         json={"email": "acme-admin@example.com", "password": "Str0ngPass!9"})
        assert ok.status_code == 200
        me = client.get("/api/auth/me", headers=_auth(ok.json()["access_token"])).json()
        assert me["email"] == "acme-admin@example.com"
        assert me["role"] == "admin"


def test_duplicate_email_rejected():
    with TestClient(app) as client:
        _register(client, "Org1", "dup@example.com")
        r = client.post("/api/auth/register",
                        json={"org_name": "Org2", "email": "dup@example.com", "password": "Str0ngPass!9"})
        assert r.status_code == 409


def test_tenant_isolation():
    with TestClient(app) as client:
        a = _register(client, "Alpha Corp", "alpha@example.com")
        b = _register(client, "Beta Corp", "beta@example.com")

        # Org A creates an environment.
        env = client.post("/api/environments", headers=_auth(a),
                          json={"name": "A-env", "sector": "fin"})
        assert env.status_code == 201
        env_id = env.json()["id"]

        # Org B cannot see it (404, not 403 — existence is hidden).
        assert client.get(f"/api/environments/{env_id}", headers=_auth(b)).status_code == 404
        # And it does not appear in B's list.
        b_ids = [e["id"] for e in client.get("/api/environments", headers=_auth(b)).json()]
        assert env_id not in b_ids
        # A sees it fine.
        assert client.get(f"/api/environments/{env_id}", headers=_auth(a)).status_code == 200


def test_rbac_evaluator_cannot_author_but_can_observe():
    with TestClient(app) as client:
        admin = _register(client, "Gamma", "gamma-admin@example.com")
        # Admin adds an evaluator to the org.
        client.post("/api/auth/users", headers=_auth(admin),
                    json={"email": "evaluator@example.com", "password": "Str0ngPass!9",
                          "role": "evaluator"})
        ev = client.post("/api/auth/login",
                         json={"email": "evaluator@example.com", "password": "Str0ngPass!9"}).json()["access_token"]

        # Admin sets up an environment + scenario + session.
        env_id = client.post("/api/environments", headers=_auth(admin),
                             json={"name": "g-env"}).json()["id"]
        scn = client.post("/api/scenarios", headers=_auth(admin), json={
            "environment_id": env_id, "name": "g-scn",
            "objectives": [{"code": "OBJ-1", "title": "Detect"}],
            "injects": [{"code": "INJ-01", "title": "start", "is_start": True,
                         "branches": [{"when": "proctor_choice", "goto": "INJ-02"}]},
                        {"code": "INJ-02", "title": "end"}],
        }).json()["id"]
        sid = client.post("/api/sessions", headers=_auth(admin),
                          json={"scenario_id": scn, "name": "run"}).json()["id"]
        client.post(f"/api/sessions/{sid}/start", headers=_auth(admin))  # observations need a live session (F-1)

        # Evaluator may NOT create a scenario...
        forbidden = client.post("/api/scenarios", headers=_auth(ev), json={
            "environment_id": env_id, "name": "nope"})
        assert forbidden.status_code == 403
        # ...but MAY log an observation.
        obs = client.post(f"/api/sessions/{sid}/observe", headers=_auth(ev),
                          json={"objective_code": "OBJ-1", "rating": "met", "note": "seen"})
        assert obs.status_code == 201


def test_unauthenticated_rejected_when_auth_enforced(monkeypatch):
    # Force enforcement (the suite otherwise runs auth-optional).
    monkeypatch.setattr(security, "AUTH_OPTIONAL", False)
    with TestClient(app) as client:
        assert client.get("/api/environments").status_code == 401
        assert client.get("/api/scenarios").status_code == 401
