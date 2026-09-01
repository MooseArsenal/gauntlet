"""Platform hardening: headers, config fail-fast, throttling, audit, caps (M8)."""
import uuid

from fastapi.testclient import TestClient

from app import config
from app.main import app


def _email():
    return f"u-{uuid.uuid4().hex[:8]}@example.com"


def _reg(client, email):
    return client.post("/api/auth/register",
                       json={"org_name": "H", "email": email, "password": "Str0ngPass!9"}).json()


def _h(tok):
    return {"Authorization": f"Bearer {tok}"}


def test_security_headers_present():
    with TestClient(app) as client:
        r = client.get("/api/health")
        assert "content-security-policy" in r.headers
        assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
        assert r.headers["x-frame-options"] == "DENY"
        assert r.headers["x-content-type-options"] == "nosniff"


def test_config_fail_fast_in_prod(monkeypatch):
    monkeypatch.setattr(config, "IS_PROD", True)
    monkeypatch.setattr(config, "SECRET_IS_DEFAULT", True)
    monkeypatch.setattr(config, "SECRET_KEY", "short")
    monkeypatch.setattr(config, "CORS_ORIGINS", ["*"])
    monkeypatch.setattr(config, "AUTH_OPTIONAL", True)
    problems = config.startup_problems()
    assert any("SECRET_KEY" in p for p in problems)
    assert any("CORS" in p for p in problems)
    assert any("AUTH_OPTIONAL" in p for p in problems)
    try:
        config.validate_config()
        assert False, "should have raised"
    except RuntimeError:
        pass


def test_login_lockout_after_repeated_failures():
    with TestClient(app) as client:
        email = _email()
        _reg(client, email)
        # 5 wrong-password attempts (LOGIN_MAX_ATTEMPTS) are 401; the next is locked.
        for _ in range(5):
            r = client.post("/api/auth/login", json={"email": email, "password": "wrong"})
            assert r.status_code == 401
        locked = client.post("/api/auth/login", json={"email": email, "password": "wrong"})
        assert locked.status_code == 429
        # Even the correct password is refused while locked.
        assert client.post("/api/auth/login",
                           json={"email": email, "password": "Str0ngPass!9"}).status_code == 429


def test_audit_log_records_and_is_admin_only_and_tenant_scoped():
    with TestClient(app) as client:
        a_email, b_email = _email(), _email()
        a = _reg(client, a_email)["access_token"]
        b = _reg(client, b_email)["access_token"]
        client.post("/api/auth/login", json={"email": a_email, "password": "Str0ngPass!9"})

        entries = client.get("/api/audit", headers=_h(a)).json()
        actions = {e["action"] for e in entries}
        assert "auth.register" in actions
        assert "auth.login.success" in actions

        # Org B's audit never contains org A's email.
        b_entries = client.get("/api/audit", headers=_h(b)).json()
        assert all(e["actor_email"] != a_email for e in b_entries)

        # Evaluators cannot read the audit log.
        client.post("/api/auth/users", headers=_h(a),
                    json={"email": _email(), "password": "Str0ngPass!9", "role": "evaluator"})


def test_audit_requires_admin_role():
    with TestClient(app) as client:
        admin_email = _email()
        admin = _reg(client, admin_email)["access_token"]
        ev_email = _email()
        client.post("/api/auth/users", headers=_h(admin),
                    json={"email": ev_email, "password": "Str0ngPass!9", "role": "evaluator"})
        ev = client.post("/api/auth/login",
                         json={"email": ev_email, "password": "Str0ngPass!9"}).json()["access_token"]
        assert client.get("/api/audit", headers=_h(ev)).status_code == 403


def test_oversized_yaml_rejected():
    with TestClient(app) as client:
        env_id = client.post("/api/environments", json={"name": "e"}).json()["id"]
        big = "name: X\ninjects:\n" + ("  - {code: A, is_start: true, branches: []}\n" * 1)
        big += "# padding\n" + ("x" * (config.MAX_YAML_BYTES + 10))
        r = client.post("/api/scenarios/import", json={"environment_id": env_id, "yaml": big})
        assert r.status_code == 413
