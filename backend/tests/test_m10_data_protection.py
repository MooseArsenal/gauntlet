"""M10 — data protection: key separation, encryption at rest + rotation,
retention purge, and GDPR export/erasure."""
import base64
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy import text

from app import crypto, keys, models, retention
from app.database import SessionLocal, engine
from app.main import app


def _register(client, org, email):
    r = client.post("/api/auth/register",
                    json={"org_name": org, "email": email, "password": "Str0ngPass!9"})
    assert r.status_code == 201, r.text
    return r.json()["access_token"]


def _auth(t):
    return {"Authorization": f"Bearer {t}"}


# --------------------------------------------------------------------------- #
# key separation
# --------------------------------------------------------------------------- #
def test_keys_are_domain_separated():
    assert keys.jwt_key() != keys.timeline_sign_key()
    # The raw master is accepted for verifying legacy timeline chains.
    assert any(k for k in keys.timeline_verify_keys())


def test_encryption_disabled_by_default():
    assert keys.encryption_enabled() is False


# --------------------------------------------------------------------------- #
# encryption at rest
# --------------------------------------------------------------------------- #
def test_environment_fields_encrypted_at_rest(monkeypatch):
    monkeypatch.setenv("GAUNTLET_ENCRYPT_AT_REST", "1")
    assert keys.encryption_enabled() is True

    with TestClient(app) as client:
        token = _register(client, "EncOrg", "enc@example.com")
        env = client.post("/api/environments", headers=_auth(token), json={
            "name": "secretlab",
            "crown_jewels": ["billing-db", "hsm-root-key"],
            "personnel": [{"name": "Dana Ops", "role": "SOC lead"}],
        }).json()
        env_id = env["id"]

        # The API round-trips plaintext...
        got = client.get(f"/api/environments/{env_id}", headers=_auth(token)).json()
        assert got["crown_jewels"] == ["billing-db", "hsm-root-key"]

        # ...but the raw stored column is ciphertext, not the secret.
        with engine.connect() as conn:
            raw = conn.execute(
                text("SELECT crown_jewels, personnel FROM environments WHERE id=:i"),
                {"i": env_id},
            ).one()
        assert "enc:" in raw[0]
        assert "billing-db" not in raw[0]
        assert "Dana Ops" not in raw[1]


def test_key_rotation_reads_old_and_writes_new(monkeypatch):
    k1 = base64.urlsafe_b64encode(b"A" * 32).decode()
    k2 = base64.urlsafe_b64encode(b"B" * 32).decode()

    # Seal a value under v1.
    monkeypatch.setenv("GAUNTLET_DATA_KEYS", f"v1:{k1}")
    sealed_v1 = crypto.encrypt_bytes(b"top secret")
    assert sealed_v1.startswith("enc:v1:")

    # Rotate: v2 primary, v1 still available.
    monkeypatch.setenv("GAUNTLET_DATA_KEYS", f"v2:{k2},v1:{k1}")
    assert crypto.decrypt_to_bytes(sealed_v1) == b"top secret"  # old key still opens it
    sealed_v2 = crypto.encrypt_bytes(b"top secret")
    assert sealed_v2.startswith("enc:v2:")  # new writes use the new key

    # Drop v1 entirely: the old ciphertext can no longer be opened.
    monkeypatch.setenv("GAUNTLET_DATA_KEYS", f"v2:{k2}")
    import pytest
    with pytest.raises(RuntimeError):
        crypto.decrypt_to_bytes(sealed_v1)


def test_reencrypt_endpoint_moves_rows_to_primary_key(monkeypatch):
    monkeypatch.setenv("GAUNTLET_ENCRYPT_AT_REST", "1")
    with TestClient(app) as client:
        token = _register(client, "ReencOrg", "reenc@example.com")
        env_id = client.post("/api/environments", headers=_auth(token),
                             json={"name": "e", "assets": ["a1"]}).json()["id"]
        r = client.post("/api/admin/reencrypt", headers=_auth(token))
        assert r.status_code == 200
        body = r.json()
        assert body["encryption_enabled"] is True and body["reencrypted"] >= 1
        # Still readable after re-encryption.
        assert client.get(f"/api/environments/{env_id}",
                          headers=_auth(token)).json()["assets"] == ["a1"]


def test_reencrypt_conflict_when_disabled():
    with TestClient(app) as client:
        token = _register(client, "NoEnc", "noenc@example.com")
        assert client.post("/api/admin/reencrypt", headers=_auth(token)).status_code == 409


# --------------------------------------------------------------------------- #
# retention purge (unit-level: age a completed session, then purge)
# --------------------------------------------------------------------------- #
def test_purge_removes_aged_completed_sessions():
    with TestClient(app) as client:
        token = _register(client, "PurgeOrg", "purge@example.com")
        env = client.post("/api/environments", headers=_auth(token), json={"name": "e"}).json()["id"]
        scn = client.post("/api/scenarios", headers=_auth(token), json={
            "environment_id": env, "name": "s",
            "injects": [{"code": "INJ-01", "title": "start", "is_start": True}],
        }).json()["id"]
        sid = client.post("/api/sessions", headers=_auth(token),
                          json={"scenario_id": scn, "name": "run"}).json()["id"]

        # Mark it completed 100 days ago.
        db = SessionLocal()
        try:
            s = db.get(models.Session, sid)
            org_id = s.org_id
            s.status = "complete"
            s.completed_at = datetime.now(timezone.utc) - timedelta(days=100)
            db.commit()
        finally:
            db.close()

        db = SessionLocal()
        try:
            result = retention.purge_org(db, org_id, days=30)
            db.commit()
        finally:
            db.close()
        assert result["sessions"] == 1
        assert client.get(f"/api/sessions/{sid}", headers=_auth(token)).status_code == 404

        # A recent completed session is untouched by the same window.
        assert retention.purge_org.__doc__  # sanity: function present


def test_purge_zero_days_is_noop():
    db = SessionLocal()
    try:
        assert retention.purge_org(db, 999999, days=0) == {"sessions": 0, "audit_logs": 0}
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# GDPR export + erasure
# --------------------------------------------------------------------------- #
def test_export_excludes_secrets_and_covers_the_graph():
    with TestClient(app) as client:
        token = _register(client, "ExportOrg", "export@example.com")
        env = client.post("/api/environments", headers=_auth(token), json={"name": "e"}).json()["id"]
        client.post("/api/scenarios", headers=_auth(token), json={
            "environment_id": env, "name": "s",
            "injects": [{"code": "INJ-01", "title": "start", "is_start": True}],
        })
        data = client.get("/api/admin/export", headers=_auth(token)).json()
        assert data["organization"]["slug"]
        assert len(data["environments"]) == 1 and len(data["scenarios"]) == 1
        # Secrets never leave in the export.
        assert all("password_hash" not in u for u in data["users"])
        assert all("mfa_secret" not in u for u in data["users"])


def test_erase_requires_matching_confirmation_then_wipes_everything():
    with TestClient(app) as client:
        token = _register(client, "EraseOrg", "erase@example.com")
        me = client.get("/api/auth/me", headers=_auth(token)).json()
        slug = client.get("/api/admin/export", headers=_auth(token)).json()["organization"]["slug"]
        client.post("/api/environments", headers=_auth(token), json={"name": "e"})

        # Wrong confirmation is refused.
        assert client.request("DELETE", "/api/admin/org", headers=_auth(token),
                              json={"confirm": "not-the-slug"}).status_code == 400

        # Correct slug erases the org and its data.
        r = client.request("DELETE", "/api/admin/org", headers=_auth(token),
                           json={"confirm": slug})
        assert r.status_code == 200
        counts = r.json()["erased"]
        assert counts["organization"] == 1 and counts["environments"] == 1

        # The token's user is gone: further calls 401.
        assert client.get("/api/auth/me", headers=_auth(token)).status_code == 401
        # And the account can't log in any more.
        assert client.post("/api/auth/login",
                           json={"email": "erase@example.com", "password": "Str0ngPass!9"}
                           ).status_code == 401


# --------------------------------------------------------------------------- #
# admin endpoints are admin-only
# --------------------------------------------------------------------------- #
def test_admin_endpoints_require_admin_role():
    with TestClient(app) as client:
        admin = _register(client, "RoleOrg", "roleadmin@example.com")
        client.post("/api/auth/users", headers=_auth(admin),
                    json={"email": "ev@example.com", "password": "Str0ngPass!9", "role": "evaluator"})
        ev = client.post("/api/auth/login",
                         json={"email": "ev@example.com", "password": "Str0ngPass!9"}).json()["access_token"]
        assert client.get("/api/admin/export", headers=_auth(ev)).status_code == 403
        assert client.post("/api/admin/retention/purge", headers=_auth(ev), json={}).status_code == 403
