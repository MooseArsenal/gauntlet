"""A6 — security hardening pass (post-M10 review).

Covers the fixes from the input-validation / authorization review:
- sensitive exports are gated to evaluator+ (participants can't pull the full,
  unredacted timeline / evidence / reports the fog-of-war layer exists to hide);
- the scenario graph-save and direct-create paths honour MAX_INJECTS;
- the F6 bulk-import payload is size-capped;
- CSV exports neutralise spreadsheet formula injection;
- live-inject authorization TTL is clamped (no overflow, no never-expiring grant);
- oversized request bodies are rejected by the global middleware.
"""
from fastapi.testclient import TestClient

from app import exports
from app.main import app


def _auth(t):
    return {"Authorization": f"Bearer {t}"}


def _org_with_roles(client):
    """A fresh org's admin token plus an evaluator and a participant token."""
    import uuid
    o = uuid.uuid4().hex[:8]
    admin = client.post("/api/auth/register", json={
        "org_name": f"Org-{o}", "email": f"admin-{o}@ex.com", "password": "Str0ngPass!9",
    }).json()["access_token"]
    for role in ("evaluator", "participant"):
        client.post("/api/auth/users", headers=_auth(admin), json={
            "email": f"{role}-{o}@ex.com", "password": "Str0ngPass!9", "role": role})
    ev = client.post("/api/auth/login", json={
        "email": f"evaluator-{o}@ex.com", "password": "Str0ngPass!9"}).json()["access_token"]
    part = client.post("/api/auth/login", json={
        "email": f"participant-{o}@ex.com", "password": "Str0ngPass!9"}).json()["access_token"]
    return admin, ev, part


def _session_with_report(client, admin):
    env = client.post("/api/environments", headers=_auth(admin), json={"name": "e"}).json()["id"]
    scn = client.post("/api/scenarios", headers=_auth(admin), json={
        "environment_id": env, "name": "s",
        "injects": [{"code": "INJ-01", "title": "start", "is_start": True}],
    }).json()["id"]
    sid = client.post("/api/sessions", headers=_auth(admin),
                      json={"scenario_id": scn, "name": "r"}).json()["id"]
    client.post(f"/api/sessions/{sid}/start", headers=_auth(admin))
    rid = client.post(f"/api/sessions/{sid}/reports", headers=_auth(admin),
                      json={"audience": "executive"}).json()["id"]
    return sid, rid


# --------------------------------------------------------------------------- #
# Export authorization (fog-of-war): participants must NOT reach full exports
# --------------------------------------------------------------------------- #
def test_participant_is_denied_sensitive_exports():
    with TestClient(app) as client:
        admin, ev, part = _org_with_roles(client)
        sid, rid = _session_with_report(client, admin)
        paths = [
            f"/api/sessions/{sid}/timeline.csv",
            f"/api/sessions/{sid}/timeline.json",
            f"/api/sessions/{sid}/reports/{rid}.docx",
            f"/api/sessions/{sid}/evidence.docx",
            f"/api/sessions/{sid}/evidence.pdf",
            f"/api/sessions/{sid}/evidence",
            f"/api/sessions/{sid}/reports/{rid}.pdf",
            f"/api/sessions/{sid}/reports",
        ]
        for p in paths:
            assert client.get(p, headers=_auth(part)).status_code == 403, f"participant reached {p}"
            assert client.get(p, headers=_auth(ev)).status_code == 200, f"evaluator blocked from {p}"


# --------------------------------------------------------------------------- #
# MAX_INJECTS is enforced on the graph-save and direct-create paths
# --------------------------------------------------------------------------- #
def test_graph_and_create_honour_max_injects(monkeypatch):
    import app.api.scenarios as scen
    monkeypatch.setattr(scen, "MAX_INJECTS", 2)
    with TestClient(app) as client:
        env = client.post("/api/environments", json={"name": "cap"}).json()["id"]
        too_many = [{"code": f"INJ-{i}", "title": "x", "is_start": i == 0} for i in range(3)]
        # direct create
        r = client.post("/api/scenarios", json={"environment_id": env, "name": "c", "injects": too_many})
        assert r.status_code == 413, r.text
        # graph save
        sid = client.post("/api/scenarios", json={
            "environment_id": env, "name": "g",
            "injects": [{"code": "INJ-0", "title": "s", "is_start": True}]}).json()["id"]
        r = client.put(f"/api/scenarios/{sid}/graph", json={"injects": too_many})
        assert r.status_code == 422
        assert any("too many injects" in p for p in r.json()["detail"]["graph"])


# --------------------------------------------------------------------------- #
# F6 bulk import is size-capped
# --------------------------------------------------------------------------- #
def test_import_payload_is_size_capped(monkeypatch):
    import app.api.environments as envs
    monkeypatch.setattr(envs, "MAX_IMPORT_BYTES", 64)
    with TestClient(app) as client:
        r = client.post("/api/environments/import", json={
            "source": "cmdb", "format": "json", "name": "big", "data": "x" * 500})
        assert r.status_code == 413


# --------------------------------------------------------------------------- #
# CSV formula injection is neutralised
# --------------------------------------------------------------------------- #
def test_csv_formula_injection_is_neutralised():
    assert exports._csv_safe("=HYPERLINK(\"http://evil\")").startswith("'=")
    for lead in ("+", "-", "@", "\t", "\r"):
        assert exports._csv_safe(lead + "x").startswith("'")
    # benign values pass through untouched
    assert exports._csv_safe("INJ-01") == "INJ-01"
    assert exports._csv_safe("") == ""


# --------------------------------------------------------------------------- #
# Live-inject authorization TTL is clamped
# --------------------------------------------------------------------------- #
def test_authorization_ttl_is_clamped(monkeypatch):
    import app.api.live as live
    monkeypatch.setattr(live, "MAX_AUTHORIZATION_TTL_MIN", 60)
    with TestClient(app) as client:
        env = client.post("/api/environments", json={"name": "ttl"}).json()["id"]
        scn = client.post("/api/scenarios", json={
            "environment_id": env, "name": "s",
            "injects": [{"code": "INJ-01", "title": "start", "is_start": True}]}).json()["id"]
        sid = client.post("/api/sessions", json={"scenario_id": scn, "name": "r"}).json()["id"]
        # An absurd TTL must not 500 (overflow) and must be capped, not never-expiring.
        r = client.post(f"/api/sessions/{sid}/authorize", json={
            "scope": ["*"], "authorized_by": "cmdr", "ttl_minutes": 10 ** 12})
        assert r.status_code == 200, r.text


# --------------------------------------------------------------------------- #
# Global request-body-size backstop
# --------------------------------------------------------------------------- #
def test_oversized_request_body_is_rejected(monkeypatch):
    import app.main as m
    monkeypatch.setattr(m, "MAX_REQUEST_BYTES", 100)
    with TestClient(app) as client:
        r = client.post("/api/environments", json={"name": "x" * 500})
        assert r.status_code == 413
