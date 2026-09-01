"""D3 — longitudinal maturity analytics."""
import uuid

from fastapi.testclient import TestClient

from app.main import app


def _auth(t):
    return {"Authorization": f"Bearer {t}"}


def _env_and_scenario(client, h):
    env = client.post("/api/environments", headers=h, json={
        "name": "e", "sector": "financial",
        "detections": [{"name": "EDR", "covers": ["T1003.001"], "assets": ["*"],
                        "efficacy": 0.9, "latency_min": 7}],
    }).json()["id"]
    scn = client.post("/api/scenarios", headers=h, json={
        "environment_id": env, "name": "s",
        "injects": [{"code": "INJ-01", "title": "a", "is_start": True,
                     "attack_techniques": ["T1003.001"], "target_asset": "FIN-APP-02"}],
    }).json()["id"]
    return scn


def _run(client, h, scn, detected_tech, missed_tech):
    sid = client.post("/api/sessions", headers=h, json={"scenario_id": scn, "name": "run"}).json()["id"]
    client.post(f"/api/sessions/{sid}/start", headers=h)
    client.post(f"/api/sessions/{sid}/adjudicate", headers=h,
                json={"techniques": [detected_tech], "target_asset": "FIN-APP-02"})
    client.post(f"/api/sessions/{sid}/adjudicate", headers=h,
                json={"techniques": [missed_tech], "target_asset": "OTHER"})
    return sid


def test_maturity_aggregates_across_exercises():
    o = uuid.uuid4().hex[:8]
    with TestClient(app) as client:
        admin = client.post("/api/auth/register", json={
            "org_name": f"O{o}", "email": f"a{o}@ex.com", "password": "Str0ngPass!9"}).json()["access_token"]
        h = _auth(admin)
        scn = _env_and_scenario(client, h)
        _run(client, h, scn, "T1003.001", "T1590")   # 1/2 detected
        _run(client, h, scn, "T1003.001", "T1595")   # 1/2 detected
        m = client.get("/api/analytics/maturity", headers=h).json()
        assert m["exercises"] == 2
        assert m["exercises_with_activity"] == 2
        assert m["summary"]["detection_rate"] == 0.5
        assert m["summary"]["unique_techniques"] >= 3
        assert len(m["series"]) == 2
        assert all("detection_rate" in s for s in m["series"])


def test_maturity_empty_org():
    o = uuid.uuid4().hex[:8]
    with TestClient(app) as client:
        admin = client.post("/api/auth/register", json={
            "org_name": f"O{o}", "email": f"a{o}@ex.com", "password": "Str0ngPass!9"}).json()["access_token"]
        m = client.get("/api/analytics/maturity", headers=_auth(admin)).json()
        assert m["exercises"] == 0
        assert m["summary"]["detection_rate"] is None


def test_maturity_requires_evaluator():
    o = uuid.uuid4().hex[:8]
    with TestClient(app) as client:
        admin = client.post("/api/auth/register", json={
            "org_name": f"O{o}", "email": f"a{o}@ex.com", "password": "Str0ngPass!9"}).json()["access_token"]
        client.post("/api/auth/users", headers=_auth(admin), json={
            "email": f"p{o}@ex.com", "password": "Str0ngPass!9", "role": "participant"})
        part = client.post("/api/auth/login", json={
            "email": f"p{o}@ex.com", "password": "Str0ngPass!9"}).json()["access_token"]
        assert client.get("/api/analytics/maturity", headers=_auth(part)).status_code == 403


def test_maturity_page_and_assets_served():
    with TestClient(app) as client:
        assert client.get("/analytics.html").status_code == 200
        assert client.get("/analytics.js").status_code == 200
