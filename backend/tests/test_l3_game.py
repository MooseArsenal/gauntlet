"""L3 — game mode is a skin: the engine exposes what the skin needs and nothing
about the record changes."""
import uuid

from fastapi.testclient import TestClient

from app.main import app

PW = "Str0ngPass!9"


def _h(t):
    return {"Authorization": f"Bearer {t}"}


def test_ruling_carries_its_probability_and_cell_view_carries_impact():
    with TestClient(app) as c:
        o = uuid.uuid4().hex[:8]
        t = c.post("/api/auth/register", json={"org_name": f"O{o}", "email": f"a{o}@ex.com", "password": PW}).json()["access_token"]
        h = _h(t)
        env = c.post("/api/environments", headers=h, json={
            "name": "e", "assets": [{"code": "SRV-01", "name": "srv"}],
            "detections": [{"name": "EDR", "covers": ["T1003"], "assets": ["*"], "efficacy": 0.7, "latency_min": 4}]}).json()["id"]
        scn = c.post("/api/scenarios", headers=h, json={
            "environment_id": env, "name": "s",
            "injects": [{"code": "INJ-01", "title": "t", "narrative": "n", "is_start": True, "expected_actions": ["Act"],
                         "branches": [{"when": "proctor_choice", "goto": "INJ-02", "impact": {"cost": 400000, "downtime_hours": 8}}]},
                        {"code": "INJ-02", "title": "end", "narrative": "n"}]}).json()["id"]
        sid = c.post("/api/sessions", headers=h, json={"scenario_id": scn, "name": "r"}).json()["id"]
        c.post(f"/api/sessions/{sid}/start", headers=h)
        r = c.post(f"/api/sessions/{sid}/adjudicate", headers=h, json={"techniques": ["T1003"], "target_asset": "SRV-01", "description": "m"}).json()["ruling"]
        assert r["probability"] == 0.7 and r["detected"] is True
        miss = c.post(f"/api/sessions/{sid}/adjudicate", headers=h, json={"techniques": ["T1566"], "target_asset": "SRV-01", "description": "m"}).json()["ruling"]
        assert miss["probability"] == 0.0 and miss["detected"] is False
        assert c.get(f"/api/sessions/{sid}/cell/blue_cell", headers=h).json()["impact"] == {}
        c.post(f"/api/sessions/{sid}/advance", headers=h, json={"when": "proctor_choice"})
        assert c.get(f"/api/sessions/{sid}/cell/blue_cell", headers=h).json()["impact"] == {"cost": 400000, "downtime_hours": 8}
        assert c.get(f"/api/sessions/{sid}/verify", headers=h).json()["chain_valid"] is True
