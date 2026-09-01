"""D1 — MITRE ATT&CK Navigator layer export."""
from fastapi.testclient import TestClient

from app.main import app


def _auth(t):
    return {"Authorization": f"Bearer {t}"}


def _scenario_with_techniques(client, headers=None):
    h = headers or {}
    env = client.post("/api/environments", headers=h, json={
        "name": "e", "sector": "financial",
        "detections": [{"name": "EDR", "covers": ["T1003.001"], "assets": ["*"],
                        "efficacy": 0.9, "latency_min": 7}],
    }).json()["id"]
    scn = client.post("/api/scenarios", headers=h, json={
        "environment_id": env, "name": "layer scn",
        "injects": [
            {"code": "INJ-01", "title": "a", "is_start": True,
             "attack_techniques": ["T1003.001", "T1021.002"], "target_asset": "FIN-APP-02"},
            {"code": "INJ-02", "title": "b", "attack_techniques": ["T1003.001"]},
        ],
    }).json()["id"]
    return env, scn


def test_scenario_layer_is_a_valid_navigator_layer():
    with TestClient(app) as client:
        _, scn = _scenario_with_techniques(client)
        r = client.get(f"/api/scenarios/{scn}/attack-layer.json")
        assert r.status_code == 200
        assert "attachment" in r.headers["content-disposition"]
        layer = r.json()
        assert layer["domain"] == "enterprise-attack"
        assert layer["versions"]["attack"] and layer["versions"]["layer"]
        by_id = {t["techniqueID"]: t for t in layer["techniques"]}
        assert set(by_id) == {"T1003.001", "T1021.002"}
        assert by_id["T1003.001"]["score"] == 2  # used in two injects
        assert by_id["T1021.002"]["score"] == 1


def test_session_layer_reflects_detection():
    with TestClient(app) as client:
        _, scn = _scenario_with_techniques(client)
        sid = client.post("/api/sessions", json={"scenario_id": scn, "name": "s"}).json()["id"]
        client.post(f"/api/sessions/{sid}/start")
        # detected (matches EDR) and missed
        client.post(f"/api/sessions/{sid}/adjudicate",
                    json={"techniques": ["T1003.001"], "target_asset": "FIN-APP-02"})
        client.post(f"/api/sessions/{sid}/adjudicate",
                    json={"techniques": ["T1021.002"], "target_asset": "OTHER"})
        layer = client.get(f"/api/sessions/{sid}/attack-layer.json").json()
        by_id = {t["techniqueID"]: t for t in layer["techniques"]}
        assert by_id["T1003.001"]["score"] == 100 and by_id["T1003.001"]["color"] == "#3DD68C"
        assert by_id["T1021.002"]["score"] == 0 and by_id["T1021.002"]["color"] == "#FF4D6D"


def test_session_layer_requires_evaluator():
    """A participant can't pull detection coverage (same gate as other exports)."""
    import uuid
    o = uuid.uuid4().hex[:8]
    with TestClient(app) as client:
        admin = client.post("/api/auth/register", json={
            "org_name": f"O{o}", "email": f"a{o}@ex.com", "password": "Str0ngPass!9"}).json()["access_token"]
        client.post("/api/auth/users", headers=_auth(admin), json={
            "email": f"p{o}@ex.com", "password": "Str0ngPass!9", "role": "participant"})
        part = client.post("/api/auth/login", json={
            "email": f"p{o}@ex.com", "password": "Str0ngPass!9"}).json()["access_token"]
        _, scn = _scenario_with_techniques(client, _auth(admin))
        sid = client.post("/api/sessions", headers=_auth(admin),
                          json={"scenario_id": scn, "name": "s"}).json()["id"]
        assert client.get(f"/api/sessions/{sid}/attack-layer.json", headers=_auth(part)).status_code == 403
        assert client.get(f"/api/sessions/{sid}/attack-layer.json", headers=_auth(admin)).status_code == 200
