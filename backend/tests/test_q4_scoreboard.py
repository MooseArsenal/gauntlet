"""Q4 — the live blue-vs-red scoreboard reflects console adjudications too.

The purple-team scoreboard originally tallied only explicit red-cell submissions
(`red_action`). The console proctor rules moves via `/adjudicate` (kind
`adjudication`), which carries the same ruling payload — so the scoreboard now
counts both, and populates from the ordinary console flow.
"""
from fastapi.testclient import TestClient

from app.main import app


def _running_session(client):
    env = client.post("/api/environments", json={
        "name": "sb", "sector": "financial",
        "detections": [{"name": "EDR", "type": "edr", "covers": ["T1003.001"], "assets": ["*"],
                        "efficacy": 0.9, "latency_min": 8}],
    }).json()["id"]
    scn = client.post("/api/scenarios", json={
        "environment_id": env, "name": "s",
        "injects": [{"code": "INJ-01", "title": "start", "is_start": True,
                     "attack_techniques": ["T1003.001"], "target_asset": "FIN-APP-02"}],
    }).json()["id"]
    sid = client.post("/api/sessions", json={"scenario_id": scn, "name": "r"}).json()["id"]
    client.post(f"/api/sessions/{sid}/start")
    return sid


def test_scoreboard_starts_empty():
    with TestClient(app) as client:
        sid = _running_session(client)
        sb = client.get(f"/api/sessions/{sid}/scoreboard").json()
        assert sb["red_actions"] == 0
        assert sb["detected"] == 0


def test_console_adjudication_feeds_the_scoreboard():
    with TestClient(app) as client:
        sid = _running_session(client)
        # A detected move (matches the EDR detection) …
        client.post(f"/api/sessions/{sid}/adjudicate",
                    json={"techniques": ["T1003.001"], "target_asset": "FIN-APP-02"})
        # … and a missed one (no matching control).
        client.post(f"/api/sessions/{sid}/adjudicate",
                    json={"techniques": ["T1195.002"], "target_asset": "OTHER"})
        sb = client.get(f"/api/sessions/{sid}/scoreboard").json()
        assert sb["red_actions"] == 2, sb
        assert sb["detected"] == 1
        assert sb["missed"] == 1
        assert sb["detection_rate"] == 0.5
        techs = {r["technique"] for r in sb["by_technique"]}
        assert "T1003.001" in techs


def test_scoreboard_counts_both_red_actions_and_adjudications():
    with TestClient(app) as client:
        sid = _running_session(client)
        client.post(f"/api/sessions/{sid}/adjudicate",
                    json={"techniques": ["T1003.001"], "target_asset": "FIN-APP-02"})
        client.post(f"/api/sessions/{sid}/red-actions",
                    json={"action": "dump creds", "techniques": ["T1003.001"], "target": "FIN-APP-02"})
        sb = client.get(f"/api/sessions/{sid}/scoreboard").json()
        assert sb["red_actions"] == 2  # one console adjudication + one red-cell submission


def test_red_cell_page_and_assets_served():
    with TestClient(app) as client:
        r = client.get("/red.html")
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]
        assert client.get("/red.js").status_code == 200
