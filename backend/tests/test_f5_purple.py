"""F5 — purple-team interactive mode: red-cell action submission, live
adjudication onto the timeline, and the scoreboard."""
from fastapi.testclient import TestClient

from app.main import app


def _auth(t):
    return {"Authorization": f"Bearer {t}"}


def _started_session(client):
    scn = client.get("/api/scenarios").json()[0]["id"]
    sid = client.post("/api/sessions", json={"scenario_id": scn, "name": "purple"}).json()["id"]
    client.post(f"/api/sessions/{sid}/start")
    return sid


def _submit(client, sid, techniques, target, headers=None):
    return client.post(f"/api/sessions/{sid}/red-actions",
                       json={"techniques": techniques, "target": target, "action": "recon"},
                       headers=headers or {})


# --------------------------------------------------------------------------- #
# submission + live adjudication
# --------------------------------------------------------------------------- #
def test_red_action_is_adjudicated_and_lands_on_timeline():
    with TestClient(app) as client:
        sid = _started_session(client)
        r = _submit(client, sid, ["T1003.001"], "FIN-APP-02")
        assert r.status_code == 201, r.text
        body = r.json()
        assert "detected" in body["ruling"]
        assert body["event"]["kind"] == "red_action"
        assert body["event"]["payload"]["actor"]

        # It shows up in the red-action list and on the verifiable timeline.
        actions = client.get(f"/api/sessions/{sid}/red-actions").json()
        assert len(actions) == 1
        assert client.get(f"/api/sessions/{sid}/verify").json()["chain_valid"] is True


# --------------------------------------------------------------------------- #
# scoreboard aggregation
# --------------------------------------------------------------------------- #
def test_scoreboard_tallies_detection_and_techniques():
    with TestClient(app) as client:
        sid = _started_session(client)
        rulings = []
        for techniques, target in (
            (["T1003.001"], "FIN-APP-02"),
            (["T1566.001"], "MAIL-01"),
            (["T9999"], "no-such-asset"),  # uncovered -> a detection gap
        ):
            rulings.append(_submit(client, sid, techniques, target).json()["ruling"]["detected"])

        sb = client.get(f"/api/sessions/{sid}/scoreboard").json()
        assert sb["red_actions"] == 3
        assert sb["detected"] == sum(1 for d in rulings if d)
        assert sb["missed"] == sum(1 for d in rulings if not d)
        assert sb["detected"] + sb["missed"] == 3
        assert 0.0 <= sb["detection_rate"] <= 1.0
        techs = {t["technique"] for t in sb["by_technique"]}
        assert {"T1003.001", "T1566.001", "T9999"} <= techs
        # An uncovered technique records an attempt with zero detections.
        gap = next(t for t in sb["by_technique"] if t["technique"] == "T9999")
        assert gap["attempts"] == 1 and gap["detected"] == 0


def test_empty_scoreboard():
    with TestClient(app) as client:
        sid = _started_session(client)
        sb = client.get(f"/api/sessions/{sid}/scoreboard").json()
        assert sb["red_actions"] == 0
        assert sb["detection_rate"] is None
        assert sb["mean_time_to_detect_min"] is None


# --------------------------------------------------------------------------- #
# role gating + tenant isolation
# --------------------------------------------------------------------------- #
def test_participant_cannot_submit_red_actions():
    with TestClient(app) as client:
        admin = client.post("/api/auth/register", json={
            "org_name": "PurpleOrg", "email": "purple-admin@example.com", "password": "Str0ngPass!9",
        }).json()["access_token"]
        # Admin adds a participant (blue-only) and sets up a session.
        client.post("/api/auth/users", headers=_auth(admin), json={
            "email": "blue@example.com", "password": "Str0ngPass!9", "role": "participant"})
        blue = client.post("/api/auth/login",
                           json={"email": "blue@example.com", "password": "Str0ngPass!9"}
                           ).json()["access_token"]
        env = client.post("/api/environments", headers=_auth(admin), json={"name": "e"}).json()["id"]
        scn = client.post("/api/scenarios", headers=_auth(admin), json={
            "environment_id": env, "name": "s",
            "injects": [{"code": "INJ-01", "title": "start", "is_start": True}],
        }).json()["id"]
        sid = client.post("/api/sessions", headers=_auth(admin),
                          json={"scenario_id": scn, "name": "r"}).json()["id"]

        # A participant who has not joined as the red cell may not submit red actions (H1).
        assert _submit(client, sid, ["T1003.001"], "x", headers=_auth(blue)).status_code == 403
        # And may not even read the scoreboard until they have joined (H1) …
        assert client.get(f"/api/sessions/{sid}/scoreboard", headers=_auth(blue)).status_code == 403
        code = client.post(f"/api/sessions/{sid}/join-code", headers=_auth(admin)).json()["join_code"]
        assert client.post("/api/join", headers=_auth(blue), json={"code": code, "cell": "blue_cell"}).status_code == 200
        # … after which the blue cell sees the scoreboard but still cannot move as red.
        assert client.get(f"/api/sessions/{sid}/scoreboard", headers=_auth(blue)).status_code == 200
        assert _submit(client, sid, ["T1003.001"], "x", headers=_auth(blue)).status_code == 403


def test_red_actions_tenant_scoped():
    with TestClient(app) as client:
        sid = _started_session(client)  # owned by the seeded default org
        other = client.post("/api/auth/register", json={
            "org_name": "PurpleOther", "email": "purple-other@example.com", "password": "Str0ngPass!9",
        }).json()["access_token"]
        h = _auth(other)
        assert _submit(client, sid, ["T1003.001"], "x", headers=h).status_code == 404
        assert client.get(f"/api/sessions/{sid}/scoreboard", headers=h).status_code == 404
        assert client.get(f"/api/sessions/{sid}/red-actions", headers=h).status_code == 404
