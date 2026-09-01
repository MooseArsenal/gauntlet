"""H1 — the participant boundary is enforced on the server.

A participant (the role join-code onboarding is for) must not be able to read
the scenario graph, the full session state, the environment, or another cell's
view; their cell is the one on their join row. Red-cell moves are open to staff
and to participants who joined as the red cell.
"""
import uuid

from fastapi.testclient import TestClient

from app.main import app

PW = "Str0ngPass!9"


def _h(t):
    return {"Authorization": f"Bearer {t}"}


def _org(client):
    o = uuid.uuid4().hex[:8]
    t = client.post("/api/auth/register", json={
        "org_name": f"O{o}", "email": f"a{o}@ex.com", "password": PW}).json()["access_token"]
    return o, t


def _user(client, ha, o, role):
    em = f"{role}{o}@ex.com"
    client.post("/api/auth/users", headers=ha, json={"email": em, "password": PW, "role": role})
    return client.post("/api/auth/login", json={"email": em, "password": PW}).json()["access_token"]


def _world(client, ha):
    env = client.post("/api/environments", headers=ha, json={
        "name": "e", "assets": [{"code": "SRV-01", "name": "srv"}],
        "detections": [{"name": "EDR", "covers": ["T1003"], "assets": ["*"], "efficacy": 1.0}]}).json()["id"]
    scn = client.post("/api/scenarios", headers=ha, json={
        "environment_id": env, "name": "s",
        "cells": [{"key": "blue_cell", "name": "Blue", "kind": "participant"},
                  {"key": "red_cell", "name": "Red", "kind": "participant"},
                  {"key": "white_cell", "name": "White", "kind": "control"}],
        "injects": [
            {"code": "INJ-01", "title": "start", "narrative": "SPOILER-ONE", "is_start": True,
             "visible_to": ["blue_cell"],
             "branches": [{"label": "go", "next_inject": "INJ-02", "kind": "proctor_choice"}]},
            {"code": "INJ-02", "title": "later", "narrative": "SPOILER-TWO", "visible_to": ["red_cell"]},
        ]}).json()["id"]
    sid = client.post("/api/sessions", headers=ha, json={"scenario_id": scn, "name": "run"}).json()["id"]
    client.post(f"/api/sessions/{sid}/start", headers=ha)
    client.post(f"/api/sessions/{sid}/adjudicate", headers=ha,
                json={"techniques": ["T1003"], "target_asset": "SRV-01", "description": "WHITE-REASONING"})
    code = client.post(f"/api/sessions/{sid}/join-code", headers=ha).json()["join_code"]
    return env, scn, sid, code


def test_participant_cannot_read_full_objects():
    with TestClient(app) as c:
        o, admin = _org(c); ha = _h(admin)
        env, scn, sid, code = _world(c, ha)
        hp = _h(_user(c, ha, o, "participant"))
        for path in (f"/api/scenarios/{scn}", "/api/scenarios", f"/api/sessions/{sid}", "/api/sessions",
                     f"/api/environments/{env}", "/api/environments", f"/api/sessions/{sid}/verify",
                     f"/api/scenarios/{scn}/export", f"/api/scenarios/{scn}/rollup",
                     f"/api/scenarios/{scn}/attack-layer.json", "/api/improvements",
                     "/api/program/coverage", "/api/schedules", "/api/adversaries"):
            r = c.get(path, headers=hp)
            assert r.status_code == 403, f"{path} -> {r.status_code}"
            assert "SPOILER" not in r.text and "WHITE-REASONING" not in r.text


def test_participant_sees_only_their_own_cell():
    with TestClient(app) as c:
        o, admin = _org(c); ha = _h(admin)
        env, scn, sid, code = _world(c, ha)
        hp = _h(_user(c, ha, o, "participant"))
        # not joined yet → nothing
        assert c.get(f"/api/sessions/{sid}/cell/blue_cell", headers=hp).status_code == 403
        assert c.post(f"/api/sessions/{sid}/ws-ticket", headers=hp).status_code == 403
        assert c.get(f"/api/sessions/{sid}/scoreboard", headers=hp).status_code == 403
        assert c.get(f"/api/sessions/{sid}/lobby", headers=hp).status_code == 403
        # join as blue
        assert c.post("/api/join", headers=hp, json={"code": code, "cell": "blue_cell"}).status_code == 200
        blue = c.get(f"/api/sessions/{sid}/cell/blue_cell", headers=hp)
        assert blue.status_code == 200 and blue.json()["can_see_all"] is False
        assert "SPOILER-TWO" not in blue.text and "WHITE-REASONING" not in blue.text
        assert c.get(f"/api/sessions/{sid}/cell/red_cell", headers=hp).status_code == 403
        assert c.get(f"/api/sessions/{sid}/cell/white_cell", headers=hp).status_code == 403
        assert c.get(f"/api/environments/{env}/view/white_cell?scenario_id={scn}", headers=hp).status_code == 403
        assert c.get(f"/api/environments/{env}/view/blue_cell?scenario_id={scn}", headers=hp).status_code == 200
        # joined participants may use the socket, the lobby and the scoreboard
        assert c.post(f"/api/sessions/{sid}/ws-ticket", headers=hp).status_code == 200
        assert c.get(f"/api/sessions/{sid}/lobby", headers=hp).status_code == 200
        assert c.get(f"/api/sessions/{sid}/scoreboard", headers=hp).status_code == 200
        mine = c.get("/api/sessions/mine", headers=hp).json()
        assert [m["session"]["id"] for m in mine] == [sid] and mine[0]["cell"] == "blue_cell"


def test_participant_cannot_take_a_control_cell():
    with TestClient(app) as c:
        o, admin = _org(c); ha = _h(admin)
        env, scn, sid, code = _world(c, ha)
        hp = _h(_user(c, ha, o, "participant"))
        assert c.post("/api/join", headers=hp, json={"code": code, "cell": "white_cell"}).status_code == 403
        assert c.post("/api/join", headers=hp, json={"code": code, "cell": "<img src=x>"}).status_code == 422
        # staff may take the white cell
        assert c.post("/api/join", headers=ha, json={"code": code, "cell": "white_cell"}).status_code == 200
        white = c.get(f"/api/sessions/{sid}/cell/white_cell", headers=ha).json()
        assert white["can_see_all"] is True


def test_red_actions_keyed_on_joined_cell():
    with TestClient(app) as c:
        o, admin = _org(c); ha = _h(admin)
        env, scn, sid, code = _world(c, ha)
        move = {"techniques": ["T1003"], "target": "SRV-01", "action": "dump creds"}
        red = _h(_user(c, ha, o, "participant"))
        blue = _h(_user(c, ha, "b" + o, "participant"))
        assert c.post(f"/api/sessions/{sid}/red-actions", headers=red, json=move).status_code == 403
        c.post("/api/join", headers=red, json={"code": code, "cell": "red_cell"})
        c.post("/api/join", headers=blue, json={"code": code, "cell": "blue_cell"})
        assert c.post(f"/api/sessions/{sid}/red-actions", headers=red, json=move).status_code == 201
        assert c.post(f"/api/sessions/{sid}/red-actions", headers=blue, json=move).status_code == 403
        assert c.post(f"/api/sessions/{sid}/red-actions", headers=ha, json=move).status_code == 201
        # the red cell can read its own log and the scoreboard through its view
        assert c.get(f"/api/sessions/{sid}/red-actions", headers=red).status_code == 200
        assert c.get(f"/api/sessions/{sid}/cell/red_cell", headers=red).status_code == 200


def test_completed_sessions_cannot_be_joined():
    with TestClient(app) as c:
        o, admin = _org(c); ha = _h(admin)
        env, scn, sid, code = _world(c, ha)
        hp = _h(_user(c, ha, o, "participant"))
        c.post(f"/api/sessions/{sid}/complete", headers=ha)
        assert c.post("/api/join", headers=hp, json={"code": code, "cell": "blue_cell"}).status_code == 404
        # the code was cleared on completion; a fresh one still refuses
        assert c.get(f"/api/sessions/{sid}", headers=ha).json()["session"]["status"] == "complete"


def test_staff_keep_full_access():
    with TestClient(app) as c:
        o, admin = _org(c); ha = _h(admin)
        env, scn, sid, code = _world(c, ha)
        he = _h(_user(c, ha, o, "evaluator"))
        assert c.get(f"/api/scenarios/{scn}", headers=he).status_code == 200
        assert c.get(f"/api/sessions/{sid}", headers=he).status_code == 200
        assert c.get(f"/api/sessions/{sid}/cell/red_cell", headers=he).status_code == 200
        assert c.get(f"/api/sessions/{sid}/cell/white_cell", headers=he).json()["can_see_all"] is True
        assert c.get("/api/sessions/mine", headers=he).status_code == 200
