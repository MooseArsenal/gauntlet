"""L4 — education edition: cohorts, enrolment by code, seating, anonymous
grading and the gradebook; session replay as scenes and rewind-to-branch."""
import uuid

import pytest
from fastapi.testclient import TestClient

from app import entitlements
from app.database import SessionLocal
from app.main import app

PW = "Str0ngPass!9"


def _h(t):
    return {"Authorization": f"Bearer {t}"}


def _org(client):
    o = uuid.uuid4().hex[:8]
    t = client.post("/api/auth/register", json={
        "org_name": f"O{o}", "email": f"a{o}@ex.com", "password": PW}).json()["access_token"]
    return o, t


def _user(client, ha, o, role, tag=""):
    em = f"{role}{tag}{o}@ex.com"
    client.post("/api/auth/users", headers=ha, json={"email": em, "password": PW, "role": role})
    return client.post("/api/auth/login", json={"email": em, "password": PW}).json()["access_token"]


def _world(client, ha):
    env = client.post("/api/environments", headers=ha, json={
        "name": "e", "assets": [{"code": "SRV-01", "name": "srv"}],
        "detections": [{"name": "EDR", "covers": ["T1003"], "assets": ["*"], "efficacy": 1.0}]}).json()["id"]
    scn = client.post("/api/scenarios", headers=ha, json={
        "environment_id": env, "name": "s", "variables": {"tension": 1},
        "cells": [{"key": "blue_cell", "name": "Blue", "kind": "participant"},
                  {"key": "exec_cell", "name": "Exec", "kind": "participant"},
                  {"key": "white_cell", "name": "White", "kind": "control"}],
        "injects": [
            {"code": "INJ-01", "title": "alert", "narrative": "n1", "is_start": True, "visible_to": ["blue_cell", "exec_cell"],
             "clock": "T+00:05",
             "meta": {"decision": {"prompt": "First move?", "options": [
                 {"key": "a", "label": "Isolate", "score": 1.0}, {"key": "b", "label": "Wait", "score": 0.2}]}},
             "branches": [{"label": "contain", "when": "proctor_choice", "goto": "INJ-02", "set": {"tension": 2}},
                          {"label": "ignore", "when": "proctor_choice", "goto": "INJ-03"}]},
            {"code": "INJ-02", "title": "contained", "narrative": "n2", "visible_to": ["blue_cell", "exec_cell"], "clock": "T+00:20",
             "expected_actions": ["Open an incident", "Notify the CISO"],
             "branches": [{"label": "end", "when": "proctor_choice", "goto": "INJ-04"}]},
            {"code": "INJ-03", "title": "spread", "narrative": "n3", "visible_to": ["blue_cell"], "clock": "T+00:20",
             "branches": [{"label": "end", "when": "proctor_choice", "goto": "INJ-04"}]},
            {"code": "INJ-04", "title": "end", "narrative": "n4", "visible_to": ["blue_cell", "exec_cell"], "clock": "T+00:40"},
        ]}).json()["id"]
    sid = client.post("/api/sessions", headers=ha, json={"scenario_id": scn, "name": "run"}).json()["id"]
    return scn, sid


@pytest.fixture
def community(monkeypatch):
    monkeypatch.delenv("GAUNTLET_LICENSE", raising=False)
    db = SessionLocal()
    try:
        entitlements.store_token(db, None); db.commit()
    finally:
        db.close()
    yield
    db = SessionLocal()
    try:
        entitlements.store_token(db, None); db.commit()
    finally:
        db.close()


def test_cohort_enrol_seat_and_grade():
    with TestClient(app) as c:
        o, admin = _org(c); ha = _h(admin)
        r = c.post("/api/cohorts", headers=ha, json={"name": "CS-401 Incident Response", "anonymous": True})
        assert r.status_code == 201, r.text
        cid, code = r.json()["id"], r.json()["code"]
        assert len(code) == 7 and r.json()["students"] == 0
        # two students create their own accounts from the code alone
        toks = []
        for i in range(2):
            r = c.post("/api/cohorts/enrol", json={"code": code.lower(), "email": f"stu{i}{o}@uni.edu", "password": PW, "name": f"Student {i}"})
            assert r.status_code == 201, r.text
            assert r.json()["user"]["role"] == "participant"
            toks.append(r.json()["access_token"])
        # an existing member joins by code; joining twice keeps the alias
        p3 = _user(c, ha, o, "participant", "3")
        j = c.post("/api/cohorts/join", headers=_h(p3), json={"code": code}).json()
        assert j["alias"] == "S-03" and c.post("/api/cohorts/join", headers=_h(p3), json={"code": code}).json()["alias"] == "S-03"
        # students never count as seats and the instructor sees aliases only while grading is anonymous
        det = c.get(f"/api/cohorts/{cid}", headers=ha).json()
        assert [m["alias"] for m in det["members"]] == ["S-01", "S-02", "S-03"]
        assert all(m["email"] == "" and m["name"] == m["alias"] for m in det["members"])
        # a participant cannot read the cohort roster
        assert c.get(f"/api/cohorts/{cid}", headers=_h(toks[0])).status_code == 403
        # a classroom run: attach, seat everyone in the blue cell, start
        scn, sid = _world(c, ha)
        assert c.post(f"/api/cohorts/{cid}/sessions/{sid}/seat", headers=ha, json={"cell": "blue_cell"}).status_code == 409  # attach first
        assert c.put(f"/api/cohorts/{cid}/sessions/{sid}", headers=ha).json()["sessions"][0]["id"] == sid
        seat = c.post(f"/api/cohorts/{cid}/sessions/{sid}/seat", headers=ha, json={"cell": "auto"}).json()
        assert seat["seated"] == 3 and seat["cells"] == {"blue_cell": 2, "exec_cell": 1}
        seat = c.post(f"/api/cohorts/{cid}/sessions/{sid}/seat", headers=ha, json={"cell": "blue_cell"}).json()
        assert seat["cells"] == {"blue_cell": 3}
        assert c.post(f"/api/cohorts/{cid}/sessions/{sid}/seat", headers=ha, json={"cell": "white_cell"}).status_code == 422
        lobby = c.get(f"/api/sessions/{sid}/lobby", headers=ha).json()
        assert sorted(m["display_name"] for m in lobby) == ["S-01", "S-02", "S-03"]  # the room sees aliases
        assert c.post(f"/api/sessions/{sid}/start", headers=ha).status_code == 200
        assert c.post(f"/api/sessions/{sid}/respond", headers=_h(toks[0]), json={"option": "a"}).status_code == 201
        assert c.post(f"/api/sessions/{sid}/respond", headers=_h(toks[1]), json={"option": "b"}).status_code == 201
        # gradebook: aliases, grades, coverage
        book = c.get(f"/api/cohorts/{cid}/gradebook", headers=ha).json()
        assert book["cohort"]["revealed"] is False and book["sessions"][0]["possible"] == 1
        rows = {r["alias"]: r for r in book["students"]}
        assert rows["S-01"]["grade"] == 100 and rows["S-02"]["grade"] == 20 and rows["S-03"]["grade"] is None
        assert rows["S-01"]["name"] == "S-01" and rows["S-01"]["email"] == ""
        assert rows["S-03"]["answered"] == 0 and rows["S-03"]["possible"] == 1
        assert book["class_mean_score"] == 0.6
        revealed = c.get(f"/api/cohorts/{cid}/gradebook?reveal=true", headers=ha).json()
        assert revealed["cohort"]["revealed"] is True and revealed["students"][0]["email"] == f"stu0{o}@uni.edu"
        csv = c.get(f"/api/cohorts/{cid}/gradebook.csv", headers=ha)
        assert csv.status_code == 200 and csv.headers["content-type"].startswith("text/csv")
        assert csv.text.splitlines()[0].startswith("alias,name,email,grade") and "S-02,S-02,,20," in csv.text and "run score" in csv.text
        # a student sees only their own standing
        mine = c.get("/api/cohorts/mine", headers=_h(toks[1])).json()
        assert len(mine) == 1 and mine[0]["alias"] == "S-02" and mine[0]["me"]["grade"] == 20
        assert "students" not in mine[0]
        # turn anonymity off: names appear everywhere the instructor looks
        assert c.patch(f"/api/cohorts/{cid}", headers=ha, json={"anonymous": False}).json()["anonymous"] is False
        assert c.get(f"/api/cohorts/{cid}", headers=ha).json()["members"][0]["name"] == "Student 0"
        # close, rotate, remove, archive
        assert c.patch(f"/api/cohorts/{cid}", headers=ha, json={"open": False}).json()["open"] is False
        assert c.post("/api/cohorts/enrol", json={"code": code, "email": f"late{o}@uni.edu", "password": PW}).status_code == 409
        new = c.post(f"/api/cohorts/{cid}/rotate-code", headers=ha).json()["code"]
        assert new != code
        assert c.delete(f"/api/cohorts/{cid}/members/{det['members'][2]['user_id']}", headers=ha).status_code == 204
        assert c.get(f"/api/cohorts/{cid}", headers=ha).json()["students"] == 2
        assert c.delete(f"/api/cohorts/{cid}", headers=ha).status_code == 204
        assert c.get("/api/cohorts", headers=ha).json() == []
        assert c.get(f"/api/cohorts/{cid}", headers=ha).status_code == 404


def test_enrol_and_join_guards():
    with TestClient(app) as c:
        o, admin = _org(c); ha = _h(admin)
        code = c.post("/api/cohorts", headers=ha, json={"name": "x"}).json()["code"]
        assert c.post("/api/cohorts/enrol", json={"code": "NOPE123", "email": f"z{o}@uni.edu", "password": PW}).status_code == 404
        assert c.post("/api/cohorts/enrol", json={"code": code, "email": f"z{o}@uni.edu", "password": "weak"}).status_code == 422
        assert c.post("/api/cohorts/enrol", json={"code": code, "email": f"a{o}@ex.com", "password": PW}).status_code == 409
        # a member of another organisation cannot join this cohort: the code is not a cross-tenant door
        o2, t2 = _org(c)
        assert c.post("/api/cohorts/join", headers=_h(t2), json={"code": code}).status_code == 404
        # nor can another org's facilitator read or attach to it
        cid = c.get("/api/cohorts", headers=ha).json()[0]["id"]
        assert c.get(f"/api/cohorts/{cid}", headers=_h(t2)).status_code == 404
        assert c.get(f"/api/cohorts/{cid}/gradebook", headers=_h(t2)).status_code == 404


def test_replay_scenes_and_rewind():
    with TestClient(app) as c:
        o, admin = _org(c); ha = _h(admin)
        scn, sid = _world(c, ha)
        assert c.post(f"/api/sessions/{sid}/rewind", headers=ha, json={"seq": 1}).status_code == 409  # not started
        p = _user(c, ha, o, "participant")
        code = c.post(f"/api/sessions/{sid}/join-code", headers=ha).json()["join_code"]
        assert c.post("/api/join", headers=_h(p), json={"code": code, "cell": "blue_cell", "display_name": "Ada"}).status_code == 200
        c.post(f"/api/sessions/{sid}/start", headers=ha)
        c.post(f"/api/sessions/{sid}/respond", headers=_h(p), json={"option": "a"})
        c.post(f"/api/sessions/{sid}/adjudicate", headers=ha, json={"techniques": ["T1003"], "target_asset": "SRV-01", "description": "dump"})
        c.post(f"/api/sessions/{sid}/note", headers=ha, json={"text": "proctor only"})
        assert c.post(f"/api/sessions/{sid}/advance", headers=ha, json={"when": "proctor_choice", "trigger": "contain"}).status_code == 200
        c.post(f"/api/sessions/{sid}/advance", headers=ha, json={"when": "proctor_choice", "trigger": "end"})
        c.post(f"/api/sessions/{sid}/complete", headers=ha)
        rep = c.get(f"/api/sessions/{sid}/replay", headers=ha).json()
        assert [s["code"] for s in rep["scenes"]] == ["INJ-01", "INJ-02", "INJ-04"] and rep["branch_points"] == 1
        s1 = rep["scenes"][0]
        assert s1["responses"][0]["display_name"] == "Ada" and s1["responses"][0]["score"] == 1.0
        assert s1["rulings"][0]["outcome"] == "detected" and s1["rulings"][0]["probability"] is not None
        assert s1["notes"] == ["proctor only"]
        assert s1["decision"]["goto"] == "INJ-02" and [b["label"] for b in s1["alternatives"]] == ["ignore"]
        assert s1["state_before"] == {"tension": 1} and rep["scenes"][1]["state_before"]["tension"] == 2
        assert "INJ-01" in s1["narrative_line"] and "other road" in s1["narrative_line"]
        assert rep["scenes"][2].get("ended") is True and rep["duration_sec"] is not None
        # a seated participant gets their cell's view: no proctor notes, no state, own answers only
        prep = c.get(f"/api/sessions/{sid}/replay", headers=_h(p)).json()
        assert [s["code"] for s in prep["scenes"]] == ["INJ-01", "INJ-02", "INJ-04"]
        assert prep["scenes"][0]["notes"] == [] and prep["scenes"][0]["state_before"] == {} and prep["session"]["state"] == {}
        assert prep["scenes"][0]["decision"]["goto"] == "INJ-02"
        # rewind at the second scene: a new running session, state as it was, original untouched
        seq2 = rep["scenes"][1]["seq"]
        assert c.post(f"/api/sessions/{sid}/rewind", headers=_h(p), json={"seq": seq2}).status_code == 403
        r = c.post(f"/api/sessions/{sid}/rewind", headers=ha, json={"seq": seq2})
        assert r.status_code == 201, r.text
        nid = r.json()["id"]
        st = c.get(f"/api/sessions/{nid}", headers=ha).json()
        assert st["session"]["status"] == "running" and st["current_inject"]["code"] == "INJ-02"
        assert st["state"]["tension"] == 2 and st["state"]["rewound_from"]["session_id"] == sid
        assert "rewind at INJ-02" in st["session"]["name"]
        assert c.get(f"/api/sessions/{nid}/verify", headers=ha).json()["chain_valid"] is True
        orig = c.get(f"/api/sessions/{sid}", headers=ha).json()
        assert orig["session"]["status"] == "complete" and orig["timeline"][-1]["kind"] == "note"
        assert c.get(f"/api/sessions/{sid}/verify", headers=ha).json()["chain_valid"] is True
        assert c.get(f"/api/sessions/{nid}/replay", headers=ha).json()["rewound_from"]["code"] == "INJ-02"
        assert c.post(f"/api/sessions/{sid}/rewind", headers=ha, json={"seq": 999}).status_code == 404


def test_education_and_replay_are_gated(community):
    with TestClient(app) as c:
        o, admin = _org(c); ha = _h(admin)
        assert c.post("/api/cohorts", headers=ha, json={"name": "x"}).status_code == 402
        assert c.get("/api/cohorts", headers=ha).status_code == 402
        assert c.post("/api/cohorts/enrol", json={"code": "ABCDEFG", "email": f"z{o}@uni.edu", "password": PW}).status_code == 402
        scn, sid = _world(c, ha)
        assert c.get(f"/api/sessions/{sid}/replay", headers=ha).status_code == 402
        assert c.post(f"/api/sessions/{sid}/rewind", headers=ha, json={"seq": 1}).status_code == 402
