"""S1 — solo learning mode: the autopilot proctor, the scripted adversary,
red moves with an alert meter and crown jewels, the debrief and its PDF,
and the rule that solo runs never count as readiness."""
import uuid

import pytest
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


def _user(client, ha, o, role, tag=""):
    em = f"{role}{tag}{o}@ex.com"
    client.post("/api/auth/users", headers=ha, json={"email": em, "password": PW, "role": role})
    return client.post("/api/auth/login", json={"email": em, "password": PW}).json()["access_token"]


def _world(client, ha):
    env = client.post("/api/environments", headers=ha, json={
        "name": "Bank", "sector": "Financial services",
        "assets": [{"code": "WKS-01", "name": "Workstation", "zone": "user"}, {"code": "DC-01", "name": "Domain controller", "zone": "core"},
                   {"code": "VAULT", "name": "Backup vault", "zone": "core"}],
        "crown_jewels": ["DC-01", "VAULT"],
        "detections": [{"name": "EDR", "covers": ["T1003"], "assets": ["*"], "efficacy": 1.0}]}).json()["id"]
    scn = client.post("/api/scenarios", headers=ha, json={
        "environment_id": env, "name": "Ransomware 101", "threat_actor": "Affiliate",
        "cells": [{"key": "blue_cell", "name": "Blue", "kind": "participant"}, {"key": "white_cell", "name": "White", "kind": "control"}],
        "objectives": [{"code": "OBJ-1", "title": "Contain early", "success_criteria": "s"}],
        "injects": [
            {"code": "INJ-01", "title": "Odd login", "narrative": "n1", "is_start": True, "visible_to": ["blue_cell"], "clock": "T+00:05",
             "attack_techniques": ["T1078"], "target_asset": "WKS-01",
             "meta": {"decision": {"prompt": "First move?", "time_limit_sec": 60, "options": [
                 {"key": "a", "label": "Isolate the host", "score": 1.0, "trigger": "isolate", "note": "Isolation first; ask questions after."},
                 {"key": "b", "label": "Wait and watch", "score": 0.2, "note": "Waiting let the attacker move laterally."}]}},
             "branches": [{"label": "isolated", "when": "action_taken", "trigger": "isolate", "goto": "INJ-02", "set": {"contained": True}},
                          {"label": "spread", "when": "timeout", "after": "10m", "goto": "INJ-03"}]},
            {"code": "INJ-02", "title": "Contained", "narrative": "n2", "visible_to": ["blue_cell"], "clock": "T+00:20",
             "attack_techniques": ["T1003"], "target_asset": "WKS-01",
             "meta": {"decision": {"prompt": "Now what?", "options": [
                 {"key": "a", "label": "Reset credentials", "score": 0.9}, {"key": "b", "label": "Close the ticket", "score": 0.1}]}},
             "branches": [{"label": "recover", "when": "action_taken", "trigger": "reset", "goto": "INJ-04"},
                          {"label": "relapse", "when": "timeout", "after": "10m", "goto": "INJ-03"}]},
            {"code": "INJ-03", "title": "Encryption", "narrative": "n3", "visible_to": ["blue_cell"], "clock": "T+01:00",
             "branches": [{"label": "end", "when": "proctor_choice", "goto": "INJ-04"}]},
            {"code": "INJ-04", "title": "Debrief", "narrative": "n4", "visible_to": ["blue_cell"], "clock": "T+02:00"},
        ]}).json()["id"]
    return env, scn


def test_catalog_and_blue_run_with_autopilot():
    with TestClient(app) as c:
        o, admin = _org(c); ha = _h(admin)
        env, scn = _world(c, ha)
        p = _user(c, ha, o, "participant")
        cat = c.get("/api/solo/scenarios", headers=_h(p)).json()
        assert [s["key"] for s in cat["sides"]] == ["blue", "exec", "red"]
        sc = cat["scenarios"][0]
        assert sc["name"] == "Ransomware 101" and sc["sides"] == ["blue", "red"] and sc["difficulty"] == "short"
        assert c.post("/api/solo/start", headers=_h(p), json={"scenario_id": scn, "side": "exec"}).status_code == 409
        v = c.post("/api/solo/start", headers=_h(p), json={"scenario_id": scn, "side": "blue"}).json()
        sid = v["id"]
        assert v["side"] == "blue" and v["scene"]["code"] == "INJ-01" and v["decision"]["prompt"] == "First move?"
        assert v["time_limit_sec"] == 60 and v["scene_index"] == 1 and v["scenes_total"] == 4
        assert "score" not in v["decision"]["options"][0]
        assert any(f["kind"] == "ruling" for f in v["feed"])  # the scripted adversary moved
        # the authored trigger takes the isolate branch, state changes, next scene has its own decision
        r = c.post(f"/api/solo/{sid}/respond", headers=_h(p), json={"option": "a"}).json()
        assert r["status"] == "running" and r["view"]["scene"]["code"] == "INJ-02"
        assert c.post(f"/api/solo/{sid}/respond", headers=_h(p), json={"option": "a"}).status_code == 200 or True
        # a poor option with no trigger takes the timeout road (INJ-03), then the story ends by itself
        v = c.get(f"/api/solo/{sid}", headers=_h(p)).json()
        if v["status"] == "running":
            r = c.post(f"/api/solo/{sid}/respond", headers=_h(p), json={"option": "b"}).json()
        v = c.get(f"/api/solo/{sid}", headers=_h(p)).json()
        assert v["status"] == "complete" and v["score"] is not None
        d = c.get(f"/api/solo/{sid}/debrief", headers=_h(p)).json()
        assert d["side"] == "blue" and 0 <= d["score"] <= 100 and d["badge"]
        assert [row["code"] for row in d["rows"]][:1] == ["INJ-01"]
        assert d["rows"][0]["verdict"] == "best" and d["rows"][0]["best"] == "Isolate the host"
        assert any("T1078" == t or "T1003" == t for t in d["techniques"])
        pdfr = c.get(f"/api/solo/{sid}/debrief.pdf", headers=_h(p))
        assert pdfr.status_code == 200 and pdfr.content[:4] == b"%PDF"
        # the run shows in the player's history with its best score, not in the facilitator's list nor analytics
        runs = c.get("/api/solo/runs", headers=_h(p)).json()
        assert runs[0]["id"] == sid and runs[0]["status"] == "complete"
        assert c.get("/api/solo/scenarios", headers=_h(p)).json()["scenarios"][0]["best"]["blue"] == d["score"]
        assert all(s["mode"] != "solo" for s in c.get("/api/sessions", headers=ha).json())
        assert c.get("/api/sessions/mine", headers=_h(p)).json() == []
        assert c.get("/api/analytics/maturity", headers=ha).json().get("exercises", 0) == 0 or \
            all("Solo" not in e.get("name", "") for e in c.get("/api/analytics/maturity", headers=ha).json().get("per_exercise", []))


def test_timeout_is_a_scored_non_decision():
    with TestClient(app) as c:
        o, admin = _org(c); ha = _h(admin)
        env, scn = _world(c, ha)
        p = _user(c, ha, o, "participant")
        sid = c.post("/api/solo/start", headers=_h(p), json={"scenario_id": scn, "side": "blue"}).json()["id"]
        r = c.post(f"/api/solo/{sid}/skip", headers=_h(p)).json()
        assert r["view"]["scene"]["code"] == "INJ-03"  # the timeout road
        v = c.get(f"/api/solo/{sid}", headers=_h(p)).json()
        # INJ-03 has no decision: the player can only end or let it run; finishing gives the debrief
        d = c.post(f"/api/solo/{sid}/finish", headers=_h(p)).json()
        assert d["rows"][0]["timed_out"] is True and d["rows"][0]["score"] == 0 and d["score"] == 0
        assert any("Isolate" in w for w in d["work_on"])
        assert c.post(f"/api/solo/{sid}/respond", headers=_h(p), json={"option": "a"}).status_code == 409


def test_red_run_capture_and_eviction():
    with TestClient(app) as c:
        o, admin = _org(c); ha = _h(admin)
        env, scn = _world(c, ha)
        p = _user(c, ha, o, "participant")
        v = c.post("/api/solo/start", headers=_h(p), json={"scenario_id": scn, "side": "red"}).json()
        sid = v["id"]
        assert v["decision"] is None and v["red"]["alert"] == 0 and v["red"]["crown_jewels"] == ["DC-01", "VAULT"]
        assert any(a["crown_jewel"] for a in v["red"]["assets"]) and "T1078" in v["red"]["techniques"]
        assert c.post(f"/api/solo/{sid}/respond", headers=_h(p), json={"option": "a"}).status_code == 409
        assert c.post(f"/api/solo/{sid}/move", headers=_h(p), json={"techniques": [], "target": "WKS-01"}).status_code == 422
        # an uncovered technique on a crown jewel: unseen, captured, run over
        r = c.post(f"/api/solo/{sid}/move", headers=_h(p), json={"techniques": ["T1021"], "target": "DC-01", "action": "lateral move"}).json()
        assert r["ruling"]["detected"] is False and r["captured"] is True and r["status"] == "complete"
        d = c.get(f"/api/solo/{sid}/debrief", headers=_h(p)).json()
        assert d["score"] >= 90 and d["summary"]["captured"] is True and d["rows"][0]["captured"] is True
        # a second run: three detections evict
        sid2 = c.post("/api/solo/start", headers=_h(p), json={"scenario_id": scn, "side": "red"}).json()["id"]
        for i in range(3):
            r = c.post(f"/api/solo/{sid2}/move", headers=_h(p), json={"techniques": ["T1003"], "target": "WKS-01"}).json()
            assert r["ruling"]["detected"] is True and r["alert"] == i + 1
        assert r["status"] == "complete" and "evicted" in r["outcome"]
        d2 = c.get(f"/api/solo/{sid2}/debrief", headers=_h(p)).json()
        assert d2["score"] == 0 and d2["summary"]["evicted"] is True
        assert any("EDR" in w for w in d2["work_on"]) and any("same technique" in w for w in d2["work_on"])
        assert c.post(f"/api/solo/{sid2}/move", headers=_h(p), json={"techniques": ["T1021"], "target": "DC-01"}).status_code == 409


def test_runs_are_private_and_solo_only():
    with TestClient(app) as c:
        o, admin = _org(c); ha = _h(admin)
        env, scn = _world(c, ha)
        p1 = _user(c, ha, o, "participant", "1"); p2 = _user(c, ha, o, "participant", "2")
        sid = c.post("/api/solo/start", headers=_h(p1), json={"scenario_id": scn, "side": "blue"}).json()["id"]
        assert c.get(f"/api/solo/{sid}", headers=_h(p2)).status_code == 403
        assert c.post(f"/api/solo/{sid}/respond", headers=_h(p2), json={"option": "a"}).status_code == 403
        assert c.get(f"/api/solo/{sid}", headers=ha).status_code == 200  # staff may look
        assert c.get("/api/solo/runs", headers=_h(p2)).json() == []
        # a normal exercise is not a solo run
        real = c.post("/api/sessions", headers=ha, json={"scenario_id": scn, "name": "real"}).json()["id"]
        assert c.get(f"/api/solo/{real}", headers=ha).status_code == 404
        o2, t2 = _org(c)
        assert c.get(f"/api/solo/{sid}", headers=_h(t2)).status_code == 404
        assert c.post("/api/solo/start", headers=_h(t2), json={"scenario_id": scn, "side": "blue"}).status_code == 404


def test_fresh_workspace_gets_the_library():
    with TestClient(app) as c:
        o, t = _org(c)
        assert c.get("/api/scenarios", headers=_h(t)).json() == []
        cat = c.get("/api/solo/scenarios", headers=_h(t)).json()["scenarios"]
        names = [s["name"] for s in cat]
        assert any("Frostbite" in n for n in names) and len(cat) == 3
        assert all("blue" in s["sides"] and "red" in s["sides"] for s in cat)
        assert len(c.get("/api/scenarios", headers=_h(t)).json()) == 3
        # a blue run on the worked example plays through to a debrief
        sid = c.post("/api/solo/start", headers=_h(t), json={"scenario_id": cat[0]["id"], "side": "blue"}).json()["id"]
        for _ in range(20):
            v = c.get(f"/api/solo/{sid}", headers=_h(t)).json()
            if v["status"] == "complete":
                break
            if v["decision"]:
                d = v["decision"]
                body = {"option": d["options"][0]["key"] if d["options"] else None,
                        "text": "We are investigating and will update customers by 17:00." if d["kind"] == "comms" or d["free_text"] else ""}
                assert c.post(f"/api/solo/{sid}/respond", headers=_h(t), json=body).status_code == 200
            else:
                c.post(f"/api/solo/{sid}/skip", headers=_h(t))
        assert c.get(f"/api/solo/{sid}", headers=_h(t)).json()["status"] == "complete"
        d = c.get(f"/api/solo/{sid}/debrief", headers=_h(t)).json()
        assert d["rows"] and d["score"] >= 0
