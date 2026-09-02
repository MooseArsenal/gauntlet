"""P1 — participant decisions: cards on injects, answers on the signed chain
with latency and score, the proctor's tally, per-participant scoring, and the
roll-up into analytics, reports and the certificate."""
import uuid

from fastapi.testclient import TestClient

from app import decisions
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
        "environment_id": env, "name": "s",
        "cells": [{"key": "blue_cell", "name": "Blue", "kind": "participant"},
                  {"key": "red_cell", "name": "Red", "kind": "participant"},
                  {"key": "white_cell", "name": "White", "kind": "control"}],
        "injects": [
            {"code": "INJ-01", "title": "alert", "narrative": "n", "is_start": True, "visible_to": ["blue_cell"],
             "meta": {"decision": {"prompt": "First move?", "options": [
                 {"key": "a", "label": "Isolate", "score": 1.0, "note": "secret proctor note"},
                 {"key": "b", "label": "Wait", "score": 0.2}], "time_limit_sec": 120}},
             "branches": [{"label": "go", "when": "proctor_choice", "goto": "INJ-02"}]},
            {"code": "INJ-02", "title": "derived", "narrative": "n", "visible_to": ["blue_cell"],
             "expected_actions": ["Open an incident", "Notify the CISO"],
             "branches": [{"label": "go", "when": "proctor_choice", "goto": "INJ-03"}]},
            {"code": "INJ-03", "title": "end", "narrative": "n", "visible_to": ["blue_cell"]},
        ]}).json()["id"]
    sid = client.post("/api/sessions", headers=ha, json={"scenario_id": scn, "name": "run"}).json()["id"]
    code = client.post(f"/api/sessions/{sid}/join-code", headers=ha).json()["join_code"]
    return sid, code


def test_spec_is_declared_or_derived_and_public_view_hides_scores():
    class I:  # noqa: D401 - a stand-in inject
        meta = {}; expected_actions = ["Open an incident", "Call legal"]
    d = decisions.spec_for(I())
    assert d["derived"] is True and [o["label"] for o in d["options"]][:2] == ["Open an incident", "Call legal"]
    assert d["options"][-1]["label"] == "Wait and monitor" and d["options"][-1]["score"] == 0.2
    pub = decisions.public_spec(d)
    assert "score" not in pub["options"][0] and "note" not in pub["options"][0] and "derived" not in pub
    class J:
        meta = {"decision": {"prompt": "?", "free_text": True}}; expected_actions = []
    assert decisions.spec_for(J())["free_text"] is True and decisions.spec_for(J())["options"] == []
    class K:
        meta = {}; expected_actions = []
    assert decisions.spec_for(K()) is None


def test_participants_answer_once_and_the_proctor_sees_the_tally():
    with TestClient(app) as c:
        o, admin = _org(c); ha = _h(admin)
        sid, code = _world(c, ha)
        p1 = _h(_user(c, ha, o, "participant", "1")); p2 = _h(_user(c, ha, o, "participant", "2"))
        red = _h(_user(c, ha, o, "participant", "3"))
        for hp, cell, name in ((p1, "blue_cell", "Ana"), (p2, "blue_cell", "Ben"), (red, "red_cell", "Cy")):
            assert c.post("/api/join", headers=hp, json={"code": code, "cell": cell, "display_name": name}).status_code == 200
        # nothing before start
        assert c.post(f"/api/sessions/{sid}/respond", headers=p1, json={"option": "a"}).status_code == 409
        c.post(f"/api/sessions/{sid}/start", headers=ha)
        # the participant view carries the card without scores or notes
        v = c.get(f"/api/sessions/{sid}/cell/blue_cell", headers=p1).json()
        assert v["decision"]["prompt"] == "First move?" and v["decision"]["time_limit_sec"] == 120
        assert "score" not in v["decision"]["options"][0] and "secret" not in c.get(f"/api/sessions/{sid}/cell/blue_cell", headers=p1).text
        assert v["my_response"] is None
        # answer
        r = c.post(f"/api/sessions/{sid}/respond", headers=p1, json={"option": "a"})
        assert r.status_code == 201, r.text
        ev = r.json()
        assert ev["kind"] == "response" and ev["payload"]["score"] == 1.0 and ev["payload"]["latency_sec"] >= 0
        assert ev["payload"]["display_name"] == "Ana" and ev["payload"]["cell"] == "blue_cell"
        assert c.post(f"/api/sessions/{sid}/respond", headers=p1, json={"option": "b"}).status_code == 409  # once
        assert c.post(f"/api/sessions/{sid}/respond", headers=p2, json={"option": "z"}).status_code == 422
        assert c.post(f"/api/sessions/{sid}/respond", headers=p2, json={"text": "free text not allowed here"}).status_code == 422
        assert c.post(f"/api/sessions/{sid}/respond", headers=p2, json={"option": "b"}).status_code == 201
        # the red cell was not addressed
        assert c.post(f"/api/sessions/{sid}/respond", headers=red, json={"option": "a"}).status_code == 403
        # my_response and cell-scoped visibility
        v = c.get(f"/api/sessions/{sid}/cell/blue_cell", headers=p1).json()
        assert v["my_response"]["option"] == "a"
        assert sum(1 for e in v["timeline"] if e["kind"] == "response") == 2
        assert not any(e["kind"] == "response" for e in c.get(f"/api/sessions/{sid}/cell/red_cell", headers=red).json()["timeline"])
        # participants cannot read the tally; the proctor can
        assert c.get(f"/api/sessions/{sid}/responses", headers=p1).status_code == 403
        t = c.get(f"/api/sessions/{sid}/responses", headers=ha).json()
        assert t["inject_code"] == "INJ-01" and t["responses"] == 2 and t["expected"] == 2
        assert {x["key"]: x["count"] for x in t["options"]} == {"a": 1, "b": 1} and t["mean_score"] == 0.6
        assert t["median_latency_sec"] is not None and t["spec"]["options"][0]["note"] == "secret proctor note"
        # staff may answer too, as the white cell
        assert c.post(f"/api/sessions/{sid}/respond", headers=ha, json={"option": "a"}).status_code == 201
        # derived card on the next inject
        c.post(f"/api/sessions/{sid}/advance", headers=ha, json={"when": "proctor_choice"})
        v = c.get(f"/api/sessions/{sid}/cell/blue_cell", headers=p1).json()
        assert v["current_inject"]["code"] == "INJ-02" and v["decision"]["options"][0]["label"] == "Open an incident"
        assert v["my_response"] is None
        assert c.post(f"/api/sessions/{sid}/respond", headers=p1, json={"option": "a"}).status_code == 201
        # a named, already-fired inject can still be answered by someone who missed it
        assert c.post(f"/api/sessions/{sid}/respond", headers=p2, json={"inject_code": "INJ-02", "option": "c"}).status_code == 201
        assert c.post(f"/api/sessions/{sid}/respond", headers=p2, json={"inject_code": "INJ-03", "option": "a"}).status_code == 409
        # chain still verifies; scores roll up
        assert c.get(f"/api/sessions/{sid}/verify", headers=ha).json()["chain_valid"] is True
        sc = c.get(f"/api/sessions/{sid}/participants/scores", headers=ha).json()
        assert sc["summary"]["responses"] == 5 and sc["summary"]["responders"] == 3 and sc["summary"]["injects_answered"] == 2
        ana = next(r for r in sc["participants"] if r["display_name"] == "Ana")
        assert ana["responses"] == 2 and ana["mean_score"] == 1.0 and sc["participants"][0]["mean_score"] == 1.0
        # reports and certificate
        tech = c.post(f"/api/sessions/{sid}/reports", headers=ha, json={"audience": "technical"}).json()["content"]
        assert "Participant decisions" in tech and "Decision by Ana" in tech
        ex = c.post(f"/api/sessions/{sid}/reports", headers=ha, json={"audience": "executive"}).json()["content"]
        assert "How the room decided" in ex
        c.post(f"/api/sessions/{sid}/complete", headers=ha)
        cert = c.post(f"/api/sessions/{sid}/certificate", headers=ha).json()
        assert cert["payload"]["participant_decisions"]["responders"] == 3
        assert c.get(f"/api/certificates/{cert['serial']}/verify").json()["record"]["participant_decisions"]["responses"] == 5
        m = c.get("/api/analytics/maturity", headers=ha).json()
        assert m["summary"]["decision_score"] is not None


def test_free_text_cards_and_seeded_content():
    with TestClient(app) as c:
        o, admin = _org(c); ha = _h(admin)
        scn = c.post("/api/scenarios/import-ctep", headers=ha, json={"pack_key": "ransomware"}).json()
        first = scn["injects"][0]
        assert first["meta"]["decision"]["free_text"] is True and first["meta"]["decision"]["prompt"]
        sid = c.post("/api/sessions", headers=ha, json={"scenario_id": scn["id"], "name": "r"}).json()["id"]
        c.post(f"/api/sessions/{sid}/start", headers=ha)
        r = c.post(f"/api/sessions/{sid}/respond", headers=ha, json={"text": "Declare an incident and isolate the file server."})
        assert r.status_code == 201 and r.json()["payload"]["score"] is None
        assert c.get(f"/api/sessions/{sid}/responses", headers=ha).json()["free_text"][0]["text"].startswith("Declare")
        # the worked example carries scored cards
        from sqlalchemy import select

        from app import models
        from app.database import SessionLocal
        db = SessionLocal()
        try:
            frost = db.execute(select(models.Scenario).where(models.Scenario.name.like("Operation Frostbite%"))).scalars().first()
            cards = [i for i in frost.injects if (i.meta or {}).get("decision")]
            assert len(cards) == 5 and all(len(i.meta["decision"]["options"]) == 4 for i in cards)
            assert sum(1 for i in cards if i.meta["decision"].get("kind") == "comms") == 2
        finally:
            db.close()
