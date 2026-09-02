"""P4 — the executive track: impact per branch accumulates on the path taken,
communications decisions capture the statement, comms channels render, and
the executive report and certificate carry the numbers."""
import uuid

from fastapi.testclient import TestClient
from sqlalchemy import select

from app import impact, models
from app.authoring import delivery as preview
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


def test_impact_engine_normalises_and_accumulates():
    state, step = impact.apply({}, {"impact": {"cost": "250000", "downtime_hours": 4.5, "label": "x" * 300, "bogus": 1}})
    assert step == {"cost": 250000, "downtime_hours": 4.5, "label": "x" * 200}
    state, step2 = impact.apply(state, {"impact": {"cost": 50000, "records": 10}})
    assert state["impact"] == {"cost": 300000, "downtime_hours": 4.5, "records": 10}
    same, none = impact.apply(state, {"goto": "X"})
    assert none is None and same == state
    assert impact.money(1_900_000) == "$1.9M" and impact.money(25_000) == "$25k" and impact.money(900) == "$900"


def test_path_taken_costs_and_reports():
    with TestClient(app) as c:
        o, admin = _org(c); ha = _h(admin)
        env = c.post("/api/environments", headers=ha, json={"name": "e", "sector": "Financial services", "assets": [{"code": "A", "name": "a"}]}).json()["id"]
        scn = c.post("/api/scenarios", headers=ha, json={
            "environment_id": env, "name": "s",
            "cells": [{"key": "blue_cell", "name": "Blue", "kind": "participant"},
                      {"key": "exec_cell", "name": "Exec", "kind": "participant"},
                      {"key": "white_cell", "name": "White", "kind": "control"}],
            "injects": [
                {"code": "INJ-01", "title": "start", "narrative": "n", "is_start": True, "visible_to": ["blue_cell"],
                 "branches": [{"label": "Contain", "when": "proctor_choice", "goto": "INJ-02",
                               "impact": {"cost": 20000, "downtime_hours": 2, "label": "Contained"}},
                              {"label": "Ignore", "when": "timeout", "after": "PT1M", "goto": "INJ-03",
                               "impact": {"cost": 900000, "downtime_hours": 48, "records": 5000}}]},
                {"code": "INJ-02", "title": "press", "narrative": "n", "channel": "media", "visible_to": ["exec_cell"],
                 "meta": {"decision": {"kind": "comms", "prompt": "Position?", "options": [
                     {"key": "a", "label": "Confirm and commit to an update", "score": 1.0},
                     {"key": "b", "label": "No comment", "score": 0.3}], "free_text": True}},
                 "branches": [{"label": "go", "when": "proctor_choice", "goto": "INJ-03", "impact": {"cost": 5000, "label": "Comms retainer"}}]},
                {"code": "INJ-03", "title": "end", "narrative": "n", "channel": "regulator", "visible_to": ["blue_cell", "exec_cell"]},
            ]}).json()["id"]
        sid = c.post("/api/sessions", headers=ha, json={"scenario_id": scn, "name": "run"}).json()["id"]
        code = c.post(f"/api/sessions/{sid}/join-code", headers=ha).json()["join_code"]
        ex = _h(_user(c, ha, o, "participant", "x"))
        c.post("/api/join", headers=ex, json={"code": code, "cell": "exec_cell", "display_name": "CEO"})
        c.post(f"/api/sessions/{sid}/start", headers=ha)
        # the contain branch
        st = c.post(f"/api/sessions/{sid}/advance", headers=ha, json={"when": "proctor_choice"}).json()
        assert st["state"]["impact"] == {"cost": 20000, "downtime_hours": 2}
        dec = [e for e in st["timeline"] if e["kind"] == "decision"][-1]
        assert dec["payload"]["impact"] == {"cost": 20000, "downtime_hours": 2, "label": "Contained"}
        # the executive cell sees a comms card, must write the statement
        v = c.get(f"/api/sessions/{sid}/cell/exec_cell", headers=ex).json()
        assert v["decision"]["kind"] == "comms" and v["current_inject"]["channel"] == "media"
        assert c.post(f"/api/sessions/{sid}/respond", headers=ex, json={"option": "a"}).status_code == 422
        r = c.post(f"/api/sessions/{sid}/respond", headers=ex, json={"option": "a", "text": "We are aware of a contained security incident. Services are restored. Next update at 16:00."})
        assert r.status_code == 201 and r.json()["payload"]["kind"] == "comms" and r.json()["payload"]["score"] == 1.0
        # second branch adds to the totals
        st = c.post(f"/api/sessions/{sid}/advance", headers=ha, json={"when": "proctor_choice"}).json()
        assert st["state"]["impact"] == {"cost": 25000, "downtime_hours": 2}
        # comms channels render with their own fields
        inj = next(i for i in c.get(f"/api/scenarios/{scn}", headers=ha).json()["injects"] if i["code"] == "INJ-03")
        d = c.get(f"/api/injects/{inj['id']}/delivery", headers=ha).json()
        assert d["channel"] == "regulator" and "Response due" in d["fields"]
        # executive report and certificate
        ex_rep = c.post(f"/api/sessions/{sid}/reports", headers=ha, json={"audience": "executive"}).json()["content"]
        assert "Impact of the path taken" in ex_rep and "$25k" in ex_rep and "Contained" in ex_rep and "not a forecast" in ex_rep
        assert "Communications decisions" in ex_rep and "Next update at 16:00" in ex_rep and "100%" in ex_rep
        c.post(f"/api/sessions/{sid}/complete", headers=ha)
        cert = c.post(f"/api/sessions/{sid}/certificate", headers=ha).json()
        assert cert["payload"]["impact"] == {"cost": 25000, "downtime_hours": 2}
        assert c.get(f"/api/certificates/{cert['serial']}/verify").json()["record"]["impact"]["cost"] == 25000


def test_seeded_and_generated_content_carry_the_executive_track():
    with TestClient(app) as c:
        o, admin = _org(c); ha = _h(admin)
        db = SessionLocal()
        try:
            frost = db.execute(select(models.Scenario).where(models.Scenario.name.like("Operation Frostbite%"))).scalars().first()
            assert any(cell["key"] == "exec_cell" for cell in frost.cells)
            ends = {i.code: i for i in frost.injects if i.code in ("INJ-06a", "INJ-06b")}
            assert ends["INJ-06a"].channel == "media" and ends["INJ-06b"].channel == "regulator"
            assert all("exec_cell" in i.visible_to and i.meta["decision"]["kind"] == "comms" for i in ends.values())
            branches = [b for i in frost.injects for b in i.branches if b.get("impact")]
            assert len(branches) == 4 and max(b["impact"]["cost"] for b in branches) == 1900000
        finally:
            db.close()
        env = c.post("/api/environments/from-template", headers=ha, json={"key": "hospital"}).json()["id"]
        scn = c.post("/api/scenarios/generate", headers=ha, json={"environment_id": env, "template_key": "ransomware_finance"}).json()
        bad = next(i for i in scn["injects"] if i["code"].endswith("b") and i["code"].startswith("INJ"))
        assert bad["channel"] == "media" and bad["meta"]["decision"]["kind"] == "comms"
        assert any(b.get("impact", {}).get("cost") == 1500000 for i in scn["injects"] for b in i["branches"])
        # a session that takes the timeout path reports the major impact
        sid = c.post("/api/sessions", headers=ha, json={"scenario_id": scn["id"], "name": "g"}).json()["id"]
        c.post(f"/api/sessions/{sid}/start", headers=ha)
        state = c.get(f"/api/sessions/{sid}", headers=ha).json()
        for _ in range(12):
            if state["terminal"]:
                break
            state = c.post(f"/api/sessions/{sid}/advance", headers=ha, json={"when": "proctor_choice"}).json()
        assert state["state"].get("impact", {}).get("cost") == 120000  # the proctor path is the contained one


def test_preview_renders_every_comms_channel():
    class I:
        code = "INJ-09"; title = "Story"; narrative = "n"; target_asset = ""; clock = "T+01:00"
        attack_techniques = []; expected_actions = []
        def __init__(self, ch): self.channel = ch
    for ch, key in (("media", "Deadline"), ("regulator", "Response due"), ("customer", "Tone"), ("social", "Reach"), ("board", "Wants")):
        assert key in preview.render(I(ch))["fields"], ch
