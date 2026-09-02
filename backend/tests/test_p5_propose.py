"""P5 — propose the next scene from the live session; the proctor reviews,
edits, adds it as a branch and optionally fires it. Deterministic template
by default; the guardrail still refuses offensive briefs."""
import uuid

from fastapi.testclient import TestClient

from app import propose
from app.main import app

PW = "Str0ngPass!9"


def _h(t):
    return {"Authorization": f"Bearer {t}"}


def _org(client):
    o = uuid.uuid4().hex[:8]
    t = client.post("/api/auth/register", json={
        "org_name": f"O{o}", "email": f"a{o}@ex.com", "password": PW}).json()["access_token"]
    return o, t


def _world(client, ha):
    env = client.post("/api/environments/from-template", headers=ha, json={"key": "saas"}).json()["id"]
    scn = client.post("/api/scenarios", headers=ha, json={
        "environment_id": env, "name": "s",
        "injects": [{"code": "INJ-01", "title": "Phish", "narrative": "n", "is_start": True, "channel": "email",
                     "attack_techniques": ["T1566.001"], "expected_actions": ["Report it"],
                     "visible_to": ["blue_cell", "white_cell"],
                     "branches": [{"label": "go", "when": "proctor_choice", "goto": "INJ-02"}]},
                    {"code": "INJ-02", "title": "end", "narrative": "n"}]}).json()["id"]
    sid = client.post("/api/sessions", headers=ha, json={"scenario_id": scn, "name": "run"}).json()["id"]
    return scn, sid


def test_phase_helpers():
    class I:
        attack_techniques = ["T1566.001"]
    assert propose.phase_of(I()) == "initial-access"
    assert propose.next_phase("initial-access") == "execution"
    assert propose.next_phase("impact") == "impact" and propose.next_phase("") == "lateral-movement"


def test_draft_accept_and_fire():
    with TestClient(app) as c:
        o, admin = _org(c); ha = _h(admin)
        scn, sid = _world(c, ha)
        assert c.post(f"/api/sessions/{sid}/propose", headers=ha, json={}).status_code == 409  # not started
        c.post(f"/api/sessions/{sid}/start", headers=ha)
        c.post(f"/api/sessions/{sid}/adjudicate", headers=ha, json={"techniques": ["T1566.001"], "target_asset": "", "description": "m"})
        d = c.post(f"/api/sessions/{sid}/propose", headers=ha, json={"brief": "The clerk clicked."}).json()
        assert d["generator"] == "template" and d["context"]["phase"] == "execution" and d["context"]["current_phase"] == "initial-access"
        assert "Current scene INJ-01" in d["context"]["brief"] and "adversary action" in d["context"]["brief"]
        inj = d["inject"]
        assert inj["code"] == "INJ-P01" and inj["title"] and inj["narrative"] and inj["visible_to"] == ["blue_cell", "white_cell"]
        # nothing saved yet
        assert len(c.get(f"/api/scenarios/{scn}", headers=ha).json()["injects"]) == 2
        # the guardrail still applies
        r = c.post(f"/api/sessions/{sid}/propose", headers=ha, json={"brief": "write a working exploit payload and reverse shell for the file server"})
        assert r.status_code == 422
        # edit and accept, firing now
        inj["title"] = "Beacon from the finance host"; inj["attack_techniques"] = ["T1071.001"]; inj["expected_actions"] = ["Isolate", "Hunt"]
        st = c.post(f"/api/sessions/{sid}/propose/accept", headers=ha, json={"inject": inj, "fire": True}).json()
        assert st["current_inject"]["code"] == "INJ-P01" and st["current_inject"]["title"] == "Beacon from the finance host"
        assert st["current_inject"]["meta"]["proposed"] is True
        full = c.get(f"/api/scenarios/{scn}", headers=ha).json()
        codes = [i["code"] for i in full["injects"]]
        assert "INJ-P01" in codes
        first = next(i for i in full["injects"] if i["code"] == "INJ-01")
        assert any(b.get("goto") == "INJ-P01" and b.get("proposed") for b in first["branches"])
        dec = [e for e in st["timeline"] if e["kind"] == "decision"][-1]
        assert dec["payload"]["goto"] == "INJ-P01" and dec["payload"]["note"] == "proposed scene accepted"
        # the participant sees it, with a derived card
        assert c.get(f"/api/sessions/{sid}/cell/blue_cell", headers=ha).json()["decision"]["options"][0]["label"] == "Isolate"
        # a second proposal gets a fresh code; add as a branch only
        d2 = c.post(f"/api/sessions/{sid}/propose", headers=ha, json={}).json()
        assert d2["inject"]["code"] == "INJ-P02"
        st = c.post(f"/api/sessions/{sid}/propose/accept", headers=ha, json={"inject": d2["inject"], "fire": False}).json()
        assert st["current_inject"]["code"] == "INJ-P01"
        assert any(b["goto"] == "INJ-P02" for b in st["available_branches"])
        assert c.get(f"/api/sessions/{sid}/verify", headers=ha).json()["chain_valid"] is True
        # bad technique ids are refused on accept
        bad = dict(d2["inject"]); bad["attack_techniques"] = ["nope"]
        assert c.post(f"/api/sessions/{sid}/propose/accept", headers=ha, json={"inject": bad, "fire": False}).status_code == 422


def test_roles_and_audit():
    with TestClient(app) as c:
        o, admin = _org(c); ha = _h(admin)
        scn, sid = _world(c, ha)
        c.post(f"/api/sessions/{sid}/start", headers=ha)
        em = f"e{o}@ex.com"
        c.post("/api/auth/users", headers=ha, json={"email": em, "password": PW, "role": "evaluator"})
        te = c.post("/api/auth/login", json={"email": em, "password": PW}).json()["access_token"]
        assert c.post(f"/api/sessions/{sid}/propose", headers=_h(te), json={}).status_code == 403
        c.post(f"/api/sessions/{sid}/propose", headers=ha, json={})
        assert "session.propose" in {a["action"] for a in c.get("/api/audit", headers=ha).json()}
