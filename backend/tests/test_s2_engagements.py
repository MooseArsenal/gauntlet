"""S2 — generated engagements with a type and a difficulty: the levers on
red (foothold, deception, thresholds, efficacy) and blue (clock, shuffle,
distractors, hints, impact), the score weight, and the arenas hidden from
the facilitator's pickers."""
import uuid

from fastapi.testclient import TestClient

from app import engagements
from app.main import app

PW = "Str0ngPass!9"


def _h(t):
    return {"Authorization": f"Bearer {t}"}


def _org(client):
    o = uuid.uuid4().hex[:8]
    t = client.post("/api/auth/register", json={
        "org_name": f"O{o}", "email": f"a{o}@ex.com", "password": PW}).json()["access_token"]
    return o, t


def test_catalogue_offers_types_and_difficulties():
    with TestClient(app) as c:
        o, t = _org(c)
        cat = c.get("/api/solo/scenarios", headers=_h(t)).json()
        assert [d["key"] for d in cat["difficulties"]] == ["easy", "standard", "hard", "expert"]
        assert {x["key"] for x in cat["types"]["red"]} == {"smash_grab", "ransomware", "espionage", "insider"}
        assert {x["key"] for x in cat["types"]["blue"]} >= {"phishing", "ransomware", "insider", "espionage", "ics"}
        assert cat["types"]["exec"] == cat["types"]["blue"]
        assert c.post("/api/solo/start", headers=_h(t), json={"side": "red"}).status_code == 422
        assert c.post("/api/solo/start", headers=_h(t), json={"side": "red", "type": "nope"}).status_code == 422
        assert c.post("/api/solo/start", headers=_h(t), json={"side": "red", "type": "espionage", "difficulty": "brutal"}).status_code == 422


def test_every_type_builds_on_every_difficulty():
    with TestClient(app) as c:
        o, t = _org(c)
        for side, kinds in engagements.TYPES.items():
            for etype in kinds:
                for diff in engagements.DIFFICULTIES:
                    r = c.post("/api/solo/start", headers=_h(t), json={"side": side, "type": etype, "difficulty": diff})
                    assert r.status_code == 201, (side, etype, diff, r.text)
                    v = r.json()
                    assert v["difficulty"] == diff and v["type"] == etype and v["scene"]["code"] == "INJ-01"
                    if side == "red":
                        assert v["red"]["max_alert"] == engagements.LEVERS[diff]["alert"]
                        assert v["red"]["max_moves"] == engagements.LEVERS[diff]["moves"]
                        assert (len(v["red"]["techniques"]) > 0) == engagements.LEVERS[diff]["hints"]
                        assert all((a["zone"] != "") == engagements.LEVERS[diff]["zones"] for a in v["red"]["assets"] if True) or not engagements.LEVERS[diff]["zones"]
                    else:
                        assert v["time_limit_sec"] == engagements.LEVERS[diff]["clock"]
                        assert (len(v["scene"]["expected_actions"]) > 0) == engagements.LEVERS[diff]["hints"]
        # generated scenarios and arenas never reach the facilitator's pickers
        assert all(s["exercise_type"] != "solo" for s in c.get("/api/scenarios", headers=_h(t)).json())
        assert all(not e["name"].startswith("Solo arena") for e in c.get("/api/environments", headers=_h(t)).json())
        assert all(s["mode"] != "solo" for s in c.get("/api/sessions", headers=_h(t)).json())


def test_red_levers_foothold_deception_and_thresholds():
    with TestClient(app) as c:
        o, t = _org(c)
        # standard: a crown jewel needs a foothold first
        v = c.post("/api/solo/start", headers=_h(t), json={"side": "red", "type": "insider", "difficulty": "standard"}).json()
        sid = v["id"]; jewel = v["red"]["crown_jewels"][0]
        outer = next(a["code"] for a in v["red"]["assets"] if not a["crown_jewel"])
        r = c.post(f"/api/solo/{sid}/move", headers=_h(t), json={"techniques": ["T1999"], "target": jewel}).json()
        assert r["ruling"]["detected"] is False and r["captured"] is False and "foothold" in r["ruling"]["rationale"]
        r = c.post(f"/api/solo/{sid}/move", headers=_h(t), json={"techniques": ["T1999"], "target": outer}).json()
        assert r["foothold"] is True
        r = c.post(f"/api/solo/{sid}/move", headers=_h(t), json={"techniques": ["T1999"], "target": jewel}).json()
        assert r["captured"] is True and r["status"] == "complete"
        d = c.get(f"/api/solo/{sid}/debrief", headers=_h(t)).json()
        assert d["difficulty"] == "standard" and d["weight"] == 1.0 and d["score"] == d["raw_score"]
        # easy: no foothold needed, and the score is weighted down
        v = c.post("/api/solo/start", headers=_h(t), json={"side": "red", "type": "insider", "difficulty": "easy"}).json()
        r = c.post(f"/api/solo/{v['id']}/move", headers=_h(t), json={"techniques": ["T1999"], "target": v["red"]["crown_jewels"][0]}).json()
        assert r["captured"] is True
        d = c.get(f"/api/solo/{v['id']}/debrief", headers=_h(t)).json()
        assert d["score"] == min(100, round(d["raw_score"] * 0.85))
        # expert: deception live, two alert points per canary, threshold two
        v = c.post("/api/solo/start", headers=_h(t), json={"side": "red", "type": "insider", "difficulty": "expert"}).json()
        assert v["red"]["deception_live"] is True and v["red"]["max_alert"] == 2 and v["red"]["techniques"] == []
        assert all(a["zone"] == "" for a in v["red"]["assets"])


def test_deception_costs_two_alert_points_when_live(monkeypatch):
    from app import solo as solo_mod
    from app.engine import adjudication
    real = adjudication.adjudicate
    def tripped(env, techniques, target):
        r = real(env, techniques, target)
        return {**r, "detected": True, "deception_tripped": True, "rationale": "Deception asset 'canary' was tripped"}
    monkeypatch.setattr(adjudication, "adjudicate", tripped)
    with TestClient(app) as c:
        o, t = _org(c)
        v = c.post("/api/solo/start", headers=_h(t), json={"side": "red", "type": "espionage", "difficulty": "hard"}).json()
        outer = next(a["code"] for a in v["red"]["assets"] if not a["crown_jewel"])
        r = c.post(f"/api/solo/{v['id']}/move", headers=_h(t), json={"techniques": ["T1078"], "target": outer}).json()
        assert r["alert"] == 2 and r["status"] == "complete" and "canary" in r["outcome"]


def test_blue_levers_distractors_shuffle_and_impact():
    with TestClient(app) as c:
        o, t = _org(c)
        v = c.post("/api/solo/start", headers=_h(t), json={"side": "blue", "type": "ransomware", "difficulty": "expert"}).json()
        sid = v["id"]
        labels = [o_["label"] for o_ in v["decision"]["options"]]
        assert len([l for l in labels if any(l == d[0] for d in engagements.DISTRACTORS)]) == 2
        assert v["time_limit_sec"] == 45 and v["scene"]["expected_actions"] == []
        # shuffle is deterministic for the run and the scene
        again = c.get(f"/api/solo/{sid}", headers=_h(t)).json()
        assert [o_["key"] for o_ in again["decision"]["options"]] == [o_["key"] for o_ in v["decision"]["options"]]
        # a distractor scores zero and the coaching note explains why
        key = next(o_["key"] for o_ in v["decision"]["options"] if any(o_["label"] == d[0] for d in engagements.DISTRACTORS))
        r = c.post(f"/api/solo/{sid}/respond", headers=_h(t), json={"option": key}).json()
        assert r["recorded"]["score"] == 0.0
        d = c.post(f"/api/solo/{sid}/finish", headers=_h(t)).json()
        assert d["rows"][0]["score"] == 0.0 and d["rows"][0]["chosen_note"] and d["weight"] == 1.3
        # easy: no distractors, long clock, hints shown, half impact
        v = c.post("/api/solo/start", headers=_h(t), json={"side": "blue", "type": "ransomware", "difficulty": "easy"}).json()
        assert not any(o_["label"] == dd[0] for o_ in v["decision"]["options"] for dd in engagements.DISTRACTORS)
        assert v["time_limit_sec"] == 240 and v["scene"]["expected_actions"]
        # worked examples are still offered, without generated runs
        cat = c.get("/api/solo/scenarios", headers=_h(t)).json()
        assert all("·" not in s["name"] or "Solo" not in s["name"] for s in cat["scenarios"]) and len(cat["scenarios"]) == 3
