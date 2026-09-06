"""H — red-side balance pass and option shuffle on worked examples.

The efficacy lever used to scale the wildcard SIEM too, which pushed it over
the detection threshold on hard and expert: every move detected in four of
the six arenas. A made-up technique id or asset code was a guaranteed win at
any difficulty. And a hand-authored scenario listed its best option first at
every difficulty where shuffle was off."""
import uuid

from fastapi.testclient import TestClient

from app import engagements
from app.authoring import environments as env_library
from app.engine import adjudication
from app.main import app

PW = "Str0ngPass!9"


def _h(t):
    return {"Authorization": f"Bearer {t}"}


def _org(client):
    o = uuid.uuid4().hex[:8]
    t = client.post("/api/auth/register", json={
        "org_name": f"O{o}", "email": f"a{o}@ex.com", "password": PW}).json()["access_token"]
    return o, t


def test_wildcard_controls_are_not_scaled_so_hard_and_expert_have_unseen_moves():
    bank = sorted({t for b in engagements.INJECT_BANK.values() for t in b["techniques"]})
    for key in env_library.ENVIRONMENT_TEMPLATES:
        env = env_library.build_from_template(key)
        for diff in ("hard", "expert"):
            sc = engagements.scaled_environment(env, diff)
            wild = [c for c in list(sc.controls) + list(sc.detections) if "*" in (c.get("covers") or [])]
            authored = [c for c in list(env.controls) + list(env.detections) if "*" in (c.get("covers") or [])]
            assert [c["efficacy"] for c in wild] == [c["efficacy"] for c in authored], (key, diff)
            named = [c for c in sc.controls if "*" not in (c.get("covers") or [])]
            assert all(c["efficacy"] > 0 for c in named)
            unseen = sum(1 for t in bank for a in env.assets if not adjudication.adjudicate(sc, [t], a["code"])["detected"])
            assert unseen > 0, (key, diff)  # there is a game to play
            # and the named controls still bite harder than on standard
            std = engagements.scaled_environment(env, "standard")
            covered = next(c for c in env.controls if "*" not in c["covers"])
            tech, asset = covered["covers"][0], (covered.get("assets") or ["*"])[0]
            target = asset if asset != "*" else env.assets[0]["code"]
            assert adjudication.adjudicate(sc, [tech], target)["probability"] >= adjudication.adjudicate(std, [tech], target)["probability"]


def test_made_up_techniques_and_assets_are_refused():
    with TestClient(app) as c:
        o, t = _org(c)
        v = c.post("/api/solo/start", headers=_h(t), json={"side": "red", "type": "ransomware", "difficulty": "expert"}).json()
        sid = v["id"]; outer = next(a["code"] for a in v["red"]["assets"] if not a["crown_jewel"])
        r = c.post(f"/api/solo/{sid}/move", headers=_h(t), json={"techniques": ["T1999"], "target": outer})
        assert r.status_code == 422 and "T1999" in r.json()["detail"]
        r = c.post(f"/api/solo/{sid}/move", headers=_h(t), json={"techniques": ["not-a-technique"], "target": outer})
        assert r.status_code == 422
        r = c.post(f"/api/solo/{sid}/move", headers=_h(t), json={"techniques": ["T1200"], "target": "NOPE-01"})
        assert r.status_code == 422 and "not an asset" in r.json()["detail"]
        # nothing was counted against the player
        v = c.get(f"/api/solo/{sid}", headers=_h(t)).json()
        assert v["red"]["moves"] == 0 and v["red"]["alert"] == 0 and v["status"] == "running"
        # a real technique on a real asset plays; sub-techniques of a known parent count as known
        r = c.post(f"/api/solo/{sid}/move", headers=_h(t), json={"techniques": ["t1200", "T1078.002"], "target": outer})
        assert r.status_code == 200 and r.json()["moves"] == 1


def test_a_worked_example_shuffles_at_every_difficulty_but_a_generated_easy_run_does_not():
    with TestClient(app) as c:
        o, admin = _org(c); ha = _h(admin)
        env = c.post("/api/environments", headers=ha, json={"name": "e", "assets": [{"code": "A", "name": "a"}]}).json()["id"]
        options = [{"key": k, "label": f"Option {k}", "score": 1.0 if k == "a" else 0.2} for k in "abcdef"]
        scn = c.post("/api/scenarios", headers=ha, json={
            "environment_id": env, "name": "Worked", "cells": [{"key": "blue_cell", "name": "Blue", "kind": "participant"}],
            "injects": [{"code": "INJ-01", "title": "t", "narrative": "n", "is_start": True, "visible_to": ["blue_cell"],
                         "meta": {"decision": {"prompt": "Pick", "options": options}}, "branches": [{"when": "proctor_choice", "goto": "INJ-02"}]},
                        {"code": "INJ-02", "title": "end", "narrative": "n"}]}).json()["id"]
        orders = []
        for diff in engagements.DIFFICULTIES:
            v = c.post("/api/solo/start", headers=ha, json={"scenario_id": scn, "side": "blue", "difficulty": diff}).json()
            assert v["levers"]["shuffle"] is True, diff
            keys = [o_["key"] for o_ in v["decision"]["options"]]
            assert sorted(keys) == list("abcdef")
            # deterministic within a run
            assert [o_["key"] for o_ in c.get(f"/api/solo/{v['id']}", headers=ha).json()["decision"]["options"]] == keys
            orders.append(keys)
        assert any(k != list("abcdef") for k in orders)
        g = c.post("/api/solo/start", headers=ha, json={"side": "blue", "type": "ransomware", "difficulty": "easy"}).json()
        assert g["levers"]["shuffle"] is False
        g2 = c.post("/api/solo/start", headers=ha, json={"side": "blue", "type": "ransomware", "difficulty": "standard"}).json()
        assert g2["levers"]["shuffle"] is True
