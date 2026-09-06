"""E — the first content pack: four authored scenarios under content/packs/2026q4
that validate, carry decisions and coaching notes on every active scene, name
real assets of their library environment, sign and install as a pack, and play
to an ending on the blue and executive sides."""
import glob
import os
import re
import uuid

import pytest
from fastapi.testclient import TestClient

from app import entitlements, packs, scenario_io
from app.authoring import environments as env_library
from app.main import app

PW = "Str0ngPass!9"
PACK_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "content", "packs", "2026q4")
EXPECTED = {"halvorsen-lathe.yaml": "manufacturer", "clearwater-stillwater.yaml": "water_utility",
            "marrow-ballot-box.yaml": "county", "northgate-cold-archive.yaml": "university"}


def _h(t):
    return {"Authorization": f"Bearer {t}"}


def _org(client):
    o = uuid.uuid4().hex[:8]
    t = client.post("/api/auth/register", json={
        "org_name": f"O{o}", "email": f"a{o}@ex.com", "password": PW}).json()["access_token"]
    return o, t


def _docs():
    out = {}
    for path in sorted(glob.glob(os.path.join(PACK_DIR, "*.yaml"))):
        with open(path, encoding="utf-8") as f:
            out[os.path.basename(path)] = scenario_io.load_yaml(f.read())
    return out


@pytest.fixture
def pack_key(monkeypatch):
    priv, pub = entitlements.keygen()
    monkeypatch.setenv("GAUNTLET_PACK_PUBKEY", pub)
    return priv


def test_every_file_is_a_playable_graph_with_coaching_on_every_option():
    docs = _docs()
    assert set(docs) == set(EXPECTED)
    for name, d in docs.items():
        env = env_library.ENVIRONMENT_TEMPLATES[EXPECTED[name]]
        assets = {a["code"] for a in env["assets"]}
        v = scenario_io.validate(d)
        assert v == {"errors": [], "warnings": []}, (name, v)
        keys = {c["key"] for c in d["cells"]}
        assert {"white_cell", "blue_cell", "exec_cell"} <= keys, name
        assert len(d["objectives"]) == 4 and all(o["meta"].get("compliance") for o in d["objectives"]), name
        endings = [i for i in d["injects"] if not i.get("branches")]
        assert len(endings) >= 3, name
        comms = 0
        for inj in d["injects"]:
            if inj.get("target_asset"):
                assert inj["target_asset"] in assets, (name, inj["code"], inj["target_asset"])
            assert all(re.match(r"^T\d{4}(\.\d{3})?$", t) for t in inj.get("attack", [])), (name, inj["code"])
            if not inj.get("branches"):
                assert "decision" not in inj.get("meta", {}), (name, inj["code"])  # endings are read, not decided
                continue
            decl = inj["meta"]["decision"]
            assert len(decl["options"]) >= 3 and decl.get("time_limit_sec"), (name, inj["code"])
            triggers = {b.get("trigger") for b in inj["branches"] if b.get("when") == "action_taken"}
            scores = []
            for o in decl["options"]:
                assert o["note"].strip() and o["label"].strip(), (name, inj["code"], o["key"])
                scores.append(o["score"])
                if o.get("trigger"):
                    assert o["trigger"] in triggers, (name, inj["code"], o["trigger"])
            assert max(scores) == 1.0 and min(scores) < 0.5, (name, inj["code"])
            best = max(decl["options"], key=lambda o: o["score"])
            assert best.get("trigger") in triggers, (name, inj["code"])  # the best answer always has a road of its own
            assert any(b.get("when") == "timeout" for b in inj["branches"]), (name, inj["code"])
            if decl.get("kind") == "comms":
                comms += 1
                assert decl.get("free_text") and "exec_cell" in inj["visible_to"], (name, inj["code"])
        assert comms >= 1, name
        # the endings carry impact on the way in, so the debrief can price the path
        priced = {b["goto"] for i in d["injects"] for b in i.get("branches", []) if b.get("impact")}
        assert {e["code"] for e in endings} <= priced, (name, {e["code"] for e in endings} - priced)


def _best_labels(d):
    """prompt -> the label the author scored 1.0 (the player view hides scores and shuffles)."""
    out = {}
    for inj in d["injects"]:
        decl = (inj.get("meta") or {}).get("decision")
        if decl:
            out[decl["prompt"]] = max(decl["options"], key=lambda o: o["score"])["label"]
    return out


def _play(c, t, sid, best_labels):
    """Answer every decision addressed to the player with its best option until the run ends."""
    other = 0
    for _ in range(30):
        v = c.get(f"/api/solo/{sid}", headers=_h(t)).json()
        if v["status"] != "running":
            return v, other
        if v["decision"]:
            # an ending carries no authored card; the engine derives one from the expected actions
            want = best_labels.get(v["decision"]["prompt"]) or v["scene"]["expected_actions"][0]
            key = next(o["key"] for o in v["decision"]["options"] if o["label"] == want)
            r = c.post(f"/api/solo/{sid}/respond", headers=_h(t), json={"option": key, "text": "We act." if v["decision"]["kind"] == "comms" else ""})
            assert r.status_code == 200, r.text
        elif v["terminal"]:
            c.post(f"/api/solo/{sid}/finish", headers=_h(t))
        else:
            if v["addressed"] is False:
                other += 1
                assert v["time_limit_sec"] is None
                assert c.post(f"/api/solo/{sid}/respond", headers=_h(t), json={"option": "a"}).status_code == 409
            assert c.post(f"/api/solo/{sid}/skip", headers=_h(t)).status_code == 200
    raise AssertionError("the run never ended")


def test_pack_signs_installs_and_plays_on_both_sides(pack_key):
    items = [{"environment_key": EXPECTED[name], "scenario": d} for name, d in _docs().items()]
    manifest = {"v": 1, "kind": "scenarios", "id": "moosearsenal-2026q4", "name": "Autumn 2026 scenario pack",
                "version": "2026.10", "publisher": "Moose Arsenal", "issued": "2026-10-01", "items": items}
    tok = packs.sign(pack_key, manifest)
    labels = {d["name"]: _best_labels(d) for d in _docs().values()}
    with TestClient(app) as c:
        o, admin = _org(c); ha = _h(admin)
        pre = c.post("/api/packs/inspect", headers=ha, json={"token": tok}).json()
        assert pre["count"] == 4 and {i["environment_key"] for i in pre["items"]} == set(EXPECTED.values())
        r = c.post("/api/packs/install", headers=ha, json={"token": tok})
        assert r.status_code == 201, r.text
        created = r.json()["created"]
        assert len(created) == 4
        envs = {e["name"] for e in c.get("/api/environments", headers=ha).json()}
        assert all(env_library.ENVIRONMENT_TEMPLATES[k]["name"] in envs for k in EXPECTED.values())
        cat = c.get("/api/solo/scenarios", headers=ha).json()
        offered = {s["name"]: s for s in cat["scenarios"]}
        for it in created:
            assert it["name"] in offered and {"blue", "exec", "red"} <= set(offered[it["name"]]["sides"]), it["name"]
            for side in ("blue", "exec"):
                v = c.post("/api/solo/start", headers=ha, json={"scenario_id": it["scenario_id"], "side": side})
                assert v.status_code == 201, (it["name"], side, v.text)
                end, other = _play(c, admin, v.json()["id"], labels[it["name"]])
                d = c.get(f"/api/solo/{end['id']}/debrief", headers=ha).json()
                assert d["status"] == "complete" and d["rows"], (it["name"], side)
                assert other >= 1, (it["name"], side)  # every scenario has a scene for the other cell
                # only the player's own scenes are scored, and the best path scores full marks
                assert all(row["verdict"] == "best" and not row["timed_out"] for row in d["rows"]), (it["name"], side, d["rows"])
                assert d["raw_score"] == 100 and d["summary"]["impact"].get("cost"), (it["name"], side, d["summary"])
