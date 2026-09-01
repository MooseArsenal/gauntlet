"""D5 — CISA CTEP importer: bundled/uploaded packs → runnable scenarios."""
from fastapi.testclient import TestClient

from app.authoring import ctep
from app.main import app


def _env(client):
    return client.post("/api/environments", json={"name": "e", "sector": "gov"}).json()["id"]


def test_bundled_packs_build_coherent_scenarios():
    class _Env:  # a light stand-in with an id
        id = 1
    for key, pack in ctep.CTEP_PACKS.items():
        scn = ctep.build_from_pack(_Env(), pack)
        starts = [i for i in scn.injects if i.is_start]
        assert len(starts) == 1, key
        # one inject per module + a hotwash
        assert len(scn.injects) == len(pack["modules"]) + 1, key
        assert scn.objectives
        # discussion questions land as expected actions
        assert scn.injects[0].expected_actions


def test_catalog_lists_ctep_packs():
    with TestClient(app) as client:
        packs = {p["key"] for p in client.get("/api/catalog/ctep-packs").json()}
        assert {"ransomware", "ics_ot"} <= packs


def test_import_bundled_pack_runs():
    with TestClient(app) as client:
        env = _env(client)
        r = client.post("/api/scenarios/import-ctep",
                        json={"environment_id": env, "pack_key": "ransomware"})
        assert r.status_code == 201, r.text
        scn = r.json()
        assert sum(1 for i in scn["injects"] if i["is_start"]) == 1
        assert scn["objectives"]
        # it starts and advances like any generated scenario
        sid = client.post("/api/sessions", json={"scenario_id": scn["id"], "name": "t"}).json()["id"]
        state = client.post(f"/api/sessions/{sid}/start").json()
        assert state["session"]["status"] == "running"
        assert state["current_inject"] is not None


def test_import_uploaded_pack():
    with TestClient(app) as client:
        env = _env(client)
        pack = {
            "title": "Custom CTEP", "threat_actor": "X",
            "objectives": [{"title": "O1", "success_criteria": "c"}],
            "modules": [{"title": "M1", "narrative": "n", "techniques": ["T1566"],
                         "discussion_questions": ["q1?"]}],
        }
        r = client.post("/api/scenarios/import-ctep", json={"environment_id": env, "pack": pack})
        assert r.status_code == 201, r.text
        assert r.json()["name"] == "Custom CTEP"


def test_unknown_pack_key_is_400():
    with TestClient(app) as client:
        env = _env(client)
        r = client.post("/api/scenarios/import-ctep", json={"environment_id": env, "pack_key": "nope"})
        assert r.status_code == 400


def test_empty_pack_is_422():
    with TestClient(app) as client:
        env = _env(client)
        r = client.post("/api/scenarios/import-ctep",
                        json={"environment_id": env, "pack": {"title": "t", "modules": []}})
        assert r.status_code == 422
