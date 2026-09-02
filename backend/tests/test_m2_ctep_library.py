"""M2 — the CTEP content library: every bundled pack is well-formed, written
against a library environment, and imports into a runnable scenario in one
call, stamping that environment into the org when it is missing."""
import uuid

from fastapi.testclient import TestClient

from app.authoring import ctep
from app.authoring.environments import ENVIRONMENT_TEMPLATES
from app.engine import technique
from app.main import app

PW = "Str0ngPass!9"


def _h(t):
    return {"Authorization": f"Bearer {t}"}


def _org(client):
    o = uuid.uuid4().hex[:8]
    t = client.post("/api/auth/register", json={
        "org_name": f"O{o}", "email": f"a{o}@ex.com", "password": PW}).json()["access_token"]
    return o, t


def test_library_packs_are_well_formed():
    assert len(ctep.CTEP_PACKS) >= 11
    sectors = set()
    for key, p in ctep.CTEP_PACKS.items():
        assert p["title"] and p["threat_actor"] and p.get("description"), key
        assert p.get("environment_key") in ENVIRONMENT_TEMPLATES, key
        assert len(p["modules"]) >= 3 and len(p["objectives"]) >= 3, key
        sectors.add(p["sector"])
        for m in p["modules"]:
            assert m["title"] and m["narrative"] and len(m["discussion_questions"]) == 3, (key, m["title"])
            for t in m["techniques"]:
                assert technique.is_valid(t), (key, t)
        # the first modules carry techniques so the exercise adjudicates
        assert any(m["techniques"] for m in p["modules"]), key
    assert len(sectors) >= 6


def test_catalog_lists_sector_and_environment():
    with TestClient(app) as c:
        o, t = _org(c); h = _h(t)
        packs = c.get("/api/catalog/ctep-packs", headers=h).json()
        by = {p["key"]: p for p in packs}
        assert by["hospital_ransomware"]["sector"] == "Healthcare"
        assert by["hospital_ransomware"]["environment_key"] == "hospital"
        assert by["hospital_ransomware"]["environment_name"].startswith("St. Aldric")
        assert by["ransomware"]["sector"] == "Cross-sector"


def test_every_pack_imports_into_its_own_environment_and_runs():
    with TestClient(app) as c:
        o, t = _org(c); h = _h(t)
        assert c.get("/api/environments", headers=h).json() == []
        for key in ctep.CTEP_PACKS:
            r = c.post("/api/scenarios/import-ctep", headers=h, json={"pack_key": key})
            assert r.status_code == 201, (key, r.text)
            scn = r.json()
            assert len(scn["injects"]) == len(ctep.CTEP_PACKS[key]["modules"]) + 1
            sid = c.post("/api/sessions", headers=h, json={"scenario_id": scn["id"], "name": key}).json()["id"]
            assert c.post(f"/api/sessions/{sid}/start", headers=h).status_code == 200
            first = next(i for i in scn["injects"] if i["attack_techniques"])
            a = c.post(f"/api/sessions/{sid}/adjudicate", headers=h,
                       json={"techniques": first["attack_techniques"], "target_asset": "", "description": "m"})
            assert a.status_code == 200, (key, a.text)
        # the org's environments were stamped once each, not once per pack
        envs = c.get("/api/environments", headers=h).json()
        wanted = {ENVIRONMENT_TEMPLATES[p["environment_key"]]["name"] for p in ctep.CTEP_PACKS.values()}
        assert sorted(e["name"] for e in envs) == sorted(wanted)


def test_import_still_honours_a_chosen_environment_and_rejects_bad_input():
    with TestClient(app) as c:
        o, t = _org(c); h = _h(t)
        env = c.post("/api/environments", headers=h, json={"name": "mine", "assets": [{"code": "A", "name": "a"}]}).json()["id"]
        scn = c.post("/api/scenarios/import-ctep", headers=h, json={"pack_key": "bec_wire_fraud", "environment_id": env}).json()
        assert scn["environment_id"] == env
        assert c.get("/api/environments", headers=h).json()[0]["id"] == env
        assert len(c.get("/api/environments", headers=h).json()) == 1
        # an uploaded pack must name an environment
        up = {"title": "x", "modules": [{"title": "m", "narrative": "n"}]}
        assert c.post("/api/scenarios/import-ctep", headers=h, json={"pack": up}).status_code == 400
        assert c.post("/api/scenarios/import-ctep", headers=h, json={"pack_key": "nope"}).status_code == 400
        # participants cannot import
        em = f"p{o}@ex.com"
        c.post("/api/auth/users", headers=h, json={"email": em, "password": PW, "role": "participant"})
        tp = c.post("/api/auth/login", json={"email": em, "password": PW}).json()["access_token"]
        assert c.post("/api/scenarios/import-ctep", headers=_h(tp), json={"pack_key": "ransomware"}).status_code == 403
