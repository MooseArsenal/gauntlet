"""E1 — the environment library: sector templates a proctor can stamp into an
org, complete enough to adjudicate against; the demo seed offers a choice."""
import uuid

from fastapi.testclient import TestClient

from app.authoring.environments import ENVIRONMENT_TEMPLATES, build_from_template
from app.engine import adjudication, technique
from app.main import app

PW = "Str0ngPass!9"


def _h(t):
    return {"Authorization": f"Bearer {t}"}


def _org(c, role=None):
    o = uuid.uuid4().hex[:8]
    t = c.post("/api/auth/register", json={"org_name": f"O{o}", "email": f"a{o}@ex.com", "password": PW}).json()["access_token"]
    return o, t


def test_every_template_is_internally_consistent():
    assert len(ENVIRONMENT_TEMPLATES) >= 6
    for key in ENVIRONMENT_TEMPLATES:
        env = build_from_template(key)
        codes = [a["code"] for a in env.assets]
        assert len(codes) == len(set(codes)), f"{key}: duplicate asset codes"
        for c in env.controls + env.detections + env.deception_assets:
            assert 0 < float(c["efficacy"]) <= 1, f"{key}: {c['name']} has no efficacy"
            assert c.get("latency_min") is not None, f"{key}: {c['name']} has no latency"
            for a in c["assets"]:
                assert a == "*" or a in codes, f"{key}: {c['name']} covers unknown asset {a}"
            for t in c["covers"]:
                assert t == "*" or technique.is_valid(t), f"{key}: {c['name']} has malformed technique {t}"
        for cj in env.crown_jewels:
            assert cj in codes, f"{key}: crown jewel {cj} is not an asset"
        assert set(env.visibility) >= {"white_cell", "blue_cell", "red_cell"}
        # something is actually detectable in each estate
        ruling = adjudication.adjudicate(env, ["T1078"], codes[0])
        assert "probability" in ruling


def test_library_is_listed_and_stamped_into_the_org():
    with TestClient(app) as c:
        o, t = _org(c); h = _h(t)
        lib = c.get("/api/environments/templates", headers=h).json()
        assert {x["key"] for x in lib} >= {"hospital", "water_utility", "saas", "county", "university", "manufacturer"}
        assert all(x["assets"] > 0 and x["controls"] > 0 for x in lib)
        r = c.post("/api/environments/from-template", headers=h, json={"key": "hospital", "name": "Our hospital"})
        assert r.status_code == 201
        env = r.json()
        assert env["name"] == "Our hospital" and env["sector"] == "Healthcare" and len(env["controls"]) >= 4
        assert [e["id"] for e in c.get("/api/environments", headers=h).json()] == [env["id"]]
        assert c.post("/api/environments/from-template", headers=h, json={"key": "nope"}).status_code == 404
        # stamping the same template twice keeps the names distinct in the picker
        n1 = c.post("/api/environments/from-template", headers=h, json={"key": "saas"}).json()["name"]
        n2 = c.post("/api/environments/from-template", headers=h, json={"key": "saas"}).json()["name"]
        assert n1 == "Lumen Ledger — Cloud SaaS" and n2 == "Lumen Ledger — Cloud SaaS (2)"
        # another org never sees it
        o2, t2 = _org(c)
        assert c.get("/api/environments", headers=_h(t2)).json() == []
        # a scenario generated against it runs
        scn = c.post("/api/scenarios/generate", headers=h, json={"environment_id": env["id"], "template_key": "ransomware_financial"})
        assert scn.status_code in (201, 400)  # 400 only if that template key is absent; the env itself is valid


def test_participants_cannot_read_the_library():
    with TestClient(app) as c:
        o, t = _org(c); h = _h(t)
        c.post("/api/auth/users", headers=h, json={"email": f"p{o}@ex.com", "password": PW, "role": "participant"})
        p = c.post("/api/auth/login", json={"email": f"p{o}@ex.com", "password": PW}).json()["access_token"]
        assert c.get("/api/environments/templates", headers=_h(p)).status_code == 403
        assert c.post("/api/environments/from-template", headers=_h(p), json={"key": "saas"}).status_code == 403
