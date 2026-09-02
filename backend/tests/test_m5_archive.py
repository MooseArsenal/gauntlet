"""U-3 — archive (soft delete): hidden from lists and pickers, kept on the
record, restorable; no new runs of an archived scenario; a live exercise cannot
be archived."""
import uuid

from fastapi.testclient import TestClient

from app.main import app

PW = "Str0ngPass!9"


def _h(t):
    return {"Authorization": f"Bearer {t}"}


def _org(c):
    o = uuid.uuid4().hex[:8]
    return _h(c.post("/api/auth/register", json={"org_name": f"O{o}", "email": f"a{o}@ex.com", "password": PW}).json()["access_token"])


def _world(c, h):
    env = c.post("/api/environments", headers=h, json={"name": "e"}).json()["id"]
    scn = c.post("/api/scenarios", headers=h, json={"environment_id": env, "name": "s",
                                                     "injects": [{"code": "A", "title": "a", "is_start": True}]}).json()["id"]
    sid = c.post("/api/sessions", headers=h, json={"scenario_id": scn, "name": "r"}).json()["id"]
    return env, scn, sid


def test_archive_hides_restore_shows():
    with TestClient(app) as c:
        h = _org(c)
        env, scn, sid = _world(c, h)
        for kind, i in (("scenarios", scn), ("environments", env), ("sessions", sid)):
            r = c.post(f"/api/{kind}/{i}/archive", headers=h)
            assert r.status_code == 200 and r.json()["archived_at"], kind
            assert i not in [x["id"] for x in c.get(f"/api/{kind}", headers=h).json()], kind
            assert i in [x["id"] for x in c.get(f"/api/{kind}?include_archived=1", headers=h).json()], kind
            assert c.get(f"/api/{kind}/{i}", headers=h).status_code == 200  # the record itself is kept
            assert c.post(f"/api/{kind}/{i}/unarchive", headers=h).status_code == 200
            assert i in [x["id"] for x in c.get(f"/api/{kind}", headers=h).json()], kind


def test_archived_scenario_cannot_start_new_runs_and_live_sessions_cannot_be_archived():
    with TestClient(app) as c:
        h = _org(c)
        env, scn, sid = _world(c, h)
        c.post(f"/api/sessions/{sid}/start", headers=h)
        assert c.post(f"/api/sessions/{sid}/archive", headers=h).status_code == 409
        c.post(f"/api/sessions/{sid}/complete", headers=h)
        assert c.post(f"/api/sessions/{sid}/archive", headers=h).status_code == 200
        c.post(f"/api/scenarios/{scn}/archive", headers=h)
        assert c.post("/api/sessions", headers=h, json={"scenario_id": scn, "name": "again"}).status_code == 409
        c.post(f"/api/scenarios/{scn}/unarchive", headers=h)
        assert c.post("/api/sessions", headers=h, json={"scenario_id": scn, "name": "again"}).status_code == 201


def test_archive_is_facilitator_only_and_org_scoped():
    with TestClient(app) as c:
        h = _org(c); env, scn, sid = _world(c, h)
        other = _org(c)
        assert c.post(f"/api/scenarios/{scn}/archive", headers=other).status_code == 404
        o = uuid.uuid4().hex[:6]
        c.post("/api/auth/users", headers=h, json={"email": f"ev{o}@ex.com", "password": PW, "role": "evaluator"})
        ev = _h(c.post("/api/auth/login", json={"email": f"ev{o}@ex.com", "password": PW}).json()["access_token"])
        assert c.post(f"/api/scenarios/{scn}/archive", headers=ev).status_code == 403
        actions = {a["action"] for a in c.get("/api/audit", headers=h).json()}
        c.post(f"/api/scenarios/{scn}/archive", headers=h)
        assert "scenario.archive" in {a["action"] for a in c.get("/api/audit", headers=h).json()}
