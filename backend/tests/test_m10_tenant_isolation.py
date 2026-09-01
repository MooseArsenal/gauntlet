"""M10 — tenant-isolation fuzz: no org can reach another org's resources.

Creates several orgs, each with a full object graph, then systematically probes
every cross-tenant access path (read, list, update, delete) across
environments, scenarios, and sessions, asserting the API never leaks.
"""
import itertools

from fastapi.testclient import TestClient

from app.main import app


def _register(client, org, email):
    r = client.post("/api/auth/register",
                    json={"org_name": org, "email": email, "password": "Str0ngPass!9"})
    assert r.status_code == 201, r.text
    return r.json()["access_token"]


def _auth(t):
    return {"Authorization": f"Bearer {t}"}


def _seed_org(client, token):
    """Give an org an environment, a scenario, and a running session."""
    env = client.post("/api/environments", headers=_auth(token),
                       json={"name": "env", "crown_jewels": ["billing-db"]}).json()["id"]
    scn = client.post("/api/scenarios", headers=_auth(token), json={
        "environment_id": env, "name": "scn",
        "objectives": [{"code": "OBJ-1", "title": "Detect"}],
        "injects": [{"code": "INJ-01", "title": "start", "is_start": True}],
    }).json()["id"]
    sid = client.post("/api/sessions", headers=_auth(token),
                      json={"scenario_id": scn, "name": "run"}).json()["id"]
    return {"env": env, "scn": scn, "sid": sid}


def test_cross_tenant_access_is_denied_everywhere():
    with TestClient(app) as client:
        orgs = {
            name: {"token": _register(client, f"iso-{name}", f"iso-{name}@example.com")}
            for name in ("alpha", "bravo", "charlie")
        }
        for o in orgs.values():
            o["ids"] = _seed_org(client, o["token"])

        for a, b in itertools.permutations(orgs.values(), 2):
            tb, ids = b["token"], a["ids"]  # b tries to touch a's objects

            # Reads are 404 (existence hidden, not 403).
            assert client.get(f"/api/environments/{ids['env']}", headers=_auth(tb)).status_code == 404
            assert client.get(f"/api/scenarios/{ids['scn']}", headers=_auth(tb)).status_code == 404
            assert client.get(f"/api/sessions/{ids['sid']}", headers=_auth(tb)).status_code == 404
            assert client.get(f"/api/sessions/{ids['sid']}/verify", headers=_auth(tb)).status_code == 404

            # Mutations are refused too (404, never a silent success).
            assert client.patch(f"/api/scenarios/{ids['scn']}", headers=_auth(tb),
                                json={"name": "hijacked"}).status_code == 404
            assert client.post(f"/api/sessions/{ids['sid']}/advance", headers=_auth(tb),
                               json={"when": "proctor_choice"}).status_code == 404
            assert client.post(f"/api/sessions/{ids['sid']}/ws-ticket",
                               headers=_auth(tb)).status_code == 404

            # And nothing leaks through the list endpoints.
            env_ids = [e["id"] for e in client.get("/api/environments", headers=_auth(tb)).json()]
            scn_ids = [s["id"] for s in client.get("/api/scenarios", headers=_auth(tb)).json()]
            ses_ids = [s["id"] for s in client.get("/api/sessions", headers=_auth(tb)).json()]
            assert ids["env"] not in env_ids
            assert ids["scn"] not in scn_ids
            assert ids["sid"] not in ses_ids


def test_owner_still_has_full_access():
    """The isolation must not be so blunt it blocks the legitimate owner."""
    with TestClient(app) as client:
        token = _register(client, "iso-own", "iso-own@example.com")
        ids = _seed_org(client, token)
        assert client.get(f"/api/environments/{ids['env']}", headers=_auth(token)).status_code == 200
        assert client.get(f"/api/scenarios/{ids['scn']}", headers=_auth(token)).status_code == 200
        assert client.get(f"/api/sessions/{ids['sid']}", headers=_auth(token)).status_code == 200
