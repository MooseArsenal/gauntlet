"""Q2 — visual editor save: the scenario graph-replace endpoint + page serving."""
from fastapi.testclient import TestClient

from app.main import app


def _scenario(client):
    env = client.post("/api/environments", json={"name": "q2-env"}).json()["id"]
    return client.post("/api/scenarios", json={
        "environment_id": env, "name": "q2",
        "injects": [{"code": "INJ-01", "title": "start", "is_start": True,
                     "branches": [{"when": "proctor_choice", "goto": "INJ-02"}]},
                    {"code": "INJ-02", "title": "next"}],
    }).json()["id"]


def _auth(t):
    return {"Authorization": f"Bearer {t}"}


def test_replace_graph_swaps_injects_and_keeps_positions():
    with TestClient(app) as client:
        sid = _scenario(client)
        new_graph = {"injects": [
            {"code": "A", "title": "Alpha", "is_start": True, "sequence": 0,
             "meta": {"pos": {"x": 40, "y": 60}},
             "branches": [{"when": "action_taken", "trigger": "go", "goto": "B"}]},
            {"code": "B", "title": "Bravo", "sequence": 1, "meta": {"pos": {"x": 300, "y": 60}}},
        ]}
        r = client.put(f"/api/scenarios/{sid}/graph", json=new_graph)
        assert r.status_code == 200, r.text
        injects = r.json()["injects"]
        assert {i["code"] for i in injects} == {"A", "B"}
        a = next(i for i in injects if i["code"] == "A")
        assert a["meta"]["pos"] == {"x": 40, "y": 60}  # editor node position round-trips
        # The old injects are gone.
        fetched = client.get(f"/api/scenarios/{sid}").json()
        assert {i["code"] for i in fetched["injects"]} == {"A", "B"}


def test_replace_graph_rejects_incoherent_graphs():
    with TestClient(app) as client:
        sid = _scenario(client)
        # No start node.
        r = client.put(f"/api/scenarios/{sid}/graph",
                       json={"injects": [{"code": "X", "title": "x"}]})
        assert r.status_code == 422
        # Two starts.
        r = client.put(f"/api/scenarios/{sid}/graph", json={"injects": [
            {"code": "X", "title": "x", "is_start": True},
            {"code": "Y", "title": "y", "is_start": True}]})
        assert r.status_code == 422
        # Dangling goto.
        r = client.put(f"/api/scenarios/{sid}/graph", json={"injects": [
            {"code": "X", "title": "x", "is_start": True,
             "branches": [{"when": "proctor_choice", "goto": "NOPE"}]}]})
        assert r.status_code == 422
        # Duplicate codes.
        r = client.put(f"/api/scenarios/{sid}/graph", json={"injects": [
            {"code": "X", "title": "x", "is_start": True},
            {"code": "X", "title": "dup"}]})
        assert r.status_code == 422


def test_replace_graph_facilitator_and_tenant_scoped():
    with TestClient(app) as client:
        sid = _scenario(client)
        # Another tenant can't touch it.
        other = client.post("/api/auth/register", json={
            "org_name": "Q2Other", "email": "q2-other@example.com", "password": "Str0ngPass!9",
        }).json()["access_token"]
        r = client.put(f"/api/scenarios/{sid}/graph", headers=_auth(other),
                       json={"injects": [{"code": "A", "title": "a", "is_start": True}]})
        assert r.status_code == 404

        # An evaluator (non-facilitator) in the owning org is forbidden.
        # (Register a fresh org where we control roles.)
        admin = client.post("/api/auth/register", json={
            "org_name": "Q2Own", "email": "q2-admin@example.com", "password": "Str0ngPass!9",
        }).json()["access_token"]
        env = client.post("/api/environments", headers=_auth(admin), json={"name": "e"}).json()["id"]
        my = client.post("/api/scenarios", headers=_auth(admin), json={
            "environment_id": env, "name": "s",
            "injects": [{"code": "INJ-01", "title": "s", "is_start": True}]}).json()["id"]
        client.post("/api/auth/users", headers=_auth(admin), json={
            "email": "q2-ev@example.com", "password": "Str0ngPass!9", "role": "evaluator"})
        ev = client.post("/api/auth/login",
                         json={"email": "q2-ev@example.com", "password": "Str0ngPass!9"}
                         ).json()["access_token"]
        r = client.put(f"/api/scenarios/{my}/graph", headers=_auth(ev),
                       json={"injects": [{"code": "A", "title": "a", "is_start": True}]})
        assert r.status_code == 403


def test_editor_page_is_served():
    with TestClient(app) as client:
        r = client.get("/editor.html")
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]


def test_progress_map_assets_served():
    with TestClient(app) as client:
        for path in ("/progressmap.js", "/progressmap.css"):
            r = client.get(path)
            assert r.status_code == 200, path
