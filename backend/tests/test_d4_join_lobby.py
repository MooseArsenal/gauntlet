"""D4 — join-code lobby: generate a code, join by it, see the lobby; org-scoped."""
import uuid

from fastapi.testclient import TestClient

from app.main import app


def _auth(t):
    return {"Authorization": f"Bearer {t}"}


def _org(client):
    o = uuid.uuid4().hex[:8]
    admin = client.post("/api/auth/register", json={
        "org_name": f"O{o}", "email": f"a{o}@ex.com", "password": "Str0ngPass!9"}).json()["access_token"]
    return o, admin


def _session(client, h):
    env = client.post("/api/environments", headers=h, json={"name": "e"}).json()["id"]
    scn = client.post("/api/scenarios", headers=h, json={
        "environment_id": env, "name": "s",
        "injects": [{"code": "INJ-01", "title": "a", "is_start": True}]}).json()["id"]
    return client.post("/api/sessions", headers=h, json={"scenario_id": scn, "name": "run"}).json()["id"]


def test_generate_join_and_lobby():
    with TestClient(app) as client:
        o, admin = _org(client)
        ha = _auth(admin)
        sid = _session(client, ha)
        code = client.post(f"/api/sessions/{sid}/join-code", headers=ha).json()["join_code"]
        assert len(code) == 6

        # A participant joins by the code, choosing the red cell.
        client.post("/api/auth/users", headers=ha, json={
            "email": f"p{o}@ex.com", "password": "Str0ngPass!9", "role": "evaluator"})
        p = client.post("/api/auth/login", json={
            "email": f"p{o}@ex.com", "password": "Str0ngPass!9"}).json()["access_token"]
        r = client.post("/api/join", headers=_auth(p),
                        json={"code": code, "cell": "red_cell", "display_name": "Red 1"})
        assert r.status_code == 200
        assert r.json()["session_id"] == sid and r.json()["cell"] == "red_cell"

        lobby = client.get(f"/api/sessions/{sid}/lobby", headers=ha).json()
        assert any(m["display_name"] == "Red 1" and m["cell"] == "red_cell" for m in lobby)


def test_join_is_idempotent_per_user():
    with TestClient(app) as client:
        o, admin = _org(client)
        ha = _auth(admin)
        sid = _session(client, ha)
        code = client.post(f"/api/sessions/{sid}/join-code", headers=ha).json()["join_code"]
        # admin (a facilitator) joins twice, switching cell — one lobby row, updated.
        client.post("/api/join", headers=ha, json={"code": code, "cell": "blue_cell"})
        client.post("/api/join", headers=ha, json={"code": code, "cell": "white_cell"})
        lobby = client.get(f"/api/sessions/{sid}/lobby", headers=ha).json()
        assert len(lobby) == 1 and lobby[0]["cell"] == "white_cell"


def test_bad_code_is_404():
    with TestClient(app) as client:
        _, admin = _org(client)
        assert client.post("/api/join", headers=_auth(admin),
                           json={"code": "ZZZZZZ"}).status_code == 404


def test_join_code_is_org_scoped():
    with TestClient(app) as client:
        _, a = _org(client)
        sid = _session(client, _auth(a))
        code = client.post(f"/api/sessions/{sid}/join-code", headers=_auth(a)).json()["join_code"]
        _, b = _org(client)  # a different org
        assert client.post("/api/join", headers=_auth(b), json={"code": code}).status_code == 404


def test_join_page_served():
    with TestClient(app) as client:
        assert client.get("/join.html").status_code == 200
        assert client.get("/join.js").status_code == 200
