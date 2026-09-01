"""F4 — improvement plan + tracker sync: CRUD, gap generation, push to a
tracker, and closure verification (via the simulation adapter + a stub)."""
from fastapi.testclient import TestClient

from app import tracker
from app.main import app


def _reg(client, org, email):
    return client.post("/api/auth/register",
                       json={"org_name": org, "email": email, "password": "Str0ngPass!9"}
                       ).json()["access_token"]


def _auth(t):
    return {"Authorization": f"Bearer {t}"}


def _session_with_gaps(client):
    scn = client.get("/api/scenarios").json()[0]["id"]
    sid = client.post("/api/sessions", json={"scenario_id": scn, "name": "f4"}).json()["id"]
    client.post(f"/api/sessions/{sid}/start")
    objectives = client.get(f"/api/scenarios/{scn}").json()["objectives"]
    client.post(f"/api/sessions/{sid}/observe",
                json={"objective_code": objectives[0]["code"], "rating": "missed", "note": "no detection"})
    client.post(f"/api/sessions/{sid}/observe",
                json={"objective_code": objectives[1]["code"], "rating": "partial", "note": "slow"})
    client.post(f"/api/sessions/{sid}/observe",
                json={"objective_code": objectives[2]["code"], "rating": "met", "note": "ok"})
    return sid


# --------------------------------------------------------------------------- #
# CRUD + validation
# --------------------------------------------------------------------------- #
def test_improvement_crud_and_validation():
    with TestClient(app) as client:
        r = client.post("/api/improvements",
                        json={"title": "Tune EDR", "severity": "high"})
        assert r.status_code == 201
        item_id = r.json()["id"]
        assert r.json()["status"] == "open" and r.json()["source"] == "manual"

        assert client.post("/api/improvements",
                           json={"title": "x", "severity": "urgent"}).status_code == 422
        assert client.patch(f"/api/improvements/{item_id}",
                            json={"status": "done"}).status_code == 422

        client.patch(f"/api/improvements/{item_id}", json={"status": "in_progress"})
        opens = client.get("/api/improvements?status=in_progress").json()
        assert any(i["id"] == item_id for i in opens)


# --------------------------------------------------------------------------- #
# generate from gaps
# --------------------------------------------------------------------------- #
def test_from_gaps_creates_items_for_missed_and_partial():
    with TestClient(app) as client:
        sid = _session_with_gaps(client)
        items = client.post(f"/api/sessions/{sid}/improvements/from-gaps").json()
        # missed + partial -> 2 items (met is skipped).
        assert len(items) == 2
        sevs = {i["severity"] for i in items}
        assert sevs == {"high", "medium"}
        assert all(i["source"] == "gap" for i in items)
        # They show up under the session.
        listed = client.get(f"/api/sessions/{sid}/improvements").json()
        assert len(listed) == 2


# --------------------------------------------------------------------------- #
# push + closure sync
# --------------------------------------------------------------------------- #
def test_push_uses_simulation_adapter_by_default():
    with TestClient(app) as client:
        item_id = client.post("/api/improvements", json={"title": "Patch VPN"}).json()["id"]
        pushed = client.post(f"/api/improvements/{item_id}/push").json()
        assert pushed["external_system"] == "simulation"
        assert pushed["external_ref"].startswith("SIM-")
        assert pushed["external_url"]
        # Pushing twice is a conflict.
        assert client.post(f"/api/improvements/{item_id}/push").status_code == 409


def test_sync_requires_a_link_then_closes_on_external_closure(monkeypatch):
    with TestClient(app) as client:
        item_id = client.post("/api/improvements", json={"title": "Rotate keys"}).json()["id"]
        # Syncing before pushing is a conflict.
        assert client.post(f"/api/improvements/{item_id}/sync").status_code == 409

        client.post(f"/api/improvements/{item_id}/push")

        # Stub the adapter so the external ticket reports "closed".
        class _Closed:
            name = "simulation"
            def create_issue(self, *a):  # pragma: no cover - not used here
                return "SIM-X", "u"
            def fetch_status(self, ref):
                return "closed"

        monkeypatch.setattr(tracker, "get_adapter", lambda: _Closed())
        synced = client.post(f"/api/improvements/{item_id}/sync").json()
        assert synced["external_status"] == "closed"
        assert synced["status"] == "closed"
        # The item itself is now closed.
        assert client.get("/api/improvements?status=closed").json()


def test_sync_marks_in_progress(monkeypatch):
    with TestClient(app) as client:
        item_id = client.post("/api/improvements", json={"title": "Segment net"}).json()["id"]
        client.post(f"/api/improvements/{item_id}/push")

        class _WIP:
            name = "simulation"
            def create_issue(self, *a):
                return "SIM-Y", "u"
            def fetch_status(self, ref):
                return "in_progress"

        monkeypatch.setattr(tracker, "get_adapter", lambda: _WIP())
        synced = client.post(f"/api/improvements/{item_id}/sync").json()
        assert synced["status"] == "in_progress"


# --------------------------------------------------------------------------- #
# adapter selection (unit)
# --------------------------------------------------------------------------- #
def test_get_adapter_defaults_to_simulation():
    assert tracker.get_adapter().name == "simulation"


# --------------------------------------------------------------------------- #
# tenant isolation
# --------------------------------------------------------------------------- #
def test_improvements_tenant_scoped():
    with TestClient(app) as client:
        a = _reg(client, "ImpA", "f4-a@example.com")
        b = _reg(client, "ImpB", "f4-b@example.com")
        item_id = client.post("/api/improvements", headers=_auth(a),
                              json={"title": "A-only"}).json()["id"]
        assert client.patch(f"/api/improvements/{item_id}", headers=_auth(b),
                            json={"status": "closed"}).status_code == 404
        assert client.post(f"/api/improvements/{item_id}/push", headers=_auth(b)).status_code == 404
        assert item_id not in [i["id"] for i in client.get("/api/improvements", headers=_auth(b)).json()]
