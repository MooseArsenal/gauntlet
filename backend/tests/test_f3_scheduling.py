"""F3 — exercise scheduling & cadence: recurrence maths, due materialisation,
reminders, and the schedules API (tenant-scoped)."""
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from app import models, scheduling
from app.database import SessionLocal
from app.main import app


def _iso(dt):
    return dt.isoformat()


# --------------------------------------------------------------------------- #
# cadence maths (unit)
# --------------------------------------------------------------------------- #
def test_next_occurrence_cadences():
    base = datetime(2026, 1, 31, 9, 0, tzinfo=timezone.utc)
    assert scheduling.next_occurrence(base, "daily") == base + timedelta(days=1)
    assert scheduling.next_occurrence(base, "weekly") == base + timedelta(weeks=1)
    # Month rollover clamps the day (Jan 31 -> Feb 28).
    assert scheduling.next_occurrence(base, "monthly") == datetime(2026, 2, 28, 9, 0, tzinfo=timezone.utc)
    assert scheduling.next_occurrence(base, "quarterly") == datetime(2026, 4, 30, 9, 0, tzinfo=timezone.utc)
    assert scheduling.next_occurrence(base, "once") is None


# --------------------------------------------------------------------------- #
# API CRUD + validation
# --------------------------------------------------------------------------- #
def _scenario_id(client):
    return client.get("/api/scenarios").json()[0]["id"]


def test_schedule_crud_and_validation():
    with TestClient(app) as client:
        scn = _scenario_id(client)
        soon = datetime.now(timezone.utc) + timedelta(days=7)
        r = client.post("/api/schedules", json={
            "scenario_id": scn, "name": "Weekly drill", "cadence": "weekly",
            "next_run_at": _iso(soon), "invitees": ["soc@example.com"],
        })
        assert r.status_code == 201, r.text
        sid = r.json()["id"]
        assert r.json()["enabled"] is True

        # Bad cadence rejected.
        assert client.post("/api/schedules", json={
            "scenario_id": scn, "name": "x", "cadence": "hourly", "next_run_at": _iso(soon),
        }).status_code == 422

        # List + get + patch + delete.
        assert any(s["id"] == sid for s in client.get("/api/schedules").json())
        client.patch(f"/api/schedules/{sid}", json={"enabled": False})
        assert client.get(f"/api/schedules/{sid}").json()["enabled"] is False
        assert client.delete(f"/api/schedules/{sid}").status_code == 204
        assert client.get(f"/api/schedules/{sid}").status_code == 404


# --------------------------------------------------------------------------- #
# run-due materialises sessions + advances cadence
# --------------------------------------------------------------------------- #
def test_run_due_materialises_and_advances():
    with TestClient(app) as client:
        scn = _scenario_id(client)
        past = datetime.now(timezone.utc) - timedelta(minutes=5)
        sid = client.post("/api/schedules", json={
            "scenario_id": scn, "name": "Due now", "cadence": "weekly", "next_run_at": _iso(past),
        }).json()["id"]

        before = len(client.get("/api/sessions").json())
        r = client.post("/api/schedules/run-due")
        assert r.status_code == 200 and r.json()["ran"] >= 1
        after = len(client.get("/api/sessions").json())
        assert after > before

        # Weekly cadence advanced into the future; a second run does nothing.
        sched = client.get(f"/api/schedules/{sid}").json()
        nxt = datetime.fromisoformat(sched["next_run_at"])
        if nxt.tzinfo is None:
            nxt = nxt.replace(tzinfo=timezone.utc)
        assert nxt > datetime.now(timezone.utc)
        assert sched["last_run_at"] is not None
        assert client.post("/api/schedules/run-due").json()["ran"] == 0


def test_once_schedule_retires_after_run():
    with TestClient(app) as client:
        scn = _scenario_id(client)
        past = datetime.now(timezone.utc) - timedelta(minutes=1)
        sid = client.post("/api/schedules", json={
            "scenario_id": scn, "name": "One-off", "cadence": "once", "next_run_at": _iso(past),
        }).json()["id"]
        client.post("/api/schedules/run-due")
        assert client.get(f"/api/schedules/{sid}").json()["enabled"] is False


# --------------------------------------------------------------------------- #
# reminders
# --------------------------------------------------------------------------- #
def test_reminders_window_and_send_dedupe():
    with TestClient(app) as client:
        scn = _scenario_id(client)
        # Runs in 10h with a 24h reminder lead -> reminder window is open now.
        run_at = datetime.now(timezone.utc) + timedelta(hours=10)
        sid = client.post("/api/schedules", json={
            "scenario_id": scn, "name": "Imminent", "cadence": "once",
            "next_run_at": _iso(run_at), "reminder_lead_hours": 24,
        }).json()["id"]

        pending = client.get("/api/schedules/reminders").json()
        assert any(p["schedule_id"] == sid for p in pending)

        # Sending marks it reminded, so it drops out of the pending list.
        sent = client.get("/api/schedules/reminders?send=true").json()
        assert any(p["schedule_id"] == sid for p in sent)
        still = client.get("/api/schedules/reminders").json()
        assert not any(p["schedule_id"] == sid for p in still)


# --------------------------------------------------------------------------- #
# tenant isolation
# --------------------------------------------------------------------------- #
def test_schedules_tenant_scoped():
    with TestClient(app) as client:
        scn = _scenario_id(client)
        run_at = datetime.now(timezone.utc) + timedelta(days=3)
        sid = client.post("/api/schedules", json={
            "scenario_id": scn, "name": "Mine", "cadence": "once", "next_run_at": _iso(run_at),
        }).json()["id"]

        tok = client.post("/api/auth/register", json={
            "org_name": "SchedOther", "email": "f3-other@example.com", "password": "Str0ngPass!9",
        }).json()["access_token"]
        h = {"Authorization": f"Bearer {tok}"}
        assert client.get(f"/api/schedules/{sid}", headers=h).status_code == 404
        assert sid not in [s["id"] for s in client.get("/api/schedules", headers=h).json()]
