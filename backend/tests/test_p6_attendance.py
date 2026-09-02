"""P6 — attendance certificates verifiable through the public endpoint,
calendar invites, and the board pack."""
import uuid
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from app import attendance
from app.main import app

PW = "Str0ngPass!9"


def _h(t):
    return {"Authorization": f"Bearer {t}"}


def _org(client):
    o = uuid.uuid4().hex[:8]
    t = client.post("/api/auth/register", json={
        "org_name": f"O{o}", "email": f"a{o}@ex.com", "password": PW}).json()["access_token"]
    return o, t


def _user(client, ha, o, role, tag=""):
    em = f"{role}{tag}{o}@ex.com"
    client.post("/api/auth/users", headers=ha, json={"email": em, "password": PW, "role": role})
    return client.post("/api/auth/login", json={"email": em, "password": PW}).json()["access_token"]


def _world(client, ha):
    env = client.post("/api/environments", headers=ha, json={"name": "e", "assets": [{"code": "A", "name": "a"}]}).json()["id"]
    scn = client.post("/api/scenarios", headers=ha, json={
        "environment_id": env, "name": "s",
        "injects": [{"code": "INJ-01", "title": "t", "narrative": "n", "is_start": True, "expected_actions": ["Act"]}]}).json()["id"]
    sid = client.post("/api/sessions", headers=ha, json={"scenario_id": scn, "name": "Q3 tabletop"}).json()["id"]
    return sid


def test_attendance_certificates_and_public_check():
    with TestClient(app) as c:
        o, admin = _org(c); ha = _h(admin)
        sid = _world(c, ha)
        code = c.post(f"/api/sessions/{sid}/join-code", headers=ha).json()["join_code"]
        p1 = _h(_user(c, ha, o, "participant", "1")); p2 = _h(_user(c, ha, o, "participant", "2"))
        c.post("/api/join", headers=p1, json={"code": code, "cell": "blue_cell", "display_name": "Ana Ruiz"})
        c.post("/api/join", headers=p2, json={"code": code, "cell": "blue_cell", "display_name": "Ben Ola"})
        c.post(f"/api/sessions/{sid}/start", headers=ha)
        c.post(f"/api/sessions/{sid}/respond", headers=p1, json={"option": "a"})
        # needs the exercise certificate first
        assert c.get(f"/api/sessions/{sid}/attendance", headers=ha).status_code == 409
        assert c.get(f"/api/sessions/{sid}/my-attendance.pdf", headers=p1).status_code == 409
        c.post(f"/api/sessions/{sid}/complete", headers=ha)
        serial = c.post(f"/api/sessions/{sid}/certificate", headers=ha).json()["serial"]
        att = c.get(f"/api/sessions/{sid}/attendance", headers=ha).json()
        assert att["serial"] == serial and att["hours"] >= 0.25 and len(att["attendees"]) == 2
        ana = next(a for a in att["attendees"] if a["display_name"] == "Ana Ruiz")
        assert ana["responses"] == 1 and ana["mean_score"] == 1.0 and ana["attendee_code"].startswith("AT-")
        assert ana["email"].startswith("participant1")
        # staff PDF and the participant's own PDF
        r = c.get(f"/api/sessions/{sid}/attendance/{ana['join_id']}.pdf", headers=ha)
        assert r.status_code == 200 and r.content[:4] == b"%PDF"
        mine = c.get(f"/api/sessions/{sid}/my-attendance.pdf", headers=p1)
        assert mine.status_code == 200 and mine.content[:4] == b"%PDF" and ana["attendee_code"] in mine.headers["content-disposition"]
        # someone who never joined has none; participants cannot list others
        assert c.get(f"/api/sessions/{sid}/my-attendance.pdf", headers=ha).status_code == 404
        assert c.get(f"/api/sessions/{sid}/attendance", headers=p1).status_code == 403
        # public attendee check: no email, no score
        v = c.get(f"/api/certificates/{serial}/attendance/{ana['attendee_code'].lower()}").json()
        assert v["valid"] is True and v["record"]["display_name"] == "Ana Ruiz" and v["record"]["responses"] == 1
        assert "email" not in v["record"] and "mean_score" not in v["record"]
        assert c.get(f"/api/certificates/{serial}/attendance/AT-0000000000").json()["valid"] is False
        assert c.get(f"/api/certificates/GC-2026-NOPE0000/attendance/{ana['attendee_code']}").json()["valid"] is False
        # the code is bound to this exercise's serial and cannot be reused across sessions
        sid2 = _world(c, ha)
        assert attendance.attendee_code(serial, ana["join_id"], 1) != attendance.attendee_code("GC-2026-OTHER000", ana["join_id"], 1)
        # revoked certificate → attendee no longer verifies
        c.post(f"/api/sessions/{sid}/certificate/revoke", headers=ha)
        assert c.get(f"/api/certificates/{serial}/attendance/{ana['attendee_code']}").json()["valid"] is False


def test_board_pack_and_calendar_files():
    with TestClient(app) as c:
        o, admin = _org(c); ha = _h(admin)
        sid = _world(c, ha)
        c.post(f"/api/sessions/{sid}/start", headers=ha)
        c.post(f"/api/sessions/{sid}/adjudicate", headers=ha, json={"techniques": ["T1003"], "target_asset": "A", "description": "m"})
        assert c.get(f"/api/sessions/{sid}/board-pack.pdf", headers=ha).status_code == 409
        c.post(f"/api/sessions/{sid}/complete", headers=ha)
        serial = c.post(f"/api/sessions/{sid}/certificate", headers=ha).json()["serial"]
        bp = c.get(f"/api/sessions/{sid}/board-pack.pdf", headers=ha)
        assert bp.status_code == 200 and bp.content[:4] == b"%PDF" and serial in bp.headers["content-disposition"]
        # calendar files
        ics = c.get(f"/api/sessions/{sid}/invite.ics", headers=ha, params={"start": "2026-10-01T09:30:00Z", "hours": 3, "location": "Boardroom"})
        assert ics.status_code == 200 and ics.headers["content-type"].startswith("text/calendar")
        body = ics.text
        assert "BEGIN:VCALENDAR" in body and "DTSTART:20261001T093000Z" in body and "DTEND:20261001T123000Z" in body
        assert "SUMMARY:Exercise: Q3 tabletop" in body and "LOCATION:Boardroom" in body and "/join.html" in body
        assert c.get(f"/api/sessions/{sid}/invite.ics", headers=ha, params={"start": "tomorrow"}).status_code == 422
        scn = c.get(f"/api/sessions/{sid}", headers=ha).json()["scenario"]["id"]
        when = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
        sch = c.post("/api/schedules", headers=ha, json={"scenario_id": scn, "name": "Quarterly drill", "cadence": "once", "next_run_at": when})
        assert sch.status_code == 201, sch.text
        sics = c.get(f"/api/schedules/{sch.json()['id']}/invite.ics", headers=ha)
        assert sics.status_code == 200 and "SUMMARY:Exercise: Quarterly drill" in sics.text and "VALARM" in sics.text
        # participants cannot fetch calendar files or the board pack
        tp = _user(c, ha, o, "participant")
        assert c.get(f"/api/sessions/{sid}/board-pack.pdf", headers=_h(tp)).status_code == 403
        assert c.get(f"/api/schedules/{sch.json()['id']}/invite.ics", headers=_h(tp)).status_code == 403


def test_ics_escaping():
    body = attendance.ics("u@x", "A; B, C", datetime(2026, 1, 2, 3, 4, tzinfo=timezone.utc), 1.5, "line1\nline2")
    assert "SUMMARY:A\\; B\\, C" in body and "DESCRIPTION:line1\\nline2" in body and "DTEND:20260102T043400Z" in body
