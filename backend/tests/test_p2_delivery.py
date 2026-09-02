"""P2 — real inject delivery: SMTP to the people who joined the addressed
cells, Slack/Teams/webhook to a channel, invites with the join code; every
send operator-configured, air-gap guarded, and recorded on the timeline."""
import uuid

import pytest
from fastapi.testclient import TestClient

from app import delivery
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
    return em, client.post("/api/auth/login", json={"email": em, "password": PW}).json()["access_token"]


def _world(client, ha):
    env = client.post("/api/environments", headers=ha, json={"name": "e", "assets": [{"code": "A", "name": "a"}]}).json()["id"]
    scn = client.post("/api/scenarios", headers=ha, json={
        "environment_id": env, "name": "s",
        "cells": [{"key": "blue_cell", "name": "Blue", "kind": "participant"},
                  {"key": "red_cell", "name": "Red", "kind": "participant"},
                  {"key": "white_cell", "name": "White", "kind": "control"}],
        "injects": [{"code": "INJ-01", "title": "Invoice overdue", "narrative": "Please see attached.", "is_start": True,
                     "channel": "email", "visible_to": ["blue_cell"], "expected_actions": ["Report it"]}]}).json()["id"]
    sid = client.post("/api/sessions", headers=ha, json={"scenario_id": scn, "name": "run"}).json()["id"]
    return sid


class FakeSMTP:
    sent = []
    def __init__(self, host, port, timeout=None): self.host = host; self.port = port
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def starttls(self): FakeSMTP.sent.append(("starttls",))
    def login(self, u, p): FakeSMTP.sent.append(("login", u))
    def send_message(self, msg): FakeSMTP.sent.append(("send", msg["To"], msg["Subject"], msg.get_content()))


@pytest.fixture
def senders(monkeypatch):
    FakeSMTP.sent = []
    posts = []
    monkeypatch.setattr(delivery.smtplib, "SMTP", FakeSMTP)
    class R:  # noqa: D401
        status_code = 200
    import httpx
    monkeypatch.setattr(httpx, "post", lambda url, json=None, timeout=None: posts.append((url, json)) or R())
    monkeypatch.setenv("GAUNTLET_SMTP_HOST", "smtp.example.test"); monkeypatch.setenv("GAUNTLET_SMTP_USER", "u")
    monkeypatch.setenv("GAUNTLET_SMTP_PASSWORD", "p"); monkeypatch.setenv("GAUNTLET_SMTP_FROM", "excon@example.test")
    monkeypatch.setenv("GAUNTLET_SLACK_WEBHOOK", "https://hooks.slack.test/abc")
    monkeypatch.setenv("GAUNTLET_TEAMS_WEBHOOK", "https://teams.test/hook")
    monkeypatch.delenv("GAUNTLET_NOTIFY_WEBHOOK", raising=False)
    return posts


def test_channels_reflect_configuration(senders):
    with TestClient(app) as c:
        o, t = _org(c); h = _h(t)
        ch = c.get("/api/delivery/channels", headers=h).json()["channels"]
        assert ch == {"email": True, "slack": True, "teams": True, "webhook": False}


def test_inject_goes_to_the_addressed_cell_and_the_channel(senders):
    posts = senders
    with TestClient(app) as c:
        o, admin = _org(c); ha = _h(admin)
        sid = _world(c, ha)
        code = c.post(f"/api/sessions/{sid}/join-code", headers=ha).json()["join_code"]
        blue_em, blue = _user(c, ha, o, "participant", "b"); red_em, red = _user(c, ha, o, "participant", "r")
        c.post("/api/join", headers=_h(blue), json={"code": code, "cell": "blue_cell"})
        c.post("/api/join", headers=_h(red), json={"code": code, "cell": "red_cell"})
        assert c.post(f"/api/sessions/{sid}/deliver", headers=ha, json={"channels": ["email"]}).status_code == 409  # not started
        c.post(f"/api/sessions/{sid}/start", headers=ha)
        r = c.post(f"/api/sessions/{sid}/deliver", headers=ha, json={
            "channels": ["email", "slack", "teams", "bogus"], "cells": ["blue_cell", "red_cell"],
            "extra_emails": ["Board.Member@Ex.com", "not-an-email"]})
        assert r.status_code == 200, r.text
        out = r.json()
        # the red cell is not addressed by this inject, so only blue + the extra address
        assert out["cells"] == ["blue_cell"] and out["recipients"] == 2 and out["delivered"] is True
        assert out["channels"]["email"] == {"ok": True, "error": "", "recipients": 2}
        assert out["channels"]["slack"]["ok"] and out["channels"]["teams"]["ok"] and "bogus" not in out["channels"]
        send = [x for x in FakeSMTP.sent if x[0] == "send"][0]
        assert blue_em in send[1] and "board.member@ex.com" in send[1] and red_em not in send[1]
        assert send[2] == "[Exercise] Invoice overdue" and "/participant.html?session=" in send[3] and "simulated" in send[3]
        assert ("login", "u") in FakeSMTP.sent and ("starttls",) in FakeSMTP.sent
        assert posts[0][0].startswith("https://hooks.slack.test") and posts[0][1]["text"].startswith("*[Exercise]")
        assert posts[1][1]["@type"] == "MessageCard"
        # recorded for the control cell only
        state = c.get(f"/api/sessions/{sid}", headers=ha).json()
        ev = [e for e in state["timeline"] if e["kind"] == "delivery"]
        assert len(ev) == 1 and ev[0]["payload"]["recipients"] == 2
        assert not any(e["kind"] == "delivery" for e in c.get(f"/api/sessions/{sid}/cell/blue_cell", headers=_h(blue)).json()["timeline"])
        assert c.get(f"/api/sessions/{sid}/verify", headers=ha).json()["chain_valid"] is True
        tech = c.post(f"/api/sessions/{sid}/reports", headers=ha, json={"audience": "technical"}).json()["content"]
        assert "Delivered INJ-01 via email, slack, teams to 2 recipient(s)" in tech
        # roles
        _, ev_tok = _user(c, ha, o, "evaluator")
        assert c.post(f"/api/sessions/{sid}/deliver", headers=_h(ev_tok), json={"channels": ["slack"]}).status_code == 403
        assert c.post(f"/api/sessions/{sid}/deliver", headers=ha, json={"channels": []}).status_code == 422


def test_invites_carry_the_join_code(senders):
    with TestClient(app) as c:
        o, admin = _org(c); ha = _h(admin)
        sid = _world(c, ha)
        assert c.post(f"/api/sessions/{sid}/invite", headers=ha, json={"emails": ["x@ex.com"]}).status_code == 409  # no code
        code = c.post(f"/api/sessions/{sid}/join-code", headers=ha).json()["join_code"]
        r = c.post(f"/api/sessions/{sid}/invite", headers=ha, json={"emails": ["x@ex.com", "y@ex.com"], "channels": ["email", "slack"], "message": "Bring coffee."})
        assert r.status_code == 200 and r.json()["recipients"] == 2 and r.json()["delivered"]
        send = [x for x in FakeSMTP.sent if x[0] == "send"][-1]
        assert code in send[3] and "/join.html" in send[3] and "Bring coffee." in send[3]


def test_air_gap_refuses_and_records(monkeypatch):
    import app.config as config
    monkeypatch.setattr(config, "AIRGAPPED", True)
    monkeypatch.setenv("GAUNTLET_SMTP_HOST", "smtp.example.test"); monkeypatch.setenv("GAUNTLET_SLACK_WEBHOOK", "https://hooks.slack.test/abc")
    calls = []
    monkeypatch.setattr(delivery.smtplib, "SMTP", lambda *a, **k: calls.append(a))
    with TestClient(app) as c:
        o, admin = _org(c); ha = _h(admin)
        sid = _world(c, ha)
        c.post(f"/api/sessions/{sid}/start", headers=ha)
        out = c.post(f"/api/sessions/{sid}/deliver", headers=ha, json={"channels": ["email", "slack"], "extra_emails": ["a@ex.com"]}).json()
        assert out["delivered"] is False and "air-gapped" in out["channels"]["email"]["error"] and "air-gapped" in out["channels"]["slack"]["error"]
        assert calls == []
        assert c.get("/api/delivery/channels", headers=ha).json()["airgapped"] is True


def test_unconfigured_channel_reports_itself():
    with TestClient(app) as c:
        o, admin = _org(c); ha = _h(admin)
        sid = _world(c, ha)
        c.post(f"/api/sessions/{sid}/start", headers=ha)
        out = c.post(f"/api/sessions/{sid}/deliver", headers=ha, json={"channels": ["teams"]}).json()
        assert out["delivered"] is False and "not configured" in out["channels"]["teams"]["error"]
