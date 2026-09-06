"""G — email confirmation on free sign-up: when the deployment can send mail,
a self-registered account gets a link instead of tokens, cannot sign in until
it follows the link, and the link works once. Accounts created any other way
(admin, class code, SCIM, seed) are confirmed on creation."""
import re
import uuid

import pytest
from fastapi.testclient import TestClient

from app import delivery
from app.main import app

PW = "Str0ngPass!9"


def _h(t):
    return {"Authorization": f"Bearer {t}"}


class FakeSMTP:
    sent = []
    def __init__(self, host, port, timeout=None): self.host = host
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def starttls(self): pass
    def login(self, u, p): pass
    def send_message(self, msg): FakeSMTP.sent.append((msg["To"], msg["Subject"], msg.get_content()))


@pytest.fixture
def mail(monkeypatch):
    FakeSMTP.sent = []
    monkeypatch.setattr(delivery.smtplib, "SMTP", FakeSMTP)
    monkeypatch.setenv("GAUNTLET_SMTP_HOST", "smtp.example.test")
    monkeypatch.setenv("GAUNTLET_SMTP_FROM", "noreply@example.test")
    monkeypatch.delenv("GAUNTLET_SIGNUP_CONFIRM", raising=False)
    from app import config
    monkeypatch.setattr(config, "SIGNUP_CONFIRM", "auto")
    from app.throttle import throttle
    with throttle._lock:
        for store in (throttle._fails, throttle._locked_until):
            for k in [k for k in store if k.startswith("confirm|")]:
                store.pop(k, None)
    yield


def _token_from(text):
    m = re.search(r"solo\.html\?confirm=([A-Za-z0-9._-]+)", text)
    assert m, text
    return m.group(1)


def test_signup_needs_the_link_when_mail_is_configured(mail):
    with TestClient(app) as c:
        o = uuid.uuid4().hex[:8]
        email = f"learner{o}@ex.com"
        r = c.post("/api/auth/register", json={"org_name": f"L{o}", "email": email.upper(), "password": PW, "name": "Ada"})
        assert r.status_code == 202, r.text
        assert r.json()["confirmation_required"] is True and r.json()["email"] == email and "access_token" not in r.json()
        assert len(FakeSMTP.sent) == 1 and FakeSMTP.sent[0][0] == email and "Confirm" in FakeSMTP.sent[0][1]
        body = FakeSMTP.sent[0][2]
        assert "http://testserver/solo.html?confirm=" in body and "Hello Ada" in body and "only once" in body
        # the right password is not enough until the link is followed
        r = c.post("/api/auth/login", json={"email": email, "password": PW})
        assert r.status_code == 403 and "confirm your email" in r.json()["detail"]
        assert c.post("/api/auth/login", json={"email": email, "password": "wrong"}).status_code == 401
        # a bad link is refused; the real one signs the person in, once
        assert c.post("/api/auth/confirm", json={"token": "nope"}).status_code == 400
        tok = _token_from(body)
        r = c.post("/api/auth/confirm", json={"token": tok})
        assert r.status_code == 200 and r.json()["user"]["email"] == email
        me = c.get("/api/auth/me", headers=_h(r.json()["access_token"])).json()
        assert me["role"] == "admin"
        assert c.post("/api/auth/confirm", json={"token": tok}).status_code == 409
        assert c.post("/api/auth/login", json={"email": email, "password": PW}).status_code == 200
        # a confirmed learner gets the bundled library like anyone else
        cat = c.get("/api/solo/scenarios", headers=_h(r.json()["access_token"])).json()
        assert len(cat["scenarios"]) == 3


def test_resend_is_quiet_and_throttled(mail):
    with TestClient(app) as c:
        o = uuid.uuid4().hex[:8]
        email = f"again{o}@ex.com"
        assert c.post("/api/auth/register", json={"org_name": f"L{o}", "email": email, "password": PW}).status_code == 202
        assert c.post("/api/auth/confirm/resend", json={"email": email}).status_code == 204
        assert len(FakeSMTP.sent) == 2
        # an unknown address gets the same answer and no mail
        assert c.post("/api/auth/confirm/resend", json={"email": f"nobody{o}@ex.com"}).status_code == 204
        assert len(FakeSMTP.sent) == 2
        # the second link still works, then the address is confirmed and resend sends nothing more
        tok = _token_from(FakeSMTP.sent[1][2])
        assert c.post("/api/auth/confirm", json={"token": tok}).status_code == 200
        assert c.post("/api/auth/confirm/resend", json={"email": email}).status_code in (204, 429)
        assert len(FakeSMTP.sent) == 2
        # per-source throttle: three asks in a window, then 429
        c.post("/api/auth/confirm/resend", json={"email": f"x{o}@ex.com"})
        r = None
        for i in range(4):
            r = c.post("/api/auth/confirm/resend", json={"email": f"y{i}{o}@ex.com"})
        assert r.status_code == 429


def test_failed_send_creates_no_account(mail, monkeypatch):
    def boom(host, port, timeout=None):
        raise OSError("connection refused")
    monkeypatch.setattr(delivery.smtplib, "SMTP", boom)
    with TestClient(app) as c:
        o = uuid.uuid4().hex[:8]
        email = f"lost{o}@ex.com"
        r = c.post("/api/auth/register", json={"org_name": f"L{o}", "email": email, "password": PW})
        assert r.status_code == 502
        # nothing was kept: the same address registers again once mail works
        monkeypatch.setattr(delivery.smtplib, "SMTP", FakeSMTP)
        assert c.post("/api/auth/register", json={"org_name": f"L{o}", "email": email, "password": PW}).status_code == 202


def test_other_creation_paths_are_confirmed_and_the_switch_works(mail, monkeypatch):
    with TestClient(app) as c:
        o = uuid.uuid4().hex[:8]
        # forced off: tokens straight away even with mail configured
        from app import config
        monkeypatch.setattr(config, "SIGNUP_CONFIRM", "0")
        r = c.post("/api/auth/register", json={"org_name": f"O{o}", "email": f"a{o}@ex.com", "password": PW})
        assert r.status_code == 201
        ha = _h(r.json()["access_token"])
        monkeypatch.setattr(config, "SIGNUP_CONFIRM", "auto")
        # an admin-created member signs in without any link
        em = f"f{o}@ex.com"
        assert c.post("/api/auth/users", headers=ha, json={"email": em, "password": PW, "role": "facilitator"}).status_code == 201
        assert c.post("/api/auth/login", json={"email": em, "password": PW}).status_code == 200
        assert FakeSMTP.sent == []
        # a malformed address is refused before anything is created
        assert c.post("/api/auth/register", json={"org_name": "x", "email": "not-an-address", "password": PW}).status_code == 422


def test_without_mail_registration_is_unchanged():
    with TestClient(app) as c:
        o = uuid.uuid4().hex[:8]
        r = c.post("/api/auth/register", json={"org_name": f"O{o}", "email": f"a{o}@ex.com", "password": PW})
        assert r.status_code == 201 and r.json()["access_token"]
