"""M4 — MFA challenge throttle and single use (S-4), per-account lockout (S-5),
signed chain head (S-6), streaming body cap (S-7), verified-email SSO linking
(S-8), scenario validation on JSON create (F-3), bounded inputs (F-4), and
timer re-arm after restart (F-5)."""
import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import models, scheduler, security
from app.api import auth as auth_api
from app.database import SessionLocal
from app.main import app

PW = "Str0ngPass!9"


def _h(t):
    return {"Authorization": f"Bearer {t}"}


def _org(c):
    o = uuid.uuid4().hex[:8]
    r = c.post("/api/auth/register", json={"org_name": f"O{o}", "email": f"a{o}@ex.com", "password": PW})
    return o, f"a{o}@ex.com", r.json()["access_token"]


def _now_code(secret):
    return security._totp_at(secret, int(time.time() // 30))


def _world(c, h, injects=None):
    env = c.post("/api/environments", headers=h, json={"name": "e", "assets": [{"code": "SRV-01", "name": "s"}]}).json()["id"]
    scn = c.post("/api/scenarios", headers=h, json={"environment_id": env, "name": "s", "injects": injects or [
        {"code": "INJ-01", "title": "a", "is_start": True,
         "branches": [{"when": "proctor_choice", "goto": "INJ-02"}]},
        {"code": "INJ-02", "title": "b"}]})
    return env, scn


# ---------------------------------------------------------------- S-4
def test_mfa_challenge_is_single_use_and_throttled():
    with TestClient(app) as c:
        o, email, t = _org(c); h = _h(t)
        sec = c.post("/api/auth/mfa/setup", headers=h).json()["secret"]
        c.post("/api/auth/mfa/enable", headers=h, json={"code": _now_code(sec)})
        ch = c.post("/api/auth/login", json={"email": email, "password": PW}).json()["challenge"]
        assert c.post("/api/auth/login/mfa", json={"challenge": ch, "code": _now_code(sec)}).status_code == 200
        # used once → dead, even with the right code
        assert c.post("/api/auth/login/mfa", json={"challenge": ch, "code": _now_code(sec)}).status_code == 401
        # guessing: after the limit the account's second factor locks and the challenge is spent
        ch = c.post("/api/auth/login", json={"email": email, "password": PW}).json()["challenge"]
        codes = [c.post("/api/auth/login/mfa", json={"challenge": ch, "code": f"{i:06d}"}).status_code for i in range(8)]
        assert codes[:4] == [401] * 4
        # the challenge is spent at the lock, so even the right code is refused …
        assert c.post("/api/auth/login/mfa", json={"challenge": ch, "code": _now_code(sec)}).status_code == 401
        # … and a fresh challenge (password still correct) reports the lockout
        ch = c.post("/api/auth/login", json={"email": email, "password": PW}).json()["challenge"]
        assert c.post("/api/auth/login/mfa", json={"challenge": ch, "code": _now_code(sec)}).status_code == 429


# ---------------------------------------------------------------- S-5
def test_password_spray_from_rotating_addresses_locks_the_account(monkeypatch):
    ips = iter(f"10.0.{i // 250}.{i % 250}" for i in range(10_000))
    monkeypatch.setattr(auth_api, "client_ip", lambda request: next(ips))
    with TestClient(app) as c:
        o, email, t = _org(c)
        statuses = [c.post("/api/auth/login", json={"email": email, "password": "wrong"}).status_code
                    for _ in range(25)]
        assert statuses[:5] == [401] * 5          # per-address limit never trips (new IP each time)
        assert 429 in statuses                    # …but the per-account limit does
        assert c.post("/api/auth/login", json={"email": email, "password": PW}).status_code == 429


# ---------------------------------------------------------------- S-6
def test_truncated_or_edited_chain_no_longer_verifies():
    with TestClient(app) as c:
        o, email, t = _org(c); h = _h(t)
        env, scn = _world(c, h)
        sid = c.post("/api/sessions", headers=h, json={"scenario_id": scn.json()["id"], "name": "r"}).json()["id"]
        c.post(f"/api/sessions/{sid}/start", headers=h)
        for _ in range(3):
            c.post(f"/api/sessions/{sid}/note", headers=h, json={"text": "evidence"})
        v = c.get(f"/api/sessions/{sid}/verify", headers=h).json()
        assert v["chain_valid"] is True and v["head"]["signed"] is True and v["head"]["seq"] == v["events"]
        db = SessionLocal()
        evs = db.execute(select(models.TimelineEvent).where(models.TimelineEvent.session_id == sid)
                         .order_by(models.TimelineEvent.seq)).scalars().all()
        db.delete(evs[-1]); db.commit(); db.close()
        assert c.get(f"/api/sessions/{sid}/verify", headers=h).json()["chain_valid"] is False
        # a session that predates the head verifies on the chain alone
        db = SessionLocal(); s = db.get(models.Session, sid); s.head_seq = s.head_hash = s.head_sig = None; db.commit(); db.close()
        assert c.get(f"/api/sessions/{sid}/verify", headers=h).json()["chain_valid"] is True
        # …but a gap in the sequence still fails
        db = SessionLocal()
        evs = db.execute(select(models.TimelineEvent).where(models.TimelineEvent.session_id == sid)
                         .order_by(models.TimelineEvent.seq)).scalars().all()
        db.delete(evs[1]); db.commit(); db.close()
        assert c.get(f"/api/sessions/{sid}/verify", headers=h).json()["chain_valid"] is False


# ---------------------------------------------------------------- S-7
def test_chunked_body_is_capped_too():
    from app import config
    big = b'{"email":"' + b"a" * (config.MAX_REQUEST_BYTES + 10) + b'","password":"x"}'
    with TestClient(app) as c:
        assert c.post("/api/auth/login", content=big, headers={"Content-Type": "application/json"}).status_code == 413

        def gen():
            for i in range(0, len(big), 65536):
                yield big[i:i + 65536]
        assert c.post("/api/auth/login", content=gen(), headers={"Content-Type": "application/json"}).status_code == 413


# ---------------------------------------------------------------- S-8
def test_sso_links_by_email_only_when_the_provider_verified_it():
    with TestClient(app) as c:
        o, email, t = _org(c)
        db = SessionLocal()
        with pytest.raises(Exception) as ex:
            auth_api._sso_user(db, {"sub": "idp-1", "email": email, "email_verified": False})
        assert getattr(ex.value, "status_code", None) == 403
        u = auth_api._sso_user(db, {"sub": "idp-1", "email": email, "email_verified": True})
        assert u.email == email and u.oidc_subject == "idp-1"
        db.commit()  # the callback commits after linking
        # once linked, the subject alone identifies the account
        assert auth_api._sso_user(db, {"sub": "idp-1"}).id == u.id
        db.close()


# ---------------------------------------------------------------- F-3
def test_json_created_scenarios_are_validated():
    with TestClient(app) as c:
        o, email, t = _org(c); h = _h(t)
        env = c.post("/api/environments", headers=h, json={"name": "e"}).json()["id"]
        def make(injects):
            return c.post("/api/scenarios", headers=h, json={"environment_id": env, "name": "x", "injects": injects})
        assert make([{"code": "A", "title": "a", "is_start": True, "branches": [{"when": "proctor_choice", "goto": "GHOST"}]}]).status_code == 422
        assert make([{"code": "A", "title": "a", "is_start": True}, {"code": "A", "title": "b"}]).status_code == 422
        assert make([{"code": "A", "title": "a", "is_start": True}, {"code": "B", "title": "b", "is_start": True}]).status_code == 422
        assert make([{"code": "A", "title": "a", "is_start": True, "branches": [{"when": "proctor_choice", "goto": "A"}]}]).status_code == 422
        assert make([{"code": "A", "title": "a", "is_start": True}]).status_code == 201
        assert make([]).status_code == 201  # an inject-less draft for the editor


# ---------------------------------------------------------------- F-4
def test_free_text_inputs_are_bounded():
    with TestClient(app) as c:
        o, email, t = _org(c); h = _h(t)
        env = c.post("/api/environments", headers=h, json={"name": "e"}).json()["id"]
        assert c.post("/api/scenarios", headers=h, json={"environment_id": env, "name": "N" * 100_000,
                                                          "injects": [{"code": "A", "title": "a", "is_start": True}]}).status_code == 422
        scn = c.post("/api/scenarios", headers=h, json={"environment_id": env, "name": "ok",
                                                         "injects": [{"code": "A", "title": "a", "is_start": True}]}).json()["id"]
        sid = c.post("/api/sessions", headers=h, json={"scenario_id": scn, "name": "r"}).json()["id"]
        c.post(f"/api/sessions/{sid}/start", headers=h)
        assert c.post(f"/api/sessions/{sid}/observe", headers=h, json={"note": "n" * 100_000}).status_code == 422
        assert c.post(f"/api/sessions/{sid}/adjudicate", headers=h,
                      json={"techniques": ["T1003"] * 501, "target_asset": "x"}).status_code == 422


# ---------------------------------------------------------------- F-5
def test_overdue_timers_are_rearmed_on_startup():
    with TestClient(app) as c:
        o, email, t = _org(c); h = _h(t)
        env, scn = _world(c, h, injects=[
            {"code": "INJ-01", "title": "a", "is_start": True,
             "branches": [{"when": "timeout", "after": "PT1M", "goto": "INJ-02"}]},
            {"code": "INJ-02", "title": "b"}])
        sid = c.post("/api/sessions", headers=h, json={"scenario_id": scn.json()["id"], "name": "rt", "auto_advance": True}).json()["id"]
        c.post(f"/api/sessions/{sid}/start", headers=h)
        db = SessionLocal(); s = db.get(models.Session, sid)
        assert s.due_at is not None                      # persisted when armed
        scheduler.cancel(sid)                            # simulate the process dying
        s.due_at = datetime.now(timezone.utc) - timedelta(seconds=5)
        db.commit(); db.close()
        assert scheduler.rearm_all() >= 1   # other suites may leave timed sessions behind
        time.sleep(1.6)
        assert c.get(f"/api/sessions/{sid}", headers=h).json()["session"]["current_inject_code"] == "INJ-02"
