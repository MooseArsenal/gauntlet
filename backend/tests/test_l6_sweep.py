"""L6 — the low-severity sweep: strict token type (S-10), no-store + register
throttle (S-11), startup guards (S-12, U-5), pagination (F-6), unknown-asset
flag (F-7), demo flag on health (U-5)."""
import time
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from fastapi.testclient import TestClient

from app import config
from app.keys import jwt_key
from app.main import app

PW = "Str0ngPass!9"


def _h(t):
    return {"Authorization": f"Bearer {t}"}


def _org(c):
    o = uuid.uuid4().hex[:8]
    r = c.post("/api/auth/register", json={"org_name": f"O{o}", "email": f"a{o}@ex.com", "password": PW})
    return o, r.json()


def test_token_without_a_type_claim_is_refused():
    with TestClient(app) as c:
        o, reg = _org(c)
        uid = reg["user"]["id"]
        now = datetime.now(timezone.utc)
        untyped = jwt.encode({"sub": str(uid), "iat": now, "exp": now + timedelta(minutes=5)}, jwt_key(), algorithm="HS256")
        assert c.get("/api/auth/me", headers=_h(untyped)).status_code == 401
        assert c.get("/api/auth/me", headers=_h(reg["access_token"])).status_code == 200


def test_api_responses_are_never_cached_and_pages_still_are():
    with TestClient(app) as c:
        o, reg = _org(c)
        assert c.get("/api/auth/me", headers=_h(reg["access_token"])).headers["cache-control"] == "no-store"
        assert "no-store" not in c.get("/index.html").headers.get("cache-control", "")


def test_registration_is_throttled_per_address():
    with TestClient(app) as c:
        codes = []
        for i in range(config.REGISTER_MAX_PER_WINDOW + 2):
            o = uuid.uuid4().hex[:8]
            codes.append(c.post("/api/auth/register", json={"org_name": o, "email": f"r{o}@ex.com", "password": PW}).status_code)
        assert 429 in codes and codes[0] == 201


def test_startup_guards_name_multi_worker_and_seeded_prod(monkeypatch):
    monkeypatch.setattr(config, "IS_PROD", True)
    monkeypatch.setattr(config, "SECRET_IS_DEFAULT", False)
    monkeypatch.setattr(config, "SECRET_KEY", "x" * 40)
    monkeypatch.setattr(config, "CORS_ORIGINS", [])
    monkeypatch.setattr(config, "AUTH_OPTIONAL", False)
    monkeypatch.setattr(config, "SEED_ON_START", True)
    monkeypatch.delenv("GAUNTLET_DEMO_PASSWORD", raising=False)
    monkeypatch.setattr(config, "WORKERS", 4)
    problems = "\n".join(config.startup_problems())
    assert "demo admin" in problems and "workers" in problems
    monkeypatch.setattr(config, "WORKERS", 1)
    monkeypatch.setattr(config, "SEED_ON_START", False)
    assert config.startup_problems() == []


def test_lists_paginate():
    with TestClient(app) as c:
        o, reg = _org(c); h = _h(reg["access_token"])
        env = c.post("/api/environments", headers=h, json={"name": "e"}).json()["id"]
        for i in range(4):
            c.post("/api/scenarios", headers=h, json={"environment_id": env, "name": f"s{i}",
                                                       "injects": [{"code": "A", "title": "a", "is_start": True}]})
        assert len(c.get("/api/scenarios?limit=2", headers=h).json()) == 2
        page2 = c.get("/api/scenarios?limit=2&offset=2", headers=h).json()
        assert [s["name"] for s in page2] == ["s2", "s3"]
        c.post("/api/auth/users", headers=h, json={"email": f"x{o}@ex.com", "password": PW, "role": "evaluator"})
        assert len(c.get("/api/audit?limit=1&offset=1", headers=h).json()) == 1


def test_unknown_target_asset_is_flagged_in_the_ruling():
    with TestClient(app) as c:
        o, reg = _org(c); h = _h(reg["access_token"])
        env = c.post("/api/environments", headers=h, json={
            "name": "e", "assets": [{"code": "SRV-01", "name": "s"}],
            "detections": [{"name": "EDR", "covers": ["*"], "assets": ["*"], "efficacy": 1.0}]}).json()["id"]
        scn = c.post("/api/scenarios", headers=h, json={"environment_id": env, "name": "s",
                                                         "injects": [{"code": "A", "title": "a", "is_start": True}]}).json()["id"]
        sid = c.post("/api/sessions", headers=h, json={"scenario_id": scn, "name": "r"}).json()["id"]
        c.post(f"/api/sessions/{sid}/start", headers=h)
        good = c.post(f"/api/sessions/{sid}/adjudicate", headers=h, json={"techniques": ["T1003"], "target_asset": "SRV-01"}).json()["ruling"]
        typo = c.post(f"/api/sessions/{sid}/adjudicate", headers=h, json={"techniques": ["T1003"], "target_asset": "SRV-O1"}).json()["ruling"]
        assert good["asset_known"] is True and typo["asset_known"] is False
        assert "not an asset" in typo["rationale"]


def test_health_reports_whether_the_demo_account_exists():
    with TestClient(app) as c:
        h = c.get("/api/health").json()
        assert "demo" in h and h["demo"] is (config.SEED_ON_START and not config.IS_PROD)
