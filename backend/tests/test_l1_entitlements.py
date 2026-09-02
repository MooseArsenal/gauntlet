"""L1 — licences: signed offline, tiers and features, grace then degrade,
seat limits, admin install, and 402 on gated features in Community."""
import uuid
from datetime import date, timedelta

import pytest
from fastapi.testclient import TestClient

from app import entitlements
from app.database import SessionLocal
from app.main import app
from tests.conftest import TEST_PRIV

PW = "Str0ngPass!9"


def _h(t):
    return {"Authorization": f"Bearer {t}"}


def _org(client):
    o = uuid.uuid4().hex[:8]
    t = client.post("/api/auth/register", json={
        "org_name": f"O{o}", "email": f"a{o}@ex.com", "password": PW}).json()["access_token"]
    return o, t


@pytest.fixture
def community(monkeypatch):
    """Run as an unlicensed deployment for one test."""
    monkeypatch.delenv("GAUNTLET_LICENSE", raising=False)
    db = SessionLocal()
    try:
        entitlements.store_token(db, None); db.commit()
    finally:
        db.close()
    yield
    db = SessionLocal()
    try:
        entitlements.store_token(db, None); db.commit()
    finally:
        db.close()


def test_issue_parse_and_tiers():
    tok = entitlements.issue(TEST_PRIV, tier="team", customer="Acme", exp="2999-01-01", features=["replay", "bogus"], seats={"facilitators": 3})
    p = entitlements.parse(tok)
    assert p["tier"] == "team" and p["customer"] == "Acme" and p["seats"] == {"facilitators": 3}
    with pytest.raises(entitlements.LicenseError):
        entitlements.parse(tok[:-4] + "AAAA")
    with pytest.raises(entitlements.LicenseError):
        entitlements.parse("GL1.abc.def")
    other_priv, _ = entitlements.keygen()
    with pytest.raises(entitlements.LicenseError):
        entitlements.parse(entitlements.issue(other_priv, tier="team", customer="x", exp="2999-01-01"))
    assert "scim" in entitlements.TIER_FEATURES["enterprise"] and "scim" not in entitlements.TIER_FEATURES["team"]
    assert "education" in entitlements.TIER_FEATURES["education"]


def test_status_grace_and_degrade(monkeypatch):
    today = date(2026, 9, 2)
    with TestClient(app):
        pass  # schema is created by the app lifespan
    db = SessionLocal()
    try:
        monkeypatch.setenv("GAUNTLET_LICENSE", entitlements.issue(TEST_PRIV, tier="team", customer="Acme", exp="2026-09-10", features=["replay"]))
        st = entitlements.status(db, today)
        assert st["state"] == "active" and st["tier"] == "team" and "replay" in st["features"] and st["days_left"] == 8
        st = entitlements.status(db, date(2026, 9, 20))
        assert st["state"] == "grace" and st["licensed"] and "white_label" in st["features"]
        st = entitlements.status(db, date(2026, 11, 1))
        assert st["state"] == "expired" and st["tier"] == "community" and st["features"] == []
        monkeypatch.setenv("GAUNTLET_LICENSE", "GL1.garbage.garbage")
        st = entitlements.status(db, today)
        assert st["state"] == "invalid" and st["tier"] == "community" and st["error"]
    finally:
        db.close()


def test_admin_install_and_remove_and_visibility():
    with TestClient(app) as c:
        o, admin = _org(c); ha = _h(admin)
        st = c.get("/api/license", headers=ha).json()
        assert st["tier"] == "enterprise" and st["licensed"] and "labels" in st
        em = f"f{o}@ex.com"
        c.post("/api/auth/users", headers=ha, json={"email": em, "password": PW, "role": "facilitator"})
        tf = c.post("/api/auth/login", json={"email": em, "password": PW}).json()["access_token"]
        assert c.get("/api/license", headers=_h(tf)).status_code == 200
        assert c.post("/api/admin/license", headers=_h(tf), json={"token": "x"}).status_code == 403
        assert c.post("/api/admin/license", headers=ha, json={"token": "GL1.nope.nope"}).status_code == 422
        tok = entitlements.issue(TEST_PRIV, tier="team", customer="Acme", exp="2999-06-30")
        st = c.post("/api/admin/license", headers=ha, json={"token": tok}).json()
        assert st["tier"] == "team" and st["customer"] == "Acme"
        assert c.get("/api/license", headers=ha).json()["tier"] == "team"  # stored token wins over the env
        assert c.delete("/api/admin/license", headers=ha).status_code == 204
        assert c.get("/api/license", headers=ha).json()["tier"] == "enterprise"  # back to the env licence
        actions = {a["action"] for a in c.get("/api/audit", headers=ha).json()}
        assert {"license.install", "license.remove"} <= actions


def test_community_gates_paid_features_and_keeps_data(community):
    with TestClient(app) as c:
        o, admin = _org(c); ha = _h(admin)
        st = c.get("/api/license", headers=ha).json()
        assert st["tier"] == "community" and st["licensed"] is False
        # SCIM, cohort opt-in and the telemetry loop close with a plain message
        tok = c.post("/api/admin/scim-token", headers=ha).json()["token"]
        r = c.get("/scim/v2/Users", headers=_h(tok))
        assert r.status_code == 402 and "licence" in r.json()["detail"]
        r = c.post("/api/analytics/benchmark/opt-in", headers=ha, json={"opt_in": True})
        assert r.status_code == 402 and "community" in r.json()["detail"]
        env = c.post("/api/environments", headers=ha, json={"name": "e", "assets": [{"code": "A", "name": "a"}]}).json()["id"]
        scn = c.post("/api/scenarios", headers=ha, json={"environment_id": env, "name": "s",
                                                         "injects": [{"code": "INJ-01", "title": "t", "narrative": "n", "is_start": True}]}).json()["id"]
        sid = c.post("/api/sessions", headers=ha, json={"scenario_id": scn, "name": "r"}).json()["id"]
        c.post(f"/api/sessions/{sid}/start", headers=ha)
        assert c.post(f"/api/sessions/{sid}/telemetry", headers=ha, json={"alert": "x"}).status_code == 402
        # the engine, the record, reports, the certificate and the benchmark reference stay open
        assert c.post(f"/api/sessions/{sid}/adjudicate", headers=ha, json={"techniques": ["T1003"], "target_asset": "A", "description": "m"}).status_code == 200
        assert c.get("/api/analytics/benchmark", headers=ha).status_code == 200
        assert c.get(f"/api/sessions/{sid}/telemetry/compare", headers=ha).status_code == 200
        c.post(f"/api/sessions/{sid}/complete", headers=ha)
        assert c.post(f"/api/sessions/{sid}/certificate", headers=ha).status_code == 201
        assert c.post(f"/api/sessions/{sid}/reports", headers=ha, json={"audience": "executive"}).status_code == 201


def test_seat_limits(monkeypatch):
    monkeypatch.setenv("GAUNTLET_LICENSE", entitlements.issue(TEST_PRIV, tier="team", customer="Acme", exp="2999-01-01", seats={"facilitators": 2}))
    with TestClient(app) as c:
        o, admin = _org(c); ha = _h(admin)  # the admin is seat 1
        assert c.post("/api/auth/users", headers=ha, json={"email": f"f1{o}@ex.com", "password": PW, "role": "facilitator"}).status_code == 201
        r = c.post("/api/auth/users", headers=ha, json={"email": f"f2{o}@ex.com", "password": PW, "role": "facilitator"})
        assert r.status_code == 402 and "2 facilitator seat" in r.json()["detail"]
        # participants and evaluators are not seats
        assert c.post("/api/auth/users", headers=ha, json={"email": f"p{o}@ex.com", "password": PW, "role": "participant"}).status_code == 201
        r2 = c.post("/api/auth/users", headers=ha, json={"email": f"e{o}@ex.com", "password": PW, "role": "evaluator"})
        assert r2.status_code == 201
        # promoting into a seat is refused too
        members = c.get("/api/members", headers=ha).json()
        ev = next(m for m in members if m["email"].startswith("e"))
        assert c.patch(f"/api/members/{ev['id']}", headers=ha, json={"role": "facilitator"}).status_code == 402
