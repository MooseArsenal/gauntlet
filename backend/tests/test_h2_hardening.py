"""H2 — MFA re-enrolment, the session state machine, erasure completeness,
and parent/sub-technique matching (S-2, F-1, S-3, F-2)."""
import time
import uuid
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy import select

from app import models, security
from app.database import SessionLocal
from app.engine import technique
from app.main import app

PW = "Str0ngPass!9"


def _h(t):
    return {"Authorization": f"Bearer {t}"}


def _org(c):
    o = uuid.uuid4().hex[:8]
    r = c.post("/api/auth/register", json={"org_name": f"O{o}", "email": f"a{o}@ex.com", "password": PW})
    return o, r.json()["access_token"]


def _now_code(secret):
    return security._totp_at(secret, int(time.time() // 30))


def _world(c, h):
    env = c.post("/api/environments", headers=h, json={
        "name": "e", "assets": [{"code": "SRV-01", "name": "srv"}],
        "detections": [{"name": "EDR", "covers": ["T1003"], "assets": ["*"], "efficacy": 1.0}]}).json()["id"]
    scn = c.post("/api/scenarios", headers=h, json={
        "environment_id": env, "name": "s",
        "injects": [{"code": "INJ-01", "title": "a", "is_start": True,
                     "branches": [{"label": "go", "when": "proctor_choice", "goto": "INJ-02"}]},
                    {"code": "INJ-02", "title": "b"}]}).json()["id"]
    sid = c.post("/api/sessions", headers=h, json={"scenario_id": scn, "name": "run"}).json()["id"]
    return env, scn, sid


# --------------------------------------------------------------------------- #
# S-2
# --------------------------------------------------------------------------- #
def test_mfa_setup_cannot_disable_an_enabled_second_factor():
    with TestClient(app) as c:
        o, t = _org(c); h = _h(t); email = f"a{o}@ex.com"
        old = c.post("/api/auth/mfa/setup", headers=h).json()["secret"]
        assert c.post("/api/auth/mfa/enable", headers=h, json={"code": _now_code(old)}).json()["mfa_enabled"]
        # bearer-only re-setup is refused, and nothing changed
        assert c.post("/api/auth/mfa/setup", headers=h).status_code == 401
        assert c.post("/api/auth/mfa/setup", headers=h, json={"code": "000000"}).status_code == 401
        assert c.get("/api/auth/me", headers=h).json()["mfa_enabled"] is True
        assert c.post("/api/auth/login", json={"email": email, "password": PW}).json()["mfa_required"] is True
        # with a current code a new enrolment may begin — but the old factor keeps working until confirmed
        new = c.post("/api/auth/mfa/setup", headers=h, json={"code": _now_code(old)}).json()["secret"]
        ch = c.post("/api/auth/login", json={"email": email, "password": PW}).json()["challenge"]
        assert c.post("/api/auth/login/mfa", json={"challenge": ch, "code": _now_code(old)}).status_code == 200
        # confirming promotes the new secret and retires the old one
        assert c.post("/api/auth/mfa/enable", headers=h, json={"code": _now_code(new)}).status_code == 200
        ch = c.post("/api/auth/login", json={"email": email, "password": PW}).json()["challenge"]
        assert c.post("/api/auth/login/mfa", json={"challenge": ch, "code": _now_code(old)}).status_code == 401
        assert c.post("/api/auth/login/mfa", json={"challenge": ch, "code": _now_code(new)}).status_code == 200


def test_pending_mfa_secret_is_inert_until_confirmed():
    with TestClient(app) as c:
        o, t = _org(c); h = _h(t)
        c.post("/api/auth/mfa/setup", headers=h)
        assert c.get("/api/auth/me", headers=h).json()["mfa_enabled"] is False
        assert "access_token" in c.post("/api/auth/login", json={"email": f"a{o}@ex.com", "password": PW}).json()


# --------------------------------------------------------------------------- #
# F-1
# --------------------------------------------------------------------------- #
def test_session_state_machine_is_enforced_everywhere():
    with TestClient(app) as c:
        o, t = _org(c); h = _h(t)
        env, scn, sid = _world(c, h)
        rule = {"techniques": ["T1003"], "target_asset": "SRV-01"}
        move = {"techniques": ["T1003"], "target": "SRV-01", "action": "x"}
        writes = {
            "adjudicate": lambda: c.post(f"/api/sessions/{sid}/adjudicate", headers=h, json=rule),
            "observe": lambda: c.post(f"/api/sessions/{sid}/observe", headers=h, json={"note": "n"}),
            "note": lambda: c.post(f"/api/sessions/{sid}/note", headers=h, json={"text": "n"}),
            "red": lambda: c.post(f"/api/sessions/{sid}/red-actions", headers=h, json=move),
            "pause": lambda: c.post(f"/api/sessions/{sid}/pause", headers=h),
            "resume": lambda: c.post(f"/api/sessions/{sid}/resume", headers=h),
            "complete": lambda: c.post(f"/api/sessions/{sid}/complete", headers=h),
            "advance": lambda: c.post(f"/api/sessions/{sid}/advance", headers=h, json={"when": "proctor_choice"}),
        }
        # setup: nothing but start is valid
        for name, call in writes.items():
            assert call().status_code == 409, name
        assert c.post(f"/api/sessions/{sid}/start", headers=h).status_code == 200
        assert c.post(f"/api/sessions/{sid}/start", headers=h).status_code == 409  # no double start
        assert writes["resume"]().status_code == 409
        assert writes["adjudicate"]().status_code == 200
        # paused: rulings and notes still land; advance and pause do not
        assert writes["pause"]().status_code == 200
        assert writes["pause"]().status_code == 409
        assert writes["adjudicate"]().status_code == 200
        assert writes["observe"]().status_code == 201
        assert writes["advance"]().status_code == 409
        assert writes["resume"]().status_code == 200
        assert writes["complete"]().status_code == 200
        # complete: the record is sealed
        n = len(c.get(f"/api/sessions/{sid}", headers=h).json()["timeline"])
        for name, call in writes.items():
            assert call().status_code == 409, name
        assert c.post(f"/api/sessions/{sid}/start", headers=h).status_code == 409
        assert len(c.get(f"/api/sessions/{sid}", headers=h).json()["timeline"]) == n


# --------------------------------------------------------------------------- #
# S-3
# --------------------------------------------------------------------------- #
TENANT_TABLES = {
    "users", "refresh_tokens", "audit_logs", "environments", "scenarios", "sessions",
    "timeline_events", "observations", "reports", "improvement_items",
    "exercise_schedules", "custom_adversaries", "session_joins", "certificates", "attachments",
}


def _seed_everything(c, h, org_id, scn, sid):
    code = c.post(f"/api/sessions/{sid}/join-code", headers=h).json()["join_code"]
    c.post("/api/join", headers=h, json={"code": code, "cell": "white_cell"})
    c.post(f"/api/sessions/{sid}/start", headers=h)
    c.post(f"/api/sessions/{sid}/observe", headers=h, json={"note": "n"})
    c.post(f"/api/sessions/{sid}/reports", headers=h, json={"audience": "executive"})
    assert c.post(f"/api/sessions/{sid}/evidence", headers=h, json={
        "filename": "note.txt", "content_type": "text/plain", "content": "aGVsbG8="}).status_code == 201
    c.post(f"/api/sessions/{sid}/complete", headers=h)
    assert c.post(f"/api/sessions/{sid}/certificate", headers=h).status_code == 201
    db = SessionLocal()
    db.add(models.ImprovementItem(org_id=org_id, session_id=sid, title="fix", description="d"))
    db.add(models.CustomAdversary(org_id=org_id, key="k", name="n", description="d"))
    db.add(models.ExerciseSchedule(org_id=org_id, scenario_id=scn, name="s",
                                   next_run_at=datetime.now(timezone.utc)))
    db.commit(); db.close()


def _tenant_leftovers(org_id, session_ids, user_ids):
    """Walk every mapped table and count rows still pointing at the org."""
    db = SessionLocal()
    left, seen = {}, set()
    for mapper in models.Base.registry.mappers:
        cls = mapper.class_
        cols = {col.name for col in cls.__table__.columns}
        hits = 0
        if "org_id" in cols:
            seen.add(cls.__tablename__)
            hits += len(db.execute(select(cls).where(cls.org_id == org_id)).scalars().all())
        if "session_id" in cols and session_ids:
            seen.add(cls.__tablename__)
            hits += len(db.execute(select(cls).where(cls.session_id.in_(session_ids))).scalars().all())
        if "user_id" in cols and user_ids:
            seen.add(cls.__tablename__)
            hits += len(db.execute(select(cls).where(cls.user_id.in_(user_ids))).scalars().all())
        if hits:
            left[cls.__tablename__] = hits
    db.close()
    return left, seen


def test_erase_org_leaves_nothing_behind_in_any_tenant_table():
    with TestClient(app) as c:
        o, t = _org(c); h = _h(t)
        env, scn, sid = _world(c, h)
        me = c.get("/api/auth/me", headers=h).json(); org_id = me["org_id"]
        _seed_everything(c, h, org_id, scn, sid)
        db = SessionLocal(); slug = db.get(models.Organization, org_id).slug; db.close()
        assert c.request("DELETE", "/api/admin/org", headers=h, json={"confirm": slug}).status_code == 200
        left, seen = _tenant_leftovers(org_id, [sid], [me["id"]])
        assert not left, f"rows survived erasure: {left}"
        # A new tenant-scoped model must be added to the seeding above, or this fires.
        assert seen - {"organizations"} == TENANT_TABLES, (
            f"tenant tables changed: {sorted(seen ^ TENANT_TABLES)} — extend _seed_everything and TENANT_TABLES")


def test_purge_removes_lobby_rows_and_detaches_improvements():
    with TestClient(app) as c:
        o, t = _org(c); h = _h(t)
        env, scn, sid = _world(c, h)
        org_id = c.get("/api/auth/me", headers=h).json()["org_id"]
        _seed_everything(c, h, org_id, scn, sid)
        c.post(f"/api/sessions/{sid}/complete", headers=h)
        db = SessionLocal()
        db.get(models.Session, sid).completed_at = datetime.now(timezone.utc) - timedelta(days=400)
        db.commit(); db.close()
        r = c.post("/api/admin/retention/purge", headers=h, json={"days": 30})
        assert r.status_code == 200 and r.json()["sessions"] == 1
        db = SessionLocal()
        assert db.execute(select(models.SessionJoin).where(models.SessionJoin.session_id == sid)).first() is None
        item = db.execute(select(models.ImprovementItem).where(models.ImprovementItem.org_id == org_id)).scalars().one()
        assert item.session_id is None  # backlog survives, reference cleared
        db.close()


# --------------------------------------------------------------------------- #
# F-2
# --------------------------------------------------------------------------- #
def test_parent_and_sub_technique_cover_each_other():
    assert technique.covers("T1003", "T1003.001")
    assert technique.covers("T1003.001", "T1003")
    assert technique.covers("t1003", " T1003 ")
    assert technique.covers("*", "T9999")
    assert not technique.covers("T1003.001", "T1003.002")  # siblings are distinct
    assert not technique.covers("T1003", "T1055")
    assert technique.normalize_list(["t1003.001", "phishing"]) == ["T1003.001", "phishing"]


def test_rulings_use_normalised_matching_and_reject_garbage():
    with TestClient(app) as c:
        o, t = _org(c); h = _h(t)
        env, scn, sid = _world(c, h)   # control covers the parent T1003
        c.post(f"/api/sessions/{sid}/start", headers=h)
        for techs in (["T1003.001"], ["t1003"], [" T1003.002 "]):
            r = c.post(f"/api/sessions/{sid}/adjudicate", headers=h, json={"techniques": techs, "target_asset": "SRV-01"})
            assert r.status_code == 200 and r.json()["ruling"]["detected"] is True, techs
        r = c.post(f"/api/sessions/{sid}/adjudicate", headers=h, json={"techniques": ["phishing"], "target_asset": "SRV-01"})
        assert r.status_code == 422
        r = c.post(f"/api/sessions/{sid}/red-actions", headers=h, json={"techniques": ["T1003.001"], "target": "SRV-01"})
        assert r.status_code == 201 and r.json()["ruling"]["detected"] is True
        # authoring stays permissive but normalises well-formed ids
        inj = c.post(f"/api/scenarios/{scn}/injects", headers=h, json={
            "code": "INJ-09", "title": "x", "attack_techniques": ["t1566.001", "custom-label"]}).json()
        assert inj["attack_techniques"] == ["T1566.001", "custom-label"]
