"""M1 — exercise certificate: issued only for completed exercises, numbers frozen
and signed, verifiable without an account, tamper-evident, tenant-scoped."""
import uuid

from fastapi.testclient import TestClient
from sqlalchemy import select

from app import models
from app.database import SessionLocal
from app.main import app

PW = "Str0ngPass!9"


def _h(t):
    return {"Authorization": f"Bearer {t}"}


def _org(client):
    o = uuid.uuid4().hex[:8]
    t = client.post("/api/auth/register", json={
        "org_name": f"Org {o}", "email": f"a{o}@ex.com", "password": PW}).json()["access_token"]
    return o, t


def _user(client, ha, o, role):
    em = f"{role}{o}@ex.com"
    client.post("/api/auth/users", headers=ha, json={"email": em, "password": PW, "role": role})
    return client.post("/api/auth/login", json={"email": em, "password": PW}).json()["access_token"]


def _world(client, ha):
    env = client.post("/api/environments", headers=ha, json={
        "name": "e", "sector": "Healthcare", "assets": [{"code": "SRV-01", "name": "srv"}],
        "detections": [{"name": "EDR", "covers": ["T1003"], "assets": ["*"], "efficacy": 1.0, "latency_min": 4}]}).json()["id"]
    scn = client.post("/api/scenarios", headers=ha, json={
        "environment_id": env, "name": "s", "threat_actor": "ransomware crew",
        "objectives": [{"code": "OBJ-1", "title": "Detect"}, {"code": "OBJ-2", "title": "Contain"}],
        "injects": [{"code": "INJ-01", "title": "start", "narrative": "SPOILER", "is_start": True,
                     "branches": [{"label": "go", "when": "proctor_choice", "goto": "INJ-02"}]},
                    {"code": "INJ-02", "title": "later", "narrative": "SPOILER"}]}).json()["id"]
    sid = client.post("/api/sessions", headers=ha, json={"scenario_id": scn, "name": "Q3 run"}).json()["id"]
    client.post(f"/api/sessions/{sid}/start", headers=ha)
    client.post(f"/api/sessions/{sid}/adjudicate", headers=ha,
                json={"techniques": ["T1003"], "target_asset": "SRV-01", "description": "dump"})
    client.post(f"/api/sessions/{sid}/adjudicate", headers=ha,
                json={"techniques": ["T1486"], "target_asset": "SRV-01", "description": "encrypt"})
    client.post(f"/api/sessions/{sid}/observe", headers=ha,
                json={"objective_code": "OBJ-1", "rating": "met", "note": "good"})
    client.post(f"/api/sessions/{sid}/observe", headers=ha,
                json={"objective_code": "OBJ-2", "rating": "partial", "note": "slow"})
    return sid


def test_certificate_lifecycle():
    with TestClient(app) as c:
        o, admin = _org(c); ha = _h(admin)
        sid = _world(c, ha)
        # not complete yet
        assert c.post(f"/api/sessions/{sid}/certificate", headers=ha).status_code == 409
        assert c.get(f"/api/sessions/{sid}/certificate", headers=ha).status_code == 404
        c.post(f"/api/sessions/{sid}/complete", headers=ha)
        r = c.post(f"/api/sessions/{sid}/certificate", headers=ha)
        assert r.status_code == 201, r.text
        cert = r.json()
        p = cert["payload"]
        assert cert["serial"].startswith("GC-") and len(cert["signature"]) == 64
        assert p["organization"] == f"Org {o}" and p["exercise"] == "Q3 run" and p["sector"] == "Healthcare"
        assert p["adversary_actions"] == 2 and p["detected"] == 1 and p["detection_rate"] == 0.5
        assert p["mean_time_to_detect_min"] == 4.0
        assert p["techniques_exercised"] == ["T1003", "T1486"] and p["coverage_gaps"] == ["T1486"]
        assert p["objectives"] == {"total": 2, "assessed": 2, "met": 1, "partial": 1, "missed": 0, "met_rate": 0.75}
        assert p["chain_verified"] is True and p["timeline_head"]["seq"] == p["timeline_events"]
        assert "SPOILER" not in r.text
        # idempotent
        again = c.post(f"/api/sessions/{sid}/certificate", headers=ha).json()
        assert again["serial"] == cert["serial"]
        # pdf
        pdf = c.get(f"/api/sessions/{sid}/certificate.pdf", headers=ha)
        assert pdf.status_code == 200 and pdf.content[:4] == b"%PDF"
        assert "attachment" in pdf.headers["content-disposition"]
        # public verify, no auth
        v = c.get(f"/api/certificates/{cert['serial']}/verify").json()
        assert v["valid"] is True and v["record"]["detection_rate"] == 0.5
        assert v["record"]["organization"] == f"Org {o}"
        assert "SPOILER" not in c.get(f"/api/certificates/{cert['serial']}/verify").text
        assert set(v["record"]) & {"threat_actor", "session_id", "issued_by"} == set()
        # case-insensitive serial
        assert c.get(f"/api/certificates/{cert['serial'].lower()}/verify").json()["valid"] is True
        # unknown serial
        u = c.get("/api/certificates/GC-2026-00000000/verify").json()
        assert u["valid"] is False and u["record"] == {}
        # revoke
        assert c.post(f"/api/sessions/{sid}/certificate/revoke", headers=ha).json()["revoked_at"]
        assert c.get(f"/api/certificates/{cert['serial']}/verify").json()["reason"] == "revoked"
        assert c.get(f"/api/sessions/{sid}/certificate", headers=ha).status_code == 404
        # re-issue after revocation gives a new serial
        assert c.post(f"/api/sessions/{sid}/certificate", headers=ha).json()["serial"] != cert["serial"]


def test_certificate_is_tamper_evident():
    with TestClient(app) as c:
        o, admin = _org(c); ha = _h(admin)
        sid = _world(c, ha)
        c.post(f"/api/sessions/{sid}/complete", headers=ha)
        serial = c.post(f"/api/sessions/{sid}/certificate", headers=ha).json()["serial"]
        db = SessionLocal()
        try:
            cert = db.execute(select(models.Certificate).where(models.Certificate.serial == serial)).scalar_one()
            payload = dict(cert.payload); payload["detection_rate"] = 1.0; payload["detected"] = 2
            cert.payload = payload
            db.commit()
        finally:
            db.close()
        v = c.get(f"/api/certificates/{serial}/verify").json()
        assert v["valid"] is False and "digest" in v["reason"] and v["record"] == {}


def test_certificate_is_tenant_scoped_and_role_gated():
    with TestClient(app) as c:
        o, admin = _org(c); ha = _h(admin)
        sid = _world(c, ha)
        c.post(f"/api/sessions/{sid}/complete", headers=ha)
        he = _h(_user(c, ha, o, "evaluator")); hp = _h(_user(c, ha, o, "participant"))
        assert c.post(f"/api/sessions/{sid}/certificate", headers=he).status_code == 403
        assert c.post(f"/api/sessions/{sid}/certificate", headers=ha).status_code == 201
        assert c.get(f"/api/sessions/{sid}/certificate", headers=he).status_code == 200
        assert c.get(f"/api/sessions/{sid}/certificate.pdf", headers=he).status_code == 200
        assert c.get(f"/api/sessions/{sid}/certificate", headers=hp).status_code == 403
        o2, t2 = _org(c)
        assert c.get(f"/api/sessions/{sid}/certificate", headers=_h(t2)).status_code == 404
        assert c.post(f"/api/sessions/{sid}/certificate", headers=_h(t2)).status_code == 404
        assert c.get("/api/certificates/GC-2026-ZZZZZZZZ/verify").status_code == 200
