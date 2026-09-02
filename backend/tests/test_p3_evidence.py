"""P3 — evidence attachments: a file's digest is bound into the signed chain;
a swapped file fails verification; staff-only; erased with the tenant."""
import base64
import hashlib
import uuid

from fastapi.testclient import TestClient
from sqlalchemy import select

from app import evidence, models
from app.database import SessionLocal
from app.main import app

PW = "Str0ngPass!9"


def _h(t):
    return {"Authorization": f"Bearer {t}"}


def _org(client):
    o = uuid.uuid4().hex[:8]
    t = client.post("/api/auth/register", json={
        "org_name": f"O{o}", "email": f"a{o}@ex.com", "password": PW}).json()["access_token"]
    return o, t


def _user(client, ha, o, role):
    em = f"{role}{o}@ex.com"
    client.post("/api/auth/users", headers=ha, json={"email": em, "password": PW, "role": role})
    return client.post("/api/auth/login", json={"email": em, "password": PW}).json()["access_token"]


def _world(client, ha):
    env = client.post("/api/environments", headers=ha, json={"name": "e", "assets": [{"code": "A", "name": "a"}]}).json()["id"]
    scn = client.post("/api/scenarios", headers=ha, json={
        "environment_id": env, "name": "s",
        "injects": [{"code": "INJ-01", "title": "t", "narrative": "n", "is_start": True}]}).json()["id"]
    sid = client.post("/api/sessions", headers=ha, json={"scenario_id": scn, "name": "run"}).json()["id"]
    return sid


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def test_attach_download_verify_and_report():
    with TestClient(app) as c:
        o, admin = _org(c); ha = _h(admin)
        sid = _world(c, ha)
        png = b"\x89PNG\r\n\x1a\n" + b"x" * 500
        # not before start
        assert c.post(f"/api/sessions/{sid}/evidence", headers=ha, json={"filename": "a.png", "content_type": "image/png", "content": _b64(png)}).status_code == 409
        c.post(f"/api/sessions/{sid}/start", headers=ha)
        r = c.post(f"/api/sessions/{sid}/evidence", headers=ha, json={
            "filename": "../siem screenshot.png", "content_type": "image/png; charset=binary", "content": _b64(png),
            "note": "SIEM at T+00:12", "about_seq": 1})
        assert r.status_code == 201, r.text
        a = r.json()
        assert a["filename"] == "siem screenshot.png" and a["size"] == len(png) and a["content_type"] == "image/png"
        assert a["sha256"] == hashlib.sha256(png).hexdigest() and a["about_seq"] == 1 and a["event_seq"] >= 2
        # the event is on the chain and lists with a verified state
        lst = c.get(f"/api/sessions/{sid}/evidence", headers=ha).json()
        assert lst["attachments"][0]["id"] == a["id"] and lst["valid"] is True and lst["problems"] == []
        v = c.get(f"/api/sessions/{sid}/verify", headers=ha).json()
        assert v["chain_valid"] is True and v["evidence"] == {"attachments": 1, "valid": True, "problems": []}
        # download
        d = c.get(f"/api/sessions/{sid}/evidence/{a['id']}", headers=ha)
        assert d.status_code == 200 and d.content == png and d.headers["x-evidence-sha256"] == a["sha256"]
        assert 'filename="siem screenshot.png"' in d.headers["content-disposition"]
        # bad input
        assert c.post(f"/api/sessions/{sid}/evidence", headers=ha, json={"filename": "x", "content": "not*base64"}).status_code == 422
        assert c.post(f"/api/sessions/{sid}/evidence", headers=ha, json={"filename": "x", "content": ""}).status_code == 422
        assert c.post(f"/api/sessions/{sid}/evidence", headers=ha, json={"filename": "x.exe", "content_type": "application/x-msdownload", "content": _b64(b"MZ")}).status_code == 422
        assert c.post(f"/api/sessions/{sid}/evidence", headers=ha, json={"filename": "x.txt", "content_type": "text/plain", "content": _b64(b"hi"), "about_seq": 999}).status_code == 404
        # participants never see it; evaluators may attach and read
        hp = _h(_user(c, ha, o, "participant")); he = _h(_user(c, ha, o, "evaluator"))
        assert c.get(f"/api/sessions/{sid}/evidence", headers=hp).status_code == 403
        assert c.post(f"/api/sessions/{sid}/evidence", headers=he, json={"filename": "n.txt", "content_type": "text/plain", "content": _b64(b"note")}).status_code == 201
        # after completion too (post-exercise collection), and in the GRC report
        c.post(f"/api/sessions/{sid}/complete", headers=ha)
        assert c.post(f"/api/sessions/{sid}/evidence", headers=ha, json={"filename": "ticket.json", "content_type": "application/json", "content": _b64(b"{}")}).status_code == 201
        grc = c.post(f"/api/sessions/{sid}/reports", headers=ha, json={"audience": "grc"}).json()["content"]
        assert "Evidence attached" in grc and "siem screenshot.png" in grc and a["sha256"] in grc
        tech = c.post(f"/api/sessions/{sid}/reports", headers=ha, json={"audience": "technical"}).json()["content"]
        assert "Evidence attached — siem screenshot.png" in tech
        # other org
        o2, t2 = _org(c)
        assert c.get(f"/api/sessions/{sid}/evidence/{a['id']}", headers=_h(t2)).status_code == 404


def test_swapped_file_fails_verification():
    with TestClient(app) as c:
        o, admin = _org(c); ha = _h(admin)
        sid = _world(c, ha)
        c.post(f"/api/sessions/{sid}/start", headers=ha)
        a = c.post(f"/api/sessions/{sid}/evidence", headers=ha, json={"filename": "log.txt", "content_type": "text/plain", "content": _b64(b"original")}).json()
        db = SessionLocal()
        try:
            att = db.get(models.Attachment, a["id"]); att.data = b"tampered"; db.commit()
        finally:
            db.close()
        v = c.get(f"/api/sessions/{sid}/verify", headers=ha).json()
        assert v["chain_valid"] is False and "does not match its recorded digest" in v["evidence"]["problems"][0]


def test_size_cap_and_safe_names(monkeypatch):
    monkeypatch.setattr(evidence, "MAX_BYTES", 64)
    with TestClient(app) as c:
        o, admin = _org(c); ha = _h(admin)
        sid = _world(c, ha)
        c.post(f"/api/sessions/{sid}/start", headers=ha)
        assert c.post(f"/api/sessions/{sid}/evidence", headers=ha, json={"filename": "big.txt", "content_type": "text/plain", "content": _b64(b"x" * 65)}).status_code == 413
        assert c.post(f"/api/sessions/{sid}/evidence", headers=ha, json={"filename": "ok.txt", "content_type": "text/plain", "content": _b64(b"x" * 64)}).status_code == 201
    assert evidence.safe_name("../../etc/passwd") == "passwd" and evidence.safe_name("C:\\tmp\\shot.png") == "shot.png"
    assert evidence.safe_name("") == "evidence" and "<" not in evidence.safe_name("<script>.png")
