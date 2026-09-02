"""L2 — white-label branding on console and PDFs; partner mode with a shadow
admin inside each client organisation and isolation kept."""
import base64
import uuid

import pytest

from fastapi.testclient import TestClient

from app import branding
from app.main import app


def _pdf_text(raw: bytes) -> str:
    fitz = pytest.importorskip("fitz")
    doc = fitz.open(stream=raw, filetype="pdf")
    return "\n".join(page.get_text() for page in doc)

PW = "Str0ngPass!9"
PNG = "data:image/png;base64," + base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"x" * 40).decode()


def _h(t):
    return {"Authorization": f"Bearer {t}"}


def _org(client, name=None):
    o = uuid.uuid4().hex[:8]
    t = client.post("/api/auth/register", json={
        "org_name": name or f"O{o}", "email": f"a{o}@ex.com", "password": PW}).json()["access_token"]
    return o, t


def test_branding_validation_and_defaults():
    assert branding.defaults()["name"] == "Gauntlet" and branding.defaults()["custom"] is False
    ok = branding.validate({"name": "Northwind Security", "accent": "2F5D7C", "tagline": "Programme", "logo": PNG, "footer": "Prepared by NS"})
    assert ok["accent"] == "#2f5d7c" and ok["logo"] == PNG
    from fastapi import HTTPException
    with pytest.raises(HTTPException):
        branding.validate({"accent": "red"})
    with pytest.raises(HTTPException):
        branding.validate({"logo": "data:text/html;base64,PHNjcmlwdD4="})
    with pytest.raises(HTTPException):
        branding.validate({"name": "x" * 61})


def test_branding_applies_to_console_and_pdfs():
    with TestClient(app) as c:
        o, admin = _org(c); ha = _h(admin)
        assert c.get("/api/branding").json()["custom"] is False  # signed out: defaults
        r = c.put("/api/admin/branding", headers=ha, json={"name": "Northwind Security", "accent": "#2F5D7C", "tagline": "Exercise programme", "logo": PNG, "footer": "Prepared by NS"})
        assert r.status_code == 200 and r.json()["custom"] is True and r.json()["accent"] == "#2f5d7c"
        assert c.get("/api/branding", headers=ha).json()["name"] == "Northwind Security"
        # another org is untouched
        o2, t2 = _org(c)
        assert c.get("/api/branding", headers=_h(t2)).json()["custom"] is False
        # PDFs carry the brand
        env = c.post("/api/environments", headers=ha, json={"name": "e", "assets": [{"code": "A", "name": "a"}]}).json()["id"]
        scn = c.post("/api/scenarios", headers=ha, json={"environment_id": env, "name": "s", "injects": [{"code": "INJ-01", "title": "t", "narrative": "n", "is_start": True}]}).json()["id"]
        sid = c.post("/api/sessions", headers=ha, json={"scenario_id": scn, "name": "r"}).json()["id"]
        c.post(f"/api/sessions/{sid}/start", headers=ha); c.post(f"/api/sessions/{sid}/complete", headers=ha)
        c.post(f"/api/sessions/{sid}/certificate", headers=ha)
        text = _pdf_text(c.get(f"/api/sessions/{sid}/certificate.pdf", headers=ha).content)
        assert "NORTHWIND SECURITY" in text and "Prepared by NS" in text
        rep = c.post(f"/api/sessions/{sid}/reports", headers=ha, json={"audience": "executive"}).json()["id"]
        assert "NORTHWIND SECURITY" in _pdf_text(c.get(f"/api/sessions/{sid}/reports/{rep}.pdf", headers=ha).content)
        assert "NORTHWIND SECURITY" in _pdf_text(c.get(f"/api/sessions/{sid}/board-pack.pdf", headers=ha).content)
        # reset
        assert c.delete("/api/admin/branding", headers=ha).status_code == 204
        assert c.get("/api/branding", headers=ha).json()["custom"] is False
        assert "GAUNTLET" in _pdf_text(c.get(f"/api/sessions/{sid}/certificate.pdf", headers=ha).content)


def test_branding_is_gated_by_tier(monkeypatch):
    from app import entitlements
    from tests.conftest import TEST_PRIV
    monkeypatch.setenv("GAUNTLET_LICENSE", entitlements.issue(TEST_PRIV, tier="community", customer="x", exp="2999-01-01"))
    with TestClient(app) as c:
        o, admin = _org(c); ha = _h(admin)
        assert c.put("/api/admin/branding", headers=ha, json={"name": "X"}).status_code == 402
        assert c.get("/api/partner/clients", headers=ha).status_code == 402


def test_partner_mode_enters_clients_with_isolation():
    with TestClient(app) as c:
        o, admin = _org(c, "Acme Consulting"); ha = _h(admin)
        assert c.get("/api/partner/clients", headers=ha).json() == {"partner": "Acme Consulting", "clients": []}
        cl = c.post("/api/partner/clients", headers=ha, json={"name": "Bright Bank"}).json()
        assert cl["name"] == "Bright Bank" and cl["slug"].startswith("bright-bank-")
        # enter: a session inside the client as a shadow admin
        tok = c.post(f"/api/partner/clients/{cl['id']}/enter", headers=ha).json()
        me = c.get("/api/auth/me", headers=_h(tok["access_token"])).json()
        assert me["org_id"] == cl["id"] and me["role"] == "admin" and "+bright-bank" in me["email"]
        # the shadow sees only the client's data; the partner org's data is out of reach
        env = c.post("/api/environments", headers=ha, json={"name": "partner-env", "assets": [{"code": "A", "name": "a"}]}).json()["id"]
        assert c.get(f"/api/environments/{env}", headers=_h(tok["access_token"])).status_code == 404
        cenv = c.post("/api/environments", headers=_h(tok["access_token"]), json={"name": "client-env", "assets": [{"code": "B", "name": "b"}]}).json()["id"]
        assert c.get(f"/api/environments/{cenv}", headers=ha).status_code == 404
        # entering again reuses the shadow; both audit logs know
        tok2 = c.post(f"/api/partner/clients/{cl['id']}/enter", headers=ha).json()
        assert c.get("/api/auth/me", headers=_h(tok2["access_token"])).json()["id"] == me["id"]
        assert "partner.enter" in {a["action"] for a in c.get("/api/audit", headers=ha).json()}
        assert "partner.enter" in {a["action"] for a in c.get("/api/audit", headers=_h(tok["access_token"])).json()}
        # the client's member list shows the partner user marked via the partner
        names = [m["name"] for m in c.get("/api/members", headers=_h(tok["access_token"])).json()]
        assert any("via Acme Consulting" in n for n in names)
        # a non-admin partner user cannot enter; an unrelated org cannot enter
        em = f"f{o}@ex.com"
        c.post("/api/auth/users", headers=ha, json={"email": em, "password": PW, "role": "facilitator"})
        tf = c.post("/api/auth/login", json={"email": em, "password": PW}).json()["access_token"]
        assert c.post(f"/api/partner/clients/{cl['id']}/enter", headers=_h(tf)).status_code == 403
        o3, t3 = _org(c)
        assert c.post(f"/api/partner/clients/{cl['id']}/enter", headers=_h(t3)).status_code == 404
        # unlink deactivates the shadow; the client's data stays
        assert c.delete(f"/api/partner/clients/{cl['id']}", headers=ha).status_code == 204
        assert c.get("/api/auth/me", headers=_h(tok["access_token"])).status_code == 401
        assert c.get("/api/partner/clients", headers=ha).json()["clients"] == []
