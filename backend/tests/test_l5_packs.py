"""L5 — signed content packs: verification, scenario packs bound to library
environments, intel packs that upsert adversaries and feed the console,
versioning, tenant scope and tier gates."""
import json
import uuid

import pytest
from fastapi.testclient import TestClient

from app import entitlements, packs
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


@pytest.fixture
def pack_key(monkeypatch):
    priv, pub = entitlements.keygen()
    monkeypatch.setenv("GAUNTLET_PACK_PUBKEY", pub)
    return priv


@pytest.fixture
def community(monkeypatch):
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


SCENARIO = {"name": "Ward ransomware", "threat_actor": "Affiliate", "narrative": "n",
            "objectives": [{"code": "OBJ-1", "title": "Recognise", "success_criteria": "s"}],
            "injects": [{"code": "INJ-01", "title": "Slow charts", "narrative": "n", "is_start": True,
                         "branches": [{"label": "go", "when": "proctor_choice", "goto": "INJ-02"}]},
                        {"code": "INJ-02", "title": "Ransom note", "narrative": "n"}]}


def _scen_manifest(version="2026.9", env_key="hospital"):
    return {"v": 1, "kind": "scenarios", "id": "acme-healthcare", "name": "Healthcare pack", "version": version,
            "publisher": "Acme", "issued": "2026-09-01", "items": [{"environment_key": env_key, "scenario": SCENARIO}]}


def _intel_manifest(version="2026.09.02", headline="IAB selling into affiliates"):
    return {"v": 1, "kind": "intel", "id": "acme-intel", "name": "Acme intel", "version": version, "publisher": "Acme",
            "issued": "2026-09-02", "items": [
                {"key": "glasswing", "name": "GLASSWING", "headline": headline, "notes": "phishing then hand-off",
                 "published": "2026-08-28", "sectors": ["Healthcare"], "techniques": ["T1566.001", "T1486"],
                 "kill_chain": ["not-a-scene"], "motivation": "financial", "is_fictitious": True,
                 "references": ["https://example.invalid/r"]},
                {"key": "apt29", "name": "Cozy Bear (update)", "published": "2026-09-01", "techniques": ["T1078"]}]}


def test_sign_verify_and_manifest_checks(pack_key):
    tok = packs.sign(pack_key, _intel_manifest())
    m, digest = packs.verify(tok)
    assert m["id"] == "acme-intel" and len(digest) == 64
    with pytest.raises(packs.PackError):
        packs.verify(tok[:-4] + "AAAA")  # tampered signature
    with pytest.raises(packs.PackError):
        packs.verify("GL1.x.y")  # a licence is not a pack
    other, _ = entitlements.keygen()
    with pytest.raises(packs.PackError):
        packs.verify(packs.sign(other, _intel_manifest()))  # another publisher's key
    for bad in ({**_intel_manifest(), "kind": "malware"}, {**_intel_manifest(), "id": "Bad Id"},
                {**_intel_manifest(), "items": []}, {**_scen_manifest(), "items": [{"scenario": {"name": "x"}}]}):
        with pytest.raises(packs.PackError):
            packs.sign(pack_key, bad)


def test_scenario_pack_installs_into_library_environment(pack_key):
    with TestClient(app) as c:
        o, admin = _org(c); ha = _h(admin)
        tok = packs.sign(pack_key, _scen_manifest())
        pre = c.post("/api/packs/inspect", headers=ha, json={"token": tok}).json()
        assert pre["kind"] == "scenarios" and pre["count"] == 1 and pre["items"][0]["injects"] == 2 and pre["licensed"] is True
        assert c.get("/api/environments", headers=ha).json() == []
        r = c.post("/api/packs/install", headers=ha, json={"token": tok})
        assert r.status_code == 201, r.text
        out = r.json()
        assert out["pack"]["version"] == "2026.9" and out["created"][0]["name"] == "Ward ransomware"
        envs = c.get("/api/environments", headers=ha).json()
        assert len(envs) == 1 and "Hospital" in envs[0]["name"] or "hospital" in envs[0]["name"].lower()
        scn = c.get(f"/api/scenarios/{out['created'][0]['scenario_id']}", headers=ha).json()
        assert scn["environment_id"] == envs[0]["id"] and len(scn["injects"]) == 2
        # same version again: refused; a newer version installs and reuses the environment
        assert c.post("/api/packs/install", headers=ha, json={"token": tok}).status_code == 409
        r = c.post("/api/packs/install", headers=ha, json={"token": packs.sign(pack_key, _scen_manifest("2026.10"))})
        assert r.status_code == 201 and len(c.get("/api/environments", headers=ha).json()) == 1
        lst = c.get("/api/packs", headers=ha).json()
        assert len(lst) == 1 and lst[0]["version"] == "2026.10"
        # a pack without a library environment needs one chosen
        tok2 = packs.sign(pack_key, {**_scen_manifest("1", env_key=""), "id": "acme-other"})
        assert c.post("/api/packs/install", headers=ha, json={"token": tok2}).status_code == 400
        assert c.post("/api/packs/install", headers=ha, json={"token": tok2, "environment_id": envs[0]["id"]}).status_code == 201
        # another org sees none of it
        o2, t2 = _org(c)
        assert c.get("/api/packs", headers=_h(t2)).json() == [] and c.get("/api/scenarios", headers=_h(t2)).json() == []
        assert c.delete(f"/api/packs/{lst[0]['id']}", headers=_h(t2)).status_code == 404
        # forgetting the record keeps the content
        assert c.delete(f"/api/packs/{lst[0]['id']}", headers=ha).status_code == 204
        assert len(c.get("/api/scenarios", headers=ha).json()) == 3
        # a tampered token is refused with a plain message
        r = c.post("/api/packs/install", headers=ha, json={"token": tok[:-3] + "zzz"})
        assert r.status_code == 422 and "signature" in r.json()["detail"]


def test_intel_pack_upserts_adversaries_and_feeds(pack_key):
    with TestClient(app) as c:
        o, admin = _org(c); ha = _h(admin)
        assert c.get("/api/packs/intel", headers=ha).json() == []
        r = c.post("/api/packs/install", headers=ha, json={"token": packs.sign(pack_key, _intel_manifest())})
        assert r.status_code == 201, r.text
        out = r.json()
        assert [x["action"] for x in out["created"]] == ["created", "created"]
        assert out["created"][1]["key"] == "apt29-intel"  # never shadows a built-in actor
        assert any("kill chain" in w for w in out["warnings"])
        advs = {a["key"]: a for a in c.get("/api/adversaries", headers=ha).json()}
        assert advs["glasswing"]["label"].startswith("IAB") and advs["glasswing"]["techniques"] == ["T1566.001", "T1486"]
        assert advs["glasswing"]["kill_chain"] == []
        feed = c.get("/api/packs/intel", headers=ha).json()
        assert [e["key"] for e in feed] == ["apt29", "glasswing"] and feed[1]["pack"] == "Acme intel"
        assert feed[1]["references"] == ["https://example.invalid/r"]
        # a newer pack updates in place: same adversary rows, new headline
        r = c.post("/api/packs/install", headers=ha, json={"token": packs.sign(pack_key, _intel_manifest("2026.09.09", "Now also hitting clinics"))})
        assert r.status_code == 201 and [x["action"] for x in r.json()["created"]] == ["updated", "updated"]
        advs2 = {a["key"]: a for a in c.get("/api/adversaries", headers=ha).json()}
        assert len(advs2) == 2 and advs2["glasswing"]["id"] == advs["glasswing"]["id"] and advs2["glasswing"]["label"].startswith("Now")
        assert c.get("/api/packs/intel", headers=ha).json()[1]["headline"].startswith("Now")
        # participants cannot read the feed or install
        em = f"p{o}@ex.com"
        c.post("/api/auth/users", headers=ha, json={"email": em, "password": PW, "role": "participant"})
        pt = c.post("/api/auth/login", json={"email": em, "password": PW}).json()["access_token"]
        assert c.get("/api/packs/intel", headers=_h(pt)).status_code == 403
        assert c.post("/api/packs/install", headers=_h(pt), json={"token": "x"}).status_code == 403


def test_packs_are_gated_by_tier(pack_key, community):
    with TestClient(app) as c:
        o, admin = _org(c); ha = _h(admin)
        tok = packs.sign(pack_key, _intel_manifest())
        pre = c.post("/api/packs/inspect", headers=ha, json={"token": tok}).json()
        assert pre["licensed"] is False  # inspecting is always allowed; it says what the install needs
        assert c.post("/api/packs/install", headers=ha, json={"token": tok}).status_code == 402
        assert c.post("/api/packs/install", headers=ha, json={"token": packs.sign(pack_key, _scen_manifest())}).status_code == 402
        assert c.get("/api/packs/intel", headers=ha).status_code == 402
        assert c.get("/api/packs", headers=ha).json() == []


def test_build_tool_round_trip(pack_key, tmp_path):
    import subprocess, sys, os
    root = os.path.join(os.path.dirname(__file__), "..", "..")
    intel = tmp_path / "intel.json"
    intel.write_text(json.dumps(_intel_manifest()["items"]))
    out = subprocess.run([sys.executable, os.path.join(root, "tools", "build_pack.py"), "intel", "--key", pack_key,
                          "--id", "acme-intel", "--name", "Acme intel", "--version", "1", "--publisher", "Acme", str(intel)],
                         capture_output=True, text=True, check=True, env={**os.environ})
    tok = out.stdout.strip()
    m, _ = packs.verify(tok)
    assert m["kind"] == "intel" and m["items"][0]["key"] == "glasswing"
    f = tmp_path / "p.gpack"; f.write_text(tok)
    ins = subprocess.run([sys.executable, os.path.join(root, "tools", "build_pack.py"), "inspect", str(f)],
                         capture_output=True, text=True, check=True, env={**os.environ})
    assert json.loads(ins.stdout)["count"] == 2
