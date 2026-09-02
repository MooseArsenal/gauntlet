"""L6 — trust anchors: key ids and rotation, production pinning, licence
serials and signed revocation lists, encrypted key files, the tools, and no
private key material in the tree."""
import json
import os
import re
import subprocess
import sys
import uuid

import pytest
from fastapi.testclient import TestClient

from app import config, entitlements, packs, signing
from app.database import SessionLocal
from app.main import app

PW = "Str0ngPass!9"
ROOT = os.path.join(os.path.dirname(__file__), "..", "..")


def _h(t):
    return {"Authorization": f"Bearer {t}"}


def _org(client):
    o = uuid.uuid4().hex[:8]
    t = client.post("/api/auth/register", json={
        "org_name": f"O{o}", "email": f"a{o}@ex.com", "password": PW}).json()["access_token"]
    return o, t


@pytest.fixture
def clean_license():
    with TestClient(app):
        pass  # make sure the schema exists before touching instance settings directly

    def _clear():
        db = SessionLocal()
        try:
            entitlements.store_token(db, None); entitlements.store_revocations(db, None); db.commit()
        finally:
            db.close()
    _clear()
    yield
    _clear()


def test_kid_selection_and_rotation(monkeypatch):
    p1, k1 = signing.keygen(); p2, k2 = signing.keygen(); p3, k3 = signing.keygen()
    monkeypatch.delenv("GAUNTLET_LICENSE_PUBKEY", raising=False)  # the suite's own key
    monkeypatch.setenv("GAUNTLET_LICENSE_PUBKEYS", f"{signing.kid_for(k1)}={k1},{k2}")  # explicit and derived kids
    keys = signing.trusted_keys("license")
    assert set(keys) - set(signing.VENDOR_KEYS) == {signing.kid_for(k1), signing.kid_for(k2)}
    t1 = entitlements.issue(p1, tier="team", customer="A", exp="2999-01-01")
    t2 = entitlements.issue(p2, tier="team", customer="B", exp="2999-01-01")
    assert entitlements.parse(t1)["kid"] == signing.kid_for(k1) and entitlements.parse(t2)["kid"] == signing.kid_for(k2)
    assert len(entitlements.parse(t1)["serial"]) == 16
    with pytest.raises(entitlements.LicenseError, match="not trusted"):
        entitlements.parse(entitlements.issue(p3, tier="team", customer="C", exp="2999-01-01"))
    # a v1 token (no kid) is checked against every trusted key
    body = json.dumps({"v": 1, "tier": "team", "customer": "old", "org": "*", "exp": "2999-01-01",
                       "features": [], "seats": {}, "issued": "2026-01-01"}, sort_keys=True, separators=(",", ":")).encode()
    v1 = f"GL1.{signing.b64e(body)}.{signing.b64e(signing.sign(p2, body))}"
    assert entitlements.parse(v1)["kid"] == signing.kid_for(k2) and entitlements.parse(v1)["serial"] == ""
    # retire key 2: its tokens stop verifying
    monkeypatch.setenv("GAUNTLET_LICENSE_PUBKEYS", f"{k1}")
    with pytest.raises(entitlements.LicenseError):
        entitlements.parse(t2)
    assert entitlements.parse(t1)["customer"] == "A"


def test_production_ignores_environment_keys(monkeypatch):
    p1, k1 = signing.keygen()
    monkeypatch.setenv("GAUNTLET_LICENSE_PUBKEY", k1)
    tok = entitlements.issue(p1, tier="enterprise", customer="A", exp="2999-01-01")
    assert entitlements.parse(tok)["tier"] == "enterprise"
    monkeypatch.setattr(config, "IS_PROD", True)
    monkeypatch.setattr(signing, "VENDOR_KEYS", {})
    with pytest.raises(entitlements.LicenseError, match="no trusted signing key"):
        entitlements.parse(tok)
    with pytest.raises(packs.PackError, match="no trusted"):
        packs.verify(packs.sign(p1, {"v": 1, "kind": "intel", "id": "xpack", "name": "x", "version": "1", "publisher": "p",
                                     "issued": "2026-01-01", "items": [{"key": "alpha", "name": "A"}]}))
    # the built-in vendor key is the anchor in production
    monkeypatch.setattr(signing, "VENDOR_KEYS", {signing.kid_for(k1): k1})
    assert entitlements.parse(tok)["kid"] == signing.kid_for(k1)
    # an explicit opt-in restores environment keys (for forks)
    monkeypatch.setattr(signing, "VENDOR_KEYS", {})
    monkeypatch.setenv("GAUNTLET_TRUST_ENV_KEYS", "1")
    assert entitlements.parse(tok)["tier"] == "enterprise"
    # and the start-up check names silently-ignored env keys in production
    monkeypatch.delenv("GAUNTLET_TRUST_ENV_KEYS")
    assert any("GAUNTLET_LICENSE_PUBKEY" in p for p in config.startup_problems())


def test_revocation_list_degrades_a_licence(clean_license, monkeypatch):
    priv, pub = signing.keygen()
    monkeypatch.setenv("GAUNTLET_LICENSE_PUBKEY", pub)
    monkeypatch.delenv("GAUNTLET_LICENSE", raising=False)
    with TestClient(app) as c:
        o, admin = _org(c); ha = _h(admin)
        tok = entitlements.issue(priv, tier="enterprise", customer="Acme", exp="2999-01-01")
        serial = entitlements.parse(tok)["serial"]
        st = c.post("/api/admin/license", headers=ha, json={"token": tok}).json()
        assert st["state"] == "active" and st["serial"] == serial and st["revocations"]["revoked"] == []
        assert c.post("/api/cohorts", headers=ha, json={"name": "x"}).status_code == 201  # education works
        # someone else's revocation list is refused
        other, _ = signing.keygen()
        assert c.post("/api/admin/license/revocations", headers=ha,
                      json={"token": entitlements.issue_revocations(other, [serial])}).status_code == 422
        # a revocation of a different serial changes nothing
        st = c.post("/api/admin/license/revocations", headers=ha, json={"token": entitlements.issue_revocations(priv, ["deadbeef"])}).json()
        assert st["state"] == "active" and st["revocations"]["revoked"] == ["deadbeef"]
        # revoking this serial degrades to Community at once
        rl = entitlements.issue_revocations(priv, [serial, "deadbeef"], issued="2026-09-03")
        st = c.post("/api/admin/license/revocations", headers=ha, json={"token": rl}).json()
        assert st["state"] == "revoked" and st["tier"] == "community" and st["licensed"] is False
        assert "revoked" in st["error"] and st["revocations"]["issued"] == "2026-09-03"
        assert c.post("/api/cohorts", headers=ha, json={"name": "y"}).status_code == 402
        assert c.get("/api/license", headers=ha).json()["state"] == "revoked"
        # a fresh licence under a new serial works again; removing the list restores the old one
        tok2 = entitlements.issue(priv, tier="enterprise", customer="Acme", exp="2999-01-01")
        assert c.post("/api/admin/license", headers=ha, json={"token": tok2}).json()["state"] == "active"
        assert c.post("/api/admin/license", headers=ha, json={"token": tok}).json()["state"] == "revoked"
        assert c.delete("/api/admin/license/revocations", headers=ha).status_code == 204
        assert c.get("/api/license", headers=ha).json()["state"] == "active"
        # revocation via environment, for deployments configured that way
        monkeypatch.setenv("GAUNTLET_LICENSE_REVOCATIONS", rl)
        assert c.get("/api/license", headers=ha).json()["state"] == "revoked"
        # a participant cannot install lists
        em = f"p{o}@ex.com"
        c.post("/api/auth/users", headers=ha, json={"email": em, "password": PW, "role": "participant"})
        pt = c.post("/api/auth/login", json={"email": em, "password": PW}).json()["access_token"]
        assert c.post("/api/admin/license/revocations", headers=_h(pt), json={"token": rl}).status_code == 403


def test_encrypted_key_files(tmp_path):
    priv, pub = signing.keygen()
    path = str(tmp_path / "vendor.key")
    with pytest.raises(ValueError):
        signing.save_private_key(path, priv, "short")
    signing.save_private_key(path, priv, "correct horse battery staple")
    assert oct(os.stat(path).st_mode & 0o777) == "0o600"
    pem = open(path, "rb").read()
    assert b"ENCRYPTED PRIVATE KEY" in pem and signing.b64d(priv) not in pem
    assert signing.load_private_key(path, "correct horse battery staple") == priv
    with pytest.raises(ValueError, match="passphrase"):
        signing.load_private_key(path, "wrong passphrase here")
    assert signing.public_of(priv) == pub


def test_tools_keygen_issue_revoke_with_key_file(tmp_path, monkeypatch):
    env = {**os.environ, "GAUNTLET_SIGNING_PASSPHRASE": "correct horse battery staple"}
    tool = os.path.join(ROOT, "tools", "issue_license.py")
    key = str(tmp_path / "vendor.key")
    out = subprocess.run([sys.executable, tool, "keygen", "--out", key], capture_output=True, text=True, check=True, env=env).stdout
    pub = re.search(r"PUBLIC: (\S+)", out).group(1); kid = re.search(r"KID: (\S+)", out).group(1)
    assert "PRIVATE" not in out and os.path.exists(key) and kid == signing.kid_for(pub)
    assert f'"{kid}": "{pub}"' in out  # the line to paste into VENDOR_KEYS
    r = subprocess.run([sys.executable, tool, "issue", "--key-file", key, "--tier", "team", "--customer", "Acme", "--exp", "2027-01-01",
                        "--seats", "facilitators=5"], capture_output=True, text=True, check=True, env=env)
    tok = r.stdout.strip()
    monkeypatch.setenv("GAUNTLET_LICENSE_PUBKEY", pub)
    p = entitlements.parse(tok)
    assert p["kid"] == kid and p["seats"] == {"facilitators": 5} and p["serial"] in r.stderr
    rl = subprocess.run([sys.executable, tool, "revoke", "--key-file", key, "--serial", p["serial"]],
                        capture_output=True, text=True, check=True, env=env).stdout.strip()
    assert entitlements.parse_revocations(rl)["revoked"] == [p["serial"]]
    prev = tmp_path / "prev.grl"; prev.write_text(rl)
    rl2 = subprocess.run([sys.executable, tool, "revoke", "--key-file", key, "--serial", "abcd", "--previous", str(prev)],
                         capture_output=True, text=True, check=True, env=env).stdout.strip()
    assert entitlements.parse_revocations(rl2)["revoked"] == sorted([p["serial"], "abcd"])
    # wrong passphrase: refused, nothing issued
    bad = subprocess.run([sys.executable, tool, "issue", "--key-file", key, "--tier", "team", "--customer", "A", "--exp", "2027-01-01"],
                         capture_output=True, text=True, env={**env, "GAUNTLET_SIGNING_PASSPHRASE": "not the passphrase"})
    assert bad.returncode != 0 and "passphrase" in (bad.stderr + bad.stdout)
    # show names the key inside a key file
    sh = subprocess.run([sys.executable, tool, "show", "--key-file", key], capture_output=True, text=True, check=True, env=env)
    assert f"KID: {kid}" in sh.stdout and f"PUBLIC: {pub}" in sh.stdout
    # inspect decodes without a key
    ins = subprocess.run([sys.executable, tool, "inspect", tok], capture_output=True, text=True, check=True, env=env)
    assert json.loads(ins.stdout)["customer"] == "Acme"
    # packs sign with the same kind of key file
    ptool = os.path.join(ROOT, "tools", "build_pack.py")
    intel = tmp_path / "i.json"; intel.write_text(json.dumps([{"key": "alpha", "name": "A"}]))
    pk = subprocess.run([sys.executable, ptool, "intel", "--key-file", key, "--id", "xpack", "--name", "x", "--version", "1",
                         "--publisher", "p", str(intel)], capture_output=True, text=True, check=True, env=env).stdout.strip()
    assert pk.split(".")[1] == kid and packs.verify(pk)[0]["id"] == "xpack"


def test_no_private_key_material_in_tree():
    bad = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in (".git", ".venv", "node_modules", "__pycache__", ".pytest_cache")]
        for fn in filenames:
            path = os.path.join(dirpath, fn)
            try:
                with open(path, "rb") as f:
                    head = f.read(512 * 1024)
            except OSError:
                continue
            if b"PRIVATE KEY-----" in head and b"BEGIN" in head and not fn.endswith((".py", ".md")):
                bad.append(os.path.relpath(path, ROOT))
    assert not bad, f"private key material committed: {bad}"
    assert signing.VENDOR_KEYS == {} or all(len(signing.b64d(v)) == 32 for v in signing.VENDOR_KEYS.values())


def test_vendor_keys_are_well_formed_and_named_by_their_kid():
    """Every compiled-in vendor key is a 32-byte Ed25519 public key and its id
    is the id the tool would print for it — a paste error would fail here."""
    assert signing.VENDOR_KEYS, "no vendor key compiled in"
    for kid, pub in signing.VENDOR_KEYS.items():
        assert len(signing.b64d(pub)) == 32
        assert signing.kid_for(pub) == kid
    assert set(signing.VENDOR_KEYS) <= set(signing.trusted_keys("license"))
