"""A7 — custom adversary designer: design your own (real/fictitious) or random.

Covers the random composer, hand-designing + persistence, generating a scenario
from a custom adversary (the generator treats it like a built-in group),
validation, and org isolation.
"""
import random

from fastapi.testclient import TestClient

from app.authoring import designer
from app.main import app


# --------------------------------------------------------------------------- #
# random composer (unit)
# --------------------------------------------------------------------------- #
def test_random_adversary_is_coherent_and_grounded():
    for seed in range(6):
        d = designer.random_adversary(random.Random(seed))
        assert d["name"] and d["motivation"]
        assert d["is_fictitious"] is True
        assert len(d["kill_chain"]) >= 3
        assert designer.validate_kill_chain(d["kill_chain"]) == []
        assert d["objectives"]


def test_validate_kill_chain_rejects_unknown_scenes():
    assert designer.validate_kill_chain([]) != []
    assert any("nope" in p for p in designer.validate_kill_chain(["phish_invoice", "nope"]))


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #
def test_random_endpoint_returns_a_draft():
    with TestClient(app) as client:
        d = client.post("/api/adversaries/random").json()
        assert d["kill_chain"] and d["objectives"]
        assert d["is_fictitious"] is True


def test_design_persist_and_generate_a_scenario():
    with TestClient(app) as client:
        env = client.post("/api/environments", json={"name": "e", "sector": "energy"}).json()["id"]
        # Hand-design a fictitious adversary.
        adv = client.post("/api/adversaries", json={
            "name": "Obsidian Kraken",
            "description": "A bespoke sabotage crew for the ICS drill.",
            "motivation": "sabotage",
            "is_fictitious": True,
            "sectors": ["energy", "critical-infrastructure"],
            "kill_chain": ["exploit_public", "c2_beacon", "lateral_smb", "ransomware_deploy"],
        })
        assert adv.status_code == 201, adv.text
        adv = adv.json()
        assert adv["key"]
        assert adv["objectives"]  # derived when omitted
        # It shows up in the org's list.
        keys = {a["key"] for a in client.get("/api/adversaries").json()}
        assert adv["key"] in keys
        # The generator emulates it exactly like a built-in group.
        scn = client.post("/api/scenarios/generate",
                          json={"environment_id": env, "actor_key": adv["key"]})
        assert scn.status_code == 201, scn.text
        scn = scn.json()
        assert sum(1 for i in scn["injects"] if i["is_start"]) == 1
        assert "Obsidian Kraken" in scn["threat_actor"]


def test_create_rejects_bad_kill_chain():
    with TestClient(app) as client:
        r = client.post("/api/adversaries", json={"name": "Bad", "kill_chain": ["not_a_scene"]})
        assert r.status_code == 422
        assert "kill_chain" in r.json()["detail"]


def test_custom_adversary_is_org_scoped(monkeypatch):
    """One org's custom adversary is not usable by another org."""
    monkeypatch.setenv("GAUNTLET_AUTH_OPTIONAL", "0")
    with TestClient(app) as client:
        a = client.post("/api/auth/register", json={
            "org_name": "OrgA", "email": "a@ex.com", "password": "Str0ngPass!9"}).json()["access_token"]
        ha = {"Authorization": f"Bearer {a}"}
        adv = client.post("/api/adversaries", headers=ha, json={
            "name": "Secret Wolverine", "kill_chain": ["phish_invoice", "malware_exec"]}).json()
        envb_admin = client.post("/api/auth/register", json={
            "org_name": "OrgB", "email": "b@ex.com", "password": "Str0ngPass!9"}).json()["access_token"]
        hb = {"Authorization": f"Bearer {envb_admin}"}
        envb = client.post("/api/environments", headers=hb, json={"name": "eb"}).json()["id"]
        # OrgB cannot generate from OrgA's adversary key.
        r = client.post("/api/scenarios/generate", headers=hb,
                        json={"environment_id": envb, "actor_key": adv["key"]})
        assert r.status_code == 400  # unknown threat actor for this org
