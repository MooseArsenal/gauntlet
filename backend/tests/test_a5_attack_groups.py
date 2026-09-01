"""A5 — adversary emulation: real ATT&CK groups the proctor can pick.

Covers catalog integrity (every group's kill chain grounds in the bank, every
group generates a coherent scenario), sector-based recommendation, the random
picker, and the catalog endpoints — including mix-and-match (a chosen group with
a chosen attack-type template).
"""
from fastapi.testclient import TestClient

from app.authoring import attack_groups as ag
from app.authoring import catalog
from app.main import app


# --------------------------------------------------------------------------- #
# catalog integrity (unit)
# --------------------------------------------------------------------------- #
def test_groups_are_registered_as_actors():
    for key in ag.ATTACK_GROUPS:
        assert key in catalog.THREAT_ACTORS, key
        actor = catalog.THREAT_ACTORS[key]
        assert actor.get("is_attack_group") is True
        assert actor["attack_id"].startswith("G"), key


def test_every_group_kill_chain_grounds_in_the_bank():
    for key, g in ag.ATTACK_GROUPS.items():
        assert g["kill_chain"], key
        for scene in g["kill_chain"]:
            assert scene in catalog.INJECT_BANK, f"{key} -> missing scene {scene}"


def test_every_group_is_well_formed():
    for key, g in ag.ATTACK_GROUPS.items():
        assert g["name"] and g["label"] and g["description"], key
        assert g["aliases"] and g["sectors"] and g["techniques"], key
        # sectors use the normalised vocabulary
        for s in g["sectors"]:
            assert s in ag.SECTORS, f"{key}: unknown sector {s}"
        # objectives are (title, criteria) pairs
        for title, crit in g["objectives"]:
            assert title and crit, key


# --------------------------------------------------------------------------- #
# sector recommendation + random (unit)
# --------------------------------------------------------------------------- #
def test_recommend_by_sector_ranks_relevant_groups():
    fin = ag.recommend("financial")
    assert fin, "expected financial-sector adversaries"
    assert all("financial" in catalog.THREAT_ACTORS[k]["sectors"] for k in fin)
    # FIN7 (retail/hospitality/financial) should surface for finance.
    assert "fin7" in fin


def test_recommend_matches_free_text_sector():
    # Environments store a free string; matching is case-insensitive substring.
    assert ag.recommend("Financial Services") == ag.recommend("financial")
    assert ag.recommend("") == list(ag.ATTACK_GROUPS)  # empty -> everyone


def test_recommend_unknown_sector_is_empty():
    assert ag.recommend("astrology") == []


def test_random_group_is_stable_and_sector_biased():
    import random
    g = ag.random_group("energy", random.Random(0))
    assert g in ag.recommend("energy")
    # unknown sector falls back to the full set, never raises
    assert ag.random_group("astrology", random.Random(1)) in ag.ATTACK_GROUPS


# --------------------------------------------------------------------------- #
# endpoints + generation (API)
# --------------------------------------------------------------------------- #
def _env(client):
    return client.get("/api/environments").json()[0]["id"]


def test_attack_groups_endpoint_lists_groups():
    with TestClient(app) as client:
        rows = client.get("/api/catalog/attack-groups").json()
        keys = {r["key"] for r in rows}
        assert {"apt29", "fin7", "scattered_spider", "lazarus"} <= keys
        apt29 = next(r for r in rows if r["key"] == "apt29")
        assert apt29["attack_id"] == "G0016"
        assert apt29["aliases"] and apt29["techniques"] and apt29["kill_chain"]


def test_attack_groups_endpoint_filters_by_sector():
    with TestClient(app) as client:
        rows = client.get("/api/catalog/attack-groups", params={"sector": "healthcare"}).json()
        keys = {r["key"] for r in rows}
        assert keys, "expected healthcare adversaries"
        assert all("healthcare" in r["sectors"] for r in rows)


def test_random_attack_group_endpoint():
    with TestClient(app) as client:
        r = client.get("/api/catalog/attack-groups/random", params={"sector": "financial"})
        assert r.status_code == 200
        assert r.json()["key"] in ag.recommend("financial")


def test_every_group_generates_a_coherent_scenario():
    with TestClient(app) as client:
        env = _env(client)
        for key in ag.ATTACK_GROUPS:
            r = client.post("/api/scenarios/generate",
                            json={"environment_id": env, "actor_key": key})
            assert r.status_code == 201, f"{key}: {r.text}"
            scn = r.json()
            assert scn["injects"], key
            assert sum(1 for i in scn["injects"] if i["is_start"]) == 1, key
            assert scn["objectives"], key


def test_group_plus_template_mix_and_match():
    """A chosen adversary emulated through a chosen attack-type template:
    the group drives the kill chain, the template supplies narrative/scope/ROE."""
    with TestClient(app) as client:
        env = _env(client)
        r = client.post("/api/scenarios/generate", json={
            "environment_id": env, "actor_key": "apt29", "template_key": "network_pentest",
        })
        assert r.status_code == 201, r.text
        scn = r.json()
        assert scn["injects"]
        assert sum(1 for i in scn["injects"] if i["is_start"]) == 1
        # threat_actor label reflects the emulated group, not the template default
        assert "APT29" in scn["threat_actor"]


def test_generated_group_scenario_runs():
    with TestClient(app) as client:
        env = _env(client)
        scn = client.post("/api/scenarios/generate",
                          json={"environment_id": env, "actor_key": "scattered_spider"}).json()
        sid = client.post("/api/sessions", json={"scenario_id": scn["id"], "name": "ss"}).json()["id"]
        state = client.post(f"/api/sessions/{sid}/start").json()
        assert state["session"]["status"] == "running"
        assert state["current_inject"] is not None
