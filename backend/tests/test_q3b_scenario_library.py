"""Q3b — the built-in scenario library: every template generates a valid,
coherent scenario, and the catalog is internally consistent."""
from fastapi.testclient import TestClient

from app.authoring import catalog
from app.main import app

# The attack types the library must offer out of the box.
_EXPECTED = {
    "phishing_sim", "network_pentest", "social_engineering", "malware_deployment",
    "physical_intrusion", "insider_threat", "multi_vector", "appsec_ai", "attacker_modeling",
}


# --------------------------------------------------------------------------- #
# catalog integrity (unit)
# --------------------------------------------------------------------------- #
def test_library_covers_requested_attack_types():
    assert _EXPECTED <= set(catalog.SCENARIO_TEMPLATES)


def test_every_actor_kill_chain_key_exists_in_the_bank():
    for actor, spec in catalog.THREAT_ACTORS.items():
        for key in spec["kill_chain"]:
            assert key in catalog.INJECT_BANK, f"{actor} -> missing bank key {key}"


def test_every_template_points_at_a_real_actor():
    for tmpl, spec in catalog.SCENARIO_TEMPLATES.items():
        assert spec["actor"] in catalog.THREAT_ACTORS, tmpl


def test_bank_entries_are_well_formed():
    for key, e in catalog.INJECT_BANK.items():
        assert e.get("title") and e.get("narrative"), key
        assert isinstance(e.get("techniques", []), list)
        assert e.get("phase"), key


# --------------------------------------------------------------------------- #
# generation (API) — each template builds a runnable scenario
# --------------------------------------------------------------------------- #
def _env(client):
    return client.get("/api/environments").json()[0]["id"]


def test_catalog_lists_new_actors_and_templates():
    with TestClient(app) as client:
        actors = {a["key"] for a in client.get("/api/catalog/actors").json()}
        templates = {t["key"] for t in client.get("/api/catalog/templates").json()}
        assert {"pentester", "social_engineer", "appsec_ai", "assumed_breach"} <= actors
        assert _EXPECTED <= templates


def test_every_template_generates_a_valid_scenario():
    with TestClient(app) as client:
        env = _env(client)
        for tmpl in catalog.SCENARIO_TEMPLATES:
            r = client.post("/api/scenarios/generate",
                            json={"environment_id": env, "template_key": tmpl})
            assert r.status_code == 201, f"{tmpl}: {r.text}"
            scn = r.json()
            injects = scn["injects"]
            assert injects, tmpl
            # Coherent graph: exactly one start, objectives present.
            assert sum(1 for i in injects if i["is_start"]) == 1, tmpl
            assert scn["objectives"], tmpl


def test_generated_library_scenario_runs():
    """A generated pen-test scenario can start and advance like any other."""
    with TestClient(app) as client:
        env = _env(client)
        scn = client.post("/api/scenarios/generate",
                          json={"environment_id": env, "template_key": "network_pentest"}).json()
        sid = client.post("/api/sessions", json={"scenario_id": scn["id"], "name": "pt"}).json()["id"]
        state = client.post(f"/api/sessions/{sid}/start").json()
        assert state["session"]["status"] == "running"
        assert state["current_inject"] is not None
