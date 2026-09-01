"""YAML scenario import/export/validation and state-driven branching (M7)."""
from pathlib import Path

from fastapi.testclient import TestClient

from app import scenario_io
from app.main import app

DEEP_YAML = (Path(__file__).resolve().parents[2] / "scenarios" / "ransomware-deep.yaml").read_text()


def _env(client):
    return client.post("/api/environments", json={"name": "io-env"}).json()["id"]


def test_deep_scenario_validates_clean():
    data = scenario_io.load_yaml(DEEP_YAML)
    result = scenario_io.validate(data)
    assert result["errors"] == [], result["errors"]


def test_validate_endpoint_flags_dangling_goto():
    bad = """
    name: Bad
    injects:
      - {code: A, is_start: true, branches: [{when: proctor_choice, goto: NOPE}]}
    """
    with TestClient(app) as client:
        r = client.post("/api/scenarios/validate", json={"yaml": bad}).json()
        assert any("NOPE" in e for e in r["errors"])


def test_import_export_round_trips():
    with TestClient(app) as client:
        env_id = _env(client)
        scn = client.post("/api/scenarios/import",
                          json={"environment_id": env_id, "yaml": DEEP_YAML}).json()
        assert len(scn["injects"]) == 11
        assert scn["variables"] == {"contained": False, "backups_intact": True,
                                    "domain_compromised": False}

        exported = client.get(f"/api/scenarios/{scn['id']}/export").text
        # The exported YAML re-validates cleanly.
        assert scenario_io.validate(scenario_io.load_yaml(exported))["errors"] == []


def _import(client, env_id):
    return client.post("/api/scenarios/import",
                       json={"environment_id": env_id, "yaml": DEEP_YAML}).json()["id"]


def test_state_guards_hide_ineligible_branches():
    with TestClient(app) as client:
        env_id = _env(client)
        scn_id = _import(client, env_id)
        sid = client.post("/api/sessions", json={"scenario_id": scn_id, "name": "guards"}).json()["id"]
        client.post(f"/api/sessions/{sid}/start")
        # Walk to INJ-08 on the clean path (backups_intact stays true, domain false).
        client.post(f"/api/sessions/{sid}/advance", json={"when": "proctor_choice"})  # 01->03
        client.post(f"/api/sessions/{sid}/advance", json={"when": "proctor_choice"})  # 03->04
        client.post(f"/api/sessions/{sid}/advance",
                    json={"when": "action_taken", "trigger": "isolate_host"})           # 04->05
        client.post(f"/api/sessions/{sid}/advance", json={"when": "proctor_choice"})   # 05->08
        state = client.get(f"/api/sessions/{sid}").json()
        assert state["current_inject"]["code"] == "INJ-08"
        gotos = [b["goto"] for b in state["available_branches"]]
        # The disclosure branch is guarded on domain_compromised == true -> hidden.
        assert "INJ-11" not in gotos
        assert "INJ-09" in gotos  # recovery is eligible (backups intact)


def test_accumulated_state_routes_to_disclosure_ending():
    with TestClient(app) as client:
        env_id = _env(client)
        scn_id = _import(client, env_id)
        sid = client.post("/api/sessions", json={"scenario_id": scn_id, "name": "disclosure"}).json()["id"]
        client.post(f"/api/sessions/{sid}/start")
        client.post(f"/api/sessions/{sid}/advance", json={"when": "proctor_choice"})  # 01->03
        client.post(f"/api/sessions/{sid}/advance", json={"when": "proctor_choice"})  # 03->04
        client.post(f"/api/sessions/{sid}/advance", json={"when": "timeout"})          # 04->06 (no containment)
        client.post(f"/api/sessions/{sid}/advance", json={"when": "proctor_choice"})  # 06->08, sets domain_compromised
        st = client.get(f"/api/sessions/{sid}").json()
        assert st["state"]["domain_compromised"] is True
        # Now the guarded disclosure branch becomes eligible and takes priority.
        client.post(f"/api/sessions/{sid}/advance", json={"when": "proctor_choice"})  # 08->11
        final = client.get(f"/api/sessions/{sid}").json()
        assert final["current_inject"]["code"] == "INJ-11"
        assert final["terminal"] is True
