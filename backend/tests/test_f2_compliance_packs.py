"""F2 — Tier-2 compliance packs: HIPAA, NERC CIP, FFIEC, NIS2, NIST 800-53.

Adding a framework is a crosswalk table, so these assert the new packs are wired
into the same evidence engine as the Tier-1 packs (no new exercise logic)."""
from fastapi.testclient import TestClient

from app import compliance
from app.main import app

_TIER2 = {"hipaa", "nerc_cip", "ffiec", "nis2", "nist_800_53"}


# --------------------------------------------------------------------------- #
# data integrity
# --------------------------------------------------------------------------- #
def test_every_framework_has_a_crosswalk_and_tier():
    assert set(compliance.FRAMEWORKS) == set(compliance.CROSSWALK)
    assert set(compliance.FRAMEWORKS) == set(compliance.FRAMEWORK_TIER)
    # Tier-2 packs are present and tagged.
    assert _TIER2 <= set(compliance.FRAMEWORKS)
    assert all(compliance.FRAMEWORK_TIER[k] == 2 for k in _TIER2)


def test_crosswalks_reference_known_capabilities():
    caps = set(compliance.CAPABILITIES)
    for fw, cap_map in compliance.CROSSWALK.items():
        assert set(cap_map) <= caps, fw
        for refs in cap_map.values():
            assert all(isinstance(cid, str) and title for cid, title in refs)


# --------------------------------------------------------------------------- #
# API surface
# --------------------------------------------------------------------------- #
def test_frameworks_endpoint_lists_tier2_with_tier_field():
    with TestClient(app) as client:
        rows = client.get("/api/compliance/frameworks").json()
        by_key = {r["key"]: r for r in rows}
        assert _TIER2 <= set(by_key)
        assert by_key["hipaa"]["tier"] == 2
        assert by_key["pci"]["tier"] == 1
        assert "NIST SP 800-53" in by_key["nist_800_53"]["name"]


def _seeded_session_with_outcome(client):
    scenario_id = client.get("/api/scenarios").json()[0]["id"]
    sid = client.post("/api/sessions",
                      json={"scenario_id": scenario_id, "name": "f2 drill"}).json()["id"]
    client.post(f"/api/sessions/{sid}/start")
    # Log a 'met' observation so at least one control shows as demonstrated.
    objectives = client.get(f"/api/scenarios/{scenario_id}").json()["objectives"]
    client.post(f"/api/sessions/{sid}/observe",
                json={"objective_code": objectives[0]["code"], "rating": "met", "note": "ok"})
    return sid


def test_evidence_builds_for_each_tier2_pack():
    with TestClient(app) as client:
        sid = _seeded_session_with_outcome(client)
        for fw in _TIER2:
            ev = client.get(f"/api/sessions/{sid}/evidence?framework={fw}").json()
            assert len(ev["frameworks"]) == 1
            block = ev["frameworks"][0]
            assert block["key"] == fw
            assert block["controls"], f"{fw} produced no mapped controls"
            # Summary counts are coherent.
            s = block["summary"]
            assert s["controls"] == len(block["controls"])


def test_full_evidence_includes_all_eleven_frameworks():
    with TestClient(app) as client:
        sid = _seeded_session_with_outcome(client)
        ev = client.get(f"/api/sessions/{sid}/evidence").json()
        keys = {f["key"] for f in ev["frameworks"]}
        assert keys == set(compliance.FRAMEWORKS)


def test_tier2_pack_renders_to_markdown_and_pdf():
    with TestClient(app) as client:
        sid = _seeded_session_with_outcome(client)
        # Markdown-backed PDF export for a Tier-2 framework.
        r = client.get(f"/api/sessions/{sid}/evidence.pdf?framework=nist_800_53")
        assert r.status_code == 200 and r.content[:5] == b"%PDF-"
