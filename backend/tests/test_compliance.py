"""Compliance crosswalk, evidence, and PDF export (M7 phase 2)."""
from fastapi.testclient import TestClient

from app import compliance
from app.main import app


def _run_with_outcomes(client, met_obj, missed_obj):
    scenario_id = client.get("/api/scenarios").json()[0]["id"]
    sid = client.post("/api/sessions", json={"scenario_id": scenario_id, "name": "ev"}).json()["id"]
    client.post(f"/api/sessions/{sid}/start")
    client.post(f"/api/sessions/{sid}/observe",
                json={"objective_code": met_obj, "rating": "met", "note": "ok"})
    client.post(f"/api/sessions/{sid}/observe",
                json={"objective_code": missed_obj, "rating": "missed", "note": "gap"})
    return sid


def test_frameworks_endpoint():
    with TestClient(app) as client:
        keys = {f["key"] for f in client.get("/api/compliance/frameworks").json()}
        assert {"pci", "dora", "nist_csf", "cis_v8", "iso_27001", "soc2"} <= keys


def test_evidence_maps_capability_to_controls_with_outcomes():
    with TestClient(app) as client:
        sid = _run_with_outcomes(client, met_obj="OBJ-1", missed_obj="OBJ-3")  # detect met, contain missed
        ev = client.get(f"/api/sessions/{sid}/evidence", params={"framework": "nist_csf"}).json()
        assert len(ev["frameworks"]) == 1
        controls = {c["id"]: c for c in ev["frameworks"][0]["controls"]}
        # detect -> DE.AE demonstrated; contain -> RS.MI gap
        assert controls["DE.AE"]["status"] == "demonstrated"
        assert controls["RS.MI"]["status"] == "gap"


def test_evidence_spans_all_frameworks():
    with TestClient(app) as client:
        sid = _run_with_outcomes(client, met_obj="OBJ-1", missed_obj="OBJ-3")
        ev = client.get(f"/api/sessions/{sid}/evidence").json()
        # Tier-1 (6) + Tier-2 (5) packs.
        from app.compliance import FRAMEWORKS
        assert len(ev["frameworks"]) == len(FRAMEWORKS)
        assert "not a compliance assessment" in ev["disclaimer"].lower()


def test_evidence_pdf_and_report_pdf():
    with TestClient(app) as client:
        sid = _run_with_outcomes(client, met_obj="OBJ-1", missed_obj="OBJ-3")
        # evidence PDF
        r = client.get(f"/api/sessions/{sid}/evidence.pdf")
        assert r.status_code == 200
        assert r.headers["content-type"] == "application/pdf"
        assert r.content[:4] == b"%PDF" and len(r.content) > 800
        # report PDF
        rep = client.post(f"/api/sessions/{sid}/reports", json={"audience": "grc"}).json()
        rp = client.get(f"/api/sessions/{sid}/reports/{rep['id']}.pdf")
        assert rp.status_code == 200 and rp.content[:4] == b"%PDF"


def test_render_markdown_smoke():
    ev = {"exercise": {"scenario": "S", "threat_actor": "T", "session": "run",
                       "exercise_type": "tabletop"},
          "disclaimer": "not a compliance assessment",
          "frameworks": [{"key": "pci", "name": "PCI-DSS v4.0",
                          "summary": {"controls": 1, "demonstrated": 1, "gaps": 0},
                          "controls": [{"id": "12.10.2", "title": "Test IR plan",
                                        "capabilities": ["govern"], "status": "demonstrated",
                                        "objectives": [{"code": "OBJ-1", "title": "x",
                                                        "status": "demonstrated"}]}]}]}
    md = compliance.render_markdown(ev)
    assert "PCI-DSS v4.0" in md and "12.10.2" in md
