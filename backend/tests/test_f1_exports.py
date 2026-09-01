"""F1 — additional export formats: CSV/JSON timeline, DOCX reports & evidence,
and branded PDF. Runs over the seeded tabletop (AUTH_OPTIONAL default admin)."""
import csv
import io
import json

from fastapi.testclient import TestClient

from app import exports, pdf
from app.main import app


def _running_session(client):
    """A started session with a few timeline events and a report."""
    scenario_id = client.get("/api/scenarios").json()[0]["id"]
    sid = client.post("/api/sessions",
                      json={"scenario_id": scenario_id, "name": "export drill"}).json()["id"]
    client.post(f"/api/sessions/{sid}/start")
    client.post(f"/api/sessions/{sid}/advance",
                json={"when": "action_taken", "trigger": "investigate_and_block"})
    client.post(f"/api/sessions/{sid}/observe",
                json={"objective_code": "OBJ-2", "rating": "met", "note": "Triaged."})
    return sid


# --------------------------------------------------------------------------- #
# unit-level render checks
# --------------------------------------------------------------------------- #
def test_markdown_to_docx_is_a_valid_zip_with_content():
    data = exports.markdown_to_docx("Title", "# H1\n\n- bullet\n\n| A | B |\n|---|---|\n| 1 | 2 |\n")
    assert data[:2] == b"PK"  # docx is a zip
    from docx import Document
    doc = Document(io.BytesIO(data))
    text = "\n".join(p.text for p in doc.paragraphs)
    assert "Title" in text
    assert len(doc.tables) == 1


def test_branded_pdf_has_footer_pagenumbers():
    out = pdf.render("Report", "# Section\n\nbody text\n", brand="AcmeSOC")
    assert out[:5] == b"%PDF-"
    assert len(out) > 800


# --------------------------------------------------------------------------- #
# CSV timeline
# --------------------------------------------------------------------------- #
def test_timeline_csv_export():
    with TestClient(app) as client:
        sid = _running_session(client)
        r = client.get(f"/api/sessions/{sid}/timeline.csv")
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/csv")
        assert "attachment" in r.headers["content-disposition"]
        rows = list(csv.reader(io.StringIO(r.text)))
        assert rows[0] == ["seq", "at", "game_clock", "kind", "ref", "payload", "hash"]
        assert len(rows) >= 2  # header + at least one event


# --------------------------------------------------------------------------- #
# JSON timeline
# --------------------------------------------------------------------------- #
def test_timeline_json_export():
    with TestClient(app) as client:
        sid = _running_session(client)
        r = client.get(f"/api/sessions/{sid}/timeline.json")
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("application/json")
        data = json.loads(r.text)
        assert data["session"]["id"] == sid
        assert data["scenario"]["name"]
        assert len(data["timeline"]) >= 1
        # Each event carries the hash-chain fields.
        assert {"seq", "at", "kind", "hash", "prev_hash"} <= set(data["timeline"][0])
        assert len(data["observations"]) >= 1


# --------------------------------------------------------------------------- #
# DOCX report + evidence
# --------------------------------------------------------------------------- #
_DOCX_MIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"


def test_report_docx_export():
    with TestClient(app) as client:
        sid = _running_session(client)
        rep = client.post(f"/api/sessions/{sid}/reports", json={"audience": "executive"}).json()
        r = client.get(f"/api/sessions/{sid}/reports/{rep['id']}.docx")
        assert r.status_code == 200
        assert r.headers["content-type"].startswith(_DOCX_MIME)
        assert r.content[:2] == b"PK"

        # Wrong session can't reach the report.
        other = client.post("/api/sessions",
                            json={"scenario_id": client.get("/api/scenarios").json()[0]["id"],
                                  "name": "other"}).json()["id"]
        assert client.get(f"/api/sessions/{other}/reports/{rep['id']}.docx").status_code == 404


def test_evidence_docx_export():
    with TestClient(app) as client:
        sid = _running_session(client)
        r = client.get(f"/api/sessions/{sid}/evidence.docx")
        assert r.status_code == 200
        assert r.content[:2] == b"PK"


def test_export_endpoints_tenant_scoped():
    """A second org cannot export a first org's session."""
    with TestClient(app) as client:
        # Owner (seeded default admin, auth-optional) creates a session.
        sid = _running_session(client)
        # A real, separate tenant.
        tok = client.post("/api/auth/register", json={
            "org_name": "OtherCo", "email": "f1-other@example.com", "password": "Str0ngPass!9",
        }).json()["access_token"]
        h = {"Authorization": f"Bearer {tok}"}
        assert client.get(f"/api/sessions/{sid}/timeline.csv", headers=h).status_code == 404
        assert client.get(f"/api/sessions/{sid}/timeline.json", headers=h).status_code == 404
        assert client.get(f"/api/sessions/{sid}/evidence.docx", headers=h).status_code == 404
