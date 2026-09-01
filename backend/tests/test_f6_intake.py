"""F6 — automated environment intake: CMDB/EDR/SIEM/ASM importers, create vs
merge, and that imported controls actually drive adjudication."""
import json

from fastapi.testclient import TestClient

from app import intake
from app.main import app


def _auth(t):
    return {"Authorization": f"Bearer {t}"}


# --------------------------------------------------------------------------- #
# mappers (unit)
# --------------------------------------------------------------------------- #
def test_parse_json_list_and_wrapped():
    assert intake.parse("json", '[{"a":1}]') == [{"a": 1}]
    assert intake.parse("json", '{"result":[{"a":1}]}') == [{"a": 1}]


def test_parse_csv():
    rows = intake.parse("csv", "name,type\nDB-1,database\n")
    assert rows == [{"name": "DB-1", "type": "database"}]


def test_bad_source_and_format():
    import pytest
    with pytest.raises(intake.IntakeError):
        intake.build_import("nope", "json", "[]")
    with pytest.raises(intake.IntakeError):
        intake.build_import("cmdb", "xml", "<x/>")
    with pytest.raises(intake.IntakeError):
        intake.build_import("cmdb", "json", "{not json")


def test_technique_list_coercion():
    edr = intake.build_import("edr", "json",
                              json.dumps([{"product": "X", "techniques": "T1;T2|T3"}]))
    assert edr["controls"][0]["covers"] == ["T1", "T2", "T3"]


# --------------------------------------------------------------------------- #
# API — create
# --------------------------------------------------------------------------- #
def test_import_cmdb_creates_environment():
    with TestClient(app) as client:
        data = "name,type,criticality,owner\nDB-1,database,high,alice\nWEB-1,host,medium,bob\n"
        r = client.post("/api/environments/import",
                        json={"source": "cmdb", "format": "csv", "data": data, "name": "From CMDB"})
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["created"] is True
        assert body["imported"]["assets"] == 2
        env = body["environment"]
        assert env["name"] == "From CMDB"
        assert {a["name"] for a in env["assets"]} == {"DB-1", "WEB-1"}
        # Owners became personnel.
        assert {p["name"] for p in env["personnel"]} == {"alice", "bob"}


def test_import_asm_marks_external():
    with TestClient(app) as client:
        data = json.dumps([{"domain": "api.example.com", "severity": "high", "ports": "443"}])
        env = client.post("/api/environments/import",
                          json={"source": "asm", "format": "json", "data": data}).json()["environment"]
        asset = env["assets"][0]
        assert asset["type"] == "external" and asset["internet_facing"] is True


# --------------------------------------------------------------------------- #
# API — merge into existing
# --------------------------------------------------------------------------- #
def test_import_merges_into_existing_environment():
    with TestClient(app) as client:
        env_id = client.post("/api/environments", json={"name": "Base", "assets": [{"name": "SEED"}]}).json()["id"]
        edr = json.dumps([{"product": "Defender", "techniques": "T1003.001", "assets": "*", "efficacy": 0.9}])
        r = client.post("/api/environments/import",
                        json={"source": "edr", "format": "json", "data": edr, "environment_id": env_id})
        assert r.status_code == 201
        assert r.json()["created"] is False
        assert r.json()["imported"]["controls"] == 1
        env = client.get(f"/api/environments/{env_id}").json()
        # Seed asset preserved; EDR control appended.
        assert any(a["name"] == "SEED" for a in env["assets"])
        assert any(c["type"] == "edr" for c in env["controls"])


def test_imported_control_drives_adjudication():
    """An imported EDR control should actually detect its technique in a run."""
    with TestClient(app) as client:
        edr = json.dumps([{"product": "Defender", "techniques": "T1003.001",
                           "assets": "*", "efficacy": 0.95, "latency_min": 5}])
        env_id = client.post("/api/environments/import",
                             json={"source": "edr", "format": "json", "data": edr,
                                   "name": "EDR env"}).json()["environment"]["id"]
        scn = client.post("/api/scenarios", json={
            "environment_id": env_id, "name": "s",
            "injects": [{"code": "INJ-01", "title": "start", "is_start": True}],
        }).json()["id"]
        sid = client.post("/api/sessions", json={"scenario_id": scn, "name": "r"}).json()["id"]
        client.post(f"/api/sessions/{sid}/start")
        ruling = client.post(f"/api/sessions/{sid}/red-actions",
                             json={"techniques": ["T1003.001"], "target": "anything"}).json()["ruling"]
        assert ruling["detected"] is True


# --------------------------------------------------------------------------- #
# tenant isolation
# --------------------------------------------------------------------------- #
def test_import_merge_tenant_scoped():
    with TestClient(app) as client:
        # Owner (seeded default org) creates an env.
        env_id = client.post("/api/environments", json={"name": "Owned"}).json()["id"]
        tok = client.post("/api/auth/register", json={
            "org_name": "IntakeOther", "email": "f6-other@example.com", "password": "Str0ngPass!9",
        }).json()["access_token"]
        # A different tenant can't merge into it.
        r = client.post("/api/environments/import", headers=_auth(tok),
                        json={"source": "cmdb", "format": "csv", "data": "name\nX\n",
                              "environment_id": env_id})
        assert r.status_code == 404
