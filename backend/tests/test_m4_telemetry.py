"""M4 — the telemetry loop: real alerts recorded on the timeline and compared
with the adjudicated expectation, per action and per technique."""
import uuid

from fastapi.testclient import TestClient

from app.main import app
from app.telemetry import map_alerts

PW = "Str0ngPass!9"


def _h(t):
    return {"Authorization": f"Bearer {t}"}


def _org(client):
    o = uuid.uuid4().hex[:8]
    t = client.post("/api/auth/register", json={
        "org_name": f"O{o}", "email": f"a{o}@ex.com", "password": PW}).json()["access_token"]
    return o, t


def _user(client, ha, o, role):
    em = f"{role}{o}@ex.com"
    client.post("/api/auth/users", headers=ha, json={"email": em, "password": PW, "role": role})
    return client.post("/api/auth/login", json={"email": em, "password": PW}).json()["access_token"]


def _world(client, ha):
    env = client.post("/api/environments", headers=ha, json={
        "name": "e", "assets": [{"code": "SRV-01", "name": "srv"}, {"code": "WKS-02", "name": "wks"}],
        "detections": [{"name": "EDR", "covers": ["T1003"], "assets": ["*"], "efficacy": 1.0, "latency_min": 4}]}).json()["id"]
    scn = client.post("/api/scenarios", headers=ha, json={
        "environment_id": env, "name": "s",
        "injects": [{"code": "INJ-01", "title": "start", "narrative": "n", "is_start": True}]}).json()["id"]
    sid = client.post("/api/sessions", headers=ha, json={"scenario_id": scn, "name": "run"}).json()["id"]
    return sid


def test_map_alerts_accepts_common_export_columns():
    rows = [
        {"rule_name": "LSASS access", "mitre_technique": "T1003.001", "hostname": "SRV-01", "product": "EDR", "severity": "high", "@timestamp": "2026-09-02T10:00:00Z", "alert_id": "A1"},
        {"title": "Odd VPN login", "technique": "T1078; T1110", "host": "vpn-gw"},
        {"nothing": "useful"},
    ]
    out = map_alerts(rows)
    assert len(out) == 2
    assert out[0] == {"alert": "LSASS access", "techniques": ["T1003.001"], "asset": "SRV-01", "source": "edr",
                      "severity": "high", "observed_at": "2026-09-02T10:00:00Z", "external_ref": "A1"}
    assert out[1]["techniques"] == ["T1078", "T1110"] and out[1]["source"] == "siem"


def test_compare_classifies_every_action():
    with TestClient(app) as c:
        o, t = _org(c); h = _h(t)
        sid = _world(c, h)
        # nothing before start
        assert c.post(f"/api/sessions/{sid}/telemetry", headers=h, json={"alert": "x"}).status_code == 409
        c.post(f"/api/sessions/{sid}/start", headers=h)
        # four actions: expected-detected (T1003 on SRV-01 twice), expected-missed (T1486, T1566)
        for techs, asset in ((["T1003"], "SRV-01"), (["T1003"], "WKS-02"), (["T1486"], "SRV-01"), (["T1566.001"], "")):
            assert c.post(f"/api/sessions/{sid}/adjudicate", headers=h,
                          json={"techniques": techs, "target_asset": asset, "description": "m"}).status_code == 200
        # alerts: one confirms the first T1003 (sub-technique on the same host), one is a surprise for T1486,
        # one matches nothing
        r = c.post(f"/api/sessions/{sid}/telemetry", headers=h, json={
            "alert": "Credential dumping via LSASS", "techniques": ["T1003.001"], "asset": "srv-01", "source": "edr"})
        assert r.status_code == 201 and r.json()["kind"] == "telemetry"
        assert c.post(f"/api/sessions/{sid}/telemetry", headers=h, json={
            "alert": "Ransomware behaviour", "techniques": ["T1486"], "asset": "SRV-01", "source": "edr"}).status_code == 201
        assert c.post(f"/api/sessions/{sid}/telemetry", headers=h, json={
            "alert": "Port scan", "techniques": ["T1046"], "source": "ndr"}).status_code == 201
        cmp = c.get(f"/api/sessions/{sid}/telemetry/compare", headers=h).json()
        assert cmp["actions"] == 4 and cmp["alerts"] == 3
        assert cmp["counts"] == {"confirmed": 1, "silent_gap": 1, "surprise": 1, "missed": 1}
        assert cmp["expected_rate"] == 0.5 and cmp["observed_rate"] == 0.5 and cmp["model_agreement"] == 0.5
        outcomes = [r["outcome"] for r in cmp["rows"]]
        assert outcomes == ["confirmed", "silent_gap", "surprise", "missed"]
        assert cmp["rows"][0]["alerts"][0]["alert"] == "Credential dumping via LSASS"
        assert cmp["rows"][0]["observed_latency_min"] is not None
        assert [u["alert"] for u in cmp["unmatched_alerts"]] == ["Port scan"]
        tech = {b["technique"]: b for b in cmp["by_technique"]}
        assert tech["T1003"] == {"technique": "T1003", "actions": 2, "expected": 2, "observed": 1}
        # the alerts are on the signed chain
        assert c.get(f"/api/sessions/{sid}/verify", headers=h).json()["chain_valid"] is True
        assert len(c.get(f"/api/sessions/{sid}/telemetry", headers=h).json()) == 3
        # reports carry the section; the certificate carries the numbers
        rep = c.post(f"/api/sessions/{sid}/reports", headers=h, json={"audience": "technical"}).json()["content"]
        assert "expected vs observed" in rep and "Silent gap" in rep and "Port scan" in rep
        ex = c.post(f"/api/sessions/{sid}/reports", headers=h, json={"audience": "executive"}).json()["content"]
        assert "What the tools saw" in ex
        c.post(f"/api/sessions/{sid}/complete", headers=h)
        cert = c.post(f"/api/sessions/{sid}/certificate", headers=h).json()
        assert cert["payload"]["telemetry"] == {"alerts": 3, "observed_rate": 0.5, "model_agreement": 0.5,
                                                "confirmed": 1, "silent_gap": 1, "surprise": 1, "missed": 1}
        v = c.get(f"/api/certificates/{cert['serial']}/verify").json()
        assert v["record"]["telemetry"]["alerts"] == 3
        # telemetry can still be recorded after completion (post-exercise SIEM review)
        assert c.post(f"/api/sessions/{sid}/telemetry", headers=h, json={"alert": "late", "techniques": ["T1003"]}).status_code == 201


def test_import_json_and_csv_exports():
    with TestClient(app) as c:
        o, t = _org(c); h = _h(t)
        sid = _world(c, h)
        c.post(f"/api/sessions/{sid}/start", headers=h)
        js = '{"results": [{"rule_name": "A", "technique_id": "T1003", "host": "SRV-01"}, {"name": "B", "techniques": ["T1078"]}, {"noise": 1}]}'
        r = c.post(f"/api/sessions/{sid}/telemetry/import", headers=h, json={"format": "json", "data": js})
        assert r.status_code == 201 and r.json() == {"recorded": 2, "skipped": 1}
        csv_data = "alert,technique,host,source,time\nC,T1486,SRV-01,edr,2026-09-02T09:00:00Z\n"
        r = c.post(f"/api/sessions/{sid}/telemetry/import", headers=h, json={"format": "csv", "data": csv_data})
        assert r.status_code == 201 and r.json()["recorded"] == 1
        assert c.post(f"/api/sessions/{sid}/telemetry/import", headers=h, json={"format": "json", "data": "{bad"}).status_code == 422
        assert c.post(f"/api/sessions/{sid}/telemetry/import", headers=h, json={"format": "xml", "data": "<a/>"}).status_code == 422
        assert len(c.get(f"/api/sessions/{sid}/telemetry", headers=h).json()) == 3
        assert c.post(f"/api/sessions/{sid}/telemetry", headers=h, json={"alert": "x", "techniques": ["nope"]}).status_code == 422


def test_telemetry_is_role_and_tenant_scoped():
    with TestClient(app) as c:
        o, t = _org(c); h = _h(t)
        sid = _world(c, h)
        c.post(f"/api/sessions/{sid}/start", headers=h)
        he = _h(_user(c, h, o, "evaluator")); hp = _h(_user(c, h, o, "participant"))
        assert c.post(f"/api/sessions/{sid}/telemetry", headers=he, json={"alert": "ok"}).status_code == 201
        assert c.post(f"/api/sessions/{sid}/telemetry", headers=hp, json={"alert": "no"}).status_code == 403
        assert c.get(f"/api/sessions/{sid}/telemetry/compare", headers=hp).status_code == 403
        o2, t2 = _org(c)
        assert c.get(f"/api/sessions/{sid}/telemetry/compare", headers=_h(t2)).status_code == 404
        assert c.post(f"/api/sessions/{sid}/telemetry", headers=_h(t2), json={"alert": "x"}).status_code == 404
