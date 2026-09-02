"""M7 — sector benchmarking: a modelled reference from the library, and a
k-anonymous instance cohort that only opted-in organisations join and see."""
import uuid

from fastapi.testclient import TestClient

from app import benchmark
from app.main import app

PW = "Str0ngPass!9"


def _h(t):
    return {"Authorization": f"Bearer {t}"}


def _org(client):
    o = uuid.uuid4().hex[:8]
    t = client.post("/api/auth/register", json={
        "org_name": f"O{o}", "email": f"a{o}@ex.com", "password": PW}).json()["access_token"]
    return o, t


def _exercise(client, h, sector, detected_ratio):
    env = client.post("/api/environments", headers=h, json={
        "name": f"e-{uuid.uuid4().hex[:4]}", "sector": sector, "assets": [{"code": "SRV-01", "name": "srv"}],
        "detections": [{"name": "EDR", "covers": ["T1003"], "assets": ["*"], "efficacy": 1.0, "latency_min": 5}]}).json()["id"]
    scn = client.post("/api/scenarios", headers=h, json={
        "environment_id": env, "name": "s",
        "injects": [{"code": "INJ-01", "title": "t", "narrative": "n", "is_start": True}]}).json()["id"]
    sid = client.post("/api/sessions", headers=h, json={"scenario_id": scn, "name": "run"}).json()["id"]
    client.post(f"/api/sessions/{sid}/start", headers=h)
    for i in range(4):
        tech = "T1003" if i < detected_ratio * 4 else "T1486"
        client.post(f"/api/sessions/{sid}/adjudicate", headers=h, json={"techniques": [tech], "target_asset": "SRV-01", "description": "m"})
    client.post(f"/api/sessions/{sid}/complete", headers=h)
    return sid


def test_reference_covers_every_library_sector_and_is_a_model_yardstick():
    ref = benchmark.reference()
    assert {"Healthcare", "Utilities (water)", "Manufacturing", "Technology (SaaS)",
            "Public sector (local government)", "Higher education"} <= set(ref)
    for r in ref.values():
        assert r["actions"] > 0 and 0 <= r["detection_rate"] <= 1 and r["packs"]
    assert ref["Healthcare"]["detection_rate"] > ref["Public sector (local government)"]["detection_rate"]


def test_benchmark_is_opt_in_and_k_anonymous():
    with TestClient(app) as c:
        orgs = [_org(c) for _ in range(4)]
        # three other orgs complete a healthcare exercise each with different results
        for (o, t), ratio in zip(orgs[1:], (0.25, 0.5, 1.0)):
            _exercise(c, _h(t), "Healthcare", ratio)
        me = _h(orgs[0][1])
        _exercise(c, me, "Healthcare", 0.75)
        # not opted in: reference only, no cohort
        b = c.get("/api/analytics/benchmark", headers=me).json()
        assert b["opt_in"] is False and b["k_anonymity"] == 3
        hc = next(r for r in b["sectors"] if r["sector"] == "Healthcare")
        assert hc["own"]["detection_rate"] == 0.75 and hc["own"]["mean_time_to_detect_min"] == 5.0
        assert hc["reference"]["detection_rate"] is not None and "vs_reference" in hc
        assert hc["cohort"] is None
        # opting in is admin-only
        em = f"f{orgs[0][0]}@ex.com"
        c.post("/api/auth/users", headers=me, json={"email": em, "password": PW, "role": "facilitator"})
        tf = c.post("/api/auth/login", json={"email": em, "password": PW}).json()["access_token"]
        assert c.post("/api/analytics/benchmark/opt-in", headers=_h(tf), json={"opt_in": True}).status_code == 403
        assert c.post("/api/analytics/benchmark/opt-in", headers=me, json={"opt_in": True}).json()["opt_in"] is True
        # opted in, but the others are not: suppressed (0 of 3 organisations)
        hc = next(r for r in c.get("/api/analytics/benchmark", headers=me).json()["sectors"] if r["sector"] == "Healthcare")
        assert hc["cohort"] is None or hc["cohort"].get("suppressed")
        # two others opt in: still below k
        for o, t in orgs[1:3]:
            c.post("/api/analytics/benchmark/opt-in", headers=_h(t), json={"opt_in": True})
        hc = next(r for r in c.get("/api/analytics/benchmark", headers=me).json()["sectors"] if r["sector"] == "Healthcare")
        assert hc["cohort"]["suppressed"] is True and hc["cohort"]["organisations"] == 2
        # the third opts in: the cohort appears, as a median of per-org medians, excluding me
        c.post("/api/analytics/benchmark/opt-in", headers=_h(orgs[3][1]), json={"opt_in": True})
        b = c.get("/api/analytics/benchmark", headers=me).json()
        hc = next(r for r in b["sectors"] if r["sector"] == "Healthcare")
        assert hc["cohort"]["organisations"] == 3 and hc["cohort"]["exercises"] == 3
        assert hc["cohort"]["detection_rate"] == 0.5 and hc["vs_cohort"]["detection_rate"] == 0.25
        # no organisation names or ids appear anywhere in the response
        text = str(b)
        assert all(f"O{o}" not in text for o, _ in orgs)
        # participants cannot read it
        em2 = f"p{orgs[0][0]}@ex.com"
        c.post("/api/auth/users", headers=me, json={"email": em2, "password": PW, "role": "participant"})
        tp = c.post("/api/auth/login", json={"email": em2, "password": PW}).json()["access_token"]
        assert c.get("/api/analytics/benchmark", headers=_h(tp)).status_code == 403


def test_executive_report_carries_the_modelled_expectation():
    with TestClient(app) as c:
        o, t = _org(c); h = _h(t)
        sid = _exercise(c, h, "Healthcare", 0.5)
        rep = c.post(f"/api/sessions/{sid}/reports", headers=h, json={"audience": "executive"}).json()["content"]
        assert "modelled expectation" in rep and "Healthcare" in rep and "not survey data" in rep
