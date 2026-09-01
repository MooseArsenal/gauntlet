"""Full-stack integration: one realistic flow that touches every milestone and
proves they compose — not just that each feature works in isolation.

M1 domain + MSEL + adjudication + timeline · M2 generation + delivery ·
M3 fog-of-war + roll-up · M4 live-inject gate + program analytics ·
M5 auth + tenancy + RBAC + signed timeline · M6 real-time advance path.
"""
from fastapi.testclient import TestClient

from app import models, scheduler, session_ops
from app.database import SessionLocal
from app.main import app


def _reg(client, org, email, pw="Str0ngPass!9"):
    return client.post("/api/auth/register",
                       json={"org_name": org, "email": email, "password": pw}).json()["access_token"]


def _h(tok):
    return {"Authorization": f"Bearer {tok}"}


def test_end_to_end_across_all_milestones():
    with TestClient(app) as client:
        # --- M5: two organisations -------------------------------------- #
        admin = _reg(client, "Integration Co", "int-admin@example.com")
        client.post("/api/auth/users", headers=_h(admin),
                    json={"email": "int-eval@example.com", "password": "Str0ngPass!9",
                          "role": "evaluator"})
        evaluator = client.post("/api/auth/login",
                                json={"email": "int-eval@example.com", "password": "Str0ngPass!9"}
                                ).json()["access_token"]
        other = _reg(client, "Rival Inc", "rival@example.com")

        # --- M1: environment intake ------------------------------------- #
        env = client.post("/api/environments", headers=_h(admin), json={
            "name": "Integration Bank", "sector": "fin",
            "assets": [{"code": "APP-1", "name": "App host", "zone": "app"},
                       {"code": "WKS-1", "name": "Workstation", "zone": "user"}],
            "controls": [{"name": "EDR", "covers": ["T1003.001", "T1204.002", "T1021.002"],
                          "assets": ["*"], "efficacy": 0.8, "latency_min": 8}],
            "deception_assets": [{"name": "canary", "covers": ["T1021.002"], "assets": ["APP-1"],
                                  "efficacy": 1.0, "latency_min": 1}],
            "crown_jewels": ["APP-1"],
            "visibility": {"blue_cell": ["assets", "controls", "crown_jewels"],
                           "white_cell": ["assets", "controls", "detections", "deception_assets",
                                          "playbooks", "policies", "personnel", "crown_jewels"]},
        }).json()
        env_id = env["id"]

        # --- M2: generate a grounded scenario --------------------------- #
        scn = client.post("/api/scenarios/generate", headers=_h(admin),
                          json={"environment_id": env_id, "template_key": "ransomware_finance",
                                "name": "Integration drill"}).json()
        scn_id = scn["id"]
        assert len(scn["injects"]) >= 5
        # techniques were grounded onto real assets
        assert any(i["target_asset"] in ("APP-1", "WKS-1") for i in scn["injects"] if i["target_asset"])

        # M5: the rival org cannot see any of it
        assert client.get(f"/api/environments/{env_id}", headers=_h(other)).status_code == 404
        assert client.get(f"/api/scenarios/{scn_id}", headers=_h(other)).status_code == 404

        # M2: delivery renders the first inject in its channel
        first_inject = client.get(f"/api/scenarios/{scn_id}", headers=_h(admin)).json()["injects"][0]
        deliv = client.get(f"/api/injects/{first_inject['id']}/delivery", headers=_h(admin)).json()
        assert deliv["headline"] == first_inject["title"]

        # --- M1/M6: run the scenario to a terminal state ---------------- #
        sid = client.post("/api/sessions", headers=_h(admin),
                          json={"scenario_id": scn_id, "name": "run A"}).json()["id"]
        client.post(f"/api/sessions/{sid}/start", headers=_h(admin))
        # adjudicate a credential-dump against the environment's EDR
        adj = client.post(f"/api/sessions/{sid}/adjudicate", headers=_h(admin),
                          json={"techniques": ["T1003.001"], "target_asset": "APP-1"}).json()
        assert adj["ruling"]["detected"] is True

        # M5 RBAC: evaluator may observe, may not author
        assert client.post("/api/scenarios", headers=_h(evaluator),
                           json={"environment_id": env_id, "name": "x"}).status_code == 403
        assert client.post(f"/api/sessions/{sid}/observe", headers=_h(evaluator),
                           json={"objective_code": "OBJ-1", "rating": "missed",
                                 "note": "slow triage"}).status_code == 201

        # drive to the end via proctor choices
        for _ in range(20):
            st = client.get(f"/api/sessions/{sid}", headers=_h(admin)).json()
            if st["terminal"]:
                break
            client.post(f"/api/sessions/{sid}/advance", headers=_h(admin),
                        json={"when": "proctor_choice"})
        assert client.get(f"/api/sessions/{sid}", headers=_h(admin)).json()["terminal"] is True

        # --- M3: fog-of-war --------------------------------------------- #
        blue = client.get(f"/api/sessions/{sid}/cell/blue_cell", headers=_h(admin)).json()
        white = client.get(f"/api/sessions/{sid}/cell/white_cell", headers=_h(admin)).json()
        assert "adjudication" not in {e["kind"] for e in blue["timeline"]}
        assert "adjudication" in {e["kind"] for e in white["timeline"]}
        env_blue = client.get(f"/api/environments/{env_id}/view/blue_cell",
                              headers=_h(admin), params={"scenario_id": scn_id}).json()
        assert env_blue["deception_assets"] == []  # hidden from the blue cell

        # --- M5: the timeline is signed and intact ---------------------- #
        assert client.get(f"/api/sessions/{sid}/verify", headers=_h(admin)).json()["chain_valid"] is True

        # --- M4: authorization-gated live inject ------------------------ #
        live_sid = client.post("/api/sessions", headers=_h(admin),
                               json={"scenario_id": scn_id, "name": "sandbox", "mode": "sandbox"}
                               ).json()["id"]
        # refused before authorization
        assert client.post(f"/api/sessions/{live_sid}/live-inject", headers=_h(admin),
                           json={"technique": "T1003.001", "target": "APP-1"}).status_code == 403
        client.post(f"/api/sessions/{live_sid}/authorize", headers=_h(admin),
                    json={"scope": ["APP-1"], "authorized_by": "CISO"})
        li = client.post(f"/api/sessions/{live_sid}/live-inject", headers=_h(admin),
                        json={"technique": "T1003.001", "target": "APP-1"}).json()
        assert li["executed"] and li["adapter"] == "simulation" and li["ruling"]["detected"]
        # still refused outside the authorized scope
        assert client.post(f"/api/sessions/{live_sid}/live-inject", headers=_h(admin),
                           json={"technique": "T1003.001", "target": "WKS-1"}).status_code == 403

        # --- M1: audience reports --------------------------------------- #
        for audience in ("executive", "technical", "grc", "training"):
            r = client.post(f"/api/sessions/{sid}/reports", headers=_h(admin),
                            json={"audience": audience})
            assert r.status_code == 201 and len(r.json()["content"]) > 100

        # --- M3: roll-up across runs ------------------------------------ #
        rollup = client.get(f"/api/scenarios/{scn_id}/rollup", headers=_h(admin)).json()
        assert rollup["totals"]["sessions"] >= 2

        # --- M4: program analytics scoped to this org ------------------- #
        cov = client.get("/api/program/coverage", headers=_h(admin)).json()
        techs = {t["technique"]: t for t in cov["techniques"]}
        assert techs.get("T1003.001", {}).get("tested") is True
        imp = client.get("/api/program/improvements", headers=_h(admin)).json()
        assert any(i["objective_code"] == "OBJ-1" for i in imp["items"])
        # the rival org's program is empty — full isolation end to end
        assert client.get("/api/program/coverage", headers=_h(other)).json()["techniques"] == []

        # --- M6: the auto-advance path works on this generated scenario -- #
        auto_id = client.post("/api/sessions", headers=_h(admin),
                              json={"scenario_id": scn_id, "name": "auto", "mode": "real_time",
                                    "auto_advance": True}).json()["id"]
        client.post(f"/api/sessions/{auto_id}/start", headers=_h(admin))
        db = SessionLocal()
        try:
            s = db.get(models.Session, auto_id)
            start_code = s.current_inject_code
            cur = session_ops.current_inject(db, s)
            assert session_ops.timeout_branch(cur) is not None  # start inject can time out
        finally:
            db.close()
        scheduler._fire(auto_id, start_code)  # simulate the timer elapsing
        assert client.get(f"/api/sessions/{auto_id}", headers=_h(admin)).json(
        )["current_inject"]["code"] != start_code
