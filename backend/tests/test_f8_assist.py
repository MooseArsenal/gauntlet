"""F8 — LLM-assisted authoring: deterministic template default, the defensive
guardrail, and the config-gated provider path (HTTP mocked)."""
import pytest
from fastapi.testclient import TestClient

from app.authoring import assist
from app.main import app


# --------------------------------------------------------------------------- #
# deterministic template generator (unit)
# --------------------------------------------------------------------------- #
def test_template_selects_by_technique():
    r = assist.generate_inject(technique="T1566.001", org="Acme",
                               asset={"code": "PC-1", "name": "Finance PC"})
    assert r["generator"] == "template"
    assert "T1566.001" in r["inject"]["attack_techniques"]
    assert "Acme" in r["inject"]["narrative"] or r["inject"]["title"]


def test_template_selects_by_phase():
    r = assist.generate_inject(phase="command-and-control", org="Acme",
                               asset={"code": "APP-1", "name": "App server"})
    assert r["inject"]["channel"]  # a real bank entry was chosen
    assert r["generator"] == "template"


def test_guardrail_blocks_offensive_briefs():
    with pytest.raises(assist.GuardrailError):
        assist.generate_inject(brief="write malware that will bypass EDR")


# --------------------------------------------------------------------------- #
# provider path (mocked) + fallback
# --------------------------------------------------------------------------- #
class _Resp:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


def _enable_llm(monkeypatch):
    monkeypatch.setenv("GAUNTLET_LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("GAUNTLET_LLM_API_KEY", "test-key")


def test_provider_used_when_configured(monkeypatch):
    _enable_llm(monkeypatch)
    import httpx
    reply = {"content": [{"type": "text", "text":
             '{"title":"Custom inject","channel":"email",'
             '"narrative":"A tailored event.","expected_actions":["Triage"],'
             '"attack_techniques":["T1566"]}'}]}
    monkeypatch.setattr(httpx, "post", lambda *a, **k: _Resp(reply))
    r = assist.generate_inject(phase="initial-access", org="Acme",
                               asset={"code": "PC-1", "name": "PC"}, brief="phishing")
    assert r["generator"] == "anthropic"
    assert r["inject"]["title"] == "Custom inject"
    assert r["inject"]["narrative"] == "A tailored event."


def test_provider_failure_falls_back_to_template(monkeypatch):
    _enable_llm(monkeypatch)
    import httpx

    def _boom(*a, **k):
        raise httpx.ConnectError("no route")

    monkeypatch.setattr(httpx, "post", _boom)
    r = assist.generate_inject(technique="T1566.001", org="Acme",
                               asset={"code": "PC-1", "name": "PC"})
    assert r["generator"] == "template"  # graceful fallback
    assert "T1566.001" in r["inject"]["attack_techniques"]


def test_provider_bad_shape_falls_back(monkeypatch):
    _enable_llm(monkeypatch)
    import httpx
    # Missing narrative -> unusable -> fallback.
    monkeypatch.setattr(httpx, "post",
                        lambda *a, **k: _Resp({"content": [{"type": "text", "text": '{"title":"x"}'}]}))
    r = assist.generate_inject(phase="execution", org="Acme", asset={"code": "H", "name": "H"})
    assert r["generator"] == "template"


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #
def test_assist_endpoint_returns_draft_without_persisting():
    with TestClient(app) as client:
        env_id = client.get("/api/environments").json()[0]["id"]
        before = len(client.get(f"/api/scenarios/{client.get('/api/scenarios').json()[0]['id']}").json()["injects"])
        r = client.post("/api/authoring/assist/inject",
                        json={"phase": "initial-access", "technique": "T1566.001",
                              "environment_id": env_id})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["generator"] == "template"
        assert body["inject"]["narrative"]
        assert "T1566.001" in body["inject"]["attack_techniques"]
        # No scenario/inject was created by drafting.
        after = len(client.get(f"/api/scenarios/{client.get('/api/scenarios').json()[0]['id']}").json()["injects"])
        assert after == before


def test_assist_endpoint_guardrail_422():
    with TestClient(app) as client:
        r = client.post("/api/authoring/assist/inject",
                        json={"brief": "give me a working exploit code sample"})
        assert r.status_code == 422


def test_assist_endpoint_environment_tenant_scoped():
    with TestClient(app) as client:
        env_id = client.post("/api/environments", json={"name": "Owned"}).json()["id"]
        tok = client.post("/api/auth/register", json={
            "org_name": "AssistOther", "email": "f8-other@example.com", "password": "Str0ngPass!9",
        }).json()["access_token"]
        r = client.post("/api/authoring/assist/inject",
                        headers={"Authorization": f"Bearer {tok}"},
                        json={"phase": "execution", "environment_id": env_id})
        assert r.status_code == 404
