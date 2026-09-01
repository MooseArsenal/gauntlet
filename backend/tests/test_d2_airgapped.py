"""D2 — air-gapped mode: every outbound path fails closed; /api/health reports it."""
import pytest
from fastapi.testclient import TestClient

from app import config, egress, tracker
from app.main import app


def test_guard_blocks_only_when_airgapped(monkeypatch):
    monkeypatch.setattr(config, "AIRGAPPED", False)
    egress.guard("x")  # no raise
    monkeypatch.setattr(config, "AIRGAPPED", True)
    with pytest.raises(egress.EgressBlocked):
        egress.guard("x")


def test_health_reports_airgapped(monkeypatch):
    with TestClient(app) as client:
        assert client.get("/api/health").json()["airgapped"] is False
    monkeypatch.setattr("app.main.AIRGAPPED", True)
    with TestClient(app) as client:
        assert client.get("/api/health").json()["airgapped"] is True


def test_outbound_adapter_fails_closed_when_airgapped(monkeypatch):
    """A representative egress path (Jira tracker) refuses before any network I/O."""
    monkeypatch.setattr(config, "AIRGAPPED", True)
    with pytest.raises(tracker.TrackerError) as ei:
        tracker.JiraTracker().create_issue("t", "d", "medium")
    assert "air-gapped" in str(ei.value).lower()


def test_llm_assist_is_disabled_when_airgapped(monkeypatch):
    """With the LLM provider configured AND air-gapped, the guarded call refuses
    rather than reaching the provider."""
    from app.authoring import assist
    monkeypatch.setenv("GAUNTLET_LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("GAUNTLET_LLM_API_KEY", "x")
    monkeypatch.setattr(config, "AIRGAPPED", True)
    with pytest.raises(egress.EgressBlocked):
        assist._provider_inject("execution", "T1059", "Org", {"name": "host"}, "brief")
