"""F7 — real range adapter: config selection, the SSRF/allow-list safety gate,
and live execution through Caldera/Atomic (HTTP mocked)."""
import httpx
import pytest
from fastapi.testclient import TestClient

from app import config
from app.engine import range_adapter as ra
from app.main import app


class _Resp:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


def _env():
    return type("E", (), {"controls": [], "detections": [], "deception_assets": []})()


# --------------------------------------------------------------------------- #
# host parsing + selection
# --------------------------------------------------------------------------- #
def test_target_host_parsing():
    assert ra._target_host("https://h.example:8443/p") == "h.example"
    assert ra._target_host("10.0.0.5:22") == "10.0.0.5"
    assert ra._target_host("WEB-1") == "web-1"


def test_adapter_selected_from_config(monkeypatch):
    monkeypatch.setattr(config, "RANGE_ADAPTER", "simulation")
    assert ra.get_adapter().name == "simulation"
    monkeypatch.setattr(config, "RANGE_ADAPTER", "caldera")
    assert ra.get_adapter().name == "caldera"
    monkeypatch.setattr(config, "RANGE_ADAPTER", "atomic")
    assert ra.get_adapter().name == "atomic"
    # An unknown value falls back to the safe simulation adapter.
    monkeypatch.setattr(config, "RANGE_ADAPTER", "bogus")
    assert ra.get_adapter().name == "simulation"


# --------------------------------------------------------------------------- #
# allow-list safety gate (fail closed)
# --------------------------------------------------------------------------- #
def test_caldera_refuses_non_allowlisted_target(monkeypatch):
    monkeypatch.setattr(config, "RANGE_ALLOWLIST", ["allowed-host"])
    with pytest.raises(ra.RangeNotAllowed):
        ra.CalderaAdapter().execute(_env(), "T1003", "evil.example")


def test_empty_allowlist_blocks_everything(monkeypatch):
    monkeypatch.setattr(config, "RANGE_ALLOWLIST", [])
    with pytest.raises(ra.RangeNotAllowed):
        ra.AtomicRedTeamAdapter().execute(_env(), "T1003", "anything")


# --------------------------------------------------------------------------- #
# live execution (HTTP mocked)
# --------------------------------------------------------------------------- #
def test_caldera_executes_against_allowlisted_target(monkeypatch):
    monkeypatch.setattr(config, "RANGE_ALLOWLIST", ["host-1"])
    monkeypatch.setattr(config, "CALDERA_URL", "https://caldera.local")
    monkeypatch.setattr(httpx, "post", lambda *a, **k: _Resp({"id": "op-123", "state": "running"}))
    out = ra.CalderaAdapter().execute(_env(), "T1059", "host-1")
    assert out["adapter"] == "caldera" and out["executed"] is True
    assert out["telemetry"][0]["operation_id"] == "op-123"
    assert "ruling" in out


def test_caldera_network_failure_raises_range_error(monkeypatch):
    monkeypatch.setattr(config, "RANGE_ALLOWLIST", ["host-1"])
    monkeypatch.setattr(config, "CALDERA_URL", "https://caldera.local")

    def _boom(*a, **k):
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(httpx, "post", _boom)
    with pytest.raises(ra.RangeError):
        ra.CalderaAdapter().execute(_env(), "T1059", "host-1")


# --------------------------------------------------------------------------- #
# end-to-end through the authorization-gated live-inject endpoint
# --------------------------------------------------------------------------- #
def _sandbox_session(client):
    scenario_id = client.get("/api/scenarios").json()[0]["id"]
    return client.post("/api/sessions",
                       json={"scenario_id": scenario_id, "name": "range", "mode": "sandbox"}
                       ).json()["id"]


def test_live_inject_allowlist_blocks_then_allows(monkeypatch):
    monkeypatch.setattr(config, "RANGE_ADAPTER", "caldera")
    monkeypatch.setattr(config, "CALDERA_URL", "https://caldera.local")
    monkeypatch.setattr(httpx, "post", lambda *a, **k: _Resp({"id": "op-9", "state": "finished"}))

    with TestClient(app) as client:
        sid = _sandbox_session(client)
        # Authorize the target in scope (the M4 gate) — but it's not allow-listed.
        client.post(f"/api/sessions/{sid}/authorize",
                    json={"scope": ["FIN-APP-02"], "authorized_by": "CISO", "ttl_minutes": 60})

        monkeypatch.setattr(config, "RANGE_ALLOWLIST", [])  # nothing allowed yet
        blocked = client.post(f"/api/sessions/{sid}/live-inject",
                              json={"technique": "T1003.001", "target": "FIN-APP-02"})
        assert blocked.status_code == 403
        assert "allow" in blocked.json()["detail"].lower()

        # Add the host to the allow-list -> live execution succeeds via Caldera.
        monkeypatch.setattr(config, "RANGE_ALLOWLIST", ["fin-app-02"])
        ok = client.post(f"/api/sessions/{sid}/live-inject",
                         json={"technique": "T1003.001", "target": "FIN-APP-02"})
        assert ok.status_code == 200, ok.text
        assert ok.json()["adapter"] == "caldera"


def test_live_inject_still_requires_authorization(monkeypatch):
    """F7's allow-list is *in addition to* the M4 authorization gate, not a
    replacement — an unauthorized session is refused before any range call."""
    monkeypatch.setattr(config, "RANGE_ADAPTER", "caldera")
    monkeypatch.setattr(config, "RANGE_ALLOWLIST", ["fin-app-02"])
    with TestClient(app) as client:
        sid = _sandbox_session(client)  # no /authorize
        r = client.post(f"/api/sessions/{sid}/live-inject",
                        json={"technique": "T1003.001", "target": "FIN-APP-02"})
        assert r.status_code == 403
        assert "authorization" in r.json()["detail"].lower()
