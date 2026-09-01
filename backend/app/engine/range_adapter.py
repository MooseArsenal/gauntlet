"""Cyber-range hooks (M4): a pluggable adapter for live/technical injects.

An operational or sandbox exercise can execute a technical action and feed the
resulting telemetry back into adjudication. The adapter interface makes the
range pluggable; the shipped default is a **simulation** adapter that contacts
nothing — it derives synthetic telemetry from the environment model, so the
product is safe out of the box.

Safety posture: a real adapter that touches systems must be gated by an
authorization grant and a target allow-list (see ``app/api/live.py``). Adversary
actions are executed only against an environment the user is authorized to test.
"""
from __future__ import annotations

from urllib.parse import urlparse

from .. import config, egress
from . import adjudication


class RangeError(Exception):
    """A live execution failed (network, auth, or a bad response)."""


class RangeNotAllowed(RangeError):
    """The target is outside the range allow-list — a hard safety stop."""


def _target_host(target: str) -> str:
    """Extract a host from a target that may be a bare host, host:port, or URL."""
    t = (target or "").strip()
    if "://" in t:
        return (urlparse(t).hostname or "").lower()
    return t.split(":", 1)[0].strip().lower()


def _require_allowlisted(target: str) -> None:
    """SSRF / blast-radius guard: a real adapter may only touch allow-listed
    hosts. An empty allow-list means *nothing* is allowed (fail closed)."""
    host = _target_host(target)
    if not host or host not in config.RANGE_ALLOWLIST:
        raise RangeNotAllowed(
            f"target host '{host or target}' is not on GAUNTLET_RANGE_ALLOWLIST — "
            "refusing to execute live"
        )


class RangeAdapter:
    """Interface a concrete range integration implements."""

    name = "base"

    def execute(self, environment, technique: str, target: str) -> dict:  # pragma: no cover
        raise NotImplementedError


class SimulationRangeAdapter(RangeAdapter):
    """Default, safe adapter. Contacts no external system.

    It runs the technique through the deterministic adjudication engine to decide
    what the environment's controls *would* have observed, and returns that as
    synthetic telemetry alongside the ruling.
    """

    name = "simulation"

    def execute(self, environment, technique: str, target: str) -> dict:
        ruling = adjudication.adjudicate(environment, [technique], target)
        telemetry = [
            {"source": c["name"], "type": c["type"], "deception": c.get("deception", False)}
            for c in ruling["controls_hit"]
        ]
        return {
            "adapter": self.name,
            "executed": True,
            "technique": technique,
            "target": target,
            "telemetry": telemetry,
            "ruling": ruling,
            "note": "Synthetic telemetry — no live system was contacted.",
        }


def _ruling_with_telemetry(environment, technique: str, target: str,
                           adapter_name: str, telemetry: list, note: str) -> dict:
    """Adjudicate against the modelled controls and attach live telemetry.

    The environment model still decides detection (we don't have a live SIEM
    feedback loop); the value of a real adapter is that the action actually ran
    and produced real execution telemetry.
    """
    ruling = adjudication.adjudicate(environment, [technique], target)
    return {
        "adapter": adapter_name, "executed": True, "technique": technique,
        "target": target, "telemetry": telemetry, "ruling": ruling, "note": note,
    }


class CalderaAdapter(RangeAdapter):
    """MITRE Caldera. Runs an ability for the technique against an allow-listed
    agent, then adjudicates the modelled controls against it."""

    name = "caldera"

    def execute(self, environment, technique: str, target: str) -> dict:
        _require_allowlisted(target)
        import httpx

        egress.guard("range adapter: Caldera")
        try:
            r = httpx.post(
                f"{config.CALDERA_URL}/api/v2/operations",
                headers={"KEY": config.CALDERA_API_KEY, "Accept": "application/json"},
                json={"name": f"gauntlet-{technique}", "adversary": {"atomic_ordering": [technique]},
                      "group": target},
                timeout=15.0,
            )
            r.raise_for_status()
            body = r.json()
        except Exception as exc:  # noqa: BLE001
            raise RangeError(f"Caldera execution failed: {exc}") from exc
        telemetry = [{"source": "caldera", "operation_id": body.get("id"),
                      "state": body.get("state")}]
        return _ruling_with_telemetry(environment, technique, target, self.name, telemetry,
                                      "Executed via Caldera against an allow-listed target.")


class AtomicRedTeamAdapter(RangeAdapter):
    """Atomic Red Team via a runner endpoint that executes a single atomic test."""

    name = "atomic"

    def execute(self, environment, technique: str, target: str) -> dict:
        _require_allowlisted(target)
        import httpx

        egress.guard("range adapter: Atomic Red Team")
        try:
            r = httpx.post(
                f"{config.ATOMIC_URL}/run",
                headers={"Authorization": f"Bearer {config.ATOMIC_TOKEN}",
                         "Accept": "application/json"},
                json={"technique": technique, "target": target},
                timeout=15.0,
            )
            r.raise_for_status()
            body = r.json()
        except Exception as exc:  # noqa: BLE001
            raise RangeError(f"Atomic Red Team execution failed: {exc}") from exc
        telemetry = [{"source": "atomic", "test": body.get("test"),
                      "exit_code": body.get("exit_code")}]
        return _ruling_with_telemetry(environment, technique, target, self.name, telemetry,
                                      "Executed via Atomic Red Team against an allow-listed target.")


# An explicit override (set_adapter) wins; otherwise the adapter is chosen from
# config. The authorization gate in the API applies regardless of which is set.
_OVERRIDE: RangeAdapter | None = None
_BY_NAME = {
    "simulation": SimulationRangeAdapter,
    "caldera": CalderaAdapter,
    "atomic": AtomicRedTeamAdapter,
}


def get_adapter() -> RangeAdapter:
    if _OVERRIDE is not None:
        return _OVERRIDE
    return _BY_NAME.get(config.RANGE_ADAPTER, SimulationRangeAdapter)()


def set_adapter(adapter: RangeAdapter | None) -> None:
    global _OVERRIDE
    _OVERRIDE = adapter
