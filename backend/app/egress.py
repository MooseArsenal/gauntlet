"""Air-gapped egress guard (D2).

A single choke point every outbound-network call passes through. In air-gapped
mode (``GAUNTLET_AIRGAPPED=1``) it refuses, fail-closed, so the deployment can
guarantee it makes no egress. Reads the flag from ``config`` at call time so the
posture is honoured even if the module was imported earlier.
"""
from __future__ import annotations

from . import config


class EgressBlocked(RuntimeError):
    """Raised when air-gapped mode blocks an outbound network call."""


def guard(purpose: str) -> None:
    if config.AIRGAPPED:
        raise EgressBlocked(
            f"air-gapped mode: outbound network is disabled ({purpose})"
        )
