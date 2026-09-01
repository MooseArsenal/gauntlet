"""MITRE ATT&CK Navigator layer export (D1).

Emits a scenario's technique spread — or a session's *detection* coverage — as a
MITRE ATT&CK Navigator layer JSON, ready to drop into
https://mitre-attack.github.io/attack-navigator/. No competitor in the tabletop
space does this; it turns Gauntlet's technique-tagged injects and adjudications
into the artifact SOC teams already live in.

Pure transforms over data the caller already owns — the API layer scopes + audits.
"""
from __future__ import annotations

from . import models

# Navigator schema/version pinning (layer 4.5 / ATT&CK v15 / Navigator 4.9.x).
_ATTACK_VERSION = "15"
_NAVIGATOR_VERSION = "4.9.1"
_LAYER_VERSION = "4.5"

# Blue-team blue → crimson (matches the app's purple-team palette).
_C_COVERED = "#6C8BFF"   # present / attempted
_C_DETECTED = "#3DD68C"  # detected
_C_MISSED = "#FF4D6D"    # attempted but undetected


def _base(name: str, description: str, techniques: list[dict],
          gradient: list[str], max_score: int) -> dict:
    return {
        "name": name,
        "versions": {"attack": _ATTACK_VERSION, "navigator": _NAVIGATOR_VERSION, "layer": _LAYER_VERSION},
        "domain": "enterprise-attack",
        "description": description,
        "sorting": 3,  # descending by score
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {"colors": gradient, "minValue": 0, "maxValue": max(1, max_score)},
        "legendItems": [],
        "metadata": [{"name": "generator", "value": "Gauntlet"}],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#2A2340",
        "selectTechniquesAcrossTactics": True,
    }


def scenario_layer(scenario: models.Scenario) -> dict:
    """Techniques the scenario exercises, scored by how many injects use each."""
    counts: dict[str, int] = {}
    for inj in scenario.injects:
        for t in (inj.attack_techniques or []):
            counts[t] = counts.get(t, 0) + 1
    techniques = [
        {"techniqueID": t, "score": n, "color": _C_COVERED,
         "comment": f"Exercised in {n} inject{'s' if n != 1 else ''}", "enabled": True}
        for t, n in sorted(counts.items())
    ]
    return _base(
        name=f"Gauntlet — {scenario.name}",
        description=(f"ATT&CK coverage exercised by scenario '{scenario.name}' "
                    f"(threat actor: {scenario.threat_actor})."),
        techniques=techniques,
        gradient=["#2A2340", _C_COVERED],
        max_score=max(counts.values(), default=1),
    )


def _scored_events(session: models.Session) -> list[models.TimelineEvent]:
    return [e for e in session.events if e.kind in ("red_action", "adjudication")]


def session_layer(session: models.Session, scenario: models.Scenario) -> dict:
    """Live detection coverage: per technique, attempts vs detections from the
    session's adjudicated moves. Green = detected at least once, crimson = only
    ever missed; score is the detection percentage."""
    tally: dict[str, dict] = {}
    for e in _scored_events(session):
        detected = bool(e.payload.get("detected"))
        for t in (e.payload.get("techniques") or []):
            row = tally.setdefault(t, {"attempts": 0, "detected": 0})
            row["attempts"] += 1
            row["detected"] += 1 if detected else 0
    techniques = []
    for t, r in sorted(tally.items()):
        pct = round(100 * r["detected"] / r["attempts"]) if r["attempts"] else 0
        techniques.append({
            "techniqueID": t, "score": pct,
            "color": _C_DETECTED if r["detected"] else _C_MISSED,
            "comment": f"{r['detected']}/{r['attempts']} detected",
            "enabled": True,
        })
    return _base(
        name=f"Gauntlet — {session.name} (detection)",
        description=(f"Detection coverage from session '{session.name}' over "
                    f"scenario '{scenario.name}'. Green = detected, crimson = missed."),
        techniques=techniques,
        gradient=[_C_MISSED, "#F5B544", _C_DETECTED],
        max_score=100,
    )
