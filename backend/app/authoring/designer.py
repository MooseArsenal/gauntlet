"""Custom adversary designer (A7).

Lets a proctor design their own adversary — real or fictitious — or have the
program compose a random-but-coherent one. Either way the result is stored as a
``CustomAdversary`` and projected into the same threat-actor dict the generator
consumes (:func:`to_actor`), so a custom adversary produces scenarios exactly
like a built-in ATT&CK group.

A designed adversary is grounded in the shared scene bank: its kill chain is an
ordered list of ``INJECT_BANK`` keys, validated here, so the generator can fill
each scene with real assets from the target environment.
"""
from __future__ import annotations

import random as _random
import re
from typing import Optional

from .catalog import INJECT_BANK, _objs

# Canonical kill-chain phase order — a composed chain walks these in sequence.
PHASE_ORDER = [
    "initial-access", "execution", "discovery", "credential-access",
    "privilege-escalation", "lateral-movement", "command-and-control",
    "collection", "exfiltration", "impact",
]


def _bank_by_phase() -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for key, scene in INJECT_BANK.items():
        out.setdefault(scene.get("phase", ""), []).append(key)
    return out


def slugify(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "_", (name or "").strip().lower()).strip("_")
    return s or "adversary"


def validate_kill_chain(kill_chain: list[str]) -> list[str]:
    """Return a list of problems (empty = valid)."""
    problems: list[str] = []
    if not kill_chain:
        problems.append("a kill chain needs at least one scene")
    for k in kill_chain:
        if k not in INJECT_BANK:
            problems.append(f"unknown scene '{k}'")
    return problems


def default_objectives(kill_chain: list[str]) -> list[tuple[str, str]]:
    """Sensible capability-tagged objectives derived from the chain's shape."""
    objs = [("Detect the initial access",
             "The adversary's entry is identified and escalated in good time.")]
    phases = {INJECT_BANK[k]["phase"] for k in kill_chain if k in INJECT_BANK}
    if phases & {"lateral-movement", "privilege-escalation", "command-and-control"}:
        objs.append(("Contain the intrusion",
                     "Spread is halted before the adversary reaches its objective."))
    if phases & {"collection", "exfiltration"}:
        objs.append(("Protect the target data",
                     "Data staging or exfiltration is detected and stopped."))
    if "impact" in phases:
        objs.append(("Recover and communicate",
                     "Impact is contained; recovery and comms plans are executed."))
    if len(objs) < 2:
        objs.append(("Triage and report",
                     "The activity is scoped and a hotwash captures the lessons."))
    return objs


# --- random adversary composition ----------------------------------------- #
_ADJ = ["Spectral", "Crimson", "Silent", "Obsidian", "Gilded", "Hollow", "Feral",
        "Cobalt", "Amber", "Vesper", "Iron", "Pale", "Radiant", "Umbral", "Scarlet"]
_NOUN = ["Chimera", "Basilisk", "Viper", "Mantis", "Kraken", "Wyvern", "Jackal",
         "Cormorant", "Sable", "Lynx", "Adder", "Falcon", "Hydra", "Marmot", "Wolverine"]
_MOTIVES = ["financial", "espionage", "hacktivist", "sabotage", "extortion", "insider"]
_MOTIVE_SECTORS = {
    "financial": ["financial", "retail", "hospitality"],
    "espionage": ["government", "defense", "technology"],
    "hacktivist": ["government", "energy", "media"],
    "sabotage": ["energy", "critical-infrastructure", "manufacturing"],
    "extortion": ["healthcare", "financial", "manufacturing"],
    "insider": ["technology", "financial", "government"],
}
# A motive biases which terminal phase the chain builds toward.
_MOTIVE_IMPACT = {
    "financial": "impact", "extortion": "impact", "sabotage": "impact",
    "espionage": "exfiltration", "hacktivist": "impact", "insider": "exfiltration",
}


def random_adversary(rng: Optional[_random.Random] = None,
                     sector: Optional[str] = None) -> dict:
    """Compose a coherent, unsaved adversary draft (fictitious). Deterministic
    when given a seeded ``rng``."""
    r = rng or _random
    by_phase = _bank_by_phase()
    motive = r.choice(_MOTIVES)

    # Walk the phases in order; always open with initial access, always close on
    # the motive's terminal phase, and include a random slice of the middle.
    chain: list[str] = []
    if by_phase.get("initial-access"):
        chain.append(r.choice(by_phase["initial-access"]))
    middle = ["execution", "discovery", "credential-access", "privilege-escalation",
              "lateral-movement", "command-and-control", "collection"]
    for phase in middle:
        pool = by_phase.get(phase)
        if pool and r.random() < 0.55:
            chain.append(r.choice(pool))
    terminal = _MOTIVE_IMPACT.get(motive, "impact")
    if by_phase.get(terminal):
        chain.append(r.choice(by_phase[terminal]))
    # Guarantee a sane length even if the coin-flips were unkind.
    if len(chain) < 3:
        for phase in middle:
            if by_phase.get(phase) and by_phase[phase][0] not in chain:
                chain.append(by_phase[phase][0])
            if len(chain) >= 3:
                break

    name = f"{r.choice(_ADJ)} {r.choice(_NOUN)}"
    sectors = _MOTIVE_SECTORS.get(motive, [])
    if sector and sector not in sectors:
        sectors = [sector] + sectors
    techs = sorted({t for k in chain for t in INJECT_BANK[k].get("techniques", [])})
    return {
        "name": name,
        "label": f"{name} — {motive}-motivated adversary (generated)",
        "description": (f"A {motive}-motivated threat actor composed by Gauntlet, "
                        f"moving through {len(chain)} stages against the target."),
        "motivation": motive,
        "is_fictitious": True,
        "sectors": sectors,
        "techniques": techs,
        "kill_chain": chain,
        "objectives": [{"title": t, "success_criteria": c}
                       for t, c in default_objectives(chain)],
    }


def to_actor(adv) -> dict:
    """Project a ``CustomAdversary`` (or a draft dict) into the THREAT_ACTORS shape
    the generator consumes. Objectives are stored as {title, success_criteria}
    pairs and rebuilt through the catalog's ``_objs`` for a consistent shape."""
    def g(attr, default=None):
        return getattr(adv, attr, None) if not isinstance(adv, dict) else adv.get(attr, default)

    raw_objs = g("objectives") or []
    pairs = [(o.get("title", ""), o.get("success_criteria", "")) for o in raw_objs]
    if not pairs:
        pairs = default_objectives(list(g("kill_chain") or []))
    return {
        "name": g("name") or "Custom adversary",
        "label": g("label") or (g("name") or "Custom adversary"),
        "description": g("description") or "",
        "kill_chain": list(g("kill_chain") or []),
        "objectives": _objs(*pairs),
        "attack_id": "CUSTOM",
        "aliases": [],
        "sectors": list(g("sectors") or []),
        "techniques": list(g("techniques") or []),
        "is_custom": True,
        "is_fictitious": bool(g("is_fictitious")),
        "motivation": g("motivation") or "",
    }
