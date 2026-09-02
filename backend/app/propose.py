"""Propose the next inject (P5): the facilitator's co-author, in session.

Cybertabletop's AI-driven mode writes the next inject from what the team just
did. Gauntlet keeps the proctor in charge: this drafts the next scene from the
live session — the current inject, the last rulings and the room's decisions —
through the same guard-railed assist used for authoring (deterministic template
by default, a provider only when configured), and the proctor reviews, edits,
then adds it as a branch and optionally fires it. Nothing is written until the
proctor accepts.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import models
from .authoring import assist
from .authoring.catalog import INJECT_BANK
from .authoring.generator import _pick_asset

PHASES = ["reconnaissance", "initial-access", "execution", "persistence", "privilege-escalation",
          "defense-evasion", "credential-access", "discovery", "lateral-movement", "collection",
          "command-and-control", "exfiltration", "impact"]


def phase_of(inject) -> str:
    """The kill-chain phase of an inject, from the bank entry its technique matches."""
    for t in (getattr(inject, "attack_techniques", None) or []):
        for entry in INJECT_BANK.values():
            if t in (entry.get("techniques") or []) or t.split(".")[0] in {x.split(".")[0] for x in (entry.get("techniques") or [])}:
                return entry.get("phase", "")
    return ""


def next_phase(current: str) -> str:
    if current in PHASES and PHASES.index(current) + 1 < len(PHASES):
        return PHASES[PHASES.index(current) + 1]
    return "lateral-movement" if current not in PHASES else "impact"


def context(db: Session, session: models.Session, scenario: models.Scenario, current) -> dict:
    events = list(session.events)
    rulings = [e.payload or {} for e in events if e.kind in ("adjudication", "red_action")][-3:]
    decisions = [e.payload or {} for e in events if e.kind == "decision"][-3:]
    responses = [e.payload or {} for e in events if e.kind == "response" and (e.payload or {}).get("inject_code") == (current.code if current else None)]
    detected = sum(1 for r in rulings if r.get("detected"))
    cur_phase = phase_of(current) if current else ""
    nxt = next_phase(cur_phase)
    lines = []
    if current:
        lines.append(f"Current scene {current.code}: {current.title} ({current.channel}).")
    if rulings:
        lines.append(f"Last {len(rulings)} adversary action(s): {detected} detected, {len(rulings) - detected} missed.")
    if decisions:
        lines.append("Recent proctor decisions: " + "; ".join(d.get("label") or d.get("goto") or "" for d in decisions) + ".")
    if responses:
        picks = {}
        for r in responses:
            k = r.get("label") or "(free text)"
            picks[k] = picks.get(k, 0) + 1
        lines.append("The room chose: " + ", ".join(f"{k} ({n})" for k, n in picks.items()) + ".")
    lines.append(f"Write the next scene in the {nxt} phase; the adversary "
                 + ("was noticed and adapts." if detected else "has not been noticed yet."))
    return {"phase": nxt, "current_phase": cur_phase, "brief": " ".join(lines), "rulings": len(rulings),
            "detected": detected, "responses": len(responses)}


def draft(db: Session, session: models.Session, scenario: models.Scenario, env: models.Environment,
          current, brief: str = "") -> dict:
    ctx = context(db, session, scenario, current)
    asset = _pick_asset(env, "app")
    org = env.name
    result = assist.generate_inject(phase=ctx["phase"], technique="", org=org, asset=asset,
                                    brief=(brief + " " + ctx["brief"]).strip())
    inj = dict(result["inject"])
    codes = {i.code for i in scenario.injects}
    n = 1
    while f"INJ-P{n:02d}" in codes:
        n += 1
    inj.setdefault("code", f"INJ-P{n:02d}")
    inj["code"] = f"INJ-P{n:02d}"
    inj.setdefault("channel", "briefing")
    inj.setdefault("expected_actions", [])
    inj.setdefault("attack_techniques", inj.pop("techniques", []) if "techniques" in inj else [])
    inj.setdefault("target_asset", asset.get("code", ""))
    inj["visible_to"] = list(getattr(current, "visible_to", None) or ["blue_cell", "white_cell"])
    inj["clock"] = ""
    return {"inject": inj, "generator": result["generator"], "context": ctx}


def accept(db: Session, session: models.Session, scenario: models.Scenario, current, data: dict) -> models.Inject:
    """Add the (edited) draft to the scenario and branch the current inject to it."""
    codes = {i.code for i in scenario.injects}
    code = str(data.get("code") or "").strip() or "INJ-P01"
    n = 1
    while code in codes:
        n += 1
        code = f"INJ-P{n:02d}"
    seq = max((i.sequence for i in scenario.injects), default=0) + 1
    inject = models.Inject(
        scenario_id=scenario.id, code=code, sequence=seq, title=str(data.get("title") or "Proposed scene")[:240],
        channel=str(data.get("channel") or "briefing")[:40], clock=str(data.get("clock") or "")[:20],
        narrative=str(data.get("narrative") or ""), visible_to=list(data.get("visible_to") or ["blue_cell", "white_cell"]),
        expected_actions=[str(a) for a in (data.get("expected_actions") or [])][:12],
        attack_techniques=list(data.get("attack_techniques") or []), target_asset=str(data.get("target_asset") or "")[:120],
        objective_code=str(data.get("objective_code") or (getattr(current, "objective_code", "") or ""))[:40],
        branches=[], is_start=False, act=str(data.get("act") or "")[:120],
        meta={"proposed": True, "generator": data.get("generator", "template")},
    )
    db.add(inject)
    db.flush()
    if current is not None:
        branches = list(current.branches or [])
        branches.append({"when": "proctor_choice", "goto": code, "label": f"Proctor: proposed scene {code}", "proposed": True})
        current.branches = branches
        from sqlalchemy.orm.attributes import flag_modified
        flag_modified(current, "branches")
    return inject
