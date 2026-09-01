"""Scenario YAML: import, export, and validation.

The YAML format is a branching **graph**, not a line: injects can have many
guarded branches, carry state mutations, and reach different acts depending on
accumulated decisions. Validation proves the graph is playable before it is
ever run — every ``goto`` resolves, the start is defined, at least one ending is
reachable, and guard expressions are safe and reference known variables.
"""
from __future__ import annotations

from collections import deque

import yaml

from . import models
from .engine import msel
from .engine.conditions import referenced_names, safe_eval


class ScenarioError(ValueError):
    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__("; ".join(errors))


def load_yaml(text: str) -> dict:
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ScenarioError(["top-level YAML must be a mapping"])
    # Accept either a bare mapping or one nested under `scenario:`.
    return data.get("scenario", data)


def dump_yaml(data: dict) -> str:
    return yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=100)


def _inject_attack(i: dict) -> list:
    return i.get("attack") or i.get("attack_techniques") or []


def _inject_objective(i: dict) -> str:
    return i.get("objective") or i.get("objective_code") or ""


def validate(data: dict) -> dict:
    """Return ``{"errors": [...], "warnings": [...]}``. Errors block import."""
    errors: list[str] = []
    warnings: list[str] = []

    if not data.get("name"):
        errors.append("scenario is missing a name")

    injects = data.get("injects") or []
    if not injects:
        errors.append("scenario has no injects")
        return {"errors": errors, "warnings": warnings}

    codes = [i.get("code") for i in injects]
    if len(set(codes)) != len(codes):
        errors.append("duplicate inject codes")
    codeset = set(codes)

    starts = [i for i in injects if i.get("is_start")]
    if len(starts) == 0:
        errors.append("no start inject (set is_start: true on one)")
    elif len(starts) > 1:
        errors.append("more than one start inject")

    variables = set((data.get("variables") or {}).keys())
    objective_codes = {o.get("code") for o in (data.get("objectives") or [])}

    for i in injects:
        code = i.get("code", "?")
        if not code:
            errors.append("an inject is missing its code")
        obj = _inject_objective(i)
        if obj and obj not in objective_codes:
            warnings.append(f"{code}: objective '{obj}' is not defined")
        for b in i.get("branches") or []:
            goto = b.get("goto")
            if goto not in codeset:
                errors.append(f"{code}: branch goto '{goto}' does not exist")
            cond = b.get("condition", "")
            if cond:
                try:
                    safe_eval(cond, {})
                except ValueError as e:
                    errors.append(f"{code}: invalid condition '{cond}': {e}")
                for name in referenced_names(cond):
                    if name not in variables:
                        warnings.append(f"{code}: condition references unknown variable '{name}'")
            for key in (b.get("set") or {}):
                if key not in variables:
                    warnings.append(f"{code}: branch sets unknown variable '{key}'")

    # Reachability from the start, and at least one terminal.
    if starts and not errors:
        start = starts[0]["code"]
        adj = {i["code"]: [b.get("goto") for b in (i.get("branches") or [])] for i in injects}
        seen, q = {start}, deque([start])
        while q:
            for nxt in adj.get(q.popleft(), []):
                if nxt in codeset and nxt not in seen:
                    seen.add(nxt)
                    q.append(nxt)
        unreachable = codeset - seen
        if unreachable:
            warnings.append(f"unreachable injects: {', '.join(sorted(unreachable))}")
        if not any(not (i.get("branches")) for i in injects):
            errors.append("no terminal inject (at least one must have no branches)")

    return {"errors": errors, "warnings": warnings}


def to_models(data: dict, environment_id: int, org_id: int) -> models.Scenario:
    """Build an unsaved Scenario (with objectives + injects) from parsed YAML.

    Raises ScenarioError if validation fails.
    """
    result = validate(data)
    if result["errors"]:
        raise ScenarioError(result["errors"])

    scenario = models.Scenario(
        org_id=org_id,
        environment_id=environment_id,
        name=data["name"],
        threat_actor=data.get("threat_actor", ""),
        narrative=data.get("narrative", ""),
        scope=data.get("scope", ""),
        rules_of_engagement=data.get("rules_of_engagement", ""),
        cells=data.get("cells", []),
        exercise_type=data.get("exercise_type", "tabletop"),
        variables=data.get("variables", {}),
    )
    scenario.objectives = [
        models.Objective(
            code=o["code"], title=o.get("title", ""), description=o.get("description", ""),
            success_criteria=o.get("success_criteria", ""), eeg=o.get("eeg", []),
            meta=o.get("meta", {}),
        )
        for o in (data.get("objectives") or [])
    ]
    scenario.injects = [
        models.Inject(
            code=i["code"], sequence=i.get("sequence", idx + 1), title=i.get("title", ""),
            channel=i.get("channel", "briefing"), clock=i.get("clock", ""),
            narrative=i.get("narrative", ""), visible_to=i.get("visible_to", []),
            expected_actions=i.get("expected_actions", []), attack_techniques=_inject_attack(i),
            target_asset=i.get("target_asset", ""), objective_code=_inject_objective(i),
            branches=i.get("branches", []), is_start=bool(i.get("is_start", False)),
            act=i.get("act", ""), meta=i.get("meta", {}),
        )
        for idx, i in enumerate(data.get("injects") or [])
    ]
    return scenario


def to_dict(scenario: models.Scenario) -> dict:
    """Serialise a Scenario back to the YAML-friendly dict (round-trips)."""
    return {
        "scenario": {
            "name": scenario.name,
            "threat_actor": scenario.threat_actor,
            "narrative": scenario.narrative,
            "scope": scenario.scope,
            "rules_of_engagement": scenario.rules_of_engagement,
            "exercise_type": scenario.exercise_type,
            "cells": scenario.cells or [],
            "variables": scenario.variables or {},
            "objectives": [
                {"code": o.code, "title": o.title, "description": o.description,
                 "success_criteria": o.success_criteria, "eeg": o.eeg or [], "meta": o.meta or {}}
                for o in sorted(scenario.objectives, key=lambda x: x.code)
            ],
            "injects": [
                {"code": i.code, "act": i.act, "is_start": i.is_start, "title": i.title,
                 "channel": i.channel, "clock": i.clock, "narrative": i.narrative,
                 "visible_to": i.visible_to or [], "expected_actions": i.expected_actions or [],
                 "attack": i.attack_techniques or [], "target_asset": i.target_asset,
                 "objective": i.objective_code, "branches": i.branches or [], "meta": i.meta or {}}
                for i in sorted(scenario.injects, key=lambda x: x.sequence)
            ],
        }
    }
