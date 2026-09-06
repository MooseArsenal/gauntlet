"""Solo engagements (S2): generated runs with a type and a difficulty.

The library already holds seven environments, eleven CTEP packs, a dozen real
ATT&CK groups and four attack templates. An engagement draws on that: pick a
side, a type and a difficulty, and the engine assembles a fresh run — a
library environment (kept as a hidden "solo arena" per organisation), an
adversary from the type's pool, the template that fits — so the catalogue
never runs out and no two runs are quite the same. Hand-written scenarios
remain available as worked examples.

Difficulty is a set of levers, applied at play time from the run's state:

* red — control efficacy scaling (named controls only: the wildcard SIEM
  that watches everything is baseline noise and stays at its authored value,
  otherwise a 1.15× on a 0.45 baseline detects every move and hard is not
  hard but impossible), alert threshold, move budget, whether a crown jewel
  needs a foothold first, whether deception assets are live (and cost two
  alert points), whether technique hints and zones are shown;
* blue / executive — the decision clock, option shuffling, extra plausible
  distractors (authored into the generated scenario), whether the "consider"
  hints are shown, an impact multiplier;
* both — a score weight, so the same choices on expert are worth more and a
  history can compare across difficulties.

Two things are not levers. A red move must name techniques this build knows
and an asset of the arena: a made-up technique id is a detection gap by
construction and a made-up asset code is a free foothold, and both were
guaranteed wins at every difficulty. And a worked example (a hand-authored
scenario, where the best option is usually written first) shuffles its
options at every difficulty, easy included; only generated engagements
keep the authored order on easy.
"""
from __future__ import annotations

import random

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import models
from .authoring import environments as env_library
from .authoring import generator
from .authoring.catalog import INJECT_BANK, THREAT_ACTORS
from .engine import technique

DIFFICULTIES = ("easy", "standard", "hard", "expert")
LEVERS: dict[str, dict] = {
    "easy":     {"efficacy": 0.7,  "alert": 5, "moves": 12, "foothold": False, "deception": False, "hints": True,  "zones": True,
                 "clock": 240, "shuffle": False, "distractors": 0, "impact": 0.5, "weight": 0.85},
    "standard": {"efficacy": 1.0,  "alert": 3, "moves": 8,  "foothold": True,  "deception": False, "hints": True,  "zones": True,
                 "clock": 120, "shuffle": True,  "distractors": 0, "impact": 1.0, "weight": 1.0},
    "hard":     {"efficacy": 1.15, "alert": 2, "moves": 6,  "foothold": True,  "deception": True,  "hints": False, "zones": True,
                 "clock": 60,  "shuffle": True,  "distractors": 1, "impact": 1.5, "weight": 1.15},
    "expert":   {"efficacy": 1.3,  "alert": 2, "moves": 5,  "foothold": True,  "deception": True,  "hints": False, "zones": False,
                 "clock": 45,  "shuffle": True,  "distractors": 2, "impact": 2.0, "weight": 1.3},
}
DIFFICULTY_LABELS = {"easy": "Easy — learn the ropes", "standard": "Standard — a fair fight",
                     "hard": "Hard — tight clocks, live traps", "expert": "Expert — no hints, no mercy"}

# Engagement types per side: an adversary pool, the environments that fit, a template.
TYPES: dict[str, dict[str, dict]] = {
    "red": {
        "smash_grab": {"label": "Smash and grab", "blurb": "Get in, take data, get out. Short and loud.",
                       "actors": ["fin7", "ta505", "scattered_spider", "lapsus"], "envs": ["saas", "university", "county"],
                       "template": "apt_intrusion", "win": "Reach a crown jewel unseen."},
        "ransomware": {"label": "Ransomware", "blurb": "Foothold, spread, then hit a crown jewel before they notice.",
                       "actors": ["wizard_spider", "ransomware_affiliate", "ta505"], "envs": ["hospital", "manufacturer", "county"],
                       "template": "ransomware_finance", "win": "Reach a crown jewel unseen."},
        "espionage": {"label": "Espionage", "blurb": "Low and slow. Every detection is a failure.",
                      "actors": ["apt29", "apt28", "apt41", "volt_typhoon", "apt33"], "envs": ["university", "saas", "water_utility", "county"],
                      "template": "apt_intrusion", "win": "Reach a crown jewel unseen with the alert level still low."},
        "insider": {"label": "Insider", "blurb": "You already have access. The traps are the problem.",
                    "actors": ["malicious_insider"], "envs": ["hospital", "saas", "manufacturer"],
                    "template": "insider_exfil", "win": "Reach a crown jewel without tripping a canary."},
    },
    "blue": {
        "phishing": {"label": "Phishing to fraud", "blurb": "A lure, a login, a wire request. Stop it early.",
                     "actors": ["bec_actor", "ransomware_affiliate", "apt29"], "envs": ["county", "university", "saas"],
                     "template": "bec_finance"},
        "ransomware": {"label": "Ransomware", "blurb": "Contain before the domain controller falls.",
                       "actors": ["wizard_spider", "ransomware_affiliate"], "envs": ["hospital", "manufacturer", "county"],
                       "template": "ransomware_finance"},
        "insider": {"label": "Insider", "blurb": "A privileged user is collecting data. Prove it and stop it.",
                    "actors": ["malicious_insider"], "envs": ["hospital", "saas", "university"],
                    "template": "insider_exfil"},
        "espionage": {"label": "Targeted intrusion", "blurb": "Quiet C2 and slow exfil. Notice what is barely there.",
                      "actors": ["apt29", "apt28", "apt41", "volt_typhoon"], "envs": ["university", "saas", "county"],
                      "template": "apt_intrusion"},
        "ics": {"label": "Industrial", "blurb": "Safety first: the network is untrusted and the plant is running.",
                "actors": ["sandworm", "volt_typhoon"], "envs": ["water_utility", "manufacturer"],
                "template": "apt_intrusion"},
    },
}
TYPES["exec"] = TYPES["blue"]

# Wrong-but-plausible options mixed into generated decisions on harder runs.
DISTRACTORS = [
    ("Post a reassuring update on the company's social media", "Public statements before facts invite correction later and tip off the adversary."),
    ("Reboot the affected systems and see if it clears", "Rebooting destroys volatile evidence and rarely removes a foothold."),
    ("Wait for the vendor's support line to call back", "Waiting hands the adversary the time they need."),
    ("Email the whole company asking if anyone clicked", "Mass mail creates noise, panic and a second phishing surface."),
    ("Pay quietly and keep it out of the incident log", "Undocumented payment breaks the record and possibly the law."),
    ("Ask the intern to look into it after lunch", "Delegating a live incident without ownership is the same as waiting."),
]


def levers(difficulty: str) -> dict:
    return dict(LEVERS.get(difficulty or "standard", LEVERS["standard"]))


def catalogue() -> dict:
    return {"difficulties": [{"key": k, "label": DIFFICULTY_LABELS[k], **LEVERS[k]} for k in DIFFICULTIES],
            "types": {side: [{"key": k, **{kk: v for kk, v in t.items() if kk in ("label", "blurb", "win")}}
                             for k, t in kinds.items()] for side, kinds in TYPES.items()}}


ARENA_PREFIX = "Solo arena — "


def arena(db: Session, org_id: int, env_key: str) -> models.Environment:
    """The organisation's copy of a library environment used only for solo
    play, created on first use and hidden from the facilitator's picker."""
    name = ARENA_PREFIX + env_library.ENVIRONMENT_TEMPLATES[env_key]["name"]
    env = db.execute(select(models.Environment).where(
        models.Environment.org_id == org_id, models.Environment.name == name,
        models.Environment.archived_at.is_(None))).scalars().first()
    if env is None:
        env = env_library.build_from_template(env_key, name=name)
        env.org_id = org_id
        vis = dict(env.visibility or {})
        vis["solo"] = True
        env.visibility = vis
        db.add(env)
        db.flush()
    return env


def _with_distractors(scenario: models.Scenario, n: int, rng: random.Random) -> None:
    if n <= 0:
        return
    for inj in scenario.injects:
        meta = dict(inj.meta or {})
        decl = meta.get("decision")
        options = list(decl.get("options") or []) if isinstance(decl, dict) else None
        if options is None:
            # derive the card the engine would derive, so the distractors can join it
            actions = [a for a in (inj.expected_actions or []) if str(a).strip()]
            if not actions:
                continue
            options = [{"key": chr(97 + i), "label": a, "score": 1.0} for i, a in enumerate(actions[:6])]
            options.append({"key": chr(97 + len(options)), "label": "Wait and monitor", "score": 0.2, "note": "Delay rarely helps."})
            decl = {"prompt": "What does your team do first?", "options": options}
        picks = rng.sample(DISTRACTORS, k=min(n, len(DISTRACTORS)))
        for label, note in picks:
            options.append({"key": chr(97 + len(options)), "label": label, "score": 0.0, "note": note})
        decl["options"] = options[:8]
        meta["decision"] = decl
        inj.meta = meta


def build(db: Session, org_id: int, side: str, etype: str, difficulty: str, seed: int | None = None) -> models.Scenario:
    kinds = TYPES.get(side) or {}
    if etype not in kinds:
        raise ValueError(f"unknown engagement type '{etype}' for the {side} side")
    if difficulty not in LEVERS:
        raise ValueError(f"difficulty must be one of {list(LEVERS)}")
    t = kinds[etype]
    rng = random.Random(seed)
    env = arena(db, org_id, rng.choice(t["envs"]))
    actor_key = rng.choice([a for a in t["actors"] if a in THREAT_ACTORS] or ["ransomware_affiliate"])
    scenario = generator.build_scenario(env, actor_key, template_key=t["template"],
                                        name=f"{t['label']} · {THREAT_ACTORS[actor_key]['name']} · {difficulty}")
    scenario.org_id = org_id
    scenario.exercise_type = "solo"
    if side == "exec":
        # the generated story is addressed to blue; the executive plays the same scenes from the leadership seat
        cells = [c for c in (scenario.cells or []) if c.get("key") != "exec_cell"]
        cells.append({"key": "exec_cell", "name": "Executive Cell (leadership + comms)", "kind": "participant"})
        scenario.cells = cells
        for inj in scenario.injects:
            inj.visible_to = sorted(set(inj.visible_to or []) | {"exec_cell"})
    scenario.variables = {**dict(scenario.variables or {}),
                          "solo_engagement": {"side": side, "type": etype, "difficulty": difficulty, "actor": actor_key,
                                              "environment_key": env.name.replace(ARENA_PREFIX, "")}}
    if side != "red":
        _with_distractors(scenario, levers(difficulty)["distractors"], rng)
    db.add(scenario)
    db.flush()
    return scenario


def scaled_environment(env: models.Environment, difficulty: str) -> models.Environment:
    """A transient copy of the environment with the red-side levers applied:
    named controls' efficacy scaled, deception live or not. Never persisted.

    Wildcard controls (``covers: ["*"]``, the SIEM that sees a little of
    everything) are left alone: they sit just under the detection threshold by
    design, and scaling them over it made every move detected on hard and
    expert in four of the six arenas (nothing unseen, nothing to learn)."""
    lv = levers(difficulty)
    copy = models.Environment(id=env.id, org_id=env.org_id, name=env.name, sector=env.sector, box_type=env.box_type,
                              assets=list(env.assets or []), crown_jewels=list(env.crown_jewels or []))
    def scale(items):
        out = []
        for c in items or []:
            c = dict(c)
            if "*" not in (c.get("covers") or []):
                c["efficacy"] = max(0.0, min(0.98, float(c.get("efficacy", 0.0)) * lv["efficacy"]))
            out.append(c)
        return out
    copy.controls = scale(env.controls)
    copy.detections = scale(env.detections)
    copy.deception_assets = list(env.deception_assets or []) if lv["deception"] else []
    return copy


_KNOWN: set[str] = set()


def known_techniques() -> set[str]:
    """Every technique id this build models: the inject bank, the adversary
    catalog, and the controls of the library environments. Computed once."""
    if not _KNOWN:
        for b in INJECT_BANK.values():
            _KNOWN.update(technique.normalize(t) for t in b.get("techniques") or [])
        for a in THREAT_ACTORS.values():
            _KNOWN.update(technique.normalize(t) for t in a.get("techniques") or [])
        for t in env_library.ENVIRONMENT_TEMPLATES.values():
            for c in (t.get("controls") or []) + (t.get("detections") or []) + (t.get("deception_assets") or []):
                _KNOWN.update(technique.normalize(x) for x in c.get("covers") or [] if x != "*")
        _KNOWN.discard("")
    return _KNOWN


def unknown_techniques(techniques: list[str], env: models.Environment, scenario_techniques: set[str]) -> list[str]:
    """Ids a red move may not use: malformed, or known neither to this build,
    nor to the arena's controls, nor to the scenario's own scenes. Parents
    and sub-techniques of a known id count as known."""
    known = set(known_techniques()) | {technique.normalize(t) for t in scenario_techniques}
    for c in list(env.controls or []) + list(env.detections or []) + list(env.deception_assets or []):
        known.update(technique.normalize(x) for x in c.get("covers") or [] if x != "*")
    bad = []
    for t in techniques:
        n = technique.normalize(t)
        if not technique.is_valid(n) or not any(technique.covers(k, n) for k in known):
            bad.append(t)
    return bad


def shuffled(options: list[dict], seed: str) -> list[dict]:
    rng = random.Random(seed)
    out = list(options)
    rng.shuffle(out)
    return out
