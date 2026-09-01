"""CISA CTEP importer (D5).

CISA publishes free Cybersecurity Tabletop Exercise Packages (CTEPs) — the most
widely used *starting point* in the space — but they ship as static documents:
objectives, a scenario split into modules, and discussion questions. Gauntlet
turns that structure into a **runnable, adjudicated** scenario: each CTEP module
becomes an inject wired into the branching engine, discussion questions become
expected actions, and CTEP objectives become measurable objectives.

Import is offline by design (consistent with air-gapped mode): a facilitator
picks a bundled CTEP-derived pack or uploads a CTEP-structured pack — Gauntlet
never fetches from cisa.gov. The bundled packs below are modelled on the public
CTEP format with original wording (not copied CISA text).

Pack shape::

    {
      "title": "...", "threat_actor": "...", "scope": "...",
      "objectives": [{"title": "...", "success_criteria": "..."}],
      "modules": [{"title": "...", "narrative": "...", "techniques": ["T1566"],
                   "discussion_questions": ["...", "..."]}],
    }
"""
from __future__ import annotations

from .. import models

# Bundled CTEP-derived packs (original wording, CTEP structure).
CTEP_PACKS: dict[str, dict] = {
    "ransomware": {
        "title": "Ransomware CTEP",
        "threat_actor": "Ransomware operator",
        "scope": "Discussion-based tabletop covering detection, containment, "
                 "continuity and recovery from an enterprise ransomware event.",
        "roe": "Facilitated discussion. No live systems are touched; 'pause' halts play.",
        "objectives": [
            {"title": "Detection & reporting", "success_criteria": "Initial indicators are recognised and escalated through the incident process."},
            {"title": "Containment decisions", "success_criteria": "Isolation and access-revocation decisions are made and their business impact weighed."},
            {"title": "Continuity of operations", "success_criteria": "Critical services are prioritised and continuity plans invoked."},
            {"title": "Recovery & communications", "success_criteria": "Recovery from trusted backups is planned and internal/external comms executed."},
        ],
        "modules": [
            {"title": "Module 1 — Suspicious activity", "techniques": ["T1566.001"],
             "narrative": "Endpoint tools flag unusual encryption activity on a file server and several users report inaccessible documents.",
             "discussion_questions": [
                 "Who is notified first, and through what channel?",
                 "What tells you this is ransomware rather than a hardware failure?",
                 "At what point does this become a declared incident?"]},
            {"title": "Module 2 — Spread & containment", "techniques": ["T1021.002", "T1486"],
             "narrative": "Encryption is spreading across shares and a ransom note appears. Domain admin accounts may be compromised.",
             "discussion_questions": [
                 "What can you isolate, and what does isolating it cost the business?",
                 "How do you preserve evidence while containing the spread?",
                 "Who authorises taking production systems offline?"]},
            {"title": "Module 3 — Business impact", "techniques": [],
             "narrative": "Core services are degraded. Leadership asks for an impact assessment and a recovery timeline.",
             "discussion_questions": [
                 "Which services are restored first, and why?",
                 "What is your position on paying a ransom, and who decides?",
                 "What are your legal/regulatory notification obligations?"]},
            {"title": "Module 4 — Recovery & lessons", "techniques": [],
             "narrative": "Backups are being validated and restoration is underway. The event is nearing resolution.",
             "discussion_questions": [
                 "How do you know a backup is clean before you restore from it?",
                 "What internal and external communications go out, and when?",
                 "What one control, if it had existed, would have changed this outcome?"]},
        ],
    },
    "ics_ot": {
        "title": "ICS / OT disruption CTEP",
        "threat_actor": "State-aligned OT intruder",
        "scope": "Tabletop for an intrusion threatening operational-technology "
                 "processes — IT/OT coordination, safety, and continuity.",
        "roe": "Facilitated discussion. Safety takes precedence; 'pause' halts play.",
        "objectives": [
            {"title": "IT/OT detection", "success_criteria": "Anomalies crossing the IT/OT boundary are detected and jointly triaged."},
            {"title": "Safety-first containment", "success_criteria": "Containment weighs process safety and does not create an unsafe state."},
            {"title": "Process continuity", "success_criteria": "Manual/degraded operating modes are invoked to sustain the process."},
            {"title": "Coordination & recovery", "success_criteria": "IT, OT, safety and leadership coordinate recovery and external reporting."},
        ],
        "modules": [
            {"title": "Module 1 — Boundary anomaly", "techniques": ["T0886", "T1190"],
             "narrative": "Network monitoring shows unexpected connections between the corporate network and a historian in the OT environment.",
             "discussion_questions": [
                 "Who owns the decision when an alert spans IT and OT?",
                 "What visibility do you actually have inside the OT network?",
                 "How do you triage without disturbing the process?"]},
            {"title": "Module 2 — Process anomaly", "techniques": ["T0836"],
             "narrative": "Operators report set-points that don't match their commands. A safety instrumented function is questioned.",
             "discussion_questions": [
                 "How do you distinguish an attack from an equipment fault?",
                 "What is the threshold for moving to manual operation?",
                 "Who has authority to stop the process, and how fast can they?"]},
            {"title": "Module 3 — Continuity & recovery", "techniques": [],
             "narrative": "The process is stabilised in a degraded mode while investigation continues.",
             "discussion_questions": [
                 "How long can you run in degraded mode, and what breaks first?",
                 "What must be validated before returning to automated control?",
                 "Which regulators and partners must be notified, and when?"]},
        ],
    },
}


def _objs(items: list[dict]) -> list[models.Objective]:
    out = []
    for i, o in enumerate(items, start=1):
        out.append(models.Objective(
            code=f"OBJ-{i}", title=o.get("title", f"Objective {i}"),
            description=o.get("title", ""),
            success_criteria=o.get("success_criteria", ""),
            meta={"source": "ctep"},
        ))
    return out


def build_from_pack(env: models.Environment, pack: dict, name: str | None = None) -> models.Scenario:
    """Turn a CTEP pack into an unsaved, runnable Scenario bound to ``env``."""
    modules = pack.get("modules") or []
    if not modules:
        raise ValueError("a CTEP pack needs at least one module")
    objectives = pack.get("objectives") or []
    codes = [f"INJ-{i + 1:02d}" for i in range(len(modules))]
    end_code = f"INJ-{len(modules) + 1:02d}"

    injects: list[models.Inject] = []
    for i, m in enumerate(modules):
        nxt = codes[i + 1] if i + 1 < len(modules) else end_code
        obj_code = f"OBJ-{min(i + 1, len(objectives)) or 1}" if objectives else ""
        injects.append(models.Inject(
            code=codes[i], sequence=i + 1, is_start=(i == 0),
            title=m.get("title", f"Module {i + 1}"),
            channel="briefing", clock=f"T+{i * 20:02d}:00",
            narrative=m.get("narrative", ""),
            visible_to=["blue_cell", "white_cell"],
            expected_actions=list(m.get("discussion_questions") or []),
            attack_techniques=list(m.get("techniques") or []),
            target_asset="", objective_code=obj_code,
            branches=[{"when": "proctor_choice", "goto": nxt,
                       "label": "Facilitator: move to the next module"}],
        ))
    injects.append(models.Inject(
        code=end_code, sequence=len(modules) + 1, is_start=False,
        title="Hotwash", channel="briefing", clock=f"T+{len(modules) * 20:02d}:00",
        narrative="Capture observations and run the after-action review.",
        visible_to=["blue_cell", "white_cell"],
        expected_actions=["Run the hotwash", "Log improvement items"],
        attack_techniques=[], target_asset="",
        objective_code=(f"OBJ-{len(objectives)}" if objectives else ""), branches=[],
    ))

    return models.Scenario(
        environment_id=env.id,
        name=name or pack.get("title", "CTEP exercise"),
        threat_actor=pack.get("threat_actor", "Tabletop scenario"),
        narrative=pack.get("title", ""),
        scope=pack.get("scope", "Discussion-based tabletop."),
        rules_of_engagement=pack.get("roe", "Facilitated exercise only."),
        exercise_type="tabletop",
        cells=[{"key": "blue_cell", "name": "Blue Cell", "kind": "participant"},
               {"key": "white_cell", "name": "White Cell", "kind": "control"}],
        objectives=_objs(objectives) or _objs([{"title": "Exercise the incident process",
                                                "success_criteria": "The team works the scenario end to end."}]),
        injects=injects,
    )
