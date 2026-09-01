"""Compliance crosswalk (M7 phase 2).

The design principle: an exercise objective maps to a canonical **capability**
(detect / triage / contain / eradicate / recover / communicate / govern), and
each capability cross-walks to the relevant controls in each framework. So one
exercise emits evidence for many frameworks at once, and adding a framework is a
mapping table — not new exercise logic.

These mappings indicate which controls an exercise is **relevant to** for
remediation and evidence. They are not a compliance assessment or attestation.
"""
from __future__ import annotations

CAPABILITIES = ["detect", "triage", "contain", "eradicate", "recover", "communicate", "govern"]

FRAMEWORKS = {
    # Tier 1 — core packs (M7).
    "pci": "PCI-DSS v4.0",
    "dora": "DORA (Digital Operational Resilience Act)",
    "nist_csf": "NIST Cybersecurity Framework 2.0",
    "cis_v8": "CIS Controls v8",
    "iso_27001": "ISO/IEC 27001:2022",
    "soc2": "SOC 2 (Trust Services Criteria)",
    # Tier 2 — sector & regional packs (F2).
    "hipaa": "HIPAA Security Rule (45 CFR Part 164)",
    "nerc_cip": "NERC CIP (Critical Infrastructure Protection)",
    "ffiec": "FFIEC (CAT / IT Examination Handbook)",
    "nis2": "NIS2 Directive (EU 2022/2555)",
    "nist_800_53": "NIST SP 800-53 Rev. 5",
}

# Grouping so a UI can present core vs. sector/regional packs.
FRAMEWORK_TIER = {
    "pci": 1, "dora": 1, "nist_csf": 1, "cis_v8": 1, "iso_27001": 1, "soc2": 1,
    "hipaa": 2, "nerc_cip": 2, "ffiec": 2, "nis2": 2, "nist_800_53": 2,
}

# framework -> capability -> [(control id, title)]
CROSSWALK: dict[str, dict[str, list[tuple[str, str]]]] = {
    "nist_csf": {
        "detect": [("DE.AE", "Adverse Event Analysis"), ("DE.CM", "Continuous Monitoring")],
        "triage": [("RS.AN", "Incident Analysis")],
        "contain": [("RS.MI", "Incident Mitigation")],
        "eradicate": [("RS.MI", "Incident Mitigation")],
        "recover": [("RC.RP", "Incident Recovery Plan Execution")],
        "communicate": [("RS.CO", "Incident Response Reporting & Communication"),
                        ("RC.CO", "Incident Recovery Communication")],
        "govern": [("GV.RM", "Risk Management Strategy"), ("GV.OC", "Organizational Context")],
    },
    "cis_v8": {
        "detect": [("8.11", "Conduct Audit Log Reviews"), ("13.1", "Centralize Security Event Alerting")],
        "triage": [("17.4", "Establish and Maintain an Incident Response Process")],
        "contain": [("17.7", "Conduct Routine Incident Response Exercises"),
                    ("17.9", "Establish and Maintain Post-Incident Reviews")],
        "eradicate": [("17.7", "Conduct Routine Incident Response Exercises")],
        "recover": [("11.2", "Perform Automated Backups"), ("11.5", "Test Data Recovery")],
        "communicate": [("17.5", "Assign Key Roles and Responsibilities"),
                        ("17.6", "Define Mechanisms for Communicating During Incident Response")],
        "govern": [("17.1", "Designate Personnel to Manage Incident Handling")],
    },
    "iso_27001": {
        "detect": [("A.5.25", "Assessment and decision on information security events"),
                   ("A.8.16", "Monitoring activities")],
        "triage": [("A.5.25", "Assessment and decision on information security events"),
                   ("A.5.26", "Response to information security incidents")],
        "contain": [("A.5.26", "Response to information security incidents")],
        "eradicate": [("A.5.26", "Response to information security incidents")],
        "recover": [("A.5.29", "Information security during disruption"),
                    ("A.5.30", "ICT readiness for business continuity")],
        "communicate": [("A.6.8", "Information security event reporting"),
                        ("A.5.5", "Contact with authorities")],
        "govern": [("A.5.24", "Information security incident management planning and preparation")],
    },
    "soc2": {
        "detect": [("CC7.2", "Monitors system components for anomalies"),
                   ("CC7.3", "Evaluates security events")],
        "triage": [("CC7.3", "Evaluates security events")],
        "contain": [("CC7.4", "Responds to identified security incidents")],
        "eradicate": [("CC7.4", "Responds to identified security incidents")],
        "recover": [("CC7.5", "Recovers from identified security incidents"),
                    ("A1.3", "Tests recovery plan procedures")],
        "communicate": [("CC2.3", "Communicates with external parties"),
                        ("CC7.4", "Responds to identified security incidents")],
        "govern": [("CC1.1", "Demonstrates commitment to integrity and ethical values")],
    },
    "pci": {
        "detect": [("10.4", "Audit logs are reviewed"), ("12.10.5", "IR plan monitors security alerts")],
        "triage": [("12.10.1", "Incident response plan exists and is ready to be activated")],
        "contain": [("12.10.1", "Incident response plan exists and is ready to be activated")],
        "eradicate": [("12.10.1", "Incident response plan exists and is ready to be activated")],
        "recover": [("12.10.1", "Incident response plan exists and is ready to be activated")],
        "communicate": [("12.10.3", "Specific personnel are available on a 24/7 basis to respond")],
        "govern": [("12.10.2", "Incident response plan is reviewed and tested at least annually")],
    },
    "dora": {
        "detect": [("Art.10", "Detection of anomalous activities")],
        "triage": [("Art.17", "ICT-related incident management process")],
        "contain": [("Art.17", "ICT-related incident management process")],
        "eradicate": [("Art.17", "ICT-related incident management process")],
        "recover": [("Art.11", "Response and recovery"), ("Art.12", "Backup and restoration procedures")],
        "communicate": [("Art.19", "Reporting of major ICT-related incidents")],
        "govern": [("Art.24", "Digital operational resilience testing programme")],
    },
    # ------------------------------------------------------------------ Tier 2
    "hipaa": {
        "detect": [("164.308(a)(1)(ii)(D)", "Information system activity review")],
        "triage": [("164.308(a)(6)(i)", "Security incident procedures")],
        "contain": [("164.308(a)(6)(ii)", "Response and reporting")],
        "eradicate": [("164.308(a)(6)(ii)", "Response and reporting")],
        "recover": [("164.308(a)(7)(i)", "Contingency plan"),
                    ("164.308(a)(7)(ii)(D)", "Testing and revision procedures")],
        "communicate": [("164.308(a)(6)(ii)", "Response and reporting"),
                        ("164.404", "Breach notification to individuals")],
        "govern": [("164.308(a)(1)(i)", "Security management process"),
                   ("164.316", "Policies, procedures, and documentation requirements")],
    },
    "nerc_cip": {
        "detect": [("CIP-007-6 R4", "Security event monitoring")],
        "triage": [("CIP-008-6 R1", "Incident response plan specifications")],
        "contain": [("CIP-008-6 R2", "Incident response plan implementation and testing")],
        "eradicate": [("CIP-008-6 R2", "Incident response plan implementation and testing")],
        "recover": [("CIP-009-6 R1", "Recovery plan specifications"),
                    ("CIP-009-6 R3", "Recovery plan review, update, and testing")],
        "communicate": [("CIP-008-6 R4", "Notifications and reporting (E-ISAC)")],
        "govern": [("CIP-008-6 R3", "Incident response plan review, update, and communication")],
    },
    "ffiec": {
        "detect": [("D3.DC", "Detective controls"), ("D2.TI", "Threat intelligence")],
        "triage": [("D5.IR", "Incident resilience planning and strategy")],
        "contain": [("D5.DR", "Detection, response, and mitigation")],
        "eradicate": [("D5.DR", "Detection, response, and mitigation")],
        "recover": [("D5.ER", "Escalation and reporting"),
                    ("BCM", "Business continuity management — recovery testing")],
        "communicate": [("D5.ER", "Escalation and reporting"),
                        ("D4.RM", "External dependency management")],
        "govern": [("D1.RM", "Cyber risk management and oversight")],
    },
    "nis2": {
        "detect": [("Art.21(2)(b)", "Incident handling — detection")],
        "triage": [("Art.21(2)(b)", "Incident handling")],
        "contain": [("Art.21(2)(b)", "Incident handling")],
        "eradicate": [("Art.21(2)(b)", "Incident handling")],
        "recover": [("Art.21(2)(c)", "Business continuity, backup, and disaster recovery")],
        "communicate": [("Art.23", "Reporting obligations (24h early warning / 72h notification)")],
        "govern": [("Art.20", "Governance — management body responsibility"),
                   ("Art.21(1)", "Cybersecurity risk-management measures")],
    },
    "nist_800_53": {
        "detect": [("SI-4", "System monitoring"), ("AU-6", "Audit record review, analysis, and reporting")],
        "triage": [("IR-4", "Incident handling"), ("IR-5", "Incident monitoring")],
        "contain": [("IR-4", "Incident handling")],
        "eradicate": [("IR-4", "Incident handling")],
        "recover": [("CP-10", "System recovery and reconstitution"),
                    ("CP-4", "Contingency plan testing")],
        "communicate": [("IR-6", "Incident reporting"), ("IR-7", "Incident response assistance")],
        "govern": [("IR-8", "Incident response plan"), ("IR-3", "Incident response testing")],
    },
}

_RANK = {"met": 3, "partial": 2, "missed": 1, "not_assessed": 0}
_STATUS = {3: "demonstrated", 2: "partial", 1: "gap", 0: "not_assessed"}


def _outcome_by_objective(observations) -> dict[str, str]:
    """Best observed rating per objective (met > partial > missed)."""
    best: dict[str, int] = {}
    for o in observations:
        r = o.rating if o.rating in _RANK else None
        if r is None:
            continue
        best[o.objective_code] = max(best.get(o.objective_code, 0), _RANK[r])
    return {code: _STATUS[rank] for code, rank in best.items()}


def build_evidence(scenario, session, observations, only: str | None = None) -> dict:
    """Cross-walk the exercise's objectives to control coverage per framework."""
    outcomes = _outcome_by_objective(observations)
    frameworks = [only] if only in FRAMEWORKS else list(FRAMEWORKS)

    out_frameworks = []
    for fw in frameworks:
        cap_map = CROSSWALK[fw]
        # control id -> {title, capability, objectives:[{code,title,status}], status_rank}
        controls: dict[str, dict] = {}

        def _add(cid, title, capability, obj):
            entry = controls.setdefault(cid, {
                "id": cid, "title": title, "capabilities": set(),
                "objectives": [], "rank": 0,
            })
            entry["capabilities"].add(capability)
            status = outcomes.get(obj.code, "not_assessed")
            entry["objectives"].append({"code": obj.code, "title": obj.title, "status": status})
            entry["rank"] = max(entry["rank"], _RANK[{
                "demonstrated": "met", "partial": "partial", "gap": "missed", "not_assessed": "not_assessed"
            }[status]])

        for obj in scenario.objectives:
            cap = (obj.meta or {}).get("capability")
            # capability-mapped controls
            for cid, title in cap_map.get(cap, []):
                _add(cid, title, cap or "general", obj)
            # explicit control refs on the objective override/augment the crosswalk
            for cid in ((obj.meta or {}).get("compliance", {}) or {}).get(fw, []):
                title = _lookup_title(fw, cid)
                _add(cid, title, cap or "general", obj)

        rows = []
        for c in sorted(controls.values(), key=lambda x: x["id"]):
            rows.append({
                "id": c["id"], "title": c["title"],
                "capabilities": sorted(c["capabilities"]),
                "objectives": c["objectives"], "status": _STATUS[c["rank"]],
            })
        out_frameworks.append({
            "key": fw, "name": FRAMEWORKS[fw],
            "controls": rows,
            "summary": {
                "controls": len(rows),
                "demonstrated": sum(1 for r in rows if r["status"] == "demonstrated"),
                "gaps": sum(1 for r in rows if r["status"] == "gap"),
            },
        })

    return {
        "exercise": {
            "scenario": scenario.name,
            "threat_actor": scenario.threat_actor,
            "session": session.name,
            "exercise_type": scenario.exercise_type,
        },
        "disclaimer": ("Control mappings indicate relevance for remediation and evidence; "
                       "they are not a compliance assessment, audit, or attestation."),
        "frameworks": out_frameworks,
    }


def _lookup_title(fw: str, cid: str) -> str:
    for refs in CROSSWALK.get(fw, {}).values():
        for rid, title in refs:
            if rid == cid:
                return title
    return cid


def render_markdown(evidence: dict) -> str:
    ex = evidence["exercise"]
    lines = [f"# Compliance Evidence — {ex['scenario']}", ""]
    lines.append(f"_Session: **{ex['session']}** · Type: {ex['exercise_type']} · "
                 f"Threat: {ex['threat_actor'] or 'n/a'}_\n")
    lines.append(f"> {evidence['disclaimer']}\n")
    for fw in evidence["frameworks"]:
        s = fw["summary"]
        lines.append(f"## {fw['name']}")
        lines.append(f"_{s['demonstrated']} demonstrated · {s['gaps']} gap(s) · "
                     f"{s['controls']} control(s) relevant_\n")
        lines.append("| Control | Title | Status | Objectives |")
        lines.append("|---|---|---|---|")
        for c in fw["controls"]:
            objs = ", ".join(f"{o['code']} ({o['status']})" for o in c["objectives"])
            lines.append(f"| {c['id']} | {c['title']} | {c['status']} | {objs} |")
        lines.append("")
    return "\n".join(lines)
