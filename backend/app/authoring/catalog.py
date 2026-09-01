"""The reusable catalog: an inject bank, threat-actor profiles, and templates.

* **Inject bank** — parameterised scene templates keyed by kill-chain phase and
  ATT&CK technique, with a delivery channel and a target zone. The generator
  fills the ``{...}`` placeholders with real assets from the environment.
* **Threat actors** — an ordered kill-chain (a list of inject-bank keys) plus a
  preset objective set. Choosing an actor is how you say "generate a plausible
  campaign of this shape".
* **Templates** — a named packaging of an actor with narrative, scope, and
  rules of engagement, so a proctor can start from "Ransomware — finance".
"""
from __future__ import annotations

# --------------------------------------------------------------------------- #
# Inject bank — reusable, parameterised scenes.
#   placeholders: {org} {asset} {asset_name}
#   target_zone steers which environment asset the generator picks.
# --------------------------------------------------------------------------- #
INJECT_BANK: dict[str, dict] = {
    "phish_invoice": {
        "phase": "initial-access", "channel": "email", "target_zone": "user",
        "techniques": ["T1566.001"], "objective_hint": "detect",
        "title": "Phishing email reported — fake invoice",
        "narrative": ("A {org} employee forwards a suspicious invoice email to the SOC "
                      "mailbox. It links to a look-alike SSO portal aimed at {asset_name}."),
        "expected_actions": ["Triage against the phishing playbook",
                             "Check who else received the message"],
    },
    "phish_credential": {
        "phase": "initial-access", "channel": "email", "target_zone": "user",
        "techniques": ["T1566.002"], "objective_hint": "detect",
        "title": "Spear-phish with credential link",
        "narrative": ("A targeted email to a finance approver at {org} carries a link to "
                      "a credential-harvesting page themed as a payment portal."),
        "expected_actions": ["Detonate the link safely", "Warn recipients"],
    },
    "exploit_public": {
        "phase": "initial-access", "channel": "siem_alert", "target_zone": "perimeter",
        "techniques": ["T1190"], "objective_hint": "detect",
        "title": "Exploit attempt against {asset_name}",
        "narrative": ("The WAF and SIEM show repeated exploitation attempts against the "
                      "internet-facing {asset_name} ({asset})."),
        "expected_actions": ["Confirm whether exploitation succeeded",
                             "Check the asset's patch level"],
    },
    "malware_exec": {
        "phase": "execution", "channel": "edr_alert", "target_zone": "user",
        "techniques": ["T1204.002", "T1059.001"], "objective_hint": "triage",
        "title": "EDR: scripted payload executed on {asset_name}",
        "narrative": ("Defender flags a macro-spawned PowerShell process on {asset_name} "
                      "({asset}) reaching out to an unknown host."),
        "expected_actions": ["Triage the alert", "Contain the endpoint if confirmed"],
    },
    "c2_beacon": {
        "phase": "command-and-control", "channel": "siem_alert", "target_zone": "app",
        "techniques": ["T1071.001"], "objective_hint": "triage",
        "title": "Beaconing traffic from {asset_name}",
        "narrative": ("Regular, low-and-slow HTTPS beacons leave {asset_name} ({asset}) "
                      "to a newly registered domain."),
        "expected_actions": ["Correlate with proxy logs", "Scope affected hosts"],
    },
    "lsass_dump": {
        "phase": "credential-access", "channel": "edr_alert", "target_zone": "app",
        "techniques": ["T1003.001"], "objective_hint": "contain",
        "title": "EDR flags LSASS access on {asset_name}",
        "narrative": ("A non-standard process read LSASS memory on {asset_name} ({asset}); "
                      "credential theft is likely."),
        "expected_actions": ["Triage against the IR playbook",
                             "Check whether the host is crown-jewel-adjacent"],
    },
    "lateral_smb": {
        "phase": "lateral-movement", "channel": "siem_alert", "target_zone": "app",
        "techniques": ["T1021.002"], "objective_hint": "contain",
        "title": "Lateral movement toward {asset_name}",
        "narrative": ("Reused credentials authenticate over SMB toward {asset_name} "
                      "({asset}) — the adversary is spreading."),
        "expected_actions": ["Decide on containment", "Watch for any deception signal"],
    },
    "priv_esc_dc": {
        "phase": "privilege-escalation", "channel": "siem_alert", "target_zone": "core",
        "techniques": ["T1078", "T1098"], "objective_hint": "contain",
        "title": "Privileged account minted on {asset_name}",
        "narrative": ("A new privileged account appears on {asset_name} ({asset}); the "
                      "adversary may now control the domain."),
        "expected_actions": ["Escalate to full IR", "Consider domain-wide credential reset"],
    },
    "insider_access": {
        "phase": "initial-access", "channel": "siem_alert", "target_zone": "app",
        "techniques": ["T1078"], "objective_hint": "detect",
        "title": "After-hours access to {asset_name}",
        "narrative": ("A privileged employee accesses {asset_name} ({asset}) far outside "
                      "their normal pattern, browsing data unrelated to their role."),
        "expected_actions": ["Confirm business justification", "Preserve access logs"],
    },
    "data_staging": {
        "phase": "collection", "channel": "ticket", "target_zone": "app",
        "techniques": ["T1074"], "objective_hint": "contain",
        "title": "Large archive staged on {asset_name}",
        "narrative": ("An unusually large compressed archive is assembled on {asset_name} "
                      "({asset}) — data is being staged for exfiltration."),
        "expected_actions": ["Identify the data classification", "Restrict egress"],
    },
    "exfil_dns": {
        "phase": "exfiltration", "channel": "siem_alert", "target_zone": "core",
        "techniques": ["T1048"], "objective_hint": "contain",
        "title": "Exfiltration over an alternate channel from {asset_name}",
        "narrative": ("Sustained anomalous outbound traffic from {asset_name} ({asset}) "
                      "suggests data is leaving over a non-standard channel."),
        "expected_actions": ["Block the channel", "Quantify what left"],
    },
    "bec_wire_request": {
        "phase": "impact", "channel": "email", "target_zone": "user",
        "techniques": ["T1656"], "objective_hint": "prevent-loss",
        "title": "Urgent wire-transfer request from a spoofed executive",
        "narrative": ("Finance at {org} receives an urgent wire-change request appearing "
                      "to come from an executive, pressuring an immediate payment."),
        "expected_actions": ["Verify out-of-band against policy", "Halt the payment"],
    },
    "ransomware_deploy": {
        "phase": "impact", "channel": "edr_alert", "target_zone": "core",
        "techniques": ["T1486", "T1490"], "objective_hint": "recover",
        "title": "Ransomware staging on {asset_name}",
        "narrative": ("Mass file-encryption begins and the adversary tries to delete "
                      "backup snapshots reachable from {asset_name} ({asset})."),
        "expected_actions": ["Invoke the ransomware IR playbook",
                             "Protect and validate immutable backups",
                             "Engage the communications lead"],
    },
}


# Objectives are ordered along the response lifecycle; tag them with the
# canonical capability so generated scenarios also emit compliance evidence.
_CAPS = ["detect", "triage", "contain", "recover", "communicate", "govern"]


def _objs(*items) -> list[dict]:
    out = []
    for i, (title, crit) in enumerate(items, start=1):
        out.append({"code": f"OBJ-{i}", "title": title, "success_criteria": crit,
                    "description": title, "meta": {"capability": _CAPS[min(i - 1, len(_CAPS) - 1)]}})
    return out


# --------------------------------------------------------------------------- #
# Threat-actor profiles: an ordered kill-chain + preset objectives.
# --------------------------------------------------------------------------- #
THREAT_ACTORS: dict[str, dict] = {
    "ransomware_affiliate": {
        "name": "Ransomware affiliate",
        "label": "Financially motivated ransomware affiliate (phishing → ransomware)",
        "description": "Phishing-led intrusion escalating to domain compromise and ransomware.",
        "kill_chain": ["phish_invoice", "malware_exec", "lsass_dump", "lateral_smb",
                       "ransomware_deploy"],
        "objectives": _objs(
            ("Detect the initial intrusion", "Initial access identified and escalated within 30 game-minutes."),
            ("Triage and scope the compromise", "Compromised host identified and its crown-jewel dependency recognised."),
            ("Contain lateral movement", "Host isolated before the domain controller is reached."),
            ("Recover and communicate", "Recovery initiated from immutable backups; comms plan executed."),
        ),
    },
    "bec_actor": {
        "name": "Business email compromise actor",
        "label": "BEC / payment-fraud actor (credential theft → wire fraud)",
        "description": "Credential phishing leading to a fraudulent wire-transfer attempt.",
        "kill_chain": ["phish_credential", "insider_access", "bec_wire_request"],
        "objectives": _objs(
            ("Detect the credential phish", "Phishing identified and affected accounts reset."),
            ("Spot the account takeover", "Anomalous access recognised and investigated."),
            ("Prevent the financial loss", "Wire request verified out-of-band and stopped per policy."),
        ),
    },
    "malicious_insider": {
        "name": "Malicious insider",
        "label": "Privileged insider exfiltrating sensitive data",
        "description": "A trusted employee abuses access to collect and exfiltrate data.",
        "kill_chain": ["insider_access", "data_staging", "exfil_dns"],
        "objectives": _objs(
            ("Detect the anomalous access", "Out-of-pattern access flagged and reviewed."),
            ("Scope the collection", "Staged data identified and classified."),
            ("Contain the exfiltration", "Egress channel blocked and loss quantified."),
        ),
    },
    "apt_espionage": {
        "name": "Espionage-motivated intruder",
        "label": "Targeted intrusion for long-dwell data theft",
        "description": "External exploitation, quiet C2, credential theft, lateral movement, exfiltration.",
        "kill_chain": ["exploit_public", "c2_beacon", "lsass_dump", "lateral_smb", "exfil_dns"],
        "objectives": _objs(
            ("Detect the external intrusion", "Exploitation or C2 recognised early."),
            ("Triage and scope", "Compromised hosts and accounts identified."),
            ("Contain the intruder", "Lateral movement halted before crown jewels."),
            ("Eradicate and quantify", "Access removed and data-loss quantified."),
        ),
    },
}


# --------------------------------------------------------------------------- #
# Templates: named packaging of an actor + narrative + scope + RoE.
# --------------------------------------------------------------------------- #
SCENARIO_TEMPLATES: dict[str, dict] = {
    "ransomware_finance": {
        "name": "Ransomware — financial services",
        "actor": "ransomware_affiliate",
        "narrative": "A phishing-led ransomware intrusion tests detection, containment, and recovery.",
        "scope": "Discussion-based tabletop. No live systems are touched.",
        "roe": "Facilitated exercise only. 'Pause' halts play at any time. All actions are simulated.",
    },
    "bec_finance": {
        "name": "Business email compromise — payment fraud",
        "actor": "bec_actor",
        "narrative": "A BEC campaign pressures finance into a fraudulent wire transfer.",
        "scope": "Discussion-based tabletop focused on process and verification controls.",
        "roe": "Facilitated exercise only. All actions are simulated.",
    },
    "insider_exfil": {
        "name": "Malicious insider — data exfiltration",
        "actor": "malicious_insider",
        "narrative": "A privileged insider collects and exfiltrates sensitive data.",
        "scope": "Discussion-based tabletop with HR and legal touchpoints.",
        "roe": "Facilitated exercise only. Handle personnel details with care.",
    },
    "apt_intrusion": {
        "name": "Targeted intrusion — long-dwell data theft",
        "actor": "apt_espionage",
        "narrative": "A patient intruder establishes C2 and moves toward crown-jewel data.",
        "scope": "Discussion-based tabletop across SOC, IR, and threat-intel.",
        "roe": "Facilitated exercise only. All actions are simulated.",
    },
}


# --------------------------------------------------------------------------- #
# Built-in scenario library (Q3b): more attack types out of the box.
# Each is a threat-actor kill-chain (ordered inject-bank keys) packaged as a
# template. New scenes reuse the same parameterised shape as the core bank.
# --------------------------------------------------------------------------- #
INJECT_BANK.update({
    "recon_osint": {
        "phase": "discovery", "channel": "intel", "target_zone": "perimeter",
        "techniques": ["T1589", "T1592"], "objective_hint": "detect",
        "title": "OSINT reconnaissance against {org}",
        "narrative": ("Threat-intel flags scraping of {org} employee and infrastructure "
                      "details — a tester or adversary is mapping the attack surface."),
        "expected_actions": ["Assess external exposure", "Note likely target accounts"],
    },
    "net_scan": {
        "phase": "discovery", "channel": "siem_alert", "target_zone": "perimeter",
        "techniques": ["T1046", "T1595"], "objective_hint": "detect",
        "title": "Port and service scanning of {asset_name}",
        "narrative": ("The SIEM shows systematic port and service scanning against the "
                      "internet-facing {asset_name} ({asset})."),
        "expected_actions": ["Confirm the source and intent", "Check exposed services"],
    },
    "exploit_service": {
        "phase": "initial-access", "channel": "siem_alert", "target_zone": "perimeter",
        "techniques": ["T1210", "T1190"], "objective_hint": "triage",
        "title": "Exploitation of a vulnerable service on {asset_name}",
        "narrative": ("A known-vulnerable service on {asset_name} ({asset}) is exploited to "
                      "gain a foothold."),
        "expected_actions": ["Confirm exploitation", "Isolate and patch the service"],
    },
    "vishing": {
        "phase": "initial-access", "channel": "phone", "target_zone": "user",
        "techniques": ["T1566.004", "T1598"], "objective_hint": "detect",
        "title": "Vishing call impersonating IT support",
        "narrative": ("An employee at {org} reports a phone call from 'IT support' pressuring "
                      "them to read back an MFA code or install a remote-support tool."),
        "expected_actions": ["Follow the caller-verification policy", "Report and warn peers"],
    },
    "pretext_helpdesk": {
        "phase": "initial-access", "channel": "phone", "target_zone": "user",
        "techniques": ["T1598", "T1656"], "objective_hint": "detect",
        "title": "Help-desk pretext — password reset",
        "narrative": ("Someone contacts the {org} help desk posing as a travelling executive "
                      "and requests an urgent password reset, bypassing normal checks."),
        "expected_actions": ["Enforce identity-proofing", "Flag the attempt to security"],
    },
    "tailgate_entry": {
        "phase": "initial-access", "channel": "briefing", "target_zone": "facility",
        "techniques": ["T1200"], "objective_hint": "detect",
        "title": "Tailgating into a {org} facility",
        "narrative": ("A tester follows staff through a secured door at {org} without badging "
                      "in, reaching an internal floor unchallenged."),
        "expected_actions": ["Review physical-access policy", "Check reception/escort controls"],
    },
    "badge_clone": {
        "phase": "initial-access", "channel": "briefing", "target_zone": "facility",
        "techniques": ["T1200"], "objective_hint": "triage",
        "title": "Cloned access badge used after hours",
        "narrative": ("A cloned proximity badge is used to enter a restricted area of {org} "
                      "outside working hours."),
        "expected_actions": ["Correlate badge logs with CCTV", "Revoke the credential"],
    },
    "rogue_device": {
        "phase": "command-and-control", "channel": "siem_alert", "target_zone": "core",
        "techniques": ["T1200", "T1571"], "objective_hint": "contain",
        "title": "Rogue device beaconing from inside the network",
        "narrative": ("A small unmanaged device planted on-site at {org} beacons out from an "
                      "internal VLAN reachable from {asset_name}."),
        "expected_actions": ["Locate and quarantine the device", "Trace its network path"],
    },
    "malware_delivery": {
        "phase": "execution", "channel": "email", "target_zone": "user",
        "techniques": ["T1105", "T1204.002"], "objective_hint": "detect",
        "title": "Malicious attachment delivered to {org} staff",
        "narrative": ("A weaponised document is delivered to {org} users; on open it fetches a "
                      "second-stage payload toward {asset_name}."),
        "expected_actions": ["Detonate safely and scope recipients", "Block the payload host"],
    },
    "app_injection": {
        "phase": "initial-access", "channel": "siem_alert", "target_zone": "app",
        "techniques": ["T1190", "T1059"], "objective_hint": "triage",
        "title": "Injection attack against {asset_name}",
        "narrative": ("The WAF logs SQL/command-injection attempts against the {asset_name} "
                      "application, one of which returns unexpected data."),
        "expected_actions": ["Confirm exploitability", "Patch input handling and review logs"],
    },
    "api_abuse": {
        "phase": "collection", "channel": "siem_alert", "target_zone": "app",
        "techniques": ["T1552", "T1078"], "objective_hint": "contain",
        "title": "Broken-authorization API abuse on {asset_name}",
        "narrative": ("Sequential object-id requests to the {asset_name} API return records "
                      "belonging to other tenants — a broken-access-control flaw."),
        "expected_actions": ["Confirm the IDOR", "Add authorization checks and rate limits"],
    },
    "prompt_injection": {
        "phase": "execution", "channel": "app", "target_zone": "app",
        "techniques": ["AML.T0051"], "objective_hint": "triage",
        "title": "Prompt-injection against the {org} AI assistant",
        "narrative": ("A user-supplied document coerces the {org} LLM assistant into ignoring "
                      "its guardrails and revealing system instructions."),
        "expected_actions": ["Reproduce and scope the bypass", "Harden the system prompt / tools"],
    },
    "model_exfil": {
        "phase": "exfiltration", "channel": "siem_alert", "target_zone": "app",
        "techniques": ["AML.T0024", "T1567"], "objective_hint": "contain",
        "title": "Sensitive data leaked through the AI application",
        "narrative": ("The AI assistant is manipulated into returning sensitive records to an "
                      "unauthorized user, exfiltrating data via {asset_name}."),
        "expected_actions": ["Cut the data path", "Quantify what was exposed"],
    },
    "assume_breach": {
        "phase": "lateral-movement", "channel": "edr_alert", "target_zone": "core",
        "techniques": ["T1021", "T1078"], "objective_hint": "triage",
        "title": "Assumed breach — active foothold on {asset_name}",
        "narrative": ("Start from assumed compromise: an attacker already holds valid access "
                      "on {asset_name} ({asset}). Model how far they get."),
        "expected_actions": ["Hunt for the foothold", "Scope reachable crown jewels"],
    },
    "ad_enum": {
        "phase": "discovery", "channel": "edr_alert", "target_zone": "core",
        "techniques": ["T1087", "T1069"], "objective_hint": "detect",
        "title": "Active Directory enumeration from {asset_name}",
        "narrative": ("Bulk account, group, and trust queries run from {asset_name} — classic "
                      "pre-lateral-movement discovery."),
        "expected_actions": ["Detect the enumeration", "Review tiering and privileged groups"],
    },
    "insider_sabotage": {
        "phase": "impact", "channel": "edr_alert", "target_zone": "core",
        "techniques": ["T1485", "T1490"], "objective_hint": "recover",
        "title": "Insider destroys data on {asset_name}",
        "narrative": ("A departing privileged user deletes datasets and disables backups on "
                      "{asset_name} ({asset})."),
        "expected_actions": ["Revoke access immediately", "Recover from immutable backups"],
    },
})


THREAT_ACTORS.update({
    "phishing_campaign": {
        "name": "Phishing campaign", "label": "Email phishing simulation (awareness + detection)",
        "description": "A multi-lure phishing campaign testing reporting and detection.",
        "kill_chain": ["phish_invoice", "phish_credential", "malware_exec"],
        "objectives": _objs(
            ("Detect and report the phish", "Suspicious mail reported to the SOC promptly."),
            ("Scope the campaign", "All recipients identified; credentials reset as needed."),
            ("Contain any execution", "Endpoints that ran the payload isolated."),
        ),
    },
    "pentester": {
        "name": "Network penetration tester", "label": "Authorized network penetration test",
        "description": "Recon → scan → exploit → post-exploitation against the estate.",
        "kill_chain": ["recon_osint", "net_scan", "exploit_service", "lsass_dump", "lateral_smb"],
        "objectives": _objs(
            ("Detect recon and scanning", "Scanning recognised and sourced."),
            ("Catch the exploitation", "Foothold detected and triaged."),
            ("Contain post-exploitation", "Lateral movement halted; findings logged."),
        ),
    },
    "social_engineer": {
        "name": "Social engineer", "label": "Human-focused social-engineering attack",
        "description": "Vishing and help-desk pretexting to obtain access.",
        "kill_chain": ["vishing", "pretext_helpdesk", "insider_access"],
        "objectives": _objs(
            ("Resist the pretext", "Verification policy followed; attempt reported."),
            ("Detect the takeover", "Anomalous access from the ploy recognised."),
            ("Contain and educate", "Access revoked; awareness reinforced."),
        ),
    },
    "malware_operator": {
        "name": "Malware operator", "label": "Malware delivery and execution",
        "description": "Delivery, execution, and command-and-control of commodity malware.",
        "kill_chain": ["malware_delivery", "malware_exec", "c2_beacon"],
        "objectives": _objs(
            ("Detect the delivery", "Malicious delivery caught or reported."),
            ("Triage execution", "Infected endpoints identified."),
            ("Cut the C2", "Command-and-control channel blocked."),
        ),
    },
    "physical_intruder": {
        "name": "Physical intruder", "label": "Physical-security intrusion test",
        "description": "Tailgating, badge cloning, and a planted rogue device.",
        "kill_chain": ["tailgate_entry", "badge_clone", "rogue_device", "data_staging"],
        "objectives": _objs(
            ("Detect the physical breach", "Unauthorized entry noticed and challenged."),
            ("Find the rogue device", "Planted device located and quarantined."),
            ("Contain and review", "Physical and network controls corrected."),
        ),
    },
    "insider_threat": {
        "name": "Insider threat", "label": "Malicious insider — theft and sabotage",
        "description": "A privileged insider collects data and sabotages systems.",
        "kill_chain": ["insider_access", "data_staging", "insider_sabotage"],
        "objectives": _objs(
            ("Detect the abuse", "Out-of-pattern privileged activity flagged."),
            ("Scope the damage", "Collected data and affected systems identified."),
            ("Recover and act", "Access revoked; recovery and HR/legal engaged."),
        ),
    },
    "multi_vector": {
        "name": "Multi-vector adversary", "label": "Multi-stage, multi-vector intrusion",
        "description": "Parallel phishing and web exploitation converging on ransomware.",
        "kill_chain": ["phish_invoice", "exploit_public", "malware_exec", "lateral_smb",
                       "exfil_dns", "ransomware_deploy"],
        "objectives": _objs(
            ("Correlate the vectors", "Phishing and web-exploit paths linked as one intrusion."),
            ("Triage across fronts", "Compromised hosts across vectors scoped."),
            ("Contain the convergence", "Lateral movement and exfiltration stopped."),
            ("Recover and communicate", "Recovery and comms executed under pressure."),
        ),
    },
    "appsec_ai": {
        "name": "Application & AI attacker", "label": "Application and AI security test",
        "description": "Web-app injection, API abuse, and LLM prompt-injection/data leakage.",
        "kill_chain": ["app_injection", "api_abuse", "prompt_injection", "model_exfil"],
        "objectives": _objs(
            ("Detect the app attack", "Injection/API abuse caught in logs."),
            ("Triage the AI abuse", "Prompt-injection reproduced and scoped."),
            ("Contain data exposure", "Leak path cut and exposure quantified."),
        ),
    },
    "assumed_breach": {
        "name": "Assumed-breach attacker", "label": "Internal attacker modeling (assume breach)",
        "description": "Start compromised: model discovery, privilege escalation, and reach.",
        "kill_chain": ["assume_breach", "ad_enum", "priv_esc_dc", "lateral_smb", "exfil_dns"],
        "objectives": _objs(
            ("Hunt the foothold", "Assumed-breach access located."),
            ("Detect escalation", "Enumeration and privilege escalation recognised."),
            ("Contain the reach", "Path to crown jewels blocked; gaps documented."),
        ),
    },
})


SCENARIO_TEMPLATES.update({
    "phishing_sim": {
        "name": "Phishing simulation", "actor": "phishing_campaign",
        "narrative": "A phishing campaign tests user reporting and SOC detection.",
        "scope": "Awareness + detection exercise. No real mail is sent to staff.",
        "roe": "Facilitated exercise only. All lures are simulated.",
    },
    "network_pentest": {
        "name": "Network penetration test", "actor": "pentester",
        "narrative": "An authorized pen test walks recon → exploit → post-exploitation.",
        "scope": "Tabletop walk-through of a network pen test's stages and detections.",
        "roe": "Discussion-based. Any live testing runs only under a separate signed authorization.",
    },
    "social_engineering": {
        "name": "Social-engineering attack", "actor": "social_engineer",
        "narrative": "Vishing and help-desk pretexting probe the human perimeter.",
        "scope": "Tabletop focused on verification policy and reporting culture.",
        "roe": "Facilitated exercise only. No real staff are deceived.",
    },
    "malware_deployment": {
        "name": "Malware deployment", "actor": "malware_operator",
        "narrative": "Commodity malware is delivered, executed, and calls home.",
        "scope": "Tabletop across email security, EDR, and network detection.",
        "roe": "Facilitated exercise only. All actions are simulated.",
    },
    "physical_intrusion": {
        "name": "Physical-security intrusion test", "actor": "physical_intruder",
        "narrative": "An on-site tester tailgates, clones a badge, and plants a device.",
        "scope": "Tabletop covering physical access, reception, and network monitoring.",
        "roe": "Discussion-based. Any on-site testing requires separate written authorization.",
    },
    "insider_threat": {
        "name": "Insider threat", "actor": "insider_threat",
        "narrative": "A privileged insider exfiltrates data and sabotages systems.",
        "scope": "Tabletop with HR, legal, and IT touchpoints.",
        "roe": "Facilitated exercise only. Handle personnel details with care.",
    },
    "multi_vector": {
        "name": "Multi-stage, multi-vector attack", "actor": "multi_vector",
        "narrative": "Phishing and web exploitation converge into a ransomware endgame.",
        "scope": "Tabletop stress-testing correlation across simultaneous vectors.",
        "roe": "Facilitated exercise only. All actions are simulated.",
    },
    "appsec_ai": {
        "name": "AI & application security test", "actor": "appsec_ai",
        "narrative": "App injection, API abuse, and LLM prompt-injection with data leakage.",
        "scope": "Tabletop across AppSec, API security, and AI/LLM guardrails.",
        "roe": "Discussion-based. Any live testing runs only against non-production systems.",
    },
    "attacker_modeling": {
        "name": "Internal attacker modeling (assume breach)", "actor": "assumed_breach",
        "narrative": "Assume the attacker is already inside — model how far they reach.",
        "scope": "Tabletop assuming compromise, focused on discovery, escalation, and reach.",
        "roe": "Facilitated exercise only. All actions are simulated.",
    },
})
