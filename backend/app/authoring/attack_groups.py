"""Adversary-emulation catalog — real MITRE ATT&CK groups the proctor can pick.

A curated, **offline** set of well-known named adversaries. Each entry pairs a
real ATT&CK group (its G-ID, aliases, and signature techniques) with an ordered
kill chain built from Gauntlet's own inject-bank scenes, so choosing a group
grounds a scenario in the target environment deterministically — no live STIX
pull, no network dependency, consistent with the rest of the engine.

The data lives here as plain dicts; ``catalog`` merges it into ``THREAT_ACTORS``
(so the existing generator uses a chosen group unchanged) via :func:`as_threat_actors`.
Sector targeting powers "what hits an org like mine?" — :func:`recommend`.

Curation note: kill chains are a faithful *emulation* of each group's known
tradecraft mapped onto Gauntlet's abstract scenes, not a byte-for-byte replay of
any single intrusion. Technique IDs are illustrative signatures, not exhaustive.
To extend: add an entry below; the tests assert every kill-chain key exists in
the bank and every group generates a coherent scenario.
"""
from __future__ import annotations

import random as _random
from typing import Optional

# Normalised sector tags used for org-type matching. Environments store a free
# ``sector`` string; matching is case-insensitive substring against these + aliases.
SECTORS = (
    "financial", "healthcare", "government", "energy", "technology", "telecom",
    "retail", "manufacturing", "defense", "critical-infrastructure",
    "aviation", "education", "media", "hospitality",
)

# key -> curated adversary profile.
#   attack_id  : MITRE ATT&CK group G-ID
#   aliases    : common public names
#   sectors    : industries the group is publicly reported to target
#   techniques : signature ATT&CK technique IDs (illustrative, for display/tags)
#   kill_chain : ordered inject-bank scene keys emulating the group's tradecraft
#   objectives : (title, success-criteria) pairs, same shape as the base catalog
ATTACK_GROUPS: dict[str, dict] = {
    "apt29": {
        "attack_id": "G0016",
        "name": "APT29",
        "aliases": ["Cozy Bear", "Midnight Blizzard", "Nobelium", "The Dukes"],
        "label": "APT29 — stealthy state espionage (spearphish → cloud/AD credential theft)",
        "description": "Patient, well-resourced espionage actor. Low-and-slow credential "
                       "access, living-off-the-land, and quiet exfiltration.",
        "sectors": ["government", "technology", "healthcare", "defense", "education"],
        "techniques": ["T1566.002", "T1078", "T1071.001", "T1003.001", "T1567.002"],
        "kill_chain": ["recon_osint", "phish_credential", "c2_beacon", "lsass_dump",
                       "ad_enum", "exfil_dns"],
        "objectives": [
            ("Detect the targeted spearphish", "Credential-harvest lure spotted and reported before use."),
            ("Catch the quiet foothold", "Beaconing / anomalous auth recognised despite low volume."),
            ("Scope credential access", "Credential theft and directory recon identified and contained."),
            ("Stop the slow exfil", "Covert-channel data egress detected and blocked."),
        ],
    },
    "apt28": {
        "attack_id": "G0007",
        "name": "APT28",
        "aliases": ["Fancy Bear", "Sofacy", "Sednit", "STRONTIUM"],
        "label": "APT28 — military-intelligence intrusion (phish / edge-exploit → lateral)",
        "description": "GRU-linked espionage targeting government, military and defense; "
                       "phishing and internet-facing exploitation into lateral movement.",
        "sectors": ["government", "defense", "aviation", "energy", "media"],
        "techniques": ["T1566.001", "T1190", "T1071.001", "T1021.002", "T1114"],
        "kill_chain": ["recon_osint", "phish_credential", "exploit_public", "c2_beacon",
                       "lateral_smb", "exfil_dns"],
        "objectives": [
            ("Detect initial access", "Phish or edge exploitation identified and escalated."),
            ("Recognise the C2 channel", "Command-and-control beaconing detected."),
            ("Contain lateral movement", "SMB/remote pivoting halted before sensitive systems."),
            ("Prevent collection & exfil", "Targeted data access and egress stopped."),
        ],
    },
    "fin7": {
        "attack_id": "G0046",
        "name": "FIN7",
        "aliases": ["Carbanak (affiliated)", "Carbon Spider"],
        "label": "FIN7 — financially motivated intrusion (invoice phish → point-of-sale/data theft)",
        "description": "Prolific e-crime group. Weaponised documents and social lures into "
                       "credential theft, lateral movement, and monetisable data collection.",
        "sectors": ["retail", "hospitality", "financial", "manufacturing"],
        "techniques": ["T1566.001", "T1204.002", "T1055", "T1003.001", "T1074"],
        "kill_chain": ["phish_invoice", "malware_exec", "c2_beacon", "lsass_dump",
                       "lateral_smb", "data_staging"],
        "objectives": [
            ("Detect the weaponised lure", "Malicious invoice/document caught before execution."),
            ("Spot execution & C2", "Payload execution and beaconing identified."),
            ("Contain the spread", "Credential theft and lateral movement contained."),
            ("Protect the crown-jewel data", "Staging of target data detected and stopped."),
        ],
    },
    "lazarus": {
        "attack_id": "G0032",
        "name": "Lazarus Group",
        "aliases": ["Hidden Cobra", "APT38 (financial arm)", "ZINC"],
        "label": "Lazarus — state e-crime (targeted lure → implant → financial/crypto theft)",
        "description": "DPRK-linked actor blending espionage and revenue generation; "
                       "elaborate lures, custom implants, and theft from financial/crypto targets.",
        "sectors": ["financial", "energy", "defense", "technology"],
        "techniques": ["T1566", "T1204", "T1105", "T1071.001", "T1567"],
        "kill_chain": ["recon_osint", "phish_invoice", "malware_delivery", "c2_beacon",
                       "lsass_dump", "exfil_dns"],
        "objectives": [
            ("Detect the tailored lure", "Social-engineering approach recognised and reported."),
            ("Catch implant delivery", "Malware delivery and execution identified."),
            ("Recognise C2 & credential access", "Beaconing and credential theft detected."),
            ("Stop the theft", "Exfiltration / fraudulent movement blocked."),
        ],
    },
    "sandworm": {
        "attack_id": "G0034",
        "name": "Sandworm",
        "aliases": ["Voodoo Bear", "IRIDIUM", "ELECTRUM"],
        "label": "Sandworm — destructive ICS/enterprise attack (exploit → wiper/impact)",
        "description": "GRU-linked actor known for destructive operations against energy and "
                       "critical infrastructure; exploitation to disruptive impact.",
        "sectors": ["energy", "government", "critical-infrastructure", "manufacturing"],
        "techniques": ["T1190", "T1210", "T1021.002", "T1485", "T1486"],
        "kill_chain": ["exploit_public", "malware_exec", "c2_beacon", "lateral_smb",
                       "priv_esc_dc", "ransomware_deploy"],
        "objectives": [
            ("Detect the exploitation", "Internet-facing exploitation identified and escalated."),
            ("Recognise the foothold", "Execution and C2 detected."),
            ("Contain before escalation", "Lateral movement and privilege escalation halted."),
            ("Prevent destructive impact", "Wiper/ransomware detonation prevented or recovered."),
        ],
    },
    "apt41": {
        "attack_id": "G0096",
        "name": "APT41",
        "aliases": ["Double Dragon", "Winnti", "BARIUM"],
        "label": "APT41 — dual espionage + e-crime (edge-exploit → webshell → data theft)",
        "description": "China-linked actor mixing state espionage with financially motivated "
                       "intrusion; exploitation and webshells into broad data collection.",
        "sectors": ["healthcare", "telecom", "technology", "manufacturing"],
        "techniques": ["T1190", "T1505.003", "T1071.001", "T1003", "T1074"],
        "kill_chain": ["exploit_public", "c2_beacon", "lsass_dump", "lateral_smb",
                       "data_staging", "exfil_dns"],
        "objectives": [
            ("Detect the exploit/webshell", "Exploitation of a public app identified."),
            ("Recognise persistence & C2", "Beaconing and persistence detected."),
            ("Contain credential access", "Credential theft and lateral movement contained."),
            ("Stop broad collection", "Data staging and exfiltration blocked."),
        ],
    },
    "scattered_spider": {
        "attack_id": "G1015",
        "name": "Scattered Spider",
        "aliases": ["UNC3944", "Octo Tempest", "Muddled Libra"],
        "label": "Scattered Spider — social-engineering intrusion (help-desk/vishing → ransomware)",
        "description": "Aggressive social-engineering crew: help-desk pretexting, MFA fatigue "
                       "and SIM-swaps into rapid privilege abuse and extortion.",
        "sectors": ["telecom", "technology", "financial", "hospitality"],
        "techniques": ["T1598", "T1656", "T1621", "T1078", "T1486"],
        "kill_chain": ["recon_osint", "vishing", "pretext_helpdesk", "assume_breach",
                       "ad_enum", "ransomware_deploy"],
        "objectives": [
            ("Detect the social-engineering approach", "Vishing / help-desk pretext recognised and refused."),
            ("Enforce identity controls", "MFA-reset / account-takeover attempt blocked per policy."),
            ("Contain the foothold", "Abused access identified and directory recon contained."),
            ("Prevent extortion impact", "Ransomware/extortion staging detected and stopped."),
        ],
    },
    "lapsus": {
        "attack_id": "G1004",
        "name": "LAPSUS$",
        "aliases": ["DEV-0537", "Strawberry Tempest"],
        "label": "LAPSUS$ — extortion via insider access & social engineering (data theft → leak)",
        "description": "Extortion group leveraging bribed insiders and social engineering for "
                       "source-code and data theft, then public leak pressure.",
        "sectors": ["technology", "telecom", "media", "retail"],
        "techniques": ["T1585", "T1621", "T1078", "T1213", "T1567"],
        "kill_chain": ["recon_osint", "pretext_helpdesk", "insider_access", "data_staging",
                       "exfil_dns", "insider_sabotage"],
        "objectives": [
            ("Detect the pretext / insider approach", "Social-engineering or insider-recruitment attempt surfaced."),
            ("Recognise anomalous access", "Abused legitimate access identified and investigated."),
            ("Contain data collection", "Source/data staging detected and access revoked."),
            ("Prevent leak & sabotage", "Exfiltration and destructive action stopped."),
        ],
    },
    "wizard_spider": {
        "attack_id": "G0102",
        "name": "Wizard Spider",
        "aliases": ["TrickBot", "Ryuk / Conti operators", "Grim Spider"],
        "label": "Wizard Spider — big-game ransomware (loader phish → domain-wide encryption)",
        "description": "Ransomware-as-operation crew: commodity-loader phishing escalating to "
                       "domain compromise and enterprise-wide encryption.",
        "sectors": ["healthcare", "financial", "government", "manufacturing"],
        "techniques": ["T1566.001", "T1204", "T1071.001", "T1003.001", "T1486"],
        "kill_chain": ["phish_invoice", "malware_exec", "c2_beacon", "lsass_dump",
                       "lateral_smb", "ransomware_deploy"],
        "objectives": [
            ("Detect the loader phish", "Malicious attachment caught before execution."),
            ("Spot the C2 & credential theft", "Beaconing and credential dumping identified."),
            ("Contain lateral movement", "Domain-ward spread halted before the DC."),
            ("Prevent enterprise encryption", "Ransomware detonation prevented or recovered from backups."),
        ],
    },
    "ta505": {
        "attack_id": "G0092",
        "name": "TA505",
        "aliases": ["Hive0065", "Graceful Spider", "Clop operators"],
        "label": "TA505 — mass-phishing to extortion (malspam → data theft → leak/ransom)",
        "description": "High-volume malspam operator feeding downstream ransomware and "
                       "extortion; document lures into data theft and leak pressure.",
        "sectors": ["financial", "retail", "manufacturing", "healthcare"],
        "techniques": ["T1566.001", "T1105", "T1071.001", "T1074", "T1567"],
        "kill_chain": ["phish_invoice", "malware_delivery", "c2_beacon", "data_staging",
                       "exfil_dns", "ransomware_deploy"],
        "objectives": [
            ("Detect the malspam lure", "Document lure identified and quarantined."),
            ("Catch payload & C2", "Delivery and beaconing detected."),
            ("Contain data collection", "Staging of sensitive data detected and stopped."),
            ("Prevent extortion", "Exfiltration and ransomware impact blocked."),
        ],
    },
    "volt_typhoon": {
        "attack_id": "G1017",
        "name": "Volt Typhoon",
        "aliases": ["VANGUARD PANDA", "BRONZE SILHOUETTE"],
        "label": "Volt Typhoon — living-off-the-land pre-positioning in critical infrastructure",
        "description": "China-linked actor emphasising stealthy living-off-the-land tradecraft "
                       "to pre-position in critical-infrastructure networks.",
        "sectors": ["critical-infrastructure", "energy", "telecom", "government"],
        "techniques": ["T1190", "T1003", "T1021.002", "T1078", "T1567"],
        "kill_chain": ["exploit_public", "ad_enum", "lsass_dump", "lateral_smb",
                       "assume_breach", "exfil_dns"],
        "objectives": [
            ("Detect the edge compromise", "Exploitation of an internet-facing device identified."),
            ("Catch living-off-the-land recon", "Native-tool directory recon recognised despite low noise."),
            ("Contain credential access", "Credential theft and quiet lateral movement contained."),
            ("Expose the pre-position", "Dormant foothold and covert egress uncovered."),
        ],
    },
    "apt33": {
        "attack_id": "G0064",
        "name": "APT33",
        "aliases": ["Elfin", "HOLMIUM", "Peach Sandstorm"],
        "label": "APT33 — regional espionage (spearphish → implant → data theft)",
        "description": "Iran-linked espionage targeting energy and aviation supply chains; "
                       "spearphishing into implants and credential theft.",
        "sectors": ["energy", "aviation", "manufacturing", "government"],
        "techniques": ["T1566", "T1204", "T1071.001", "T1003.001", "T1567"],
        "kill_chain": ["recon_osint", "phish_credential", "malware_exec", "c2_beacon",
                       "lsass_dump", "exfil_dns"],
        "objectives": [
            ("Detect the spearphish", "Targeted lure identified and reported."),
            ("Catch the implant & C2", "Execution and beaconing detected."),
            ("Contain credential access", "Credential theft identified and contained."),
            ("Stop the exfil", "Data egress detected and blocked."),
        ],
    },
}


def _norm(s: str) -> str:
    return (s or "").strip().lower()


def as_threat_actors(objs_factory) -> dict[str, dict]:
    """Project the curated groups into the ``THREAT_ACTORS`` shape.

    ``objs_factory`` is the catalog's ``_objs`` builder (kept out of this module
    to avoid an import cycle). Extra keys (attack_id, aliases, sectors,
    techniques) ride along; the generator ignores them and the API surfaces them.
    """
    out: dict[str, dict] = {}
    for key, g in ATTACK_GROUPS.items():
        out[key] = {
            "name": g["name"],
            "label": g["label"],
            "description": g["description"],
            "kill_chain": list(g["kill_chain"]),
            "objectives": objs_factory(*g["objectives"]),
            "attack_id": g["attack_id"],
            "aliases": list(g["aliases"]),
            "sectors": list(g["sectors"]),
            "techniques": list(g["techniques"]),
            "is_attack_group": True,
        }
    return out


def recommend(sector: Optional[str] = None) -> list[str]:
    """Group keys whose targeted sectors match ``sector`` (case-insensitive,
    substring either way). Empty/None returns every group. Order is by number of
    matching sector tags, then name — most sector-relevant first.
    """
    if not sector or not _norm(sector):
        return list(ATTACK_GROUPS)
    q = _norm(sector)

    def score(g: dict) -> int:
        return sum(1 for s in g["sectors"] if q in _norm(s) or _norm(s) in q)

    scored = [(score(g), g["name"], key) for key, g in ATTACK_GROUPS.items()]
    matched = [t for t in scored if t[0] > 0]
    matched.sort(key=lambda t: (-t[0], t[1]))
    return [key for _, _, key in matched]


def random_group(sector: Optional[str] = None, rng: Optional[_random.Random] = None) -> str:
    """A random group key, optionally biased to a sector. Falls back to the full
    set when a sector matches nothing.
    """
    pool = recommend(sector) or list(ATTACK_GROUPS)
    return (rng or _random).choice(pool)
