"""Environment library (E1): sector templates a proctor can stamp into an org.

An environment is the system under test — the assets, controls, detections and
deception every ruling is made against. Building one from nothing is the
single largest piece of authoring work in the product, so each template here
is a complete, internally consistent estate for a sector: asset codes are
referenced by the controls that cover them, every control carries an efficacy
and a latency so adjudication has something to compute, and the visibility map
implements the box type. Names and figures are original; nothing is copied
from a real organisation.
"""
from __future__ import annotations

from .. import models

_ALL = ["assets", "controls", "detections", "deception_assets", "playbooks", "policies",
        "personnel", "crown_jewels"]


def _visibility(box_type: str) -> dict:
    """White Cell sees everything. What the blue cell may read depends on the
    box: white = the full estate; grey = everything but where the deception is;
    black = only the people, playbooks and policies they would know anyway.
    The red cell attacks blind unless the box is white."""
    blue = {
        "white": list(_ALL),
        "grey": ["assets", "controls", "detections", "playbooks", "policies", "personnel", "crown_jewels"],
        "black": ["playbooks", "policies", "personnel"],
    }.get(box_type, _ALL)
    return {
        "white_cell": list(_ALL),
        "blue_cell": blue,
        "red_cell": ["assets"] if box_type == "white" else [],
        "observers": ["playbooks", "policies"],
    }


ENVIRONMENT_TEMPLATES: dict[str, dict] = {
    "hospital": {
        "name": "St. Aldric Regional — Hospital Network",
        "sector": "Healthcare",
        "box_type": "grey",
        "description": ("A 400-bed regional hospital: EHR, clinical devices on a flat network, a "
                        "hosted patient portal and an over-worked two-person security team. "
                        "Availability is the crown jewel — a ransomware event stops care."),
        "assets": [
            {"code": "EHR-APP-01", "name": "Electronic health record application", "zone": "clinical"},
            {"code": "EHR-DB-01", "name": "EHR database cluster", "zone": "core"},
            {"code": "PACS-01", "name": "Medical imaging archive (PACS)", "zone": "clinical"},
            {"code": "IV-PUMP-NET", "name": "Infusion-pump VLAN (legacy firmware)", "zone": "clinical"},
            {"code": "NURSE-WKS", "name": "Nursing-station workstations", "zone": "user"},
            {"code": "PORTAL-WEB", "name": "Patient portal (hosted)", "zone": "perimeter"},
            {"code": "AD-DC-01", "name": "Domain controller", "zone": "core"},
            {"code": "BACKUP-VAULT", "name": "Offline backup vault", "zone": "core"},
        ],
        "controls": [
            {"name": "EDR on Windows endpoints", "type": "edr",
             "covers": ["T1003", "T1055", "T1486", "T1059"], "assets": ["NURSE-WKS", "EHR-APP-01", "AD-DC-01"],
             "efficacy": 0.75, "latency_min": 10},
            {"name": "Email filtering with link rewriting", "type": "email",
             "covers": ["T1566"], "assets": ["*"], "efficacy": 0.55, "latency_min": 3},
            {"name": "Clinical VLAN segmentation", "type": "segmentation",
             "covers": ["T1021", "T1210"], "assets": ["IV-PUMP-NET", "PACS-01"], "efficacy": 0.5, "latency_min": 30},
            {"name": "MFA on remote and admin access", "type": "identity",
             "covers": ["T1078", "T1110"], "assets": ["*"], "efficacy": 0.7, "latency_min": 5},
            {"name": "Offline backup rotation", "type": "resilience",
             "covers": ["T1490", "T1486"], "assets": ["BACKUP-VAULT"], "efficacy": 0.85, "latency_min": 5},
        ],
        "detections": [
            {"name": "Managed SIEM (MDR) correlation", "type": "siem",
             "covers": ["*"], "assets": ["*"], "efficacy": 0.45, "latency_min": 25},
            {"name": "Medical-device network monitoring", "type": "ot-monitoring",
             "covers": ["T0886", "T1046", "T1021"], "assets": ["IV-PUMP-NET", "PACS-01"], "efficacy": 0.6, "latency_min": 12},
        ],
        "deception_assets": [
            {"name": "Decoy 'patient-export' share", "type": "canary",
             "covers": ["T1083", "T1005", "T1021"], "assets": ["EHR-APP-01"], "efficacy": 1.0, "latency_min": 1},
        ],
        "playbooks": [
            {"name": "Clinical downtime procedure (paper charting)", "owner": "Nursing informatics"},
            {"name": "Ransomware IR playbook", "owner": "IT security"},
            {"name": "HIPAA breach notification", "owner": "Privacy officer"},
        ],
        "policies": [{"name": "Medical device network policy"}, {"name": "Remote access standard"}],
        "personnel": [
            {"role": "Security analyst", "name": "on-shift (MDR partner after hours)"},
            {"role": "CIO", "name": "D. Ferreira"},
            {"role": "Chief nursing officer", "name": "A. Nwosu"},
            {"role": "Privacy officer", "name": "K. Lindqvist"},
        ],
        "crown_jewels": ["EHR-DB-01", "PACS-01", "IV-PUMP-NET"],
    },
    "water_utility": {
        "name": "Clearwater District — Water & Wastewater",
        "sector": "Utilities (water)",
        "box_type": "grey",
        "description": ("A municipal water district: SCADA over a plant network, remote pump "
                        "stations on cellular links, an engineering workstation that bridges IT "
                        "and OT, and a corporate network for billing. Safety of supply is the "
                        "crown jewel."),
        "assets": [
            {"code": "SCADA-HMI-01", "name": "Plant SCADA HMI", "zone": "ot"},
            {"code": "SCADA-HIST", "name": "Process historian", "zone": "ot"},
            {"code": "PLC-CHEM", "name": "Chemical dosing PLC", "zone": "ot"},
            {"code": "ENG-WKS-01", "name": "Engineering workstation (IT/OT bridge)", "zone": "user"},
            {"code": "RTU-PUMP-07", "name": "Remote pump station RTU (cellular)", "zone": "ot"},
            {"code": "BILLING-APP", "name": "Customer billing application", "zone": "app"},
            {"code": "CORP-DC", "name": "Corporate domain controller", "zone": "core"},
            {"code": "FW-ITOT", "name": "IT/OT boundary firewall", "zone": "perimeter"},
        ],
        "controls": [
            {"name": "IT/OT firewall with conduit rules", "type": "segmentation",
             "covers": ["T1021", "T0886", "T0812", "T1210"], "assets": ["FW-ITOT", "SCADA-HMI-01", "PLC-CHEM"],
             "efficacy": 0.65, "latency_min": 15},
            {"name": "EDR on corporate endpoints", "type": "edr",
             "covers": ["T1003", "T1059", "T1486"], "assets": ["ENG-WKS-01", "CORP-DC", "BILLING-APP"],
             "efficacy": 0.7, "latency_min": 10},
            {"name": "Application allow-listing on HMI", "type": "hardening",
             "covers": ["T1204", "T0853", "T1059"], "assets": ["SCADA-HMI-01"], "efficacy": 0.8, "latency_min": 2},
            {"name": "Dosing set-point interlocks", "type": "safety",
             "covers": ["T0836", "T0831"], "assets": ["PLC-CHEM"], "efficacy": 0.9, "latency_min": 1},
        ],
        "detections": [
            {"name": "OT network monitoring (passive)", "type": "ot-monitoring",
             "covers": ["T0846", "T0886", "T0855", "T1046"], "assets": ["SCADA-HMI-01", "PLC-CHEM", "SCADA-HIST"],
             "efficacy": 0.6, "latency_min": 8},
            {"name": "Corporate SIEM", "type": "siem",
             "covers": ["*"], "assets": ["ENG-WKS-01", "CORP-DC", "BILLING-APP"], "efficacy": 0.4, "latency_min": 30},
            {"name": "Cellular RTU heartbeat alarms", "type": "log",
             "covers": ["T0814", "T0816"], "assets": ["RTU-PUMP-07"], "efficacy": 0.5, "latency_min": 20},
        ],
        "deception_assets": [
            {"name": "Decoy PLC on the plant VLAN", "type": "canary",
             "covers": ["T0846", "T0886"], "assets": ["SCADA-HMI-01"], "efficacy": 1.0, "latency_min": 1},
        ],
        "playbooks": [
            {"name": "Manual plant operation procedure", "owner": "Plant superintendent"},
            {"name": "OT incident response (isolate and sustain)", "owner": "OT engineer"},
            {"name": "State regulator notification", "owner": "General manager"},
        ],
        "policies": [{"name": "Remote access to OT standard"}, {"name": "Removable media policy"}],
        "personnel": [
            {"role": "Plant superintendent", "name": "M. Haddad"},
            {"role": "OT/controls engineer", "name": "S. Brennan"},
            {"role": "IT manager", "name": "on-call"},
            {"role": "General manager", "name": "R. Castellanos"},
        ],
        "crown_jewels": ["PLC-CHEM", "SCADA-HMI-01", "RTU-PUMP-07"],
    },
    "manufacturer": {
        "name": "Halvorsen Precision — Discrete Manufacturing",
        "sector": "Manufacturing",
        "box_type": "grey",
        "description": ("A two-plant precision-parts manufacturer: an ERP that drives the shop "
                        "floor, MES and CNC cells on a plant network, a supplier portal and a "
                        "design-file vault. Downtime is measured in dollars per minute."),
        "assets": [
            {"code": "ERP-APP", "name": "ERP application", "zone": "app"},
            {"code": "MES-01", "name": "Manufacturing execution system", "zone": "ot"},
            {"code": "CNC-CELL-A", "name": "CNC cell A controllers", "zone": "ot"},
            {"code": "CAD-VAULT", "name": "Design-file vault (IP)", "zone": "core"},
            {"code": "SUPPLIER-PORTAL", "name": "Supplier portal", "zone": "perimeter"},
            {"code": "OFFICE-WKS", "name": "Office workstations", "zone": "user"},
            {"code": "PLANT-FW", "name": "Plant boundary firewall", "zone": "perimeter"},
            {"code": "AD-DC-01", "name": "Domain controller", "zone": "core"},
        ],
        "controls": [
            {"name": "EDR on office and server estate", "type": "edr",
             "covers": ["T1003", "T1055", "T1486", "T1059"], "assets": ["OFFICE-WKS", "ERP-APP", "AD-DC-01", "CAD-VAULT"],
             "efficacy": 0.75, "latency_min": 8},
            {"name": "Plant network segmentation", "type": "segmentation",
             "covers": ["T1021", "T1210", "T0886"], "assets": ["PLANT-FW", "MES-01", "CNC-CELL-A"], "efficacy": 0.55, "latency_min": 20},
            {"name": "DLP on the design vault", "type": "dlp",
             "covers": ["T1567", "T1048", "T1005"], "assets": ["CAD-VAULT"], "efficacy": 0.6, "latency_min": 10},
            {"name": "Web application firewall on the supplier portal", "type": "waf",
             "covers": ["T1190", "T1505"], "assets": ["SUPPLIER-PORTAL"], "efficacy": 0.5, "latency_min": 5},
            {"name": "Immutable backups", "type": "resilience",
             "covers": ["T1490", "T1486"], "assets": ["ERP-APP", "CAD-VAULT"], "efficacy": 0.85, "latency_min": 5},
        ],
        "detections": [
            {"name": "SIEM with identity analytics", "type": "siem",
             "covers": ["*"], "assets": ["*"], "efficacy": 0.45, "latency_min": 20},
            {"name": "Plant network monitoring", "type": "ot-monitoring",
             "covers": ["T0846", "T0886", "T1046"], "assets": ["MES-01", "CNC-CELL-A"], "efficacy": 0.55, "latency_min": 15},
        ],
        "deception_assets": [
            {"name": "Decoy 'next-gen design' folder", "type": "canary",
             "covers": ["T1083", "T1005"], "assets": ["CAD-VAULT"], "efficacy": 1.0, "latency_min": 1},
        ],
        "playbooks": [
            {"name": "Ransomware IR playbook", "owner": "IT security"},
            {"name": "Plant isolation and manual run", "owner": "Plant manager"},
            {"name": "IP theft response", "owner": "General counsel"},
        ],
        "policies": [{"name": "Supplier access standard"}, {"name": "Design-data classification"}],
        "personnel": [
            {"role": "IT security lead", "name": "J. Okonkwo"},
            {"role": "Plant manager", "name": "E. Halvorsen"},
            {"role": "CFO", "name": "T. Mbeki"},
            {"role": "General counsel", "name": "V. Rossi"},
        ],
        "crown_jewels": ["CAD-VAULT", "MES-01", "ERP-APP"],
    },
    "saas": {
        "name": "Lumen Ledger — Cloud SaaS",
        "sector": "Technology (SaaS)",
        "box_type": "white",
        "description": ("A 120-person B2B SaaS running on a single cloud provider: Kubernetes "
                        "workloads, a managed database, CI/CD with broad tokens, SSO for staff "
                        "and a customer-facing API. Customer data and the signing keys are the "
                        "crown jewels."),
        "assets": [
            {"code": "API-GW", "name": "Public API gateway", "zone": "perimeter"},
            {"code": "K8S-PROD", "name": "Production Kubernetes cluster", "zone": "cloud"},
            {"code": "DB-CUST", "name": "Managed customer database", "zone": "core"},
            {"code": "CI-RUNNERS", "name": "CI/CD runners", "zone": "cloud"},
            {"code": "SECRETS-KMS", "name": "Key management / signing keys", "zone": "core"},
            {"code": "IDP-SSO", "name": "Staff identity provider (SSO)", "zone": "core"},
            {"code": "ENG-LAPTOPS", "name": "Engineering laptops", "zone": "user"},
        ],
        "controls": [
            {"name": "Cloud workload protection", "type": "cwpp",
             "covers": ["T1610", "T1611", "T1059", "T1525"], "assets": ["K8S-PROD", "CI-RUNNERS"], "efficacy": 0.7, "latency_min": 6},
            {"name": "Phishing-resistant MFA (FIDO2)", "type": "identity",
             "covers": ["T1078", "T1110", "T1566"], "assets": ["IDP-SSO", "*"], "efficacy": 0.85, "latency_min": 3},
            {"name": "EDR on laptops", "type": "edr",
             "covers": ["T1003", "T1059", "T1055"], "assets": ["ENG-LAPTOPS"], "efficacy": 0.75, "latency_min": 8},
            {"name": "KMS access policy with dual control", "type": "identity",
             "covers": ["T1552", "T1528"], "assets": ["SECRETS-KMS"], "efficacy": 0.8, "latency_min": 2},
            {"name": "API rate limiting and WAF", "type": "waf",
             "covers": ["T1190", "T1499"], "assets": ["API-GW"], "efficacy": 0.55, "latency_min": 4},
        ],
        "detections": [
            {"name": "Cloud audit-log analytics", "type": "cloudtrail",
             "covers": ["T1078.004", "T1098", "T1562", "T1530"], "assets": ["K8S-PROD", "DB-CUST", "SECRETS-KMS"],
             "efficacy": 0.6, "latency_min": 7},
            {"name": "SIEM correlation", "type": "siem",
             "covers": ["*"], "assets": ["*"], "efficacy": 0.4, "latency_min": 15},
            {"name": "Secret-scanning in CI", "type": "log",
             "covers": ["T1552"], "assets": ["CI-RUNNERS"], "efficacy": 0.65, "latency_min": 5},
        ],
        "deception_assets": [
            {"name": "Canary API token in a public repo", "type": "canary",
             "covers": ["T1552", "T1078.004"], "assets": ["CI-RUNNERS"], "efficacy": 1.0, "latency_min": 1},
        ],
        "playbooks": [
            {"name": "Compromised credential / token rotation", "owner": "Platform team"},
            {"name": "Customer data breach notification", "owner": "Legal"},
            {"name": "Status page and customer comms", "owner": "Support lead"},
        ],
        "policies": [{"name": "Secrets management standard"}, {"name": "Production access policy"}],
        "personnel": [
            {"role": "Head of platform", "name": "N. Sørensen"},
            {"role": "Security engineer", "name": "P. Iyer"},
            {"role": "CTO", "name": "L. Marchetti"},
            {"role": "Legal counsel", "name": "external firm"},
        ],
        "crown_jewels": ["DB-CUST", "SECRETS-KMS", "IDP-SSO"],
    },
    "county": {
        "name": "Marrow County — Local Government",
        "sector": "Public sector (local government)",
        "box_type": "black",
        "description": ("A county government: property and tax systems, a 911 dispatch "
                        "centre on a separate network, an elections office, dozens of small "
                        "departments on one Active Directory and a thin IT team. Continuity of "
                        "emergency services is the crown jewel."),
        "assets": [
            {"code": "TAX-APP", "name": "Property tax system", "zone": "app"},
            {"code": "CAD-911", "name": "911 computer-aided dispatch", "zone": "critical"},
            {"code": "ELECTIONS-WKS", "name": "Elections office workstations", "zone": "user"},
            {"code": "COUNTY-DC", "name": "County domain controller", "zone": "core"},
            {"code": "DEPT-FILE", "name": "Departmental file server", "zone": "app"},
            {"code": "PUBLIC-WEB", "name": "County website and payment portal", "zone": "perimeter"},
            {"code": "VPN-GW", "name": "Remote-access VPN", "zone": "perimeter"},
            {"code": "BACKUP-01", "name": "Backup server (online)", "zone": "core"},
        ],
        "controls": [
            {"name": "Antivirus with EDR add-on (partial rollout)", "type": "edr",
             "covers": ["T1486", "T1059"], "assets": ["COUNTY-DC", "DEPT-FILE"], "efficacy": 0.5, "latency_min": 15},
            {"name": "Dispatch network isolation", "type": "segmentation",
             "covers": ["T1021", "T1210"], "assets": ["CAD-911"], "efficacy": 0.8, "latency_min": 10},
            {"name": "MFA on VPN", "type": "identity",
             "covers": ["T1078", "T1133"], "assets": ["VPN-GW"], "efficacy": 0.6, "latency_min": 5},
            {"name": "Nightly backups (online, same domain)", "type": "resilience",
             "covers": ["T1490"], "assets": ["BACKUP-01"], "efficacy": 0.3, "latency_min": 60},
        ],
        "detections": [
            {"name": "State-provided SOC monitoring", "type": "siem",
             "covers": ["*"], "assets": ["*"], "efficacy": 0.35, "latency_min": 45},
            {"name": "Domain audit logging", "type": "log",
             "covers": ["T1078", "T1098", "T1484"], "assets": ["COUNTY-DC"], "efficacy": 0.45, "latency_min": 20},
        ],
        "deception_assets": [
            {"name": "Honey admin account", "type": "canary",
             "covers": ["T1078", "T1110"], "assets": ["COUNTY-DC"], "efficacy": 1.0, "latency_min": 2},
        ],
        "playbooks": [
            {"name": "Continuity of operations (COOP) plan", "owner": "Emergency management"},
            {"name": "Ransomware response with state assistance", "owner": "IT director"},
            {"name": "Public information procedure", "owner": "County administrator"},
        ],
        "policies": [{"name": "Acceptable use policy"}, {"name": "Records retention schedule"}],
        "personnel": [
            {"role": "IT director", "name": "G. Whitfield"},
            {"role": "911 communications manager", "name": "B. Tanaka"},
            {"role": "County administrator", "name": "H. Delacroix"},
            {"role": "Elections clerk", "name": "F. Abara"},
        ],
        "crown_jewels": ["CAD-911", "COUNTY-DC", "ELECTIONS-WKS"],
    },
    "university": {
        "name": "Northgate University — Campus & Research",
        "sector": "Higher education",
        "box_type": "grey",
        "description": ("A research university: a student information system, a research "
                        "computing cluster with grant-funded data, open campus wireless, "
                        "federated identity and a health centre. Research data and the "
                        "identity system are the crown jewels."),
        "assets": [
            {"code": "SIS-APP", "name": "Student information system", "zone": "app"},
            {"code": "HPC-CLUSTER", "name": "Research computing cluster", "zone": "research"},
            {"code": "RESEARCH-STORE", "name": "Research data store (grant-restricted)", "zone": "core"},
            {"code": "IDP-SHIB", "name": "Federated identity provider", "zone": "core"},
            {"code": "CAMPUS-WIFI", "name": "Open campus wireless", "zone": "perimeter"},
            {"code": "HEALTH-EHR", "name": "Student health centre records", "zone": "clinical"},
            {"code": "LAB-WKS", "name": "Departmental lab workstations (unmanaged)", "zone": "user"},
            {"code": "ADMIN-WKS", "name": "Administrative workstations (managed)", "zone": "user"},
        ],
        "controls": [
            {"name": "EDR on managed endpoints", "type": "edr",
             "covers": ["T1003", "T1059", "T1486"], "assets": ["ADMIN-WKS", "SIS-APP"], "efficacy": 0.7, "latency_min": 10},
            {"name": "MFA on identity provider", "type": "identity",
             "covers": ["T1078", "T1110", "T1566"], "assets": ["IDP-SHIB", "*"], "efficacy": 0.7, "latency_min": 5},
            {"name": "Research network access controls", "type": "segmentation",
             "covers": ["T1021", "T1210"], "assets": ["HPC-CLUSTER", "RESEARCH-STORE"], "efficacy": 0.5, "latency_min": 20},
            {"name": "Health-centre network isolation", "type": "segmentation",
             "covers": ["T1021"], "assets": ["HEALTH-EHR"], "efficacy": 0.75, "latency_min": 10},
        ],
        "detections": [
            {"name": "Campus SIEM", "type": "siem",
             "covers": ["*"], "assets": ["*"], "efficacy": 0.4, "latency_min": 25},
            {"name": "Identity anomaly detection", "type": "log",
             "covers": ["T1078", "T1110", "T1621"], "assets": ["IDP-SHIB"], "efficacy": 0.55, "latency_min": 10},
            {"name": "Research egress monitoring", "type": "network",
             "covers": ["T1048", "T1567", "T1041"], "assets": ["HPC-CLUSTER", "RESEARCH-STORE"], "efficacy": 0.5, "latency_min": 15},
        ],
        "deception_assets": [
            {"name": "Decoy grant dataset", "type": "canary",
             "covers": ["T1083", "T1005", "T1048"], "assets": ["RESEARCH-STORE"], "efficacy": 1.0, "latency_min": 1},
        ],
        "playbooks": [
            {"name": "Compromised account response", "owner": "Identity team"},
            {"name": "Research data incident (grant reporting)", "owner": "Research compliance"},
            {"name": "Campus communications", "owner": "University relations"},
        ],
        "policies": [{"name": "Research data handling standard"}, {"name": "Network acceptable use"}],
        "personnel": [
            {"role": "CISO", "name": "O. Bergström"},
            {"role": "Research computing director", "name": "W. Chen"},
            {"role": "Registrar", "name": "I. Mahmoud"},
            {"role": "Research compliance officer", "name": "C. Dubois"},
        ],
        "crown_jewels": ["RESEARCH-STORE", "IDP-SHIB", "SIS-APP"],
    },
}


def summaries() -> list[dict]:
    out = []
    for key, t in ENVIRONMENT_TEMPLATES.items():
        out.append({
            "key": key, "name": t["name"], "sector": t["sector"], "box_type": t["box_type"],
            "description": t["description"],
            "assets": len(t["assets"]), "controls": len(t["controls"]) + len(t["detections"]),
            "deception": len(t["deception_assets"]), "crown_jewels": list(t["crown_jewels"]),
        })
    return out


def build_from_template(key: str, name: str | None = None) -> models.Environment:
    t = ENVIRONMENT_TEMPLATES.get(key)
    if t is None:
        raise KeyError(key)
    return models.Environment(
        name=(name or "").strip() or t["name"],
        sector=t["sector"], box_type=t["box_type"], description=t["description"],
        assets=[dict(a) for a in t["assets"]],
        controls=[dict(c) for c in t["controls"]],
        detections=[dict(d) for d in t["detections"]],
        deception_assets=[dict(d) for d in t["deception_assets"]],
        playbooks=[dict(p) for p in t["playbooks"]],
        policies=[dict(p) for p in t["policies"]],
        personnel=[dict(p) for p in t["personnel"]],
        crown_jewels=list(t["crown_jewels"]),
        visibility=_visibility(t["box_type"]),
    )
