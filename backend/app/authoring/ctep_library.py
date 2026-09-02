"""CTEP content library (M2): sector packs in the CTEP structure.

Each pack is original wording in the public CTEP shape — objectives, a
scenario in modules, discussion questions — plus what makes it runnable
here: ATT&CK techniques per module and the library environment it is
written against, so a facilitator with an empty organisation can import a
pack and be running in one click.
"""
from __future__ import annotations

# key -> pack. ``environment_key`` names a template in authoring.environments.
LIBRARY: dict[str, dict] = {
    "hospital_ransomware": {
        "title": "Hospital ransomware & clinical continuity",
        "sector": "Healthcare",
        "environment_key": "hospital",
        "threat_actor": "Ransomware affiliate targeting healthcare",
        "description": "Encryption reaches the EHR and clinical devices; the exercise is about "
                       "keeping patients safe while the network is untrusted.",
        "scope": "Discussion-based tabletop for clinical, IT and executive staff on a ransomware "
                 "event that degrades the electronic health record.",
        "roe": "Facilitated discussion. No clinical or IT systems are touched; 'pause' halts play.",
        "objectives": [
            {"title": "Early recognition", "success_criteria": "Clinical and IT reports of odd behaviour are joined into one incident within the first module."},
            {"title": "Clinical safety decisions", "success_criteria": "Downtime procedures are invoked deliberately, with named owners, before systems are forced off."},
            {"title": "Containment without harm", "success_criteria": "Isolation choices weigh the patient-safety impact of every segment taken offline."},
            {"title": "Recovery & disclosure", "success_criteria": "Restoration order follows clinical priority; regulator and patient notifications are planned."},
        ],
        "modules": [
            {"title": "Module 1 — Slow charts", "techniques": ["T1566.001", "T1078"],
             "narrative": "Nurses on two wards report the EHR timing out. The service desk has logged it as a performance ticket. A phishing report from a clinic administrator sits unread.",
             "discussion_questions": [
                 "Who connects a clinical complaint to a security event, and how?",
                 "What is the threshold to declare an incident rather than an outage?",
                 "Which downtime procedures exist, and who can invoke them?"]},
            {"title": "Module 2 — Encryption on the flat network", "techniques": ["T1021.002", "T1486"],
             "narrative": "File shares are encrypting and an imaging workstation shows a ransom note. Infusion pumps and the EHR share the network the workstation is on.",
             "discussion_questions": [
                 "What can be isolated without endangering a patient?",
                 "Who decides to take the EHR offline, and how is that communicated to wards?",
                 "How do you preserve evidence while containing spread?"]},
            {"title": "Module 3 — Divert and downtime", "techniques": ["T1490"],
             "narrative": "The EHR is down. The emergency department is on paper. Backups are being checked; one repository has been touched by the attacker.",
             "discussion_questions": [
                 "What is the ambulance-diversion decision, and who makes it?",
                 "How long can each department run on paper before care is affected?",
                 "What do you tell patients and staff, and when?"]},
            {"title": "Module 4 — Restore and report", "techniques": [],
             "narrative": "Clean backups are confirmed. Restoration begins in clinical-priority order. Regulators are asking about protected health information.",
             "discussion_questions": [
                 "In what order do systems come back, and who signed off on that order?",
                 "What notification obligations apply, and what is the clock?",
                 "Which single control would have stopped this at module one?"]},
        ],
    },
    "water_remote_access": {
        "title": "Water treatment remote-access intrusion",
        "sector": "Utilities (water)",
        "environment_key": "water_utility",
        "threat_actor": "Opportunistic intruder via exposed remote access",
        "description": "An exposed remote-desktop path into the treatment SCADA network lets an "
                       "intruder change chemical dosing set-points.",
        "scope": "Tabletop for plant operators, IT and leadership on an intrusion that reaches "
                 "process control at a municipal water plant.",
        "roe": "Facilitated discussion. Safety of supply takes precedence; 'pause' halts play.",
        "objectives": [
            {"title": "Spot the remote session", "success_criteria": "The unexpected remote session is noticed and questioned before set-points change."},
            {"title": "Safe manual control", "success_criteria": "Operators move to manual control without creating an unsafe dosing state."},
            {"title": "IT/OT coordination", "success_criteria": "IT and operations share one picture of the intrusion and one set of decisions."},
            {"title": "Public and regulator communication", "success_criteria": "State regulator and the public are informed accurately and on time."},
        ],
        "modules": [
            {"title": "Module 1 — Someone else's cursor", "techniques": ["T1133", "T1078"],
             "narrative": "An operator on the night shift sees the mouse move on the HMI. The remote-access tool shows a session from a vendor account nobody remembers creating.",
             "discussion_questions": [
                 "What does the operator do in the first sixty seconds?",
                 "Who can disconnect the session, and is that safe to do?",
                 "How are vendor remote accounts inventoried and reviewed?"]},
            {"title": "Module 2 — Set-point change", "techniques": ["T0836", "T0855"],
             "narrative": "Sodium hydroxide dosing is set far above the safe range. The change was made through the HMI with valid credentials.",
             "discussion_questions": [
                 "Which physical safeguards limit what a set-point change can do?",
                 "What is the decision path to go to manual, and how long does it take?",
                 "How do you confirm the water leaving the plant is safe?"]},
            {"title": "Module 3 — Scope and cooperation", "techniques": ["T1021.001"],
             "narrative": "The engineering workstation bridging IT and OT shows the same account logging in. Law enforcement and the state regulator are asking questions.",
             "discussion_questions": [
                 "What evidence do you preserve, and who owns it?",
                 "Who speaks to the regulator, and what do they say today?",
                 "What do the other plants in the district need to know?"]},
            {"title": "Module 4 — Return to automatic", "techniques": [],
             "narrative": "Remote access has been rebuilt behind multi-factor authentication. The plant is still on manual control.",
             "discussion_questions": [
                 "What must be validated before returning to automated control?",
                 "What is the public statement, and who approves it?",
                 "Which of today's decisions should become a written procedure?"]},
        ],
    },
    "manufacturing_disruption": {
        "title": "Production-line disruption through the ERP",
        "sector": "Manufacturing",
        "environment_key": "manufacturer",
        "threat_actor": "Financially motivated intruder",
        "description": "A compromise of the ERP that drives the shop floor stops both plants and "
                       "raises the question of whether the design vault was reached.",
        "scope": "Tabletop for plant management, IT/OT and finance on an intrusion that halts "
                 "production and threatens intellectual property.",
        "roe": "Facilitated discussion. No production systems are touched; 'pause' halts play.",
        "objectives": [
            {"title": "Detect at the boundary", "success_criteria": "The supplier-portal exploitation is detected before the ERP is reached."},
            {"title": "Plant safety and shutdown", "success_criteria": "A controlled stop is chosen over an uncontrolled one, with safety leads involved."},
            {"title": "Intellectual-property scope", "success_criteria": "Whether the design vault was accessed is established with evidence, not assumption."},
            {"title": "Restart and customer communication", "success_criteria": "Restart sequence is agreed and key customers are told the truth about delivery."},
        ],
        "modules": [
            {"title": "Module 1 — Supplier portal", "techniques": ["T1190", "T1505.003"],
             "narrative": "A web-shell is found on the supplier portal during routine patching. It has been there for weeks.",
             "discussion_questions": [
                 "What did the portal have access to, and how do you know?",
                 "Who is told, and does production continue while you look?",
                 "What logs exist for the past weeks, and who can read them?"]},
            {"title": "Module 2 — ERP and MES", "techniques": ["T1078", "T1021.002"],
             "narrative": "The ERP shows work orders created by a service account at 03:00. The MES has stopped receiving schedules and line two is idle.",
             "discussion_questions": [
                 "Is this a safety matter, a production matter or a security matter, and who leads?",
                 "Can you run the lines from paper schedules, and for how long?",
                 "What is the cost per hour, and who is tracking it?"]},
            {"title": "Module 3 — The vault question", "techniques": ["T1005", "T1041"],
             "narrative": "Outbound transfers from the file server that holds the design vault appear in proxy logs. The volume is large.",
             "discussion_questions": [
                 "How do you establish what was taken?",
                 "What contractual and legal obligations follow from design-file loss?",
                 "What do you tell the customers whose designs may be involved?"]},
            {"title": "Module 4 — Restart", "techniques": [],
             "narrative": "The ERP is rebuilt from a verified backup. Plant management wants lines running by the morning shift.",
             "discussion_questions": [
                 "What is the minimum validated state before a line restarts?",
                 "What monitoring is added before you trust the network again?",
                 "What changes for supplier access from now on?"]},
        ],
    },
    "saas_cicd_compromise": {
        "title": "CI/CD compromise & customer-data exposure",
        "sector": "Technology (SaaS)",
        "environment_key": "saas",
        "threat_actor": "Supply-chain intruder targeting build systems",
        "description": "A leaked CI token turns into a malicious build, a poisoned release and a "
                       "question of what customer data the attacker could read.",
        "scope": "Tabletop for engineering, security, legal and customer-facing leads on a "
                 "software-supply-chain incident at a multi-tenant SaaS.",
        "roe": "Facilitated discussion. No production or customer systems are touched; 'pause' halts play.",
        "objectives": [
            {"title": "Token hygiene and detection", "success_criteria": "The abused CI token is identified and revoked, and the blast radius of its permissions is understood."},
            {"title": "Release integrity", "success_criteria": "The tampered release is identified and pulled; customers are told which versions are affected."},
            {"title": "Data-access scoping", "success_criteria": "What tenant data was reachable is established from evidence, and notification decisions follow from it."},
            {"title": "Customer trust", "success_criteria": "Communications are timely, accurate and consistent across support, status page and legal."},
        ],
        "modules": [
            {"title": "Module 1 — Unusual pipeline run", "techniques": ["T1552.001", "T1078.004"],
             "narrative": "A pipeline ran at 02:14 from an unfamiliar IP using a long-lived CI token found in a public repository fork.",
             "discussion_questions": [
                 "What could that token do, and who can answer that in an hour?",
                 "Do you stop releases now, and who decides?",
                 "How do you find every other place that token was used?"]},
            {"title": "Module 2 — Poisoned release", "techniques": ["T1195.002", "T1554"],
             "narrative": "The last release contains a dependency nobody added. It calls home. Customers are already running it.",
             "discussion_questions": [
                 "How do you identify affected versions and customers?",
                 "What goes on the status page, and when?",
                 "What is your obligation to customers' own security teams?"]},
            {"title": "Module 3 — Tenant data", "techniques": ["T1530", "T1552.005"],
             "narrative": "Cloud audit logs show the attacker read the managed database's credentials from instance metadata. Whether they queried tenant data is unclear.",
             "discussion_questions": [
                 "What evidence would prove or disprove data access?",
                 "Who decides that this is a notifiable breach, and on what basis?",
                 "Which contracts have specific notification clocks?"]},
            {"title": "Module 4 — Rebuild trust", "techniques": [],
             "narrative": "Keys are rotated and the release is rebuilt from a clean pipeline. Customers want a written account.",
             "discussion_questions": [
                 "What does the post-incident report contain, and who signs it?",
                 "Which pipeline controls change permanently?",
                 "How do you verify the rebuilt release is clean?"]},
        ],
    },
    "county_services_outage": {
        "title": "County services outage — dispatch and elections",
        "sector": "Public sector (local government)",
        "environment_key": "county",
        "threat_actor": "Ransomware operator targeting local government",
        "description": "Ransomware across the county's shared Active Directory threatens 911 "
                       "dispatch and an elections office weeks from an election.",
        "scope": "Tabletop for county leadership, IT, emergency services and the elections office "
                 "on a ransomware event across shared infrastructure.",
        "roe": "Facilitated discussion. Public-safety systems are never touched; 'pause' halts play.",
        "objectives": [
            {"title": "Public-safety continuity", "success_criteria": "911 dispatch continues, on paper or on a separate network, with named decisions."},
            {"title": "Shared-identity containment", "success_criteria": "Containment across departments sharing one directory is coordinated, not improvised."},
            {"title": "Election integrity", "success_criteria": "The elections office demonstrates which systems are affected and which are not, with evidence."},
            {"title": "Public communication", "success_criteria": "Residents and the press receive accurate, consistent information from one voice."},
        ],
        "modules": [
            {"title": "Module 1 — Monday morning", "techniques": ["T1566.002", "T1078"],
             "narrative": "Property-tax staff cannot open files. The service desk sees encrypted shares in three departments. Dispatch reports its CAD system is slow.",
             "discussion_questions": [
                 "Who is the incident commander for a county-wide event?",
                 "What is the first decision for dispatch, and who makes it?",
                 "How do departments with their own IT staff coordinate?"]},
            {"title": "Module 2 — The shared directory", "techniques": ["T1003.001", "T1021.002", "T1486"],
             "narrative": "Domain admin credentials were dumped. The attacker can reach every department. Dispatch is isolated by cutting its link to the county network.",
             "discussion_questions": [
                 "What does isolating dispatch cost, and what does it protect?",
                 "Who authorises a county-wide password reset, and how is it executed?",
                 "What state and federal partners are engaged now?"]},
            {"title": "Module 3 — The election question", "techniques": ["T1565.001"],
             "narrative": "A reporter asks whether voter registration was altered. The elections office cannot immediately prove it was not.",
             "discussion_questions": [
                 "What evidence would show the registration database is intact?",
                 "Who speaks publicly, and what can they truthfully say today?",
                 "What is the contingency if the election systems must be rebuilt?"]},
            {"title": "Module 4 — Rebuild and reform", "techniques": [],
             "narrative": "The directory is rebuilt. Departments come back one at a time. The board wants to know why this happened and what changes.",
             "discussion_questions": [
                 "In what order do departments return, and who decided?",
                 "What does the public after-action report contain?",
                 "Which governance change prevents shared-directory blast radius next time?"]},
        ],
    },
    "university_research_theft": {
        "title": "Research data theft through federated identity",
        "sector": "Higher education",
        "environment_key": "university",
        "threat_actor": "State-sponsored espionage actor",
        "description": "A researcher's federated account is used from abroad to pull grant-funded "
                       "data from the research cluster and the health centre.",
        "scope": "Tabletop for research computing, the security office, the research office and "
                 "the health centre on quiet theft of export-controlled and health data.",
        "roe": "Facilitated discussion. No live systems are touched; 'pause' halts play.",
        "objectives": [
            {"title": "Anomalous access", "success_criteria": "The impossible-travel access is triaged as a security event rather than a user quirk."},
            {"title": "Data classification in practice", "success_criteria": "What was reachable is answered from data classification records, not guesses."},
            {"title": "Funder and regulator obligations", "success_criteria": "Grant, export-control and health-privacy notification duties are identified with owners."},
            {"title": "Research continuity", "success_criteria": "Researchers regain access safely without losing weeks of work."},
        ],
        "modules": [
            {"title": "Module 1 — Two continents", "techniques": ["T1078", "T1110.003"],
             "narrative": "The identity provider logs a principal investigator signing in from campus and from overseas within the same hour. The account has no multi-factor enrolment.",
             "discussion_questions": [
                 "Who reviews identity alerts, and what would they do with this one?",
                 "How is a researcher contacted safely to confirm activity?",
                 "What does this account reach: cluster, grant systems, health centre?"]},
            {"title": "Module 2 — The cluster", "techniques": ["T1021.004", "T1005", "T1048.003"],
             "narrative": "Large transfers from the research cluster to a foreign host ran for a week. The datasets include an export-controlled project.",
             "discussion_questions": [
                 "Who determines whether the data was export-controlled or human-subject data?",
                 "What is the reporting duty to the funder and to the government?",
                 "Do you cut the cluster off, and what does that cost the labs?"]},
            {"title": "Module 3 — The health centre", "techniques": ["T1213"],
             "narrative": "The same identity accessed the student health centre's records portal. The centre's own logs are thin.",
             "discussion_questions": [
                 "Who owns the health-privacy determination?",
                 "How do you scope access when logs are incomplete?",
                 "What do you tell affected students, and when?"]},
            {"title": "Module 4 — Reset and continuity", "techniques": [],
             "narrative": "Credentials are reset and multi-factor enforced for research accounts. Labs need their data back.",
             "discussion_questions": [
                 "How do researchers get working again without recreating the exposure?",
                 "Which policy gap (multi-factor, data classification, log retention) do you fix first?",
                 "What does the funder need in writing?"]},
        ],
    },
    "bec_wire_fraud": {
        "title": "Business email compromise & wire fraud",
        "sector": "Cross-sector",
        "environment_key": "saas",
        "threat_actor": "Business-email-compromise crew",
        "description": "A finance mailbox is taken over, a supplier's bank details are changed, "
                       "and money moves before anyone notices.",
        "scope": "Tabletop for finance, security and leadership on an email-compromise fraud "
                 "with a live payment in flight.",
        "roe": "Facilitated discussion. No banking or email systems are touched; 'pause' halts play.",
        "objectives": [
            {"title": "Recognise the fraud", "success_criteria": "The changed bank details are challenged through an out-of-band check before payment."},
            {"title": "Recall the money", "success_criteria": "Bank recall and law-enforcement steps start within the hour, with owners named."},
            {"title": "Scope the mailbox", "success_criteria": "Forwarding rules, other victims and other in-flight payments are found from evidence."},
            {"title": "Fix the process", "success_criteria": "Payment-change verification becomes a control, not a habit."},
        ],
        "modules": [
            {"title": "Module 1 — New bank details", "techniques": ["T1566.002", "T1078.004"],
             "narrative": "Accounts payable receives a polite email from a long-standing supplier: new bank details, invoice attached, same thread as last month.",
             "discussion_questions": [
                 "What is the procedure for a payment-detail change, and is it followed?",
                 "How would anyone know the supplier's mailbox is not the supplier?",
                 "What signals would your email security have shown?"]},
            {"title": "Module 2 — The money moved", "techniques": ["T1114.003", "T1564.008"],
             "narrative": "The payment cleared yesterday. The real supplier calls asking where their money is. A forwarding rule is found in the finance director's mailbox.",
             "discussion_questions": [
                 "What is the first call, and who makes it?",
                 "What is the bank's recall window, and what does it need from you?",
                 "Who else has forwarding rules you did not create?"]},
            {"title": "Module 3 — How far it goes", "techniques": ["T1087.003", "T1534"],
             "narrative": "The attacker used the finance director's mailbox to email other staff and two other suppliers. Two more payments are queued.",
             "discussion_questions": [
                 "Which payments stop, and who can stop them?",
                 "What do you tell the suppliers who were contacted from your domain?",
                 "Is this a data breach as well as a fraud?"]},
            {"title": "Module 4 — Controls", "techniques": [],
             "narrative": "Some money is recovered. Leadership wants assurance it will not happen again.",
             "discussion_questions": [
                 "What verification step is added to payment-detail changes?",
                 "Which mailbox controls (multi-factor, rule alerts, external tagging) change?",
                 "How is the loss reported to insurers and auditors?"]},
        ],
    },
    "insider_exfiltration": {
        "title": "Insider data exfiltration",
        "sector": "Cross-sector",
        "environment_key": "manufacturer",
        "threat_actor": "Departing employee with legitimate access",
        "description": "A senior engineer on notice copies the crown jewels to personal storage; "
                       "the response has to be lawful, humane and effective.",
        "scope": "Tabletop for security, HR, legal and line management on an insider event "
                 "involving a real person with real rights.",
        "roe": "Facilitated discussion. No monitoring is enabled or changed; 'pause' halts play.",
        "objectives": [
            {"title": "Detect the transfer", "success_criteria": "The unusual data movement is detected and correlated with the departure."},
            {"title": "Lawful response", "success_criteria": "HR, legal and security act together; evidence is preserved and rights are respected."},
            {"title": "Scope the loss", "success_criteria": "What left, where it went and what it means is established from evidence."},
            {"title": "Reduce the next one", "success_criteria": "Leaver process and access review are changed with owners and dates."},
        ],
        "modules": [
            {"title": "Module 1 — Notice given", "techniques": ["T1074.001", "T1567.002"],
             "narrative": "A design engineer resigns to join a competitor. Over the weekend, their account moved a large volume from the design vault to a personal cloud drive.",
             "discussion_questions": [
                 "Who is told first: HR, legal, security or the manager?",
                 "What monitoring of leavers exists, and is it lawful here?",
                 "What is the person's account allowed to do today?"]},
            {"title": "Module 2 — The conversation", "techniques": ["T1052.001"],
             "narrative": "Evidence also shows a USB device attached to their workstation. The engineer is in the building.",
             "discussion_questions": [
                 "Who speaks to the person, and what are they entitled to?",
                 "How do you preserve evidence without prejudicing a later claim?",
                 "Do you revoke access now, and what does that do to their team?"]},
            {"title": "Module 3 — What left", "techniques": ["T1005"],
             "narrative": "The files include a customer's design under a non-disclosure agreement. Legal is asking what obligations follow.",
             "discussion_questions": [
                 "What do you tell the customer, and when?",
                 "What legal remedies exist, and who decides to pursue them?",
                 "How confident are you in the inventory of what was taken?"]},
            {"title": "Module 4 — Leaver process", "techniques": [],
             "narrative": "The person has left. The board wants to know how a leaver kept vault access for a week after resigning.",
             "discussion_questions": [
                 "What changes in the leaver process, and who owns it?",
                 "What access review would have surfaced this earlier?",
                 "How do you keep trust with the people who did nothing wrong?"]},
        ],
    },
    "msp_compromise": {
        "title": "Managed service provider compromise",
        "sector": "Cross-sector",
        "environment_key": "county",
        "threat_actor": "Intruder pivoting through a managed service provider",
        "description": "Your outsourced IT provider is breached; their tooling has administrator "
                       "rights everywhere and the attacker is using it.",
        "scope": "Tabletop for leadership, IT and procurement on an incident that arrives through "
                 "a trusted third party's management tools.",
        "roe": "Facilitated discussion. No provider systems are touched; 'pause' halts play.",
        "objectives": [
            {"title": "Recognise third-party origin", "success_criteria": "Activity through the provider's tools is questioned rather than trusted."},
            {"title": "Cut the tie safely", "success_criteria": "Provider access is suspended in a way that keeps essential services running."},
            {"title": "Independent verification", "success_criteria": "The organisation establishes its own view of what happened, not only the provider's."},
            {"title": "Contract and continuity", "success_criteria": "Notification, liability and exit options are understood with owners."},
        ],
        "modules": [
            {"title": "Module 1 — Patch night", "techniques": ["T1199", "T1219"],
             "narrative": "The provider's remote-management agent pushed a script to every server overnight. The provider says it was routine. The script is not in their change log.",
             "discussion_questions": [
                 "Who can see what the provider's tools do on your systems?",
                 "What is your escalation path into the provider, at night?",
                 "Do you have the right to suspend their access, and the ability?"]},
            {"title": "Module 2 — Confirmed breach", "techniques": ["T1078", "T1021.006"],
             "narrative": "The provider confirms their management platform was breached. Every customer's admin credentials may be exposed. Your backups are managed by them too.",
             "discussion_questions": [
                 "What do you suspend first: their access, their tools or their backups?",
                 "Who can operate your systems without the provider?",
                 "What evidence do you collect yourself?"]},
            {"title": "Module 3 — Trust but verify", "techniques": ["T1136.002"],
             "narrative": "New admin accounts appear in your directory, created by the provider's service account. The provider's incident report is thin.",
             "discussion_questions": [
                 "How do you rebuild trust in your directory?",
                 "What do you demand from the provider, and what can you compel?",
                 "Which of your customers or regulators need to hear from you?"]},
            {"title": "Module 4 — Contract", "techniques": [],
             "narrative": "Services are stable on temporary arrangements. Procurement and legal are reviewing the contract.",
             "discussion_questions": [
                 "What contract terms would have helped today?",
                 "What is the exit plan if the provider cannot be trusted?",
                 "What visibility into third-party tools do you require from now on?"]},
        ],
    },
}
