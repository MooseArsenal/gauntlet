# Gauntlet — competitive positioning

A grounded read of where Gauntlet sits in the cyber tabletop / exercise market,
what distinguishes it, and where to push next. Based on public product material
(Sept 2026) plus Gauntlet's actual shipped capabilities.

## The landscape

| Product | What it actually is | Overlap with Gauntlet | Their moat |
|---|---|---|---|
| **DrDeathLabs / cybertabletop** | Self-hosted, AI-driven **scored** TTX (Node/React/Tailwind, Postgres, Docker Compose; BSL-1.1) | **Very high** — RBAC, TOTP MFA, OIDC, AI+scripted scenario generation, live facilitation, scoring, structured debrief, audit logging, AES-GCM secrets | First-mover in the self-hosted niche; join-code lobby for large groups; NIST-CSF debrief |
| **ORNA** | Managed **SaaS**: IR automation + tabletop, "war room," MDR integrations, board-ready reports; 475+ customers | Medium — AI scenario generation, environment/document upload, audit-grade reports | Turnkey SaaS, services, install base, financial-impact framing |
| **CrowdStrike** | A **human consulting service** — on-site, ≤25 people, intel-driven, proctored, report | Low — it's people, not software | Elite facilitators + first-party threat intel; brand |
| **CISA CTEPs** | **Free static document packages** (objectives, scenarios, discussion questions) | Low — content, not a platform | Free, authoritative, ubiquitous starting point |
| **Immersive Labs** | Cyber **skills-training** platform + Crisis Sim | Low — different lane (training) | Huge content library, enterprise brand |

## What genuinely distinguishes Gauntlet

Verified against the competitors' own docs:

1. **MITRE ATT&CK is first-class.** cybertabletop does not mention ATT&CK at all.
   Gauntlet has a technique-tagged inject bank, kill-chain phases, ATT&CK-grounded
   *adjudication*, a per-technique coverage heatmap, and ATLAS (AI/LLM) techniques.
2. **Adversary-emulation depth.** 12 curated *real* ATT&CK groups (APT29, FIN7,
   Lazarus, Sandworm, Scattered Spider…), sector→actor recommendation,
   mix-and-match (a group *through* an attack-type template), **and** a custom /
   random adversary designer. Competitors ship generic "ransomware / BEC / DDoS"
   buckets.
3. **Environment-grounded, deterministic adjudication.** Gauntlet models the
   defender's assets / controls / detections / deception and rules each move
   against them with a hash-chained, verifiable, **fully offline** engine — no
   mandatory LLM. cybertabletop and ORNA lean on AI; that structurally locks out
   air-gapped government / defense / OT / ICS buyers. **This is the strongest
   ownable position.**
4. **Live purple-team loop.** Role-aware proctor / blue / red / observer views
   with real detection-rate / MTTD / deception scoring — a detection-modeling
   engine, not just "role-based decisions."
5. **Compliance + integration breadth.** Multi-framework crosswalks and evidence
   export (PDF / DOCX / CSV / JSON); improvement-tracker adapters (Jira /
   ServiceNow); CMDB / EDR / SIEM / ASM intake mappers. cybertabletop documents
   none of these.

## Review gripes → features we win on

The recurring complaint across the category is that tabletops are *"theater —
pre-printed flashcards, six-slide decks, facilitators transcribing responses into
pre-written reports,"* and *"scripts kill realism."* The industry's own stated
ideal is that **"a good tabletop runs like a skilled Dungeon Master reacting to
real decisions"** — which is Gauntlet's literal design language ("you are the
dungeon master" is in the console). We already answer this with a branching
adjudication engine and reports generated from the real timeline. Turn the
remaining gripes into moat:

- **Longitudinal maturity dashboard** — trend MTTD / detection-rate / coverage
  across exercises over time ("MTTD down 30% since Q1"). Directly answers the
  "no institutional memory" gripe.
- **ATT&CK Navigator layer export** — emit coverage as a Navigator JSON layer.
  No competitor does this; compounds the ATT&CK lead.
- **CISA CTEP importer** — ingest the free authoritative CTEP packs as *runnable,
  adjudicated* scenarios; co-opts the biggest free competitor.
- **Join-code lobby** for large groups — parity with cybertabletop's onboarding.
- **Air-gapped / no-AI-required** as explicit positioning — the one thing SaaS
  and AI-first tools structurally cannot match.
- **Financial / blast-radius impact modeling** per branch outcome — meets ORNA's
  "minimize financial damage" framing on our own terms.

## One-line positioning

> Gauntlet is the **ATT&CK-grounded, environment-driven, offline-capable** tabletop
> **and** purple-team engine: where cybertabletop is an AI-first scored TTX, ORNA a
> managed IR+TTX SaaS, CrowdStrike a human service, and CISA CTEPs free static docs,
> Gauntlet models *your* environment, adjudicates against *your* controls, emulates
> *real or custom* adversaries, runs fully self-hosted and air-gapped, and produces
> compliance evidence.

## Sources

- [DrDeathLabs/cybertabletop (GitHub)](https://github.com/DrDeathLabs/cybertabletop)
- [ORNA — Cyber Tabletop Exercise Platform](https://www.orna.app/tabletop-exercise)
- [CrowdStrike — Tabletop Exercise Services](https://www.crowdstrike.com/en-us/services/prepare/tabletop-exercise/)
- [CISA — Tabletop Exercise Packages (CTEPs)](https://www.cisa.gov/resources-tools/services/cisa-tabletop-exercise-packages)
- [Compass IT — Why Most Cybersecurity Tabletop Exercises Fail](https://www.compassitc.com/blog/why-most-cybersecurity-tabletop-exercises-fail-and-how-to-fix-it)
- [Immersive Labs reviews (G2)](https://www.g2.com/products/immersive/reviews)
