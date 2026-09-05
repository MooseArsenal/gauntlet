# Changelog

All notable changes to Gauntlet. The format follows Keep a Changelog; versions
follow SemVer. Container images are published as
`ghcr.io/moose11b/gauntlet:<version>` on each tag.

## [Unreleased]

### Added
- **Doors** — the console opens on a choice: run an exercise, join one, the
  classroom, or learn. Facilitators choose once and land on sign-in after.
- **Solo learning mode** (free) — blue, executive or red against the engine:
  an autopilot proctor, a scripted adversary, red moves with an alert meter and
  crown jewels, a scored debrief with coaching notes as a page and a PDF, run
  history, and a free workspace that comes with the bundled library. Solo runs
  are excluded from every readiness figure and the benchmark.
- **Company contact** — moosearsenal.com addresses and `security.txt`.

## [0.3.1] — 2026-09-02

The first build that carries the vendor signing key: production deployments
trust licences, revocation lists and packs signed by it, with no environment
configuration.

### Security
- **Signing keys** — vendor public keys are compiled into the release by key id
  and are the only trust anchor in production; environment keys are honoured
  outside production or with an explicit opt-in. Licences and packs carry the
  key id so keys rotate. Licences carry a serial; a signed revocation list
  degrades a revoked licence at once. The tools keep private keys in
  passphrase-encrypted files and never print them. `docs/KEY_MANAGEMENT.md`.

## [0.3.0] — 2026-09-02

The "paid surface" release: an offline licence with tiers, and the features a
programme, a classroom or an enterprise pays for around the same free engine.
Community keeps the full engine, the record and the game mode.

### Added
- **Licence and entitlements** — offline Ed25519 licences, tiers (Community,
  Team, Education, Enterprise), feature gates, facilitator seats, grace period.
- **White-label branding and partner mode** — your name, colour and logo on the
  console and every PDF; consultancies run client organisations from one login.
- **Game mode** — a free skin over the engine: cards, a d20 consistent with the
  ruling, XP, HP and quests.
- **Education edition** — cohorts, self-enrolment by code, one-click seating,
  anonymous grading, gradebook with CSV export.
- **Session replay** — the record as scenes with the roads not taken; rewind
  forks a new run from any scene without touching the original.
- **Content packs and intel feed** — signed scenario and adversary-intel packs,
  verified offline, installed from the Members page; a publisher tool.

## [0.2.0] — 2026-09-02

The "sell the number" release: the exercise produces a signed, verifiable
record, the library makes the first hour easy, and the run-day and enterprise
gaps a buyer would hit are closed.

### Added
- **Exercise certificate** — a signed one-page record per completed exercise
  (detection rate, mean time-to-detect, objectives met, techniques exercised,
  signed timeline head), publicly verifiable at `/verify.html` by serial.
- **Environment library** — six sector environments (hospital, water utility,
  discrete manufacturer, cloud SaaS, county government, research university)
  stamped in one click; a New-environment flow in the console and guided build.
- **CTEP content library** — eleven packs across eight sector groups, each
  importable into its own library environment in one call.
- **Run-day mode** — pre-brief and projector views for the room, a hotwash
  that rates objectives and logs improvement items, keyboard facilitation.
- **Telemetry loop** — record the alerts the SOC's tools raised and compare
  them with the ruling: confirmed, silent gap, surprise, missed; in reports
  and on the certificate.
- **Enterprise** — SCIM 2.0 provisioning with a per-organisation token,
  Redis-shared throttles, row-level security on by default in production,
  CycloneDX SBOM in CI, `SECURITY.md`, `docs/ENTERPRISE.md`.
- **Sector benchmark** — the organisation's figures against the library's
  modelled expectation and an opt-in, k-anonymous instance cohort.
- **Product page and tour** — `/product.html` with positioning and indicative
  pricing; a guided tour of the console for first-time facilitators.
- **Release pipeline** — tagged versions build and publish the image to GHCR
  with the SBOM attached and notes taken from this file.

### Changed
- Console files always revalidate (`Cache-Control: no-cache`), so a deploy is
  visible on the next load.
- The demo seeds three scenarios across three environments instead of one.

### Fixed
- Stale console after a deploy; single-choice environment and scenario pickers.

## [0.1.0] — 2026-08

Initial release: environment-grounded adjudication, branching MSEL engine,
tamper-evident timeline, ATT&CK-tagged inject bank, adversary catalog and
designer, purple-team scoreboard, reports for four audiences with PDF/DOCX
export, compliance crosswalks, improvement tracker adapters, intake mappers,
join-code lobby, maturity analytics, OIDC, MFA, encryption at rest, retention
and erasure, air-gapped mode, and the Exercise Control design system.
