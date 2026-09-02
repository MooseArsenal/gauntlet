# Changelog

All notable changes to Gauntlet. The format follows Keep a Changelog; versions
follow SemVer. Container images are published as
`ghcr.io/moose11b/gauntlet:<version>` on each tag.

## [Unreleased]

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
