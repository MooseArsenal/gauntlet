# Gauntlet

**A dungeon master for security exercises.** Gauntlet turns what a security team
already knows about its own environment — defenses, detections, policies, traps,
and training — into a living tabletop exercise that a proctor steers as it
unfolds, then reports on for every audience that needs to learn from it.

> **Working title.** "Gauntlet" is a placeholder — a trial of readiness, and a
> piece of armor. Rename with a single find-and-replace.

This is the **tabletop-first** reference implementation. It is a standalone
product with no dependency on any other system. See
[`docs/design.html`](docs/design.html) (open in a browser) or
[`docs/DESIGN.md`](docs/DESIGN.md) for the full design brief.

---

## What it does

- **Intake** — model the environment under test: assets, controls, detections,
  playbooks, policies, personnel, deception assets, and crown jewels, with
  per-audience visibility (white / grey / black box).
- **Scenario + MSEL** — a scenario carries objectives and a Master Scenario
  Events List: an ordered, **branching** set of injects. Branches fire on a
  player action, a game-clock timeout, or the proctor's choice.
- **Conduct** — the facilitator console presents the current inject, offers the
  branches, and drives the exercise forward.
- **Adjudication** — rule a player action against the environment's control
  coverage. Transparent, deterministic, explainable, and always overridable by
  the proctor.
- **Tamper-evident timeline** — every step is written to an append-only,
  hash-chained log that can be verified.
- **Reports** — one timeline, four audience lenses: executive, technical (SOC/IR),
  GRC/audit evidence, and training gaps.

A worked example — a finance-sector ransomware tabletop (*Operation Frostbite*)
— is seeded on first run so the whole loop works immediately.

---

## Run it

```bash
cd backend
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python -m uvicorn app.main:app --reload --port 8000
```

Then open:

- **Facilitator console** — <http://localhost:8000/>
- **API docs (OpenAPI)** — <http://localhost:8000/docs>

Sign in with the seeded demo account **`admin@demo.gauntlet` / `gauntlet-admin`**
(override the password with `GAUNTLET_DEMO_PASSWORD`). The console also links the
**evaluator**, **participant**, **parallel roll-up**, and **program coverage**
surfaces.

Zero infrastructure: it uses a local SQLite file by default and runs Alembic
migrations on startup. Point `GAUNTLET_DB_URL` at Postgres to scale out. **Set
`GAUNTLET_SECRET_KEY` to a strong value in any real deployment** — it signs both
auth tokens and the tamper-evident timeline.

## Deep scenarios & compliance (M7)

Scenarios are a **branching graph**, authored in YAML. Injects carry `condition`
guards and `set` state mutations, so paths diverge on *accumulated* decisions
(see `scenarios/ransomware-deep.yaml` — 11 injects, three divergent endings). A
safe evaluator (no `eval`) gates branches; validation proves every `goto`
resolves and an ending is reachable before a scenario runs.

```bash
curl -X POST localhost:8000/api/scenarios/validate -H 'content-type: application/json' \
  -d "{\"yaml\": \"$(sed 's/"/\\"/g' scenarios/ransomware-deep.yaml | tr '\n' '~' )\"}"   # or just POST the raw YAML
curl -X POST localhost:8000/api/scenarios/import   -d '{"environment_id":1,"yaml":"..."}'
curl        localhost:8000/api/scenarios/1/export                                          # round-trips to YAML
```

**Compliance evidence**: every exercise objective maps to a canonical capability
(detect/triage/contain/recover/communicate/govern) that cross-walks to the
relevant controls across **eleven frameworks** — so one exercise emits evidence
for all of them at once. Tier 1 (core): **PCI-DSS v4.0, DORA, NIST CSF 2.0, CIS
Controls v8, ISO/IEC 27001:2022, SOC 2**. Tier 2 (sector & regional, F2):
**HIPAA Security Rule, NERC CIP, FFIEC, NIS2 Directive, NIST SP 800-53 Rev. 5**.
Adding a framework is a crosswalk table, not new exercise logic.

```bash
curl localhost:8000/api/sessions/1/evidence                 # JSON, all frameworks
curl localhost:8000/api/sessions/1/evidence?framework=nist_csf
curl -OJ localhost:8000/api/sessions/1/evidence.pdf         # auditor-ready PDF
```

Mappings indicate control *relevance* for remediation and evidence — they are
not a compliance assessment or attestation. The console exposes YAML import and
a "Compliance evidence & PDF" action; reports also export to PDF.

## Platform security (M8)

- **Fail-fast config**: set `GAUNTLET_ENV=prod` and the app refuses to start if
  `GAUNTLET_SECRET_KEY` is the default or too short, `GAUNTLET_CORS_ORIGINS` is
  `*`, or the `AUTH_OPTIONAL` dev bypass is on.
- **Security headers** on every response (strict CSP, `X-Frame-Options: DENY`,
  `nosniff`, `Referrer-Policy`, `Permissions-Policy`; HSTS in prod) — with a
  relaxed CSP only for the Swagger/ReDoc docs.
- **Login throttling & lockout**: per-IP+email attempts are capped
  (`GAUNTLET_LOGIN_MAX_ATTEMPTS`/`_WINDOW_SEC`/`_LOCKOUT_SEC`); excess returns 429.
- **Input caps**: scenario YAML size (`GAUNTLET_MAX_YAML_BYTES`) and inject count
  (`GAUNTLET_MAX_INJECTS`) are bounded so a huge import can't DoS validation.
- **Security audit log**: logins (success/failure/lockout), registrations, user
  creation, and evidence/report exports are recorded with actor + IP; admins read
  their org's log at `GET /api/audit`.
- **CI security scanning**: `bandit` (Python SAST), `pip-audit` (dependency
  advisories), and gitleaks (secret scanning) — report-only to start. (CodeQL is
  not wired in because code scanning needs GitHub Advanced Security, which
  private repos lack; enable it if the repo goes public or GHAS is on.) Set
  `GAUNTLET_TRUST_PROXY=1` only behind a trusted proxy so `X-Forwarded-For` is
  honoured for the client IP.

## Identity & sessions (M9)

- **Password policy**: registrations, admin-created users, and password changes
  are checked for length (`GAUNTLET_PASSWORD_MIN_LEN`, default 10), all-digit
  passwords, and a common-password list. Failures return 422.
- **Short access tokens + rotating refresh tokens**: the access JWT is
  short-lived (`GAUNTLET_ACCESS_TTL_MIN`, default 30) and carries a
  `type: access` claim; login/refresh also return an **opaque refresh token**
  (stored only as a hash). Presenting one **rotates** it — the old token is
  burned and a new pair issued. Reusing a burned token is treated as theft and
  **revokes the whole token family**. `POST /api/auth/refresh` rotates,
  `POST /api/auth/logout` revokes, and changing a password revokes every
  outstanding refresh token. The console refreshes silently on a 401.
- **TOTP multi-factor (RFC 6238)**: enrol at `POST /api/auth/mfa/setup` →
  `…/mfa/enable` (confirm with a code), manage under the console's **Security**
  panel. When MFA is on, login returns an `mfa_required` challenge instead of
  tokens; the second factor is exchanged at `POST /api/auth/login/mfa`.
- **WebSocket connection tickets**: the bearer token no longer rides in the
  `ws://` URL. Clients `POST /api/sessions/{id}/ws-ticket` (authenticated,
  org-scoped) for a short-lived, single-use ticket bound to that one session,
  then connect with `?ticket=`.
- **OIDC SSO** (config-gated): set `GAUNTLET_OIDC_ISSUER` + `GAUNTLET_OIDC_CLIENT_ID`
  (+ secret + redirect URI) to enable an authorization-code flow with discovery,
  JWKS `id_token` verification (signature, issuer, audience, expiry, nonce), and
  a "Sign in with SSO" button. SSO **links to an existing account** by subject or
  email — it does not auto-provision, since org and role can't be inferred.

## Exports & outputs (F1)

Beyond the built-in Markdown + PDF, every session and report exports in the
formats stakeholders ask for downstream:

- **CSV / JSON timeline** — `GET /api/sessions/{id}/timeline.csv` and
  `…/timeline.json`. CSV drops straight into a spreadsheet or SIEM import; JSON
  is a structured, machine-readable session export (with the hash-chain fields)
  for integrations or archival. Both are in the console under **Export timeline**.
- **DOCX reports & evidence** — `…/reports/{id}.docx` and `…/evidence.docx`
  render the same content into an editable Word document, so a GRC lead can adapt
  it. The report and compliance modals now offer **Download DOCX** alongside PDF.
- **Branded PDF template** — exported PDFs carry a header rule, a footer with
  page numbers, an export timestamp, and a brand name. Set `GAUNTLET_BRAND_NAME`
  and `GAUNTLET_BRAND_ACCENT` (an `R,G,B` accent) for white-labelled output.

All exports are tenant-scoped and audited.

## Data protection & isolation depth (M10)

- **Key separation & rotation.** One master secret derives **purpose-separated**
  keys via HKDF — the JWT signing key and the tamper-evident timeline key are
  cryptographically unrelated, so a leak of one doesn't compromise the other.
  Data-at-rest uses a **versioned keyring** (`GAUNTLET_DATA_KEYS="v2:…,v1:…"`):
  new data seals under the primary key, older keys still open older data, so
  rotation needs no flag-day. `POST /api/admin/reencrypt` rewrites a tenant's
  environments under the new primary.
- **Encryption at rest.** Sensitive environment fields (assets, control gaps,
  crown jewels, deception, personnel, …) are sealed with **AES-256-GCM before
  they reach the database** — a raw DB dump yields ciphertext, not a target map.
  Opt-in (`GAUNTLET_ENCRYPT_AT_REST=1` or an explicit keyring); transparent and
  backward-compatible with un-keyed rows; works identically on SQLite and Postgres.
- **Tenant-isolation depth.** App-level `org_id` scoping (reads return 404, never
  403, so existence is hidden) is now backed by a **cross-tenant fuzz test** that
  probes every read/list/update/delete path across orgs, plus optional **Postgres
  row-level security** (`GAUNTLET_RLS_ENABLED=1`) that enforces the boundary in
  the database itself via a per-request tenant setting. RLS is a no-op on SQLite.
- **Retention & GDPR.** `POST /api/admin/retention/purge` deletes a tenant's aged
  completed sessions and audit entries (`GAUNTLET_RETENTION_DAYS`); `GET
  /api/admin/export` is a full JSON snapshot (portability, secrets excluded);
  `DELETE /api/admin/org` erases the tenant and all its data (right to be
  forgotten), guarded by a slug confirmation and audited.
- **Threat model.** [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — STRIDE over
  Gauntlet's assets, trust boundaries, and the M8–M10 mitigations.

## Access control & real-time

- **Auth & tenancy (M5):** JWT auth with organisations and roles
  (admin / facilitator / evaluator / participant). Every object belongs to one
  organisation and is invisible to others. `POST /api/auth/register` creates an
  org and its admin; admins add users via `POST /api/auth/users`.
- **Real-time (M6):** start a session with `mode: real_time, auto_advance: true`
  (or tick "Real-time" in the console). Injects with a timeout branch
  auto-advance after their clock-scaled duration (`GAUNTLET_SECONDS_PER_MIN`),
  and every surface updates live over a WebSocket (`/ws/sessions/{id}`).

## Test

```bash
cd gauntlet/backend && . .venv/bin/activate
python -m pytest -q
```

---

## Layout

```
gauntlet/
├── backend/
│   ├── app/
│   │   ├── main.py            FastAPI app + console host
│   │   ├── models.py          ORM domain model
│   │   ├── schemas.py         API contract (Pydantic)
│   │   ├── timeline.py        append-only, hash-chained log
│   │   ├── seed.py            worked ransomware tabletop
│   │   ├── engine/
│   │   │   ├── msel.py         branching MSEL logic
│   │   │   ├── adjudication.py rule an action vs. the environment
│   │   │   └── reporting.py    audience-tailored reports
│   │   └── api/               environments · scenarios · sessions · reports
│   └── tests/                 engine unit tests + API end-to-end
├── web/                       facilitator console (served SPA)
└── docs/                      design brief (HTML + Markdown)
```

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `GAUNTLET_DB_URL` | `sqlite:///…/gauntlet.db` | Database URL (SQLite or Postgres) |
| `GAUNTLET_SEED` | `1` | Load the worked example on an empty database |
| `GAUNTLET_ACCESS_TTL_MIN` | `30` | Access-token lifetime (minutes) |
| `GAUNTLET_REFRESH_TTL_DAYS` | `30` | Refresh-token lifetime (days) |
| `GAUNTLET_PASSWORD_MIN_LEN` | `10` | Minimum password length |
| `GAUNTLET_WS_TICKET_TTL_SEC` | `30` | WebSocket connection-ticket lifetime (seconds) |
| `GAUNTLET_MFA_ISSUER` | `Gauntlet` | Issuer label shown in authenticator apps |
| `GAUNTLET_OIDC_ISSUER` / `_CLIENT_ID` / `_CLIENT_SECRET` / `_REDIRECT_URI` | — | OIDC SSO (enabled when issuer + client id are set) |
| `GAUNTLET_ENCRYPT_AT_REST` | `0` | Encrypt sensitive environment fields at rest (derives a data key from the master) |
| `GAUNTLET_DATA_KEYS` | — | Explicit rotatable data keyring, `v2:<b64>,v1:<b64>` (primary first) |
| `GAUNTLET_RETENTION_DAYS` | `0` | Retention window for completed sessions + audit log (0 = off) |
| `GAUNTLET_RLS_ENABLED` | `0` | Enable Postgres row-level security (no-op on SQLite) |
| `GAUNTLET_BRAND_NAME` | `Gauntlet` | Brand name in exported PDF header/footer |
| `GAUNTLET_BRAND_ACCENT` | `37,99,235` | PDF accent colour, `R,G,B` |

---

## Roadmap

| Phase | Scope | Status |
|---|---|---|
| **M1 — Tabletop core** | Intake, scenario + MSEL, console, adjudication, timeline, reports | Shipped |
| **M2 — Authoring & library** | Template library, threat-actor-driven generation, inject bank, multi-channel delivery | Shipped |
| **M3 — Multi-cell & parallel** | Fog-of-war per cell, evaluator companion, parallel/functional roll-up | Shipped |
| **M4 — Sandbox & program analytics** | Authorization-gated live/technical injects (pluggable range adapter), program-level coverage analytics | Shipped |
| **M5 — Production-readiness** | Alembic migrations, auth + multi-tenancy + RBAC, HMAC-signed timeline, CI | Shipped |
| **M6 — Real-time** | WebSocket live updates, auto-advance timeout timers, participant console | Shipped |
| **M7 — Deep scenarios & compliance** | State-driven branching, YAML import/export/validation, compliance crosswalk (6 frameworks), evidence + PDF export | Shipped |
| **M8 — Platform hardening** | Config fail-fast, security headers, login throttling + lockout, input caps, security audit log, CI security scanning | Shipped |
| **M9 — Identity & sessions** | Password policy, short access + rotating refresh tokens (reuse detection), TOTP MFA, WebSocket connection tickets, OIDC SSO | Shipped |
| **M10 — Data protection & isolation depth** | Key separation/rotation, encryption at rest, Postgres RLS + tenant-isolation fuzzing, retention/GDPR, threat model | Shipped |

### Sandbox & program analytics (M4)

Operational modes execute technical injects through a **pluggable range
adapter** — the shipped default is a **simulation** adapter that contacts
nothing and derives synthetic telemetry from the environment model. A live
inject is **refused unless the session carries a valid, unexpired authorization
grant whose scope covers the target** — the guardrail that keeps operational
modes in bounds.

```bash
# Create a sandbox session, authorize a scope, then run a live inject
SID=$(curl -s -X POST localhost:8000/api/sessions -H 'content-type: application/json' \
  -d '{"scenario_id":1,"name":"range run","mode":"sandbox"}' | python -c 'import sys,json;print(json.load(sys.stdin)["id"])')
curl -X POST localhost:8000/api/sessions/$SID/authorize -H 'content-type: application/json' \
  -d '{"scope":["FIN-APP-02"],"authorized_by":"CISO","ttl_minutes":60}'
curl -X POST localhost:8000/api/sessions/$SID/live-inject -H 'content-type: application/json' \
  -d '{"technique":"T1003.001","target":"FIN-APP-02"}'   # refused for out-of-scope targets

# Program-level analytics across every scenario and run
curl localhost:8000/api/program/coverage
curl localhost:8000/api/program/improvements
```

The **program coverage** page (`/program.html`) shows ATT&CK coverage by tactic,
a per-technique table (exercised / detected / never-tested), and improvement
items that mark themselves *improved* when a later run meets a previously missed
objective.

### Multi-cell & parallel (M3)

```bash
# What one cell is allowed to see (fog of war) during a running session
curl localhost:8000/api/sessions/1/cell/blue_cell

# A per-cell redacted environment (white/grey/black box)
curl "localhost:8000/api/environments/1/view/blue_cell?scenario_id=1"

# Compare every run of a scenario (parallel / program view)
curl localhost:8000/api/scenarios/1/rollup
```

The console links two more surfaces: the **evaluator companion**
(`/evaluator.html`) — objectives with their evaluation guides, quick
observation logging, and the fog-of-war view of what a chosen cell can see —
and the **parallel roll-up** (`/rollup.html`) — per-run metrics and an ATT&CK
coverage heatmap across every run of a scenario.

### Authoring (M2)

Generate a grounded, branching scenario instead of starting from a blank MSEL:

```bash
# List the catalog
curl localhost:8000/api/catalog/actors
curl localhost:8000/api/catalog/templates

# Generate a scenario bound to an environment, then it's immediately runnable
curl -X POST localhost:8000/api/scenarios/generate \
  -H 'content-type: application/json' \
  -d '{"environment_id":1,"template_key":"ransomware_finance","name":"Q3 drill"}'
```

The generator walks a threat actor's kill-chain, picks real target assets from
the environment for each phase, and wires valid branches to good/bad
resolutions. Refine the draft with `PATCH /api/scenarios/{id}` and
`PATCH /api/injects/{id}`, and preview any inject in its channel with
`GET /api/injects/{id}/delivery`. The facilitator console exposes generation
(empty-state) and delivery preview (on the scene).

## Responsible use

Gauntlet is for designing and running **defensive** exercises against an
environment you own or are explicitly authorized to test. Adversary techniques
are modelled only to build the exercise — not as operational guidance against
systems you do not control. Real-time modes that could touch production stay
gated behind explicit rules of engagement.
