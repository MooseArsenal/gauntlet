# Gauntlet threat model

Gauntlet designs and proctors security exercises. To do that it stores a
concentrated, high-value picture of an organisation's defences: asset
inventories, control coverage and **gaps**, detection logic, playbooks, crown
jewels, deception placements, and named personnel. That is precisely the
target package an attacker would want. The security work in M8–M10 treats
Gauntlet itself as a system worth attacking.

This document is a living STRIDE-style model: assets, trust boundaries,
adversaries, threats, and the mitigations that answer them. It is meant to be
revisited whenever a boundary or data flow changes.

## Assets

| Asset | Sensitivity | Where it lives |
|---|---|---|
| Environment intelligence (assets, control gaps, crown jewels, deception, personnel) | **Critical** — a target map for a real attack | `environments` (encrypted at rest, M10) |
| Exercise timeline (what happened, when) | High — integrity-critical, used as audit evidence | `timeline_events` (HMAC hash-chain) |
| Credentials & session material | Critical | `users.password_hash` (PBKDF2), `refresh_tokens` (hashed), TOTP secrets |
| Audit log | High — incident-response record | `audit_logs` |
| Tenant boundary (org_id) | Critical — multi-tenant isolation | every domain table |

## Trust boundaries

1. **Browser ↔ API.** Untrusted client input; auth via short-lived bearer JWT.
2. **Tenant ↔ tenant.** Every request is scoped to one `org_id`; no tenant may
   observe another's existence.
3. **App ↔ database.** The DB may be dumped, replicated, or accessed by a
   compromised DB account independently of the app.
4. **App ↔ identity provider (OIDC).** External IdP asserts identity; its
   `id_token` is verified, not trusted blindly.
5. **App ↔ range adapter (sandbox/live injects).** Live actions require an
   explicit, scoped, time-boxed authorization grant.

## STRIDE

### Spoofing
- **Threat:** impersonating a user or tenant.
- **Mitigations:** PBKDF2-SHA256 passwords (240k rounds); short access tokens
  with a `type` claim so a refresh/MFA-challenge token can't be replayed as an
  access token (M9); optional TOTP MFA (M9); OIDC `id_token` signature/iss/aud/
  nonce verification (M9); login throttling + lockout (M8).

### Tampering
- **Threat:** altering the exercise record or another tenant's data.
- **Mitigations:** HMAC hash-chained timeline with a key **domain-separated**
  from the JWT key (M10) — forging a chain needs the timeline key, and a leak of
  the JWT key doesn't grant it; app-level `org_id` scoping plus optional Postgres
  RLS (M10); input caps (M8).

### Repudiation
- **Threat:** "I didn't do that."
- **Mitigations:** security audit log with actor + IP for logins, user/role
  changes, exports, erasure, and re-encryption (M8/M10); tamper-evident
  timeline for in-exercise actions.

### Information disclosure
- **Threat:** DB dump or leaked query exposes environment intelligence or
  secrets; token leaks via URLs/logs.
- **Mitigations:** AES-256-GCM **encryption at rest** for sensitive environment
  fields — a raw dump yields ciphertext, not crown jewels (M10); passwords and
  refresh tokens stored only as hashes; **WebSocket connection tickets** keep
  the bearer token out of `ws://` URLs and proxy logs (M9); tenant reads return
  404 (not 403) so existence is never confirmed across the boundary; security
  headers / strict CSP (M8); secret-scanning in CI (M8).

### Denial of service
- **Threat:** oversized or abusive input exhausts resources.
- **Mitigations:** scenario YAML byte cap and inject-count cap (M8); login
  throttling (M8); retention purge bounds unbounded data growth (M10).

### Elevation of privilege
- **Threat:** a lower role acts as admin, or a tenant crosses into another.
- **Mitigations:** RBAC (`admin`/`facilitator`/`evaluator`/`participant`) on
  every mutating route; admin-only data-protection endpoints (M10); defence in
  depth via Postgres RLS keyed on a per-request tenant GUC (M10); fail-fast
  production config refuses the auth-optional dev bypass (M8).

## Key management (M10)

- One master secret (`GAUNTLET_SECRET_KEY`) derives **purpose-separated** keys
  via HKDF: the JWT key and the timeline key are cryptographically unrelated, so
  compromise of one does not compromise the other.
- Data-at-rest uses a **versioned keyring**: new data is sealed under the primary
  key; older keys still open older data, so keys rotate without a flag-day. The
  admin re-encrypt endpoint rewrites a tenant's rows under the new primary.
- Production posture (`GAUNTLET_ENV=prod`) refuses to start on a default or
  short secret, wildcard CORS, or the auth bypass.

## Data protection & privacy (M10)

- **Encryption at rest** for sensitive environment fields (opt-in via a data
  key; transparent and backward-compatible with un-keyed rows).
- **Retention** purges a tenant's aged completed sessions and audit entries.
- **GDPR**: per-tenant data **export** (portability, secrets excluded) and
  **erasure** (right to be forgotten), the latter guarded by a slug confirmation
  and audited.

## Residual risks / future work

- Application-level field encryption protects the DB-at-rest boundary, not a
  fully compromised **application host** (keys are in process memory). An
  external KMS/HSM for the master secret would raise that bar.
- RLS is defence in depth, not a substitute for app scoping; it is Postgres-only.
- No per-field access logging on decrypt; audit covers coarse actions.
- Rate limiting is per-process/in-memory; a multi-node deployment should move
  throttle + WS-ticket state to a shared store (Redis).
