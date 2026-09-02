# Enterprise deployment checklist

What a security team will ask before Gauntlet goes into an environment they
are accountable for, and where each answer lives. Every item is available
today; nothing here is a roadmap.

## Identity

| Ask | Answer |
|---|---|
| Single sign-on | OIDC (`GAUNTLET_OIDC_*`); accounts are matched on verified email or subject. See `docs/DEPLOY.md`. |
| Provisioning / deprovisioning | SCIM 2.0 at `/scim/v2` (Users: filter, create, read, replace, patch, delete). An admin mints the bearer token with `POST /api/admin/scim-token`; only its SHA-256 is stored; `DELETE` revokes it. Deprovisioning deactivates the account and revokes its sessions — the record keeps its author. |
| MFA | TOTP per account; admins can reset a lost authenticator from the Members page. |
| Roles | admin, facilitator, evaluator, participant. Participants see only the cell they joined. |
| Session lifetime | Short access tokens (`GAUNTLET_ACCESS_TTL_MIN`), rotating refresh tokens (`GAUNTLET_REFRESH_TTL_DAYS`), revocable per user. |

## Tenancy and data

| Ask | Answer |
|---|---|
| Tenant isolation | Application scoping on every query, plus Postgres row-level security policies — **on by default in production** (`GAUNTLET_RLS_ENABLED`, off only if you set it to 0). The database account must be allowed to `ALTER TABLE … ENABLE ROW LEVEL SECURITY` on first start. |
| Encryption at rest | Environment data (assets, controls, deception, personnel…) sealed under a versioned keyring (`GAUNTLET_DATA_KEYS`); rotate with `POST /api/admin/reencrypt`. Database-level encryption is the platform's job. |
| Encryption in transit | Terminate TLS in front of the app; HSTS is sent in production. |
| Retention | `GAUNTLET_RETENTION_DAYS` + `POST /api/admin/retention/purge`. |
| Portability and erasure | `GET /api/admin/export` (full JSON), `DELETE /api/admin/org` (everything, slug-confirmed). |
| Audit log | Every privileged action, with actor, address and detail; `GET /api/audit`. |
| Tamper evidence | The exercise timeline is an HMAC hash chain with a signed head (`GET /api/sessions/{id}/verify`); certificates are signed and publicly verifiable. |

## Operations

| Ask | Answer |
|---|---|
| Egress | None required. `GAUNTLET_AIRGAPPED=1` refuses every outbound call fail-closed. Fonts are the only external asset the console references; self-host them if your CSP forbids Google Fonts. |
| Scaling | One worker per container. Throttles can share a Redis (`GAUNTLET_REDIS_URL`) so lockouts hold across instances and restarts; WebSocket fan-out and real-time timers remain per-process, so run one worker behind sticky sessions until pub/sub lands. |
| Backups | The database is the only state. Keys live in environment variables; back them up with the secrets store, not the database. |
| Health | `GET /api/health` (version, air-gap flag, demo flag). |
| Configuration safety | Production refuses to start with a default secret, wildcard CORS, the demo seed without a password, or more than one worker. |

## Supply chain

| Ask | Answer |
|---|---|
| SBOM | CycloneDX JSON produced by CI on every run (`sbom-cyclonedx` artifact) from the pinned `backend/requirements.lock.txt`. |
| Dependency audit | `pip-audit` blocks the build on a known vulnerability. |
| SAST / secrets | Bandit blocks; gitleaks reports. |
| Image | `backend/Dockerfile`, single worker, non-root, lockfile install. |

## Penetration-test readiness

Give the testers:

1. A dedicated deployment with `GAUNTLET_ENV=production`, a real secret key,
   `GAUNTLET_SEED=0`, and Postgres (so RLS is exercised).
2. Two organisations, each with an admin, a facilitator, an evaluator and a
   participant; a SCIM token for one of them; OIDC configured if you use it.
3. The threat model (`docs/THREAT_MODEL.md`) and this document.
4. The known limits, so time is not spent rediscovering them: throttles are
   per-process without Redis; the demo seed is a documented dev-only account;
   the certificate verify endpoint is deliberately unauthenticated and rate
   limited; exports contain the exercise record by design.

What we expect them to try, and where the controls are:

- Cross-tenant reads and writes (application scoping in `app/security.py`,
  `scope_or_404`; RLS in `app/rls.py`; the fuzz test `tests/test_m10_tenant_fuzz.py`).
- Participant privilege escalation (`app/membership.py`; `tests/test_h1_participant_boundary.py`).
- Timeline tampering (`app/timeline.py`; `tests/test_m4_hardening.py`).
- Certificate forgery (`app/certificates.py`; `tests/test_m1_certificate.py`).
- Authentication: credential stuffing, MFA bypass, refresh-token replay, OIDC
  state (`app/api/auth.py`, `app/security.py`, `app/throttle.py`).
- SCIM: token brute force, cross-org provisioning, last-admin lockout
  (`app/api/scim.py`; `tests/test_m5_enterprise.py`).
- Injection through imports (YAML, CTEP packs, environment and alert exports)
  and export rendering (PDF/DOCX) — all inputs are size-capped and validated.
