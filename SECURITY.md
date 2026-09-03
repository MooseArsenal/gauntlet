# Security policy

Gauntlet is a security product; we hold it to the standard we ask of the
organisations that exercise with it.

## Reporting a vulnerability

Email **security@moosearsenal.com**, or open a private security advisory on
the repository. The same contact is published at `/.well-known/security.txt`
on every Gauntlet instance. Please include the version (`/api/health`
returns it), steps to reproduce, and impact. We acknowledge within two working
days and aim to ship a fix for confirmed high-severity issues within fourteen.
We do not pursue researchers who act in good faith and stay within the scope
below.

**In scope:** the API, the console and every page under `web/`, the SCIM
endpoint, exports and PDFs, the timeline chain and certificate signatures,
tenant isolation, authentication (password, MFA, OIDC, refresh tokens).

**Out of scope:** denial of service by volume, findings that require a
compromised host or database account, the demo organisation's default
credentials when `GAUNTLET_SEED=1` outside production (documented, refused in
production), and third-party services you connect through the tracker or
range adapters.

## Supported versions

The `main` branch and the latest tagged release receive fixes. Older tags do
not.

## What the product does to protect itself

- Every tenant object is scoped by organisation in the application and, on
  Postgres, by row-level security policies the database enforces (on by
  default in production).
- The exercise record is an append-only, HMAC-chained timeline with a signed
  head; certificates are HMAC-signed with a domain-separated key.
- Passwords are hashed with a slow hash; refresh tokens are opaque, rotating
  and revocable; TOTP MFA; OIDC single sign-on; SCIM provisioning with a
  per-organisation token stored only as a hash.
- Login, registration and certificate verification are throttled — in
  memory by default, on Redis when `GAUNTLET_REDIS_URL` is set.
- Environment data can be encrypted at rest with a versioned keyring.
- Strict Content-Security-Policy and the usual hardening headers; request
  bodies are capped as they stream in; production refuses insecure
  configuration at start-up.
- Air-gapped mode refuses every outbound network call, fail-closed.
- CI runs Bandit (SAST), pip-audit (dependencies, blocking), gitleaks
  (secrets) and produces a CycloneDX SBOM on every run.

See `docs/THREAT_MODEL.md` for the threat model and `docs/ENTERPRISE.md` for
the deployment checklist.
