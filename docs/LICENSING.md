# Licensing and entitlements

Gauntlet is source-available and self-hosted. The paid tiers unlock features that
scale with the buyer; the engine, the record, reports, certificates, MFA, SSO,
audit, encryption and row-level security are never gated.

## Tiers

| Tier | Includes |
|---|---|
| Community (no licence) | The full engine, environment and CTEP libraries, adversary catalog, reports, certificates, exports, SSO, MFA, audit, air-gapped mode. |
| Team | White-label branding, the content subscription, the telemetry loop, Jira/ServiceNow push. |
| Education | Team, plus the education edition (cohorts, gradebook, anonymous grading) and session replay. |
| Enterprise | Education, plus partner mode, SCIM provisioning, the instance benchmark cohort, the adversary intel feed. |

A licence may add individual features beyond its tier and may cap
**facilitator seats** (admins and facilitators count; evaluators and
participants do not).

## How a licence works

A licence is a compact token `GL1.<payload>.<signature>` signed with the
vendor's Ed25519 private key and verified on the deployment with the public
key, so it works air-gapped and cannot be forged by editing a file. Install it
on the Members page (admin) or set `GAUNTLET_LICENSE`; the deployment-wide
public key is `GAUNTLET_LICENSE_PUBKEY`.

- **Active**: everything in the tier, plus listed features.
- **Grace**: for 30 days after expiry everything keeps working with a warning.
- **Expired**: the deployment degrades to Community. Data is never hidden;
  only paid features close, with a plain `402` message naming the tier.

`GET /api/license` shows the effective entitlement to any signed-in user so
the console can label what is locked.

## Issuing (vendor)

```bash
python tools/issue_license.py keygen
python tools/issue_license.py issue --key <private> --tier team --customer "Acme" \
    --exp 2027-09-01 --feature replay --seats facilitators=5
```

Keep the private key outside the repository. Rotate by issuing a new keypair,
shipping the new public key in a release, and re-issuing licences.

## What the education features do

- `education` — `/api/cohorts/*`: cohorts, enrolment by code (students create
  their own participant accounts; they never count as seats), seating a whole
  class into a run, the gradebook and its CSV export, anonymous grading.
- `replay` — `GET /api/sessions/{id}/replay` and `POST /api/sessions/{id}/rewind`:
  the exercise as scenes, and a fork of a new run from any scene.

- `content_packs` — `POST /api/packs/install` for scenario packs; `intel_feed` —
  intel packs and `GET /api/packs/intel`. Inspecting a pack is always allowed.
  See `docs/CONTENT_PACKS.md`.

## Keys, serials and revocation

Every licence names the key that signed it (`kid`) and carries a random
`serial`. Deployments trust the vendor keys compiled into the release
(`signing.VENDOR_KEYS`); key rotation adds a kid and removes the old one a
release later. A signed revocation list (`GR1`) installed on the Members page
or via `GAUNTLET_LICENSE_REVOCATIONS` degrades a revoked serial to Community at
once. Procedure and ceremony: `docs/KEY_MANAGEMENT.md`.
