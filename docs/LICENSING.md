# Licensing and entitlements

Gauntlet is source-available and self-hosted. The paid tiers unlock features that
scale with the buyer; the engine, the record, reports, certificates, MFA, SSO,
audit, encryption and row-level security are never gated.

## Tiers

| Tier | Price | Seats | Includes |
|---|---|---|---|
| Community (no licence) | free | unlimited | The full engine, environment and CTEP libraries, adversary catalog, reports, certificates, exports, SSO, MFA, audit, encryption at rest, air-gapped mode, game mode, solo learning. |
| Team | $6,000 / year | 5 facilitators, $900 per extra seat | White-label branding, the content subscription (quarterly packs), the telemetry loop, Jira/ServiceNow push. Email support next business day. |
| Education | $3,000 / year | 2 instructors, $900 per extra seat; unlimited students | The education edition (cohorts, gradebook, anonymous grading), session replay, white-label branding. Not the programme features: a classroom that also runs a programme buys Team or Enterprise. |
| Enterprise | from $24,000 / year | quoted | Team and Education together, plus SCIM provisioning, partner mode (5 client organisations included, $2,000 per additional client per year), the adversary intel feed, the sector benchmark cohort, a support SLA (4 business hours for severity 1). |

Prices are per organisation, billed annually, and one licence runs one
instance. Facilitated exercises are sold separately from $8,000 each. The
grace period after expiry is 30 days. The pricing table on the packaging page
(`/product.html`) is the customer-facing copy of this one; change both.

A licence may add individual features beyond its tier and may cap seats:

- `facilitators` — admins and facilitators count (instructors, on Education);
  evaluators, participants and students do not. Adding a member beyond the
  cap is refused with a `402` naming the limit.
- `clients` — the client organisations a partner may link in partner mode.
  Enterprise licences are issued with `clients=5`; a customer who buys more
  gets a re-issued licence with the higher number. Linking a client beyond
  the cap is refused with a `402`; existing clients are untouched.

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
python tools/issue_license.py issue --key-file <key> --tier team --customer "Acme" \
    --exp 2027-09-01 --seats facilitators=5
python tools/issue_license.py issue --key-file <key> --tier education --customer "Some College" \
    --exp 2027-09-01 --seats facilitators=2
python tools/issue_license.py issue --key-file <key> --tier enterprise --customer "Acme Consulting" \
    --exp 2027-09-01 --seats facilitators=10 --seats clients=5
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

## Buying a licence

Write to sales@moosearsenal.com with the organisation name, the tier and the
number of facilitators. Licences are issued the same working day; support is
support@moosearsenal.com.
