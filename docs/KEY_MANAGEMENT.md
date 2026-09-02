# Key management

Licences (`GL1`), revocation lists (`GR1`) and content packs (`GP1`) are
Ed25519-signed by the vendor. What a deployment trusts, and how the private
keys are kept, decides whether the paid tiers mean anything. This is the
procedure.

## What is where

| Thing | Where it lives | Who sees it |
|---|---|---|
| Vendor public keys, by key id | `backend/app/signing.py` → `VENDOR_KEYS`, compiled into every release | everyone (it is public) |
| Vendor private keys | passphrase-encrypted PEM files on an offline machine, plus one sealed backup | two named people |
| Passphrases | a password manager vault separate from the key files | the same two people |
| Licence serials issued | the customer ledger (CRM or spreadsheet): serial, customer, tier, expiry, kid | sales, support |
| Revocation list | `revocations.grl`, published with each release and installable on the Members page | customers |

Nothing private is ever in the repository, a CI secret, a chat, a ticket or
an email. The secret-scan CI job and `tests/test_l6_keys.py` refuse a commit
that contains PEM private-key material.

## Ceremony: creating a signing key

1. On a machine that is not a shared workstation (a fresh VM or a laptop
   without the repo's CI credentials), with the repository checked out:

       python tools/issue_license.py keygen --out vendor-license-2026.key

   Choose a passphrase of at least 12 characters and store it in the vault.
   The tool prints the **public key** and its **kid** and never prints the
   private key.
2. Copy the `.key` file to a second, offline medium (encrypted USB, sealed).
   Two copies, two places, never in cloud sync.
3. Add the kid and public key to `VENDOR_KEYS` in `backend/app/signing.py`,
   open a PR, release. From that release on, every deployment trusts the key.
4. Do the same with `tools/build_pack.py keygen vendor-pack-2026.key` for
   content packs, or reuse the licence key if one person does both jobs.

Repeat for a second key immediately and keep it unused: if the first is ever
compromised, the standby key is already trusted by every deployment in the
field and issuing continues the same day.

## Issuing a licence

    python tools/issue_license.py issue --key-file vendor-license-2026.key \
        --tier team --customer "Acme Corp" --exp 2027-09-01 --seats facilitators=5

The token goes to the customer; the serial and kid printed on stderr go into
the ledger. The customer installs it on the Members page or via
`GAUNTLET_LICENSE`. Expiry degrades to Community after a 30-day grace period;
it never hides data.

## Revoking

Reasons: a licence shared beyond its customer, a non-payment, a compromised key.

    python tools/issue_license.py revoke --key-file vendor-license-2026.key \
        --serial 3f9c… --serial 77ab… --previous revocations.grl > revocations.grl

Publish the new `revocations.grl` with the next release notes and send it to
the affected customer's contacts; anyone can install it (`POST
/api/admin/license/revocations` or the Members page) and it applies at once.
Revocation lists are signed, so a customer cannot forge one to revoke a rival's
licence, and a deployment ignores a list that no longer verifies.

## Rotating

1. Create the new key (ceremony above) and add it to `VENDOR_KEYS`; release.
2. Start issuing with the new key. Existing licences keep verifying under the
   old kid.
3. When every licence signed by the old key has expired or been reissued,
   remove the old kid from `VENDOR_KEYS` in a release. Until then it stays.

## If a private key leaks

1. Stop issuing with it. Switch to the standby key the same day.
2. Release a build that removes the leaked kid from `VENDOR_KEYS`. Anything
   signed by it — licences, packs — stops verifying on that build.
3. Reissue affected customers' licences under the new key, free of charge, and
   tell them why in plain words.
4. Publish a revocation list for the serials issued between the estimated
   compromise and the removal, for deployments that have not upgraded.

## Environment keys and forks

Outside production, `GAUNTLET_LICENSE_PUBKEY(S)` and `GAUNTLET_PACK_PUBKEY(S)`
add trusted keys (`kid=base64url,...`, or one bare key) so the test suite and
development instances can sign their own. In production these variables are
ignored and the start-up check names them, unless `GAUNTLET_TRUST_ENV_KEYS=1`
is set on purpose — the path for a fork that issues its own licences under its
own keys.
