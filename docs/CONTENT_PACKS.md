# Content packs and the intel feed

A content pack is one signed token:

    GP1.<base64url(zlib(manifest json))>.<base64url(ed25519 signature)>

The deployment verifies it with `GAUNTLET_PACK_PUBKEY` (default: the licence
public key), so a pack can be carried into an air-gapped deployment on removable
media and still be trusted, and cannot be altered on the way. Install from the
Members page (paste or choose the `.gpack` file, inspect, install) or with
`POST /api/packs/install`.

| Kind | Feature | Items | On install |
|---|---|---|---|
| `scenarios` | `content_packs` (Team+) | scenario documents in the YAML-export shape, each naming the library environment it was written for | scenarios are created, bound to the org's copy of that library environment (stamped if missing) or to an environment the installer chooses |
| `intel` | `intel_feed` (Enterprise) | dated adversary profiles: key, name, headline, notes, sectors, techniques, kill chain, objectives, references | custom adversaries are created or updated by key (a newer pack updates in place); the entries appear on the Members page feed and in the scenario generator |

The pack id is stable across versions; the same version installs once per
organisation, a newer version updates the record and its content. Forgetting
a pack removes only the record — the scenarios and adversaries stay.

## Publishing

    python tools/build_pack.py keygen
    python tools/build_pack.py scenarios --key <private> --id acme-healthcare --name "Healthcare pack" \
        --version 2026.9 --publisher Acme hospital.yaml:hospital clinic.yaml:hospital > healthcare.gpack
    python tools/build_pack.py intel --key <private> --id acme-intel --name "Acme intel" \
        --version 2026.09.02 --publisher Acme tools/examples/intel-sample.json > intel.gpack
    python tools/build_pack.py inspect healthcare.gpack

Scenario files are what `GET /api/scenarios/{id}/export` returns. Library
environment keys are those of `GET /api/environments/templates`. Keep the
private key out of the repository; set the public key on deployments with
`GAUNTLET_PACK_PUBKEY` when it differs from the licence key.
