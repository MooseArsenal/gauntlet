#!/usr/bin/env python3
"""Publisher tool: build and sign Gauntlet content packs (L5).

    python tools/build_pack.py keygen
    python tools/build_pack.py scenarios --key <private_b64> --id acme-healthcare --name "Healthcare pack" \
        --version 2026.9 --publisher "Acme" scenario1.yaml[:hospital] scenario2.yaml[:water_utility] > pack.gpack
    python tools/build_pack.py intel --key <private_b64> --id acme-intel --name "Acme intel" \
        --version 2026.09.02 --publisher "Acme" intel.json > intel.gpack
    python tools/build_pack.py inspect pack.gpack

A scenario file is the YAML the console exports; ``:<environment_key>`` names
the library environment it was written for (hospital, water_utility, …) so an
installer need not choose one. An intel file is a JSON list of adversary
entries: key, name, headline, notes, published, sectors, techniques,
kill_chain, objectives, references, motivation, is_fictitious.

Deployments verify with GAUNTLET_PACK_PUBKEY (default: the licence key).
Keep the private key out of the repository.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import date

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
os.environ.setdefault("GAUNTLET_SECRET_KEY", "issuer-only-not-a-deployment-key-000000000")
from app import entitlements, packs, scenario_io  # noqa: E402


def _common(sub):
    sub.add_argument("--key", required=True, help="private key (base64url) from keygen")
    sub.add_argument("--id", required=True, help="pack id: short lowercase slug, stable across versions")
    sub.add_argument("--name", required=True)
    sub.add_argument("--version", required=True)
    sub.add_argument("--publisher", required=True)
    sub.add_argument("--issued", default=date.today().isoformat())


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("keygen")
    sc = sub.add_parser("scenarios"); _common(sc)
    sc.add_argument("files", nargs="+", help="scenario.yaml[:environment_key]")
    it = sub.add_parser("intel"); _common(it)
    it.add_argument("file", help="intel.json (a list of entries)")
    ins = sub.add_parser("inspect"); ins.add_argument("file")
    a = ap.parse_args()
    if a.cmd == "keygen":
        priv, pub = entitlements.keygen()
        print(f"PRIVATE (keep secret): {priv}\nPUBLIC (GAUNTLET_PACK_PUBKEY): {pub}")
        return 0
    if a.cmd == "inspect":
        with open(a.file, encoding="utf-8") as f:
            manifest, digest = packs.verify(f.read())
        print(json.dumps(packs.summary(manifest, digest), indent=2))
        return 0
    items = []
    if a.cmd == "scenarios":
        for spec in a.files:
            path, _, env_key = spec.partition(":")
            with open(path, encoding="utf-8") as f:
                data = scenario_io.load_yaml(f.read())
            items.append({"environment_key": env_key, "scenario": data})
    else:
        with open(a.file, encoding="utf-8") as f:
            items = json.load(f)
    manifest = {"v": 1, "kind": a.cmd, "id": a.id, "name": a.name, "version": a.version,
                "publisher": a.publisher, "issued": a.issued, "items": items}
    print(packs.sign(a.key, manifest))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
