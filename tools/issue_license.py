#!/usr/bin/env python3
"""Vendor tool: mint Gauntlet licences (L1).

    python tools/issue_license.py keygen
    python tools/issue_license.py issue --key <private_b64> --tier team --customer "Acme" --exp 2027-09-01 \
        [--feature replay --feature scim] [--seats facilitators=5]

Keep the private key out of the repository. Deployments verify with the public
key (GAUNTLET_LICENSE_PUBKEY) and install the token via the Members page or
GAUNTLET_LICENSE.
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
os.environ.setdefault("GAUNTLET_SECRET_KEY", "issuer-only-not-a-deployment-key-000000000")
from app import entitlements  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("keygen")
    iss = sub.add_parser("issue")
    iss.add_argument("--key", required=True, help="private key (base64url) from keygen")
    iss.add_argument("--tier", required=True, choices=entitlements.TIERS)
    iss.add_argument("--customer", required=True)
    iss.add_argument("--exp", required=True, help="YYYY-MM-DD")
    iss.add_argument("--org", default="*")
    iss.add_argument("--feature", action="append", default=[], choices=entitlements.ALL_FEATURES)
    iss.add_argument("--seats", action="append", default=[], help="kind=count, e.g. facilitators=5")
    a = ap.parse_args()
    if a.cmd == "keygen":
        priv, pub = entitlements.keygen()
        print(f"PRIVATE (keep secret): {priv}\nPUBLIC (GAUNTLET_LICENSE_PUBKEY): {pub}")
        return 0
    seats = {}
    for kv in a.seats:
        k, _, v = kv.partition("=")
        seats[k.strip()] = int(v)
    print(entitlements.issue(a.key, tier=a.tier, customer=a.customer, exp=a.exp, features=a.feature, seats=seats, org=a.org))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
