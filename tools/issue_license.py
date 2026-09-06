#!/usr/bin/env python3
"""Vendor tool: keys, licences and revocations (L1/L6).

    python tools/issue_license.py keygen --out vendor-license.key
    python tools/issue_license.py issue --key-file vendor-license.key --tier team --customer "Acme" \
        --exp 2027-09-01 [--feature replay] [--seats facilitators=5] [--seats clients=5] [--org acme]
    python tools/issue_license.py revoke --key-file vendor-license.key --serial 1a2b… [--serial …] \
        [--previous revocations.grl] > revocations.grl
    python tools/issue_license.py inspect <token>
    python tools/issue_license.py show --key-file vendor-license.key

``keygen`` writes the private key as a passphrase-encrypted PEM (asked for
interactively, or GAUNTLET_SIGNING_PASSPHRASE) and prints the public key and
its key id — the two things that go into the product (signing.VENDOR_KEYS).
The private key is never printed. Run it on a machine you trust, keep the file
and the passphrase in separate places, and read docs/KEY_MANAGEMENT.md.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
os.environ.setdefault("GAUNTLET_SECRET_KEY", "issuer-only-not-a-deployment-key-000000000")
from app import entitlements, signing  # noqa: E402


def _passphrase(confirm: bool = False) -> str:
    env = os.environ.get("GAUNTLET_SIGNING_PASSPHRASE")
    if env:
        return env
    p = getpass.getpass("Key passphrase: ")
    if confirm and getpass.getpass("Again: ") != p:
        sys.exit("passphrases differ")
    return p


def _private_key(a) -> str:
    if getattr(a, "key_file", None):
        return signing.load_private_key(a.key_file, _passphrase())
    if getattr(a, "key", None):
        print("warning: --key puts the private key in your shell history; prefer --key-file", file=sys.stderr)
        return a.key
    sys.exit("give --key-file (recommended) or --key")


def _signing_args(sub):
    sub.add_argument("--key-file", help="encrypted private key from keygen")
    sub.add_argument("--key", help="raw private key (base64url); discouraged")


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    kg = sub.add_parser("keygen")
    kg.add_argument("--out", help="write the encrypted private key here (recommended)")
    kg.add_argument("--print-private", action="store_true", help="print the raw private key instead (discouraged)")
    iss = sub.add_parser("issue"); _signing_args(iss)
    iss.add_argument("--tier", required=True, choices=entitlements.TIERS)
    iss.add_argument("--customer", required=True)
    iss.add_argument("--exp", required=True, help="YYYY-MM-DD")
    iss.add_argument("--org", default="*")
    iss.add_argument("--feature", action="append", default=[], choices=entitlements.ALL_FEATURES)
    iss.add_argument("--seats", action="append", default=[],
                     help="kind=count: facilitators=N (admins + facilitators; instructors on Education), clients=N (partner-mode client organisations)")
    rv = sub.add_parser("revoke"); _signing_args(rv)
    rv.add_argument("--serial", action="append", default=[], required=True)
    rv.add_argument("--previous", help="an earlier revocation list to carry forward")
    ins = sub.add_parser("inspect"); ins.add_argument("token")
    sh = sub.add_parser("show", help="the public key and kid inside an encrypted key file"); sh.add_argument("--key-file", required=True)
    a = ap.parse_args()

    if a.cmd == "keygen":
        priv, pub = signing.keygen()
        kid = signing.kid_for(pub)
        if a.out:
            signing.save_private_key(a.out, priv, _passphrase(confirm=True))
            print(f"private key written (encrypted) to {a.out}")
        elif a.print_private:
            print(f"PRIVATE (keep secret): {priv}")
        else:
            sys.exit("give --out FILE to store the private key encrypted (or --print-private, discouraged)")
        print(f"PUBLIC: {pub}\nKID: {kid}\n\nAdd to backend/app/signing.py VENDOR_KEYS:\n    \"{kid}\": \"{pub}\",")
        return 0
    if a.cmd == "show":
        pub = signing.public_of(signing.load_private_key(a.key_file, _passphrase()))
        print(f"PUBLIC: {pub}\nKID: {signing.kid_for(pub)}")
        return 0
    if a.cmd == "inspect":
        parts = a.token.strip().split(".")
        body = parts[-2] if len(parts) in (3, 4) else ""
        try:
            raw = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
            if parts[0] == "GP1":
                import zlib
                raw = zlib.decompress(raw)
            print(json.dumps(json.loads(raw), indent=2))
        except Exception as exc:  # noqa: BLE001
            sys.exit(f"cannot decode: {exc}")
        print("(decoded without verifying the signature)", file=sys.stderr)
        return 0
    priv = _private_key(a)
    if a.cmd == "issue":
        seats = {}
        for kv in a.seats:
            k, _, v = kv.partition("=")
            seats[k.strip()] = int(v)
        tok = entitlements.issue(priv, tier=a.tier, customer=a.customer, exp=a.exp, features=a.feature, seats=seats, org=a.org)
        p = entitlements._unverified_payload(tok.split(".")[1])
        print(f"serial {p['serial']}  kid {p['kid']}  {a.tier} for {a.customer} until {a.exp}", file=sys.stderr)
        print(tok)
        return 0
    if a.cmd == "revoke":
        serials = list(a.serial)
        if a.previous:
            with open(a.previous, encoding="utf-8") as f:
                serials += entitlements._unverified_payload(f.read().strip().split(".")[1]).get("revoked", [])
        print(entitlements.issue_revocations(priv, serials))
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
