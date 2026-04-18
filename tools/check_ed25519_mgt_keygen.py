#!/usr/bin/env python3
"""
Derive Ed25519 management public key (64 hex) from a seed or key file, then
check GET /getAllowedEd25519MgtKeys and GET /getKeyGenResultById ClientKeys.

Use when POST /multiSignRequest returns "client sig is not valid" — the signer
must usually match a key listed in ClientKeys for that KeyGen (per-node) and
appear in getAllowedEd25519MgtKeys.

  python3 tools/check_ed25519_mgt_keygen.py \\
    --mpc-base http://127.0.0.1:8080 \\
    --key-gen-id KeyGen2026... \\
    --seed-hex 8cf6...

Requires: urllib (stdlib); cryptography if --key-file is used.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


def _get_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _data(resp: dict) -> object:
    if not isinstance(resp, dict):
        return None
    if "data" in resp:
        return resp["data"]
    return resp.get("Data")


def _pub_hex_from_seed(seed_hex: str) -> str:
    raw = seed_hex.strip().replace("0x", "")
    if len(raw) == 64:
        seed = bytes.fromhex(raw)
    elif len(raw) == 128:
        seed = bytes.fromhex(raw)[:32]
    else:
        raise SystemExit("seed must be 64 hex (32-byte seed) or 128 hex")
    try:
        from nacl.signing import SigningKey
    except ImportError as e:
        raise SystemExit("PyNaCl required: pip install PyNaCl") from e
    return SigningKey(seed).verify_key.encode().hex()


def _pub_hex_from_key_file(path: str) -> str:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            load_pem_private_key,
            load_ssh_private_key,
        )
    except ImportError as e:
        raise SystemExit("cryptography required for --key-file: pip install cryptography") from e
    blob = Path(path).expanduser().read_bytes()
    key = None
    for loader in (load_ssh_private_key, load_pem_private_key):
        try:
            k = loader(blob, password=None)
            if isinstance(k, Ed25519PrivateKey):
                key = k
                break
        except ValueError:
            pass
    if key is None:
        raise SystemExit(f"not Ed25519 PEM/OpenSSH: {path}")
    return key.public_key().public_bytes_raw().hex()


def _norm_client_val(v: object) -> str:
    if v is None:
        return ""
    s = str(v).strip()
    if s.startswith("0x") and len(s) == 66:
        return s[2:].lower()
    return s.lower()


def main() -> None:
    ap = argparse.ArgumentParser(description="Check Ed25519 mgt key vs allow-list + KeyGen ClientKeys")
    ap.add_argument("--mpc-base", required=True, help="e.g. http://127.0.0.1:8080")
    ap.add_argument("--key-gen-id", required=True)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--seed-hex", metavar="HEX")
    g.add_argument("--key-file", metavar="PATH")
    args = ap.parse_args()

    base = args.mpc_base.rstrip("/")
    if args.seed_hex:
        pub = _pub_hex_from_seed(args.seed_hex)
    else:
        pub = _pub_hex_from_key_file(args.key_file or "")

    print(f"Derived Ed25519 public key (64 hex): {pub}")

    allowed_url = f"{base}/getAllowedEd25519MgtKeys"
    try:
        allowed_resp = _get_json(allowed_url)
    except urllib.error.URLError as e:
        raise SystemExit(f"GET getAllowedEd25519MgtKeys failed: {e}") from e

    allowed_data = _data(allowed_resp)
    allowed_pubs: set[str] = set()
    if isinstance(allowed_data, list):
        for item in allowed_data:
            if isinstance(item, dict) and item.get("publicKey"):
                allowed_pubs.add(str(item["publicKey"]).strip().lower())
            elif isinstance(item, str):
                allowed_pubs.add(item.strip().lower())
    in_allowed = pub.lower() in allowed_pubs
    print(f"In GET /getAllowedEd25519MgtKeys: {'yes' if in_allowed else 'NO — this key is not on the allow-list'}")

    kg_url = f"{base}/getKeyGenResultById?{urllib.parse.urlencode({'id': args.key_gen_id})}"
    try:
        kg_resp = _get_json(kg_url)
    except urllib.error.URLError as e:
        raise SystemExit(f"GET getKeyGenResultById failed: {e}") from e

    kg = _data(kg_resp)
    if not isinstance(kg, dict):
        raise SystemExit(f"unexpected getKeyGenResultById payload: {kg_resp!r}")

    ck = kg.get("ClientKeys") or kg.get("clientkeys")
    in_client_keys = False
    if isinstance(ck, dict):
        print("ClientKeys (node_pubkey_128hex -> client key):")
        for nk, cv in ck.items():
            raw = str(cv).strip()
            nv = _norm_client_val(cv)
            match = len(nv) == 64 and nv == pub.lower()
            if match:
                in_client_keys = True
            flag = " <-- matches your Ed25519 pubkey" if match else ""
            disp = raw if len(raw) <= 72 else raw[:68] + "..."
            print(f"  {nk[:32]}... -> {disp}{flag}")
    else:
        print("ClientKeys: missing or not a dict")

    print(
        f"In ClientKeys values (64-hex Ed25519): {'yes' if in_client_keys else 'NO — use the key that appears in ClientKeys for your node'}"
    )

    if in_allowed and in_client_keys:
        print("\nIdentity check OK for multi-agree Ed25519 management signing for this KeyGen.")
        print("If POST /multiSignRequest still fails, suspect JSON canonical mismatch (rare) or stale message (re-run the recipe).")
        sys.exit(0)
    sys.exit(1)


if __name__ == "__main__":
    main()
