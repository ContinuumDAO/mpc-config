#!/usr/bin/env python3
"""Provision bootstrap_key/ed25519_private.hex and set PublicMgtKey + DeterministicNodeKey in configs.yaml.

Used by process_config.sh when the operator leaves PublicMgtKey empty (see mpc-auth
docs-internal/DATABASE_BACKUP_RESTORE_PLAN.md §8; mpc-config API_IMPLEMENTATION.md).
"""
from __future__ import annotations

import argparse
import os
import stat
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
except ImportError:
    print("bootstrap_key_provision: install cryptography (pip install cryptography)", file=sys.stderr)
    sys.exit(3)

try:
    from ruamel.yaml import YAML
except ImportError:
    print("bootstrap_key_provision: install ruamel.yaml (pip install 'ruamel.yaml')", file=sys.stderr)
    sys.exit(3)


def _seed_and_pubkey_hex(priv: ed25519.Ed25519PrivateKey) -> tuple[bytes, str]:
    seed = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    raw_pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return seed, raw_pub.hex()


def main() -> int:
    ap = argparse.ArgumentParser(description="Write bootstrap Ed25519 seed file and update configs.yaml")
    ap.add_argument("config_yaml", type=Path, help="Path to configs.yaml")
    ap.add_argument(
        "--bootstrap-subdir",
        default="bootstrap_key",
        help="Directory name under configs.yaml parent (default: bootstrap_key)",
    )
    args = ap.parse_args()

    cfg_path: Path = args.config_yaml.resolve()
    if not cfg_path.is_file():
        print(f"configs.yaml not found: {cfg_path}", file=sys.stderr)
        return 1

    yaml = YAML()
    yaml.preserve_quotes = True
    yaml.width = 4096
    yaml.indent(mapping=2, sequence=4, offset=2)

    with cfg_path.open() as f:
        data = yaml.load(f)
    if not isinstance(data, dict):
        print("invalid yaml root", file=sys.stderr)
        return 1

    existing = data.get("PublicMgtKey")
    if existing is not None and str(existing).strip():
        print("PublicMgtKey already set; skipping bootstrap_key provision.")
        return 0

    bootstrap_dir = cfg_path.parent / args.bootstrap_subdir
    bootstrap_dir.mkdir(mode=0o700, exist_ok=True)
    keyfile = bootstrap_dir / "ed25519_private.hex"

    if keyfile.is_file():
        hexs = keyfile.read_text(encoding="utf-8").strip().lower().removeprefix("0x")
        try:
            seed = bytes.fromhex(hexs)
        except ValueError:
            print(f"invalid hex in {keyfile}", file=sys.stderr)
            return 2
        if len(seed) == 32:
            priv = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        elif len(seed) == 64:
            priv = ed25519.Ed25519PrivateKey.from_private_bytes(seed[:32])
        else:
            print(f"{keyfile}: expected 32 or 64 bytes hex", file=sys.stderr)
            return 2
        pub_hex = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()
    else:
        priv = ed25519.Ed25519PrivateKey.generate()
        seed, pub_hex = _seed_and_pubkey_hex(priv)
        keyfile.write_text(seed.hex() + "\n", encoding="utf-8")
        os.chmod(keyfile, stat.S_IRUSR | stat.S_IWUSR)

    data["PublicMgtKey"] = pub_hex
    data["DeterministicNodeKey"] = True
    with cfg_path.open("w") as f:
        yaml.dump(data, f)

    print(
        f"Wrote {keyfile} (mode 0600) and set PublicMgtKey + DeterministicNodeKey in {cfg_path}.\n"
        "Back up bootstrap_key/ securely; loss prevents decrypting DB backups and reproducing deterministic nodeKey."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
