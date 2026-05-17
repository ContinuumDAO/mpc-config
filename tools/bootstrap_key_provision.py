#!/usr/bin/env python3
"""Provision bootstrap_key/ed25519_private.hex and set PublicMgtKey + DeterministicNodeKey in configs.yaml.

Used by process_config.sh when the operator leaves PublicMgtKey empty (see mpc-auth
docs-internal/DATABASE_BACKUP_RESTORE_PLAN.md §8; mpc-config API_IMPLEMENTATION.md).

When PublicMgtKey is already set (e.g. provision-node.sh --public-mgt-key), this script
still runs: if bootstrap_key/ed25519_private.hex exists and matches configs.yaml,
it sets DeterministicNodeKey: true so mpc-auth can derive the same nodeKey after a reinstall.
"""

from __future__ import annotations

import argparse
import os
import re
import stat
import sys
from pathlib import Path

try:
    from ruamel.yaml import YAML
except ImportError:
    print("bootstrap_key_provision: install ruamel.yaml (pip install 'ruamel.yaml')", file=sys.stderr)
    sys.exit(3)


def _load_crypto():
    """Import cryptography only when generating keys or verifying an on-disk bootstrap file."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError:
        print("bootstrap_key_provision: install cryptography (pip install cryptography)", file=sys.stderr)
        sys.exit(3)
    return serialization, ed25519


def _norm_64_hex_public_mgt_key(val) -> str | None:
    """Return lowercase 64-hex Ed25519 public key, or None if missing / non-hex (e.g. ssh-ed25519 line)."""
    if val is None:
        return None
    s = str(val).strip().strip('"').strip("'")
    if not s:
        return None
    if s.startswith(("0x", "0X")):
        s = s[2:]
    s = re.sub(r"\s+", "", s)
    if len(s) == 128 and re.fullmatch(r"[0-9a-fA-F]{128}", s):
        return None
    if re.fullmatch(r"[0-9a-fA-F]{64}", s):
        return s.lower()
    return None


def _seed_and_pubkey_hex(priv, serialization_mod, ed25519_mod) -> tuple[bytes, str]:
    seed = priv.private_bytes(
        encoding=serialization_mod.Encoding.Raw,
        format=serialization_mod.PrivateFormat.Raw,
        encryption_algorithm=serialization_mod.NoEncryption(),
    )
    raw_pub = priv.public_key().public_bytes(
        encoding=serialization_mod.Encoding.Raw,
        format=serialization_mod.PublicFormat.Raw,
    )
    return seed, raw_pub.hex()


def _priv_from_keyfile(keyfile: Path, ed25519_mod):
    hexs = keyfile.read_text(encoding="utf-8").strip().lower().removeprefix("0x")
    try:
        seed = bytes.fromhex(hexs)
    except ValueError as e:
        raise ValueError(f"invalid hex in {keyfile}") from e
    if len(seed) == 32:
        return ed25519_mod.Ed25519PrivateKey.from_private_bytes(seed)
    if len(seed) == 64:
        return ed25519_mod.Ed25519PrivateKey.from_private_bytes(seed[:32])
    raise ValueError(f"{keyfile}: expected 32 or 64 bytes hex")


def _sync_deterministic_config(
    data: dict,
    cfg_path: Path,
    keyfile: Path,
    yaml: YAML,
    serialization_mod,
    ed25519_mod,
    existing_hex: str,
) -> int:
    try:
        priv = _priv_from_keyfile(keyfile, ed25519_mod)
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 2
    file_pub = priv.public_key().public_bytes(
        encoding=serialization_mod.Encoding.Raw,
        format=serialization_mod.PublicFormat.Raw,
    ).hex()
    if file_pub != existing_hex:
        print(
            f"bootstrap_key_provision: {keyfile} public key {file_pub!r} does not match "
            f"configs.yaml PublicMgtKey {existing_hex!r}.",
            file=sys.stderr,
        )
        return 4
    changed = False
    if data.get("DeterministicNodeKey") is not True:
        data["DeterministicNodeKey"] = True
        changed = True
    if changed:
        with cfg_path.open("w") as f:
            yaml.dump(data, f)
        print(f"Set DeterministicNodeKey: true in {cfg_path} (bootstrap seed matches PublicMgtKey).")
    else:
        print(f"Deterministic bootstrap OK ({keyfile} matches PublicMgtKey, DeterministicNodeKey already true).")
    return 0


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

    raw_pub = data.get("PublicMgtKey")
    raw_s = "" if raw_pub is None else str(raw_pub).strip().strip('"').strip("'")
    existing_hex = _norm_64_hex_public_mgt_key(raw_pub)

    if raw_s and existing_hex is None:
        print(
            "bootstrap_key_provision: PublicMgtKey is not 64 hex; "
            "convert OpenSSH to hex first (tools/openssh_ed25519_to_hex.py). Skipping deterministic sync.",
            file=sys.stderr,
        )
        return 0

    bootstrap_dir = cfg_path.parent / args.bootstrap_subdir
    keyfile = bootstrap_dir / "ed25519_private.hex"

    # --- PublicMgtKey preset: align DeterministicNodeKey when bootstrap seed is on disk (reinstall / --public-mgt-key path).
    if existing_hex:
        if not keyfile.is_file():
            print(
                "bootstrap_key_provision: PublicMgtKey is set but "
                f"{keyfile} is missing — mpc-auth needs this file for deterministic nodeKey / DB backups. "
                "Install the seed (0600), then re-run process_config.sh or this tool.",
                file=sys.stderr,
            )
            return 0
        serialization_mod, ed25519_mod = _load_crypto()
        return _sync_deterministic_config(data, cfg_path, keyfile, yaml, serialization_mod, ed25519_mod, existing_hex)

    # --- PublicMgtKey empty: generate or load bootstrap, set PublicMgtKey + DeterministicNodeKey
    serialization_mod, ed25519_mod = _load_crypto()
    bootstrap_dir.mkdir(mode=0o700, exist_ok=True)

    if keyfile.is_file():
        try:
            priv = _priv_from_keyfile(keyfile, ed25519_mod)
        except ValueError as e:
            print(str(e), file=sys.stderr)
            return 2
        pub_hex = priv.public_key().public_bytes(
            encoding=serialization_mod.Encoding.Raw,
            format=serialization_mod.PublicFormat.Raw,
        ).hex()
    else:
        priv = ed25519_mod.Ed25519PrivateKey.generate()
        seed, pub_hex = _seed_and_pubkey_hex(priv, serialization_mod, ed25519_mod)
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
