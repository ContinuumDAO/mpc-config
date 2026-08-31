#!/usr/bin/env python3
"""
Convert an Ed25519 private key file to 64 lowercase hex (32-byte seed).

Same value as bootstrap_key/ed25519_private.hex written by bootstrap_key_provision.py.

Supports common formats:
  - OpenSSH (ssh-keygen): -----BEGIN OPENSSH PRIVATE KEY-----
  - PEM PKCS#8: openssl genpkey -algorithm ED25519
  - Raw hex seed (UTF-8 text): 64 hex chars (32-byte seed), or 128 hex chars
    (64-byte expanded secret; first 32 bytes used as seed).

Requires: cryptography (see tools/requirements-ed25519-tools.txt).

  python3 tools/ed25519_private_to_hex.py ~/.ssh/mpc_auth_ed25519
  python3 tools/ed25519_private_to_hex.py key.pem --prompt

To derive the matching public key hex (PublicMgtKey), use tools/ed25519_private_to_pubkey_hex.py.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        load_pem_private_key,
        load_ssh_private_key,
    )
except ImportError:
    print(
        "error: install cryptography: pip install -r tools/requirements-ed25519-tools.txt",
        file=sys.stderr,
    )
    sys.exit(1)


def _try_ed25519_private_from_seed_hex(data: bytes) -> Ed25519PrivateKey | None:
    """Parse bootstrap-style hex: 32-byte seed (64 hex) or 64-byte expanded (128 hex), optional 0x."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    hexs = text.strip().lower().removeprefix("0x")
    hexs = "".join(hexs.split())
    if len(hexs) % 2 != 0:
        return None
    if not hexs or any(c not in "0123456789abcdef" for c in hexs):
        return None
    try:
        seed = bytes.fromhex(hexs)
    except ValueError:
        return None
    if len(seed) == 32:
        return Ed25519PrivateKey.from_private_bytes(seed)
    if len(seed) == 64:
        return Ed25519PrivateKey.from_private_bytes(seed[:32])
    return None


def load_ed25519_private_key(data: bytes, password: bytes | None) -> Ed25519PrivateKey:
    last: Exception | None = None
    for loader in (load_ssh_private_key, load_pem_private_key):
        try:
            key = loader(data, password=password)
        except ValueError as e:
            last = e
            continue
        if isinstance(key, Ed25519PrivateKey):
            return key
        raise ValueError(f"not an Ed25519 private key (got {type(key).__name__})")

    key_hex = _try_ed25519_private_from_seed_hex(data)
    if key_hex is not None:
        return key_hex

    msg = "could not deserialize private key (wrong format or passphrase?)"
    if last is not None:
        raise ValueError(msg) from last
    raise ValueError(msg)


def ed25519_private_to_hex(data: bytes, password: bytes | None) -> str:
    key = load_ed25519_private_key(data, password=password)
    raw = key.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption(),
    )
    if len(raw) != 32:
        raise ValueError(f"expected 32-byte private seed, got {len(raw)}")
    return raw.hex()


def _looks_encrypted(data: bytes) -> bool:
    text = data.decode("utf-8", errors="ignore")
    return "ENCRYPTED" in text.upper()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Ed25519 private key file -> 64 hex private seed (bootstrap_key/ed25519_private.hex)."
    )
    parser.add_argument(
        "path",
        help="Path to private key (OpenSSH, PEM, or raw Ed25519 seed hex file)",
    )
    parser.add_argument(
        "--passphrase",
        metavar="STR",
        help="Passphrase for encrypted keys (avoid on shared shells; prefer --prompt)",
    )
    parser.add_argument(
        "--prompt",
        action="store_true",
        help="Prompt for passphrase on TTY (if key is encrypted)",
    )
    args = parser.parse_args()

    path = Path(args.path)
    if not path.is_file():
        print(f"error: not a file: {path}", file=sys.stderr)
        sys.exit(1)

    password: bytes | None = None
    if args.passphrase is not None:
        password = args.passphrase.encode("utf-8")
    elif args.prompt:
        password = getpass.getpass("Passphrase (empty if none): ").encode("utf-8")
        if password == b"":
            password = None

    data = path.read_bytes()
    try:
        print(ed25519_private_to_hex(data, password=password))
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        if password is None and _looks_encrypted(data):
            print(
                "hint: key may be encrypted; use --prompt or --passphrase",
                file=sys.stderr,
            )
        sys.exit(1)


if __name__ == "__main__":
    main()
