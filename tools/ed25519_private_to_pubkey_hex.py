#!/usr/bin/env python3
"""
Derive the raw Ed25519 public key (64 lowercase hex) from a private key file.
Use the same value for mpc-auth PublicMgtKey as you would from *.pub via
openssh_ed25519_to_hex.py.

Supports common formats:
  - OpenSSH (ssh-keygen): -----BEGIN OPENSSH PRIVATE KEY-----
  - PEM PKCS#8: openssl genpkey -algorithm ED25519

Requires: pip install cryptography

  python3 tools/ed25519_private_to_pubkey_hex.py ~/.ssh/mpc_auth_ed25519
  python3 tools/ed25519_private_to_pubkey_hex.py key.pem --passphrase secret
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
        PublicFormat,
        load_pem_private_key,
        load_ssh_private_key,
    )
except ImportError:
    print("error: install cryptography: pip install cryptography", file=sys.stderr)
    sys.exit(1)


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
    msg = "could not deserialize private key (wrong format or passphrase?)"
    if last is not None:
        raise ValueError(msg) from last
    raise ValueError(msg)


def private_key_to_pubkey_hex(data: bytes, password: bytes | None) -> str:
    key = load_ed25519_private_key(data, password=password)
    raw = key.public_key().public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )
    if len(raw) != 32:
        raise ValueError(f"expected 32-byte public key, got {len(raw)}")
    return raw.hex()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Ed25519 private key file -> 64 hex public key (PublicMgtKey)."
    )
    parser.add_argument(
        "path",
        help="Path to private key (OpenSSH or PEM)",
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
        print(private_key_to_pubkey_hex(data, password=password))
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        if password is None and _looks_encrypted(data):
            print(
                "hint: key may be encrypted; use --prompt or --passphrase",
                file=sys.stderr,
            )
        sys.exit(1)


def _looks_encrypted(data: bytes) -> bool:
    text = data.decode("utf-8", errors="ignore")
    return "ENCRYPTED" in text.upper()


if __name__ == "__main__":
    main()
