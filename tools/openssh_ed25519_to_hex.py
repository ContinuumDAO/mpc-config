#!/usr/bin/env python3
"""
Convert an OpenSSH ssh-ed25519 public key line (e.g. from *.pub) to 64 lowercase hex
for mpc-auth PublicMgtKey / KeyGen Ed25519 client public key.

  python3 tools/openssh_ed25519_to_hex.py ~/.ssh/id_ed25519.pub
  echo 'ssh-ed25519 AAAA... comment' | python3 tools/openssh_ed25519_to_hex.py
"""

from __future__ import annotations

import argparse
import base64
import struct
import sys


def openssh_ed25519_line_to_hex(line: str) -> str:
    line = line.strip()
    if not line or line.startswith("#"):
        raise ValueError("empty or comment line")
    parts = line.split()
    if len(parts) < 2:
        raise ValueError("expected: ssh-ed25519 <base64> [comment ...]")
    if parts[0] != "ssh-ed25519":
        raise ValueError(f"only ssh-ed25519 is supported, got {parts[0]!r}")

    blob = base64.standard_b64decode(parts[1])

    def read_ssh_string(data: bytes, off: int):
        (ln,) = struct.unpack_from(">I", data, off)
        off += 4
        if off + ln > len(data):
            raise ValueError("truncated SSH public key blob")
        return data[off : off + ln], off + ln

    off = 0
    key_type, off = read_ssh_string(blob, off)
    if key_type != b"ssh-ed25519":
        raise ValueError("inner key type is not ssh-ed25519")
    pubkey, off = read_ssh_string(blob, off)
    if len(pubkey) != 32:
        raise ValueError(f"expected 32-byte Ed25519 public key, got {len(pubkey)} bytes")
    return pubkey.hex()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="OpenSSH ssh-ed25519 public key -> 64 hex (raw public key bytes)."
    )
    parser.add_argument(
        "path",
        nargs="?",
        help="Path to .pub file; if omitted, read one line from stdin",
    )
    args = parser.parse_args()

    if args.path:
        with open(args.path, encoding="utf-8") as f:
            text = f.read()
    else:
        text = sys.stdin.read()

    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    if not lines:
        print("error: no key line found", file=sys.stderr)
        sys.exit(1)

    try:
        for ln in lines:
            print(openssh_ed25519_line_to_hex(ln))
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
