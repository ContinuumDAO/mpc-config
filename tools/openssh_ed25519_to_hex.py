#!/usr/bin/env python3
"""
Convert OpenSSH ssh-ed25519 material to 64 lowercase hex for mpc-auth PublicMgtKey.

Accepts:
  - Full .pub line:  ssh-ed25519 <base64> [optional comment]
  - Base64 only:    the middle field from that line (no type prefix, no comment)
  - Optional one or more matching outer " or ' wrappers (e.g. pasted quoted scalar)

  python3 tools/openssh_ed25519_to_hex.py ~/.ssh/id_ed25519.pub
  echo 'ssh-ed25519 AAAA... comment' | python3 tools/openssh_ed25519_to_hex.py
  echo 'AAAAC3NzaC1lZDI1NTE5AAAAI...' | python3 tools/openssh_ed25519_to_hex.py

From a private key file instead, use tools/ed25519_private_to_pubkey_hex.py (public key)
or tools/ed25519_private_to_seed_hex.py (32-byte private seed hex; needs cryptography).
"""

from __future__ import annotations

import argparse
import base64
import binascii
import struct
import sys


def _read_ssh_string(data: bytes, off: int):
    (ln,) = struct.unpack_from(">I", data, off)
    off += 4
    if off + ln > len(data):
        raise ValueError("truncated SSH public key blob")
    return data[off : off + ln], off + ln


def _strip_outer_quotes(s: str) -> str:
    s = s.strip()
    while len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        s = s[1:-1].strip()
    return s


def _wire_blob_to_pubkey_hex(blob: bytes) -> str:
    off = 0
    key_type, off = _read_ssh_string(blob, off)
    if key_type != b"ssh-ed25519":
        raise ValueError("inner key type is not ssh-ed25519")
    pubkey, off = _read_ssh_string(blob, off)
    if len(pubkey) != 32:
        raise ValueError(f"expected 32-byte Ed25519 public key, got {len(pubkey)} bytes")
    return pubkey.hex()


def openssh_ed25519_input_to_hex(line: str) -> str:
    """Parse one line: full ssh-ed25519 line, or raw OpenSSH base64 blob for ed25519 public key."""
    line = _strip_outer_quotes(line)
    if not line or line.startswith("#"):
        raise ValueError("empty or comment line")
    parts = line.split()
    blob: bytes
    if parts[0] == "ssh-ed25519":
        if len(parts) < 2:
            raise ValueError("expected: ssh-ed25519 <base64> [comment ...]")
        try:
            blob = base64.standard_b64decode(parts[1])
        except binascii.Error as e:
            raise ValueError("invalid base64 in ssh-ed25519 line") from e
    else:
        # OpenSSH .pub middle field only (first whitespace-separated token = base64).
        b64 = parts[0]
        try:
            blob = base64.standard_b64decode(b64)
        except binascii.Error as e:
            raise ValueError(
                "expected ssh-ed25519 <base64> [comment] or the base64 key blob alone"
            ) from e
    return _wire_blob_to_pubkey_hex(blob)


def openssh_ed25519_line_to_hex(line: str) -> str:
    """Backward-compatible name."""
    return openssh_ed25519_input_to_hex(line)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="OpenSSH ssh-ed25519 public key (full line or base64 blob) -> 64 hex."
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
            print(openssh_ed25519_input_to_hex(ln))
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
