#!/usr/bin/env python3
"""
Poll KeyGen messaging for unread items that mention the agent, then mark them read.

Designed for an **Open Claw** (or similar) **isolated cron** job: the cron ``--message``
instructs the agent to run this script (``exec``), parse the JSON on stdout, and if
``matches`` is non-empty, decide what to do and reply with ``POST /sendMessage``
(management-signed; see docs/references/API_KEYGEN_MESSAGING.md).

Flow
----
1. ``GET /listMessages`` with ``unread=true`` (paginated).
2. Keep messages whose ``title`` or ``body`` match the trigger (default substring
   ``@agent``, case-insensitive, word boundary after ``agent``).
3. Print a JSON object with ``matches`` (full message objects from the API).
4. ``POST /multiMarkMessagesRead`` with Ed25519 management signature (one nonce).

Environment
-----------
Names align with ``docs/skill/SKILL.md`` (``KEYGEN_ID``, ``AUTH_KEY_PATH``) plus
script-specific variables below.

KEYGEN_ID                   KeyGen channel id (required).
AUTH_KEY_PATH               Ed25519 management private key file (default
                            ``~/.ssh/mpc_auth_ed25519``). PEM or OpenSSH; see AGENT_ED25519_SETUP.md.
MPC_AUTH_URL                Management API host URL (default ``http://127.0.0.1``).
MANAGEMENT_PORT             Management API port (default ``8080``).
MPC_MGT_ED25519_SEED_HEX    Optional 64-hex (32-byte) raw seed; overrides key file.
MPC_KEYGEN_AGENT_TRIGGER    Trigger substring without leading @ (default ``agent``);
                            the script looks for ``@`` + this token with a word boundary.
MPC_KEYGEN_POLL_PAGESIZE    Page size for listMessages (default 50, max 100).

Dependencies: pip install -r scripts/requirements-keygen-agent.txt
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError as e:  # pragma: no cover
    print(
        "Missing dependency: install with\n"
        "  pip install -r scripts/requirements-keygen-agent.txt",
        file=sys.stderr,
    )
    raise SystemExit(2) from e


def _compact_json(obj: Any) -> str:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def _resolve_mpc_auth_base(mpc_auth_url: str, management_port: str | int | None) -> str:
    base = (mpc_auth_url or "").strip()
    if not base:
        raise RuntimeError("MPC_AUTH_URL is required")
    p = urllib.parse.urlparse(base)
    if not p.scheme or not p.netloc:
        raise RuntimeError("MPC_AUTH_URL must include scheme and host, e.g. http://127.0.0.1")
    if p.port is not None:
        return base.rstrip("/")
    port = str(management_port or "").strip()
    if not port:
        raise RuntimeError("MANAGEMENT_PORT is required when MPC_AUTH_URL has no port")
    try:
        int(port, 10)
    except ValueError as e:
        raise RuntimeError("MANAGEMENT_PORT must be numeric") from e
    return urllib.parse.urlunparse(p._replace(netloc=f"{p.netloc}:{port}")).rstrip("/")


def _http_json(
    method: str,
    base: str,
    path: str,
    *,
    query: dict[str, str] | None = None,
    body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    url = base.rstrip("/") + path
    if query:
        q = urllib.parse.urlencode(query)
        url = f"{url}?{q}"
    data = None
    headers = {"Accept": "application/json"}
    if body is not None:
        raw = _compact_json(body).encode("utf-8")
        data = raw
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            payload = resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {e.code} {path}: {err_body}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"Request failed {path}: {e}") from e
    try:
        parsed = json.loads(payload)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Invalid JSON from {path}: {payload[:500]}") from e
    if parsed.get("code") != 0:
        raise RuntimeError(f"API error {path}: {parsed.get('error', '')!r} data={parsed.get('data')}")
    return parsed


def _load_ed25519_private_key() -> Ed25519PrivateKey:
    seed_hex = os.environ.get("MPC_MGT_ED25519_SEED_HEX", "").strip()
    if seed_hex:
        if seed_hex.startswith("0x"):
            seed_hex = seed_hex[2:]
        raw = bytes.fromhex(seed_hex)
        if len(raw) != 32:
            raise SystemExit("MPC_MGT_ED25519_SEED_HEX must be 64 hex chars (32 bytes)")
        return Ed25519PrivateKey.from_private_bytes(raw)

    path_s = os.environ.get("AUTH_KEY_PATH", "").strip()
    key_path = (
        Path(path_s).expanduser()
        if path_s
        else Path.home() / ".ssh" / "mpc_auth_ed25519"
    )
    if not key_path.is_file():
        raise SystemExit(
            f"Ed25519 private key not found at {key_path}. "
            "Set AUTH_KEY_PATH or MPC_MGT_ED25519_SEED_HEX."
        )
    blob = key_path.read_bytes()
    key = None
    try:
        k = serialization.load_pem_private_key(blob, password=None)
        if isinstance(k, Ed25519PrivateKey):
            key = k
    except ValueError:
        pass
    if key is None:
        try:
            k = serialization.load_ssh_private_key(blob, password=None)
            if isinstance(k, Ed25519PrivateKey):
                key = k
        except ValueError:
            pass
    if key is None:
        raise SystemExit(f"Key file {key_path} is not an Ed25519 private key (PEM or OpenSSH)")
    return key


def _public_key_64_hex(priv: Ed25519PrivateKey) -> str:
    return priv.public_key().public_bytes_raw().hex()


def _sign_messaging_body(priv: Ed25519PrivateKey, body: dict[str, Any]) -> str:
    """Sign exact JSON of body with Sig set to \"\" (KeyGen messaging endpoints)."""
    sign_me = dict(body)
    sign_me["Sig"] = ""
    message = _compact_json(sign_me).encode("utf-8")
    sig = priv.sign(message)
    return sig.hex()


def _matches_trigger(title: str | None, body: str | None, pattern: re.Pattern[str]) -> bool:
    text = f"{title or ''}\n{body or ''}"
    return pattern.search(text) is not None


def _list_unread_page(
    base: str, key_gen_id: str, pagenum: int, pagesize: int
) -> tuple[list[dict[str, Any]], int]:
    parsed = _http_json(
        "GET",
        base,
        "/listMessages",
        query={
            "keyGenId": key_gen_id,
            "unread": "true",
            "pagenum": str(pagenum),
            "pagesize": str(pagesize),
        },
    )
    data = parsed.get("data") or {}
    lst = data.get("list") or []
    total = int(data.get("total") or 0)
    if not isinstance(lst, list):
        lst = []
    return lst, total


def run_poll(
    *,
    base: str,
    key_gen_id: str,
    pagesize: int,
    trigger_token: str,
    dry_run: bool,
) -> dict[str, Any]:
    # @token word boundary (so @agent does not match @agentic)
    pattern = re.compile(
        rf"@(?:{re.escape(trigger_token)})\b",
        re.IGNORECASE,
    )

    matches: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    pagenum = 1
    max_pages = 100

    while pagenum <= max_pages:
        page, total = _list_unread_page(base, key_gen_id, pagenum, pagesize)
        if not page:
            break
        for msg in page:
            mid = str(msg.get("id", ""))
            if not mid or mid in seen_ids:
                continue
            seen_ids.add(mid)
            if _matches_trigger(
                msg.get("title") if isinstance(msg.get("title"), str) else None,
                msg.get("body") if isinstance(msg.get("body"), str) else None,
                pattern,
            ):
                matches.append(msg)
        if len(seen_ids) >= total or len(page) < pagesize:
            break
        pagenum += 1

    result: dict[str, Any] = {
        "matches": matches,
        "match_count": len(matches),
        "marked_ids": [],
        "dry_run": dry_run,
    }

    if not matches or dry_run:
        return result

    priv = _load_ed25519_private_key()
    pub = _public_key_64_hex(priv)
    nonce_resp = _http_json(
        "GET",
        base,
        "/getPublicMgtKeyNonce",
        query={"publicKey": pub},
    )
    data = nonce_resp.get("data")
    if isinstance(data, dict) and "nonce" in data:
        nonce = data["nonce"]
    elif isinstance(data, int):
        nonce = data
    else:
        raise RuntimeError(f"Unexpected getPublicMgtKeyNonce payload: {nonce_resp!r}")
    if not isinstance(nonce, int):
        raise RuntimeError(f"Nonce is not an integer: {nonce!r}")

    ids = [str(m["id"]) for m in matches if m.get("id")]
    body = {
        "Nonce": nonce,
        "Sig": "",
        "keyGenId": key_gen_id,
        "messageIds": ids,
    }
    body["Sig"] = _sign_messaging_body(priv, body)

    _http_json("POST", base, "/multiMarkMessagesRead", body=body)
    result["marked_ids"] = ids
    return result


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="List matches but do not call multiMarkMessagesRead",
    )
    args = p.parse_args()

    base = _resolve_mpc_auth_base(
        os.environ.get("MPC_AUTH_URL") or "http://127.0.0.1",
        os.environ.get("MANAGEMENT_PORT") or "8080",
    )
    key_gen_id = os.environ.get("KEYGEN_ID", "").strip()
    if not key_gen_id:
        raise SystemExit("KEYGEN_ID is required")

    try:
        pagesize = int(os.environ.get("MPC_KEYGEN_POLL_PAGESIZE", "50"))
    except ValueError:
        raise SystemExit("MPC_KEYGEN_POLL_PAGESIZE must be an integer")
    pagesize = max(1, min(100, pagesize))

    trigger_token = os.environ.get("MPC_KEYGEN_AGENT_TRIGGER", "agent").strip() or "agent"

    out = run_poll(
        base=base,
        key_gen_id=key_gen_id,
        pagesize=pagesize,
        trigger_token=trigger_token,
        dry_run=args.dry_run,
    )
    sys.stdout.write(_compact_json(out) + "\n")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, SystemExit) as e:
        if isinstance(e, SystemExit):
            raise
        print(str(e), file=sys.stderr)
        raise SystemExit(1) from e
