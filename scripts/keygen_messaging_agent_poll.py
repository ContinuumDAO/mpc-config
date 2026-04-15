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

Dependencies: install into ``$MPA_PATH/.venv`` — e.g. ``$MPA_PATH/.venv/bin/pip install -r scripts/requirements-keygen-agent.txt`` (see ``docs/skill/SKILL.md`` **Python dependencies**).

See also: ``mpc_event_listener.py`` for optional composition with other periodic handlers.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any

from mpc_mgt_helpers import (
    api_data,
    compact_json,
    get_ed25519_nonce,
    http_json,
    load_ed25519_private_key,
    public_key_64_hex,
    resolve_mpc_auth_base,
    sign_compact_json_empty_field,
)


def _matches_trigger(title: str | None, body: str | None, pattern: re.Pattern[str]) -> bool:
    text = f"{title or ''}\n{body or ''}"
    return pattern.search(text) is not None


def _list_unread_page(
    base: str, key_gen_id: str, pagenum: int, pagesize: int
) -> tuple[list[dict[str, Any]], int]:
    parsed = http_json(
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
    data = api_data(parsed) or {}
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

    priv = load_ed25519_private_key()
    pub = public_key_64_hex(priv)
    nonce = get_ed25519_nonce(base, pub)

    ids = [str(m["id"]) for m in matches if m.get("id")]
    body = {
        "Nonce": nonce,
        "Sig": "",
        "keyGenId": key_gen_id,
        "messageIds": ids,
    }
    body["Sig"] = sign_compact_json_empty_field(priv, body, "Sig")

    http_json("POST", base, "/multiMarkMessagesRead", body=body)
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

    base = resolve_mpc_auth_base(
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
    sys.stdout.write(compact_json(out) + "\n")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, SystemExit) as e:
        if isinstance(e, SystemExit):
            raise
        print(str(e), file=sys.stderr)
        raise SystemExit(1) from e
