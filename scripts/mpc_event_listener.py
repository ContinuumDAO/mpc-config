#!/usr/bin/env python3
"""
Periodic **event listener** (single-shot per invocation; schedule with cron or a timer).

Composes optional handlers. Current handlers:

- **keygen_messages** — same behavior as ``keygen_messaging_agent_poll.py`` (``@agent``
  unread poll + ``multiMarkMessagesRead``).
- **sign_ready** — ``GET /listSignRequestsReady``, then for each id (sequential):
  ``POST /triggerSignRequestById`` (Ed25519 management key), poll ``GET /getSignResultById``
  until signatures exist, then run ``executeSignResult.py`` (optional ``--fast``).

Interactive mode (``--interactive``) prompts which handlers to enable and, for sign_ready,
whether to use ``executeSignResult --fast``. Non-interactive use: pass ``--keygen-messages``
and/or ``--sign-ready``.

Environment matches ``docs/skill/SKILL.md``: ``MPC_AUTH_URL``, ``MANAGEMENT_PORT``,
``AUTH_KEY_PATH`` (or ``MPC_MGT_ED25519_SEED_HEX``), ``KEYGEN_ID`` (required for keygen
handler only). Same Python deps as ``keygen_messaging_agent_poll.py`` plus the
``eth-account`` venv for ``executeSignResult`` when sign_ready runs execute.

Additional handlers can be registered in ``HANDLERS`` below.

**Schedule:** pick the cron period from ``mpc_cron_schedules.py`` (fixed choices: minutes 1,5,10,30,60; hours 2,4,6,8,10,12,24) for Open Claw ``--every`` or crontab.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable

_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from mpc_mgt_helpers import (
    compact_json,
    get_ed25519_nonce,
    http_json,
    http_json_any_code,
    load_ed25519_private_key,
    public_key_64_hex,
    resolve_mpc_auth_base,
    sign_compact_json_empty_field,
)

from keygen_messaging_agent_poll import run_poll

HandlerFn = Callable[..., dict[str, Any]]

HANDLERS: dict[str, HandlerFn] = {}


def _register(name: str):
    def deco(fn: HandlerFn) -> HandlerFn:
        HANDLERS[name] = fn
        return fn

    return deco


def _pick_request_id(item: dict[str, Any]) -> str | None:
    rid = item.get("requestid") or item.get("RequestId") or item.get("requestId")
    if rid is None:
        return None
    s = str(rid).strip()
    return s or None


def list_sign_requests_ready_ids(base: str, pagesize: int) -> list[str]:
    """Paginate ``GET /listSignRequestsReady`` and collect ``requestid`` values (order preserved)."""
    ids: list[str] = []
    seen: set[str] = set()
    pagenum = 0
    max_pages = 1000
    while pagenum < max_pages:
        parsed = http_json(
            "GET",
            base,
            "/listSignRequestsReady",
            query={"pagenum": str(pagenum), "pagesize": str(pagesize)},
        )
        data = parsed.get("data")
        if not isinstance(data, list) or not data:
            break
        for item in data:
            if not isinstance(item, dict):
                continue
            rid = _pick_request_id(item)
            if rid and rid not in seen:
                seen.add(rid)
                ids.append(rid)
        if len(data) < pagesize:
            break
        pagenum += 1
    return ids


def sign_result_has_signatures(data: Any) -> bool:
    if not isinstance(data, dict):
        return False
    if data.get("batchSignResult") is True:
        bs = data.get("batchSignatures")
        if not isinstance(bs, list) or len(bs) == 0:
            return False
        for x in bs:
            if not isinstance(x, dict):
                return False
            if not (x.get("signaturehex") or x.get("sigr")):
                return False
        return True
    return bool(data.get("signaturehex") or data.get("sigr"))


def poll_sign_result_ready(
    base: str,
    request_id: str,
    *,
    timeout_sec: float,
    interval_sec: float,
) -> dict[str, Any]:
    deadline = time.time() + timeout_sec
    last: dict[str, Any] | None = None
    while time.time() < deadline:
        r = http_json_any_code(
            "GET",
            base,
            "/getSignResultById",
            query={"id": request_id},
        )
        last = r
        if r.get("code") == 0:
            data = r.get("data")
            if sign_result_has_signatures(data):
                return data if isinstance(data, dict) else {}
        time.sleep(interval_sec)
    err = (last or {}).get("error", "") if last else ""
    raise RuntimeError(
        f"Timed out waiting for signatures for {request_id!r} ({timeout_sec}s). Last error: {err!r}"
    )


def post_trigger_sign_request(base: str, priv, request_id: str) -> dict[str, Any]:
    pub = public_key_64_hex(priv)
    nonce = get_ed25519_nonce(base, pub)
    body: dict[str, Any] = {
        "requestId": request_id,
        "nonce": nonce,
        "sig": "",
    }
    body["sig"] = sign_compact_json_empty_field(priv, body, "sig")
    return http_json("POST", base, "/triggerSignRequestById", body=body)


def run_execute_sign_result(
    *,
    mpc_auth_url: str,
    management_port: str,
    request_id: str,
    rpc_url: str | None,
    execute_fast: bool,
) -> subprocess.CompletedProcess:
    cmd: list[str] = [
        sys.executable,
        str(_SCRIPTS_DIR / "executeSignResult.py"),
        "--sign-request-id",
        request_id,
        "--mpc-auth-url",
        mpc_auth_url,
        "--management-port",
        management_port,
    ]
    if rpc_url:
        cmd.extend(["--rpc-url", rpc_url])
    if execute_fast:
        cmd.append("--fast")
    return subprocess.run(
        cmd,
        check=False,
        capture_output=True,
        text=True,
        timeout=3600,
    )


@_register("keygen_messages")
def handle_keygen_messages(
    *,
    base: str,
    dry_run: bool,
) -> dict[str, Any]:
    key_gen_id = os.environ.get("KEYGEN_ID", "").strip()
    if not key_gen_id:
        raise RuntimeError("KEYGEN_ID is required for keygen_messages handler")

    try:
        pagesize = int(os.environ.get("MPC_KEYGEN_POLL_PAGESIZE", "50"))
    except ValueError as e:
        raise RuntimeError("MPC_KEYGEN_POLL_PAGESIZE must be an integer") from e
    pagesize = max(1, min(100, pagesize))

    trigger_token = os.environ.get("MPC_KEYGEN_AGENT_TRIGGER", "agent").strip() or "agent"

    return run_poll(
        base=base,
        key_gen_id=key_gen_id,
        pagesize=pagesize,
        trigger_token=trigger_token,
        dry_run=dry_run,
    )


@_register("sign_ready")
def handle_sign_ready(
    *,
    base: str,
    mpc_auth_url: str,
    management_port: str,
    pagesize: int,
    dry_run_list_only: bool,
    no_execute: bool,
    execute_fast: bool,
    rpc_url: str | None,
    poll_timeout_sec: float,
    poll_interval_sec: float,
) -> dict[str, Any]:
    ready_ids = list_sign_requests_ready_ids(base, pagesize)
    out: dict[str, Any] = {
        "ready_ids": ready_ids,
        "count": len(ready_ids),
        "dry_run": dry_run_list_only,
        "steps": [],
    }

    if dry_run_list_only or not ready_ids:
        return out

    priv = load_ed25519_private_key()

    for rid in ready_ids:
        step: dict[str, Any] = {"requestId": rid}
        try:
            tr = post_trigger_sign_request(base, priv, rid)
            step["trigger"] = tr.get("data")
        except Exception as e:
            step["error"] = f"trigger: {e}"
            out["steps"].append(step)
            continue

        try:
            poll_sign_result_ready(
                base,
                rid,
                timeout_sec=poll_timeout_sec,
                interval_sec=poll_interval_sec,
            )
            step["signatures_ready"] = True
        except Exception as e:
            step["error"] = f"poll: {e}"
            out["steps"].append(step)
            continue

        if no_execute:
            step["execute"] = "skipped (--no-execute)"
            out["steps"].append(step)
            continue

        proc = run_execute_sign_result(
            mpc_auth_url=mpc_auth_url,
            management_port=management_port,
            request_id=rid,
            rpc_url=rpc_url,
            execute_fast=execute_fast,
        )
        step["execute"] = {
            "returncode": proc.returncode,
            "stdout": proc.stdout[-8000:] if proc.stdout else "",
            "stderr": proc.stderr[-8000:] if proc.stderr else "",
        }
        if proc.returncode != 0:
            step["error"] = "executeSignResult exited non-zero"
        out["steps"].append(step)

    return out


def _prompt_yes_no(prompt: str, default: bool) -> bool:
    hint = "Y/n" if default else "y/N"
    raw = input(f"{prompt} [{hint}]: ").strip().lower()
    if not raw:
        return default
    return raw in ("y", "yes")


def run_interactive() -> tuple[bool, bool, bool]:
    """Returns (keygen_messages, sign_ready, execute_fast_for_sign_ready)."""
    print("MPC event listener — enable handlers (this run only):", file=sys.stderr)
    keygen = _prompt_yes_no("Enable KeyGen @agent message poll (keygen_messages)?", default=False)
    sign_ready = _prompt_yes_no("Enable sign-ready pipeline (list → trigger → execute)?", default=False)
    execute_fast = False
    if sign_ready:
        execute_fast = _prompt_yes_no(
            "Use executeSignResult --fast (parallel receipt wait for batch txs)?",
            default=False,
        )
    return keygen, sign_ready, execute_fast


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--interactive",
        "-i",
        action="store_true",
        help="Prompt for which handlers to enable (TTY required)",
    )
    ap.add_argument(
        "--keygen-messages",
        action="store_true",
        help="Run KeyGen @agent poll (same as keygen_messaging_agent_poll.py)",
    )
    ap.add_argument(
        "--sign-ready",
        action="store_true",
        help="Process GET /listSignRequestsReady: trigger, poll signatures, executeSignResult",
    )
    ap.add_argument(
        "--execute-fast",
        action="store_true",
        help="Pass --fast to executeSignResult (only with --sign-ready)",
    )
    ap.add_argument(
        "--no-execute",
        action="store_true",
        help="With --sign-ready: trigger and wait for MPC signatures but do not broadcast",
    )
    ap.add_argument(
        "--sign-ready-dry-run",
        action="store_true",
        help="Only list ready sign request ids; no trigger or execute",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Only keygen_messages: same as keygen_messaging_agent_poll --dry-run (does not affect sign_ready)",
    )
    ap.add_argument(
        "--pagesize",
        type=int,
        default=int(os.environ.get("MPC_EVENT_LISTENER_PAGESIZE", "50")),
        help="Page size for listSignRequestsReady (default: 50 or MPC_EVENT_LISTENER_PAGESIZE)",
    )
    ap.add_argument(
        "--poll-timeout",
        type=float,
        default=float(os.environ.get("MPC_SIGN_POLL_TIMEOUT_SEC", "600")),
        help="Seconds to wait for getSignResultById after trigger (default 600)",
    )
    ap.add_argument(
        "--poll-interval",
        type=float,
        default=float(os.environ.get("MPC_SIGN_POLL_INTERVAL_SEC", "5")),
        help="Seconds between getSignResultById polls (default 5)",
    )
    ap.add_argument(
        "--rpc-url",
        default=os.environ.get("MPC_EXECUTE_RPC_URL") or None,
        help="Forwarded to executeSignResult (optional; else chain RPC from getChainDetails)",
    )
    args = ap.parse_args()

    mpc_auth_url = os.environ.get("MPC_AUTH_URL") or "http://127.0.0.1"
    management_port = os.environ.get("MANAGEMENT_PORT") or "8080"
    base = resolve_mpc_auth_base(mpc_auth_url, management_port)

    keygen_on = bool(args.keygen_messages)
    sign_on = bool(args.sign_ready)
    execute_fast = bool(args.execute_fast)

    if args.interactive:
        if not sys.stdin.isatty():
            raise SystemExit("--interactive requires a TTY")
        kg, sr, ef = run_interactive()
        keygen_on = kg
        sign_on = sr
        execute_fast = ef

    if not keygen_on and not sign_on:
        raise SystemExit(
            "No handlers enabled. Use --interactive, or --keygen-messages, and/or --sign-ready "
            "(see --help)."
        )

    if args.execute_fast and not sign_on:
        raise SystemExit("--execute-fast only applies with --sign-ready")
    if args.no_execute and not sign_on:
        raise SystemExit("--no-execute only applies with --sign-ready")
    if args.sign_ready_dry_run and not sign_on:
        raise SystemExit("--sign-ready-dry-run only applies with --sign-ready")

    result: dict[str, Any] = {"handlers": {}}

    if keygen_on:
        result["handlers"]["keygen_messages"] = handle_keygen_messages(
            base=base,
            dry_run=bool(args.dry_run),
        )

    if sign_on:
        result["handlers"]["sign_ready"] = handle_sign_ready(
            base=base,
            mpc_auth_url=mpc_auth_url,
            management_port=str(management_port),
            pagesize=max(1, min(500, args.pagesize)),
            dry_run_list_only=bool(args.sign_ready_dry_run),
            no_execute=bool(args.no_execute),
            execute_fast=execute_fast,
            rpc_url=args.rpc_url,
            poll_timeout_sec=float(args.poll_timeout),
            poll_interval_sec=float(args.poll_interval),
        )

    sys.stdout.write(compact_json(result) + "\n")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, SystemExit) as e:
        if isinstance(e, SystemExit):
            raise
        print(str(e), file=sys.stderr)
        raise SystemExit(1) from e
