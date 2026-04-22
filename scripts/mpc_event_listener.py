#!/usr/bin/env python3
"""
Periodic **event listener** (single-shot per invocation; schedule with cron or a timer).

Composes optional handlers. Current handlers:

- **keygen_messages** — same behavior as ``keygen_messaging_agent_poll.py`` (``@agent``
  unread poll + ``multiMarkMessagesRead``).
- **sign_ready** — ``GET /listSignRequestsReady``, then for each id (sequential) run
  ``executeSignResult.py`` (``POST /triggerSignRequestById`` when needed, poll, broadcast).
  Optional ``--fast`` is passed through to ``executeSignResult``.

Interactive mode (``--interactive``) prompts which handlers to enable and, for sign_ready,
whether to use ``executeSignResult --fast``. Non-interactive use: pass ``--keygen-messages``
and/or ``--sign-ready``.

Environment matches ``docs/skill/SKILL.md``: ``MPC_AUTH_URL``, ``MANAGEMENT_PORT``,
``AUTH_KEY_PATH`` (or ``MPC_MGT_ED25519_SEED_HEX``), ``KEYGEN_ID`` (required for keygen
handler only). Same Python deps as ``keygen_messaging_agent_poll.py`` plus the
``$MPA_PATH/.venv`` (``eth_account`` / ``executeSignResult`` deps) when sign_ready runs execute.

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

from mpc_evm_signing_hash import (
    assert_sign_request_fields_match_message_hash,
    merge_body_for_sign_into_sign_request,
)
from mpc_sign_request_digest import is_digest_only_trigger_sign_request

from mpc_mgt_helpers import (
    api_code,
    api_data,
    api_error,
    compact_json,
    get_ed25519_nonce,
    http_json,
    http_json_any_code,
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
        data = api_data(parsed)
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


def _get_sign_request_dict(base: str, request_id: str) -> dict[str, Any]:
    r = http_json_any_code(
        "GET",
        base,
        "/getSignRequestById",
        query={"id": request_id},
    )
    c = api_code(r)
    if c is not None and c != 0:
        raise RuntimeError(f"getSignRequestById failed (code={c}): {r!r}")
    data = api_data(r)
    if not isinstance(data, dict):
        raise RuntimeError(f"getSignRequestById: expected data object, got {data!r}")
    return data


def _pick_first_str(d: dict[str, Any], *keys: str) -> str | None:
    for k in keys:
        v = d.get(k)
        if v is not None and str(v).strip() != "":
            return str(v).strip()
    return None


def _body_like_tx_fields(sr: dict[str, Any]) -> dict[str, Any]:
    """Map getSignRequestById fields to compose-style keys used for txParams."""
    pairs: list[tuple[str, tuple[str, ...]]] = [
        ("txNonce", ("txNonce", "TxNonce")),
        ("txGasLimit", ("txGasLimit", "TxGasLimit")),
        ("txGasPrice", ("txGasPrice", "TxGasPrice")),
        ("txMaxFeePerGas", ("txMaxFeePerGas", "TxMaxFeePerGas")),
        ("txMaxPriorityFeePerGas", ("txMaxPriorityFeePerGas", "TxMaxPriorityFeePerGas")),
    ]
    out: dict[str, Any] = {}
    for canonical, variants in pairs:
        for v in variants:
            if v in sr and sr[v] is not None:
                out[canonical] = sr[v]
                break
    return out


def _tx_params_from_body_like(body: dict[str, Any]) -> dict[str, Any]:
    """Same mapping as ``generateMultiSignRequestFromCompose.trigger_tx_params_from_compose_body``."""
    raw_nonce = body.get("txNonce")
    if raw_nonce is None:
        raise ValueError("txNonce missing")
    nonce = int(raw_nonce) if not isinstance(raw_nonce, int) else raw_nonce
    gl = body.get("txGasLimit")
    gas_limit = str(gl).strip() if gl is not None else ""
    if body.get("txMaxFeePerGas") is not None or body.get("txMaxPriorityFeePerGas") is not None:
        return {
            "nonce": nonce,
            "gasLimit": gas_limit,
            "txType": "eip1559",
            "maxFeePerGas": str(body.get("txMaxFeePerGas") or ""),
            "maxPriorityFeePerGas": str(body.get("txMaxPriorityFeePerGas") or ""),
        }
    return {
        "nonce": nonce,
        "gasLimit": gas_limit,
        "txType": "legacy",
        "gasPrice": str(body.get("txGasPrice") or ""),
    }


def _validate_trigger_tx_params(tp: dict[str, Any]) -> None:
    if not str(tp.get("gasLimit") or "").strip():
        raise ValueError("txParams.gasLimit is empty")
    tt = tp.get("txType")
    if tt == "legacy":
        if not str(tp.get("gasPrice") or "").strip():
            raise ValueError("txParams.gasPrice is empty for legacy transaction")
    elif tt == "eip1559":
        if not str(tp.get("maxFeePerGas") or "").strip() or not str(
            tp.get("maxPriorityFeePerGas") or ""
        ).strip():
            raise ValueError("txParams maxFeePerGas / maxPriorityFeePerGas missing for EIP-1559")


def _normalize_message_hash_hex(mh: str) -> str:
    s = mh.strip()
    if s.startswith("0x") or s.startswith("0X"):
        s = s[2:]
    return s


def _is_evm_sign_request(sr: dict[str, Any]) -> bool:
    if not _pick_first_str(sr, "DestinationChainID", "destinationChainID", "destination_chain_id"):
        return False
    if _pick_first_str(sr, "MessageHash", "msgHash"):
        return True
    mhs = sr.get("MessageHashes") or sr.get("messageHashes")
    return isinstance(mhs, list) and len(mhs) > 0


def _evm_trigger_tx_params_and_message_hash(
    sr: dict[str, Any],
) -> tuple[dict[str, Any] | None, list[dict[str, Any]] | None, str]:
    """
    Build trigger ``txParams`` (single-tx) or ``txParamsBatch`` (multi-tx) plus ``messageHash``.

    Prefer a full ``proposalTxParams`` / ``proposal_tx_params`` list from GET (or merged
    ``body_for_sign``) when ``MessageHashes`` length matches; otherwise fall back to
    the legacy ``txNonce`` / ``txGasLimit`` / fee fields on the sign-request object.
    """
    mh = _pick_first_str(sr, "MessageHash", "msgHash")
    mhs = sr.get("MessageHashes") or sr.get("messageHashes")
    if not mh:
        if isinstance(mhs, list) and mhs:
            mh = str(mhs[0]).strip()
    if not mh:
        raise RuntimeError("MessageHash / MessageHashes missing on sign request")

    pp = sr.get("proposalTxParams") or sr.get("proposal_tx_params")
    if (
        isinstance(mhs, list)
        and len(mhs) >= 2
        and isinstance(pp, list)
        and len(pp) == len(mhs)
        and all(isinstance(x, dict) for x in pp)
    ):
        batch = [dict(x) for x in pp]
        for tp in batch:
            _validate_trigger_tx_params(tp)
        return None, batch, _normalize_message_hash_hex(mh)

    body_like = _body_like_tx_fields(sr)
    if "txNonce" not in body_like or "txGasLimit" not in body_like:
        raise RuntimeError(
            "Sign request has DestinationChainID but missing per-index proposal_tx_params on GET "
            "(or merged bodyForSign) and missing txNonce or txGasLimit; pass body_for_sign from "
            "executeSignResult.py --sign-request-file (saved compose / recipe JSON with bodyForSign)."
        )
    tp = _tx_params_from_body_like(body_like)
    _validate_trigger_tx_params(tp)
    return tp, None, _normalize_message_hash_hex(mh)


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
        if api_code(r) == 0:
            data = api_data(r)
            if sign_result_has_signatures(data):
                return data if isinstance(data, dict) else {}
        time.sleep(interval_sec)
    err = api_error(last) if last else ""
    raise RuntimeError(
        f"Timed out waiting for signatures for {request_id!r} ({timeout_sec}s). Last error: {err!r}"
    )


def post_trigger_sign_request(
    base: str,
    priv,
    request_id: str,
    *,
    body_for_sign: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    POST /triggerSignRequestById with management signature.

    For **EVM unsigned transactions** (RLP + calldata), ``txParams`` or ``txParamsBatch``
    and ``messageHash`` are derived from ``GET /getSignRequestById`` (and/or merged
    ``bodyForSign``) so Execute can rebuild the same tx. When the GET payload omits
    nonce/gas fields, pass the same ``bodyForSign`` via ``body_for_sign``.

    For **EIP-712 / digest-only** sign requests (e.g. Uniswap Permit2 ``PermitSingle``),
    ``MessageRaw`` is not calldata. Do not attach ``txParams`` or ``messageHash``; see
    ``is_digest_only_trigger_sign_request`` in ``mpc_sign_request_digest.py`` and
    WorkFlows.TriggerSignRequestById in mpc-auth.
    """
    pub = public_key_64_hex(priv)
    nonce = get_ed25519_nonce(base, pub)
    body: dict[str, Any] = {
        "requestId": request_id,
        "nonce": nonce,
        "sig": "",
    }
    sr = _get_sign_request_dict(base, request_id)
    sr = merge_body_for_sign_into_sign_request(sr, body_for_sign)
    if is_digest_only_trigger_sign_request(sr):
        # mpc-auth: worker signs stored MessageHash; MessageRaw is not contract data.
        body["sig"] = sign_compact_json_empty_field(priv, body, "sig")
        return http_json("POST", base, "/triggerSignRequestById", body=body)
    if _is_evm_sign_request(sr):
        assert_sign_request_fields_match_message_hash(sr)
        tx_params, tx_params_batch, msg_hash = _evm_trigger_tx_params_and_message_hash(sr)
        if tx_params_batch is not None:
            body["txParamsBatch"] = tx_params_batch
        elif tx_params is not None:
            body["txParams"] = tx_params
        body["messageHash"] = msg_hash
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
    execute_fast: bool,
    rpc_url: str | None,
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

    for rid in ready_ids:
        step: dict[str, Any] = {"requestId": rid}
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
    sign_ready = _prompt_yes_no("Enable sign-ready pipeline (list → executeSignResult per id)?", default=False)
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
        help="Process GET /listSignRequestsReady: executeSignResult.py per ready id",
    )
    ap.add_argument(
        "--execute-fast",
        action="store_true",
        help="Pass --fast to executeSignResult (only with --sign-ready)",
    )
    ap.add_argument(
        "--sign-ready-dry-run",
        action="store_true",
        help="Only list ready sign request ids; no executeSignResult",
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
            execute_fast=execute_fast,
            rpc_url=args.rpc_url,
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
