#!/usr/bin/env python3
"""
Build **POST /multiSignRequest** for a **Uniswap Trade API** ``POST /v1/swap`` response.

**Recommended (aligned with continuumdao-node-app):** use ``uniswap_trade_swap.py`` (Trade API
classic-allowance header ``x-permit2-disabled: true``), then build a **batch** of on-chain txs (ERC-20 approve + swap, or
approve + on-chain allowance-hub step + swap) via ``--batch-approve-and-swap``.

**Single-tx mode (default):** one **pre-encoded** compose action for the swap calldata only.
That path assumes ERC-20 allowance is already sufficient on-chain.

**Batch mode input:** create-swap JSON **and** a **quote snapshot** (``--quote-file`` / ``--quote-json``)
with classic ``quote.input.amount``, plus ``--token-in``. See ``uniswap_v4_skip_permit2_batch_multisign.py``.

**Input (single-tx):** JSON as returned by ``uniswap_trade_swap.py``, with a top-level **``swap``**
object: ``to``, ``data``, ``value``, ``chainId``, and optional gas/fee fields.

**Required**

- ``--key-gen-id``
- Swap JSON: ``--swap-file`` / ``--swap-json`` / ``--stdin`` (or pipe the file)
- If the response omits **``chainId``**, pass ``--chain-id``

**Optional**

- ``--mpc-auth-url`` / ``MPC_AUTH_URL``, ``--management-port`` / ``MANAGEMENT_PORT``
- ``--purpose``, ``--rpc-gateway``, ``--no-custom-gas-params`` (same meaning as other compose recipes)
- ``--skip-gas-check`` (skip native balance precheck; see ``recipe_gas_precheck``)
- ``--ed25519-seed-hex`` / ``--eip191-private-key-hex`` — append **postBody** with **clientSig**

Example (recommended batch)::

  python3 recipes/uniswapV4/uniswap_trade_quote.py ... > quote.json
  python3 recipes/uniswapV4/uniswap_trade_swap.py --quote-file quote.json > swap.json
  python3 recipes/uniswapV4/uniswap_swap_multisign.py --batch-approve-and-swap \\
    --key-gen-id KeyGen... --swap-file swap.json --quote-file quote.json --token-in 0x...

Example (legacy single calldata tx)::

  python3 recipes/uniswapV4/uniswap_swap_multisign.py --key-gen-id KeyGen... --swap-file swap.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

_scripts_dir = Path(__file__).resolve().parent.parent.parent / "scripts"
if str(_scripts_dir) not in sys.path:
    sys.path.insert(0, str(_scripts_dir))

import generateMultiSignRequestFromCompose as _compose
import recipe_gas_precheck as _gas

_ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


def _norm_addr(s: str, name: str) -> str:
    t = (s or "").strip()
    if not t:
        raise ValueError(f"{name} is required")
    if t.startswith("0x"):
        t = "0x" + t[2:].lower()
    if not _ADDR_RE.match(t):
        raise ValueError(f"{name} must be a 0x-prefixed 20-byte EVM address")
    return t


def extract_uniswap_create_swap(swap_api_response: Any) -> dict[str, Any]:
    """
    Normalize Uniswap **create swap** JSON to a dict with
    **to**, **data**, **value**, **chainId**, and optional **gasLimit** / fee fields.
    """
    if not isinstance(swap_api_response, dict):
        raise TypeError("Swap response must be a JSON object")
    sw = swap_api_response.get("swap")
    if not isinstance(sw, dict):
        if "to" in swap_api_response and "data" in swap_api_response:
            sw = dict(swap_api_response)
        else:
            raise ValueError("Swap response must include a 'swap' object (or top-level to/data fields)")
    to = (sw.get("to") or "").strip()
    data = (sw.get("data") or "").strip()
    if not to or not data:
        raise ValueError("swap.to and swap.data are required in the create-swap response")
    if not data.startswith("0x"):
        data = "0x" + data
    out: dict[str, Any] = {
        "to": _norm_addr(to, "swap.to"),
        "data": data,
        "value": sw.get("value", "0"),
    }
    if "chainId" in sw and sw["chainId"] is not None:
        out["chainId"] = sw["chainId"]
    for k in (
        "gasLimit",
        "gas",
        "maxFeePerGas",
        "maxPriorityFeePerGas",
        "gasPrice",
        "from",
    ):
        if k in sw and sw[k] is not None:
            out[k] = sw[k]
    return out


def build_uniswap_swap_compose(
    key_gen_id: str,
    swap_block: dict[str, Any],
    destination_chain_id: str | None = None,
    purpose: str = "",
    no_custom_gas_params: bool = False,
    rpc_gateway: str | None = None,
    signature: str = "uniswapUniversalRouterSwap",
) -> dict[str, Any]:
    """
    Build compose JSON: one **preencodedData** action for the Universal Router
    (or other contract) in the create-swap response.
    """
    sid = (key_gen_id or "").strip()
    if not sid:
        raise ValueError("keyGenId is required")
    dcid = (destination_chain_id or "").strip()
    if "chainId" in swap_block and swap_block["chainId"] is not None:
        sw_chain = int(swap_block["chainId"])
        if dcid:
            if int(dcid) != sw_chain:
                raise ValueError(
                    f"destination chain id {dcid} does not match swap.chainId {sw_chain}"
                )
            dest = dcid
        else:
            dest = str(sw_chain)
    else:
        if not dcid:
            raise ValueError("destinationChainId is required when swap has no chainId")
        dest = dcid
    to = swap_block["to"]
    data = swap_block["data"]
    val = swap_block.get("value", "0")
    action: dict[str, Any] = {
        "destinationContract": to,
        "preencodedData": data,
        "value": val,
        "signature": (signature or "uniswapUniversalRouterSwap").strip(),
    }
    est = _compose.parse_optional_int(swap_block.get("gasLimit") or swap_block.get("gas"))
    if est is not None and est > 0:
        action["estimatedGas"] = est
    mfee = _compose.parse_optional_int(swap_block.get("maxFeePerGas") or swap_block.get("max_fee_per_gas"))
    mprio = _compose.parse_optional_int(
        swap_block.get("maxPriorityFeePerGas") or swap_block.get("max_priority_fee_per_gas")
    )
    gpw = _compose.parse_optional_int(swap_block.get("gasPrice") or swap_block.get("gas_price"))
    if mfee is not None and mfee > 0 and mprio is not None and mprio > 0:
        action["maxFeePerGas"] = mfee
        action["maxPriorityFeePerGas"] = mprio
    if gpw is not None and gpw > 0 and (mfee is None or mfee <= 0):
        action["gasPriceWei"] = gpw
    c: dict[str, Any] = {
        "keyGenId": sid,
        "destinationChainId": dest,
        "composeActions": [action],
    }
    p = (purpose or "").strip()
    if p:
        c["purpose"] = p
    rg = (rpc_gateway or "").strip()
    if rg:
        c["rpcGateway"] = rg
    if no_custom_gas_params:
        c["noCustomGasParams"] = True
    return c


def uniswap_swap_multisign_payload(
    mpc_auth_url: str,
    management_port: str | int,
    key_gen_id: str,
    create_swap_response: dict[str, Any],
    destination_chain_id: str | None = None,
    purpose: str = "",
    no_custom_gas_params: bool = False,
    rpc_gateway: str | None = None,
    skip_gas_check: bool = False,
    signature_label: str = "uniswapUniversalRouterSwap",
) -> dict[str, Any]:
    sw = extract_uniswap_create_swap(create_swap_response)
    compose = build_uniswap_swap_compose(
        key_gen_id,
        sw,
        destination_chain_id=destination_chain_id,
        purpose=purpose,
        no_custom_gas_params=no_custom_gas_params,
        rpc_gateway=rpc_gateway,
        signature=signature_label,
    )
    base = _compose.resolve_mpc_auth_base(mpc_auth_url, management_port)
    if not skip_gas_check:
        _gas.require_native_gas_for_compose(compose, base)
    return _compose.build_compose_multisign(compose, base)


def main() -> None:
    ap = argparse.ArgumentParser(
        description=(
            "Build multiSignRequest JSON from Uniswap Trade API POST /v1/swap (create swap) response."
        )
    )
    ap.add_argument(
        "--mpc-auth-url",
        default=(os.environ.get("MPC_AUTH_URL") or _compose.DEFAULT_MPC_AUTH_URL),
        help="Management API host URL (env MPC_AUTH_URL, default: %(default)s)",
    )
    ap.add_argument(
        "--management-port",
        default=(os.environ.get("MANAGEMENT_PORT") or _compose.DEFAULT_MANAGEMENT_PORT),
        help="Management API port (env MANAGEMENT_PORT, default: %(default)s)",
    )
    ap.add_argument(
        "--key-gen-id",
        required=True,
        metavar="ID",
        help="KeyGen request id (GET /getKeyGenResultById)",
    )
    ap.add_argument(
        "--chain-id",
        default="",
        metavar="ID",
        help="Destination chain id if swap JSON has no chainId (must match swap.chainId when both set)",
    )
    ap.add_argument(
        "--swap-file",
        default="",
        metavar="FILE",
        help="JSON: full create-swap response (with swap object) or a wrapper; see also --stdin, --swap-json",
    )
    ap.add_argument(
        "--swap-json",
        default="",
        help="Same as --swap-file but inline JSON",
    )
    ap.add_argument(
        "--stdin",
        action="store_true",
        help="Read create-swap JSON from stdin",
    )
    ap.add_argument("--purpose", default="", help="Optional sign-request purpose (max 256 chars)")
    ap.add_argument(
        "--rpc-gateway",
        default="",
        help="Override RPC; default is GET /getChainDetails?chain_id=...",
    )
    ap.add_argument(
        "--no-custom-gas-params",
        action="store_true",
        help="Set noCustomGasParams (RPC-only gas like compose; see generateMultiSignRequestFromCompose)",
    )
    ap.add_argument(
        "--skip-gas-check",
        action="store_true",
        help="Do not require native gas balance (recipe_gas_precheck)",
    )
    ap.add_argument(
        "--signature-label",
        default="uniswapUniversalRouterSwap",
        help="composeActions[0].signature (signatureText / batch meta, default: %(default)s)",
    )
    ap.add_argument(
        "--batch-approve-and-swap",
        action="store_true",
        help=(
            "Build 2- or 3-tx batch (ERC-20 approve + [allowance-hub approve] + swap) like the app classic-allowance flow. "
            "Requires --quote-file or --quote-json and --token-in (after uniswap_trade_swap.py)."
        ),
    )
    ap.add_argument(
        "--quote-file",
        default="",
        metavar="FILE",
        help="With --batch-approve-and-swap: quote JSON (uniswap_trade_quote output or /quote body)",
    )
    ap.add_argument(
        "--quote-json",
        default="",
        help="With --batch-approve-and-swap: inline quote JSON",
    )
    ap.add_argument(
        "--token-in",
        default="",
        metavar="ADDR",
        help="With --batch-approve-and-swap: ERC-20 token address (input token)",
    )
    ap.add_argument(
        "--swap-deadline-unix",
        type=int,
        default=None,
        help="With --batch-approve-and-swap: unix seconds for allowance-hub approve expiration (3-tx path; optional)",
    )
    ap.add_argument(
        "--slippage-percent",
        type=float,
        default=None,
        help="With --batch-approve-and-swap: extra slippage on approve amount (EXACT_OUTPUT; optional)",
    )
    ap.add_argument(
        "--ed25519-seed-hex",
        metavar="HEX",
        help="If set, sign messageToSign with Ed25519 and output postBody with clientSig",
    )
    ap.add_argument(
        "--eip191-private-key-hex",
        metavar="HEX",
        help="If set, sign with secp256k1 personal_sign; output postBody",
    )
    ap.add_argument(
        "--out",
        metavar="FILE",
        default="",
        help="Write JSON result to a file in addition to stdout",
    )
    args = ap.parse_args()

    if args.stdin:
        raw = sys.stdin.read()
    elif (args.swap_json or "").strip():
        raw = args.swap_json
    elif (args.swap_file or "").strip():
        raw = Path(args.swap_file).read_text(encoding="utf-8")
    else:
        ap.error("Provide --swap-file, --swap-json, or --stdin (see --help)")

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"Invalid swap JSON: {e}", file=sys.stderr)
        sys.exit(1)
    if not isinstance(parsed, dict):
        print("Top-level JSON must be an object", file=sys.stderr)
        sys.exit(1)

    chain_opt = (args.chain_id or "").strip() or None
    try:
        if args.batch_approve_and_swap:
            if not (args.token_in or "").strip():
                print("--batch-approve-and-swap requires --token-in", file=sys.stderr)
                sys.exit(1)
            if (args.quote_json or "").strip():
                quote_raw = args.quote_json
            elif (args.quote_file or "").strip():
                quote_raw = Path(args.quote_file).read_text(encoding="utf-8")
            else:
                print("--batch-approve-and-swap requires --quote-file or --quote-json", file=sys.stderr)
                sys.exit(1)
            try:
                quote_parsed = json.loads(quote_raw)
            except json.JSONDecodeError as e:
                print(f"Invalid quote JSON: {e}", file=sys.stderr)
                sys.exit(1)
            if not isinstance(quote_parsed, dict):
                print("Quote JSON must be an object", file=sys.stderr)
                sys.exit(1)
            utq = quote_parsed.get("uniswapTradeQuote")
            quote_use = utq if isinstance(utq, dict) else quote_parsed
            from uniswap_v4_skip_permit2_batch_multisign import uniswap_v4_skip_permit2_batch_multisign_payload

            out = uniswap_v4_skip_permit2_batch_multisign_payload(
                args.mpc_auth_url,
                args.management_port,
                args.key_gen_id,
                parsed,
                quote_use,
                (args.token_in or "").strip(),
                swap_deadline_unix=args.swap_deadline_unix,
                slippage_percent=args.slippage_percent,
                destination_chain_id=chain_opt,
                purpose=(args.purpose or "").strip(),
                no_custom_gas_params=bool(args.no_custom_gas_params),
                rpc_gateway=(args.rpc_gateway or "").strip() or None,
                skip_gas_check=bool(args.skip_gas_check),
            )
        else:
            out = uniswap_swap_multisign_payload(
                args.mpc_auth_url,
                args.management_port,
                args.key_gen_id,
                parsed,
                destination_chain_id=chain_opt,
                purpose=(args.purpose or "").strip(),
                no_custom_gas_params=bool(args.no_custom_gas_params),
                rpc_gateway=(args.rpc_gateway or "").strip() or None,
                skip_gas_check=bool(args.skip_gas_check),
                signature_label=(args.signature_label or "uniswapUniversalRouterSwap").strip()
                or "uniswapUniversalRouterSwap",
            )
    except (TypeError, ValueError, RuntimeError) as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)

    if args.ed25519_seed_hex:
        sig = _compose.sign_ed25519(out["messageToSign"], args.ed25519_seed_hex)
        out["postBody"] = {**out["bodyForSign"], "clientSig": sig, "signedMessage": out["messageToSign"]}
    elif args.eip191_private_key_hex:
        sig = _compose.sign_eip191(out["messageToSign"], args.eip191_private_key_hex)
        out["postBody"] = {**out["bodyForSign"], "clientSig": sig, "signedMessage": out["messageToSign"]}

    text = json.dumps(out, indent=2, ensure_ascii=False)
    print(text)
    if (args.out or "").strip():
        Path(args.out).write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
