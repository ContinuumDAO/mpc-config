#!/usr/bin/env python3
"""
**Purpose:** call Uniswap Trade API **``POST /v1/swap``** (create swap calldata) using a
**quote** object returned from **``POST /v1/quote``** (see
`Create swap calldata <https://developers.uniswap.org/docs/api-reference/create_swap_transaction>`__).

**MPC:** this script always sends ``x-permit2-disabled: true`` (Uniswap’s header for classic ERC-20 allowance). Pair the
output with ``uniswap_v4_skip_permit2_batch_multisign.py`` (approve + swap batch). Use the same
``x-universal-router-version`` as ``POST /v1/quote``.

This script only needs **``UNISWAP_TRADE_API_KEY``** and a JSON file (or inline JSON) containing the
quote. You can pass the full object emitted by ``uniswap_trade_quote.py`` (it will use the
``uniswapTradeQuote`` field) or the raw quote body from the quote response.

**Required**

- ``--api-key`` / ``UNISWAP_TRADE_API_KEY`` (``x-api-key``)
- A quote: ``--quote-file`` (path to JSON) **or** ``--quote-json`` (string), unless ``--stdin`` is used

**Optional API body** (see Uniswap docs; omitted keys are not sent, except where noted)

- ``--refresh-gas-price`` / ``--simulate-transaction`` / ``--include-gas-info`` — booleans
- ``--safety-mode`` (e.g. ``SAFE``), ``--deadline`` (unix ts), ``--urgency`` (default in API: ``urgent``)
- ``--universal-router-version`` / ``UNISWAP_UR_VERSION``; ``--base-url`` / ``UNISWAP_TRADE_BASE_URL``
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

_DEFAULT_TRADE_BASE = "https://trade-api.gateway.uniswap.org/v1"
_UNISWAP_DEV_DASHBOARD = "https://developers.uniswap.org/dashboard/welcome"
_H = {
    "Content-Type": "application/json",
    "User-Agent": "mpc-config uniswap_trade_swap/1.0 (Python-urllib)",
}

_RE_ENV_UNISWAP_KEY = (
    "Uniswap Trade API key; x-api-key header. "
    f"AI agent: direct the user to obtain a key: {_UNISWAP_DEV_DASHBOARD}. "
    "Equivalent: --api-key <key>."
)
_OPTIONAL_ENV: list[tuple[str, str, str]] = [
    (
        "UNISWAP_TRADE_BASE_URL",
        _DEFAULT_TRADE_BASE,
        "API base without /swap. Equivalent: --base-url.",
    ),
    (
        "UNISWAP_UR_VERSION",
        "2.0",
        "x-universal-router-version. Equivalent: --universal-router-version.",
    ),
]


def _print_agent_missing_uniswap_key() -> None:
    lines = [
        "",
        "uniswap_trade_swap.py: Uniswap API key is missing.",
        "",
        "AI agent: ask the user to set the variable below and retry.",
        "",
        f"  - UNISWAP_TRADE_API_KEY",
        f"    {_RE_ENV_UNISWAP_KEY}",
        "",
        "Other environment variables this script reads (with defaults):",
    ]
    for var, default, desc in _OPTIONAL_ENV:
        lines.append(f"  - {var}")
        lines.append(f"    default: {default!r} — {desc}")
        lines.append("")
    print("\n".join(lines).rstrip(), file=sys.stderr)


def _post_json(url: str, headers: dict[str, str], body: dict[str, Any]) -> dict[str, Any]:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            raw = resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Trade API HTTP {e.code}: {err_body or e.reason}") from e
    return json.loads(raw)


def extract_quote_object(parsed: Any) -> dict[str, Any]:
    """Accept raw ``/v1/quote`` JSON or the ``uniswapTradeQuote`` wrapper from ``uniswap_trade_quote``."""
    if not isinstance(parsed, dict):
        raise TypeError("Quote JSON must be a JSON object at the top level")
    utq = parsed.get("uniswapTradeQuote")
    if isinstance(utq, dict):
        return utq
    return parsed


def create_swap_calldata(
    *,
    base_url: str = _DEFAULT_TRADE_BASE,
    api_key: str,
    quote: dict[str, Any],
    universal_router_version: str = "2.0",
    include_gas_info: bool = False,
    refresh_gas_price: bool = False,
    simulate_transaction: bool = False,
    safety_mode: str | None = None,
    deadline: int | None = None,
    urgency: str | None = None,
) -> dict[str, Any]:
    """
    ``POST /v1/swap`` — build calldata for a swap (requires a **quote** from ``POST /v1/quote``).

    See: https://developers.uniswap.org/docs/api-reference/create_swap_transaction
    """
    url = f"{(base_url or _DEFAULT_TRADE_BASE).rstrip('/')}/swap"
    hdr = {
        **_H,
        "x-api-key": api_key,
        "x-universal-router-version": (universal_router_version or "2.0").strip(),
        "x-permit2-disabled": "true",
        "x-erc20eth-enabled": "false",
    }
    body: dict[str, Any] = {"quote": quote}
    if include_gas_info:
        body["includeGasInfo"] = True
    if refresh_gas_price:
        body["refreshGasPrice"] = True
    if simulate_transaction:
        body["simulateTransaction"] = True
    if safety_mode is not None and str(safety_mode).strip() != "":
        body["safetyMode"] = str(safety_mode).strip()
    if deadline is not None:
        body["deadline"] = int(deadline)
    if urgency is not None and str(urgency).strip() != "":
        body["urgency"] = str(urgency).strip()

    return _post_json(url, hdr, body)


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--api-key",
        default=os.environ.get("UNISWAP_TRADE_API_KEY") or "",
        help="Uniswap Trade API key. Env: UNISWAP_TRADE_API_KEY",
    )
    ap.add_argument(
        "--base-url",
        default=os.environ.get("UNISWAP_TRADE_BASE_URL") or _DEFAULT_TRADE_BASE,
        help="API base without /swap (default: gateway v1)",
    )
    ap.add_argument(
        "--universal-router-version",
        default=os.environ.get("UNISWAP_UR_VERSION") or "2.0",
        help="x-universal-router-version (default: 2.0)",
    )
    ap.add_argument(
        "--quote-file",
        metavar="FILE",
        default="",
        help="JSON file: raw /v1/quote result or uniswap_trade_quote wrapper with uniswapTradeQuote",
    )
    ap.add_argument(
        "--quote-json",
        default="",
        help="Same as --quote-file but inline JSON (use a file for large payloads)",
    )
    ap.add_argument(
        "--stdin",
        action="store_true",
        help="Read JSON for the quote (raw or wrapper) from stdin",
    )
    ap.add_argument(
        "--include-gas-info",
        action="store_true",
        help="Set includeGasInfo: true in the request body (omit the flag to leave the field unset; API default false)",
    )
    ap.add_argument(
        "--refresh-gas-price",
        action="store_true",
        help="refreshGasPrice: true",
    )
    ap.add_argument(
        "--simulate-transaction",
        action="store_true",
        help="simulateTransaction: true",
    )
    ap.add_argument(
        "--safety-mode",
        default="",
        help='safetyMode (e.g. "SAFE")',
    )
    ap.add_argument(
        "--deadline",
        type=int,
        default=None,
        help="deadline (unix timestamp)",
    )
    ap.add_argument(
        "--urgency",
        default="",
        help="urgency (API default: urgent; only sent if non-empty)",
    )
    ap.add_argument(
        "--out",
        metavar="FILE",
        default="",
        help="Write full JSON response to a file in addition to stdout",
    )
    args = ap.parse_args()

    api_key = (args.api_key or "").strip()
    if not api_key:
        _print_agent_missing_uniswap_key()
        sys.exit(1)

    if args.stdin:
        raw_in = sys.stdin.read()
    elif (args.quote_json or "").strip():
        raw_in = args.quote_json
    elif (args.quote_file or "").strip():
        raw_in = Path(args.quote_file).read_text(encoding="utf-8")
    else:
        ap.error("Provide --quote-file, --quote-json, or --stdin with JSON (see --help)")

    try:
        parsed = json.loads(raw_in)
    except json.JSONDecodeError as e:
        print(f"Invalid quote JSON: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        q_obj = extract_quote_object(parsed)
    except (TypeError, ValueError) as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)

    try:
        out = create_swap_calldata(
            base_url=args.base_url,
            api_key=api_key,
            quote=q_obj,
            universal_router_version=args.universal_router_version,
            include_gas_info=bool(args.include_gas_info),
            refresh_gas_price=bool(args.refresh_gas_price),
            simulate_transaction=bool(args.simulate_transaction),
            safety_mode=(args.safety_mode or "").strip() or None,
            deadline=args.deadline,
            urgency=(args.urgency or "").strip() or None,
        )
    except (RuntimeError, urllib.error.URLError, OSError) as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Invalid JSON from Trade API: {e}", file=sys.stderr)
        sys.exit(1)

    text = json.dumps(out, indent=2, ensure_ascii=False)
    print(text)
    if (args.out or "").strip():
        Path(args.out).write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
