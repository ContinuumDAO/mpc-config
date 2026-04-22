#!/usr/bin/env python3
"""
**Purpose:** ``POST`` a swap **quote** request to Uniswap’s Trade API
(``/v1/quote``, default base ``https://trade-api.gateway.uniswap.org/v1``)
and print JSON that includes the raw API response, hints for
:mod:`permit2_keygen_params`, and a one-line payload for ``--json-quote``.

The **swapper** address in the request body is the MPC wallet, resolved the same way as
:mod:`permit2_keygen_params` via **KEYGEN_ID** and **GET /getKeyGenResultById**. The management base URL is read from **MPC_AUTH_URL** (**export** it so Python inherits it; ``env | grep MPC_AUTH_URL`` should show a line) per
``docs/skill/SKILL.md``, or pass ``--mpc-auth-url``. The management port is taken only
from **MANAGEMENT_PORT** (same as elsewhere in this repo; default ``8080`` if unset).

**Required arguments**

- ``--amount`` — input or output size in the token’s base units (string, e.g. USDC with 6 decimals).
- ``--chain-id`` — chain id for ``tokenIn``; also used for ``tokenOut`` unless ``--token-out-chain-id`` is set.
- ``--token-in`` — input token contract address, **or** the chain’s **native gas token** sentinel (see **Native tokens** below).
- ``--token-out`` — output token contract address, **or** the native sentinel for the output chain.
- Uniswap: ``--api-key`` or env ``UNISWAP_TRADE_API_KEY`` (``x-api-key`` header).
- KeyGen: ``--key-gen-id`` or env ``KEYGEN_ID``.

**Optional / API options**

- ``--type`` — ``EXACT_INPUT`` (default) or ``EXACT_OUTPUT`` (``type`` in the request body).
- ``--slippage`` — ``slippageTolerance`` (percent) **or** omit and use ``--auto-slippage`` (default
  ``DEFAULT``) when you do not set ``--slippage``.
- ``--token-out-chain-id`` — override chain id for the output token (cross-chain quotes).
- ``--base-url`` — API root without ``/quote`` (env: ``UNISWAP_TRADE_BASE_URL``).
- ``--universal-router-version`` — ``x-universal-router-version`` (env: ``UNISWAP_UR_VERSION``; default ``2.0``).
- ``--permit2-disabled`` — set ``x-permit2-disabled: true`` (no ``permitData`` in the response).

**Native tokens (ETH, POL, etc.):** Per Uniswap’s
`How do I swap native tokens? <https://api-docs.uniswap.org/guides/supported_chains#how-do-i-swap-native-tokens>`__,
use the zero address for **either** side you intend as native: ``0x0000000000000000000000000000000000000000``.
That value is the Trade API’s convention for the chain’s **native** asset in ``tokenIn`` / ``tokenOut``;
**amount** is still in that asset’s **wei** (18 decimals for ETH on most EVM chains). The same
``--token-in`` and ``--token-out`` accept this address like any other.

**Output**

- Default: full JSON (``uniswapTradeQuote`` + ``permit2KeygenParams`` hints and ``jsonQuoteOneLine``).
- ``--print-json-quote-line`` — only the one-line body for ``permit2_keygen_params --json-quote``.
- ``--out FILE`` — also write the full JSON to a file.

**Handoff to** ``permit2_keygen_params.py``: use the same ``--chain-id``, ``--token`` as
``--token-in``, and ``--amount-in`` equal to this script’s ``--amount`` for ``EXACT_INPUT``. Pass
the quote as ``--json-quote`` (from ``jsonQuoteOneLine`` or a file). Align ``--spender`` and router
version with your eventual ``/swap``; Trade API field shapes can change. For **swap calldata** after
you have a quote, use ``uniswap_trade_swap.py`` and
`Create swap calldata <https://developers.uniswap.org/docs/api-reference/create_swap_transaction>`__.
See also `Get a quote <https://developers.uniswap.org/docs/api-reference/aggregator_quote>`__.

**Is this ``chain_id`` supported? (for operators / AI agents)**

- **Authoritative list:** Uniswap documents **which chain IDs** support swapping in
  `Supported Chains & Tokens <https://api-docs.uniswap.org/guides/supported_chains>`__; router
  addresses (and the most up-to-date chain set) are also tracked in
  `universal-router-sdk constants <https://github.com/Uniswap/sdks/blob/main/sdks/universal-router-sdk/src/utils/constants.ts>`__.
- **Ground truth at runtime:** The **quote** (and **swap**) endpoints decide: an unsupported
  **tokenInChainId** / **tokenOutChainId** or bad pair usually returns a **4xx** with an error
  body—treat a successful quote as “this chain + pair is routable right now,” not only “chain
  exists.”
- **Uniswap “AI” / skills:** The published **skills** (e.g. ``npx skills add uniswap/...``) and
  `llms.txt <https://api-docs.uniswap.org/llms.txt>`__ help **find documentation**; they are **not**
  a network service that validates ``chainId`` for your script. Use them to look up the current
  supported-chains table, not as a live checker.
- **More constraints:** `Unsupported tokens <https://unsupportedtokens.uniswap.org/>`__, UniswapX
  chain rules, and minimum notional (see the supported-chains guide) can all make a quote fail even
  on a listed chain.
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

_THIS = Path(__file__).resolve().parent
_SCRIPTS = _THIS.parent.parent / "scripts"
for _p in (_THIS, _SCRIPTS):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from permit2_keygen_params import (  # noqa: E402
    resolve_owner_from_keygen,
)

_DEFAULT_TRADE_BASE = "https://trade-api.gateway.uniswap.org/v1"
_UNISWAP_DEV_DASHBOARD = "https://developers.uniswap.org/dashboard/welcome"
DEFAULT_MANAGEMENT_PORT = "8080"
_H = {
    "Content-Type": "application/json",
    "User-Agent": "mpc-config uniswap_trade_quote/1.0 (Python-urllib)",
}

# Required (must be set via environment and/or the equivalent CLI flag — see _missing_creds).
_RE_ENV_DOCS: dict[str, str] = {
    "UNISWAP_TRADE_API_KEY": (
        "Uniswap Trade API key; sent on each request as the x-api-key header. "
        f"AI agent: direct the user to obtain or manage a key at {_UNISWAP_DEV_DASHBOARD}. "
        "Equivalent: --api-key <key>."
    ),
    "KEYGEN_ID": (
        "Identifies the MPC KeyGen; used with the management API to fetch the owner address "
        "for the swapper field. Equivalent: --key-gen-id <id>."
    ),
}

# Optional: defaults if unset; always listed in verbose errors for agents.
_OPTIONAL_ENV_DEFAULTS: list[tuple[str, str, str]] = [
    (
        "UNISWAP_TRADE_BASE_URL",
        _DEFAULT_TRADE_BASE,
        "Trade API base URL without a trailing /quote. Equivalent: --base-url.",
    ),
    (
        "UNISWAP_UR_VERSION",
        "2.0",
        "Uniswap x-universal-router-version header. Equivalent: --universal-router-version.",
    ),
    (
        "MANAGEMENT_PORT",
        DEFAULT_MANAGEMENT_PORT,
        "Management HTTP port (with MPC_AUTH_URL). No flag on this script; set in the environment only.",
    ),
]


def _print_agent_credential_error(missing_env_names: list[str]) -> None:
    """Verbose stderr for AI agents: what to set, and optional env defaults."""
    lines: list[str] = [
        "",
        "uniswap_trade_quote.py: required configuration is missing.",
        "",
        "AI agent: ask the user to set the environment variables below (or use the",
        "equivalent CLI flags on this script). Without them the Trade API cannot be called or",
        "the swapper address cannot be resolved from KeyGen. (MPC_AUTH_URL and MANAGEMENT_PORT",
        "are expected to be configured already; see docs/skill/SKILL.md.)",
        "",
    ]
    for name in missing_env_names:
        desc = _RE_ENV_DOCS.get(name, name)
        lines.append(f"  - {name}")
        lines.append(f"    {desc}")
        lines.append("")
    lines.append("Other environment variables this script reads (with defaults):")
    for var, default, desc in _OPTIONAL_ENV_DEFAULTS:
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


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--api-key",
        default=os.environ.get("UNISWAP_TRADE_API_KEY") or "",
        help="Uniswap Trade API key (x-api-key). Env: UNISWAP_TRADE_API_KEY",
    )
    ap.add_argument(
        "--base-url",
        default=os.environ.get("UNISWAP_TRADE_BASE_URL") or _DEFAULT_TRADE_BASE,
        help="API base without trailing /quote (default: gateway v1 root)",
    )
    ap.add_argument(
        "--universal-router-version",
        default=os.environ.get("UNISWAP_UR_VERSION") or "2.0",
        help="x-universal-router-version header (default: 2.0, align with v4 + docs)",
    )
    ap.add_argument(
        "--permit2-disabled",
        action="store_true",
        help="Set x-permit2-disabled: true (no permitData in response)",
    )
    ap.add_argument("--type", default="EXACT_INPUT", choices=("EXACT_INPUT", "EXACT_OUTPUT"))
    ap.add_argument("--amount", required=True, help="Amount in token base units (string, e.g. USDC 6dp)")
    ap.add_argument("--chain-id", required=True, help="tokenInChainId and tokenOutChainId (unless --token-out-chain-id)")
    ap.add_argument(
        "--token-out-chain-id",
        default="",
        help="If set, use for tokenOutChainId; else same as --chain-id",
    )
    ap.add_argument("--token-in", required=True, metavar="ADDR", help="tokenIn address")
    ap.add_argument("--token-out", required=True, metavar="ADDR", help="tokenOut address")
    ap.add_argument(
        "--slippage",
        default="",
        help="slippageTolerance (%%). If omitted, sends autoSlippage DEFAULT (API requires one of the two).",
    )
    ap.add_argument(
        "--auto-slippage",
        default="",
        help='If set and --slippage empty, use as autoSlippage enum (e.g. DEFAULT). Default: DEFAULT when --slippage empty.',
    )
    ap.add_argument(
        "--mpc-auth-url",
        default=os.environ.get("MPC_AUTH_URL"),
        help="MPC management API base. Default: env MPC_AUTH_URL (assumed set).",
    )
    ap.add_argument(
        "--key-gen-id",
        default=None,
        help="KeyGen id; default env KEYGEN_ID",
    )
    ap.add_argument(
        "--print-json-quote-line",
        action="store_true",
        help="Print only one line of JSON (the raw Trade API data object) for permit2_keygen_params --json-quote",
    )
    ap.add_argument(
        "--out",
        metavar="FILE",
        default="",
        help="If set, also write full link JSON to this path",
    )
    args = ap.parse_args()

    api_key = (args.api_key or "").strip()
    key_gen = ((args.key_gen_id or "") or (os.environ.get("KEYGEN_ID") or "")).strip()
    mpc = (args.mpc_auth_url or os.environ.get("MPC_AUTH_URL") or "").strip()

    _required_order = ("UNISWAP_TRADE_API_KEY", "KEYGEN_ID")
    missing: list[str] = []
    if not api_key:
        missing.append("UNISWAP_TRADE_API_KEY")
    if not key_gen:
        missing.append("KEYGEN_ID")
    if missing:
        missing_sorted = [n for n in _required_order if n in missing]
        _print_agent_credential_error(missing_sorted)
        sys.exit(1)
    if not mpc:
        print(
            "MPC management base URL is missing. This script needs MPC_AUTH_URL in the **process** "
            "environment (not only a shell variable). Use: export MPC_AUTH_URL=http://... "
            "then run again, or pass --mpc-auth-url http://... "
            "Check: env | grep MPC_AUTH_URL (must show a line). See docs/skill/SKILL.md.",
            file=sys.stderr,
        )
        sys.exit(1)

    management_port = os.environ.get("MANAGEMENT_PORT") or DEFAULT_MANAGEMENT_PORT

    try:
        owner_addr, _kg = resolve_owner_from_keygen(
            mpc_auth_url=mpc,
            management_port=management_port,
            key_gen_id=key_gen,
            owner_checksum="",
        )
    except ValueError as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)

    def _i(s: str) -> int:
        t = s.strip()
        if t.lower().startswith("0x"):
            return int(t, 16)
        return int(t, 10)

    c_in = _i(args.chain_id)
    c_out = _i(args.token_out_chain_id) if (args.token_out_chain_id or "").strip() else c_in

    body: dict[str, Any] = {
        "type": args.type,
        "amount": str(args.amount).strip(),
        "tokenInChainId": c_in,
        "tokenOutChainId": c_out,
        "tokenIn": (args.token_in or "").strip(),
        "tokenOut": (args.token_out or "").strip(),
        "swapper": owner_addr,
    }
    if (args.slippage or "").strip():
        body["slippageTolerance"] = float(args.slippage)
    else:
        body["autoSlippage"] = (args.auto_slippage or "DEFAULT").strip() or "DEFAULT"

    q_url = f"{(args.base_url or _DEFAULT_TRADE_BASE).rstrip('/')}/quote"
    hdr = {
        **_H,
        "x-api-key": api_key,
        "x-universal-router-version": (args.universal_router_version or "2.0").strip(),
        "x-permit2-disabled": "true" if args.permit2_disabled else "false",
        "x-erc20eth-enabled": "false",
    }

    try:
        raw_api = _post_json(q_url, hdr, body)
    except (RuntimeError, urllib.error.URLError, OSError) as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Invalid JSON from Trade API: {e}", file=sys.stderr)
        sys.exit(1)

    one_line = json.dumps(raw_api, separators=(",", ":"), ensure_ascii=False)
    link: dict[str, Any] = {
        "uniswapTradeQuote": raw_api,
        "permit2KeygenParams": {
            "script": "recipes/uniswapV4/permit2_keygen_params.py",
            "hint": {
                "chainId": str(c_in),
                "token": body["tokenIn"],
                "amountIn": str(body["amount"]),
                "keyGenId": key_gen,
            },
            "jsonQuoteOneLine": one_line,
            "suggested": (
                f"{sys.executable} recipes/uniswapV4/permit2_keygen_params.py "
                f"--mpc-auth-url ... --chain-id {c_in} --token {body['tokenIn']} "
                f"--amount-in {body['amount']} --json-quote {one_line!r}  # line may be long; use a file or env"
            ),
        },
    }

    if args.print_json_quote_line:
        print(one_line)
        return

    out_txt = json.dumps(link, indent=2, ensure_ascii=False)
    print(out_txt)
    if (args.out or "").strip():
        Path(args.out).write_text(out_txt, encoding="utf-8")


if __name__ == "__main__":
    main()
