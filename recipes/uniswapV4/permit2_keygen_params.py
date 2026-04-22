#!/usr/bin/env python3
"""
Fetch on-chain Permit2 **allowance** state (amount, expiration, **nonce**) over JSON-RPC and
assemble **PermitSingle** parameters for :mod:`permit2_approval`.

This script is **only** for the **current KeyGen** identified by ``KEYGEN_ID`` (env or
``--key-gen-id``). It **requires** the management HTTP API (``--mpc-auth-url`` / ``MPC_AUTH_URL``
and ``--management-port``) to call **GET /getKeyGenResultById** (owner address) and **GET /getChainDetails**
(RPC for ``eth_call``). There is no standalone ``--owner``-only or RPC-only mode.

**Owner vs spender (Permit2)**

- **Owner** is always **GET /getKeyGenResultById** → ``ethereumaddress`` for that KeyGen. Optional
  ``--owner`` may be passed only as a **checksum**; it must match the KeyGen address.
- **Spender** (``--spender``) is **not** the KeyGen wallet. It is the contract you authorize to
  pull tokens via Permit2 (e.g. **Universal Router**).

Intended flow:

1. Set **KEYGEN_ID** and point **--mpc-auth-url** at the node (same KeyGen / chain config as
   ``permit2_approval.py``).
2. Choose **amount** (uint160), **--token**, **--spender** (see above).
3. JSON-RPC for ``eth_call`` is **only** **GET /getChainDetails** → ``rpcGateway`` (no CLI override).
   If the chain is missing, the script errors with guidance to **POST /postChainDetails** (see
   ``docs/references/API_IMPLEMENTATION.md``).
4. Use the JSON with ``permit2_approval.py`` for the **same** ``KEYGEN_ID``.

This script does **not** call a Uniswap V4 pool quoter: it does not compute swap outputs.
If you already have an ``amountIn`` from a V4 quote elsewhere, pass it as ``--amount-in``.
Use ``--json-quote`` to merge metadata (e.g. from ``uniswap_trade_quote.py``) into the emitted JSON.

**AI agent:** ``POST /multiSignRequest`` **purpose** is limited to **256** characters (API); longer
text belongs in **extraJSON** (via this script’s merge and ``--json-quote``), not in **purpose**.

**Dependencies:** ``eth_abi``, ``eth_utils`` (via ``eth_account`` install).

Example (RPC + owner from KeyGen)::

  export KEYGEN_ID=KeyGen2026...
  export MPC_AUTH_URL=http://127.0.0.1
  python3 recipes/uniswapV4/permit2_keygen_params.py \\
    --mpc-auth-url http://127.0.0.1 --management-port 8080 \\
    --key-gen-id "$KEYGEN_ID" \\
    --chain-id 1 \\
    --token 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 \\
    --amount-in 5000000 \\
    --spender default

  # Then (append quote args after MPC / KeyGen flags)::
  python3 recipes/uniswapV4/permit2_approval.py \\
    --key-gen-id "$KEYGEN_ID" --mpc-auth-url "$MPC_AUTH_URL" --management-port "$MANAGEMENT_PORT" \\
    $(python3 recipes/uniswapV4/permit2_keygen_params.py ... --format argv-fork-args-only)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

_THIS_DIR = Path(__file__).resolve().parent
_SCRIPTS_DIR = Path(__file__).resolve().parent.parent.parent / "scripts"
for _p in (_THIS_DIR, _SCRIPTS_DIR):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from permit2_approval import (
    DEFAULT_KEYGEN_PLACEHOLDER_PURPOSE,
    PURPOSE_MAX_LEN,
    default_multisign_purpose_for_permit2_swap,
    eip712_permit_single_full_message,
    permit2_approval_only_kwargs,
    permit2_eip712_digest_hex,
    uniswap_quote_object_from_blob,
)

try:
    from eth_abi import decode, encode
    from eth_utils import keccak
except ImportError as e:
    raise SystemExit(
        "eth_abi and eth_utils are required (install eth_account). "
        "See docs/skill/SKILL.md / scripts/requirements-keygen-agent.txt"
    ) from e

_HTTP_UA = "mpc-config permit2_keygen_params/1.0 (Python-urllib)"

_ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")

# Canonical Permit2 on Ethereum mainnet and most EVM chains Uniswap deploys on.
DEFAULT_PERMIT2 = "0x000000000022D473030F116dDEE9F6B43aC78BA3"

# Universal Router **2.0** — default ``spender`` when using Uniswap Trade with
# ``x-universal-router-version: 2.0`` (see ``uniswap_trade_quote.py`` / ``uniswap_trade_swap.py``).
# Synced from ``CHAIN_CONFIGS`` → ``UniversalRouterVersion.V2_0`` in
# https://github.com/Uniswap/sdks/blob/main/sdks/universal-router-sdk/src/utils/constants.ts
# Plus Ink (57073) from https://github.com/Uniswap/universal-router/blob/main/deploy-addresses/ink.json
# For UR 1.2 / 2.1.1 or custom routers, pass ``--spender`` explicitly (not ``default``).
DEFAULT_SPENDER_BY_CHAIN_ID: dict[int, str] = {
    # Mainnets & prod L2s
    1: "0x66a9893cc07d91d95644aedd05d03f95e1dba8af",  # Ethereum
    10: "0x851116d9223fabed8e56c0e6b8ad0c31d98b3507",  # Optimism
    56: "0x1906c1d672b88cd1b9ac7593301ca990f94eae07",  # BNB Chain (BSC)
    130: "0xef740bf23acae26f6492b10de645d6b98dc8eaf3",  # Unichain
    137: "0x1095692a6237d83c6a72f3f5efedb9a670c49223",  # Polygon PoS
    143: "0x0d97dc33264bfc1c226207428a79b26757fb9dc3",  # Monad
    196: "0x5507749f2c558bb3e162c6e90c314c092e7372ff",  # X Layer
    324: "0x28731BCC616B5f51dD52CF2e4dF0E78dD1136C06",  # zkSync Era
    480: "0x8ac7bee993bb44dab564ea4bc9ea67bf9eb5e743",  # World Chain
    1301: "0xf70536b3bcc1bd1a972dc186a2cf84cc6da6be5d",  # Unichain Sepolia
    1868: "0x0e2850543f69f678257266e0907ff9a58b3f13de",  # Soneium
    4217: "0x1febb76be10aaf3a1402f04e8e835f2c382f7914",  # Tempo
    42161: "0xa51afafe0263b40edaef0df8781ea9aa03e381a3",  # Arbitrum One
    42220: "0xcb695bc5D3Aa22cAD1E6DF07801b061a05A0233A",  # Celo
    43114: "0x94b75331ae8d42c1b61065089b7d48fe14aa73b7",  # Avalanche C-Chain
    57073: "0x112908dac86e20e7241b0927479ea3bf935d1fa0",  # Ink
    59144: "0x661e93cca42afacb172121ef892830ca3b70f08d",  # Linea
    7777777: "0x3315ef7ca28db74abadc6c44570efdf06b04b020",  # Zora
    81457: "0xeabbcb3e8e415306207ef514f660a3f820025be3",  # Blast
    8453: "0x6ff5693b99212da76ad316178a184ab56d299b43",  # Base
    # Historical / testnets (still in SDK CHAIN_CONFIGS for UR 2.0)
    5: "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",  # Goerli (deprecated)
    420: "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",  # Optimism Goerli (deprecated)
    421613: "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",  # Arbitrum Goerli (deprecated)
    44787: "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",  # Celo Alfajores
    80001: "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",  # Polygon Mumbai (deprecated)
    84531: "0xd0872d928672ae2ff74bdb2f5130ac12229cafaf",  # Base Goerli (deprecated)
    84532: "0x492e6456d9528771018deb9e87ef7750ef184104",  # Base Sepolia
    10143: "0x3ae6d8a282d67893e17aa70ebffb33ee5aa65893",  # Monad testnet
    11155111: "0x3a9d48ab9751398bbfa63ad67599bb04e4bdf98b",  # Sepolia
}

_AGENT_ADD_CHAIN = (
    "AI agent: if the chain is not configured on the MPC node, add this chain on the MPC node with POST /postChainDetails (body signed with the "
    "node management key). Required fields include chainName, chainId, rpcGateway, and legacy / "
    "gas fields as needed. See docs/references/API_IMPLEMENTATION.md — POST /postChainDetails and "
    "GET /getChainDetails. If the chain is configured on the MPC node, skip this step."
)


class ChainNotConfiguredError(ValueError):
    """Raised when GET /getChainDetails has no matching row or no usable rpcGateway."""


def _compose_mod():
    import generateMultiSignRequestFromCompose as m

    return m


def fetch_chain_details_strict(mpc_base: str, chain_id_num: int) -> dict[str, Any]:
    """
    **GET /getChainDetails?chain_id=…** — require a row whose ``chainId`` matches and a non-empty
    ``rpcGateway``.
    """
    m = _compose_mod()
    base = mpc_base.rstrip("/")
    url = f"{base}/getChainDetails?chain_id={chain_id_num}"
    try:
        api = m.http_get_json(url)
    except ValueError as e:
        raise ChainNotConfiguredError(
            f"GET /getChainDetails failed for chain_id={chain_id_num}: {e}. {_AGENT_ADD_CHAIN}"
        ) from e
    try:
        data = m._unwrap_management_api(api, "getChainDetails")
    except ValueError as e:
        raise ChainNotConfiguredError(
            f"getChainDetails API error for chain_id={chain_id_num}: {e}. {_AGENT_ADD_CHAIN}"
        ) from e

    rows: list[dict[str, Any]]
    if isinstance(data, list):
        rows = [x for x in data if isinstance(x, dict)]
    elif isinstance(data, dict):
        rows = [data]
    else:
        rows = []

    if not rows:
        raise ChainNotConfiguredError(
            f"Chain {chain_id_num} is not configured on this node (GET /getChainDetails returned "
            f"no rows). {_AGENT_ADD_CHAIN}"
        )

    want = str(chain_id_num)
    match: dict[str, Any] | None = None
    for row in rows:
        cid = row.get("chainId") if row.get("chainId") is not None else row.get("ChainId")
        if cid is not None and str(cid).strip() == want:
            match = row
            break

    if match is None:
        raise ChainNotConfiguredError(
            f"Chain {chain_id_num} is not configured on this node (no chainId={want} in "
            f"getChainDetails response). {_AGENT_ADD_CHAIN}"
        )

    rpc = m.pick_str(match, "rpcGateway", "RpcGateway", "rpc_gateway")
    if rpc is None or not str(rpc).strip():
        raise ChainNotConfiguredError(
            f"Chain {chain_id_num} exists on this node but rpcGateway is missing or empty. "
            f"Update with POST /postChainDetails or fix chain config. {_AGENT_ADD_CHAIN}"
        )

    return match


def resolve_evm_rpc_for_quote(
    *,
    chain_id_num: int,
    mpc_auth_url: str,
    management_port: str | int,
) -> tuple[str, dict[str, Any], str]:
    """Load RPC URL solely from **GET /getChainDetails** (field ``rpcGateway``)."""
    mpc = (mpc_auth_url or "").strip()
    if not mpc:
        raise ValueError(
            "permit2_keygen_params.py requires --mpc-auth-url (or MPC_AUTH_URL) to call GET /getChainDetails."
        )
    m = _compose_mod()
    base = m.resolve_mpc_auth_base(mpc, management_port)
    row = fetch_chain_details_strict(base, chain_id_num)
    gw = str(m.pick_str(row, "rpcGateway", "RpcGateway", "rpc_gateway") or "").strip()
    if not gw:
        raise ChainNotConfiguredError(
            f"Chain {chain_id_num}: rpcGateway empty after fetch. {_AGENT_ADD_CHAIN}"
        )
    return gw, row, "getChainDetails.rpcGateway"


def resolve_owner_from_keygen(
    *,
    mpc_auth_url: str,
    management_port: str | int,
    key_gen_id: str,
    owner_checksum: str,
) -> tuple[str, str]:
    """
    **GET /getKeyGenResultById** → ``ethereumaddress`` for ``key_gen_id``.

    If ``owner_checksum`` is non-empty, it must match that address (case-insensitive).
    """
    kgid = (key_gen_id or "").strip()
    if not kgid:
        raise ValueError("KEYGEN_ID is required (env KEYGEN_ID or --key-gen-id). permit2_keygen_params.py only supports KeyGen-derived owners.")
    mpc = (mpc_auth_url or "").strip()
    if not mpc:
        raise ValueError(
            "permit2_keygen_params.py requires --mpc-auth-url (or MPC_AUTH_URL) to call GET /getKeyGenResultById."
        )
    m = _compose_mod()
    base = m.resolve_mpc_auth_base(mpc, management_port)
    kg = m.fetch_keygen_bundle(base, kgid)
    eth = kg.get("ethereumaddress") or kg.get("EthereumAddress")
    if not eth or not isinstance(eth, str):
        raise ValueError("getKeyGenResultById: ethereumaddress missing for this KeyGen")
    derived = _addr("ethereumaddress from KeyGen", eth.strip())
    ovr = (owner_checksum or "").strip()
    if ovr and ovr.lower() != derived.lower():
        raise ValueError(
            f"--owner {ovr} does not match KeyGen ethereum address {derived}; remove --owner or fix KeyGen"
        )
    return derived, kgid


def _addr(name: str, a: str) -> str:
    s = (a or "").strip()
    if not _ADDR_RE.match(s):
        raise ValueError(f"{name} must be a 40-hex EVM address with 0x prefix")
    return s


def _rpc(url: str, method: str, params: list[Any]) -> Any:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(
        "utf-8"
    )
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "User-Agent": _HTTP_UA},
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        out = json.loads(resp.read().decode("utf-8"))
    if "error" in out and out["error"]:
        raise RuntimeError(str(out["error"]))
    return out.get("result")


def permit2_allowance_calldata(owner: str, token: str, spender: str) -> str:
    """``allowance(address,address,address)`` on Permit2."""
    sel = keccak(text="allowance(address,address,address)")[:4]
    packed = encode(
        ["address", "address", "address"],
        [_addr("owner", owner), _addr("token", token), _addr("spender", spender)],
    )
    return "0x" + (sel + packed).hex()


def eth_call_data(rpc_url: str, to: str, data: str) -> bytes:
    res = _rpc(rpc_url, "eth_call", [{"to": to, "data": data}, "latest"])
    if not res or not isinstance(res, str) or res in ("0x", "0X"):
        raise RuntimeError("eth_call returned empty result")
    h = res[2:] if res.startswith("0x") else res
    return bytes.fromhex(h)


def read_permit2_allowance(
    rpc_url: str,
    permit2: str,
    owner: str,
    token: str,
    spender: str,
) -> tuple[int, int, int]:
    """
    Call ``Permit2.allowance(owner, token, spender)`` → (uint160 amount, uint48 expiration, uint48 nonce).

    The **nonce** value is what you must place in ``PermitSingle.details.nonce`` for the *next* permit.
    """
    data = permit2_allowance_calldata(owner, token, spender)
    raw = eth_call_data(rpc_url, _addr("permit2", permit2), data)
    amount, expiration, nonce = decode(["uint160", "uint48", "uint48"], raw)
    return int(amount), int(expiration), int(nonce)


def _parse_int(s: str, name: str) -> int:
    t = (s or "").strip()
    if t.startswith("0x") or t.startswith("0X"):
        return int(t, 16)
    return int(t, 10)


def permit2_approval_cli_argv(
    chain_id: str,
    kwargs: dict[str, Any],
) -> list[str]:
    """
    ``argv`` fragment matching :mod:`permit2_approval` CLI (does not include mpc / key-gen-id).

    Keys are those from :func:`permit2_approval_only_kwargs` plus chain id.
    """
    m = {
        "permit2_address": "--permit2",
        "token": "--token",
        "amount": "--amount",
        "expiration": "--expiration",
        "permit_nonce": "--permit-nonce",
        "spender": "--spender",
        "sig_deadline": "--sig-deadline",
        "domain_name": "--domain-name",
        "msg_raw_hex": "--msg-raw",
        "destination_address": "--destination-address",
        "extra_json": "--extra-json",
        "purpose": "--purpose",
        "signature_text": "--signature-text",
        "value_wei": "--value",
        "client_id": "--client-id",
    }
    out: list[str] = ["--chain-id", str(chain_id)]
    for py_key, flag in m.items():
        if py_key not in kwargs:
            continue
        val = kwargs[py_key]
        if py_key == "extra_json" and isinstance(val, dict):
            out += [flag, json.dumps(val, separators=(",", ":"), ensure_ascii=False)]
        elif py_key == "signature_text" and isinstance(val, dict):
            out += [flag, json.dumps(val, separators=(",", ":"), ensure_ascii=False)]
        elif val is not None:
            out += [flag, str(val)]
    if kwargs.get("send_gas") is True:
        out.append("--send-gas")
    if kwargs.get("tx_params") is not None:
        out += ["--tx-params-json", json.dumps(kwargs["tx_params"], separators=(",", ":"))]
    if kwargs.get("proposal_tx_params") is not None:
        out += [
            "--proposal-tx-params-json",
            json.dumps(kwargs["proposal_tx_params"], separators=(",", ":")),
        ]
    if kwargs.get("skip_message_hash_verification"):
        out.append("--skip-message-hash-verification")
    if kwargs.get("key_list") is not None:
        out += ["--key-list-json", json.dumps(kwargs["key_list"], separators=(",", ":"))]
    return out


def build_permit2_keygen_output(
    *,
    rpc_url: str,
    chain_id: str,
    owner: str,
    token: str,
    spender: str,
    permit2: str,
    amount_in: int,
    expiration: int,
    sig_deadline: int,
    domain_name: str,
    purpose: str,
    fetch_nonce: bool,
    permit_nonce_override: int | None,
    external_quote: dict[str, Any] | None,
    rpc_source: str = "",
    chain_details_from_node: dict[str, Any] | None = None,
    key_gen_id: str | None = None,
) -> dict[str, Any]:
    chain_num = _parse_int(chain_id, "chain_id")
    _addr("owner", owner)
    _addr("token", token)
    _addr("spender", spender)
    _addr("permit2", permit2)
    if amount_in < 0 or amount_in > 2**160 - 1:
        raise ValueError("amount_in must fit uint160")
    if expiration < 0 or expiration > 2**48 - 1:
        raise ValueError("expiration must fit uint48")
    if sig_deadline < 0 or sig_deadline > 2**256 - 1:
        raise ValueError("sig_deadline must fit uint256")

    permit2_allowance_view: dict[str, Any]
    if fetch_nonce:
        view_amount, view_exp, view_nonce = read_permit2_allowance(
            rpc_url, permit2, owner, token, spender
        )
        permit_nonce = view_nonce
        permit2_allowance_view = {
            "amount": str(view_amount),
            "expiration": str(view_exp),
            "nonce": str(view_nonce),
        }
    elif permit_nonce_override is not None:
        permit_nonce = permit_nonce_override
        if permit_nonce < 0 or permit_nonce > 2**48 - 1:
            raise ValueError("permit_nonce override must fit uint48")
        permit2_allowance_view = {
            "note": "eth_call skipped; permit nonce from --permit-nonce",
            "nonce": str(permit_nonce),
        }
    else:
        raise ValueError("internal: fetch_nonce or permit_nonce_override required")

    chain_id_str = str(chain_id).strip()
    quote_extra: dict[str, Any] = {
        "source": "recipes/uniswapV4/permit2_keygen_params.py",
        "chainId": chain_id_str,
        "owner": owner,
        "evmRpcSource": rpc_source or "unknown",
    }
    if chain_details_from_node is not None:
        quote_extra["chainDetailsFromNode"] = chain_details_from_node
    if external_quote:
        quote_extra["external"] = external_quote

    uq_blob = uniswap_quote_object_from_blob(external_quote) if external_quote else None

    extra_for_api: dict[str, Any] = {"quote": quote_extra}
    if uq_blob:
        extra_for_api["uniswapTradeQuote"] = uq_blob

    p0 = (purpose or "").strip()
    if not p0 or p0 == DEFAULT_KEYGEN_PLACEHOLDER_PURPOSE:
        purpose_effective = default_multisign_purpose_for_permit2_swap(
            chain_id=chain_id_str,
            token=token,
            amount=amount_in,
            spender=spender,
            uniswap_context=uq_blob,
        )
    else:
        if len(p0) > PURPOSE_MAX_LEN:
            print(
                f"AI agent / operator: 'purpose' exceeds API maximum ({PURPOSE_MAX_LEN} characters); "
                f"truncating from {len(p0)}. Move details to --json-quote / extraJSON.",
                file=sys.stderr,
            )
        purpose_effective = p0[:PURPOSE_MAX_LEN]

    only = permit2_approval_only_kwargs(
        permit2_address=permit2,
        token=token,
        amount=amount_in,
        expiration=expiration,
        permit_nonce=permit_nonce,
        spender=spender,
        sig_deadline=sig_deadline,
        domain_name=domain_name,
        purpose=purpose_effective,
        extra_json=json.dumps(
            extra_for_api,
            separators=(",", ":"),
            ensure_ascii=False,
        ),
    )

    full_msg = eip712_permit_single_full_message(
        chain_id=chain_num,
        permit2=permit2,
        token=token,
        amount=amount_in,
        expiration=expiration,
        permit_nonce=permit_nonce,
        spender=spender,
        sig_deadline=sig_deadline,
        domain_name=domain_name,
    )
    digest_hex = permit2_eip712_digest_hex(full_msg)

    argv = permit2_approval_cli_argv(chain_id_str, only)

    out: dict[str, Any] = {
        "chainId": chain_id_str,
        "owner": owner,
        "evmRpcSource": rpc_source or "unknown",
        "permit2_allowance_view": permit2_allowance_view,
        "permit2_approval_only_kwargs": only,
        "permit2_approval_mpc_args_placeholder": {
            "mpc_auth_url": "${MPC_AUTH_URL:-http://127.0.0.1}",
            "management_port": "${MANAGEMENT_PORT:-8080}",
            "key_gen_id": key_gen_id or "${KEYGEN_ID}",
            "destination_chain_id": chain_id_str,
        },
        "eip712_digest_preview_hex": digest_hex,
        "permit2_approval_cli_argv": argv,
    }
    if chain_details_from_node is not None:
        out["chainDetailsFromNode"] = chain_details_from_node
    if key_gen_id:
        out["keyGenId"] = key_gen_id
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument(
        "--mpc-auth-url",
        default=None,
        metavar="URL",
        help=(
            "Required (or set env MPC_AUTH_URL). Management API base URL for GET /getChainDetails "
            "and GET /getKeyGenResultById. Chain must be configured on the node or the script exits "
            "with guidance for AI agents (POST /postChainDetails)."
        ),
    )
    ap.add_argument(
        "--management-port",
        default=(os.environ.get("MANAGEMENT_PORT") or "8080"),
        help="Management port when MPC_AUTH_URL has no port (env MANAGEMENT_PORT, default: %(default)s)",
    )
    ap.add_argument("--chain-id", required=True, help="Chain id (decimal or 0x hex)")
    ap.add_argument(
        "--key-gen-id",
        default=None,
        metavar="ID",
        help=(
            "KeyGen id for this run (must match permit2_approval). Default: env KEYGEN_ID. "
            "Owner is always GET /getKeyGenResultById → ethereumaddress."
        ),
    )
    ap.add_argument(
        "--owner",
        default="",
        help=(
            "Optional: if set, must match GET /getKeyGenResultById ethereumaddress (checksum). "
            "Owner is always derived from KeyGen; do not use this to substitute a different address."
        ),
    )
    ap.add_argument("--token", required=True, metavar="ADDR", help="ERC-20 token to permit")
    ap.add_argument(
        "--spender",
        default="default",
        metavar="ADDR|default",
        help=(
            "Permit2 spender: the contract authorized to pull tokens (e.g. Universal Router). "
            "Must NOT be the KeyGen wallet address — owner is always from KeyGen. "
            "Use \"default\" for built-in map by chain id, or pass an explicit address."
        ),
    )
    ap.add_argument(
        "--permit2",
        default=DEFAULT_PERMIT2,
        metavar="ADDR",
        help=f"Permit2 contract (default: canonical {DEFAULT_PERMIT2})",
    )
    ap.add_argument(
        "--amount-in",
        required=False,
        default="",
        help="uint160 approval amount (smallest token units). Required unless --amount-max-uint160",
    )
    ap.add_argument(
        "--amount-max-uint160",
        action="store_true",
        help="Set permit amount to 2**160-1 (full uint160 range)",
    )
    ap.add_argument(
        "--expiration",
        default="",
        help=f"uint48 PermitDetails.expiration (unix time). Default: {2**48 - 1} (max uint48)",
    )
    ap.add_argument(
        "--sig-deadline",
        default="",
        help="uint256 sigDeadline (unix). Default: now + --sig-deadline-seconds",
    )
    ap.add_argument(
        "--sig-deadline-seconds",
        type=int,
        default=3600,
        help="When --sig-deadline omitted: deadline = now + this (default: 3600)",
    )
    ap.add_argument("--domain-name", default="Permit2", help="EIP-712 domain.name")
    ap.add_argument(
        "--purpose",
        default=DEFAULT_KEYGEN_PLACEHOLDER_PURPOSE,
        help=(
            f"POST /multiSignRequest 'purpose' (max {PURPOSE_MAX_LEN} characters, API hard limit). "
            "AI agent: use at most 256; put long quote text in --json-quote / extraJSON, not here. "
            "Default/placeholder is replaced by a Uniswap-oriented summary; set explicitly to override."
        ),
    )
    ap.add_argument(
        "--skip-fetch-nonce",
        action="store_true",
        help="Do not eth_call Permit2.allowance; require --permit-nonce",
    )
    ap.add_argument(
        "--permit-nonce",
        default="",
        help="uint48 nonce (required with --skip-fetch-nonce)",
    )
    ap.add_argument(
        "--json-quote",
        default="",
        metavar="JSON",
        help='Optional JSON from an external quoter merged into output (e.g. V4 quote: {"amountIn":"..."})',
    )
    ap.add_argument(
        "--format",
        choices=("json", "argv-fork-args-only"),
        default="json",
        help="json: full object; argv-fork-args-only: space-safe args for permit2_approval.py",
    )
    args = ap.parse_args()
    chain_num = _parse_int(args.chain_id, "chain_id")
    key_gen_id = ((args.key_gen_id if args.key_gen_id is not None else "") or (os.environ.get("KEYGEN_ID") or "")).strip()
    mpc_url = ((args.mpc_auth_url if args.mpc_auth_url is not None else "") or (os.environ.get("MPC_AUTH_URL") or "")).strip()

    if not key_gen_id:
        print(
            "permit2_keygen_params.py requires KEYGEN_ID (environment) or --key-gen-id. "
            "This script only derives the permit owner from GET /getKeyGenResultById.",
            file=sys.stderr,
        )
        sys.exit(1)
    if not mpc_url:
        print(
            "permit2_keygen_params.py requires --mpc-auth-url or MPC_AUTH_URL for GET /getChainDetails and GET /getKeyGenResultById.",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        rpc_effective, chain_row, rpc_src = resolve_evm_rpc_for_quote(
            chain_id_num=chain_num,
            mpc_auth_url=mpc_url,
            management_port=args.management_port,
        )
    except (ChainNotConfiguredError, ValueError) as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)

    try:
        owner_addr, key_gen_id_used = resolve_owner_from_keygen(
            mpc_auth_url=mpc_url,
            management_port=args.management_port,
            key_gen_id=key_gen_id,
            owner_checksum=(args.owner or "").strip(),
        )
    except ValueError as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)

    spender_arg = (args.spender or "").strip()
    if spender_arg.lower() == "default":
        sp = DEFAULT_SPENDER_BY_CHAIN_ID.get(chain_num)
        if not sp:
            raise ValueError(
                f"No default Universal Router (spender) for chain id {chain_num}; "
                "pass --spender explicitly"
            )
        spender = sp
    else:
        spender = _addr("spender", spender_arg)

    ext: dict[str, Any] | None = None
    if args.json_quote.strip():
        ext = json.loads(args.json_quote)
        if not isinstance(ext, dict):
            raise ValueError("--json-quote must be a JSON object")

    if args.amount_max_uint160:
        amt = 2**160 - 1
    elif args.amount_in.strip():
        amt = _parse_int(args.amount_in, "amount_in")
    else:
        raise ValueError("Provide --amount-in or --amount-max-uint160")

    if args.expiration.strip():
        exp = _parse_int(args.expiration, "expiration")
    else:
        exp = 2**48 - 1

    if args.sig_deadline.strip():
        sd = _parse_int(args.sig_deadline, "sig_deadline")
    else:
        sd = int(time.time()) + int(args.sig_deadline_seconds)

    fetch_nonce = not args.skip_fetch_nonce
    nonce_override: int | None = None
    if args.skip_fetch_nonce:
        if not args.permit_nonce.strip():
            raise ValueError("--skip-fetch-nonce requires --permit-nonce")
        nonce_override = _parse_int(args.permit_nonce, "permit_nonce")
        fetch_nonce = False

    try:
        out_payload = build_permit2_keygen_output(
            rpc_url=rpc_effective,
            chain_id=args.chain_id,
            owner=owner_addr,
            token=args.token,
            spender=spender,
            permit2=args.permit2,
            amount_in=amt,
            expiration=exp,
            sig_deadline=sd,
            domain_name=args.domain_name,
            purpose=args.purpose,
            fetch_nonce=fetch_nonce,
            permit_nonce_override=nonce_override,
            external_quote=ext,
            rpc_source=rpc_src,
            chain_details_from_node=chain_row,
            key_gen_id=key_gen_id_used,
        )
    except (ValueError, RuntimeError, urllib.error.URLError) as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)

    if args.format == "json":
        print(json.dumps(out_payload, indent=2))
        return

    # argv for: python3 .../permit2_approval.py --key-gen-id ... --mpc-auth-url ... [fragment]
    frag = out_payload["permit2_approval_cli_argv"]
    print(" ".join(shlex.quote(x) for x in frag))


if __name__ == "__main__":
    main()
