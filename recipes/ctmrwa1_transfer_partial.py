#!/usr/bin/env python3
"""
Build a POST /multiSignRequest payload for CTMRWA1 **transferPartialTokenX** (partial balance).

Matches **CTMRWA1** defaults in ``docs/references/TOKEN_STORAGE_SCHEMA.md`` / **CTMRWA1X.sol**:

- **transferPartialSig:** ``transferPartialTokenX(uint256,string,string,uint256,uint256,uint256,string)``
- **transferPartialNames:** ``fromTokenId``, ``toAddressStr``, ``toChainIdStr``, ``value``, ``ID``, ``version``, ``feeTokenStr``

The **value** field uses **--value-unit** (default **Wei**) like other compose uint256 amounts.
Gas defaults match ``linea_register`` (chain fields when set, else **eth_estimateGas**;
**--no-custom-gas-params** for RPC-only).

**Expectations for an AI agent (value / decimals)**

``--value`` with ``--value-unit`` uses **compose** units (**Wei** = raw smallest units; **Ether** =
18 decimal places in the compose conversion layer). That is **not** automatically the same as an
ERC-20 **decimals** field from **GET /getTokens** for some other asset. For a **raw on-chain**
partial balance from simulation or the contract, use **Wei** and an integer string. If the
protocol documents that ``value`` is 18-decimal–style, **Ether** may apply; do **not** assume
without checking project docs or on-chain behavior.

Requires: PyNaCl, eth_account (same as scripts/generateMultiSignRequestFromCompose.py).

Example::

  python3 recipes/ctmrwa1_transfer_partial.py \\
    --key-gen-id KeyGen2026... --chain-id 59144 --token 0x... \\
    --from-token-id 1001 --to 0xRecipient... \\
    --value 1.5 --value-unit Ether \\
    --id 42 --version 1 --fee-token-str 0x...
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

_scripts_dir = Path(__file__).resolve().parent.parent / "scripts"
if str(_scripts_dir) not in sys.path:
    sys.path.insert(0, str(_scripts_dir))

import generateMultiSignRequestFromCompose as _compose

PARTIAL_SIG = "transferPartialTokenX(uint256,string,string,uint256,uint256,uint256,string)"
PARTIAL_NAMES = (
    "fromTokenId",
    "toAddressStr",
    "toChainIdStr",
    "value",
    "ID",
    "version",
    "feeTokenStr",
)

_VALID_UNITS = frozenset({"Wei", "Ether", "Gwei", "USD"})


def _normalize_address(addr: str, name: str) -> str:
    s = (addr or "").strip()
    if not s:
        raise ValueError(f"{name} is required")
    if not re.match(r"^0x[0-9a-fA-F]{40}$", s):
        raise ValueError(f"{name} must be a 40-hex-prefixed EVM address (0x…)")
    return s


def _normalize_chain_id_str(chain_id: str, label: str) -> str:
    s = (chain_id or "").strip()
    if not s:
        raise ValueError(f"{label} is required")
    return s


def _require_uint_str(label: str, v: str) -> str:
    s = (v or "").strip()
    if not s:
        raise ValueError(f"{label} is required")
    return s


def _normalize_fee_token_str(s: str) -> str:
    return (s or "").strip()


def build_ctmrwa1_partial_compose(
    key_gen_id: str,
    destination_chain_id: str,
    token_contract: str,
    from_token_id: str,
    to_address_str: str,
    to_chain_id_str: str,
    value: str,
    value_unit: str,
    rwa_id: str,
    version: str,
    fee_token_str: str,
    purpose: str = "",
    no_custom_gas_params: bool = False,
    rpc_gateway: str | None = None,
) -> dict[str, Any]:
    """Compose JSON for CTMRWA1 ``transferPartialTokenX``; RPC from getChainDetails unless rpc_gateway set.

    When ``noCustomGasParams`` is **false** (default), ``generateMultiSignRequestFromCompose``
    uses **GET /getChainDetails** gas fields **when set**; if **gasLimit** is empty, it uses
    ``eth_estimateGas``. When ``noCustomGasParams`` is **true**, chain gas fields are ignored
    and limits/fees come from the RPC only (see compose script).
    """
    pid = (key_gen_id or "").strip()
    if not pid:
        raise ValueError("keyGenId is required")
    chain = _normalize_chain_id_str(destination_chain_id, "destinationChainId (--chain-id)")
    token = _normalize_address(token_contract, "token contract")
    to_a = _normalize_address(to_address_str, "recipient (--to)")
    to_chain = _normalize_chain_id_str(to_chain_id_str, "toChainIdStr (--to-chain-id)")
    ft = _normalize_fee_token_str(fee_token_str)

    fid = _require_uint_str("fromTokenId (--from-token-id)", from_token_id)
    val = (value or "").strip()
    if not val:
        raise ValueError("value (--value) is required")
    vu = (value_unit or "Wei").strip()
    if vu not in _VALID_UNITS:
        raise ValueError(f"value-unit must be one of: {', '.join(sorted(_VALID_UNITS))}")
    rid = _require_uint_str("ID (--id)", rwa_id)
    ver = _require_uint_str("version (--version)", version)

    out: dict[str, Any] = {
        "keyGenId": pid,
        "destinationChainId": chain,
        "composeActions": [
            {
                "signature": PARTIAL_SIG,
                "destinationContract": token,
                "inputs": [
                    {"name": PARTIAL_NAMES[0], "type": "uint256", "value": fid},
                    {"name": PARTIAL_NAMES[1], "type": "string", "value": to_a},
                    {"name": PARTIAL_NAMES[2], "type": "string", "value": to_chain},
                    {"name": PARTIAL_NAMES[3], "type": "uint256", "value": val},
                    {"name": PARTIAL_NAMES[4], "type": "uint256", "value": rid},
                    {"name": PARTIAL_NAMES[5], "type": "uint256", "value": ver},
                    {"name": PARTIAL_NAMES[6], "type": "string", "value": ft},
                ],
                "paramUnits": {"0": "Wei", "3": vu, "4": "Wei", "5": "Wei"},
            }
        ],
    }
    p = (purpose or "").strip()
    if p:
        out["purpose"] = p
    rg = (rpc_gateway or "").strip()
    if rg:
        out["rpcGateway"] = rg
    if no_custom_gas_params:
        out["noCustomGasParams"] = True
    return out


def ctmrwa1_partial_multisign_payload(
    mpc_auth_url: str,
    management_port: str | int,
    key_gen_id: str,
    destination_chain_id: str,
    token_contract: str,
    from_token_id: str,
    to_address_str: str,
    to_chain_id_str: str,
    value: str,
    value_unit: str,
    rwa_id: str,
    version: str,
    fee_token_str: str,
    purpose: str = "",
    no_custom_gas_params: bool = False,
    rpc_gateway: str | None = None,
) -> dict[str, Any]:
    compose = build_ctmrwa1_partial_compose(
        key_gen_id=key_gen_id,
        destination_chain_id=destination_chain_id,
        token_contract=token_contract,
        from_token_id=from_token_id,
        to_address_str=to_address_str,
        to_chain_id_str=to_chain_id_str,
        value=value,
        value_unit=value_unit,
        rwa_id=rwa_id,
        version=version,
        fee_token_str=fee_token_str,
        purpose=purpose,
        no_custom_gas_params=no_custom_gas_params,
        rpc_gateway=rpc_gateway,
    )
    base = _compose.resolve_mpc_auth_base(mpc_auth_url, management_port)
    return _compose.build_compose_multisign(compose, base)


def main() -> None:
    ap = argparse.ArgumentParser(
        description=(
            "CTMRWA1 partial transfer: transferPartialTokenX (TOKEN_STORAGE_SCHEMA.md). "
            "AI agents: --value-unit selects compose scaling (Wei/Ether/Gwei/USD); it is not "
            "automatically the token’s decimals from GET /getTokens—use Wei for raw uint256 amounts."
        )
    )
    ap.add_argument(
        "--mpc-auth-url",
        default=(os.environ.get("MPC_AUTH_URL") or _compose.DEFAULT_MPC_AUTH_URL),
        help="Management API host URL (env MPC_AUTH_URL)",
    )
    ap.add_argument(
        "--management-port",
        default=(os.environ.get("MANAGEMENT_PORT") or _compose.DEFAULT_MANAGEMENT_PORT),
        help="Management API port (env MANAGEMENT_PORT)",
    )
    ap.add_argument("--key-gen-id", required=True, metavar="ID")
    ap.add_argument("--chain-id", required=True, help="Chain of the CTMRWA1 contract (tx chain)")
    ap.add_argument(
        "--to-chain-id",
        default="",
        help="toChainIdStr; default: same as --chain-id",
    )
    ap.add_argument("--token", required=True, metavar="ADDR", help="CTMRWA1 contract address")
    ap.add_argument("--from-token-id", required=True, help="uint256 fromTokenId")
    ap.add_argument("--to", required=True, metavar="ADDR", help="toAddressStr (recipient)")
    ap.add_argument(
        "--value",
        required=True,
        help=(
            "uint256 partial value: combine with --value-unit (compose units; use Wei for raw amounts)."
        ),
    )
    ap.add_argument(
        "--value-unit",
        default="Wei",
        choices=sorted(_VALID_UNITS),
        help=(
            "Wei | Ether | Gwei | USD for the value field (default: Wei). Compose layer scales; "
            "do not assume this equals an arbitrary ERC-20 decimals from GET /getTokens."
        ),
    )
    ap.add_argument("--id", required=True, dest="rwa_id", help="uint256 RWA token ID")
    ap.add_argument("--version", required=True, help="uint256 contract version")
    ap.add_argument(
        "--fee-token-str",
        default="",
        help="feeTokenStr (opaque string, e.g. fee token address)",
    )
    ap.add_argument("--purpose", default="")
    ap.add_argument(
        "--no-custom-gas-params",
        action="store_true",
        help=(
            "Set noCustomGasParams on compose JSON: ignore ChainDetails gas fields and use RPC-only "
            "estimates. Default (flag omitted): use chain gas when configured, otherwise eth_estimateGas."
        ),
    )
    ap.add_argument("--rpc-gateway", default="", metavar="URL")
    ap.add_argument("--ed25519-seed-hex", metavar="HEX", default="")
    ap.add_argument("--eip191-private-key-hex", metavar="HEX", default="")
    args = ap.parse_args()

    rpc = args.rpc_gateway.strip() or None
    to_chain = (args.to_chain_id or "").strip() or args.chain_id.strip()

    try:
        out = ctmrwa1_partial_multisign_payload(
            mpc_auth_url=args.mpc_auth_url,
            management_port=args.management_port,
            key_gen_id=args.key_gen_id,
            destination_chain_id=args.chain_id,
            token_contract=args.token,
            from_token_id=args.from_token_id,
            to_address_str=args.to,
            to_chain_id_str=to_chain,
            value=args.value,
            value_unit=args.value_unit,
            rwa_id=args.rwa_id,
            version=args.version,
            fee_token_str=args.fee_token_str,
            purpose=args.purpose,
            no_custom_gas_params=args.no_custom_gas_params,
            rpc_gateway=rpc,
        )
    except (ValueError, RuntimeError) as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)

    if args.ed25519_seed_hex:
        sig = _compose.sign_ed25519(out["messageToSign"], args.ed25519_seed_hex)
        out["postBody"] = {**out["bodyForSign"], "clientSig": sig, "signedMessage": ""}
    elif args.eip191_private_key_hex:
        sig = _compose.sign_eip191(out["messageToSign"], args.eip191_private_key_hex)
        out["postBody"] = {
            **out["bodyForSign"],
            "clientSig": sig,
            "signedMessage": out["messageToSign"],
        }

    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
