#!/usr/bin/env python3
"""
Build a POST /multiSignRequest payload for CTMERC20 **c3transfer(string,uint256,string)**.

This matches the **Add Asset / getTokens** defaults for **CTMERC20** in
``docs/references/TOKEN_STORAGE_SCHEMA.md``:

- **transferSig:** ``c3transfer(string,uint256,string)``
- **transferNames:** ``toStr``, ``amount``, ``toChainIdStr``

The MPC transaction is submitted on **--chain-id** (where the CTMERC20 contract
lives). **--to-chain-id** is the third argument (destination chain for the
transfer, often the same as ``--chain-id`` for same-chain; set explicitly for
cross-chain). Gas defaults match ``linea_register`` (chain fields when set, else
**eth_estimateGas**; **--no-custom-gas-params** for RPC-only).

Requires: PyNaCl, eth_account (same as scripts/generateMultiSignRequestFromCompose.py).

**Expectations for an AI agent (amount handling)**

Same rules as ``erc20_transfer.py``: **Wei** / **Ether** / **Gwei** / **USD** are compose
``paramUnits`` scales (Ether = 18 decimal places in the compose layer). **GET /getTokens**
must list this **CTMERC20** contract under ``ethereum[]`` for ``--chain-id`` with a
**decimals** field if you omit ``--amount-unit`` and pass a human token amount; otherwise
pass ``--amount-unit`` (use **Wei** for raw uint256 strings) or register **decimals** via
**POST /addToken**.

Example::

  python3 recipes/ctmerc20_transfer.py \\
    --key-gen-id KeyGen2026... \\
    --chain-id 59144 \\
    --token 0x... \\
    --to 0xRecipient... \\
    --amount 100 --amount-unit Wei

  # Cross-chain destination (third calldata arg differs from tx chain):
  python3 recipes/ctmerc20_transfer.py \\
    --key-gen-id KeyGen2026... --chain-id 59144 --to-chain-id 1 \\
    --token 0x... --to 0x... --amount 1 --amount-unit Ether
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
import recipe_gas_precheck as _gas
import recipe_token_metadata as _tokmeta

# From TOKEN_STORAGE_SCHEMA.md — CTMERC20 defaults (GET /getTokens → ethereum[].CTMERC20).
CTMERC20_TRANSFER_SIG = "c3transfer(string,uint256,string)"
CTMERC20_INPUT_NAMES = ("toStr", "amount", "toChainIdStr")

_VALID_UNITS = frozenset({"Wei", "Ether", "Gwei", "USD"})


def _normalize_address(addr: str, name: str) -> str:
    s = (addr or "").strip()
    if not s:
        raise ValueError(f"{name} is required")
    if not re.match(r"^0x[0-9a-fA-F]{40}$", s):
        raise ValueError(f"{name} must be a 40-hex-prefixed EVM address (0x…)")
    return s


def _normalize_chain_id_str(chain_id: str, label: str) -> str:
    """Pass chain id through; ensure non-empty (used as Solidity string)."""
    s = (chain_id or "").strip()
    if not s:
        raise ValueError(f"{label} is required")
    return s


def build_ctmerc20_c3transfer_compose(
    key_gen_id: str,
    destination_chain_id: str,
    token_contract: str,
    to_address: str,
    amount: str,
    to_chain_id_str: str,
    amount_unit: str = "Wei",
    purpose: str = "",
    no_custom_gas_params: bool = False,
    rpc_gateway: str | None = None,
) -> dict[str, Any]:
    """Compose JSON for CTMERC20 c3transfer; RPC from getChainDetails unless rpc_gateway set.

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
    to_addr = _normalize_address(to_address, "recipient (--to)")
    amt = (amount or "").strip()
    if not amt:
        raise ValueError("amount is required")
    unit = (amount_unit or "Wei").strip()
    if unit not in _VALID_UNITS:
        raise ValueError(f"amount-unit must be one of: {', '.join(sorted(_VALID_UNITS))}")
    to_chain = _normalize_chain_id_str(to_chain_id_str, "toChainIdStr (--to-chain-id)")

    out: dict[str, Any] = {
        "keyGenId": pid,
        "destinationChainId": chain,
        "composeActions": [
            {
                "signature": CTMERC20_TRANSFER_SIG,
                "destinationContract": token,
                "inputs": [
                    {"name": CTMERC20_INPUT_NAMES[0], "type": "string", "value": to_addr},
                    {"name": CTMERC20_INPUT_NAMES[1], "type": "uint256", "value": amt},
                    {"name": CTMERC20_INPUT_NAMES[2], "type": "string", "value": to_chain},
                ],
                "paramUnits": {"1": unit},
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


def ctmerc20_transfer_multisign_payload(
    mpc_auth_url: str,
    management_port: str | int,
    key_gen_id: str,
    destination_chain_id: str,
    token_contract: str,
    to_address: str,
    amount: str,
    to_chain_id_str: str,
    amount_unit: str = "Wei",
    purpose: str = "",
    no_custom_gas_params: bool = False,
    rpc_gateway: str | None = None,
    skip_gas_check: bool = False,
) -> dict[str, Any]:
    compose = build_ctmerc20_c3transfer_compose(
        key_gen_id=key_gen_id,
        destination_chain_id=destination_chain_id,
        token_contract=token_contract,
        to_address=to_address,
        amount=amount,
        to_chain_id_str=to_chain_id_str,
        amount_unit=amount_unit,
        purpose=purpose,
        no_custom_gas_params=no_custom_gas_params,
        rpc_gateway=rpc_gateway,
    )
    base = _compose.resolve_mpc_auth_base(mpc_auth_url, management_port)
    if not skip_gas_check:
        _gas.require_native_gas_for_compose(compose, base)
    return _compose.build_compose_multisign(compose, base)


def main() -> None:
    ap = argparse.ArgumentParser(
        description=(
            "Build multiSignRequest JSON for CTMERC20 c3transfer(string,uint256,string) "
            "(see TOKEN_STORAGE_SCHEMA.md). Transaction chain is --chain-id; "
            "calldata destination chain is --to-chain-id (default: same as --chain-id). "
            "For AI agents: omit --amount-unit only if GET /getTokens has decimals for this "
            "CTMERC20 on this chain; otherwise set --amount-unit or add decimals via POST /addToken."
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
        required=True,
        metavar="ID",
        help="Chain where the CTMERC20 contract lives (tx destinationChainId); decimal or 0x...",
    )
    ap.add_argument(
        "--to-chain-id",
        default="",
        metavar="ID",
        help="Third argument toChainIdStr (destination chain for the transfer); "
        "default: same as --chain-id",
    )
    ap.add_argument(
        "--token",
        required=True,
        metavar="ADDR",
        help="CTMERC20 contract address",
    )
    ap.add_argument(
        "--to",
        required=True,
        metavar="ADDR",
        help="Recipient address (passed as string toStr)",
    )
    ap.add_argument(
        "--amount",
        required=True,
        help=(
            "uint256 amount for c3transfer: with explicit --amount-unit, value is in that unit. "
            "If --amount-unit is omitted, value is in token units and GET /getTokens must list "
            "decimals for this CTMERC20 on this chain. Agents: use Wei + integer string for raw amounts."
        ),
    )
    ap.add_argument(
        "--amount-unit",
        default=None,
        metavar="UNIT",
        help=(
            "Wei | Ether | Gwei | USD (compose paramUnits). Omit only when GET /getTokens has "
            "decimals for this CTMERC20 contract on this chain. If missing, pass this flag or "
            "update token metadata (POST /addToken)."
        ),
    )
    ap.add_argument(
        "--purpose",
        default="",
        help="Purpose string for reviewers (optional)",
    )
    ap.add_argument(
        "--no-custom-gas-params",
        action="store_true",
        help=(
            "Set noCustomGasParams on compose JSON: ignore ChainDetails gas fields and use RPC-only "
            "estimates. Default (flag omitted): use chain gas when configured, otherwise eth_estimateGas."
        ),
    )
    ap.add_argument(
        "--skip-gas-check",
        action="store_true",
        help=(
            "Skip verifying the MPC wallet native balance against estimated gas (not recommended). "
            "By default the script requires balance ≥ estimated fees with 50% extra on gas units."
        ),
    )
    ap.add_argument(
        "--rpc-gateway",
        default="",
        metavar="URL",
        help="Override JSON-RPC URL; if omitted, use rpcGateway from getChainDetails",
    )
    ap.add_argument(
        "--ed25519-seed-hex",
        metavar="HEX",
        help="If set, sign messageToSign with Ed25519 and add postBody.clientSig",
    )
    ap.add_argument(
        "--eip191-private-key-hex",
        metavar="HEX",
        help="If set, sign with MetaMask-style personal_sign and add postBody",
    )
    args = ap.parse_args()

    rpc = args.rpc_gateway.strip() or None
    to_chain = (args.to_chain_id or "").strip() or args.chain_id.strip()

    try:
        amount = args.amount.strip()
        amount_unit = args.amount_unit
        if amount_unit is not None:
            u = amount_unit.strip()
            if u not in _VALID_UNITS:
                raise ValueError(
                    f"amount-unit must be one of: {', '.join(sorted(_VALID_UNITS))}"
                )
            amount_unit = u
        else:
            base = _compose.resolve_mpc_auth_base(args.mpc_auth_url, args.management_port)
            chain_id_num = _compose.parse_chain_id(args.chain_id)
            dec = _tokmeta.fetch_decimals_from_get_tokens(
                base,
                chain_id_num,
                args.token,
                category="CTMERC20",
                http_get_json=_compose.http_get_json,
                unwrap_management_api=_compose._unwrap_management_api,
            )
            if dec is None:
                raise ValueError(
                    "Cannot infer amount scaling: --amount-unit was not set and GET /getTokens has "
                    "no decimals for this CTMERC20 on this chain (or the token is not listed). "
                    "As an AI agent: pass --amount-unit (Wei with the raw uint256 string if needed), "
                    "or register the token with decimals (e.g. POST /addToken)."
                )
            amount = _tokmeta.human_amount_to_raw_uint256(amount, dec)
            amount_unit = "Wei"

        out = ctmerc20_transfer_multisign_payload(
            mpc_auth_url=args.mpc_auth_url,
            management_port=args.management_port,
            key_gen_id=args.key_gen_id,
            destination_chain_id=args.chain_id,
            token_contract=args.token,
            to_address=args.to,
            amount=amount,
            to_chain_id_str=to_chain,
            amount_unit=amount_unit,
            purpose=args.purpose,
            no_custom_gas_params=args.no_custom_gas_params,
            rpc_gateway=rpc,
            skip_gas_check=args.skip_gas_check,
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
