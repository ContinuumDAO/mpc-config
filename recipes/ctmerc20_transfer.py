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
cross-chain).

Requires: PyNaCl, eth_account (same as scripts/generateMultiSignRequestFromCompose.py).

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
    """
    Compose JSON for CTMERC20 c3transfer; RPC from getChainDetails unless rpc_gateway set.
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
    return _compose.build_compose_multisign(compose, base)


def main() -> None:
    ap = argparse.ArgumentParser(
        description=(
            "Build multiSignRequest JSON for CTMERC20 c3transfer(string,uint256,string) "
            "(see TOKEN_STORAGE_SCHEMA.md). Transaction chain is --chain-id; "
            "calldata destination chain is --to-chain-id (default: same as --chain-id)."
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
        help='Token amount (with --amount-unit; e.g. "1.5" with Ether)',
    )
    ap.add_argument(
        "--amount-unit",
        default="Wei",
        choices=sorted(_VALID_UNITS),
        help="Unit for uint256 amount (default: Wei). Matches compose paramUnits.",
    )
    ap.add_argument(
        "--purpose",
        default="",
        help="Purpose string for reviewers (optional)",
    )
    ap.add_argument(
        "--no-custom-gas-params",
        action="store_true",
        help="Ignore ChainDetails gas fields; estimate gas limit and fees only from the RPC",
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
        out = ctmerc20_transfer_multisign_payload(
            mpc_auth_url=args.mpc_auth_url,
            management_port=args.management_port,
            key_gen_id=args.key_gen_id,
            destination_chain_id=args.chain_id,
            token_contract=args.token,
            to_address=args.to,
            amount=args.amount,
            to_chain_id_str=to_chain,
            amount_unit=args.amount_unit,
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
