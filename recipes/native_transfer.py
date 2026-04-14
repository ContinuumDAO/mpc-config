#!/usr/bin/env python3
"""
Build a POST /multiSignRequest payload for a native chain currency transfer
(ETH on Ethereum, LINEA on Linea, etc.): to an address with empty calldata and
non-zero tx value.

Uses compose **nativeTransfer** (see scripts/generateMultiSignRequestFromCompose.py).
RPC comes from GET /getChainDetails when --rpc-gateway is omitted. Gas defaults match
``linea_register`` / other recipes: chain fields when set, else **eth_estimateGas**;
**--no-custom-gas-params** forces RPC-only (see ``build_native_transfer_compose``).

Requires: PyNaCl, eth_account (same as scripts/generateMultiSignRequestFromCompose.py).

**Expectations for an AI agent (amount handling)**

This recipe sends the chain **native** currency (ETH, LINEA, etc.), not an ERC-20. **GET /getTokens**
**decimals** do **not** apply here. ``--amount-unit`` selects compose scaling: **Wei** = smallest
units (pass an integer string); **Ether** = 18 decimal places on standard EVM native transfers;
**Gwei** / **USD** follow the compose script’s fixed scales. Do **not** confuse with a token’s
stored ``decimals`` from the asset list—there is no automatic lookup for native transfers.

Example::

  python3 recipes/native_transfer.py \\
    --key-gen-id KeyGen2026... \\
    --chain-id 59144 \\
    --to 0x... \\
    --amount 0.01 --amount-unit Ether
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

_VALID_UNITS = frozenset({"Wei", "Ether", "Gwei", "USD"})


def _normalize_address(addr: str, name: str) -> str:
    s = (addr or "").strip()
    if not s:
        raise ValueError(f"{name} is required")
    if not re.match(r"^0x[0-9a-fA-F]{40}$", s):
        raise ValueError(f"{name} must be a 40-hex-prefixed EVM address (0x…)")
    return s


def build_native_transfer_compose(
    key_gen_id: str,
    destination_chain_id: str,
    to_address: str,
    amount: str,
    amount_unit: str = "Wei",
    purpose: str = "",
    no_custom_gas_params: bool = False,
    rpc_gateway: str | None = None,
) -> dict[str, Any]:
    """Compose JSON for native transfer; destinationContract is the recipient.

    When ``noCustomGasParams`` is **false** (default), ``generateMultiSignRequestFromCompose``
    uses **GET /getChainDetails** gas fields **when set**; if **gasLimit** is empty, it uses
    ``eth_estimateGas``. When ``noCustomGasParams`` is **true**, chain gas fields are ignored
    and limits/fees come from the RPC only (see compose script).
    """
    pid = (key_gen_id or "").strip()
    if not pid:
        raise ValueError("keyGenId is required")
    chain = (destination_chain_id or "").strip()
    if not chain:
        raise ValueError("destinationChainId (--chain-id) is required")
    to_addr = _normalize_address(to_address, "recipient (--to)")
    amt = (amount or "").strip()
    if not amt:
        raise ValueError("amount is required")
    unit = (amount_unit or "Wei").strip()
    if unit not in _VALID_UNITS:
        raise ValueError(f"amount-unit must be one of: {', '.join(sorted(_VALID_UNITS))}")

    out: dict[str, Any] = {
        "keyGenId": pid,
        "destinationChainId": chain,
        "composeActions": [
            {
                "nativeTransfer": True,
                "destinationContract": to_addr,
                "inputs": [
                    {"name": "value", "type": "uint256", "value": amt},
                ],
                "paramUnits": {"0": unit},
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


def native_transfer_multisign_payload(
    mpc_auth_url: str,
    management_port: str | int,
    key_gen_id: str,
    destination_chain_id: str,
    to_address: str,
    amount: str,
    amount_unit: str = "Wei",
    purpose: str = "",
    no_custom_gas_params: bool = False,
    rpc_gateway: str | None = None,
) -> dict[str, Any]:
    compose = build_native_transfer_compose(
        key_gen_id=key_gen_id,
        destination_chain_id=destination_chain_id,
        to_address=to_address,
        amount=amount,
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
            "Build multiSignRequest JSON for a native currency transfer (gas token) "
            "to --to. Uses GET /getChainDetails?chain_id=<n> unless --rpc-gateway is set. "
            "AI agents: native transfers do not use GET /getTokens decimals; set --amount-unit "
            "explicitly (Wei for raw wei, Ether for 18-decimal human amounts on typical EVM chains)."
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
        help="Destination chain id (decimal, e.g. 59144, or hex 0x...)",
    )
    ap.add_argument(
        "--to",
        required=True,
        metavar="ADDR",
        help="Recipient address (receives the native transfer)",
    )
    ap.add_argument(
        "--amount",
        required=True,
        help=(
            "Native value to send: interpret with --amount-unit (not token decimals from getTokens)."
        ),
    )
    ap.add_argument(
        "--amount-unit",
        default="Wei",
        choices=sorted(_VALID_UNITS),
        help=(
            "Wei | Ether | Gwei | USD for the tx value (default: Wei). Compose scales only; "
            "unrelated to ERC-20 decimals in GET /getTokens."
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

    try:
        out = native_transfer_multisign_payload(
            mpc_auth_url=args.mpc_auth_url,
            management_port=args.management_port,
            key_gen_id=args.key_gen_id,
            destination_chain_id=args.chain_id,
            to_address=args.to,
            amount=args.amount,
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
