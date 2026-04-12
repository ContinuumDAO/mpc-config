#!/usr/bin/env python3
"""
Build a POST /multiSignRequest payload for a standard ERC-20 transfer(address,uint256),
using the node's stored RPC from GET /getChainDetails when rpcGateway is omitted.

Optional --use-custom-gas-config applies gas limit and fee multipliers from chain details
(same as the Compose "Use Custom Gas Config" checkbox in continuumdao-node-app).

Requires: PyNaCl, eth_account (same as scripts/generateMultiSignRequestFromCompose.py).

Example::

  python3 recipes/erc20_transfer.py \\
    --key-gen-id KeyGen2026... \\
    --chain-id 59144 \\
    --token 0x... \\
    --to 0x... \\
    --amount 1.5 --amount-unit Ether

  python3 recipes/erc20_transfer.py \\
    --key-gen-id KeyGen2026... --chain-id 1 \\
    --token 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 \\
    --to 0x... --amount 1000000 --amount-unit Wei
"""

from __future__ import annotations

import argparse
import json
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


def build_erc20_transfer_compose(
    key_gen_id: str,
    destination_chain_id: str,
    token_contract: str,
    to_address: str,
    amount: str,
    amount_unit: str = "Wei",
    purpose: str = "",
    use_custom_gas_config: bool = False,
    rpc_gateway: str | None = None,
) -> dict[str, Any]:
    """
    Compose JSON for ERC-20 transfer; RPC from getChainDetails unless rpc_gateway set.
    amount_unit: Wei | Ether | Gwei | USD (same as app paramUnits).
    """
    pid = (key_gen_id or "").strip()
    if not pid:
        raise ValueError("keyGenId is required")
    chain = (destination_chain_id or "").strip()
    if not chain:
        raise ValueError("destinationChainId (--chain-id) is required")
    token = _normalize_address(token_contract, "token contract")
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
        "useCustomGasConfig": use_custom_gas_config,
        "composeActions": [
            {
                "signature": "transfer(address,uint256)",
                "destinationContract": token,
                "inputs": [
                    {"name": "to", "type": "address", "value": to_addr},
                    {"name": "amount", "type": "uint256", "value": amt},
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
    return out


def erc20_transfer_multisign_payload(
    mpc_auth_url: str,
    key_gen_id: str,
    destination_chain_id: str,
    token_contract: str,
    to_address: str,
    amount: str,
    amount_unit: str = "Wei",
    purpose: str = "",
    use_custom_gas_config: bool = False,
    rpc_gateway: str | None = None,
) -> dict[str, Any]:
    compose = build_erc20_transfer_compose(
        key_gen_id=key_gen_id,
        destination_chain_id=destination_chain_id,
        token_contract=token_contract,
        to_address=to_address,
        amount=amount,
        amount_unit=amount_unit,
        purpose=purpose,
        use_custom_gas_config=use_custom_gas_config,
        rpc_gateway=rpc_gateway,
    )
    return _compose.build_compose_multisign(compose, mpc_auth_url.rstrip("/"))


def main() -> None:
    ap = argparse.ArgumentParser(
        description=(
            "Build multiSignRequest JSON for ERC-20 transfer(address,uint256). "
            "Loads RPC from GET /getChainDetails?chain_id=<n> unless --rpc-gateway is set."
        )
    )
    ap.add_argument(
        "--mpc-auth-url",
        default=_compose.DEFAULT_MPC_AUTH_URL,
        help="Management API base URL (default: %(default)s)",
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
        "--token",
        required=True,
        metavar="ADDR",
        help="ERC-20 contract address",
    )
    ap.add_argument(
        "--to",
        required=True,
        metavar="ADDR",
        help="Recipient address",
    )
    ap.add_argument(
        "--amount",
        required=True,
        help='Token amount (with --amount-unit; e.g. "1.5" with Ether, or raw "1000000" with Wei)',
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
        "--use-custom-gas-config",
        action="store_true",
        help="Apply gas limit / multipliers from GET /getChainDetails (custom chain gas config)",
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
        out = erc20_transfer_multisign_payload(
            mpc_auth_url=args.mpc_auth_url,
            key_gen_id=args.key_gen_id,
            destination_chain_id=args.chain_id,
            token_contract=args.token,
            to_address=args.to,
            amount=args.amount,
            amount_unit=args.amount_unit,
            purpose=args.purpose,
            use_custom_gas_config=args.use_custom_gas_config,
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
