#!/usr/bin/env python3
"""
Build a POST /multiSignRequest payload for a native chain currency transfer
(ETH on Ethereum, LINEA on Linea, etc.): to an address with empty calldata and
non-zero tx value.

Uses compose **nativeTransfer** (see scripts/generateMultiSignRequestFromCompose.py).
RPC comes from GET /getChainDetails when --rpc-gateway is omitted.

Requires: PyNaCl, eth_account (same as scripts/generateMultiSignRequestFromCompose.py).

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
    use_custom_gas_config: bool = False,
    rpc_gateway: str | None = None,
) -> dict[str, Any]:
    """
    Compose JSON for native transfer; destinationContract is the recipient.
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
        "useCustomGasConfig": use_custom_gas_config,
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
    return out


def native_transfer_multisign_payload(
    mpc_auth_url: str,
    key_gen_id: str,
    destination_chain_id: str,
    to_address: str,
    amount: str,
    amount_unit: str = "Wei",
    purpose: str = "",
    use_custom_gas_config: bool = False,
    rpc_gateway: str | None = None,
) -> dict[str, Any]:
    compose = build_native_transfer_compose(
        key_gen_id=key_gen_id,
        destination_chain_id=destination_chain_id,
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
            "Build multiSignRequest JSON for a native currency transfer (gas token) "
            "to --to. Uses GET /getChainDetails?chain_id=<n> unless --rpc-gateway is set."
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
        "--to",
        required=True,
        metavar="ADDR",
        help="Recipient address (receives the native transfer)",
    )
    ap.add_argument(
        "--amount",
        required=True,
        help='Amount to send (with --amount-unit; e.g. "0.05" with Ether)',
    )
    ap.add_argument(
        "--amount-unit",
        default="Wei",
        choices=sorted(_VALID_UNITS),
        help="Unit for uint256 value (default: Wei). Matches compose paramUnits.",
    )
    ap.add_argument(
        "--purpose",
        default="",
        help="Purpose string for reviewers (optional)",
    )
    ap.add_argument(
        "--use-custom-gas-config",
        action="store_true",
        help="Apply gas limit / multipliers from GET /getChainDetails",
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
            key_gen_id=args.key_gen_id,
            destination_chain_id=args.chain_id,
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
