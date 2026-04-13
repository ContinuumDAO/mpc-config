#!/usr/bin/env python3
"""
Build a POST /multiSignRequest payload for register() on ContinuumDAO's Linea fee
contract, using the node's stored RPC and gas hints from GET /getChainDetails
(omit rpcGateway in compose JSON — same as the app when loading chain config).

Requires: PyNaCl, eth_account (same as scripts/generateMultiSignRequestFromCompose.py).

Example::

  python3 recipes/linea_register.py --key-gen-id KeyGen2026... --mpc-auth-url http://localhost:8080
  python3 recipes/linea_register.py --key-gen-id KeyGen2026... --ed25519-seed-hex <64 hex chars>
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

# Repo root: .../mpc-config/recipes/this_file.py -> scripts/
_scripts_dir = Path(__file__).resolve().parent.parent / "scripts"
if str(_scripts_dir) not in sys.path:
    sys.path.insert(0, str(_scripts_dir))

import generateMultiSignRequestFromCompose as _compose

# Linea mainnet — must match chain row on the node (Configure blockchains).
LINEA_MAINNET_CHAIN_ID = 59144

# ContinuumDAO fee / registration contract on Linea (see docs/skill/SKILL.md).
LINEA_FEE_CONTRACT = "0x55aD6Df6d8f8824486C3fd3373f1CF29eCecF0A3"


def build_linea_register_compose(
    key_gen_id: str,
    purpose: str = "",
    no_custom_gas_params: bool = False,
) -> dict[str, Any]:
    """Compose JSON for a single register() call; RPC comes from getChainDetails.

    When ``noCustomGasParams`` is **false** (default), ``generateMultiSignRequestFromCompose``
    uses **GET /getChainDetails** gas fields **when set**; if **gasLimit** is empty, it uses
    ``eth_estimateGas``. When ``noCustomGasParams`` is **true**, chain gas fields are ignored
    and limits/fees come from the RPC only (see compose script).
    """
    pid = (key_gen_id or "").strip()
    if not pid:
        raise ValueError("keyGenId is required")
    out: dict[str, Any] = {
        "keyGenId": pid,
        "destinationChainId": str(LINEA_MAINNET_CHAIN_ID),
        "composeActions": [
            {
                "signature": "register()",
                "destinationContract": LINEA_FEE_CONTRACT,
                "inputs": [],
            }
        ],
    }
    p = (purpose or "").strip()
    if p:
        out["purpose"] = p
    if no_custom_gas_params:
        out["noCustomGasParams"] = True
    return out


def linea_register_multisign_payload(
    mpc_auth_url: str,
    management_port: str | int,
    key_gen_id: str,
    purpose: str = "",
    no_custom_gas_params: bool = False,
) -> dict[str, Any]:
    """Call GET /getKeyGenResultById and GET /getChainDetails via build_compose_multisign."""
    compose = build_linea_register_compose(
        key_gen_id=key_gen_id,
        purpose=purpose,
        no_custom_gas_params=no_custom_gas_params,
    )
    base = _compose.resolve_mpc_auth_base(mpc_auth_url, management_port)
    return _compose.build_compose_multisign(compose, base)


def main() -> None:
    ap = argparse.ArgumentParser(
        description=(
            "Build multiSignRequest JSON for register() on Linea (chainId 59144) "
            "using RPC from GET /getChainDetails?chain_id=59144 on --mpc-auth-url."
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
        "--purpose",
        default="Register MPC wallet on Linea fee contract",
        help="Purpose string for reviewers (default: %(default)s)",
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

    try:
        out = linea_register_multisign_payload(
            mpc_auth_url=args.mpc_auth_url,
            management_port=args.management_port,
            key_gen_id=args.key_gen_id,
            purpose=args.purpose,
            no_custom_gas_params=args.no_custom_gas_params,
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
