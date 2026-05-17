#!/usr/bin/env python3
"""
Build a POST /multiSignRequest payload for **deposit(address,uint256)** on ContinuumDAO’s
Linea fee contract (top up fee-token balance for a registered KeyGen).

On-chain (Linea mainnet): ``deposit`` pulls **fee token** from **msg.sender** (the MPC
wallet) via ``transferFrom`` and credits **keyGenAddress** (see verified contract on
LineaScan). The MPC wallet must have **ERC20 approve** the fee contract for at least
``amount`` before this transaction succeeds (separate tx or prior approval).

To obtain **one** ``multiSignRequest`` that performs **approve then deposit** in order,
use the Foundry script ``forge/script/LineaFeeApproveDeposit.s.sol`` (see
``docs/references/AI_AGENT_FORGE_SIGNREQUEST.md`` § Linea fee) and
``scripts/generateSignRequestWithFoundryScript.py`` on the resulting broadcast JSON.

Uses **GET /getKeyGenResultById** for ``keyList`` / ``pubKey`` and the MPC
**ethereumaddress** as the ``keyGenAddress`` argument. RPC from **GET /getChainDetails**
for chain **59144** when ``rpcGateway`` is omitted. Gas: by default compose uses chain
fields from **getChainDetails** when set, otherwise **eth_estimateGas**; use
**--no-custom-gas-params** for RPC-only estimates (see ``build_linea_fee_deposit_compose``).

Requires: PyNaCl, eth_account (same as scripts/generateMultiSignRequestFromCompose.py).

**Expectations for an AI agent (amount handling)**

``--amount-wei`` must be the **fee token** amount in **smallest on-chain units** (integer
decimal string). This script does **not** read **GET /getTokens** or scale by **decimals** for
you. If the user states a human amount (e.g. "10" tokens), look up the fee token’s
**decimals** (from node token metadata, chain docs, or the token contract) and compute
``amount = floor(human * 10**decimals)`` before passing ``--amount-wei``.

Example::

  python3 recipes/linea_fee_deposit.py \\
    --key-gen-id KeyGen2026... \\
    --amount-wei 1000000000000000000 \\
    --mpc-auth-url http://localhost:8080
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

LINEA_MAINNET_CHAIN_ID = 59144
LINEA_FEE_CONTRACT = "0x55aD6Df6d8f8824486C3fd3373f1CF29eCecF0A3"

DEPOSIT_SIG = "deposit(address,uint256)"


def _normalize_address(addr: str, name: str) -> str:
    s = (addr or "").strip()
    if not s:
        raise ValueError(f"{name} is required")
    if not re.match(r"^0x[0-9a-fA-F]{40}$", s):
        raise ValueError(f"{name} must be a 40-hex-prefixed EVM address (0x…)")
    return s


def _parse_positive_wei(s: str) -> str:
    t = (s or "").strip()
    if not t or not t.isdigit() or int(t) <= 0:
        raise ValueError("amount-wei must be a positive decimal integer (fee token smallest units)")
    return t


def build_linea_fee_deposit_compose(
    key_gen_id: str,
    key_gen_address: str,
    amount_wei: str,
    purpose: str = "",
    no_custom_gas_params: bool = False,
    rpc_gateway: str | None = None,
) -> dict[str, Any]:
    """Compose JSON for deposit(address,uint256) on the Linea fee contract.

    When ``noCustomGasParams`` is **false** (default), ``generateMultiSignRequestFromCompose``
    uses **GET /getChainDetails** gas fields **when set**; if **gasLimit** is empty, it uses
    ``eth_estimateGas``. When ``noCustomGasParams`` is **true**, chain gas fields are ignored
    and limits/fees come from the RPC only (see compose script).
    """
    pid = (key_gen_id or "").strip()
    if not pid:
        raise ValueError("keyGenId is required")
    addr = _normalize_address(key_gen_address, "keyGenAddress (MPC ethereum address)")
    amt = _parse_positive_wei(amount_wei)

    out: dict[str, Any] = {
        "keyGenId": pid,
        "destinationChainId": str(LINEA_MAINNET_CHAIN_ID),
        "composeActions": [
            {
                "signature": DEPOSIT_SIG,
                "destinationContract": LINEA_FEE_CONTRACT,
                "inputs": [
                    {"name": "keyGenAddress", "type": "address", "value": addr},
                    {"name": "amount", "type": "uint256", "value": amt},
                ],
                "paramUnits": {"1": "Wei"},
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


def linea_fee_deposit_multisign_payload(
    mpc_auth_url: str,
    management_port: str | int,
    key_gen_id: str,
    amount_wei: str,
    purpose: str = "",
    no_custom_gas_params: bool = False,
    rpc_gateway: str | None = None,
    skip_gas_check: bool = False,
) -> dict[str, Any]:
    """
    Load MPC address from GET /getKeyGenResultById, then build_compose_multisign.
    """
    base = _compose.resolve_mpc_auth_base(mpc_auth_url, management_port)
    kg = _compose.fetch_keygen_bundle(base, key_gen_id)
    eth = kg.get("ethereumaddress") or kg.get("EthereumAddress")
    if not eth or not isinstance(eth, str):
        raise ValueError("getKeyGenResultById: ethereumaddress missing")
    eth = eth.strip()
    compose = build_linea_fee_deposit_compose(
        key_gen_id=key_gen_id,
        key_gen_address=eth,
        amount_wei=amount_wei,
        purpose=purpose,
        no_custom_gas_params=no_custom_gas_params,
        rpc_gateway=rpc_gateway,
    )
    if not skip_gas_check:
        _gas.require_native_gas_for_compose(compose, base)
    return _compose.build_compose_multisign(compose, base)


def main() -> None:
    ap = argparse.ArgumentParser(
        description=(
            "Build multiSignRequest JSON for fee contract deposit(address,uint256) on Linea "
            "(59144). amount-wei is the fee token amount in smallest on-chain units (integer). "
            "AI agents: convert human token amounts to smallest units using the fee token’s "
            "decimals before calling; this CLI does not fetch decimals from GET /getTokens."
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
        "--amount-wei",
        required=True,
        metavar="N",
        help=(
            "Fee token amount: positive decimal integer string in smallest token units (not scaled "
            "by this script). Use token decimals to convert from human amounts."
        ),
    )
    ap.add_argument(
        "--purpose",
        default="Top up Linea KeyGen fee deposit",
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
        help="If set, sign with Ethereum wallet personal_sign (EIP-191) and add postBody",
    )
    args = ap.parse_args()

    rpc = args.rpc_gateway.strip() or None

    try:
        out = linea_fee_deposit_multisign_payload(
            mpc_auth_url=args.mpc_auth_url,
            management_port=args.management_port,
            key_gen_id=args.key_gen_id,
            amount_wei=args.amount_wei,
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
        out["postBody"] = {
            **out["bodyForSign"],
            "clientSig": sig,
            "signedMessage": out["messageToSign"],
        }
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
