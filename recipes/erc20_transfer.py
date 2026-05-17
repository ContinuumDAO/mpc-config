#!/usr/bin/env python3
"""
Build a POST /multiSignRequest payload for a standard ERC-20 transfer(address,uint256),
using the node's stored RPC from GET /getChainDetails when rpcGateway is omitted.

By default, compose uses **GET /getChainDetails** gas fields when set; if **gasLimit** is
empty, **eth_estimateGas** applies. Pass **--no-custom-gas-params** to set
**noCustomGasParams** and estimate gas limit and fees only from the RPC (see
``build_erc20_transfer_compose``).

Requires: PyNaCl, eth_account (same as scripts/generateMultiSignRequestFromCompose.py).

**Expectations for an AI agent (amount handling)**

- **Preferred when the user gives a human token amount** (e.g. "send 10 USDC"): omit
  ``--amount-unit``, set ``--amount`` to that number in **token units** (not wei), and ensure
  the node’s **GET /getTokens** entry for this ``--chain-id`` and ``--token`` includes
  **decimals**. The script scales by those decimals. If decimals are missing, the run fails:
  either **call POST /addToken** (or the project’s token-update flow) so the ERC-20 contract
  row includes **decimals**, or **pass ``--amount-unit``** and express ``--amount`` in that
  unit (Wei = smallest units; Ether/Gwei/USD follow the compose fixed scales).

- **When the user gives a raw on-chain amount** or you already have wei: pass
  ``--amount-unit Wei`` and ``--amount`` as the integer string (no decimals in the string
  unless you intend fractional wei, which is unusual).

- **Do not assume** a default of Ether for the token amount; fixed units Ether/Gwei/USD refer
  to the compose layer’s scales (e.g. 18 / 9 / 6), not necessarily the token’s ``decimals``.

Example::

  python3 recipes/erc20_transfer.py \\
    --key-gen-id KeyGen2026... \\
    --chain-id 59144 \\
    --token 0x... \\
    --to 0x... \\
    --amount 1.5 --amount-unit Ether

  # Omit --amount-unit only if GET /getTokens lists this ERC-20 with decimals; amount is then
  # in token units (e.g. 1.5 USDC with decimals 6). Otherwise pass --amount-unit or add decimals.

  python3 recipes/erc20_transfer.py \\
    --key-gen-id KeyGen2026... --chain-id 1 \\
    --token 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 \\
    --to 0x... --amount 1000000 --amount-unit Wei
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
    no_custom_gas_params: bool = False,
    rpc_gateway: str | None = None,
) -> dict[str, Any]:
    """Compose JSON for ERC-20 transfer; RPC from getChainDetails unless rpc_gateway set.

    ``amount_unit``: Wei | Ether | Gwei | USD (same as app paramUnits).

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
    if no_custom_gas_params:
        out["noCustomGasParams"] = True
    return out


def erc20_transfer_multisign_payload(
    mpc_auth_url: str,
    management_port: str | int,
    key_gen_id: str,
    destination_chain_id: str,
    token_contract: str,
    to_address: str,
    amount: str,
    amount_unit: str = "Wei",
    purpose: str = "",
    no_custom_gas_params: bool = False,
    rpc_gateway: str | None = None,
    skip_gas_check: bool = False,
) -> dict[str, Any]:
    compose = build_erc20_transfer_compose(
        key_gen_id=key_gen_id,
        destination_chain_id=destination_chain_id,
        token_contract=token_contract,
        to_address=to_address,
        amount=amount,
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
            "Build multiSignRequest JSON for ERC-20 transfer(address,uint256). "
            "Loads RPC from GET /getChainDetails?chain_id=<n> unless --rpc-gateway is set. "
            "For AI agents: if the user gives a human token amount, omit --amount-unit and pass "
            "the amount in token units only when GET /getTokens has decimals for this token on "
            "this chain; otherwise set --amount-unit (e.g. Wei for raw smallest units) or add "
            "decimals to the token via POST /addToken. Raw wei amounts require --amount-unit Wei."
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
        help=(
            "Token amount. If --amount-unit is set: value is in that unit (Wei = smallest units, "
            "Ether/Gwei/USD use compose fixed scales). If --amount-unit is omitted: value must be "
            "in token decimal units (e.g. 10.5 for ten and a half tokens) and GET /getTokens must "
            "list decimals for this --token on this --chain-id; the script converts to raw Wei for "
            "the calldata. Agents: use Wei + integer string for raw on-chain amounts."
        ),
    )
    ap.add_argument(
        "--amount-unit",
        default=None,
        metavar="UNIT",
        help=(
            "Wei | Ether | Gwei | USD (compose paramUnits). Omit only when the node's GET /getTokens "
            "has a decimals field for this ERC-20 on this chain—then --amount is in token units. "
            "If decimals are missing, an AI agent must either pass this flag (recommended: Wei for "
            "raw amounts) or update the token record (POST /addToken) so decimals is stored."
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
        help="If set, sign with Ethereum wallet personal_sign (EIP-191) and add postBody",
    )
    args = ap.parse_args()

    rpc = args.rpc_gateway.strip() or None

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
                category="ERC20",
                http_get_json=_compose.http_get_json,
                unwrap_management_api=_compose._unwrap_management_api,
            )
            if dec is None:
                raise ValueError(
                    "Cannot infer amount scaling: --amount-unit was not set and GET /getTokens has "
                    "no decimals for this ERC-20 on this chain (or the token is not listed). "
                    "As an AI agent: pass --amount-unit (use Wei with the raw uint256 string if you "
                    "already have smallest units), or ensure the token is registered with decimals "
                    "(e.g. POST /addToken) so omitting --amount-unit is valid."
                )
            amount = _tokmeta.human_amount_to_raw_uint256(amount, dec)
            amount_unit = "Wei"

        out = erc20_transfer_multisign_payload(
            mpc_auth_url=args.mpc_auth_url,
            management_port=args.management_port,
            key_gen_id=args.key_gen_id,
            destination_chain_id=args.chain_id,
            token_contract=args.token,
            to_address=args.to,
            amount=amount,
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
