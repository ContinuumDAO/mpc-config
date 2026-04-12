#!/usr/bin/env python3
"""
Build a POST /multiSignRequest payload for CTMRWA1 **transferWholeTokenX** (whole tokenId).

Matches **CTMRWA1** defaults in ``docs/references/TOKEN_STORAGE_SCHEMA.md`` / **CTMRWA1X.sol**:

- **transferWholeSig:** ``transferWholeTokenX(string,string,string,uint256,uint256,uint256,string)``
- **transferWholeNames:** ``fromAddrStr``, ``toAddressStr``, ``toChainIdStr``, ``fromTokenId``, ``ID``, ``version``, ``feeTokenStr``

The MPC transaction is sent on **--chain-id** (contract chain). **--to-chain-id** sets ``toChainIdStr`` (default: same as ``--chain-id``).

Requires: PyNaCl, eth_account (same as scripts/generateMultiSignRequestFromCompose.py).

Example::

  python3 recipes/ctmrwa1_transfer_whole.py \\
    --key-gen-id KeyGen2026... --chain-id 59144 --token 0x... \\
    --from 0xMpcWallet... --to 0xRecipient... \\
    --from-token-id 1001 --id 42 --version 1 \\
    --fee-token-str 0x...
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

WHOLE_SIG = "transferWholeTokenX(string,string,string,uint256,uint256,uint256,string)"
WHOLE_NAMES = (
    "fromAddrStr",
    "toAddressStr",
    "toChainIdStr",
    "fromTokenId",
    "ID",
    "version",
    "feeTokenStr",
)


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


def build_ctmrwa1_whole_compose(
    key_gen_id: str,
    destination_chain_id: str,
    token_contract: str,
    from_addr_str: str,
    to_address_str: str,
    to_chain_id_str: str,
    from_token_id: str,
    rwa_id: str,
    version: str,
    fee_token_str: str,
    purpose: str = "",
    use_custom_gas_config: bool = False,
    rpc_gateway: str | None = None,
) -> dict[str, Any]:
    pid = (key_gen_id or "").strip()
    if not pid:
        raise ValueError("keyGenId is required")
    chain = _normalize_chain_id_str(destination_chain_id, "destinationChainId (--chain-id)")
    token = _normalize_address(token_contract, "token contract")
    from_a = _normalize_address(from_addr_str, "from (--from)")
    to_a = _normalize_address(to_address_str, "recipient (--to)")
    to_chain = _normalize_chain_id_str(to_chain_id_str, "toChainIdStr (--to-chain-id)")
    ft = _normalize_fee_token_str(fee_token_str)

    fid = _require_uint_str("fromTokenId (--from-token-id)", from_token_id)
    rid = _require_uint_str("ID (--id)", rwa_id)
    ver = _require_uint_str("version (--version)", version)

    out: dict[str, Any] = {
        "keyGenId": pid,
        "destinationChainId": chain,
        "useCustomGasConfig": use_custom_gas_config,
        "composeActions": [
            {
                "signature": WHOLE_SIG,
                "destinationContract": token,
                "inputs": [
                    {"name": WHOLE_NAMES[0], "type": "string", "value": from_a},
                    {"name": WHOLE_NAMES[1], "type": "string", "value": to_a},
                    {"name": WHOLE_NAMES[2], "type": "string", "value": to_chain},
                    {"name": WHOLE_NAMES[3], "type": "uint256", "value": fid},
                    {"name": WHOLE_NAMES[4], "type": "uint256", "value": rid},
                    {"name": WHOLE_NAMES[5], "type": "uint256", "value": ver},
                    {"name": WHOLE_NAMES[6], "type": "string", "value": ft},
                ],
                "paramUnits": {"3": "Wei", "4": "Wei", "5": "Wei"},
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


def _normalize_fee_token_str(s: str) -> str:
    """feeTokenStr is an opaque string (address or symbol); allow empty if contract accepts."""
    return (s or "").strip()


def ctmrwa1_whole_multisign_payload(
    mpc_auth_url: str,
    key_gen_id: str,
    destination_chain_id: str,
    token_contract: str,
    from_addr_str: str,
    to_address_str: str,
    to_chain_id_str: str,
    from_token_id: str,
    rwa_id: str,
    version: str,
    fee_token_str: str,
    purpose: str = "",
    use_custom_gas_config: bool = False,
    rpc_gateway: str | None = None,
) -> dict[str, Any]:
    compose = build_ctmrwa1_whole_compose(
        key_gen_id=key_gen_id,
        destination_chain_id=destination_chain_id,
        token_contract=token_contract,
        from_addr_str=from_addr_str,
        to_address_str=to_address_str,
        to_chain_id_str=to_chain_id_str,
        from_token_id=from_token_id,
        rwa_id=rwa_id,
        version=version,
        fee_token_str=fee_token_str,
        purpose=purpose,
        use_custom_gas_config=use_custom_gas_config,
        rpc_gateway=rpc_gateway,
    )
    return _compose.build_compose_multisign(compose, mpc_auth_url.rstrip("/"))


def main() -> None:
    ap = argparse.ArgumentParser(
        description=(
            "CTMRWA1 whole-token transfer: transferWholeTokenX (TOKEN_STORAGE_SCHEMA.md)."
        )
    )
    ap.add_argument("--mpc-auth-url", default=_compose.DEFAULT_MPC_AUTH_URL)
    ap.add_argument("--key-gen-id", required=True, metavar="ID")
    ap.add_argument("--chain-id", required=True, help="Chain of the CTMRWA1 contract (tx chain)")
    ap.add_argument(
        "--to-chain-id",
        default="",
        help="toChainIdStr; default: same as --chain-id",
    )
    ap.add_argument("--token", required=True, metavar="ADDR", help="CTMRWA1 contract address")
    ap.add_argument("--from", dest="from_addr", required=True, metavar="ADDR", help="fromAddrStr (sender)")
    ap.add_argument("--to", required=True, metavar="ADDR", help="toAddressStr (recipient)")
    ap.add_argument("--from-token-id", required=True, help="uint256 fromTokenId")
    ap.add_argument("--id", required=True, dest="rwa_id", help="uint256 RWA token ID")
    ap.add_argument("--version", required=True, help="uint256 contract version")
    ap.add_argument(
        "--fee-token-str",
        default="",
        help="feeTokenStr (opaque string, e.g. fee token address)",
    )
    ap.add_argument("--purpose", default="")
    ap.add_argument("--use-custom-gas-config", action="store_true")
    ap.add_argument("--rpc-gateway", default="", metavar="URL")
    ap.add_argument("--ed25519-seed-hex", metavar="HEX", default="")
    ap.add_argument("--eip191-private-key-hex", metavar="HEX", default="")
    args = ap.parse_args()

    rpc = args.rpc_gateway.strip() or None
    to_chain = (args.to_chain_id or "").strip() or args.chain_id.strip()

    try:
        out = ctmrwa1_whole_multisign_payload(
            mpc_auth_url=args.mpc_auth_url,
            key_gen_id=args.key_gen_id,
            destination_chain_id=args.chain_id,
            token_contract=args.token,
            from_addr_str=args.from_addr,
            to_address_str=args.to,
            to_chain_id_str=to_chain,
            from_token_id=args.from_token_id,
            rwa_id=args.rwa_id,
            version=args.version,
            fee_token_str=args.fee_token_str,
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
