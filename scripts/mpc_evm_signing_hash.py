#!/usr/bin/env python3
"""
Recompute the EVM multiSignRequest **messageHash** (tx signing hash) from stored sign-request
fields so scripts can detect mismatches between ``MessageHash`` and ``txNonce``/gas/fees/``MessageRaw``.

Used by ``mpc_event_listener`` (before trigger) and ``executeSignResult`` (before broadcast).
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

_scripts_dir = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location(
    "forge_sign",
    _scripts_dir / "generateSignRequestWithFoundryScript.py",
)
if _spec is None or _spec.loader is None:
    raise RuntimeError("Could not load generateSignRequestWithFoundryScript.py")
_forge = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_forge)

parse_chain_id = _forge.parse_chain_id
_to_hex_wei = _forge._to_hex_wei
tx_to_signing_hash_and_raw = _forge.tx_to_signing_hash_and_raw


def pick_str(d: dict[str, Any], *keys: str) -> Any:
    for k in keys:
        if k in d:
            return d[k]
    lower = {str(a).lower(): b for a, b in d.items()}
    for k in keys:
        lk = k.lower()
        if lk in lower:
            return lower[lk]
    return None


def _pick_first_str(d: dict[str, Any], *keys: str) -> str | None:
    for k in keys:
        v = d.get(k)
        if v is not None and str(v).strip() != "":
            return str(v).strip()
    return None


def _body_like_tx_fields(sr: dict[str, Any]) -> dict[str, Any]:
    pairs: list[tuple[str, tuple[str, ...]]] = [
        ("txNonce", ("txNonce", "TxNonce")),
        ("txGasLimit", ("txGasLimit", "TxGasLimit")),
        ("txGasPrice", ("txGasPrice", "TxGasPrice")),
        ("txMaxFeePerGas", ("txMaxFeePerGas", "TxMaxFeePerGas")),
        ("txMaxPriorityFeePerGas", ("txMaxPriorityFeePerGas", "TxMaxPriorityFeePerGas")),
    ]
    out: dict[str, Any] = {}
    for canonical, variants in pairs:
        for v in variants:
            if v in sr and sr[v] is not None:
                out[canonical] = sr[v]
                break
    return out


def normalize_message_hash_hex(h: str) -> str:
    s = h.strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    return s


def message_raw_to_data_hex(msg_raw: str | None) -> str:
    """MessageRaw from API: may be calldata with or without 0x (compose stores no 0x in msgRaw)."""
    if not msg_raw or not str(msg_raw).strip():
        return "0x"
    s = str(msg_raw).strip()
    return s if s.startswith("0x") else "0x" + s


def tx_dict_execute_style_to_compose_style(tx: dict[str, Any]) -> dict[str, Any]:
    """Convert ``executeSignResult`` unsigned dict (ints, bytes data) to compose-style for hashing."""
    data = tx.get("data")
    if isinstance(data, bytes):
        data_hex = "0x" + data.hex() if data else "0x"
    else:
        data_hex = (data if data else "0x") or "0x"
        if isinstance(data_hex, str) and not data_hex.startswith("0x"):
            data_hex = "0x" + data_hex

    chain_id = tx.get("chainId")
    cid = int(chain_id) if chain_id is not None else 0

    if tx.get("gasPrice") is not None and not (
        tx.get("maxFeePerGas") is not None or tx.get("maxPriorityFeePerGas") is not None
    ):
        return {
            "nonce": str(tx["nonce"]),
            "gasPrice": _to_hex_wei(int(tx["gasPrice"])),
            "gas": _to_hex_wei(int(tx["gas"])),
            "to": tx.get("to"),
            "value": _to_hex_wei(int(tx.get("value", 0) or 0)),
            "data": data_hex,
            "chainId": str(cid),
        }

    return {
        "type": "0x2",
        "nonce": str(tx["nonce"]),
        "gas": _to_hex_wei(int(tx["gas"])),
        "maxFeePerGas": _to_hex_wei(int(tx["maxFeePerGas"])),
        "maxPriorityFeePerGas": _to_hex_wei(int(tx["maxPriorityFeePerGas"])),
        "to": tx.get("to"),
        "value": _to_hex_wei(int(tx.get("value", 0) or 0)),
        "data": data_hex,
        "chainId": str(cid),
    }


def compute_message_hash_from_execute_unsigned_dict(tx: dict[str, Any]) -> str:
    c = tx_dict_execute_style_to_compose_style(tx)
    mh, _ = tx_to_signing_hash_and_raw(c)
    return mh


def expected_message_hash_from_sign_request(sr: dict[str, Any]) -> str:
    """
    Recompute the signing hash from the same fields ``generateMultiSignRequestFromCompose`` uses:
    ``txNonce``, ``txGasLimit``, fee fields, ``DestinationChainID``, ``DestinationAddress``, ``MessageRaw``.
    """
    chain_s = _pick_first_str(sr, "DestinationChainID", "destinationChainID", "destination_chain_id")
    if not chain_s:
        raise ValueError("missing DestinationChainID")
    chain_num = parse_chain_id(str(chain_s).strip())
    if chain_num <= 0:
        raise ValueError("invalid DestinationChainID")

    body_like = _body_like_tx_fields(sr)
    if "txNonce" not in body_like or "txGasLimit" not in body_like:
        raise ValueError("missing txNonce or txGasLimit on sign request")

    raw_nonce = body_like["txNonce"]
    nonce = int(raw_nonce) if not isinstance(raw_nonce, int) else raw_nonce
    gas_limit = int(str(body_like["txGasLimit"]).strip())

    dest = _pick_first_str(sr, "DestinationAddress", "destinationAddress", "destination_contract")
    if not dest:
        raise ValueError("missing DestinationAddress")

    msg_raw = _pick_first_str(sr, "MessageRaw", "msgRaw", "messageRaw") or ""
    data_hex = message_raw_to_data_hex(msg_raw)

    value_int = 0
    val = pick_str(sr, "value", "Value")
    if val is not None and str(val).strip() != "":
        try:
            value_int = int(str(val).strip(), 0) if isinstance(val, str) else int(val)
        except (TypeError, ValueError):
            value_int = 0

    to_addr = dest if dest.startswith("0x") else "0x" + dest

    if body_like.get("txMaxFeePerGas") is not None or body_like.get("txMaxPriorityFeePerGas") is not None:
        mf = body_like.get("txMaxFeePerGas")
        mp = body_like.get("txMaxPriorityFeePerGas")
        if mf is None or mp is None:
            raise ValueError("incomplete EIP-1559 fee fields on sign request")
        max_fee = int(str(mf).strip())
        max_prio = int(str(mp).strip())
        tx = {
            "type": "0x2",
            "nonce": str(nonce),
            "gas": _to_hex_wei(gas_limit),
            "maxFeePerGas": _to_hex_wei(max_fee),
            "maxPriorityFeePerGas": _to_hex_wei(max_prio),
            "to": to_addr,
            "value": _to_hex_wei(value_int),
            "data": data_hex,
            "chainId": str(chain_num),
        }
    else:
        gp = body_like.get("txGasPrice")
        if gp is None:
            raise ValueError("missing txGasPrice for legacy tx")
        gas_price = int(str(gp).strip())
        tx = {
            "nonce": str(nonce),
            "gas": _to_hex_wei(gas_limit),
            "gasPrice": _to_hex_wei(gas_price),
            "to": to_addr,
            "value": _to_hex_wei(value_int),
            "data": data_hex,
            "chainId": str(chain_num),
        }

    mh, _ = tx_to_signing_hash_and_raw(tx)
    return mh


def assert_sign_request_fields_match_message_hash(sr: dict[str, Any]) -> None:
    """
    Raise ``ValueError`` if ``MessageHash`` does not match the recomputed hash from tx + calldata fields.

    Call this before ``POST /triggerSignRequestById`` when attaching ``txParams``/``messageHash``, and
    before broadcasting in ``executeSignResult``.
    """
    stored = _pick_first_str(sr, "MessageHash", "msgHash")
    if not stored:
        mhs = sr.get("MessageHashes") or sr.get("messageHashes")
        if isinstance(mhs, list) and len(mhs) > 1:
            raise ValueError(
                "batch sign request: hash consistency check for multiple messages is not implemented here; "
                "validate each (messageHashes[i], messageRawBatch[i], fees) manually."
            )
        if not stored and isinstance(mhs, list) and len(mhs) == 1:
            stored = str(mhs[0]).strip()

    if not stored:
        return

    try:
        expected = expected_message_hash_from_sign_request(sr)
    except ValueError as e:
        raise ValueError(
            f"Cannot recompute signing hash from sign-request fields ({e}). "
            "Ensure txNonce, txGasLimit, fee fields, MessageRaw, and DestinationAddress are present."
        ) from e

    if normalize_message_hash_hex(stored) != normalize_message_hash_hex(expected):
        raise ValueError(
            "MessageHash on the sign request does not match the transaction implied by txNonce, txGasLimit, "
            "fee fields (txGasPrice or txMaxFeePerGas/txMaxPriorityFeePerGas), MessageRaw, and DestinationAddress. "
            "This usually means multiSignRequest was produced or posted more than once with different gas/fees "
            "while the stored MessageHash still reflects an older run. "
            "Fix: run the recipe or compose script once, POST /multiSignRequest exactly that bodyForSign output, "
            "obtain threshold+1 agreements, then trigger using only messageHash and txParams from that same JSON — "
            "do not mix hashes from one run with txParams from another."
        )
