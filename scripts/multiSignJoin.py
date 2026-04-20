#!/usr/bin/env python3
"""
Join two **multiSignRequest**-style JSON payloads (e.g. stdout from recipe scripts
that wrap ``generateMultiSignRequestFromCompose.py`` or ``generateSignRequestWithFoundryScript.py``)
into **one** combined payload for **POST /multiSignRequest**.

Guarantees:

- **destinationChainID** matches across both inputs (same chain).
- **Nonces** in the serialized unsigned transactions are reassigned to consecutive
  values starting at ``--first-nonce`` (so the merged txs execute in order on-chain).
- **Output shape** is always the **batch** form (``messageHashes``, ``messageRawBatch``,
  ``extraJSON.batchMeta``, plus first-item ``msgHash`` / ``msgRaw`` compatibility fields)
  when either input was not already a batch, or when the merged transaction count is
  at least two (covers ERC20 transfer then swap, etc.). If either input's ``extraJSON``
  includes ``customGasChainDetails`` (from compose/Foundry with chain gas disclosure),
  the merged ``extraJSON`` keeps it (first input wins, then second).
- **Gas and fees** are taken from each input’s serialized transactions (whatever
  **recipes/** produced, including default **ChainDetails**-backed gas or
  ``--no-custom-gas-params`` RPC-only mode). This script only changes **nonces**
  and recomputes signing hashes; it does **not** re-derive gas limits or fees.
- **Proposal tx params** (``proposalTxParams`` per index, matching
  ``generateMultiSignRequestFromCompose`` / ``GET ?tx_params=1``) are filled from
  the re-nonce’d unsigned txs. **triggerTxParams** in the helper output matches
  the first index (same as compose batch).

Requires **eth_account** (same as other scripts in this folder).

Example::

  python3 scripts/multiSignJoin.py \\
    --a erc20.json \\
    --b swap.json \\
    --first-nonce 12

  python3 recipes/erc20_transfer.py ... > /tmp/a.json
  python3 recipes/ctmerc20_transfer.py ... > /tmp/b.json
  python3 scripts/multiSignJoin.py --a /tmp/a.json --b /tmp/b.json --first-nonce "$(cast nonce 0x... --rpc-url ...)"

**Chaining (longer sequences):** stdout is the same **multiSignRequest-helper** shape
as compose/Foundry output (``bodyForSign``, ``messageToSign``). You may **feed that
JSON back** as ``--a`` or ``--b`` in another run, together with a new helper output,
to append more transactions on the **same chain**. Repeat as needed for multi-step
DeFi flows. Set ``--first-nonce`` to the MPC account nonce for the **first** tx in
the **final** merged sequence (usually ``cast nonce <MPC address>`` at proposal time).
Each completed stdout is ready for management signing and **POST /multiSignRequest**
(see docs).
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import rlp

_scripts_dir = Path(__file__).resolve().parent
if str(_scripts_dir) not in sys.path:
    sys.path.insert(0, str(_scripts_dir))

import generateMultiSignRequestFromCompose as _gmp

_spec = importlib.util.spec_from_file_location(
    "forge_sign",
    _scripts_dir / "generateSignRequestWithFoundryScript.py",
)
if _spec is None or _spec.loader is None:
    raise RuntimeError("Could not load generateSignRequestWithFoundryScript.py")
_forge = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_forge)

hex_to_bytes = _forge.hex_to_bytes
hex_to_int = _forge.hex_to_int
parse_chain_id = _forge.parse_chain_id
tx_to_signing_hash_and_raw = _forge.tx_to_signing_hash_and_raw


def dumps_js(obj: Any) -> str:
    """Compact JSON like JavaScript JSON.stringify (no spaces)."""
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def _to_hex_wei(n: int) -> str:
    if n < 0:
        return "0x0"
    return "0x" + hex(n)[2:]


def _unwrap_body(obj: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(obj, dict):
        raise ValueError("input must be a JSON object")
    if "bodyForSign" in obj and isinstance(obj["bodyForSign"], dict):
        return obj["bodyForSign"]
    if "body" in obj and isinstance(obj["body"], dict):
        return obj["body"]
    if "msgHash" in obj or "messageHashes" in obj or "destinationChainID" in obj:
        return obj
    raise ValueError("expected bodyForSign, body, or a raw multiSignRequest body object")


def _is_batch_body(body: dict[str, Any]) -> bool:
    m = body.get("messageRawBatch")
    return isinstance(m, list) and len(m) > 0


def _parse_extra_batch_meta(body: dict[str, Any]) -> list[dict[str, str]]:
    raw = body.get("extraJSON") or body.get("extra_json") or ""
    if not (isinstance(raw, str) and raw.strip()):
        return []
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if not isinstance(parsed, dict):
        return []
    bm = parsed.get("batchMeta")
    if not isinstance(bm, list):
        return []
    out: list[dict[str, str]] = []
    for item in bm:
        if not isinstance(item, dict):
            out.append({"destinationAddress": "", "signatureText": ""})
            continue
        out.append(
            {
                "destinationAddress": str(item.get("destinationAddress") or ""),
                "signatureText": str(item.get("signatureText") or ""),
            }
        )
    return out


def _custom_gas_chain_details_from_body(body: dict[str, Any]) -> dict[str, Any] | None:
    """Parse ``extraJSON.customGasChainDetails`` from a compose/Foundry helper ``bodyForSign``."""
    raw = body.get("extraJSON") or body.get("extra_json") or ""
    if not (isinstance(raw, str) and raw.strip()):
        return None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, dict):
        return None
    c = parsed.get("customGasChainDetails") or parsed.get("CustomGasChainDetails")
    if isinstance(c, dict) and c:
        return c
    return None


def _decode_type2_unsigned(raw: bytes) -> dict[str, Any]:
    if len(raw) < 2 or raw[0] != 0x02:
        raise ValueError("expected EIP-1559 type-2 unsigned transaction bytes")
    inner = raw[1:]
    decoded = rlp.decode(inner)
    if not isinstance(decoded, list) or len(decoded) != 9:
        raise ValueError(f"unexpected type-2 unsigned RLP (got {len(decoded) if isinstance(decoded, list) else 'n/a'} fields)")
    chain_id = int.from_bytes(decoded[0], "big")
    nonce = int.from_bytes(decoded[1], "big")
    max_prio = int.from_bytes(decoded[2], "big")
    max_fee = int.from_bytes(decoded[3], "big")
    gas = int.from_bytes(decoded[4], "big")
    to_b = decoded[5]
    value = int.from_bytes(decoded[6], "big")
    data_b = decoded[7]
    access = decoded[8]
    if isinstance(access, list) and len(access) > 0:
        raise ValueError("multiSignJoin: non-empty accessList is not supported yet")
    to_hex: str | None
    if to_b and len(to_b) == 20:
        to_hex = "0x" + to_b.hex()
    elif to_b in (b"", None):
        to_hex = None
    else:
        raise ValueError("invalid 'to' in type-2 transaction")
    return {
        "type": "0x2",
        "chainId": str(chain_id),
        "nonce": str(nonce),
        "maxPriorityFeePerGas": _to_hex_wei(max_prio),
        "maxFeePerGas": _to_hex_wei(max_fee),
        "gas": _to_hex_wei(gas),
        "to": to_hex,
        "value": _to_hex_wei(value),
        "data": ("0x" + data_b.hex()) if data_b else "0x",
        "accessList": [],
    }


def _decode_legacy_unsigned(raw: bytes) -> dict[str, Any]:
    decoded = rlp.decode(raw)
    if not isinstance(decoded, list):
        raise ValueError("invalid legacy RLP")
    if len(decoded) == 9:
        nonce = int.from_bytes(decoded[0], "big")
        gas_price = int.from_bytes(decoded[1], "big")
        gas = int.from_bytes(decoded[2], "big")
        to_b = decoded[3]
        value = int.from_bytes(decoded[4], "big")
        data_b = decoded[5]
        chain_id = int.from_bytes(decoded[6], "big")
        to_hex = "0x" + to_b.hex() if to_b and len(to_b) == 20 else None
        return {
            "nonce": str(nonce),
            "gasPrice": _to_hex_wei(gas_price),
            "gas": _to_hex_wei(gas),
            "to": to_hex,
            "value": _to_hex_wei(value),
            "data": ("0x" + data_b.hex()) if data_b else "0x",
            "chainId": str(chain_id),
        }
    raise ValueError(f"multiSignJoin: unsupported legacy unsigned RLP length {len(decoded)}")


def _decode_full_message_raw_to_tx(msg_raw: str) -> dict[str, Any]:
    """Decode serialized unsigned tx hex (type-2 or legacy) to an RPC-style tx dict."""
    s = (msg_raw or "").strip()
    if not s:
        raise ValueError("empty full transaction messageRaw")
    raw = hex_to_bytes(s)
    if len(raw) == 0:
        raise ValueError("empty full transaction messageRaw")
    if raw[0] == 0x02:
        return _decode_type2_unsigned(raw)
    if raw[0] == 0x01:
        raise ValueError("multiSignJoin: EIP-2930 type-1 transactions are not supported yet")
    return _decode_legacy_unsigned(raw)


def _looks_like_compose_calldata_only(msg_raw: str) -> bool:
    """Compose single-tx uses msgRaw = calldata without 0x (not a full unsigned tx)."""
    s = (msg_raw or "").strip()
    if not s:
        return False
    if s.startswith("0x02") or s.startswith("0x01"):
        return False
    raw = hex_to_bytes(s if s.startswith("0x") else "0x" + s)
    if len(raw) >= 1 and raw[0] in (0x02, 0x01):
        return False
    # Full legacy RLP often starts with 0xf8 / 0xf9
    if len(raw) > 0 and raw[0] >= 0xC0:
        return False
    return True


def _reconstruct_compose_single_tx(body: dict[str, Any]) -> dict[str, Any]:
    """Rebuild RPC tx dict from compose-style single-tx body (tx* fee fields + calldata msgRaw)."""
    chain = body.get("destinationChainID") or body.get("destination_chain_id")
    if chain is None or str(chain).strip() == "":
        raise ValueError("body missing destinationChainID")
    dest = (
        body.get("destinationContract")
        or body.get("destination_contract")
        or body.get("destinationAddress")
        or body.get("destination_address")
    )
    if not dest or not str(dest).strip():
        raise ValueError("body missing destinationContract / destinationAddress")

    msg_raw = body.get("msgRaw")
    if msg_raw is None:
        msg_raw = ""
    msg_raw_str = str(msg_raw).strip()
    if msg_raw_str == "":
        raise ValueError(
            "native-transfer or empty-calldata single-tx body cannot be joined without full "
            "serialized transactions; build a compose JSON with both actions in one call, "
            "or supply inputs whose bodies include messageRawBatch / full-tx msgRaw."
        )

    calldata = msg_raw_str if msg_raw_str.startswith("0x") else ("0x" + msg_raw_str)

    tx_nonce = body.get("txNonce")
    if tx_nonce is None and body.get("tx_nonce") is not None:
        tx_nonce = body.get("tx_nonce")
    if tx_nonce is None:
        raise ValueError("compose single-tx body missing txNonce (cannot rebuild transaction)")
    nonce_int = int(tx_nonce) if not isinstance(tx_nonce, str) else int(str(tx_nonce).strip(), 0)

    gas_lim = body.get("txGasLimit") or body.get("tx_gas_limit")
    if gas_lim is None:
        raise ValueError("compose single-tx body missing txGasLimit")
    gas_int = int(gas_lim) if not isinstance(gas_lim, str) else int(str(gas_lim).strip(), 0)

    legacy = body.get("txGasPrice") is not None or body.get("tx_gas_price") is not None
    if legacy:
        gp = body.get("txGasPrice") or body.get("tx_gas_price")
        if gp is None:
            raise ValueError("missing txGasPrice")
        gpi = int(gp) if not isinstance(gp, str) else int(str(gp).strip(), 0)
        return {
            "nonce": str(nonce_int),
            "gasPrice": _to_hex_wei(gpi),
            "gas": _to_hex_wei(gas_int),
            "to": str(dest).strip(),
            "value": "0x0",
            "data": calldata,
            "chainId": str(parse_chain_id(str(chain))),
        }

    mf = body.get("txMaxFeePerGas") or body.get("tx_max_fee_per_gas")
    mp = body.get("txMaxPriorityFeePerGas") or body.get("tx_max_priority_fee_per_gas")
    if mf is None or mp is None:
        raise ValueError("compose single-tx body missing txMaxFeePerGas / txMaxPriorityFeePerGas")
    mfi = int(mf) if not isinstance(mf, str) else int(str(mf).strip(), 0)
    mpi = int(mp) if not isinstance(mp, str) else int(str(mp).strip(), 0)
    return {
        "type": "0x2",
        "nonce": str(nonce_int),
        "gas": _to_hex_wei(gas_int),
        "maxFeePerGas": _to_hex_wei(mfi),
        "maxPriorityFeePerGas": _to_hex_wei(mpi),
        "to": str(dest).strip(),
        "value": "0x0",
        "data": calldata,
        "chainId": str(parse_chain_id(str(chain))),
    }


def _extract_txs_and_meta(body: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Return (tx_dicts, batchMeta rows) for one body."""
    txs: list[dict[str, Any]] = []
    meta: list[dict[str, str]] = []

    if _is_batch_body(body):
        batch_raw = body.get("messageRawBatch") or []
        if not isinstance(batch_raw, list):
            raise ValueError("messageRawBatch must be a list")
        parsed_meta = _parse_extra_batch_meta(body)
        for i, mr in enumerate(batch_raw):
            if not isinstance(mr, str) or not mr.strip():
                raise ValueError(f"messageRawBatch[{i}] invalid")
            txs.append(_decode_full_message_raw_to_tx(mr))
            if i < len(parsed_meta):
                meta.append(parsed_meta[i])
            else:
                meta.append({"destinationAddress": "", "signatureText": ""})
        return txs, meta

    # Single-format body
    msg_raw = body.get("msgRaw")
    msg_raw_s = "" if msg_raw is None else str(msg_raw).strip()

    if msg_raw_s and not _looks_like_compose_calldata_only(msg_raw_s):
        txs.append(_decode_full_message_raw_to_tx(msg_raw_s))
        meta.append(
            {
                "destinationAddress": str(body.get("destinationAddress") or body.get("destination_address") or ""),
                "signatureText": str(body.get("signatureText") or body.get("signature_text") or ""),
            }
        )
        return txs, meta

    txs.append(_reconstruct_compose_single_tx(body))
    meta.append(
        {
            "destinationAddress": str(body.get("destinationAddress") or body.get("destination_address") or ""),
            "signatureText": str(body.get("signatureText") or body.get("signature_text") or ""),
        }
    )
    return txs, meta


def _normalize_chain_id(body: dict[str, Any]) -> str:
    c = body.get("destinationChainID") or body.get("destination_chain_id")
    if c is None or str(c).strip() == "":
        raise ValueError("body missing destinationChainID")
    return str(parse_chain_id(str(c)))


def _tx_dict_is_legacy(td: dict[str, Any]) -> bool:
    """Match fee classification used when building first-tx ``tx*`` helper fields."""
    if td.get("type") in ("0x2", "0x02") or td.get("maxFeePerGas") is not None:
        return False
    return True


def _merge_purpose(a: str | None, b: str | None, override: str | None) -> str | None:
    if override is not None and override.strip():
        return override.strip()
    pa = (a or "").strip()
    pb = (b or "").strip()
    if pa and pb:
        return pa + " | " + pb
    return pa or pb or None


def join_multisign_bodies(
    body_a: dict[str, Any],
    body_b: dict[str, Any],
    first_nonce: int,
    purpose: str | None = None,
) -> dict[str, Any]:
    chain_a = _normalize_chain_id(body_a)
    chain_b = _normalize_chain_id(body_b)
    if chain_a != chain_b:
        raise ValueError(f"destinationChainID mismatch: {chain_a!r} vs {chain_b!r}")

    txs_a, meta_a = _extract_txs_and_meta(body_a)
    txs_b, meta_b = _extract_txs_and_meta(body_b)
    if not txs_a or not txs_b:
        raise ValueError("each input must yield at least one transaction")

    kl_a = body_a.get("keyList")
    kl_b = body_b.get("keyList")
    if isinstance(kl_a, list) and isinstance(kl_b, list) and kl_a and kl_b and kl_a != kl_b:
        raise ValueError("keyList differs between inputs (must be the same MPC key)")
    pk_a = body_a.get("pubKey") or body_a.get("pubkeyhex")
    pk_b = body_b.get("pubKey") or body_b.get("pubkeyhex")
    if pk_a and pk_b and str(pk_a).strip() != str(pk_b).strip():
        raise ValueError("pubKey differs between inputs (must be the same MPC key)")

    key_list: list[str] | None = None
    if isinstance(kl_b, list) and kl_b:
        key_list = [str(x) for x in kl_b]
    elif isinstance(kl_a, list) and kl_a:
        key_list = [str(x) for x in kl_a]
    pub_key = (str(pk_b).strip() if pk_b else None) or (str(pk_a).strip() if pk_a else None)

    txs = txs_a + txs_b
    batch_meta = meta_a + meta_b

    message_hashes: list[str] = []
    message_raw_batch: list[str] = []

    proposal_tx_params_batch: list[dict[str, Any]] = []
    for i, tx in enumerate(txs):
        td = dict(tx)
        td["nonce"] = str(first_nonce + i)
        td["chainId"] = chain_a
        mh, mr = tx_to_signing_hash_and_raw(td)
        message_hashes.append(mh)
        message_raw_batch.append(mr)
        leg = _tx_dict_is_legacy(td)
        proposal_tx_params_batch.append(_gmp.proposal_tx_params_from_unsigned_tx(td, legacy=leg))

    first_tx = txs[0]
    first_data = first_tx.get("data") or first_tx.get("input") or "0x"
    if isinstance(first_data, bytes):
        first_calldata = "0x" + first_data.hex()
    else:
        first_calldata = str(first_data) if str(first_data).startswith("0x") else ("0x" + str(first_data))
    first_msg_raw_compact = first_calldata[2:] if first_calldata.startswith("0x") else first_calldata

    # first-tx fee fields (from first *re-encoded* tx — use original gas limits / fees)
    first_td = dict(txs[0])
    first_td["nonce"] = str(first_nonce)
    first_td["chainId"] = chain_a
    first_tx_fee: dict[str, Any] = {}
    if first_td.get("type") in ("0x2", "0x02") or first_td.get("maxFeePerGas") is not None:
        first_tx_fee["txNonce"] = int(first_nonce)
        first_tx_fee["txGasLimit"] = str(hex_to_int(first_td.get("gas")))
        first_tx_fee["txMaxFeePerGas"] = str(hex_to_int(first_td.get("maxFeePerGas")))
        first_tx_fee["txMaxPriorityFeePerGas"] = str(hex_to_int(first_td.get("maxPriorityFeePerGas")))
    else:
        first_tx_fee["txNonce"] = int(first_nonce)
        first_tx_fee["txGasLimit"] = str(hex_to_int(first_td.get("gas")))
        first_tx_fee["txGasPrice"] = str(hex_to_int(first_td.get("gasPrice")))

    merged_purpose = _merge_purpose(
        str(body_a.get("purpose") or "") if body_a.get("purpose") is not None else "",
        str(body_b.get("purpose") or "") if body_b.get("purpose") is not None else "",
        purpose,
    )

    extra_merged: dict[str, Any] = {"batchMeta": batch_meta}
    cg_join = _custom_gas_chain_details_from_body(body_a) or _custom_gas_chain_details_from_body(body_b)
    if cg_join:
        extra_merged["customGasChainDetails"] = cg_join

    out_body: dict[str, Any] = {
        "destinationChainID": chain_a,
        "msgHash": message_hashes[0],
        "msgRaw": first_msg_raw_compact,
        "messageHashes": message_hashes,
        "messageRawBatch": message_raw_batch,
        "destinationAddress": batch_meta[0].get("destinationAddress") or "",
        "signatureText": batch_meta[0].get("signatureText") or "",
        "extraJSON": dumps_js(extra_merged),
    }
    if key_list is not None:
        out_body["keyList"] = key_list
    if pub_key:
        out_body["pubKey"] = str(pub_key).strip()
    out_body.update(first_tx_fee)
    if merged_purpose:
        out_body["purpose"] = merged_purpose[:256]

    cid_a = (body_a.get("clientId") or body_a.get("client_id") or "").strip()
    cid_b = (body_b.get("clientId") or body_b.get("client_id") or "").strip()
    cid = cid_a or cid_b
    if cid:
        out_body["clientId"] = cid

    out_body["proposalTxParams"] = proposal_tx_params_batch

    message_to_sign = dumps_js(out_body)

    return {
        "endpoint": "multiSignRequest",
        "bodyForSign": out_body,
        "messageToSign": message_to_sign,
        "chainId": chain_a,
        "count": len(txs),
        "triggerTxParams": _gmp.trigger_tx_params_from_compose_body(out_body),
        "triggerMessageHash": message_hashes[0],
    }


def _load_json(path: str) -> dict[str, Any]:
    raw = Path(path).read_text(encoding="utf-8").strip()
    if not raw:
        raise ValueError(f"empty file: {path}")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError(f"top-level JSON must be an object: {path}")
    return data


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Join two multiSignRequest JSON outputs into one batch payload with consecutive nonces."
    )
    ap.add_argument(
        "--a",
        metavar="PATH",
        required=True,
        help="First JSON file (recipe / generateMultiSignRequest* output)",
    )
    ap.add_argument(
        "--b",
        metavar="PATH",
        required=True,
        help="Second JSON file",
    )
    ap.add_argument(
        "--first-nonce",
        type=int,
        required=True,
        metavar="N",
        help="EVM account nonce for the first merged transaction (following txs use N+1, N+2, …)",
    )
    ap.add_argument(
        "--purpose",
        default="",
        help="Override combined purpose (≤256 chars); default: merge both bodies' purpose with ' | '",
    )
    args = ap.parse_args()

    try:
        doc_a = _load_json(args.a)
        doc_b = _load_json(args.b)
        body_a = _unwrap_body(doc_a)
        body_b = _unwrap_body(doc_b)
        purpose = args.purpose.strip() or None
        out = join_multisign_bodies(body_a, body_b, args.first_nonce, purpose=purpose)
    except (ValueError, OSError, json.JSONDecodeError) as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)

    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
