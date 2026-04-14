#!/usr/bin/env python3
"""
executeSignResult

Broadcast EVM transactions from a **successful** MPC sign result (after
``POST /triggerSignRequestById`` and ``GET /getSignResultById``).

**Single-tx (matches continuumdao-node-app “Execute”):** rebuilds the unsigned EIP-1559/legacy
transaction using ``GET /getSignRequestById?tx_params=1`` (gas/nonce snapshot at Get Sig), chain
config from ``GET /getChainDetails``, and RPC ``estimateGas`` / fee discovery — then applies
``r,s,v`` / ``ethereumSignature``. Fee and gas-limit math when TxParams omit EIP-1559 caps matches
``generateMultiSignRequestFromCompose.build_compose_multisign`` (same RPC fee snapshot, ``baseFeeMultiplier``,
``gasMultiplier`` / ``gasPrice`` handling, and ``max(chain gasLimit, eth_estimateGas)``). The old “decode ``MessageRaw`` RLP only” approach often failed
because MPC signs the hash of that **reconstructed** payload, not an arbitrary or stale RLP blob.

**Batch:** still pairs ``batchsignatures[i]`` with ``MessageRawBatch[i]`` unsigned RLP (same as the
app ``buildBatchSignedTxsFromResult``).

Loads message hex from the sign result or ``GET /getSignRequestById`` (or JSON files) when needed.

Builds signed raw transactions with ``eth_account`` and submits ``eth_sendRawTransaction`` on
``--rpc-url`` or the node's ``GET /getChainDetails`` RPC for ``DestinationChainID``.

**Execution mode**

- **Default (slow / sequential):** send transaction *i*, wait until a receipt is available,
  then send *i+1*. Suitable when order or strict confirmation between steps matters.
- **``--fast``:** submit and wait for receipts **concurrently** (one thread per transaction).
  Works for batched txs with consecutive nonces because the mempool orders by nonce.

On failure (gas, RPC, receipt timeout, build/broadcast errors, etc.), **stderr** prints **AI agent follow-up** instructions: call ``POST /updateSignResultStatusById`` with ``status: 'failed'`` (management-signed), then optionally ``POST /shelveSignRequest``, then ``POST /sendMessage`` to the Group KeyGen thread with the error (see printed block).

After **successful** broadcast (receipt received for each tx), **stderr** prints instructions to call ``POST /updateSignResultStatusById`` with ``status: 'executed'`` and the transaction hash (or ``batchTransactionHashes``), and to report the hash(es) to the user (see printed block). **stdout** remains a single JSON object with ``results`` including ``transactionHash`` per item.
Before broadcast, the script checks that the rebuilt unsigned tx matches **MessageHash** when stored **txParams** are present (detects mixed recipe runs or mismatched trigger fields).

Requires **eth_account** and **rlp** (install into ``$MPA_PATH/.venv``; see ``docs/skill/SKILL.md`` **Python dependencies**).

Examples::

  $MPA_PATH/.venv/bin/python scripts/executeSignResult.py \\
    --sign-request-id Sign20260111003720999cf104d0f \\
    --mpc-auth-url http://127.0.0.1 --management-port 8080

  $MPA_PATH/.venv/bin/python scripts/executeSignResult.py \\
    --sign-result-file /tmp/result.json \\
    --sign-request-file /tmp/request.json \\
    --rpc-url https://linea-mainnet.g.alchemy.com/v2/SECRET

  $MPA_PATH/.venv/bin/python scripts/executeSignResult.py --sign-request-id ... --mpc-auth-url ... --fast
"""

from __future__ import annotations

import argparse
import concurrent.futures
import importlib.util
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Union

import rlp
from rlp.exceptions import DecodingError

from eth_account._utils.legacy_transactions import (
    encode_transaction,
    serializable_unsigned_transaction_from_dict,
)
from eth_account.typed_transactions import TypedTransaction

_scripts_dir = Path(__file__).resolve().parent
if str(_scripts_dir) not in sys.path:
    sys.path.insert(0, str(_scripts_dir))

_spec = importlib.util.spec_from_file_location(
    "forge_sign",
    _scripts_dir / "generateSignRequestWithFoundryScript.py",
)
if _spec is None or _spec.loader is None:
    raise RuntimeError("Could not load generateSignRequestWithFoundryScript.py")
_forge = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_forge)

import generateMultiSignRequestFromCompose as _compose

hex_to_bytes = _forge.hex_to_bytes
parse_chain_id = _forge.parse_chain_id

from mpc_evm_signing_hash import (
    compute_message_hash_from_execute_unsigned_dict,
    normalize_message_hash_hex,
)

_HTTP_UA = "executeSignResult/1.0 (Python-urllib)"
DEFAULT_MPC_AUTH_URL = "http://127.0.0.1"
DEFAULT_MANAGEMENT_PORT = "8080"


def resolve_mpc_auth_base(mpc_auth_url: str, management_port: str | int | None) -> str:
    base = (mpc_auth_url or "").strip()
    if not base:
        raise ValueError("mpc_auth_url cannot be empty")
    p = urllib.parse.urlparse(base)
    if not p.scheme or not p.netloc:
        raise ValueError("mpc_auth_url must include scheme and host, e.g. http://127.0.0.1")
    if p.port is not None:
        return base.rstrip("/")
    port = str(management_port or "").strip()
    if not port:
        raise ValueError("management_port is required when mpc_auth_url has no port")
    try:
        int(port, 10)
    except ValueError as e:
        raise ValueError("management_port must be numeric") from e
    netloc = f"{p.netloc}:{port}"
    return urllib.parse.urlunparse(p._replace(netloc=netloc)).rstrip("/")


def http_get_json(url: str) -> dict[str, Any]:
    req = urllib.request.Request(
        url,
        method="GET",
        headers={"Accept": "application/json", "User-Agent": _HTTP_UA},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        raise ValueError(f"HTTP {e.code}: {body or e.reason}") from e
    except urllib.error.URLError as e:
        raise ValueError(f"Request failed: {e.reason}") from e
    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON: {e}") from e


def rpc_call(url: str, method: str, params: list[Any]) -> Any:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(
        "utf-8"
    )
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "User-Agent": _HTTP_UA},
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        out = json.loads(resp.read().decode("utf-8"))
    if "error" in out and out["error"]:
        raise RuntimeError(str(out["error"]))
    return out.get("result")


def _api_code(resp: dict[str, Any]) -> Any:
    """Management API may use ``code`` / ``Code`` (JSON from tools or older clients)."""
    c = resp.get("code")
    return c if c is not None else resp.get("Code")


def _api_data(resp: dict[str, Any]) -> Any:
    return resp.get("data") if resp.get("data") is not None else resp.get("Data")


def unwrap_api_response(resp: dict[str, Any], what: str) -> Any:
    c = _api_code(resp)
    if c is not None and c != 0:
        err = resp.get("error") or resp.get("Error") or str(resp)
        raise ValueError(f"{what} failed (code={c}): {err}")
    return _api_data(resp)


def fetch_sign_result(mpc_base: str, request_id: str) -> dict[str, Any]:
    q = urllib.parse.urlencode({"id": request_id})
    resp = http_get_json(f"{mpc_base.rstrip('/')}/getSignResultById?{q}")
    data = unwrap_api_response(resp, "getSignResultById")
    if not isinstance(data, dict):
        raise ValueError("getSignResultById: expected data object")
    return data


def fetch_sign_request(mpc_base: str, request_id: str) -> dict[str, Any]:
    q = urllib.parse.urlencode({"id": request_id})
    resp = http_get_json(f"{mpc_base.rstrip('/')}/getSignRequestById?{q}")
    data = unwrap_api_response(resp, "getSignRequestById")
    if not isinstance(data, dict):
        raise ValueError("getSignRequestById: expected data object")
    return data


def fetch_sign_request_tx_params(mpc_base: str, request_id: str) -> dict[str, Any] | None:
    """GET /getSignRequestById?tx_params=1 — same TxParams snapshot the UI stores at Get Sig (continuumdao-node-app Execute)."""
    q = urllib.parse.urlencode({"id": request_id, "tx_params": "1"})
    try:
        resp = http_get_json(f"{mpc_base.rstrip('/')}/getSignRequestById?{q}")
    except (ValueError, OSError, json.JSONDecodeError):
        return None
    c = _api_code(resp)
    data = _api_data(resp)
    if (c is not None and c != 0) or data is None:
        return None
    if not isinstance(data, dict):
        return None
    tx_type = data.get("txType")
    if tx_type not in ("eip1559", "legacy"):
        return None
    if data.get("gasLimit") in (None, ""):
        return None
    if not isinstance(data.get("nonce"), int):
        return None
    return data


def rpc_quantity_to_int(x: Any) -> int:
    if x is None:
        return 0
    if isinstance(x, int):
        return x
    s = str(x).strip()
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    return int(s, 10)


def merge_sign_detail(sign_body: dict[str, Any] | None, sign_data: dict[str, Any]) -> dict[str, Any]:
    """Later keys win (sign result over sign request). Matches UI merging to, data, value, chain."""
    out: dict[str, Any] = {}
    if sign_body:
        out.update(sign_body)
    out.update(sign_data)
    return out


def is_batch_execution(msg_raws: list[str], merged: dict[str, Any]) -> bool:
    if len(msg_raws) > 1:
        return True
    if merged.get("BatchSignRequest") or merged.get("batchSignRequest"):
        mh = merged.get("MessageHashes") or merged.get("messageHashes")
        if isinstance(mh, list) and len(mh) >= 2:
            return True
    return False


def try_prebuilt_signed_tx_bytes(sig: dict[str, Any]) -> bytes | None:
    """If the node returned a fully serialized signed tx, broadcast it directly (continuumdao-node-app)."""
    for key in ("signedTx", "SignedTx", "rawTransaction", "RawTransaction", "serializedTx", "SerializedTx"):
        v = sig.get(key)
        if isinstance(v, str):
            t = v.strip()
            if t.startswith("0x") and len(t) > 2:
                return hex_to_bytes(t)
    return None


def message_raw_to_calldata_bytes(msg_raw: str | None) -> bytes:
    """If MessageRaw is an RLP tx, use its data field; else treat hex as calldata (same as messageRawToCalldata)."""
    if not msg_raw or not str(msg_raw).strip():
        return b""
    s = str(msg_raw).strip()
    try:
        d = message_raw_hex_to_unsigned_dict(s)
        data = d.get("data")
        if isinstance(data, (bytes, bytearray)) and len(data) > 0:
            return bytes(data)
    except (ValueError, TypeError):
        pass
    return hex_to_bytes(s)


def fetch_ethereum_address_for_sign(mpc_base: str, merged: dict[str, Any]) -> str:
    kg = pick_str(merged, "KeyGenRequestId", "keyGenRequestId")
    if not kg or not str(kg).strip():
        raise ValueError("missing KeyGenRequestId on sign request/result (need ethereum address)")
    q = urllib.parse.urlencode({"id": str(kg).strip()})
    resp = http_get_json(f"{mpc_base.rstrip('/')}/getKeyGenResultById?{q}")
    data = unwrap_api_response(resp, "getKeyGenResultById")
    if not isinstance(data, dict):
        raise ValueError("getKeyGenResultById: expected object")
    addr = pick_str(data, "ethereumaddress", "EthereumAddress")
    if not addr or not str(addr).strip():
        raise ValueError("keyGen result has no ethereumaddress")
    a = str(addr).strip()
    if not a.startswith("0x"):
        a = "0x" + a
    return a


def build_unsigned_single_tx_dict_app_style(
    merged: dict[str, Any],
    msg_raw: str,
    tx_params: dict[str, Any] | None,
    chain_detail: dict[str, Any],
    rpc_url: str,
    executor: str,
    chain_id_num: int,
) -> dict[str, Any]:
    """
    Rebuild unsigned tx dict the same way continuumdao-node-app Execute does (not raw MessageRaw RLP),
    using TxParams from getSignRequestById?tx_params=1 and RPC fees/estimateGas.
    """
    execute_is_create = False
    try:
        u = message_raw_hex_to_unsigned_dict((msg_raw or "").strip())
        execute_is_create = u.get("to") is None
    except (ValueError, TypeError):
        execute_is_create = False

    to_s = pick_str(merged, "to", "To")
    dest = pick_str(merged, "DestinationAddress", "destinationAddress")
    to_addr = (to_s or dest or "").strip() or None
    if not execute_is_create and not to_addr:
        raise ValueError(
            "missing destination address (to / DestinationAddress); cannot build tx like the web Execute flow"
        )

    data_b = merged.get("data") or merged.get("Data")
    if data_b is None:
        data_b = message_raw_to_calldata_bytes(msg_raw)
    elif isinstance(data_b, str):
        data_b = hex_to_bytes(data_b) if data_b.strip() else b""
    else:
        data_b = bytes(data_b)

    val_raw = (
        pick_str(merged, "value", "Value")
        or merged.get("value")
        or merged.get("Value")
    )
    if val_raw is None or val_raw == "":
        value_int = 0
    else:
        value_int = int(str(val_raw).strip(), 0) if isinstance(val_raw, str) and val_raw.startswith("0x") else int(val_raw)

    fee_params = _compose.fetch_chain_fee_params(rpc_url, chain_id_num)

    gas_limit_cfg = pick_str(chain_detail, "gasLimit", "GasLimit")
    chain_gas_limit_cfg: int | None = None
    if gas_limit_cfg not in (None, ""):
        try:
            gl = int(gas_limit_cfg)  # type: ignore[arg-type]
            if gl > 0:
                chain_gas_limit_cfg = gl
        except (TypeError, ValueError):
            pass

    gas_mult_raw = pick_str(chain_detail, "gasMultiplier", "GasMultiplier")
    gas_fee_multiplier: int | None = None
    if gas_mult_raw not in (None, ""):
        try:
            gas_fee_multiplier = int(gas_mult_raw)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            pass

    chain_gas_price = pick_str(chain_detail, "gasPrice", "GasPrice")
    chain_gas_price_gwei: float | None = None
    if chain_gas_price not in (None, ""):
        try:
            chain_gas_price_gwei = float(chain_gas_price)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            pass

    base_fee_mult_raw = pick_str(chain_detail, "baseFeeMultiplier", "BaseFeeMultiplier")
    base_fee_multiplier_pct = 100
    if base_fee_mult_raw not in (None, ""):
        try:
            base_fee_multiplier_pct = max(100, int(base_fee_mult_raw))  # type: ignore[arg-type]
        except (TypeError, ValueError):
            pass

    legacy_flag = pick_str(chain_detail, "legacy", "Legacy")
    legacy_from_chain = legacy_flag is True or str(legacy_flag).lower() == "true"
    if tx_params is not None and tx_params.get("txType") == "legacy":
        legacy = True
    elif tx_params is not None and str(tx_params.get("txType") or "").strip().lower() in (
        "0x2",
        "eip1559",
        "2",
    ):
        legacy = False
    else:
        legacy = legacy_from_chain or not bool(fee_params.get("isEip1559"))

    # Nonce: TxParams first, then sign result fields, then chain pending
    nonce: int | None = None
    if tx_params is not None and isinstance(tx_params.get("nonce"), int):
        nonce = int(tx_params["nonce"])
    else:
        for k in ("txNonce", "nonce", "Nonce"):
            v = merged.get(k)
            if v is not None and str(v).strip() != "":
                nonce = int(v) if isinstance(v, int) else int(str(v).strip(), 0)
                break
    if nonce is None:
        nonce = rpc_quantity_to_int(
            rpc_call(rpc_url, "eth_getTransactionCount", [executor, "pending"])
        )

    # estimateGas
    est_params: dict[str, Any] = {"from": executor, "value": hex(value_int)}
    if data_b:
        est_params["data"] = "0x" + data_b.hex()
    if not execute_is_create and to_addr:
        est_params["to"] = to_addr if to_addr.startswith("0x") else "0x" + to_addr
    try:
        est_hex = rpc_call(rpc_url, "eth_estimateGas", [est_params])
        estimated = rpc_quantity_to_int(est_hex)
    except (RuntimeError, OSError):
        estimated = 21_000

    # Gas limit: match generateMultiSignRequestFromCompose.build_compose_multisign.
    gas_limit = estimated
    if chain_gas_limit_cfg is not None and chain_gas_limit_cfg > 0:
        gas_limit = max(chain_gas_limit_cfg, estimated)
    if tx_params is not None and tx_params.get("gasLimit") not in (None, ""):
        gas_limit = int(str(tx_params["gasLimit"]).strip())
    if gas_limit < estimated:
        raise ValueError(
            f"effective gas limit ({gas_limit}) is below eth_estimateGas ({estimated}). "
            "Increase chain gasLimit in GET /getChainDetails, or ensure trigger txParams gasLimit matches."
        )

    if legacy:
        gp_raw = None
        if tx_params is not None:
            gp_raw = tx_params.get("gasPrice")
        if gp_raw in (None, ""):
            gp_raw = merged.get("txGasPrice")
        fees_from_tx_params_legacy = gp_raw not in (None, "")
        if fees_from_tx_params_legacy:
            gas_price_wei = int(str(gp_raw).strip()) if isinstance(gp_raw, int) else int(str(gp_raw).strip(), 0)
        else:
            gas_price_wei = _compose.eth_gas_price(rpc_url)
            if gas_fee_multiplier is not None and gas_fee_multiplier > 0:
                gas_price_wei = (gas_price_wei * (100 + gas_fee_multiplier)) // 100
            if chain_gas_price_gwei is not None and chain_gas_price_gwei > 0:
                configured = _compose._gwei_to_wei_ceil(chain_gas_price_gwei)
                if configured > gas_price_wei:
                    gas_price_wei = configured
        out: dict[str, Any] = {
            "nonce": nonce,
            "gasPrice": gas_price_wei,
            "gas": gas_limit,
            "value": value_int,
            "data": data_b,
            "chainId": chain_id_num,
        }
        if not execute_is_create and to_addr:
            out["to"] = to_addr if to_addr.startswith("0x") else "0x" + to_addr
        return out

    # EIP-1559: match generateMultiSignRequestFromCompose (gasMultiplier is legacy-only there).
    max_prio: int
    max_fee: int
    tx_mp = tx_params.get("maxPriorityFeePerGas") if tx_params else None
    tx_mf = tx_params.get("maxFeePerGas") if tx_params else None
    if tx_mp in (None, "") and merged:
        tx_mp = merged.get("txMaxPriorityFeePerGas") or merged.get("TxMaxPriorityFeePerGas")
    if tx_mf in (None, "") and merged:
        tx_mf = merged.get("txMaxFeePerGas") or merged.get("TxMaxFeePerGas")
    fees_from_tx_params_eip1559 = tx_mp not in (None, "") and tx_mf not in (None, "")
    if fees_from_tx_params_eip1559:
        max_prio = int(str(tx_mp).strip())
        max_fee = int(str(tx_mf).strip())
    elif fee_params.get("isEip1559"):
        base = float(fee_params.get("baseFeeGwei") or 0)
        prio = float(fee_params.get("priorityFeeGwei") or 0)
        base_component = base * base_fee_multiplier_pct / 100.0
        max_prio = _compose._gwei_to_wei_ceil(prio) if prio > 0 else _compose._gwei_to_wei_ceil(1.0)
        max_fee = _compose._gwei_to_wei_ceil(base_component + prio)
    else:
        gp = _compose.eth_gas_price(rpc_url)
        max_prio = max(gp // 10, 10**9)
        max_fee = max(gp * 2, max_prio * 2)

    out2: dict[str, Any] = {
        "type": 2,
        "chainId": chain_id_num,
        "nonce": nonce,
        "gas": gas_limit,
        "value": value_int,
        "data": data_b,
        "maxPriorityFeePerGas": max_prio,
        "maxFeePerGas": max_fee,
        "accessList": [],
    }
    if not execute_is_create and to_addr:
        out2["to"] = to_addr if to_addr.startswith("0x") else "0x" + to_addr
    return out2


def signed_raw_single_like_app(
    mpc_base: str,
    rpc_url: str,
    request_id: str,
    merged: dict[str, Any],
    msg_raw: str,
    sig: dict[str, Any],
    chain_detail: dict[str, Any],
    chain_id_num: int,
) -> bytes:
    pre = try_prebuilt_signed_tx_bytes(sig)
    if pre is not None:
        return pre

    tx_params = fetch_sign_request_tx_params(mpc_base, request_id)
    executor = fetch_ethereum_address_for_sign(mpc_base, merged)
    tx_dict = build_unsigned_single_tx_dict_app_style(
        merged, msg_raw, tx_params, chain_detail, rpc_url, executor, chain_id_num
    )
    stored_mh = pick_str(merged, "MessageHash", "msgHash")
    if stored_mh and tx_params is not None and tx_params.get("gasLimit") not in (None, ""):
        built = compute_message_hash_from_execute_unsigned_dict(tx_dict)
        if normalize_message_hash_hex(built) != normalize_message_hash_hex(stored_mh):
            raise ValueError(
                "Rebuilt unsigned transaction does not match MessageHash on the sign request (the MPC signature "
                "is over a different preimage). Common causes: multiSignRequest or trigger used mismatched "
                "txParams vs messageHash, or the recipe was run twice with different gas/fees and outputs were "
                "mixed. Use one recipe run: POST that bodyForSign only, agree, then trigger with the same "
                "triggerMessageHash and triggerTxParams from that JSON. "
                f"computed_hash={built} stored_MessageHash={normalize_message_hash_hex(stored_mh)}"
            )
    utx = serializable_unsigned_transaction_from_dict(tx_dict)
    r, s, v_byte = parse_signature_components(sig)
    legacy_cid = None
    if not isinstance(utx, TypedTransaction):
        legacy_cid = tx_dict.get("chainId")
        if legacy_cid is not None:
            legacy_cid = int(legacy_cid)
    r, s, v = finalize_vrs(r, s, v_byte, unsigned=utx, legacy_chain_id=legacy_cid)
    raw = encode_transaction(utx, (v, r, s))

    pending_nonce = rpc_quantity_to_int(rpc_call(rpc_url, "eth_getTransactionCount", [executor, "pending"]))
    built_nonce = int(tx_dict.get("nonce", 0))
    if pending_nonce > built_nonce:
        raise ValueError(
            "Chain nonce has already advanced past this transaction (likely already executed). "
            "Do not broadcast the same signatures again."
        )
    return raw


def fetch_chain_detail_for_id(mpc_base: str, chain_id_num: int) -> dict[str, Any]:
    base = mpc_base.rstrip("/")
    resp = http_get_json(f"{base}/getChainDetails?chain_id={chain_id_num}")
    ac = _api_code(resp)
    if ac is not None and ac != 0:
        err = resp.get("error") or resp.get("Error") or str(resp)
        raise ValueError(f"getChainDetails failed (code={ac}): {err}")
    data = _api_data(resp)
    rows: list[dict[str, Any]]
    if isinstance(data, list):
        rows = [x for x in data if isinstance(x, dict)]
    elif isinstance(data, dict):
        rows = [data]
    else:
        rows = []
    if not rows:
        raise ValueError("getChainDetails: empty data")
    want = str(chain_id_num)
    for row in rows:
        cid = row.get("chainId") if row.get("chainId") is not None else row.get("ChainId")
        if cid is not None and str(cid).strip() == want:
            return row
    return rows[0]


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


def resolve_rpc_url(
    mpc_base: str,
    chain_id: int,
    rpc_override: str | None,
) -> str:
    if rpc_override and str(rpc_override).strip():
        return str(rpc_override).strip().rstrip("/")
    row = fetch_chain_detail_for_id(mpc_base, chain_id)
    url = str(pick_str(row, "rpcGateway", "RpcGateway", "rpc_gateway") or "").strip()
    if not url:
        raise ValueError(
            "No --rpc-url provided and getChainDetails has no rpcGateway for this chain; "
            "set --rpc-url or configure the chain on the node (postChainDetails)."
        )
    return url.rstrip("/")


def unwrap_sign_body(obj: dict[str, Any]) -> dict[str, Any]:
    if "bodyForSign" in obj and isinstance(obj["bodyForSign"], dict):
        return obj["bodyForSign"]
    if "body" in obj and isinstance(obj["body"], dict):
        return obj["body"]
    if (
        "msgHash" in obj
        or "MessageHash" in obj
        or "messageHashes" in obj
        or "MessageHashes" in obj
        or "destinationChainID" in obj
        or "DestinationChainID" in obj
    ):
        return obj
    raise ValueError("sign request JSON must contain bodyForSign, body, or a raw sign-request body")


def coerce_wrapped_json_object(loaded: dict[str, Any]) -> dict[str, Any]:
    """
    Accept a saved API envelope ``{code, data}`` / ``{Code, Data}`` or a raw sign request/result
    object (same shapes as ``GET /getSignResultById`` / ``getSignRequestById``).
    """
    inner = loaded.get("data")
    if inner is None:
        inner = loaded.get("Data")
    if isinstance(inner, dict):
        return inner
    return loaded


def _decode_type2_unsigned(raw: bytes) -> dict[str, Any]:
    if len(raw) < 2 or raw[0] != 0x02:
        raise ValueError("expected EIP-1559 type-2 unsigned transaction bytes")
    inner = raw[1:]
    decoded = rlp.decode(inner)
    if not isinstance(decoded, list) or len(decoded) != 9:
        raise ValueError(
            f"unexpected type-2 unsigned RLP (got {len(decoded) if isinstance(decoded, list) else 'n/a'} fields)"
        )
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
        raise ValueError("executeSignResult: non-empty accessList is not supported yet")
    to_hex: str | None
    if to_b and len(to_b) == 20:
        to_hex = "0x" + to_b.hex()
    elif to_b in (b"", None):
        to_hex = None
    else:
        raise ValueError("invalid 'to' in type-2 transaction")
    return {
        "type": 2,
        "chainId": chain_id,
        "nonce": nonce,
        "maxPriorityFeePerGas": max_prio,
        "maxFeePerGas": max_fee,
        "gas": gas,
        "to": to_hex,
        "value": value,
        "data": data_b,
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
            "nonce": nonce,
            "gasPrice": gas_price,
            "gas": gas,
            "to": to_hex,
            "value": value,
            "data": data_b,
            "chainId": chain_id,
        }
    raise ValueError(f"executeSignResult: unsupported legacy unsigned RLP length {len(decoded)}")


def message_raw_hex_to_unsigned_dict(msg_raw: str) -> dict[str, Any]:
    s = (msg_raw or "").strip()
    if not s:
        raise ValueError("empty messageRaw")
    raw = hex_to_bytes(s)
    if len(raw) == 0:
        raise ValueError("empty messageRaw")
    try:
        if raw[0] == 0x02:
            return _decode_type2_unsigned(raw)
        if raw[0] == 0x01:
            raise ValueError("executeSignResult: EIP-2930 type-1 transactions are not supported yet")
        if raw[0] == 0x03:
            raise ValueError("executeSignResult: blob (type-3) transactions are not supported yet")
        if raw[0] == 0x04:
            raise ValueError("executeSignResult: set-code (type-4) transactions are not supported yet")
        return _decode_legacy_unsigned(raw)
    except DecodingError as e:
        raise ValueError(
            "messageRaw is not valid unsigned transaction RLP (calldata-only hex, truncated tx, "
            f"or malformed RLP): {e}"
        ) from e


def _pick_sig_field(d: dict[str, Any], *names: str) -> Any:
    for n in names:
        if n in d:
            return d[n]
    lower = {str(k).lower(): v for k, v in d.items()}
    for n in names:
        if n.lower() in lower:
            return lower[n.lower()]
    return None


def _big_int_from_hexish(x: Any) -> int:
    if x is None:
        raise ValueError("missing integer field")
    if isinstance(x, int):
        return x
    b = hex_to_bytes(str(x))
    if not b:
        return 0
    return int.from_bytes(b[-32:].rjust(32, b"\x00"), "big")


def parse_signature_components(sig: dict[str, Any]) -> tuple[int, int, int]:
    """Return (r, s, v_byte) where v_byte is the last byte of a 65-byte eth sig when present."""
    eth = _pick_sig_field(sig, "ethereumSignature", "ethereumsignature")
    if eth:
        h = hex_to_bytes(str(eth))
        if len(h) == 65:
            r = int.from_bytes(h[0:32], "big")
            s = int.from_bytes(h[32:64], "big")
            v = h[64]
            return r, s, v
        raise ValueError(f"ethereumSignature must be 65 bytes (130 hex chars), got {len(h)} bytes")

    r = _big_int_from_hexish(_pick_sig_field(sig, "sigr", "sigR"))
    s = _big_int_from_hexish(_pick_sig_field(sig, "sigs", "sigS"))
    rec = _pick_sig_field(sig, "sigrecover", "sigRecover")
    if rec is None:
        raise ValueError("signature missing ethereumSignature and sigrecover")
    rb = hex_to_bytes(str(rec))
    if len(rb) == 0:
        raise ValueError("empty sigrecover")
    v = rb[-1]
    return r, s, v


def finalize_vrs(
    r: int,
    s: int,
    v_byte: int,
    *,
    unsigned: Union[TypedTransaction, Any],
    legacy_chain_id: int | None,
) -> tuple[int, int, int]:
    """Map MPC v byte to the ``v`` expected by ``encode_transaction`` for typed vs legacy."""
    is_typed = isinstance(unsigned, TypedTransaction)
    if is_typed:
        if v_byte in (0, 1):
            return r, s, v_byte
        if v_byte in (27, 28):
            return r, s, v_byte - 27
        raise ValueError(f"typed transaction: expected v parity 0/1 or 27/28, got {v_byte}")

    if v_byte >= 35:
        return r, s, v_byte
    if legacy_chain_id is not None and legacy_chain_id > 0:
        if v_byte in (0, 1):
            return r, s, legacy_chain_id * 2 + 35 + v_byte
        if v_byte in (27, 28):
            return r, s, legacy_chain_id * 2 + 35 + (v_byte - 27)
        raise ValueError(f"legacy EIP-155: unexpected v/recovery byte {v_byte}")
    if v_byte in (27, 28):
        return r, s, v_byte
    if v_byte in (0, 1):
        return r, s, v_byte + 27
    raise ValueError(f"legacy transaction: unexpected v byte {v_byte}")


def _sign_from_message_raw_rlp(msg_raw: str, sig: dict[str, Any]) -> bytes:
    """
    Decode unsigned tx from MessageRaw RLP and apply MPC signature (batch txs; also used when the
    unsigned blob is authoritative).
    """
    tx_dict = message_raw_hex_to_unsigned_dict(msg_raw)
    utx = serializable_unsigned_transaction_from_dict(tx_dict)
    r, s, v_byte = parse_signature_components(sig)
    legacy_cid = None
    if not isinstance(utx, TypedTransaction):
        legacy_cid = tx_dict.get("chainId")
        if legacy_cid is not None:
            legacy_cid = int(legacy_cid)
    r, s, v = finalize_vrs(r, s, v_byte, unsigned=utx, legacy_chain_id=legacy_cid)
    return encode_transaction(utx, (v, r, s))


def build_signed_raw_dispatch(
    mpc_base: str,
    rpc_url: str,
    request_id: str,
    merged: dict[str, Any],
    msg_raw: str,
    sig: dict[str, Any],
    batch: bool,
    chain_detail: dict[str, Any],
    chain_id_num: int,
) -> bytes:
    """
    Single-tx: rebuild unsigned tx like continuumdao-node-app Execute (TxParams + RPC + estimateGas).
    Batch: combine batchsignatures[i] with MessageRawBatch[i] RLP (app buildBatchSignedTxsFromResult).
    """
    if batch:
        return _sign_from_message_raw_rlp(msg_raw, sig)
    return signed_raw_single_like_app(
        mpc_base,
        rpc_url,
        request_id,
        merged,
        msg_raw,
        sig,
        chain_detail,
        chain_id_num,
    )


def eth_send_raw_transaction(rpc_url: str, raw: bytes) -> str:
    h = rpc_call(rpc_url, "eth_sendRawTransaction", ["0x" + raw.hex()])
    if not isinstance(h, str):
        raise RuntimeError(f"unexpected eth_sendRawTransaction result: {h!r}")
    return h


def wait_for_receipt(rpc_url: str, tx_hash: str, timeout_sec: float = 180.0) -> dict[str, Any]:
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        r = rpc_call(rpc_url, "eth_getTransactionReceipt", [tx_hash])
        if r is not None:
            if isinstance(r, dict):
                return r
            raise RuntimeError(f"unexpected receipt: {r!r}")
        time.sleep(1.0)
    raise TimeoutError(f"Timed out waiting for receipt for {tx_hash}")


def load_json_file(path: str) -> dict[str, Any]:
    p = Path(path)
    text = p.read_text(encoding="utf-8").strip()
    if not text:
        raise ValueError(f"empty file: {path}")
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError(f"expected JSON object in {path}")
    return data


def _message_raws_from_dict(d: dict[str, Any]) -> list[str] | None:
    """Return unsigned tx hex list if *d* carries message fields; else None."""
    batch = d.get("messageRawBatch") or d.get("message_raw_batch")
    if isinstance(batch, list) and len(batch) > 0:
        return [str(x) for x in batch]
    single = pick_str(d, "msgRaw", "messageRaw", "msg_raw", "MessageRaw")
    if single is not None and str(single).strip():
        return [str(single).strip()]
    return None


def extract_message_raws(
    sign_body: dict[str, Any] | None,
    sign_result: dict[str, Any] | None = None,
) -> list[str]:
    """Prefer the sign result (API often echoes unsigned tx hex there), then the sign request."""
    if sign_result is not None:
        got = _message_raws_from_dict(sign_result)
        if got is not None:
            return got
    if sign_body is not None:
        got = _message_raws_from_dict(sign_body)
        if got is not None:
            return got
    raise ValueError(
        "No msgRaw/messageRaw/MessageRaw nor messageRawBatch on sign result or sign request."
    )


def extract_signatures(sign_data: dict[str, Any]) -> list[dict[str, Any]]:
    batch = sign_data.get("batchSignatures") or sign_data.get("batchsignatures")
    if isinstance(batch, list) and len(batch) > 0:
        out = [x for x in batch if isinstance(x, dict)]
        if len(out) != len(batch):
            raise ValueError("batchSignatures entries must be objects")
        return out
    return [sign_data]


def check_key_type(sign_data: dict[str, Any]) -> None:
    kt = _pick_sig_field(sign_data, "keytype", "keyType", "KeyType")
    if kt is None:
        return
    if str(kt).lower() == "ed25519":
        raise ValueError(
            "This script only broadcasts EVM (secp256k1) transactions; keytype is ed25519."
        )


def print_agent_remediation_after_execute_failure(
    sign_request_id: str | None,
    *,
    reason: str | None = None,
) -> None:
    """
    Stderr instructions for automation: mark the sign result failed, optionally shelve the request, notify the Group.
    """
    lines = [
        "",
        "---",
        "AI agent follow-up (executeSignResult failed — irrecoverable broadcast/build error):",
        "1. POST /updateSignResultStatusById — management-signed JSON per API_IMPLEMENTATION.md: Nonce, Sig, requestId, "
        "status: 'failed' (same pattern as continuumdao-node-app). Marks the sign result as failed so peers are not "
        "left waiting for a successful on-chain execution.",
        "2. POST /shelveSignRequest — optional: management-signed so the sign request is shelved and drops from "
        "pending/ready lists (same requestId as step 1).",
        "3. POST /sendMessage — to the Group KeyGen thread: quote the error below, state that the sign result was "
        "marked failed (or will be), and what to check next (gas, RPC, chain config, nonce, MessageHash mismatch, etc.).",
    ]
    rid = (sign_request_id or "").strip()
    if rid:
        lines.append(f"   Sign request id: {rid}")
    else:
        lines.append(
            "   Sign request id: unknown here — use --sign-request-id or ensure requestid is in --sign-result-file "
            "before calling updateSignResultStatusById / shelve / sendMessage."
        )
    if reason:
        lines.append(f"   Failure detail: {reason}")
    lines.append(
        "References: docs/references/API_IMPLEMENTATION.md (POST /updateSignResultStatusById, POST /shelveSignRequest), "
        "docs/references/API_KEYGEN_MESSAGING.md (POST /sendMessage)."
    )
    lines.append("---")
    print("\n".join(lines), file=sys.stderr)


def print_agent_completion_after_execute_success(
    sign_request_id: str | None,
    results: list[dict[str, Any]],
) -> None:
    """
    Stderr instructions after all txs broadcast and receipts received: mark sign result executed
    and surface hashes for the end user.
    """
    hashes: list[str] = []
    for r in results:
        h = r.get("transactionHash")
        if h is not None and str(h).strip():
            hashes.append(str(h).strip())
    rid = (sign_request_id or "").strip()
    lines = [
        "",
        "---",
        "AI agent follow-up (executeSignResult succeeded — all transactions broadcast; receipts returned):",
        "1. POST /updateSignResultStatusById — management-signed JSON per API_IMPLEMENTATION.md § POST /updateSignResultStatusById:",
        "   - requestId: the sign request id (same id you used for getSignResult / executeSignResult).",
        "   - status: 'executed'",
    ]
    if len(hashes) <= 1:
        lines.append(
            "   - transactionHash: the hash below (single-tx sign result). Omit batchTransactionHashes."
        )
    else:
        lines.append(
            "   - batchTransactionHashes: array of tx hashes in batch order (length must match batch size). "
            "Omit transactionHash when all hashes are listed here."
        )
    lines.append(
        "   - nonce, sig: management API signing pattern (sig over body with sig empty), same as other management POSTs."
    )
    lines.append(
        "2. Tell the end user the transaction hash(es) below (they can look up the tx on a block explorer for this chain)."
    )
    if rid:
        lines.append(f"   Sign request id (requestId): {rid}")
    else:
        lines.append(
            "   Sign request id: use signRequestId from the JSON printed on stdout, or --sign-request-id / "
            "requestid in --sign-result-file."
        )
    if hashes:
        if len(hashes) == 1:
            lines.append(f"   Transaction hash: {hashes[0]}")
        else:
            lines.append("   Transaction hashes (batch index order):")
            for i, h in enumerate(hashes):
                lines.append(f"      [{i}] {h}")
    lines.append(
        "Reference: docs/references/API_IMPLEMENTATION.md (POST /updateSignResultStatusById — executed, "
        "transactionHash / batchTransactionHashes)."
    )
    lines.append("---")
    print("\n".join(lines), file=sys.stderr)


def main() -> None:
    ap = argparse.ArgumentParser(description="Broadcast MPC sign results to an EVM chain.")
    ap.add_argument(
        "--sign-request-id",
        help="Sign request id for API calls and reporting; optional if --sign-result-file "
        "contains requestid",
    )
    ap.add_argument(
        "--mpc-auth-url",
        default=(os.environ.get("MPC_AUTH_URL") or DEFAULT_MPC_AUTH_URL),
        help=f"Management API host URL (env MPC_AUTH_URL, default: {DEFAULT_MPC_AUTH_URL})",
    )
    ap.add_argument(
        "--management-port",
        default=(os.environ.get("MANAGEMENT_PORT") or DEFAULT_MANAGEMENT_PORT),
        help=f"Management API port (env MANAGEMENT_PORT, default: {DEFAULT_MANAGEMENT_PORT})",
    )
    ap.add_argument(
        "--sign-result-file",
        metavar="PATH",
        help="JSON from getSignResultById, raw sign-result object, or envelope {data}/{Data}; skips HTTP",
    )
    ap.add_argument(
        "--sign-request-file",
        metavar="PATH",
        help="JSON from getSignRequestById, raw body, or envelope {data}/{Data}; optional when the "
        "sign result already includes message raw and DestinationChainID",
    )
    ap.add_argument(
        "--rpc-url",
        help="JSON-RPC URL; if omitted, uses getChainDetails.rpcGateway for DestinationChainID",
    )
    ap.add_argument(
        "--fast",
        action="store_true",
        help="Submit and confirm all transactions concurrently (default: sequential)",
    )
    ap.add_argument(
        "--receipt-timeout",
        type=float,
        default=180.0,
        help="Seconds to wait for each transaction receipt (default: 180)",
    )
    args = ap.parse_args()
    mpc = resolve_mpc_auth_base(args.mpc_auth_url, args.management_port)

    # Mutable so _execute_sign_result_main can refresh id from --sign-result-file for remediation text.
    sign_request_id_box: list[str] = [(args.sign_request_id or "").strip()]

    try:
        _execute_sign_result_main(args, mpc, sign_request_id_box)
    except KeyboardInterrupt:
        raise
    except Exception as e:
        sid = sign_request_id_box[0].strip() if sign_request_id_box else ""
        print_agent_remediation_after_execute_failure(
            sid if sid else None,
            reason=str(e),
        )
        print(f"error: {e}", file=sys.stderr)
        raise SystemExit(1) from e


def _execute_sign_result_main(
    args: argparse.Namespace,
    mpc: str,
    sign_request_id_box: list[str],
) -> None:
    request_id = sign_request_id_box[0]
    if args.sign_result_file:
        loaded = load_json_file(args.sign_result_file)
        sign_data = coerce_wrapped_json_object(loaded)
        if not request_id and isinstance(sign_data, dict):
            rid = pick_str(sign_data, "requestid", "requestId", "RequestId")
            if rid:
                request_id = str(rid).strip()
                sign_request_id_box[0] = request_id
    else:
        if not request_id:
            raise SystemExit("error: --sign-request-id is required when not using --sign-result-file")
        sign_data = fetch_sign_result(mpc, request_id)

    if not isinstance(sign_data, dict):
        raise SystemExit("sign result must be a JSON object")

    check_key_type(sign_data)

    msg_on_result = _message_raws_from_dict(sign_data) is not None
    dest_on_result = pick_str(sign_data, "DestinationChainID", "destinationChainID") is not None
    can_skip_sign_request = msg_on_result and dest_on_result

    if not request_id and not args.sign_request_file and not can_skip_sign_request:
        raise SystemExit(
            "error: need --sign-request-id (or requestid inside --sign-result-file) or --sign-request-file "
            "when the sign result omits unsigned tx hex (msgRaw/messageRaw/MessageRaw/messageRawBatch) "
            "or DestinationChainID."
        )

    sign_body: dict[str, Any] | None = None
    if args.sign_request_file:
        loaded = load_json_file(args.sign_request_file)
        raw_req = coerce_wrapped_json_object(loaded)
        sign_body = unwrap_sign_body(raw_req if isinstance(raw_req, dict) else loaded)
    elif not can_skip_sign_request:
        if not request_id:
            raise SystemExit(
                "error: --sign-request-id is required when the sign result lacks message raw or "
                "destination chain and --sign-request-file is not set."
            )
        sign_body = unwrap_sign_body(fetch_sign_request(mpc, request_id))

    msg_raws = extract_message_raws(sign_body, sign_data)
    sigs = extract_signatures(sign_data)
    if len(msg_raws) != len(sigs):
        raise SystemExit(
            f"message count ({len(msg_raws)}) != signature count ({len(sigs)}); "
            "check messageRawBatch vs batchSignatures alignment."
        )

    merged = merge_sign_detail(sign_body, sign_data)
    batch_exec = is_batch_execution(msg_raws, merged)

    dest_chain = (
        pick_str(sign_data, "DestinationChainID", "destinationChainID")
        or (
            pick_str(sign_body, "DestinationChainID", "destinationChainID", "destination_chain_id")
            if sign_body
            else None
        )
    )
    if dest_chain is None or str(dest_chain).strip() == "":
        raise SystemExit("Could not determine destination chain id from sign result or request.")
    chain_num = parse_chain_id(str(dest_chain).strip())
    if chain_num <= 0:
        raise SystemExit(f"Invalid destination chain id: {dest_chain!r}")

    rpc_url = resolve_rpc_url(mpc, chain_num, args.rpc_url)
    chain_detail_row = fetch_chain_detail_for_id(mpc, chain_num)

    timeout = float(args.receipt_timeout)

    def work(i: int, mr: str, sg: dict[str, Any]) -> dict[str, Any]:
        raw = build_signed_raw_dispatch(
            mpc,
            rpc_url,
            request_id or "",
            merged,
            mr,
            sg,
            batch_exec,
            chain_detail_row,
            chain_num,
        )
        tx_hash = eth_send_raw_transaction(rpc_url, raw)
        receipt = wait_for_receipt(rpc_url, tx_hash, timeout_sec=timeout)
        status = receipt.get("status")
        return {
            "index": i,
            "transactionHash": tx_hash,
            "status": status,
            "blockNumber": receipt.get("blockNumber"),
            "gasUsed": receipt.get("gasUsed"),
        }

    if args.fast:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(msg_raws))) as ex:
            futs = [ex.submit(work, i, msg_raws[i], sigs[i]) for i in range(len(msg_raws))]
            results = [f.result() for f in futs]
        results.sort(key=lambda x: x["index"])
    else:
        results = []
        for i in range(len(msg_raws)):
            results.append(work(i, msg_raws[i], sigs[i]))

    out = {
        "rpcUrl": rpc_url,
        "destinationChainID": chain_num,
        "signRequestId": request_id or None,
        "fast": bool(args.fast),
        "results": results,
    }
    print(json.dumps(out, indent=2))
    print_agent_completion_after_execute_success(request_id or None, results)


if __name__ == "__main__":
    main()
