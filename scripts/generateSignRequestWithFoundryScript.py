#!/usr/bin/env python3
"""
generateSignRequestWithFoundryScript

**Designed for AI agents** running on the **same machine as one of the MPC nodes**
(local management API). See ``docs/references/AI_AGENT_FORGE_SIGNREQUEST.md`` for the
full agent workflow.

For MPC keys with MsgCheck type **multi-agree** only. Output is always for
POST **/multiSignRequest** (never /signRequest; that endpoint is for tx-check
relayer keys). The server rejects multiSignRequest for non-multi-agree keys.

**keyList** and **pubKey** are filled by calling **GET /getKeyGenResultById** on the
local node. Set ``--mpc-auth-url`` to ``http://localhost:<port>`` where **port** is
**ManagementAPIsPort** in the node’s ``configs.yaml`` (often 8080 in sample configs).
See ``docs/references/AGENT_ED25519_SETUP.md`` §8.2. You must pass **--key-gen-id**.

Reads Foundry broadcast JSON (e.g. from `forge script` without --broadcast but with --rpc-url and --sender, or
broadcast/.../run-latest.json) from stdin or a file and prints a JSON wrapper
with keys endpoint (always multiSignRequest) and body suitable for that POST.
Single-tx Foundry runs use msgHash/msgRaw; multiple txs use messageHashes /
messageRawBatch and extraJSON.batchMeta for per-item destinationAddress and
signatureText. The caller must still add **clientSig** (management key) before posting.

Supports two broadcast shapes:
- transactions[].transaction: { from, gas, value, input, nonce, chainId, to?, type?, maxFeePerGas?, ... }
- transactions[].tx: { type, from, to, gas, value, data, nonce, chainId?, ... }

Nonce refresh and sender override
----------------------------------
If the broadcast was produced with a different sender (e.g. Anvil default key or
a throwaway), you can override the sender and set fresh nonces without re-running
forge script:

  --override-sender ADDR   Use this address as from for every transaction.
  --first-nonce N          Set nonces to N, N+1, N+2, ... (default: 0).

Example: broadcast from Anvil key, then sign with MPC KeyGen address and current
nonce 5:

  python3 scripts/generateSignRequestWithFoundryScript.py --key-gen-id=KeyGen... \\
    --override-sender 0xYourKeyGenAddress --first-nonce 5 \\
    < broadcast/.../run-latest.json

Gas params and custom gas configuration
---------------------------------------
By default, the script uses gas and fee fields exactly as present in the broadcast
(e.g. from `forge script --with-gas-price 50gwei`). You can instead augment or
override gas/fee for every transaction so that the payload is valid for execution
(e.g. when the broadcast came from a dry-run or has zero gas price):

  Fee params (current chain / RPC-style; overridden by chain config when set):
  --is-eip1559             Use EIP-1559 (type 0x2) fees. Default if no --legacy.
  --legacy                  Use legacy gasPrice instead of EIP-1559.
  --base-fee-gwei N        EIP-1559: base fee in gwei (default 0).
  --priority-fee-gwei N    EIP-1559: priority fee in gwei (default 1).
  --gas-price-gwei N       Legacy: gas price in gwei (default 1).

  Chain config overrides (same logic as manual batch in the app):
  --gas-limit N            Set gas limit for every tx (default: keep from broadcast or 21000).
  --gas-price N            Legacy: minimum gas price in gwei (max of this and --gas-price-gwei).
  --base-fee-multiplier N  EIP-1559: base fee percentage, >= 100 (default 100).
  --gas-multiplier N       Legacy: extra percentage on gas price, e.g. 20 = +20%%.

If any of these gas/fee options are given, the script augments the broadcast
before building the sign request. Omitted fee params default to safe values
(priority 1 gwei, etc.).

Example: dry-run broadcast with no fees; set EIP-1559 and current fees:

  python3 scripts/generateSignRequestWithFoundryScript.py --key-gen-id=KeyGen... \\
    --is-eip1559 --base-fee-gwei 30 --priority-fee-gwei 2 \\
    --first-nonce 0 --override-sender 0xYourKeyGen \\
    < broadcast/.../dry-run/run-latest.json

Usage
-----
  # Use the same port as ManagementAPIsPort in configs.yaml (default below is 8080 if unchanged).
  python3 scripts/generateSignRequestWithFoundryScript.py --key-gen-id=KeyGen... < broadcast/My.s.sol/1/run-latest.json
  python3 scripts/generateSignRequestWithFoundryScript.py --key-gen-id=KeyGen... --mpc-auth-url=http://127.0.0.1 --management-port=9000 < ...

  # Or from file path
  python3 scripts/generateSignRequestWithFoundryScript.py --key-gen-id=KeyGen... --file=broadcast/My.s.sol/1/run-latest.json

  # Producing the broadcast file with forge script: use only --rpc-url and --sender.
  # No need to pass --json, -vvv and do not pass --broadcast. Then pass the resulting broadcast
  # file (e.g. broadcast/.../run-latest.json) via stdin or --file.
  #
  #   forge script script/My.s.sol --rpc-url https://... --sender 0x...
  #   python3 scripts/generateSignRequestWithFoundryScript.py --key-gen-id=KeyGen... < broadcast/My.s.sol/CHAIN/run-latest.json

Output
------
The script prints a single JSON object to stdout with:

  endpoint   Always "multiSignRequest" (this payload is for POST /multiSignRequest only).
  body       Object to send as the request body. keyList and pubKey are filled from the node;
             add clientSig (management key) before posting.
  chainId    Destination chain ID (decimal string) from the broadcast or --destination-chain-id.
  count      Number of transactions (1 = single, >1 = batch).

  body fields:
  - destinationChainID   (required) Decimal chain ID string.
  - For a single transaction (count === 1):
    - msgHash, msgRaw    Signing hash (hex, no 0x) and serialized unsigned tx (hex with 0x).
    - destinationAddress, signatureText, extraJSON  Optional; from options or derived.
  - For a batch (count > 1):
    - messageHashes, messageRawBatch   Arrays of signing hash and serialized tx per item.
    - extraJSON   JSON string containing batchMeta: array of { destinationAddress, signatureText }
                  per transaction (for display in the app).
    - destinationAddress, signatureText  First item's values (top-level for compatibility).
  - keyList, pubKey   From GET /getKeyGenResultById for --key-gen-id (same machine as node).
  - purpose           When given via --purpose.

Use this output as the basis for the POST body; add **clientSig** only, then POST to /multiSignRequest.

Requires: eth_account (install into ``$MPA_PATH/.venv``; see ``docs/skill/SKILL.md`` **Python dependencies**)
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

# Anvil/simulation internal chain ID; never use as destination.
ANVIL_SIMULATION_CHAIN_ID = "364865"

# Fallback only if configs.yaml still has the sample port. User should set
# --mpc-auth-url from ManagementAPIsPort in configs.yaml (see AGENT_ED25519_SETUP.md).
DEFAULT_MPC_AUTH_URL = "http://127.0.0.1"
DEFAULT_MANAGEMENT_PORT = "8080"

_HTTP_UA = "generateSignRequestWithFoundryScript/1.0 (Python-urllib)"


def _api_code(resp: dict[str, Any]) -> Any:
    """Management API may use ``code`` / ``Code`` (JSON from tools or older clients)."""
    c = resp.get("code")
    return c if c is not None else resp.get("Code")


def _api_data(resp: dict[str, Any]) -> Any:
    return resp.get("data") if resp.get("data") is not None else resp.get("Data")


def _unwrap_management_api(resp: dict[str, Any], what: str) -> Any:
    """Require success (code 0 or omitted) and return ``data`` / ``Data`` (same as executeSignResult)."""
    c = _api_code(resp)
    if c is not None and c != 0:
        err = resp.get("error") or resp.get("Error") or str(resp)
        raise ValueError(f"{what} failed (code={c}): {err}")
    return _api_data(resp)


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


def hex_to_int(s: str | None) -> int:
    if not s:
        return 0
    s = str(s).strip()
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    try:
        return int(s, 10)
    except ValueError:
        return 0


def parse_chain_id(chain_id: str | int | None) -> int:
    """Parse chain ID: decimal string (e.g. '59141') or hex (e.g. '0xe738'). Avoids '59141' -> 0x59141 = 364865."""
    if chain_id is None:
        return 0
    if isinstance(chain_id, int):
        return chain_id
    t = str(chain_id).strip()
    if not t:
        return 0
    if t.startswith("0x") or t.startswith("0X"):
        n = hex_to_int(t)
        return n if n is not None else 0
    try:
        return int(t, 10)
    except ValueError:
        return 0


def hex_to_bytes(s: str | None) -> bytes:
    if not s:
        return b""
    s = str(s).strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    if len(s) % 2:
        s = "0" + s
    return bytes.fromhex(s) if s else b""


def normalize_tx(item: dict) -> dict | None:
    raw = item.get("transaction") or item.get("tx")
    if not raw:
        return None
    if "gas" not in raw and "data" not in raw and "input" not in raw:
        return None
    return raw


def is_dry_run_broadcast(broadcast: dict) -> bool:
    """True if broadcast looks like dry-run output (only rpc per item, no tx payload)."""
    txs = broadcast.get("transactions") or []
    if not txs:
        return False
    for item in txs:
        raw = item.get("transaction") or item.get("tx")
        has_rpc = isinstance(item.get("rpc"), str)
        has_tx = raw and (
            raw.get("gas") is not None
            or raw.get("data") is not None
            or raw.get("input") is not None
        )
        if not (has_rpc and not has_tx):
            return False
    return True


def to_address(tx: dict) -> str:
    """Normalize address for API (empty or 0x-prefixed hex)."""
    t = tx.get("to")
    if t is None or t == "":
        return ""
    s = str(t).strip()
    return s if s.startswith("0x") else "0x" + s


def _to_hex_wei(value: int) -> str:
    """Format integer wei as 0x-prefixed hex (for gas, gasPrice, maxFeePerGas, etc.)."""
    if value < 0:
        return "0x0"
    return "0x" + hex(value)[2:]


def broadcast_with_override_sender(
    broadcast: dict,
    first_nonce: int,
    override_sender: str | None = None,
) -> dict:
    """
    Build a new broadcast with nonces (and optionally sender) replaced.

    Every valid transaction gets nonces first_nonce, first_nonce+1, ...
    If override_sender is set, every transaction also gets from=override_sender
    (e.g. when the broadcast was made with Anvil default key and you want
    MPC KeyGen address without re-running forge script).
    """
    sender = None
    if override_sender:
        sender = override_sender if override_sender.startswith("0x") else "0x" + override_sender
    txs = broadcast.get("transactions") or []
    new_txs = []
    for i, item in enumerate(txs):
        raw = item.get("transaction") or item.get("tx")
        if not raw or (
            raw.get("gas") is None and raw.get("data") is None and raw.get("input") is None
        ):
            new_txs.append(item)
            continue
        next_raw = {**raw, "nonce": str(first_nonce + i)}
        if sender is not None:
            next_raw["from"] = sender
        if "transaction" in item:
            new_txs.append({**item, "transaction": next_raw})
        elif "tx" in item:
            new_txs.append({**item, "tx": next_raw})
        else:
            new_txs.append({**item, "transaction": next_raw})
    return {**broadcast, "transactions": new_txs}


def augment_broadcast_with_fees(
    broadcast: dict,
    chain_detail: dict[str, Any],
    fee_params: dict[str, Any],
) -> dict:
    """
    Augment every transaction in the broadcast with gas/fee so serialized txs are valid.

    Uses the same logic as manual batch in the app: fee_params (e.g. from chain/RPC)
    are overridden by chain_detail when set.

    chain_detail: legacy?, gasLimit?, gasPrice? (gwei), baseFeeMultiplier?, gasMultiplier?
    fee_params: isEip1559, baseFeeGwei?, priorityFeeGwei?, gasPriceGwei?
    """
    legacy = bool(chain_detail.get("legacy")) or not fee_params.get("isEip1559", True)
    gas_limit_config = (
        chain_detail.get("gasLimit")
        if isinstance(chain_detail.get("gasLimit"), int) and chain_detail["gasLimit"] > 0
        else None
    )
    gas_fee_multiplier = chain_detail.get("gasMultiplier")
    if gas_fee_multiplier is not None:
        gas_fee_multiplier = int(gas_fee_multiplier)
    base_pct = 100
    if chain_detail.get("baseFeeMultiplier") is not None:
        base_pct = max(100, int(chain_detail["baseFeeMultiplier"]))

    if legacy:
        gwei = fee_params.get("gasPriceGwei") or 0
        if isinstance(chain_detail.get("gasPrice"), (int, float)) and chain_detail["gasPrice"] > 0:
            gwei = max(gwei, int(chain_detail["gasPrice"]))
        if gas_fee_multiplier is not None and gas_fee_multiplier > 0:
            gwei = (gwei * (100 + gas_fee_multiplier)) // 100
        gwei = max(1, gwei)
        gas_price_wei = int(math.ceil(gwei * 1e9))
        max_fee_per_gas_wei = None
        max_priority_fee_per_gas_wei = None
    else:
        base = fee_params.get("baseFeeGwei") or 0
        prio = max(0, fee_params.get("priorityFeeGwei") or 0)
        priority_gwei = prio if prio > 0 else 1
        base_component = (base * base_pct) // 100
        max_fee_gwei = base_component + priority_gwei
        max_fee_per_gas_wei = int(math.ceil(max_fee_gwei * 1e9))
        max_priority_fee_per_gas_wei = int(math.ceil(priority_gwei * 1e9))
        gas_price_wei = None

    default_gas_hex = "0x5208"  # 21000

    txs = broadcast.get("transactions") or []
    new_txs = []
    for item in txs:
        raw = item.get("transaction") or item.get("tx")
        if not raw:
            new_txs.append(item)
            continue
        tx = dict(raw)
        if gas_limit_config is not None:
            tx["gas"] = _to_hex_wei(gas_limit_config)
        else:
            g = raw.get("gas")
            if g is None or g == "" or hex_to_int(g) == 0:
                tx["gas"] = default_gas_hex
        if legacy:
            tx["gasPrice"] = _to_hex_wei(gas_price_wei)
            tx.pop("type", None)
            tx.pop("maxFeePerGas", None)
            tx.pop("maxPriorityFeePerGas", None)
        else:
            tx["type"] = "0x2"
            tx["maxFeePerGas"] = _to_hex_wei(max_fee_per_gas_wei)
            tx["maxPriorityFeePerGas"] = _to_hex_wei(max_priority_fee_per_gas_wei)
            tx.pop("gasPrice", None)
        if "transaction" in item:
            new_txs.append({**item, "transaction": tx})
        elif "tx" in item:
            new_txs.append({**item, "tx": tx})
        else:
            new_txs.append({**item, "transaction": tx})
    return {**broadcast, "transactions": new_txs}


def tx_to_signing_hash_and_raw(tx: dict) -> tuple[str, str]:
    """Return (messageHash hex without 0x, messageRaw hex with 0x)."""
    try:
        from eth_account._utils.typed_transactions import (
            DynamicFeeTransaction,
            TypedTransaction,
        )
    except ImportError:
        try:
            from eth_account.typed_transactions import (
                DynamicFeeTransaction,
                TypedTransaction,
            )
        except ImportError:
            raise SystemExit(
                "eth_account is required. Install with: $MPA_PATH/.venv/bin/pip install eth_account "
                "(see docs/skill/SKILL.md Python dependencies)"
            ) from None

    chain_id = parse_chain_id(tx.get("chainId"))
    nonce = hex_to_int(tx.get("nonce"))
    gas = hex_to_int(tx.get("gas"))
    value = hex_to_int(tx.get("value") or "0")
    data = tx.get("data") or tx.get("input") or "0x"
    data_b = hex_to_bytes(data) if isinstance(data, str) else data
    to_addr = tx.get("to")
    to = hex_to_bytes(to_addr)[:20] if to_addr and to_addr != "0x" else b""
    if to and len(to) == 20:
        to_hex = "0x" + to.hex()
    else:
        to_hex = None
    if to_hex:
        try:
            from eth_utils.address import to_checksum_address

            to_hex = to_checksum_address(to_hex)
        except Exception:
            pass

    type_hex = tx.get("type")
    is_eip1559 = (
        type_hex in ("0x2", "0x02")
        or tx.get("maxFeePerGas") is not None
        or tx.get("maxPriorityFeePerGas") is not None
    )

    if is_eip1559:
        import rlp
        from eth_account._utils.transaction_utils import transaction_rpc_to_rlp_structure
        from eth_utils.toolz import dissoc, pipe

        max_fee = hex_to_int(tx.get("maxFeePerGas"))
        max_priority = hex_to_int(tx.get("maxPriorityFeePerGas"))
        d = {
            "type": 2,
            "chainId": chain_id or 1,
            "nonce": nonce,
            "gas": gas,
            "maxFeePerGas": max_fee or 0,
            "maxPriorityFeePerGas": max_priority or 0,
            "value": value,
            "data": data_b,
            "accessList": tx.get("accessList") or [],
        }
        if to_hex:
            d["to"] = to_hex
        try:
            typed = DynamicFeeTransaction.from_dict(d)
        except Exception:
            typed_tx = TypedTransaction.from_dict(d)
            typed = typed_tx.transaction
        message_hash = typed.hash().hex()
        transaction_without_signature_fields = dissoc(typed.dictionary, "v", "r", "s")
        rlp_structured_txn_without_sig_fields = transaction_rpc_to_rlp_structure(
            transaction_without_signature_fields
        )
        rlp_serializer = typed.__class__._unsigned_transaction_serializer
        unsigned_bytes = pipe(
            rlp_serializer.from_dict(rlp_structured_txn_without_sig_fields),  # type: ignore[arg-type]
            lambda val: rlp.encode(val),
            lambda val: bytes([typed.__class__.transaction_type]) + val,
        )
        message_raw = "0x" + unsigned_bytes.hex()
        return message_hash, message_raw
    else:
        gas_price = hex_to_int(tx.get("gasPrice"))
        from eth_account._utils.legacy_transactions import (
            serializable_unsigned_transaction_from_dict,
        )

        d = {
            "nonce": nonce,
            "gasPrice": gas_price or 0,
            "gas": gas,
            "to": to_hex,
            "value": value,
            "data": data_b,
            "chainId": chain_id or 1,
        }
        unsigned = serializable_unsigned_transaction_from_dict(d)
        encoded = unsigned.encode()
        h = unsigned.hash()
        message_hash = h.hex()
        message_raw = "0x" + encoded.hex()
        return message_hash, message_raw


def generate_sign_request(broadcast: dict, options: dict) -> dict:
    txs = broadcast.get("transactions") or []
    list_: list[tuple[str, str, str]] = []  # (messageHash, messageRaw, to)
    chain_id_str = options.get("destination_chain_id") or ""

    for item in txs:
        tx = normalize_tx(item)
        if not tx:
            continue
        if not chain_id_str:
            c = tx.get("chainId") or broadcast.get("chain")
            if c is not None:
                chain_id_str = str(parse_chain_id(c))
        try:
            msg_hash, msg_raw = tx_to_signing_hash_and_raw(tx)
            to_addr = to_address(tx)
            list_.append((msg_hash, msg_raw, to_addr))
        except Exception as e:
            raise RuntimeError(f"Failed to encode transaction: {e}") from e

    if not list_:
        if is_dry_run_broadcast(broadcast):
            raise ValueError(
                "This file is a dry-run output (no transaction data). Run with --broadcast and the Anvil default key "
                "(or any throwaway key) to produce a full broadcast file, then use 'Override sender' in the import modal to set your KeyGen address."
            )
        raise ValueError("No valid transactions found in broadcast JSON")
    if not chain_id_str:
        chain_id_str = "0"

    # Never use Anvil/simulation chain ID as destination
    if chain_id_str.strip() == ANVIL_SIMULATION_CHAIN_ID:
        chain_id_str = options.get("destination_chain_id") or "0"

    destination_chain_id = options.get("destination_chain_id") or chain_id_str
    safe_destination_chain_id = (
        (options.get("destination_chain_id") or "0")
        if destination_chain_id.strip() == ANVIL_SIMULATION_CHAIN_ID
        else destination_chain_id
    )

    body: dict[str, Any] = {
        "destinationChainID": safe_destination_chain_id,
        "purpose": options.get("purpose"),
    }
    if options.get("key_list") is not None:
        body["keyList"] = options["key_list"]
    if options.get("pub_key"):
        body["pubKey"] = options["pub_key"]

    if len(list_) == 1:
        body["msgHash"] = list_[0][0]
        body["msgRaw"] = list_[0][1]
        body["destinationAddress"] = options.get("destination_address") or list_[0][2] or None
        if body["destinationAddress"] is None:
            del body["destinationAddress"]
        body["signatureText"] = options.get("signature_text")
        body["extraJSON"] = options.get("extra_json") or ""
        return {
            "endpoint": "multiSignRequest",
            "body": body,
            "chainId": safe_destination_chain_id,
            "count": 1,
        }

    # Batch: messageHashes, messageRawBatch, batchMeta in extraJSON
    body["messageHashes"] = [x[0] for x in list_]
    body["messageRawBatch"] = [x[1] for x in list_]
    dest_addresses = options.get("destination_addresses") or [x[2] for x in list_]
    sig_texts = options.get("signature_texts") or [""] * len(list_)
    batch_meta = [
        {
            "destinationAddress": dest_addresses[i] if i < len(dest_addresses) else "",
            "signatureText": sig_texts[i] if i < len(sig_texts) else "",
        }
        for i in range(len(list_))
    ]
    extra_json = options.get("extra_json") or "{}"
    try:
        parsed = json.loads(extra_json)
        if not isinstance(parsed, dict):
            parsed = {}
    except (json.JSONDecodeError, TypeError):
        parsed = {}
    parsed["batchMeta"] = batch_meta
    body["extraJSON"] = json.dumps(parsed)
    body["destinationAddress"] = (dest_addresses[0] if dest_addresses else list_[0][2]) or None
    if body["destinationAddress"] is None:
        del body["destinationAddress"]
    body["signatureText"] = sig_texts[0] if sig_texts else None
    return {
        "endpoint": "multiSignRequest",
        "body": body,
        "chainId": safe_destination_chain_id,
        "count": len(list_),
    }


def fetch_key_list_and_pubkey_from_keygen(mpc_auth_base_url: str, key_gen_id: str) -> tuple[list[str], str]:
    """
    GET /getKeyGenResultById?id=<keyGenRequestId> on the local node's management API.
    Returns (keyList, pubKeyHex). Raises ValueError on missing data or API error.
    """
    base = mpc_auth_base_url.rstrip("/")
    q = urllib.parse.urlencode({"id": key_gen_id})
    url = f"{base}/getKeyGenResultById?{q}"
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
        raise ValueError(f"getKeyGenResultById HTTP {e.code}: {body or e.reason}") from e
    except urllib.error.URLError as e:
        raise ValueError(f"getKeyGenResultById request failed: {e.reason}") from e
    try:
        api = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"getKeyGenResultById: invalid JSON: {e}") from e
    data = _unwrap_management_api(api, "getKeyGenResultById")
    if not isinstance(data, dict):
        raise ValueError("getKeyGenResultById: missing data object")
    key_list = data.get("keylist") or data.get("KeyList")
    if not isinstance(key_list, list) or not key_list:
        raise ValueError("getKeyGenResultById: data.keylist missing or empty")
    key_list = [str(x) for x in key_list]
    pub_key = data.get("pubkeyhex") or data.get("PubKeyHex") or data.get("PubKey")
    if not pub_key or not isinstance(pub_key, str):
        raise ValueError("getKeyGenResultById: data.pubkeyhex missing or invalid")
    pub_key = pub_key.strip()
    if not pub_key:
        raise ValueError("getKeyGenResultById: data.pubkeyhex empty")
    return key_list, pub_key


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Convert Foundry broadcast JSON to POST /multiSignRequest body (multi-agree keys only). "
        "Read from stdin when no --file is given (e.g. script.py < broadcast/.../run-latest.json).",
    )
    ap.add_argument(
        "--file",
        metavar="PATH",
        help="Read broadcast JSON from file (default: stdin)",
    )
    ap.add_argument(
        "--destination-chain-id",
        help="Override destination chain ID (decimal string)",
    )
    ap.add_argument(
        "--destination-address",
        help="Single-tx destination address (default: from tx.to)",
    )
    ap.add_argument(
        "--destination-addresses",
        metavar="JSON_ARRAY",
        help="Batch: per-tx destination addresses as JSON array",
    )
    ap.add_argument(
        "--signature-text",
        help="Single-tx signature text for display",
    )
    ap.add_argument(
        "--signature-texts",
        metavar="JSON_ARRAY",
        help="Batch: per-tx signature texts as JSON array",
    )
    ap.add_argument(
        "--extra-json",
        metavar="JSON_STRING",
        help="Extra JSON string (merged with batchMeta for batch)",
    )
    ap.add_argument(
        "--key-gen-id",
        required=True,
        metavar="ID",
        help="Key generation request ID; keyList and pubKey are loaded via GET /getKeyGenResultById on --mpc-auth-url",
    )
    ap.add_argument(
        "--mpc-auth-url",
        default=(os.environ.get("MPC_AUTH_URL") or DEFAULT_MPC_AUTH_URL),
        metavar="URL",
        help=(
            "Management API host URL (env MPC_AUTH_URL), e.g. http://127.0.0.1 or http://<IP>."
        ),
    )
    ap.add_argument(
        "--management-port",
        default=(os.environ.get("MANAGEMENT_PORT") or DEFAULT_MANAGEMENT_PORT),
        metavar="PORT",
        help="Management API port (env MANAGEMENT_PORT, default: %(default)s)",
    )
    ap.add_argument("--purpose", help="Purpose text")
    # Nonce refresh and sender override
    ap.add_argument(
        "--override-sender",
        metavar="ADDR",
        help="Override from address for every tx (e.g. MPC KeyGen address). Use with --first-nonce.",
    )
    ap.add_argument(
        "--first-nonce",
        type=int,
        metavar="N",
        help="Set nonces to N, N+1, ... (default 0 when used with --override-sender).",
    )
    # Gas / fee augmentation (same logic as manual batch in app)
    ap.add_argument(
        "--legacy",
        action="store_true",
        help="Use legacy gasPrice instead of EIP-1559 when augmenting fees.",
    )
    ap.add_argument(
        "--is-eip1559",
        action="store_true",
        help="Use EIP-1559 fees when augmenting (default if no --legacy).",
    )
    ap.add_argument(
        "--base-fee-gwei",
        type=float,
        metavar="N",
        help="EIP-1559: base fee in gwei (default 0).",
    )
    ap.add_argument(
        "--priority-fee-gwei",
        type=float,
        metavar="N",
        help="EIP-1559: priority fee in gwei (default 1).",
    )
    ap.add_argument(
        "--gas-price-gwei",
        type=float,
        metavar="N",
        help="Legacy: gas price in gwei (default 1 when augmenting).",
    )
    ap.add_argument(
        "--gas-limit",
        type=int,
        metavar="N",
        help="Set gas limit for every tx when augmenting (default: keep from broadcast or 21000).",
    )
    ap.add_argument(
        "--gas-price",
        type=float,
        metavar="N",
        help="Legacy: minimum gas price in gwei when augmenting (max of this and --gas-price-gwei).",
    )
    ap.add_argument(
        "--base-fee-multiplier",
        type=int,
        metavar="N",
        default=100,
        help="EIP-1559: base fee percentage, >= 100 (default 100).",
    )
    ap.add_argument(
        "--gas-multiplier",
        type=int,
        metavar="N",
        help="Legacy: extra percentage on gas price, e.g. 20 = +20%% when augmenting.",
    )
    args = ap.parse_args()

    if args.file:
        with open(args.file, encoding="utf-8") as f:
            raw = f.read()
    else:
        raw = sys.stdin.read()

    raw = raw.strip()
    if not raw:
        print(
            "No JSON input. Pipe broadcast JSON (e.g. script.py < broadcast/.../run-latest.json) or use --file=path",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        broadcast = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"Invalid JSON: {e}", file=sys.stderr)
        sys.exit(1)

    # Nonce refresh and/or sender override (before gas augmentation)
    if args.override_sender is not None or args.first_nonce is not None:
        first_nonce = args.first_nonce if args.first_nonce is not None else 0
        broadcast = broadcast_with_override_sender(
            broadcast,
            first_nonce=first_nonce,
            override_sender=args.override_sender,
        )

    # Gas/fee augmentation (optional; same logic as manual batch in app)
    gas_args = [
        args.legacy,
        args.is_eip1559,
        args.base_fee_gwei is not None,
        args.priority_fee_gwei is not None,
        args.gas_price_gwei is not None,
        args.gas_limit is not None,
        args.gas_price is not None,
        args.base_fee_multiplier != 100,
        args.gas_multiplier is not None,
    ]
    if any(gas_args):
        chain_detail: dict[str, Any] = {}
        if args.legacy:
            chain_detail["legacy"] = True
        if args.gas_limit is not None:
            chain_detail["gasLimit"] = args.gas_limit
        if args.gas_price is not None:
            chain_detail["gasPrice"] = args.gas_price
        if args.base_fee_multiplier is not None:
            chain_detail["baseFeeMultiplier"] = max(100, args.base_fee_multiplier)
        if args.gas_multiplier is not None:
            chain_detail["gasMultiplier"] = args.gas_multiplier
        fee_params: dict[str, Any] = {
            "isEip1559": not args.legacy,
        }
        if args.base_fee_gwei is not None:
            fee_params["baseFeeGwei"] = args.base_fee_gwei
        if args.priority_fee_gwei is not None:
            fee_params["priorityFeeGwei"] = args.priority_fee_gwei
        if args.gas_price_gwei is not None:
            fee_params["gasPriceGwei"] = args.gas_price_gwei
        broadcast = augment_broadcast_with_fees(broadcast, chain_detail, fee_params)

    options: dict = {}
    if args.destination_chain_id:
        options["destination_chain_id"] = args.destination_chain_id
    if args.destination_address is not None:
        options["destination_address"] = args.destination_address
    if args.destination_addresses is not None:
        options["destination_addresses"] = json.loads(args.destination_addresses)
    if args.signature_text is not None:
        options["signature_text"] = args.signature_text
    if args.signature_texts is not None:
        options["signature_texts"] = json.loads(args.signature_texts)
    if args.extra_json is not None:
        options["extra_json"] = args.extra_json
    if args.purpose:
        options["purpose"] = args.purpose

    try:
        mpc_base = resolve_mpc_auth_base(args.mpc_auth_url, args.management_port)
        key_list, pub_key = fetch_key_list_and_pubkey_from_keygen(
            mpc_base, args.key_gen_id
        )
        options["key_list"] = key_list
        options["pub_key"] = pub_key
    except ValueError as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)

    try:
        payload = generate_sign_request(broadcast, options)
        print(json.dumps(payload, indent=2))
    except (ValueError, RuntimeError) as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
