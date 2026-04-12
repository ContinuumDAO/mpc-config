#!/usr/bin/env python3
"""
generateMultiSignRequestFromCompose

Build a **POST /multiSignRequest** payload from JSON that mirrors the **Compose**
flow in ``continuumdao-node-app`` (manual compose: function signature, parameters,
destination chain, optional “use configured gas” behavior).

This is separate from ``generateSignRequestWithFoundryScript.py`` (Foundry
broadcast JSON). It reuses the same transaction signing-hash helpers from that
module so ``msgHash`` / ``messageHashes`` match EIP-1559 / legacy encoding.

**Flow (aligned with app ``handleComposeOK`` after Validate + Simulate):**

- Resolves RPC: if ``rpcGateway`` is set in the compose JSON, uses it; otherwise
  **GET /getChainDetails?chain_id=...** on ``--mpc-auth-url`` (same as the app
  when submitting OK, which uses the node’s stored chain RPC).
- Loads ``keyList``, ``pubKey``, executor address, and optional ``clientId`` via
  **GET /getKeyGenResultById** (requires ``keyGenId``).
- Fetches pending **EVM nonce** for the MPC address from the RPC.
- For each compose action: ABI-encodes calldata (same rules as
  ``encodeActionCalldata`` in ``app/utils/continuumDAO.ts``), applies gas limits
  and fees like the app (simulated fields + ``useCustomGasConfig`` + chain
  detail multipliers / minima).
- Builds ``bodyForSign`` / ``messageToSign`` like the app (single tx:
  ``msgRaw`` = calldata hex **without** ``0x``; batch: ``messageHashes`` /
  ``messageRawBatch`` + first-item compatibility fields).

**Dependencies:** ``eth_account`` (pulls ``eth_abi`` / ``eth_utils``) and ``PyNaCl``
are **required**. Install with ``pip install eth_account PyNaCl``.

**Compose JSON schema (minimal):**

.. code-block:: json

  {
    "keyGenId": "KeyGen2026...",
    "destinationChainId": "11155111",
    "rpcGateway": "https://...",
    "purpose": "optional, max 256 chars",
    "useCustomGasConfig": false,
    "composeActions": [
      {
        "signature": "transfer(address,uint256)",
        "destinationContract": "0x...",
        "inputs": [
          {"name": "to", "type": "address", "value": "0x..."},
          {"name": "amount", "type": "uint256", "value": "1"}
        ],
        "paramUnits": {"1": "Ether"},
        "estimatedGas": "21000",
        "gasPriceWei": "...",
        "maxFeePerGas": "...",
        "maxPriorityFeePerGas": "..."
      }
    ]
  }

``paramUnits`` keys are input indices as strings; values are ``Wei`` | ``Ether`` |
``Gwei`` | ``USD`` (same as ``EVMUnit`` in the app). Per-action ``estimatedGas``
and fee fields mirror values stored after **Simulate**; omit them to estimate on
the fly via RPC.

**Native currency transfer** (ETH / chain gas token to an address, no contract
calldata): set ``"nativeTransfer": true``, ``destinationContract`` = recipient
address, a single ``inputs`` entry ``uint256`` value, and ``paramUnits`` for
index ``"0"``. Optional ``signature`` defaults to ``nativeTransfer``. Calldata is
empty (``msgRaw`` is ``""`` for a single action).

**Output:** JSON with ``endpoint``, ``bodyForSign``, ``messageToSign``, and
optional ``postBody`` if signing flags were passed. Add ``clientSig`` (and for
MetaMask flows ``signedMessage`` = ``messageToSign``) before POSTing.
Management API **nonces** apply to other endpoints (e.g. trigger); this script does
not add a management ``nonce`` to ``multiSignRequest`` unless you extend the
payload to match a custom backend.

Usage::

  python3 scripts/generateMultiSignRequestFromCompose.py --file compose.json
  python3 scripts/generateMultiSignRequestFromCompose.py < compose.json
  python3 scripts/generateMultiSignRequestFromCompose.py --file compose.json \\
      --mpc-auth-url http://localhost:8080
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import math
import sys
import urllib.error
import urllib.parse
import urllib.request
from decimal import Decimal, InvalidOperation, getcontext
from pathlib import Path
from typing import Any

try:
    from nacl.signing import SigningKey
except ImportError as e:
    raise SystemExit(
        "PyNaCl is required. Install with: pip install PyNaCl"
    ) from e

getcontext().prec = 78

DEFAULT_MPC_AUTH_URL = "http://localhost:8080"

# Public JSON-RPC gateways often return 403 if User-Agent is empty / Python-urllib default.
_HTTP_UA = "generateMultiSignRequestFromCompose/1.0 (Python-urllib)"

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

tx_to_signing_hash_and_raw = _forge.tx_to_signing_hash_and_raw
parse_chain_id = _forge.parse_chain_id


def _load_json(path: str | None, stdin: str | None) -> dict[str, Any]:
    raw = stdin if stdin is not None else Path(path).read_text(encoding="utf-8")
    raw = raw.strip()
    if not raw:
        raise ValueError("Empty JSON input")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("Top-level JSON must be an object")
    return data


def _rpc(url: str, method: str, params: list[Any]) -> Any:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(
        "utf-8"
    )
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": _HTTP_UA,
        },
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        out = json.loads(resp.read().decode("utf-8"))
    if "error" in out and out["error"]:
        raise RuntimeError(str(out["error"]))
    return out.get("result")


def _eth_address_param(addr: str) -> str:
    s = (addr or "").strip()
    if not s.startswith("0x"):
        s = "0x" + s
    return s


def _gwei_to_wei_ceil(g: float) -> int:
    return int(math.ceil(g * 1e9))


def fetch_chain_fee_params(rpc_url: str, chain_id: int) -> dict[str, Any]:
    """Mirror app/utils/chainFees.ts fetchChainFeeParams."""
    try:
        block = _rpc(rpc_url, "eth_getBlockByNumber", ["latest", False])
        if not isinstance(block, dict):
            return {"isEip1559": False}
        bf = block.get("baseFeePerGas")
        if bf is None:
            gp = _rpc(rpc_url, "eth_gasPrice", [])
            wei = int(gp, 16) if isinstance(gp, str) else int(gp)
            return {"isEip1559": False, "gasPriceGwei": wei / 1e9}
        base_wei = int(bf, 16) if isinstance(bf, str) else int(bf)
        base_fee_gwei = base_wei / 1e9
        priority_fee_gwei: float | None = None
        try:
            mp = _rpc(rpc_url, "eth_maxPriorityFeePerGas", [])
            pwei = int(mp, 16) if isinstance(mp, str) else int(mp)
            priority_fee_gwei = pwei / 1e9
        except Exception:
            pass
        gp = _rpc(rpc_url, "eth_gasPrice", [])
        gwei = int(gp, 16) if isinstance(gp, str) else int(gp)
        return {
            "isEip1559": True,
            "baseFeeGwei": base_fee_gwei,
            "priorityFeeGwei": priority_fee_gwei,
            "gasPriceGwei": gwei / 1e9,
        }
    except Exception:
        try:
            gp = _rpc(rpc_url, "eth_gasPrice", [])
            wei = int(gp, 16) if isinstance(gp, str) else int(gp)
            return {"isEip1559": False, "gasPriceGwei": wei / 1e9}
        except Exception:
            return {"isEip1559": False}


def eth_get_transaction_count(rpc_url: str, address: str) -> int:
    addr = _eth_address_param(address)
    res = _rpc(rpc_url, "eth_getTransactionCount", [addr, "pending"])
    return int(res, 16) if isinstance(res, str) else int(res)


def eth_estimate_gas(
    rpc_url: str,
    from_addr: str,
    to_addr: str,
    data_hex: str,
    value_wei: int | None = None,
) -> int:
    fx = _eth_address_param(from_addr)
    tx: dict[str, Any] = {"from": fx, "to": _eth_address_param(to_addr), "data": data_hex}
    if value_wei is not None and value_wei > 0:
        tx["value"] = _to_hex_wei(value_wei)
    res = _rpc(rpc_url, "eth_estimateGas", [tx])
    return int(res, 16) if isinstance(res, str) else int(res)


def eth_gas_price(rpc_url: str) -> int:
    res = _rpc(rpc_url, "eth_gasPrice", [])
    return int(res, 16) if isinstance(res, str) else int(res)


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


def fetch_keygen_bundle(mpc_base: str, key_gen_id: str) -> dict[str, Any]:
    base = mpc_base.rstrip("/")
    q = urllib.parse.urlencode({"id": key_gen_id})
    api = http_get_json(f"{base}/getKeyGenResultById?{q}")
    if api.get("code") != 0:
        err = api.get("error") or str(api)
        raise ValueError(f"getKeyGenResultById failed (code={api.get('code')}): {err}")
    data = api.get("data")
    if not isinstance(data, dict):
        raise ValueError("getKeyGenResultById: missing data object")
    return data


def fetch_chain_detail_for_id(mpc_base: str, chain_id_num: int) -> dict[str, Any]:
    base = mpc_base.rstrip("/")
    api = http_get_json(f"{base}/getChainDetails?chain_id={chain_id_num}")
    if api.get("code") != 0:
        err = api.get("error") or str(api)
        raise ValueError(f"getChainDetails failed (code={api.get('code')}): {err}")
    data = api.get("data")
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


def display_value_to_raw(value: str, unit: str) -> str:
    """Mirror app/utils/format.ts displayValueToRaw."""
    trimmed = (value or "").strip()
    if not trimmed:
        return "0"
    u = (unit or "Wei").strip()
    if u == "Wei":
        dot = trimmed.find(".")
        return trimmed if dot == -1 else (trimmed[:dot] or "0")
    decimals = {"Ether": 18, "Gwei": 9, "USD": 6}.get(u, 0)
    if decimals == 0:
        return trimmed
    try:
        d = Decimal(trimmed)
        scale = Decimal(10) ** decimals
        raw = int((d * scale).to_integral_value(rounding="ROUND_DOWN"))
        return str(raw)
    except (InvalidOperation, ValueError):
        return trimmed


def display_value_to_raw_array(value: str, unit: str) -> str:
    """Mirror displayValueToRawArray: JSON array string of raw decimal strings."""
    trimmed = (value or "").strip()
    if trimmed.startswith("["):
        try:
            arr = json.loads(trimmed)
        except json.JSONDecodeError:
            return "[]"
        if not isinstance(arr, list):
            return "[]"
        raw = [display_value_to_raw(str(el), unit) for el in arr]
        return json.dumps(raw)
    parts = [p.strip() for p in trimmed.split(",") if p.strip()] if trimmed else []
    raw = [display_value_to_raw(p, unit) for p in parts]
    return json.dumps(raw)


def is_uint256_type(t: str) -> bool:
    """Mirror isUint256Type in continuumdao-node-app (only uint256 / uint256[])."""
    s = t.strip()
    return s == "uint256" or s == "uint256[]"


def parse_function_signature(signature: str) -> tuple[str, list[str]]:
    sig = signature.strip()
    if "(" not in sig:
        return sig, []
    name, _, rest = sig.partition("(")
    rest = rest.rstrip(")")
    if not rest.strip():
        return name.strip(), []
    return name.strip(), [x.strip() for x in rest.split(",") if x.strip()]


def coerce_abi_value(typ: str, value: str) -> Any:
    t = typ.strip()
    if t.endswith("[]"):
        base = t[:-2]
        trimmed = (value or "").strip()
        if trimmed.startswith("["):
            try:
                arr = json.loads(trimmed)
            except json.JSONDecodeError:
                arr = []
            if not isinstance(arr, list):
                arr = []
        else:
            arr = [x.strip() for x in trimmed.split(",")] if trimmed else []
        if base == "address":
            return [_eth_address_param(str(x)) for x in arr]
        if base.startswith("uint") or base.startswith("int"):
            return [int(x) for x in arr]
        if base == "bool":
            return [str(x).strip().lower() in ("1", "true", "yes") for x in arr]
        return [str(x) for x in arr]
    if t == "address":
        return _eth_address_param(value.strip())
    if t.startswith("uint") or t.startswith("int"):
        return int(str(value).strip() or "0")
    if t == "bool":
        s = value.strip().lower()
        return s in ("1", "true", "yes")
    return value.strip()


def encode_action_calldata(signature: str, inputs: list[dict[str, Any]], param_units: dict[str, str]) -> str:
    try:
        from eth_abi import encode
        from eth_utils.crypto import keccak
    except ImportError as e:
        raise SystemExit(
            "eth_abi / eth_utils required (install: pip install eth_account)"
        ) from e

    name, types = parse_function_signature(signature)
    if len(types) != len(inputs):
        raise ValueError(
            f"encodeActionCalldata: inputs length mismatch (types={len(types)} inputs={len(inputs)})"
        )
    args: list[Any] = []
    for i, inp in enumerate(inputs):
        typ = types[i]
        raw_val = inp.get("value")
        if raw_val is None:
            raw_val = ""
        val = str(raw_val)
        if is_uint256_type(typ):
            unit_key = str(i)
            unit = param_units.get(unit_key) or param_units.get(unit_key.zfill(1)) or "Wei"
            if typ.endswith("[]"):
                val = display_value_to_raw_array(val, unit)
            else:
                val = display_value_to_raw(val, unit)
        args.append(coerce_abi_value(typ, val))

    canonical = f"{name}({','.join(types)})"
    selector = keccak(text=canonical)[:4]
    packed = encode(types, tuple(args))
    return "0x" + (selector + packed).hex()


def _to_hex_wei(n: int) -> str:
    if n < 0:
        return "0x0"
    return "0x" + hex(n)[2:]


def _maybe_int(v: Any) -> int | None:
    if v is None:
        return None
    if isinstance(v, int):
        return v
    s = str(v).strip()
    if not s:
        return None
    try:
        return int(s, 10)
    except ValueError:
        try:
            return int(s, 16) if s.startswith("0x") else int(s)
        except ValueError:
            return None


def _first_client_id(client_keys: Any) -> str | None:
    if not isinstance(client_keys, dict):
        return None
    for v in client_keys.values():
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def dumps_js(obj: Any) -> str:
    """Compact JSON like JavaScript JSON.stringify (no spaces)."""
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def build_compose_multisign(
    compose: dict[str, Any],
    mpc_auth_url: str,
) -> dict[str, Any]:
    key_gen_id = (compose.get("keyGenId") or compose.get("key_gen_id") or "").strip()
    if not key_gen_id:
        raise ValueError("compose JSON: keyGenId is required")

    dest_chain = str(compose.get("destinationChainId") or compose.get("destination_chain_id") or "").strip()
    if not dest_chain:
        raise ValueError("compose JSON: destinationChainId is required")
    dest_chain_num = parse_chain_id(dest_chain)
    if dest_chain_num < 0 or dest_chain_num > 0xFFFFFFFF:
        raise ValueError("Invalid destinationChainId")

    actions = compose.get("composeActions") or compose.get("compose_actions") or []
    if not isinstance(actions, list) or not actions:
        raise ValueError("compose JSON: composeActions must be a non-empty array")

    use_custom = bool(compose.get("useCustomGasConfig") or compose.get("use_custom_gas_config"))
    purpose = (compose.get("purpose") or "").strip()

    rpc_override = (compose.get("rpcGateway") or compose.get("rpc_gateway") or "").strip()
    if rpc_override:
        rpc_url = rpc_override
        chain_detail: dict[str, Any] = {}
        try:
            chain_detail = fetch_chain_detail_for_id(mpc_auth_url, dest_chain_num)
        except ValueError:
            chain_detail = {}
    else:
        chain_detail = fetch_chain_detail_for_id(mpc_auth_url, dest_chain_num)
        rpc_url = str(
            pick_str(chain_detail, "rpcGateway", "RpcGateway", "rpc_gateway") or ""
        ).strip()
        if not rpc_url:
            raise ValueError(
                "No rpcGateway in compose JSON and chain has no RPC; set rpcGateway or configure chain on the node."
            )

    legacy_flag = pick_str(chain_detail, "legacy", "Legacy")

    gas_limit_cfg = pick_str(chain_detail, "gasLimit", "GasLimit")
    gas_limit_config: int | None = None
    if gas_limit_cfg not in (None, ""):
        try:
            gl = int(gas_limit_cfg)  # type: ignore[arg-type]
            if gl > 0:
                gas_limit_config = gl
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

    fee_params = fetch_chain_fee_params(rpc_url, dest_chain_num)
    # Mirror: const legacy = Boolean(chainDetail?.legacy) || !feeParams.isEip1559
    legacy_from_chain = legacy_flag is True or str(legacy_flag).lower() == "true"
    legacy = legacy_from_chain or not bool(fee_params.get("isEip1559"))

    kg = fetch_keygen_bundle(mpc_auth_url, key_gen_id)
    key_list = kg.get("keylist") or kg.get("KeyList")
    if not isinstance(key_list, list) or not key_list:
        raise ValueError("getKeyGenResultById: keylist missing or empty")
    key_list = [str(x) for x in key_list]
    pub_key = kg.get("pubkeyhex") or kg.get("PubKeyHex") or kg.get("PubKey")
    if not pub_key or not isinstance(pub_key, str):
        raise ValueError("getKeyGenResultById: pubkeyhex missing")
    pub_key = pub_key.strip()
    eth_addr = kg.get("ethereumaddress") or kg.get("EthereumAddress")
    if not eth_addr or not isinstance(eth_addr, str):
        raise ValueError("getKeyGenResultById: ethereumaddress missing")
    executor = _eth_address_param(eth_addr.strip())

    client_id = (compose.get("clientId") or compose.get("client_id") or "").strip() or None
    if not client_id:
        ck = kg.get("ClientKeys") or kg.get("clientkeys")
        client_id = _first_client_id(ck)

    nonce0 = eth_get_transaction_count(rpc_url, executor)

    message_hashes: list[str] = []
    message_raw_batch: list[str] = []
    batch_meta: list[dict[str, str]] = []
    first_tx_fee: dict[str, Any] = {}
    first_calldata: str | None = None

    for i, raw_act in enumerate(actions):
        if not isinstance(raw_act, dict):
            raise ValueError(f"composeActions[{i}] must be an object")
        is_native = bool(raw_act.get("nativeTransfer") or raw_act.get("native_transfer"))
        sig = (raw_act.get("signature") or "").strip()
        if is_native and not sig:
            sig = "nativeTransfer"
        dest = (raw_act.get("destinationContract") or raw_act.get("destination_contract") or "").strip()
        if not sig or not dest:
            raise ValueError(f"composeActions[{i}]: signature and destinationContract required")
        inputs = raw_act.get("inputs") or []
        if not isinstance(inputs, list):
            raise ValueError(f"composeActions[{i}]: inputs must be an array")
        param_units = raw_act.get("paramUnits") or raw_act.get("param_units") or {}
        if not isinstance(param_units, dict):
            param_units = {}
        param_units_norm = {str(k): str(v) for k, v in param_units.items()}

        value_wei: int | None = None
        if is_native:
            if len(inputs) != 1:
                raise ValueError(
                    f"composeActions[{i}]: nativeTransfer requires exactly one input (uint256 value)"
                )
            inp0 = inputs[0] or {}
            typ0 = str(inp0.get("type") or "uint256").strip()
            if not is_uint256_type(typ0):
                raise ValueError(
                    f"composeActions[{i}]: nativeTransfer input must be uint256 (got {typ0!r})"
                )
            unit_key = "0"
            unit = param_units_norm.get(unit_key) or param_units_norm.get(unit_key.zfill(1)) or "Wei"
            raw_v = inp0.get("value")
            val = display_value_to_raw(str(raw_v if raw_v is not None else ""), unit)
            try:
                value_wei = int(val)
            except ValueError as e:
                raise ValueError(f"composeActions[{i}]: nativeTransfer value: {e}") from e
            if value_wei < 0:
                raise ValueError(f"composeActions[{i}]: nativeTransfer value must be >= 0")
            calldata = "0x"
            data_hex = "0x"
        else:
            calldata = encode_action_calldata(sig, inputs, param_units_norm)
            data_hex = calldata if calldata.startswith("0x") else "0x" + calldata

        if i == 0:
            first_calldata = calldata if calldata.startswith("0x") else "0x" + calldata

        to_addr = _eth_address_param(dest)

        est = _maybe_int(raw_act.get("estimatedGas") or raw_act.get("estimated_gas"))
        gas_limit: int
        if est is not None and est > 0:
            gas_limit = est
        elif use_custom and gas_limit_config is not None and gas_limit_config > 0:
            gas_limit = gas_limit_config
        else:
            gas_limit = eth_estimate_gas(
                rpc_url, executor, to_addr, data_hex, value_wei if is_native else None
            )

        current_nonce = nonce0 + i

        if legacy:
            gp_item = _maybe_int(raw_act.get("gasPriceWei") or raw_act.get("gas_price_wei"))
            gas_price_wei = gp_item if gp_item is not None and gp_item > 0 else eth_gas_price(rpc_url)
            if use_custom and gas_fee_multiplier is not None and gas_fee_multiplier > 0:
                gas_price_wei = (gas_price_wei * (100 + gas_fee_multiplier)) // 100
            if use_custom and chain_gas_price_gwei is not None and chain_gas_price_gwei > 0:
                configured = _gwei_to_wei_ceil(chain_gas_price_gwei)
                if configured > gas_price_wei:
                    gas_price_wei = configured
            if i == 0:
                first_tx_fee = {
                    "txNonce": nonce0,
                    "txGasLimit": str(gas_limit),
                    "txGasPrice": str(gas_price_wei),
                }
            tx = {
                "nonce": str(current_nonce),
                "gasPrice": _to_hex_wei(gas_price_wei),
                "gas": _to_hex_wei(gas_limit),
                "to": to_addr,
                "value": _to_hex_wei(value_wei if is_native and value_wei is not None else 0),
                "data": data_hex,
                "chainId": str(dest_chain_num),
            }
        else:
            mfee = _maybe_int(raw_act.get("maxFeePerGas") or raw_act.get("max_fee_per_gas"))
            mprio = _maybe_int(raw_act.get("maxPriorityFeePerGas") or raw_act.get("max_priority_fee_per_gas"))
            if mfee is None or mprio is None or mfee <= 0 or mprio <= 0:
                base = float(fee_params.get("baseFeeGwei") or 0)
                prio = float(fee_params.get("priorityFeeGwei") or 0)
                base_component = base * base_fee_multiplier_pct / 100.0
                max_prio = _gwei_to_wei_ceil(prio) if prio > 0 else _gwei_to_wei_ceil(1.0)
                max_fee = _gwei_to_wei_ceil(base_component + prio)
            else:
                max_fee = mfee
                max_prio = mprio
            if i == 0:
                first_tx_fee = {
                    "txNonce": nonce0,
                    "txGasLimit": str(gas_limit),
                    "txMaxFeePerGas": str(max_fee),
                    "txMaxPriorityFeePerGas": str(max_prio),
                }
            tx = {
                "type": "0x2",
                "nonce": str(current_nonce),
                "gas": _to_hex_wei(gas_limit),
                "maxFeePerGas": _to_hex_wei(max_fee),
                "maxPriorityFeePerGas": _to_hex_wei(max_prio),
                "to": to_addr,
                "value": _to_hex_wei(value_wei if is_native and value_wei is not None else 0),
                "data": data_hex,
                "chainId": str(dest_chain_num),
            }

        msg_hash, msg_raw = tx_to_signing_hash_and_raw(tx)
        message_hashes.append(msg_hash)
        message_raw_batch.append(msg_raw)

        names = [str((inp or {}).get("name") or "").strip() for inp in inputs]
        batch_meta.append(
            {
                "destinationAddress": dest,
                "signatureText": dumps_js({"signature": sig, "names": names}),
            }
        )

    first_dest = (actions[0].get("destinationContract") or actions[0].get("destination_contract") or "").strip()
    first_sig = (actions[0].get("signature") or "").strip()
    if (
        bool(actions[0].get("nativeTransfer") or actions[0].get("native_transfer"))
        and not first_sig
    ):
        first_sig = "nativeTransfer"
    first_inputs = actions[0].get("inputs") or []
    if not isinstance(first_inputs, list):
        first_inputs = []
    first_names = [str((inp or {}).get("name") or "").strip() for inp in first_inputs]
    first_sig_text = dumps_js({"signature": first_sig, "names": first_names})

    body: dict[str, Any] = {}
    if len(actions) == 1:
        native0 = bool(actions[0].get("nativeTransfer") or actions[0].get("native_transfer"))
        if native0:
            msg_raw_calldata = ""
        else:
            pu0 = actions[0].get("paramUnits") or actions[0].get("param_units") or {}
            pu_map = {str(k): str(v) for k, v in pu0.items()} if isinstance(pu0, dict) else {}
            cd = encode_action_calldata(
                first_sig,
                first_inputs if isinstance(first_inputs, list) else [],
                pu_map,
            )
            msg_raw_calldata = cd[2:] if cd.startswith("0x") else cd
        body["keyList"] = key_list
        body["pubKey"] = pub_key
        body["msgHash"] = message_hashes[0]
        body["msgRaw"] = msg_raw_calldata
        body["destinationChainID"] = dest_chain
        body["destinationAddress"] = first_dest
        body["destinationContract"] = first_dest
        body["signatureText"] = first_sig_text
        body.update(first_tx_fee)
    else:
        first_msg_raw = (
            first_calldata[2:] if first_calldata and first_calldata.startswith("0x") else (first_calldata or "")
        )
        body["keyList"] = key_list
        body["pubKey"] = pub_key
        body["msgHash"] = message_hashes[0]
        body["msgRaw"] = first_msg_raw
        body["messageHashes"] = message_hashes
        body["messageRawBatch"] = message_raw_batch
        body["destinationChainID"] = dest_chain
        body["destinationAddress"] = first_dest
        body["extraJSON"] = dumps_js({"batchMeta": batch_meta})
        body["signatureText"] = first_sig_text
        body.update(first_tx_fee)

    if client_id:
        body["clientId"] = client_id
    if purpose:
        body["purpose"] = purpose

    message_to_sign = dumps_js(body)

    return {
        "endpoint": "multiSignRequest",
        "bodyForSign": body,
        "messageToSign": message_to_sign,
        "chainId": dest_chain,
        "count": len(actions),
    }


def sign_ed25519(message: str, seed_hex: str) -> str:
    raw = seed_hex.strip().replace("0x", "")
    if len(raw) == 64:
        seed = bytes.fromhex(raw)
    elif len(raw) == 128:
        seed = bytes.fromhex(raw)[:32]
    else:
        raise ValueError("--ed25519-seed-hex must be 64 hex chars (32-byte seed) or 128 hex (first 32 bytes used as seed)")
    sk = SigningKey(seed)
    return sk.sign(message.encode("utf-8")).signature.hex()


def sign_eip191(message: str, eth_private_key_hex: str) -> str:
    try:
        from eth_account import Account
        from eth_account.messages import encode_defunct
    except ImportError as e:
        raise SystemExit("eth_account required for EIP-191 signing") from e
    pk = eth_private_key_hex.strip().replace("0x", "")
    if len(pk) != 64:
        raise ValueError("Ethereum private key must be 64 hex chars")
    acct = Account.from_key("0x" + pk)
    signed = acct.sign_message(encode_defunct(text=message))
    return "0x" + signed.signature.hex()


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Build POST /multiSignRequest payload from Compose-style JSON (continuumdao-node-app)."
    )
    ap.add_argument("--file", "-f", metavar="PATH", help="Compose JSON file (default: stdin)")
    ap.add_argument(
        "--key-gen-id",
        metavar="ID",
        help="Override compose JSON keyGenId (still need destinationChainId and composeActions in JSON)",
    )
    ap.add_argument(
        "--mpc-auth-url",
        default=DEFAULT_MPC_AUTH_URL,
        help="Management API base URL (default: %(default)s)",
    )
    ap.add_argument(
        "--ed25519-seed-hex",
        metavar="HEX",
        help="If set, sign messageToSign with Ed25519 (32-byte seed, 64 hex) and output postBody with clientSig",
    )
    ap.add_argument(
        "--eip191-private-key-hex",
        metavar="HEX",
        help="If set, sign with secp256k1 personal_sign (MetaMask-style) and output postBody with clientSig + signedMessage",
    )
    args = ap.parse_args()

    if args.file:
        compose = _load_json(args.file, None)
    else:
        compose = _load_json(None, sys.stdin.read())

    if args.key_gen_id:
        compose = {**compose, "keyGenId": args.key_gen_id.strip()}

    try:
        out = build_compose_multisign(compose, args.mpc_auth_url.rstrip("/"))
    except (ValueError, RuntimeError) as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)

    if args.ed25519_seed_hex:
        sig = sign_ed25519(out["messageToSign"], args.ed25519_seed_hex)
        post = {**out["bodyForSign"], "clientSig": sig, "signedMessage": ""}
        out["postBody"] = post
    elif args.eip191_private_key_hex:
        sig = sign_eip191(out["messageToSign"], args.eip191_private_key_hex)
        out["postBody"] = {**out["bodyForSign"], "clientSig": sig, "signedMessage": out["messageToSign"]}

    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
