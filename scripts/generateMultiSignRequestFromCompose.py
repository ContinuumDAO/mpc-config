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
  and fees like the app (``noCustomGasParams`` + chain detail multipliers / minima).
- Builds ``bodyForSign`` / ``messageToSign`` like the app (single tx:
  ``msgRaw`` = calldata hex **without** ``0x``; batch: ``messageHashes`` /
  ``messageRawBatch`` + first-item compatibility fields).

**Dependencies:** ``eth_account`` (pulls ``eth_abi`` / ``eth_utils``) and ``PyNaCl``
are **required**. Install into ``$MPA_PATH/.venv`` (see ``docs/skill/SKILL.md`` **Python dependencies**).

.. code-block:: bash

   $MPA_PATH/.venv/bin/pip install eth_account PyNaCl

**Compose JSON schema (minimal):**

.. code-block:: json

  {
    "keyGenId": "KeyGen2026...",
    "destinationChainId": "11155111",
    "rpcGateway": "https://...",
    "purpose": "optional, max 256 chars",
    "noCustomGasParams": false,
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
the fly via RPC. **``noCustomGasParams``:** when **false** or omitted, gas uses
**GET /getChainDetails** fields when set (see ``build_compose_multisign``); when **true**,
chain gas hints are ignored. **Recipe CLIs** under ``recipes/`` (e.g. ``linea_register.py``)
document ``--no-custom-gas-params`` the same way.

**Native currency transfer** (ETH / chain gas token to an address, no contract
calldata): set ``"nativeTransfer": true``, ``destinationContract`` = recipient
address, a single ``inputs`` entry ``uint256`` value, and ``paramUnits`` for
index ``"0"``. Optional ``signature`` defaults to ``nativeTransfer``. Calldata is
empty (``msgRaw`` is ``""`` for a single action).

**Output:** JSON with ``endpoint``, ``bodyForSign``, ``messageToSign``, and
optional ``postBody`` if signing flags were passed. Add ``clientSig`` (and for
MetaMask flows ``signedMessage`` = ``messageToSign``) before POSTing.
Also ``triggerTxParams`` and ``triggerMessageHash``: the shape required for
``POST /triggerSignRequestById`` so ``GET /getSignRequestById?tx_params=1`` can
return stored TxParams (see API docs). **multiSignRequest** uses ``txNonce`` /
``txGasLimit`` / ``txGasPrice`` (or EIP-1559 equivalents); the trigger endpoint
expects ``nonce`` / ``gasLimit`` / ``txType`` / fee fields — use ``triggerTxParams``
when building the trigger body.
**Use one recipe run per sign request:** ``msgHash`` is tied to exact gas/fees/nonce/calldata.
Re-running the recipe with different RPC fees produces a different ``msgHash``; do not mix outputs
from two runs (same for ``triggerMessageHash`` / ``triggerTxParams`` vs stored ``MessageHash``).
Management API **nonces** apply to other endpoints (e.g. trigger); this script does
not add a management ``nonce`` to ``multiSignRequest`` unless you extend the
payload to match a custom backend.

Usage::

  python3 scripts/generateMultiSignRequestFromCompose.py --file compose.json
  python3 scripts/generateMultiSignRequestFromCompose.py < compose.json
  python3 scripts/generateMultiSignRequestFromCompose.py --file compose.json \\
      --mpc-auth-url http://127.0.0.1 --management-port 8080
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import math
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from decimal import Decimal, InvalidOperation, getcontext
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    from nacl.signing import SigningKey
except ImportError as e:
    raise SystemExit(
        "PyNaCl is required. Install with: $MPA_PATH/.venv/bin/pip install PyNaCl "
        "(see docs/skill/SKILL.md Python dependencies)"
    ) from e

getcontext().prec = 78

DEFAULT_MPC_AUTH_URL = "http://127.0.0.1"
DEFAULT_MANAGEMENT_PORT = "8080"

# Public JSON-RPC gateways often return 403 if User-Agent is empty / Python-urllib default.
_HTTP_UA = "generateMultiSignRequestFromCompose/1.0 (Python-urllib)"

_scripts_dir = Path(__file__).resolve().parent
if str(_scripts_dir) not in sys.path:
    sys.path.insert(0, str(_scripts_dir))

from mpc_mgt_helpers import api_code, api_data, api_error

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


def resolve_mpc_auth_base(mpc_auth_url: str, management_port: str | int | None) -> str:
    """Resolve base URL from host-style MPC_AUTH_URL plus MANAGEMENT_PORT."""
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


def eth_get_balance_wei(rpc_url: str, address: str) -> int:
    """Native balance (wei) via ``eth_getBalance`` at latest block."""
    addr = _eth_address_param(address)
    res = _rpc(rpc_url, "eth_getBalance", [addr, "latest"])
    return int(res, 16) if isinstance(res, str) else int(res)


def latest_base_fee_per_gas_wei(rpc_url: str) -> int | None:
    """Base fee per gas from ``eth_getBlockByNumber(latest)``, or None if not EIP-1559."""
    try:
        block = _rpc(rpc_url, "eth_getBlockByNumber", ["latest", False])
        if not isinstance(block, dict):
            return None
        bf = block.get("baseFeePerGas")
        if bf is None:
            return None
        return int(bf, 16) if isinstance(bf, str) else int(bf)
    except Exception:
        return None


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


def _unwrap_management_api(resp: dict[str, Any], what: str) -> Any:
    """Require success (code 0 or omitted) and return ``data`` / ``Data`` (same as executeSignResult)."""
    c = api_code(resp)
    if c is not None and c != 0:
        err = api_error(resp) or str(resp)
        raise ValueError(f"{what} failed (code={c}): {err}")
    return api_data(resp)


def fetch_keygen_bundle(mpc_base: str, key_gen_id: str) -> dict[str, Any]:
    base = mpc_base.rstrip("/")
    q = urllib.parse.urlencode({"id": key_gen_id})
    api = http_get_json(f"{base}/getKeyGenResultById?{q}")
    data = _unwrap_management_api(api, "getKeyGenResultById")
    if not isinstance(data, dict):
        raise ValueError("getKeyGenResultById: missing data object")
    return data


def fetch_chain_detail_for_id(mpc_base: str, chain_id_num: int) -> dict[str, Any]:
    base = mpc_base.rstrip("/")
    api = http_get_json(f"{base}/getChainDetails?chain_id={chain_id_num}")
    data = _unwrap_management_api(api, "getChainDetails")
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
            "eth_abi / eth_utils required (install: $MPA_PATH/.venv/bin/pip install eth_account; "
            "see docs/skill/SKILL.md Python dependencies)"
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


def trigger_tx_params_from_compose_body(body: dict[str, Any]) -> dict[str, Any]:
    """
    Map ``bodyForSign`` fields to ``txParams`` for ``POST /triggerSignRequestById``
    (same shape as ``GET /getSignRequestById?tx_params=1``).
    """
    raw_nonce = body.get("txNonce")
    nonce = int(raw_nonce) if not isinstance(raw_nonce, int) else raw_nonce
    gl = body.get("txGasLimit")
    gas_limit = str(gl).strip() if gl is not None else ""
    if body.get("txMaxFeePerGas") is not None or body.get("txMaxPriorityFeePerGas") is not None:
        return {
            "nonce": nonce,
            "gasLimit": gas_limit,
            "txType": "eip1559",
            "maxFeePerGas": str(body.get("txMaxFeePerGas") or ""),
            "maxPriorityFeePerGas": str(body.get("txMaxPriorityFeePerGas") or ""),
        }
    return {
        "nonce": nonce,
        "gasLimit": gas_limit,
        "txType": "legacy",
        "gasPrice": str(body.get("txGasPrice") or ""),
    }


def parse_no_custom_gas_params(compose: dict[str, Any]) -> bool:
    """
    True  → ignore ChainDetails gas fields; derive gas limit and fees only from RPC
            (``eth_estimateGas``, ``eth_gasPrice`` / block base fee, etc.).
    False → use each gas-related field from ``getChainDetails`` when set; when a
            field is empty in chain config, fill it from RPC (partial custom config).
    Default when omitted: False.
    """
    if "noCustomGasParams" in compose:
        return bool(compose["noCustomGasParams"])
    if "no_custom_gas_params" in compose:
        return bool(compose["no_custom_gas_params"])
    return False


def _tx_field_int(x: Any) -> int:
    """Parse hex or decimal int from a tx dict field (e.g. ``gas``, ``gasPrice``)."""
    if isinstance(x, int):
        return x
    s = str(x).strip()
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    return int(s)


@dataclass(frozen=True)
class ComposeExecSetup:
    dest_chain: str
    dest_chain_num: int
    rpc_url: str
    chain_detail: dict[str, Any]
    no_custom_gas_params: bool
    purpose: str
    gas_limit_config: int | None
    gas_fee_multiplier: int | None
    chain_gas_price_gwei: float | None
    base_fee_multiplier_pct: int
    fee_params: dict[str, Any]
    legacy: bool
    key_list: list[str]
    pub_key: str
    executor: str
    client_id: str | None
    actions: list[dict[str, Any]]


def _compose_exec_setup(compose: dict[str, Any], mpc_auth_url: str) -> ComposeExecSetup:
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

    no_custom_gas_params = parse_no_custom_gas_params(compose)
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

    if no_custom_gas_params:
        gas_limit_config = None
        gas_fee_multiplier = None
        chain_gas_price_gwei = None
        base_fee_multiplier_pct = 100

    fee_params = fetch_chain_fee_params(rpc_url, dest_chain_num)
    # Mirror: const legacy = Boolean(chainDetail?.legacy) || !feeParams.isEip1559
    if no_custom_gas_params:
        legacy = not bool(fee_params.get("isEip1559"))
    else:
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

    return ComposeExecSetup(
        dest_chain=dest_chain,
        dest_chain_num=dest_chain_num,
        rpc_url=rpc_url,
        chain_detail=chain_detail,
        no_custom_gas_params=no_custom_gas_params,
        purpose=purpose,
        gas_limit_config=gas_limit_config,
        gas_fee_multiplier=gas_fee_multiplier,
        chain_gas_price_gwei=chain_gas_price_gwei,
        base_fee_multiplier_pct=base_fee_multiplier_pct,
        fee_params=fee_params,
        legacy=legacy,
        key_list=key_list,
        pub_key=pub_key,
        executor=executor,
        client_id=client_id,
        actions=actions,
    )


def native_transfer_value_wei_from_compose_action(raw_act: dict[str, Any]) -> int:
    """Parse nativeTransfer compose action amount in wei (same rules as ``_compose_action_tx_dict``)."""
    inputs = raw_act.get("inputs") or []
    if not isinstance(inputs, list):
        raise ValueError("composeActions: nativeTransfer inputs must be an array")
    if len(inputs) != 1:
        raise ValueError(
            "composeActions: nativeTransfer requires exactly one input (uint256 value)"
        )
    param_units = raw_act.get("paramUnits") or raw_act.get("param_units") or {}
    if not isinstance(param_units, dict):
        param_units = {}
    param_units_norm = {str(k): str(v) for k, v in param_units.items()}
    inp0 = inputs[0] or {}
    typ0 = str(inp0.get("type") or "uint256").strip()
    if not is_uint256_type(typ0):
        raise ValueError(
            f"composeActions: nativeTransfer input must be uint256 (got {typ0!r})"
        )
    unit_key = "0"
    unit = param_units_norm.get(unit_key) or param_units_norm.get(unit_key.zfill(1)) or "Wei"
    raw_v = inp0.get("value")
    val = display_value_to_raw(str(raw_v if raw_v is not None else ""), unit)
    try:
        value_wei = int(val)
    except ValueError as e:
        raise ValueError(f"composeActions: nativeTransfer value: {e}") from e
    if value_wei < 0:
        raise ValueError("composeActions: nativeTransfer value must be >= 0")
    return value_wei


def _compose_action_tx_dict(
    raw_act: dict[str, Any],
    index: int,
    *,
    dest_chain_num: int,
    rpc_url: str,
    executor: str,
    nonce0: int,
    fee_params: dict[str, Any],
    no_custom_gas_params: bool,
    gas_limit_config: int | None,
    gas_fee_multiplier: int | None,
    chain_gas_price_gwei: float | None,
    base_fee_multiplier_pct: int,
    legacy: bool,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """
    Build one signing tx dict for a compose action. Second return value is the
    ``bodyForSign`` fee snapshot for the first action only (empty dict otherwise).
    """
    if not isinstance(raw_act, dict):
        raise ValueError(f"composeActions[{index}] must be an object")
    is_native = bool(raw_act.get("nativeTransfer") or raw_act.get("native_transfer"))
    sig = (raw_act.get("signature") or "").strip()
    if is_native and not sig:
        sig = "nativeTransfer"
    dest = (raw_act.get("destinationContract") or raw_act.get("destination_contract") or "").strip()
    if not sig or not dest:
        raise ValueError(f"composeActions[{index}]: signature and destinationContract required")
    inputs = raw_act.get("inputs") or []
    if not isinstance(inputs, list):
        raise ValueError(f"composeActions[{index}]: inputs must be an array")
    param_units = raw_act.get("paramUnits") or raw_act.get("param_units") or {}
    if not isinstance(param_units, dict):
        param_units = {}
    param_units_norm = {str(k): str(v) for k, v in param_units.items()}

    value_wei: int | None = None
    if is_native:
        try:
            value_wei = native_transfer_value_wei_from_compose_action(raw_act)
        except ValueError as e:
            raise ValueError(f"composeActions[{index}]: {e}") from e
        calldata = "0x"
        data_hex = "0x"
    else:
        calldata = encode_action_calldata(sig, inputs, param_units_norm)
        data_hex = calldata if calldata.startswith("0x") else "0x" + calldata

    to_addr = _eth_address_param(dest)

    est = _maybe_int(raw_act.get("estimatedGas") or raw_act.get("estimated_gas"))
    gas_limit: int
    rpc_est = eth_estimate_gas(
        rpc_url, executor, to_addr, data_hex, value_wei if is_native else None
    )
    if est is not None and est > 0:
        gas_limit = est
    elif not no_custom_gas_params and gas_limit_config is not None and gas_limit_config > 0:
        # Chain default gasLimit is often 21000 (transfer); contract calls need at least intrinsic gas.
        gas_limit = max(gas_limit_config, rpc_est)
    else:
        gas_limit = rpc_est

    if gas_limit < rpc_est:
        raise ValueError(
            f"composeActions[{index}]: gas limit ({gas_limit}) is below eth_estimateGas ({rpc_est}). "
            "Increase composeActions[].estimatedGas, raise chain gasLimit in GET /getChainDetails, "
            "or omit estimatedGas so the limit uses max(chain gasLimit, estimate) or RPC-only gas (--no-custom-gas-params)."
        )

    current_nonce = nonce0 + index
    first_tx_fee: dict[str, Any] = {}

    if legacy:
        gp_item = _maybe_int(raw_act.get("gasPriceWei") or raw_act.get("gas_price_wei"))
        gas_price_wei = gp_item if gp_item is not None and gp_item > 0 else eth_gas_price(rpc_url)
        if not no_custom_gas_params and gas_fee_multiplier is not None and gas_fee_multiplier > 0:
            gas_price_wei = (gas_price_wei * (100 + gas_fee_multiplier)) // 100
        if not no_custom_gas_params and chain_gas_price_gwei is not None and chain_gas_price_gwei > 0:
            configured = _gwei_to_wei_ceil(chain_gas_price_gwei)
            if configured > gas_price_wei:
                gas_price_wei = configured
        if gp_item is not None and gp_item > 0:
            network_gp = eth_gas_price(rpc_url)
            if gas_price_wei < network_gp:
                raise ValueError(
                    f"composeActions[{index}]: effective gas price ({gas_price_wei} wei) is below eth_gasPrice ({network_gp} wei). "
                    "Increase composeActions[].gasPriceWei or adjust chain gasPrice / gasMultiplier in GET /getChainDetails, "
                    "or use --no-custom-gas-params for RPC-only fees."
                )
        if index == 0:
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
            # RPC-derived fee fields are in gwei; converting back to wei can yield tiny max_fee
            # (even 0) while max_prio is at least 1 gwei — invalid EIP-1559 and can appear as
            # nonsense like maxFeePerGas "7" with maxPriorityFeePerGas "1000000000".
            # The explicit per-action fee checks below only run when both mfee/mprio are set,
            # so clamp computed caps here.
            max_fee = max(max_fee, max_prio)
            bf_w_computed = latest_base_fee_per_gas_wei(rpc_url)
            if bf_w_computed is not None:
                max_fee = max(max_fee, bf_w_computed)
        else:
            max_fee = mfee
            max_prio = mprio
        if mfee is not None and mprio is not None and mfee > 0 and mprio > 0:
            if max_prio > max_fee:
                raise ValueError(
                    f"composeActions[{index}]: maxPriorityFeePerGas ({max_prio} wei) exceeds maxFeePerGas ({max_fee} wei). "
                    "Increase maxFeePerGas so it is at least as large as maxPriorityFeePerGas."
                )
            bf_w = latest_base_fee_per_gas_wei(rpc_url)
            if bf_w is not None and max_fee < bf_w:
                raise ValueError(
                    f"composeActions[{index}]: maxFeePerGas ({max_fee} wei) is below the current block base fee per gas ({bf_w} wei). "
                    "Raise maxFeePerGas (and typically maxPriorityFeePerGas) so the EIP-1559 transaction is valid."
                )
        if index == 0:
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

    return tx, first_tx_fee


def estimate_compose_native_requirement_wei(
    compose: dict[str, Any],
    mpc_auth_url: str,
    *,
    gas_margin_pct: float = 50.0,
) -> tuple[int, str]:
    """
    Upper bound on native currency (wei) the MPC wallet must hold for this compose
    flow: for each action, ``ceil(gas * (1 + margin/100)) * max_fee_per_gas`` (EIP-1559)
    or ``* gas_price`` (legacy), plus any ``value`` sent in the tx (e.g. native transfer).

    Uses the same gas limits and fee resolution as ``build_compose_multisign``;
    nonce does not affect these totals.

    Returns ``(required_wei, executor_address_0x, rpc_url)``.
    """
    s = _compose_exec_setup(compose, mpc_auth_url)
    total = 0
    nonce0 = 0
    for i, raw_act in enumerate(s.actions):
        tx, _ = _compose_action_tx_dict(
            raw_act,
            i,
            dest_chain_num=s.dest_chain_num,
            rpc_url=s.rpc_url,
            executor=s.executor,
            nonce0=nonce0,
            fee_params=s.fee_params,
            no_custom_gas_params=s.no_custom_gas_params,
            gas_limit_config=s.gas_limit_config,
            gas_fee_multiplier=s.gas_fee_multiplier,
            chain_gas_price_gwei=s.chain_gas_price_gwei,
            base_fee_multiplier_pct=s.base_fee_multiplier_pct,
            legacy=s.legacy,
        )
        gl = _tx_field_int(tx["gas"])
        gas_adj = int(math.ceil(gl * (1.0 + gas_margin_pct / 100.0)))
        if "gasPrice" in tx:
            total += gas_adj * _tx_field_int(tx["gasPrice"])
        else:
            total += gas_adj * _tx_field_int(tx["maxFeePerGas"])
        total += _tx_field_int(tx.get("value", "0x0"))
    return total, s.executor, s.rpc_url


def build_compose_multisign(
    compose: dict[str, Any],
    mpc_auth_url: str,
) -> dict[str, Any]:
    s = _compose_exec_setup(compose, mpc_auth_url)
    dest_chain = s.dest_chain
    dest_chain_num = s.dest_chain_num
    rpc_url = s.rpc_url
    actions = s.actions
    key_list = s.key_list
    pub_key = s.pub_key
    client_id = s.client_id
    purpose = s.purpose

    executor = s.executor
    nonce0 = eth_get_transaction_count(rpc_url, executor)

    message_hashes: list[str] = []
    message_raw_batch: list[str] = []
    batch_meta: list[dict[str, str]] = []
    first_tx_fee: dict[str, Any] = {}
    first_calldata: str | None = None

    for i, raw_act in enumerate(actions):
        if i == 0:
            is_native0 = bool(raw_act.get("nativeTransfer") or raw_act.get("native_transfer"))
            sig0 = (raw_act.get("signature") or "").strip()
            if is_native0 and not sig0:
                sig0 = "nativeTransfer"
            inputs0 = raw_act.get("inputs") or []
            if not isinstance(inputs0, list):
                inputs0 = []
            param_units0 = raw_act.get("paramUnits") or raw_act.get("param_units") or {}
            pu_map0 = {str(k): str(v) for k, v in param_units0.items()} if isinstance(param_units0, dict) else {}
            calldata0 = (
                encode_action_calldata(sig0, inputs0, pu_map0)
                if not is_native0
                else "0x"
            )
            first_calldata = calldata0 if calldata0.startswith("0x") else "0x" + calldata0

        tx, ft = _compose_action_tx_dict(
            raw_act,
            i,
            dest_chain_num=dest_chain_num,
            rpc_url=rpc_url,
            executor=executor,
            nonce0=nonce0,
            fee_params=s.fee_params,
            no_custom_gas_params=s.no_custom_gas_params,
            gas_limit_config=s.gas_limit_config,
            gas_fee_multiplier=s.gas_fee_multiplier,
            chain_gas_price_gwei=s.chain_gas_price_gwei,
            base_fee_multiplier_pct=s.base_fee_multiplier_pct,
            legacy=s.legacy,
        )
        if ft:
            first_tx_fee = ft

        msg_hash, msg_raw = tx_to_signing_hash_and_raw(tx)
        message_hashes.append(msg_hash)
        message_raw_batch.append(msg_raw)

        sig = (raw_act.get("signature") or "").strip()
        if bool(raw_act.get("nativeTransfer") or raw_act.get("native_transfer")) and not sig:
            sig = "nativeTransfer"
        dest = (raw_act.get("destinationContract") or raw_act.get("destination_contract") or "").strip()
        inputs = raw_act.get("inputs") or []
        if not isinstance(inputs, list):
            inputs = []
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
            body["value"] = str(native_transfer_value_wei_from_compose_action(actions[0]))
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
        "triggerTxParams": trigger_tx_params_from_compose_body(body),
        "triggerMessageHash": body.get("msgHash"),
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
        default=(os.environ.get("MPC_AUTH_URL") or DEFAULT_MPC_AUTH_URL),
        help="Management API host URL (env MPC_AUTH_URL, default: %(default)s)",
    )
    ap.add_argument(
        "--management-port",
        default=(os.environ.get("MANAGEMENT_PORT") or DEFAULT_MANAGEMENT_PORT),
        help="Management API port (env MANAGEMENT_PORT, default: %(default)s)",
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
        mpc_base = resolve_mpc_auth_base(args.mpc_auth_url, args.management_port)
        out = build_compose_multisign(compose, mpc_base)
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
