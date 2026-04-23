#!/usr/bin/env python3
"""
Build **POST /multiSignRequest** for Uniswap Trade **classic ERC-20 allowance** routing: an **EVM batch**
(2 or 3 transactions) matching ``continuumdao-node-app`` ``buildEvmMultisignBodyUniswapV4SkipPermit2Batch``.

Use Trade API ``POST /v1/swap`` with the allowance header (this repo’s ``uniswap_trade_swap.py``
sets ``x-permit2-disabled: true`` — required Uniswap header name), then this recipe.

Batch shape:

- **Dispatcher** (``swap.to`` ≠ inner router arg): **2 txs** — ``ERC20.approve(swap.to)``,
  then swap to ``swap.to``.
- **Direct Universal Router** (``swap.to`` == inner router): **3 txs** — ``ERC20.approve(allowance hub)``,
  allowance hub ``approve(token, router, amount, expiration)``, then swap.

**Dependencies:** ``eth_abi`` / ``eth_utils`` (via ``eth_account``); same stack as
``generateMultiSignRequestFromCompose.py``.

Example::

  python3 recipes/uniswapV4/uniswap_trade_quote.py ... > quote.json
  python3 recipes/uniswapV4/uniswap_trade_swap.py --quote-file quote.json > swap.json
  python3 recipes/uniswapV4/uniswap_v4_skip_permit2_batch_multisign.py \\
    --key-gen-id KeyGen... --swap-file swap.json --quote-file quote.json \\
    --token-in 0x... --swap-deadline-unix 1735689600
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
from pathlib import Path
from typing import Any

_scripts_dir = Path(__file__).resolve().parent.parent.parent / "scripts"
if str(_scripts_dir) not in sys.path:
    sys.path.insert(0, str(_scripts_dir))

import generateMultiSignRequestFromCompose as m
from uniswap_mpc_helpers import UNIVERSAL_ROUTER_V2_BY_CHAIN_ID
from recipe_gas_precheck import require_native_gas_for_compose
from uniswap_swap_multisign import extract_uniswap_create_swap

try:
    from eth_abi import decode as abi_decode
    from eth_abi import encode as abi_encode
    from eth_utils import keccak, to_checksum_address
except ImportError as e:
    raise SystemExit(
        "eth_abi and eth_utils are required (install eth_account). "
        "See docs/skill/SKILL.md / scripts/requirements-keygen-agent.txt"
    ) from e

PERMIT2_ADDRESS = "0x000000000022D473030F116dDEE9F6B43aC78BA3"
SEL_ERC20_APPROVE = keccak(text="approve(address,uint256)")[:4]
SEL_PERMIT2_APPROVE = keccak(text="approve(address,address,uint160,uint48)")[:4]
SEL_DISPATCH_EXECUTE = keccak(text="execute(address,address,uint256,bytes,bytes[],uint256)")[:4]

UNISWAP_UNIVERSAL_ROUTER_DEFAULT_GAS_UNITS = 1_500_000
MIN_V4_ROUTER_GAS = 500_000
MAX_UINT160 = (1 << 160) - 1
MAX_UINT48 = (1 << 48) - 1
PURPOSE_MAX_LEN = 256

_ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


def _norm_addr0x(name: str, a: str) -> str:
    s = (a or "").strip()
    if not s:
        raise ValueError(f"{name} is required")
    if not s.startswith("0x"):
        s = "0x" + s
    if not _ADDR_RE.match(s):
        raise ValueError(f"{name} must be a 0x-prefixed 20-byte EVM address")
    return to_checksum_address(s)


def _router_spender_or_raise(chain_id: int) -> str:
    row = UNIVERSAL_ROUTER_V2_BY_CHAIN_ID.get(chain_id)
    if not row or not str(row).startswith("0x"):
        raise ValueError(
            f"No Uniswap Universal Router in UNIVERSAL_ROUTER_V2_BY_CHAIN_ID for chainId {chain_id}. "
            "Extend uniswap_mpc_helpers.UNIVERSAL_ROUTER_V2_BY_CHAIN_ID or use a supported chain."
        )
    return to_checksum_address(str(row))


def parse_classic_quote_input_wei(full_quote_snapshot: dict[str, Any]) -> int:
    inner = full_quote_snapshot.get("quote")
    if not isinstance(inner, dict):
        raise ValueError("full_quote_snapshot must include a classic 'quote' object (Trade API /quote body)")
    inp = inner.get("input")
    if not isinstance(inp, dict):
        raise ValueError("quote.input missing")
    amt = inp.get("amount")
    if not isinstance(amt, str) or not amt.strip():
        raise ValueError("quote.input.amount missing or not a string")
    return int(amt, 10)


def quote_trade_type(full_quote_snapshot: dict[str, Any]) -> str:
    inner = full_quote_snapshot.get("quote")
    if not isinstance(inner, dict):
        return ""
    t = inner.get("type") or inner.get("tradeType")
    if isinstance(t, str) and t.strip():
        return t.strip().upper()
    return ""


def quote_slippage_percent(full_quote_snapshot: dict[str, Any]) -> float | None:
    inner = full_quote_snapshot.get("quote")
    if not isinstance(inner, dict):
        return None
    for k in ("slippage", "slippageTolerance"):
        raw = inner.get(k)
        if isinstance(raw, (int, float)) and math.isfinite(float(raw)):
            return float(raw)
        if isinstance(raw, str) and raw.strip():
            try:
                p = float(raw.strip().replace(",", ""))
                if math.isfinite(p):
                    return p
            except ValueError:
                continue
    return None


def apply_slippage_percent_to_approve_wei(base_wei: int, slippage_percent: float | None) -> int:
    if base_wei <= 0:
        return base_wei
    if slippage_percent is None or not math.isfinite(slippage_percent) or slippage_percent <= 0:
        return base_wei
    bps = min(100_000, int(round(slippage_percent * 100)))
    if bps <= 0:
        return base_wei
    return (base_wei * (10_000 + bps) + 9_999) // 10_000


def _decode_dispatch_execute(
    data_hex: str,
) -> tuple[str, str, int] | None:
    d = (data_hex or "").strip()
    if not d.startswith("0x"):
        d = "0x" + d
    raw = bytes.fromhex(d[2:])
    if len(raw) < 4 or raw[:4] != SEL_DISPATCH_EXECUTE:
        return None
    try:
        router, token, amount, _commands, _inputs, _deadline = abi_decode(
            ["address", "address", "uint256", "bytes", "bytes[]", "uint256"],
            raw[4:],
        )
        return (
            to_checksum_address(router),
            to_checksum_address(token),
            int(amount),
        )
    except Exception:
        return None


def router_spender_and_approve_wei_from_swap_calldata(
    data_hex: str,
    token_in: str,
    quote_input_wei: int,
    chain_id: int,
) -> tuple[str, int, int | None]:
    token_in_c = _norm_addr0x("token_in", token_in)
    dec = _decode_dispatch_execute(data_hex)
    canonical = _router_spender_or_raise(chain_id)
    if dec is None:
        return canonical, quote_input_wei, None
    router, token, amount = dec
    if token.lower() != token_in_c.lower():
        raise ValueError(
            f"Swap calldata token {token} does not match --token-in {token_in_c}. Refresh quote and /swap."
        )
    calldata_amt = int(amount) if amount > 0 else None
    approve_wei = quote_input_wei
    if calldata_amt is not None and calldata_amt > approve_wei:
        approve_wei = calldata_amt
    return router, approve_wei, calldata_amt


def _encode_erc20_approve(spender: str, amount_wei: int) -> str:
    body = abi_encode(["address", "uint256"], [_norm_addr0x("spender", spender), amount_wei])
    return "0x" + (SEL_ERC20_APPROVE + body).hex()


def _encode_permit2_approve(
    token: str, router: str, amount_wei: int, expiration: int
) -> str:
    if amount_wei > MAX_UINT160:
        raise ValueError("Allowance-hub approve amount exceeds uint160")
    if expiration < 0 or expiration > MAX_UINT48:
        raise ValueError("Allowance-hub approve expiration must fit uint48")
    body = abi_encode(
        ["address", "address", "uint160", "uint48"],
        [
            _norm_addr0x("token", token),
            _norm_addr0x("router", router),
            amount_wei,
            expiration,
        ],
    )
    return "0x" + (SEL_PERMIT2_APPROVE + body).hex()


def _gas_limit_from_estimate(estimated: int, chain_detail: dict[str, Any], no_custom_gas: bool) -> int:
    if no_custom_gas:
        return estimated
    gl = m.pick_str(chain_detail, "gasLimit", "GasLimit")
    cfg = m.parse_optional_int(gl) if gl is not None else None
    if cfg is not None and cfg > 0:
        return max(cfg, estimated)
    return estimated


def _legacy_fees(
    rpc_url: str,
    chain_detail: dict[str, Any],
    no_custom_gas: bool,
) -> int:
    gas_price_wei = m.eth_gas_price(rpc_url)
    if not no_custom_gas:
        mult = m.parse_optional_int(m.pick_str(chain_detail, "gasMultiplier", "GasMultiplier"))
        if mult is not None and mult > 0:
            gas_price_wei = (gas_price_wei * (100 + mult)) // 100
        gp_gwei = m.pick_str(chain_detail, "gasPrice", "GasPrice")
        cg = m.parse_optional_int(gp_gwei) if gp_gwei is not None else None
        if cg is not None and cg > 0:
            configured = m._gwei_to_wei_ceil(float(cg))
            if configured > gas_price_wei:
                gas_price_wei = configured
    return gas_price_wei


def _eip1559_fees(
    rpc_url: str,
    fee_params: dict[str, Any],
    chain_detail: dict[str, Any],
    no_custom_gas: bool,
) -> tuple[int, int]:
    base = float(fee_params.get("baseFeeGwei") or 0)
    prio = float(fee_params.get("priorityFeeGwei") or 0)
    if not no_custom_gas:
        cb = m.pick_str(chain_detail, "baseFee", "BaseFee")
        cp = m.pick_str(chain_detail, "priorityFee", "PriorityFee")
        if cb is not None and str(cb).strip():
            base = max(base, float(cb))
        if cp is not None and str(cp).strip():
            prio = max(prio, float(cp))
    mult_pct = 100
    if not no_custom_gas:
        bmp = m.pick_str(chain_detail, "baseFeeMultiplier", "BaseFeeMultiplier")
        pi = m.parse_optional_int(bmp) if bmp is not None else None
        if pi is not None and pi >= 100:
            mult_pct = pi
    base_component_gwei = base * mult_pct / 100.0
    max_fee_per_gas_gwei = base_component_gwei + prio
    max_prio = m._gwei_to_wei_ceil(prio) if prio > 0 else m._gwei_to_wei_ceil(1.0)
    max_fee = m._gwei_to_wei_ceil(max_fee_per_gas_gwei)
    bf_w = m.latest_base_fee_per_gas_wei(rpc_url)
    max_fee = max(max_fee, max_prio)
    if bf_w is not None:
        max_fee = max(max_fee, bf_w)
    if not no_custom_gas:
        gfm = m.parse_optional_int(m.pick_str(chain_detail, "gasMultiplier", "GasMultiplier"))
        if gfm is not None and gfm > 0:
            max_prio = (max_prio * (100 + gfm)) // 100
            max_fee = (max_fee * (100 + gfm)) // 100
    return max_fee, max_prio


def _unsigned_tx_legacy(
    *,
    chain_id: int,
    nonce: int,
    to_addr: str,
    data_hex: str,
    value_wei: int,
    gas_limit: int,
    gas_price_wei: int,
) -> dict[str, Any]:
    return {
        "nonce": str(nonce),
        "gasPrice": m._to_hex_wei(gas_price_wei),
        "gas": m._to_hex_wei(gas_limit),
        "to": _norm_addr0x("to", to_addr),
        "value": m._to_hex_wei(value_wei),
        "data": data_hex if data_hex.startswith("0x") else "0x" + data_hex,
        "chainId": str(chain_id),
    }


def _unsigned_tx_eip1559(
    *,
    chain_id: int,
    nonce: int,
    to_addr: str,
    data_hex: str,
    value_wei: int,
    gas_limit: int,
    max_fee: int,
    max_prio: int,
) -> dict[str, Any]:
    return {
        "type": "0x2",
        "nonce": str(nonce),
        "gas": m._to_hex_wei(gas_limit),
        "maxFeePerGas": m._to_hex_wei(max_fee),
        "maxPriorityFeePerGas": m._to_hex_wei(max_prio),
        "to": _norm_addr0x("to", to_addr),
        "value": m._to_hex_wei(value_wei),
        "data": data_hex if data_hex.startswith("0x") else "0x" + data_hex,
        "chainId": str(chain_id),
    }


def _parse_optional_gas_limit_swap(sw: dict[str, Any]) -> int | None:
    for k in ("gasLimit", "gas"):
        v = sw.get(k)
        if v is None:
            continue
        try:
            if isinstance(v, str) and v.strip().startswith("0x"):
                g = int(v.strip(), 16)
            else:
                g = int(str(v).strip(), 10)
            if g > 0:
                return g
        except ValueError:
            continue
    return None


def _swap_value_wei(sw: dict[str, Any]) -> int:
    return m._int_from_value_field(sw.get("value"))


def uniswap_v4_skip_permit2_batch_multisign_payload(
    mpc_auth_url: str,
    management_port: str | int,
    key_gen_id: str,
    create_swap_response: dict[str, Any],
    full_quote_snapshot: dict[str, Any],
    token_in: str,
    *,
    swap_deadline_unix: int | None = None,
    slippage_percent: float | None = None,
    destination_chain_id: str | None = None,
    purpose: str = "",
    no_custom_gas_params: bool = False,
    rpc_gateway: str | None = None,
    skip_gas_check: bool = False,
) -> dict[str, Any]:
    """
    Build ``endpoint`` / ``bodyForSign`` / ``messageToSign`` for the classic-allowance Uniswap batch
    (same semantics as continuumdao-node-app).
    """
    base = m.resolve_mpc_auth_base(mpc_auth_url, management_port)
    sw = extract_uniswap_create_swap(create_swap_response)
    dcid = (destination_chain_id or "").strip()
    if "chainId" in sw and sw["chainId"] is not None:
        sw_chain = int(sw["chainId"])
        if dcid:
            if int(dcid, 10) != sw_chain:
                raise ValueError(f"destination chain id {dcid} does not match swap.chainId {sw_chain}")
            chain_num = sw_chain
        else:
            chain_num = sw_chain
    else:
        if not dcid:
            raise ValueError("destinationChainId or swap.chainId is required")
        chain_num = int(dcid, 10)

    token_in_c = _norm_addr0x("token_in", token_in)
    if token_in_c.lower() == "0x0000000000000000000000000000000000000000":
        raise ValueError("Native-token swaps are not supported by this batch recipe (ERC-20 approve path only).")

    quote_input_wei = parse_classic_quote_input_wei(full_quote_snapshot)
    if quote_input_wei <= 0:
        raise ValueError("quote.input.amount must be a positive integer")

    tt = quote_trade_type(full_quote_snapshot)
    slip_use = slippage_percent
    if slip_use is None and tt == "EXACT_OUTPUT":
        slip_use = quote_slippage_percent(full_quote_snapshot)

    data_hex = sw["data"] if str(sw["data"]).startswith("0x") else "0x" + sw["data"]
    to_router = _norm_addr0x("swap.to", sw["to"])

    router_inner, base_approve_wei, calldata_amt = router_spender_and_approve_wei_from_swap_calldata(
        data_hex, token_in_c, quote_input_wei, chain_num
    )
    approve_amount_wei = apply_slippage_percent_to_approve_wei(base_approve_wei, slip_use)

    use_permit2_triple = to_router.lower() == router_inner.lower()
    if use_permit2_triple and approve_amount_wei > MAX_UINT160:
        raise ValueError("Approved transfer amount exceeds allowance-hub uint160 max; reduce trade size.")

    now = __import__("time").time()
    if use_permit2_triple:
        if swap_deadline_unix is not None and swap_deadline_unix > 0:
            exp48 = int(swap_deadline_unix)
        else:
            exp48 = int(now) + 1800
        if exp48 > MAX_UINT48:
            exp48 = MAX_UINT48
    else:
        exp48 = 0

    erc20_spender = PERMIT2_ADDRESS if use_permit2_triple else to_router
    approve_data = _encode_erc20_approve(erc20_spender, approve_amount_wei)
    approve_msg_raw = approve_data[2:] if approve_data.startswith("0x") else approve_data
    p2_calldata: str | None = None
    if use_permit2_triple:
        p2_calldata = _encode_permit2_approve(token_in_c, router_inner, approve_amount_wei, exp48)

    chain_detail = m.fetch_chain_detail_for_id(base, chain_num)
    rpc_url = (rpc_gateway or "").strip() or str(
        m.pick_str(chain_detail, "rpcGateway", "RpcGateway", "rpc_gateway") or ""
    ).strip()
    if not rpc_url:
        raise ValueError("No rpcGateway for chain; configure GET /getChainDetails or pass rpc_gateway")

    kg = m.fetch_keygen_bundle(base, key_gen_id)
    exec_eth = m.pick_str(kg, "ethereumaddress", "EthereumAddress")
    if not exec_eth or not str(exec_eth).strip():
        raise ValueError("getKeyGenResultById: ethereumaddress missing")
    executor = _norm_addr0x("executor", str(exec_eth))

    kl = kg.get("keylist") or kg.get("KeyList")
    if not isinstance(kl, list) or not kl:
        raise ValueError("getKeyGenResultById: keylist missing or empty")
    key_list_use = [str(x) for x in kl]

    pub_key = kg.get("pubkeyhex") or kg.get("PubKeyHex") or kg.get("PubKey")
    if not pub_key or not isinstance(pub_key, str):
        raise ValueError("getKeyGenResultById: pubkeyhex missing")
    pub_key = pub_key.strip()

    cid = m._first_client_id(kg.get("ClientKeys") or kg.get("clientkeys"))

    swap_val_early = _swap_value_wei(sw)
    if not skip_gas_check:
        gas_compose_actions: list[dict[str, Any]] = [
            {
                "destinationContract": token_in_c,
                "preencodedData": approve_data,
                "value": "0",
                "signature": "preencodedCall",
            }
        ]
        if p2_calldata is not None:
            gas_compose_actions.append(
                {
                    "destinationContract": PERMIT2_ADDRESS,
                    "preencodedData": p2_calldata,
                    "value": "0",
                    "signature": "preencodedCall",
                }
            )
        gas_compose_actions.append(
            {
                "destinationContract": to_router,
                "preencodedData": data_hex,
                "value": str(swap_val_early),
                "signature": "preencodedCall",
            }
        )
        gas_compose: dict[str, Any] = {
            "keyGenId": key_gen_id,
            "destinationChainId": str(chain_num),
            "composeActions": gas_compose_actions,
        }
        if rpc_gateway:
            gas_compose["rpcGateway"] = rpc_gateway.strip()
        if no_custom_gas_params:
            gas_compose["noCustomGasParams"] = True
        require_native_gas_for_compose(gas_compose, base)

    legacy_raw = m.pick_str(chain_detail, "legacy", "Legacy")
    legacy = bool(
        legacy_raw is True or (isinstance(legacy_raw, str) and legacy_raw.strip().lower() == "true")
    )
    fee_params = m.fetch_chain_fee_params(rpc_url, chain_num)
    if not legacy and not bool(fee_params.get("isEip1559")):
        legacy = True

    nonce0 = m.eth_get_transaction_count(rpc_url, executor)
    no_custom = bool(no_custom_gas_params)

    message_hashes: list[str] = []
    message_raw_batch: list[str] = []
    proposal_tx_params_batch: list[dict[str, Any]] = []
    first_tx_fee: dict[str, Any] = {}

    # --- Approve (tx 0)
    est0 = m.eth_estimate_gas(rpc_url, executor, token_in_c, approve_data, 0)
    gl0 = _gas_limit_from_estimate(est0, chain_detail, no_custom)
    if legacy:
        gp0 = _legacy_fees(rpc_url, chain_detail, no_custom)
        tx0 = _unsigned_tx_legacy(
            chain_id=chain_num,
            nonce=nonce0,
            to_addr=token_in_c,
            data_hex=approve_data,
            value_wei=0,
            gas_limit=gl0,
            gas_price_wei=gp0,
        )
        first_tx_fee = {"txNonce": nonce0, "txGasLimit": str(gl0), "txGasPrice": str(gp0)}
    else:
        mf0, mp0 = _eip1559_fees(rpc_url, fee_params, chain_detail, no_custom)
        tx0 = _unsigned_tx_eip1559(
            chain_id=chain_num,
            nonce=nonce0,
            to_addr=token_in_c,
            data_hex=approve_data,
            value_wei=0,
            gas_limit=gl0,
            max_fee=mf0,
            max_prio=mp0,
        )
        first_tx_fee = {
            "txNonce": nonce0,
            "txGasLimit": str(gl0),
            "txMaxFeePerGas": str(mf0),
            "txMaxPriorityFeePerGas": str(mp0),
        }
    h0, r0 = m.tx_to_signing_hash_and_raw(tx0)
    message_hashes.append(h0)
    message_raw_batch.append(r0)
    proposal_tx_params_batch.append(m.proposal_tx_params_from_unsigned_tx(tx0, legacy=legacy))

    # --- Allowance-hub approve toward router (tx 1) when swap targets router directly
    if use_permit2_triple and p2_calldata is not None:
        est1 = m.eth_estimate_gas(rpc_url, executor, PERMIT2_ADDRESS, p2_calldata, 0)
        gl1 = _gas_limit_from_estimate(est1, chain_detail, no_custom)
        n1 = nonce0 + 1
        if legacy:
            gp1 = _legacy_fees(rpc_url, chain_detail, no_custom)
            tx1 = _unsigned_tx_legacy(
                chain_id=chain_num,
                nonce=n1,
                to_addr=PERMIT2_ADDRESS,
                data_hex=p2_calldata,
                value_wei=0,
                gas_limit=gl1,
                gas_price_wei=gp1,
            )
        else:
            mf1, mp1 = _eip1559_fees(rpc_url, fee_params, chain_detail, no_custom)
            tx1 = _unsigned_tx_eip1559(
                chain_id=chain_num,
                nonce=n1,
                to_addr=PERMIT2_ADDRESS,
                data_hex=p2_calldata,
                value_wei=0,
                gas_limit=gl1,
                max_fee=mf1,
                max_prio=mp1,
            )
        h1, r1 = m.tx_to_signing_hash_and_raw(tx1)
        message_hashes.append(h1)
        message_raw_batch.append(r1)
        proposal_tx_params_batch.append(m.proposal_tx_params_from_unsigned_tx(tx1, legacy=legacy))

    # --- Swap (last)
    swap_val = _swap_value_wei(sw)
    from_trade = _parse_optional_gas_limit_swap(sw)
    gas_build_source = "rpcEstimate"
    estimate_err: str | None = None
    if from_trade is not None:
        base_gas = from_trade
        gas_build_source = "tradeApi"
    else:
        try:
            base_gas = m.eth_estimate_gas(rpc_url, executor, to_router, data_hex, swap_val or None)
        except Exception as e:
            estimate_err = str(e)
            if no_custom:
                base_gas = UNISWAP_UNIVERSAL_ROUTER_DEFAULT_GAS_UNITS
            else:
                cfg_gl = m.parse_optional_int(m.pick_str(chain_detail, "gasLimit", "GasLimit"))
                if cfg_gl is not None and cfg_gl >= MIN_V4_ROUTER_GAS:
                    base_gas = cfg_gl
                else:
                    base_gas = UNISWAP_UNIVERSAL_ROUTER_DEFAULT_GAS_UNITS
            gas_build_source = "estimateFailedFallback"

    gls = _gas_limit_from_estimate(base_gas, chain_detail, no_custom)
    n_swap = nonce0 + (2 if use_permit2_triple else 1)
    if legacy:
        gps = _legacy_fees(rpc_url, chain_detail, no_custom)
        txs = _unsigned_tx_legacy(
            chain_id=chain_num,
            nonce=n_swap,
            to_addr=to_router,
            data_hex=data_hex,
            value_wei=swap_val,
            gas_limit=gls,
            gas_price_wei=gps,
        )
    else:
        mfs, mps = _eip1559_fees(rpc_url, fee_params, chain_detail, no_custom)
        txs = _unsigned_tx_eip1559(
            chain_id=chain_num,
            nonce=n_swap,
            to_addr=to_router,
            data_hex=data_hex,
            value_wei=swap_val,
            gas_limit=gls,
            max_fee=mfs,
            max_prio=mps,
        )
    hs, rs = m.tx_to_signing_hash_and_raw(txs)
    message_hashes.append(hs)
    message_raw_batch.append(rs)
    proposal_tx_params_batch.append(m.proposal_tx_params_from_unsigned_tx(txs, legacy=legacy))

    swap_msg_index = 2 if use_permit2_triple else 1
    canonical_ur = _router_spender_or_raise(chain_num)

    audit: dict[str, Any] = {
        "skipPermit2Batch": True,
        "approvalPath": "permit2_triple" if use_permit2_triple else "dispatcher",
        "approveAmount": {
            "baseWeiBeforeSlippage": str(base_approve_wei),
            "finalWei": str(approve_amount_wei),
            "slippagePercent": slip_use,
            "quoteInputWei": str(quote_input_wei),
            **(
                {"swapCalldataAmountWei": str(calldata_amt)}
                if calldata_amt is not None
                else {}
            ),
        },
        "uniswapCreateSwap": {
            "requestId": create_swap_response.get("requestId"),
            "gasFee": create_swap_response.get("gasFee"),
            "gasBuildSwap": {
                "useCustomGas": not no_custom,
                "source": gas_build_source,
                "baseGasUnits": str(base_gas),
                **({"estimateGasError": estimate_err} if estimate_err else {}),
            },
            "swap": {
                "to": sw["to"],
                "value": sw.get("value", "0"),
                "dataNibbles": len(data_hex) - 2 if data_hex.startswith("0x") else len(data_hex),
            },
        },
        "fullQuoteFromPermitSnapshot": full_quote_snapshot,
        "originalPurpose": purpose,
        "innerRouterFromCalldata": router_inner,
        "swapToEqualsInnerRouter": use_permit2_triple,
    }
    if use_permit2_triple:
        audit["permit2Erc20Approve"] = {
            "token": token_in_c,
            "spender": PERMIT2_ADDRESS,
            "amountWei": str(approve_amount_wei),
            "note": "ERC-20 → allowance hub before hub approve(router).",
        }
        audit["permit2ApproveUniversalRouter"] = {
            "permit2": PERMIT2_ADDRESS,
            "token": token_in_c,
            "spender": router_inner,
            "canonicalUniversalRouterFromAppMap": canonical_ur,
            "spenderMatchesCanonicalMap": router_inner.lower() == canonical_ur.lower(),
            "amountWei": str(approve_amount_wei),
            "expiration": str(exp48),
            "note": "Allowance-hub spender must match the router in swap calldata.",
        }
    else:
        audit["erc20ApproveDispatcher"] = {
            "token": token_in_c,
            "spender": to_router,
            "amountWei": str(approve_amount_wei),
            "note": "Dispatcher pulls via transferFrom; allowance on swap.to.",
        }

    batch_meta: list[dict[str, Any]] = [
        {
            "destinationAddress": token_in_c,
            "signatureText": m.dumps_js(
                {
                    "kind": "UniswapV4",
                    "name": "ERC20.approve",
                    "to": "allowance hub" if use_permit2_triple else "dispatcher(swap.to)",
                    "function": "approve(address spender, uint256 amount)",
                    "spender": erc20_spender,
                    "amountWei": str(approve_amount_wei),
                }
            ),
            "evm": {
                "type": (
                    "uniswap_v4_skip_permit2_approve"
                    if use_permit2_triple
                    else "uniswap_v4_skip_permit2_dispatcher_approve"
                ),
                "version": 1,
                "chainId": str(chain_num),
                **({"permit2": PERMIT2_ADDRESS} if use_permit2_triple else {"dispatcher": to_router}),
            },
        }
    ]
    if use_permit2_triple:
        batch_meta.append(
            {
                "destinationAddress": PERMIT2_ADDRESS,
                "signatureText": m.dumps_js(
                    {
                        "kind": "UniswapV4",
                        "name": "AllowanceHub.approve",
                        "function": "approve(address token, address spender, uint160 amount, uint48 expiration)",
                        "token": token_in_c,
                        "spender": router_inner,
                        "amountWei": str(approve_amount_wei),
                        "expiration": str(exp48),
                    }
                ),
                "evm": {
                    "type": "uniswap_v4_skip_permit2_permit2_approve",
                    "version": 1,
                    "chainId": str(chain_num),
                    "permit2": PERMIT2_ADDRESS,
                    "permit2Spender": router_inner,
                },
            }
        )
    batch_meta.append(
        {
            "destinationAddress": to_router,
            "signatureText": m.dumps_js(
                {
                    "kind": "UniswapV4",
                    "name": "UniversalRouter.execute",
                    "note": f"Calldata from Trade API POST /swap; signed tx hash in messageHashes[{swap_msg_index}].",
                }
            ),
            "evm": {"type": "uniswap_v4_swap_tx", "version": 1, "chainId": str(chain_num)},
            "uniswapV4": audit,
        }
    )

    extra_payload: dict[str, Any] = {"batchMeta": batch_meta}
    if not no_custom:
        snap = m.chain_snapshot_for_custom_gas_extra_json(chain_detail)
        if snap:
            extra_payload["customGasChainDetails"] = snap
    extra_json = m.dumps_js(extra_payload)
    first_sig_text = batch_meta[0]["signatureText"]

    batch_desc = (
        "Uniswap V4: 3-tx batch (classic allowance) — (1) ERC-20 approve allowance hub, (2) hub approve(Universal Router), (3) swap (Trade /swap)."
        if use_permit2_triple
        else "Uniswap V4: 2-tx batch (classic allowance, dispatcher) — (1) ERC-20 approve swap.to (dispatcher pulls tokens), (2) swap (Trade /swap)."
    )
    purpose_trim = (purpose or "").strip()
    purpose_final = ((purpose_trim + "\n\n") if purpose_trim else "") + batch_desc
    if len(purpose_final) > PURPOSE_MAX_LEN:
        purpose_final = purpose_final[: PURPOSE_MAX_LEN - 1] + "…"

    body: dict[str, Any] = {
        "keyList": key_list_use,
        "pubKey": pub_key,
        "msgHash": message_hashes[0],
        "msgRaw": approve_msg_raw,
        "messageHashes": message_hashes,
        "messageRawBatch": message_raw_batch,
        "destinationChainID": str(chain_num),
        "destinationAddress": token_in_c,
        "extraJSON": extra_json,
        "signatureText": first_sig_text,
        "purpose": purpose_final,
        **first_tx_fee,
        "proposalTxParams": proposal_tx_params_batch,
    }
    if swap_val > 0:
        body["value"] = str(swap_val)
    if cid:
        body["clientId"] = cid

    message_to_sign = m.dumps_js(body)

    return {
        "endpoint": "multiSignRequest",
        "bodyForSign": body,
        "messageToSign": message_to_sign,
        "chainId": str(chain_num),
        "count": len(message_hashes),
        "triggerTxParams": m.trigger_tx_params_from_compose_body(body),
        "triggerMessageHash": body.get("msgHash"),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument(
        "--mpc-auth-url",
        default=(os.environ.get("MPC_AUTH_URL") or m.DEFAULT_MPC_AUTH_URL),
        help="Management API host URL (env MPC_AUTH_URL)",
    )
    ap.add_argument(
        "--management-port",
        default=(os.environ.get("MANAGEMENT_PORT") or m.DEFAULT_MANAGEMENT_PORT),
        help="Management API port (env MANAGEMENT_PORT)",
    )
    ap.add_argument("--key-gen-id", required=True, metavar="ID", help="KeyGen request id")
    ap.add_argument("--chain-id", default="", help="Destination chain if swap JSON omits chainId")
    ap.add_argument("--swap-file", default="", metavar="FILE", help="JSON: Trade POST /swap response (with swap)")
    ap.add_argument("--swap-json", default="", help="Inline JSON for create-swap response")
    ap.add_argument("--stdin-swap", action="store_true", help="Read create-swap JSON from stdin")
    ap.add_argument("--quote-file", default="", metavar="FILE", help="JSON: quote snapshot (uniswap_trade_quote output or /quote body with quote.input.amount)")
    ap.add_argument("--quote-json", default="", help="Inline quote snapshot JSON")
    ap.add_argument("--token-in", required=True, metavar="ADDR", help="ERC-20 token spent (same as Trade quote tokenIn)")
    ap.add_argument(
        "--swap-deadline-unix",
        type=int,
        default=None,
        help="Unix seconds for allowance-hub approve expiration (3-tx path); default now+1800 if omitted",
    )
    ap.add_argument(
        "--slippage-percent",
        type=float,
        default=None,
        help="Extra slippage on approve amount (recommended for EXACT_OUTPUT); else taken from quote when possible",
    )
    ap.add_argument("--purpose", default="", help="Sign-request purpose prefix (batch description is appended)")
    ap.add_argument("--rpc-gateway", default="", help="Override RPC URL")
    ap.add_argument(
        "--no-custom-gas-params",
        action="store_true",
        help="RPC-only gas (same as compose noCustomGasParams)",
    )
    ap.add_argument("--skip-gas-check", action="store_true", help="Skip native balance precheck")
    ap.add_argument("--ed25519-seed-hex", metavar="HEX", help="Sign messageToSign; output postBody")
    ap.add_argument("--eip191-private-key-hex", metavar="HEX", help="Sign messageToSign; output postBody")
    ap.add_argument("--out", metavar="FILE", default="", help="Write JSON to file as well as stdout")
    args = ap.parse_args()

    if args.stdin_swap:
        swap_raw = sys.stdin.read()
    elif (args.swap_json or "").strip():
        swap_raw = args.swap_json
    elif (args.swap_file or "").strip():
        swap_raw = Path(args.swap_file).read_text(encoding="utf-8")
    else:
        ap.error("Provide --swap-file, --swap-json, or --stdin-swap")

    if (args.quote_json or "").strip():
        quote_raw = args.quote_json
    elif (args.quote_file or "").strip():
        quote_raw = Path(args.quote_file).read_text(encoding="utf-8")
    else:
        ap.error("Provide --quote-file or --quote-json (classic quote for input amount)")

    try:
        swap_parsed = json.loads(swap_raw)
        quote_parsed = json.loads(quote_raw)
    except json.JSONDecodeError as e:
        print(f"Invalid JSON: {e}", file=sys.stderr)
        sys.exit(1)
    if not isinstance(swap_parsed, dict) or not isinstance(quote_parsed, dict):
        print("Swap and quote JSON must be objects", file=sys.stderr)
        sys.exit(1)

    utq = quote_parsed.get("uniswapTradeQuote")
    if isinstance(utq, dict):
        quote_use = utq
    else:
        quote_use = quote_parsed

    chain_opt = (args.chain_id or "").strip() or None
    try:
        out = uniswap_v4_skip_permit2_batch_multisign_payload(
            args.mpc_auth_url,
            args.management_port,
            args.key_gen_id,
            swap_parsed,
            quote_use,
            args.token_in,
            swap_deadline_unix=args.swap_deadline_unix,
            slippage_percent=args.slippage_percent,
            destination_chain_id=chain_opt,
            purpose=(args.purpose or "").strip(),
            no_custom_gas_params=bool(args.no_custom_gas_params),
            rpc_gateway=(args.rpc_gateway or "").strip() or None,
            skip_gas_check=bool(args.skip_gas_check),
        )
    except (TypeError, ValueError, RuntimeError) as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)

    if args.ed25519_seed_hex:
        sig = m.sign_ed25519(out["messageToSign"], args.ed25519_seed_hex)
        out["postBody"] = {**out["bodyForSign"], "clientSig": sig, "signedMessage": out["messageToSign"]}
    elif args.eip191_private_key_hex:
        sig = m.sign_eip191(out["messageToSign"], args.eip191_private_key_hex)
        out["postBody"] = {**out["bodyForSign"], "clientSig": sig, "signedMessage": out["messageToSign"]}

    text = json.dumps(out, indent=2, ensure_ascii=False)
    print(text)
    if (args.out or "").strip():
        Path(args.out).write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
