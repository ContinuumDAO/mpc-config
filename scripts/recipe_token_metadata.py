"""Helpers for recipe CLIs: scale human token amounts and read decimals from GET /getTokens."""

from __future__ import annotations

import urllib.parse
from decimal import Decimal, InvalidOperation, getcontext
from typing import Any, Callable

getcontext().prec = 78


def _chain_id_matches(stored: Any, want_num: int) -> bool:
    try:
        s = str(stored).strip()
        if s.lower().startswith("0x"):
            return int(s, 16) == want_num
        return int(s, 10) == want_num
    except (ValueError, TypeError):
        return False


def _token_bucket(row: dict[str, Any], category: str) -> Any:
    if category == "ERC20":
        return row.get("ERC20") or row.get("erc20")
    if category == "CTMERC20":
        return row.get("CTMERC20") or row.get("ctmerc20")
    raise ValueError(f"unsupported token category: {category!r}")


def human_amount_to_raw_uint256(amount: str, decimals: int) -> str:
    """Scale a human-readable token amount by 10**decimals (ROUND_DOWN)."""
    trimmed = (amount or "").strip()
    if not trimmed:
        return "0"
    try:
        d = Decimal(trimmed)
        scale = Decimal(10) ** int(decimals)
        raw = int((d * scale).to_integral_value(rounding="ROUND_DOWN"))
        return str(raw)
    except (InvalidOperation, ValueError):
        raise ValueError(f"amount is not a valid decimal number: {amount!r}") from None


def fetch_decimals_from_get_tokens(
    mpc_base: str,
    chain_id_num: int,
    token_contract: str,
    *,
    category: str,
    http_get_json: Callable[[str], dict[str, Any]],
    unwrap_management_api: Callable[[dict[str, Any], str], Any],
) -> int | None:
    """Return decimals from GET /getTokens for this contract on chain, or None if unavailable."""
    base = mpc_base.rstrip("/")
    token_lc = token_contract.strip().lower()
    want = str(chain_id_num)

    def scan_data(data: Any) -> int | None:
        if not isinstance(data, dict):
            return None
        eth = data.get("ethereum") or data.get("Ethereum")
        if not isinstance(eth, list):
            return None
        for row in eth:
            if not isinstance(row, dict):
                continue
            cid = row.get("chainId") if row.get("chainId") is not None else row.get("ChainId")
            if cid is None or not _chain_id_matches(cid, chain_id_num):
                continue
            bucket = _token_bucket(row, category)
            if not isinstance(bucket, dict):
                continue
            contracts = bucket.get("contracts")
            if not isinstance(contracts, list):
                continue
            for c in contracts:
                if not isinstance(c, dict):
                    continue
                addr = (
                    c.get("contractAddress")
                    if c.get("contractAddress") is not None
                    else c.get("contract_address")
                )
                if addr is None or str(addr).strip().lower() != token_lc:
                    continue
                d = c.get("decimals")
                if d is None:
                    return None
                try:
                    return int(d)
                except (TypeError, ValueError):
                    return None
        return None

    q = urllib.parse.urlencode({"chainType": "ethereum", "chain_id": want})
    api = http_get_json(f"{base}/getTokens?{q}")
    data = unwrap_management_api(api, "getTokens")
    found = scan_data(data)
    if found is not None:
        return found

    q2 = urllib.parse.urlencode({"chainType": "ethereum"})
    api2 = http_get_json(f"{base}/getTokens?{q2}")
    data2 = unwrap_management_api(api2, "getTokens")
    return scan_data(data2)
