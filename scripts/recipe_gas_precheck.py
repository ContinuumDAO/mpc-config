"""
Native gas balance checks for compose recipes and Foundry broadcast flows.

**Compose:** uses ``build_compose_multisign``-aligned gas/fees, then
``ceil(gas * (1 + margin/100)) * price`` per action plus native ``value``.

**Foundry:** uses the final broadcast transaction dicts (after optional fee augmentation),
same margin formula, and resolves RPC from ``transactions[].rpc``, **GET /getChainDetails**,
or an explicit ``--rpc-url``.
"""

from __future__ import annotations

from typing import Any

import generateMultiSignRequestFromCompose as _compose


def require_native_gas_for_compose(
    compose: dict[str, Any],
    mpc_auth_base: str,
    *,
    gas_margin_pct: float = 50.0,
) -> None:
    """
    Raise ``ValueError`` with guidance for an AI agent if the MPC wallet cannot cover
    estimated fees (with margin) plus native value in compose actions.

    ``mpc_auth_base`` must be the resolved management API base URL (same as passed to
    ``build_compose_multisign``).
    """
    req_wei, executor, rpc_url = _compose.estimate_compose_native_requirement_wei(
        compose, mpc_auth_base, gas_margin_pct=gas_margin_pct
    )
    bal = _compose.eth_get_balance_wei(rpc_url, executor)
    if bal == 0:
        raise ValueError(
            "[AI_AGENT] Native gas balance on this chain is zero for MPC wallet "
            f"{executor}. The user must send the chain's native gas token to this address "
            "before this sign request can succeed. After funding, retry the recipe "
            "(network fees may differ slightly)."
        )
    if bal < req_wei:
        raise ValueError(
            "[AI_AGENT] MPC wallet "
            f"{executor} likely has insufficient native gas for this operation: balance is "
            f"{bal} wei but the estimated requirement (including {gas_margin_pct}% margin on "
            f"gas units and per-action fees from compose) is about {req_wei} wei. Ask the user "
            "to add more native gas to this address. Actual cost at execution can still differ "
            "from this RPC-based estimate."
        )


def require_native_gas_for_foundry_broadcast(
    broadcast: dict[str, Any],
    mpc_auth_base: str,
    *,
    executor: str,
    destination_chain_id: str | None = None,
    gas_margin_pct: float = 50.0,
    rpc_url: str | None = None,
) -> None:
    """
    Same balance check as ``require_native_gas_for_compose``, for Foundry
    ``run-latest``-style JSON (see ``generateSignRequestWithFoundryScript``).
    """
    import generateSignRequestWithFoundryScript as _fs

    req = _fs.estimate_foundry_broadcast_native_requirement_wei(
        broadcast, gas_margin_pct=gas_margin_pct
    )
    url = _fs.resolve_rpc_url_for_broadcast(
        broadcast,
        mpc_auth_base,
        destination_chain_id_override=destination_chain_id,
        rpc_url_override=rpc_url,
    )
    bal = _compose.eth_get_balance_wei(url, executor)
    if bal == 0:
        raise ValueError(
            "[AI_AGENT] Native gas balance on this chain is zero for wallet "
            f"{executor}. The user must send the chain's native gas token to this address "
            "before this sign request can succeed. After funding, retry "
            "(network fees may differ slightly)."
        )
    if bal < req:
        raise ValueError(
            "[AI_AGENT] Wallet "
            f"{executor} likely has insufficient native gas for this Foundry broadcast: balance is "
            f"{bal} wei but the estimated requirement (including {gas_margin_pct}% margin on "
            f"gas units and per-tx fees) is about {req} wei. Ask the user to add more native gas. "
            "Actual cost at execution can still differ from this RPC-based estimate."
        )
