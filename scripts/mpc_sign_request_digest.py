#!/usr/bin/env python3
"""
Detect **multi-agree** sign requests whose **MessageHash** is a domain digest (EIP-712, etc.),
not an RLP unsigned-transaction hash. For these, ``POST /triggerSignRequestById`` must **omit**
``txParams`` / ``txParamsBatch`` and **omit** ``messageHash`` so mpc-auth uses the stored
``MessageHash`` from ``POST /multiSignRequest`` (MessageRaw is not EVM calldata — do not run
``eth_estimateGas`` with it).

Aligned with continuumdao-node-app ``isPermit2Eip712MessageRawNotContractCall`` and
``docs/SIGN_REQUEST_TX_PARAMS.md``.

**Future:** extend :func:`is_digest_only_trigger_sign_request` when adding non-EVM kinds
(SSH, raw secp256k1, etc.) using ``extraJSON`` conventions or ``signatureText`` markers.
"""

from __future__ import annotations

import json
from typing import Any


def _extra_json_object(d: dict[str, Any]) -> dict[str, Any]:
    for key in ("extraJSON", "ExtraJSON", "extra_json"):
        raw = d.get(key)
        if raw is None or str(raw).strip() == "":
            continue
        try:
            j = json.loads(str(raw))
            if isinstance(j, dict):
                return j
        except (json.JSONDecodeError, TypeError):
            continue
    return {}


def _permit2_eip712_from_signature_text(sr: dict[str, Any]) -> bool:
    for key in ("signatureText", "SignatureText"):
        raw = sr.get(key)
        if not raw or not str(raw).strip():
            continue
        try:
            o = json.loads(str(raw)) if not isinstance(raw, dict) else dict(raw)
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(o, dict):
            continue
        if o.get("kind") != "EIP-712":
            continue
        if o.get("name") == "Permit2" and o.get("primaryType") == "PermitSingle":
            return True
    return False


def is_digest_only_trigger_sign_request(sr: dict[str, Any]) -> bool:
    """
    Return True if ``POST /triggerSignRequestById`` should not attach ``txParams`` or
    ``messageHash`` (MPC signs the existing ``MessageHash``; no Execute RLP tx on this id).

    Detection (any match):
    - ``extraJSON.permit2.evm.type == \"permit2_approval\"`` (app / merged audit blob)
    - ``extraJSON.permit2.kind == \"PermitSingle\"`` (``recipes/uniswapV4/permit2_approval.py``)
    - ``SignatureText`` JSON: EIP-712 Permit2 / PermitSingle (fallback if ExtraJSON shape differs)
    """
    ex = _extra_json_object(sr)
    p2 = ex.get("permit2")
    if isinstance(p2, dict):
        evm = p2.get("evm")
        if isinstance(evm, dict) and str(evm.get("type") or "").strip() == "permit2_approval":
            return True
        if str(p2.get("kind") or "").strip() == "PermitSingle":
            return True
    if _permit2_eip712_from_signature_text(sr):
        return True
    return False


def is_permit2_eip712_merged(merged: dict[str, Any]) -> bool:
    """
    True when merged sign-request / sign-result data indicates a Permit2 **PermitSingle** EIP-712
    digest (``executeSignResult`` must not treat ``MessageRaw`` as RLP + broadcast).
    """
    return is_digest_only_trigger_sign_request(merged)
