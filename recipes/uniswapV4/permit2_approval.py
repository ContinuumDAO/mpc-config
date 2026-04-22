#!/usr/bin/env python3
"""
Build **POST /multiSignRequest** output for a Uniswap **Permit2** *IAllowanceTransfer*
**PermitSingle** EIP-712 digest (``msgHash``), so the MPC KeyGen (multi-agree) flow can
produce the ECDSA signature used with ``permit`` / ``permitTransferFrom`` on Permit2.

This is **not** a contract calldata proposal: ``msgHash`` is the 32-byte EIP-712 hash
the MPC signs. You typically **do not** use ``executeSignResult.py`` to broadcast this
result as a raw transaction; you pass the returned MPC signature into a follow-on
transaction that submits the permit (or use it off-chain as Permit2 expects).

**Dependencies:** ``eth_account``; the same stack as ``generateMultiSignRequestFromCompose.py``
(``PyNaCl``, ``cryptography``, etc. — see ``docs/skill/SKILL.md`` / ``scripts/requirements-keygen-agent.txt``).

To derive **nonce**, **deadlines**, and optional Universal Router **spender** from JSON-RPC,
see ``recipes/uniswapV4/permit2_keygen_params.py`` (outputs ``permit2_approval_only_kwargs`` for this module).

**Purpose** and **extraJSON** (``POST /multiSignRequest``): The API expects **purpose** (a string,
**maximum 256 characters** — a hard server/API limit) to explain *to other nodes* what they are
agreeing to; it is **always** present in the signed JSON. **AI agent:** keep **purpose** at or under
**256** UTF-8 code points; put longer context in **extraJSON** (e.g. **uniswapTradeQuote**), not
in **purpose**. Use **purpose** to describe the **intended Uniswap swap** (router, tokens, and
that this request is a **Permit2** approval enabling that path). **extraJSON** is an arbitrary JSON
string for reviewer context; this script merges a structured **permit2** audit blob and, when you
provide a Trade API quote, **uniswapTradeQuote** (see ``docs/references/API_IMPLEMENTATION.md`` §
``POST /multiSignRequest``). The reference notes Ed25519-focused handling for some server paths; the
field is still part of the standard request body and is used here for **swap/quote** metadata and
permit context.

Example::

  python3 recipes/uniswapV4/permit2_approval.py \\
    --key-gen-id KeyGen2026... \\
    --chain-id 1 \\
    --permit2 0x000000000022D473030F116dDEE9F6B43aC78BA3 \\
    --token 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 \\
    --amount 1000000 \\
    --expiration 4294967295 \\
    --permit-nonce 0 \\
    --spender 0x... \\
    --sig-deadline 1735689600

  # Add management signing (same as compose recipes):
  python3 recipes/uniswapV4/permit2_approval.py ... --ed25519-seed-hex <hex>
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

_scripts_dir = Path(__file__).resolve().parent.parent.parent / "scripts"
if str(_scripts_dir) not in sys.path:
    sys.path.insert(0, str(_scripts_dir))


def _compose():
    """Lazy import: pulls ``generateMultiSignRequestFromCompose`` and its dependency chain."""
    import generateMultiSignRequestFromCompose as m

    return m


try:
    from eth_account.messages import encode_typed_data
except ImportError as e:
    raise SystemExit(
        "eth_account is required. Install with: pip install eth_account "
        "(see docs/skill/SKILL.md Python dependencies)"
    ) from e


_ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")

DEFAULT_KEYGEN_PLACEHOLDER_PURPOSE = "Permit2 PermitSingle (from permit2_keygen_params.py)"
PURPOSE_MAX_LEN = 256


def _addr_short(a: str) -> str:
    s = (a or "").strip()
    if len(s) >= 12 and s.startswith("0x"):
        return f"{s[:6]}...{s[-4:]}"
    return s or "0x?"


def uniswap_quote_object_from_blob(obj: Any) -> dict[str, Any] | None:
    """
    If ``obj`` is a wrapper (e.g. from ``uniswap_trade_quote`` output) or a raw Trade **Get a
    quote** response, return the quote object to store under **extraJSON** as ``uniswapTradeQuote``;
    otherwise return ``None``.
    """
    if not isinstance(obj, dict):
        return None
    uq = obj.get("uniswapTradeQuote")
    if isinstance(uq, dict):
        return uq
    for k in ("tokenIn", "tokenOut", "tokenInChainId", "type", "quote"):
        if k in obj:
            return obj
    return None


def default_multisign_purpose_for_permit2_swap(
    *,
    chain_id: str,
    token: str,
    amount: int,
    spender: str,
    uniswap_context: dict[str, Any] | None = None,
) -> str:
    """
    **purpose** for ``POST /multiSignRequest``: what other nodes see before ``signRequestAgree``.
    Capped at :data:`PURPOSE_MAX_LEN` (256) per API. **AI agent:** the limit is strict; this helper
    truncates with an ellipsis if the generated line would exceed 256.
    """
    c = (chain_id or "").strip()
    s = (
        f"Uniswap: agreement is to authorize Permit2 (EIP-712) so the Universal Router at "
        f"{_addr_short(spender)} can pull amount {amount} of token {_addr_short(token)} on chain "
        f"{c} for the intended trade. Full trade/quote context: extraJSON.uniswapTradeQuote when set."
    )
    if uniswap_context and isinstance(uniswap_context, dict):
        qid = uniswap_context.get("quoteId") or uniswap_context.get("id")
        if isinstance(qid, (str, int)) and str(qid).strip():
            s = f"{s} Quote id: {qid}."
    if len(s) > PURPOSE_MAX_LEN:
        s = s[: PURPOSE_MAX_LEN - 1] + "…"
    return s


def _addr(name: str, a: str) -> str:
    s = (a or "").strip()
    if not _ADDR_RE.match(s):
        raise ValueError(f"{name} must be a 40-hex EVM address with 0x prefix")
    return s


def _u256(name: str, v: int) -> int:
    if v < 0 or v > 2**256 - 1:
        raise ValueError(f"{name} must fit uint256")
    return v


def _u160(name: str, v: int) -> int:
    if v < 0 or v > 2**160 - 1:
        raise ValueError(f"{name} must fit uint160")
    return v


def _u48(name: str, v: int) -> int:
    if v < 0 or v > 2**48 - 1:
        raise ValueError(f"{name} must fit uint48")
    return v


def eip712_permit_single_full_message(
    *,
    chain_id: int,
    permit2: str,
    token: str,
    amount: int,
    expiration: int,
    permit_nonce: int,
    spender: str,
    sig_deadline: int,
    domain_name: str = "Permit2",
) -> dict[str, Any]:
    """
    Full EIP-712 ``full_message`` dict for Permit2 **PermitSingle** (IAllowanceTransfer).

    Matches Uniswap Permit2 ``PermitDetails`` / ``PermitSingle`` structs.
    """
    _u160("amount", amount)
    _u48("expiration", expiration)
    _u48("permit_nonce", permit_nonce)
    _u256("sig_deadline", sig_deadline)
    permit2 = _addr("permit2", permit2)
    token = _addr("token", token)
    spender = _addr("spender", spender)
    dn = (domain_name or "Permit2").strip() or "Permit2"

    return {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "PermitDetails": [
                {"name": "token", "type": "address"},
                {"name": "amount", "type": "uint160"},
                {"name": "expiration", "type": "uint48"},
                {"name": "nonce", "type": "uint48"},
            ],
            "PermitSingle": [
                {"name": "details", "type": "PermitDetails"},
                {"name": "spender", "type": "address"},
                {"name": "sigDeadline", "type": "uint256"},
            ],
        },
        "primaryType": "PermitSingle",
        "domain": {
            "name": dn,
            "chainId": chain_id,
            "verifyingContract": permit2,
        },
        "message": {
            "details": {
                "token": token,
                "amount": amount,
                "expiration": expiration,
                "nonce": permit_nonce,
            },
            "spender": spender,
            "sigDeadline": sig_deadline,
        },
    }


def permit2_eip712_digest_hex(full_message: dict[str, Any]) -> str:
    """32-byte EIP-712 digest as 64 lowercase hex chars (no 0x), suitable for ``msgHash``."""
    signable = encode_typed_data(full_message=full_message)
    return signable.body.hex()


def permit2_approval_only_kwargs(
    *,
    permit2_address: str,
    token: str,
    amount: int,
    expiration: int,
    permit_nonce: int,
    spender: str,
    sig_deadline: int,
    domain_name: str = "Permit2",
    msg_raw_hex: str | None = None,
    destination_address: str | None = None,
    extra_json: str | dict[str, Any] | None = None,
    purpose: str = "",
    uniswap_trade_quote: dict[str, Any] | None = None,
    signature_text: str | dict[str, Any] | None = None,
    send_gas: bool | None = None,
    value_wei: str | None = None,
    tx_params: dict[str, Any] | None = None,
    proposal_tx_params: list[dict[str, Any]] | None = None,
    skip_message_hash_verification: bool | None = None,
    client_id: str | None = None,
    key_list: list[str] | None = None,
) -> dict[str, Any]:
    """
    Keyword arguments for :func:`permit2_approval_multisign_payload` **excluding** MPC connection
    and ``destination_chain_id`` / ``key_gen_id``. Built by ``permit2_keygen_params.py`` from chain + Permit2 data.
    """
    d: dict[str, Any] = {
        "permit2_address": permit2_address,
        "token": token,
        "amount": amount,
        "expiration": expiration,
        "permit_nonce": permit_nonce,
        "spender": spender,
        "sig_deadline": sig_deadline,
        "domain_name": domain_name,
        "purpose": purpose,
    }
    if msg_raw_hex is not None:
        d["msg_raw_hex"] = msg_raw_hex
    if destination_address is not None:
        d["destination_address"] = destination_address
    if extra_json is not None:
        d["extra_json"] = extra_json
    if uniswap_trade_quote is not None:
        d["uniswap_trade_quote"] = uniswap_trade_quote
    if signature_text is not None:
        d["signature_text"] = signature_text
    if send_gas is not None:
        d["send_gas"] = send_gas
    if value_wei is not None:
        d["value_wei"] = value_wei
    if tx_params is not None:
        d["tx_params"] = tx_params
    if proposal_tx_params is not None:
        d["proposal_tx_params"] = proposal_tx_params
    if skip_message_hash_verification is not None:
        d["skip_message_hash_verification"] = skip_message_hash_verification
    if client_id is not None:
        d["client_id"] = client_id
    if key_list is not None:
        d["key_list"] = key_list
    return d


def _merge_extra_json(
    user: str | dict[str, Any] | None,
    permit2_meta: dict[str, Any],
    uniswap_trade_quote: dict[str, Any] | None = None,
) -> str:
    base: dict[str, Any] = {}
    if user is not None:
        if isinstance(user, str):
            u = user.strip()
            if u:
                try:
                    parsed = json.loads(u)
                except json.JSONDecodeError as e:
                    raise ValueError(f"extraJSON must be valid JSON: {e}") from e
                if not isinstance(parsed, dict):
                    raise ValueError("extraJSON string must decode to a JSON object")
                base = parsed
        else:
            base = dict(user)
    existing = base.get("permit2")
    if isinstance(existing, dict):
        merged_p2 = {**existing, **permit2_meta}
    else:
        merged_p2 = permit2_meta
    out: dict[str, Any] = {**base, "permit2": merged_p2}
    if uniswap_trade_quote is not None and isinstance(uniswap_trade_quote, dict) and uniswap_trade_quote:
        out["uniswapTradeQuote"] = uniswap_trade_quote
    return json.dumps(out, separators=(",", ":"), ensure_ascii=False)


def permit2_approval_multisign_payload(
    mpc_auth_url: str,
    management_port: str | int,
    key_gen_id: str,
    destination_chain_id: str,
    permit2_address: str,
    token: str,
    amount: int,
    expiration: int,
    permit_nonce: int,
    spender: str,
    sig_deadline: int,
    *,
    domain_name: str = "Permit2",
    msg_raw_hex: str | None = None,
    destination_address: str | None = None,
    extra_json: str | dict[str, Any] | None = None,
    purpose: str = "",
    uniswap_trade_quote: dict[str, Any] | None = None,
    signature_text: str | dict[str, Any] | None = None,
    send_gas: bool | None = None,
    value_wei: str | None = None,
    tx_params: dict[str, Any] | None = None,
    proposal_tx_params: list[dict[str, Any]] | None = None,
    skip_message_hash_verification: bool | None = None,
    client_id: str | None = None,
    key_list: list[str] | None = None,
) -> dict[str, Any]:
    """
    Build **endpoint** / **bodyForSign** / **messageToSign** for ``POST /multiSignRequest``
    (single message) targeting a Permit2 **PermitSingle** EIP-712 hash.

    Fetches ``keyList`` / ``pubKey`` / optional ``clientId`` from **GET /getKeyGenResultById**
    unless ``key_list`` is provided (use ``[]`` to rely on the node default per API).

    **Permit2 fields** map to the ``PermitSingle`` struct. ``permit_nonce`` is the
    **Permit2 allowance nonce** (uint48), not the EVM transaction nonce.

    **purpose** is truncated to :data:`PURPOSE_MAX_LEN` (**256**). **AI agent:** the management API
    enforces a **maximum length of 256** for the human-readable **purpose** string; longer prose
    must go in **extraJSON**, not in **purpose**.

    **Optional API fields** (``POST /multiSignRequest`` single): pass through the same names
    as the HTTP API: ``msg_raw_hex`` → ``msgRaw``, ``destination_address`` →
    ``destinationAddress``, ``extra_json`` → ``extraJSON``, ``signature_text`` →
    ``signatureText``, ``purpose``, ``uniswap_trade_quote`` (merged into **extraJSON** as
    ``uniswapTradeQuote``), ``send_gas`` → ``sendGas``, ``value_wei`` → ``value``,
    ``tx_params`` → ``txParams``, ``proposal_tx_params`` → ``proposalTxParams``,
    ``skip_message_hash_verification`` → ``skipMessageHashVerification``, ``client_id`` →
    ``clientId``. Do not set both ``tx_params`` and ``proposal_tx_params`` for a single-tx
    request (API: mutually exclusive on the same POST).

    Returns a dict with ``endpoint``, ``bodyForSign``, ``messageToSign``, ``chainId``,
    ``count``, ``eip712`` (full typed-data for audit). Optional ``txParams`` outputs use the
    same compose helpers as other recipes **only** when you passed ``tx_params`` / ``proposal_tx_params``;
    for default Permit2 EIP-712, **do not** send those to ``POST /triggerSignRequestById`` — use
    ``triggerSignRequestByIdOmit`` in the output (omitted ``txParams`` and ``messageHash`` so mpc-auth
    keeps the ``msgHash`` from this ``bodyForSign``). See ``mpc_sign_request_digest.py`` and mpc-auth
    ``TriggerSignRequestById`` comment.
    """
    c = _compose()
    base = c.resolve_mpc_auth_base(mpc_auth_url, management_port)
    chain_num = c.parse_chain_id(destination_chain_id)
    if chain_num < 0 or chain_num > 0xFFFFFFFF:
        raise ValueError("Invalid destination_chain_id")

    full_msg = eip712_permit_single_full_message(
        chain_id=chain_num,
        permit2=permit2_address,
        token=token,
        amount=amount,
        expiration=expiration,
        permit_nonce=permit_nonce,
        spender=spender,
        sig_deadline=sig_deadline,
        domain_name=domain_name,
    )
    digest_hex = permit2_eip712_digest_hex(full_msg)

    kg = c.fetch_keygen_bundle(base, key_gen_id)
    if key_list is None:
        kl = kg.get("keylist") or kg.get("KeyList")
        if not isinstance(kl, list) or not kl:
            raise ValueError("getKeyGenResultById: keylist missing or empty")
        key_list_use = [str(x) for x in kl]
    else:
        key_list_use = list(key_list)

    pub_key = kg.get("pubkeyhex") or kg.get("PubKeyHex") or kg.get("PubKey")
    if not pub_key or not isinstance(pub_key, str):
        raise ValueError("getKeyGenResultById: pubkeyhex missing")
    pub_key = pub_key.strip()

    cid = (client_id or "").strip() or None
    if not cid:
        ck = kg.get("ClientKeys") or kg.get("clientkeys")
        cid = c._first_client_id(ck)

    dest_chain = str(destination_chain_id).strip()

    if tx_params is not None and proposal_tx_params is not None:
        raise ValueError("Set at most one of tx_params and proposal_tx_params")

    permit_meta = {
        "kind": "PermitSingle",
        "domain": full_msg["domain"],
        "message": full_msg["message"],
    }
    uq_in: dict[str, Any] | None = None
    if uniswap_trade_quote is not None and isinstance(uniswap_trade_quote, dict) and uniswap_trade_quote:
        uq_in = uniswap_trade_quote
    extra_merged = _merge_extra_json(extra_json, permit_meta, uq_in)

    body: dict[str, Any] = {
        "keyList": key_list_use,
        "pubKey": pub_key,
        "msgHash": digest_hex,
        "destinationChainID": dest_chain,
        "purpose": (purpose or "")[:PURPOSE_MAX_LEN],
    }

    if msg_raw_hex is not None:
        body["msgRaw"] = msg_raw_hex.strip()
    else:
        # Audit: UTF-8 hex of compact EIP-712 JSON (no 0x prefix; matches compose msgRaw style)
        audit = c.dumps_js(full_msg).encode("utf-8").hex()
        body["msgRaw"] = audit

    if destination_address is not None:
        body["destinationAddress"] = _addr("destination_address", destination_address)

    body["extraJSON"] = extra_merged

    if signature_text is not None:
        if isinstance(signature_text, dict):
            body["signatureText"] = c.dumps_js(signature_text)
        else:
            body["signatureText"] = str(signature_text)

    if cid:
        body["clientId"] = cid

    if send_gas is not None:
        body["sendGas"] = bool(send_gas)
    if value_wei is not None:
        body["value"] = str(value_wei).strip()

    if tx_params is not None:
        body["txParams"] = dict(tx_params)
    if proposal_tx_params is not None:
        body["proposalTxParams"] = list(proposal_tx_params)

    if skip_message_hash_verification is not None:
        body["skipMessageHashVerification"] = bool(skip_message_hash_verification)

    message_to_sign = c.dumps_js(body)

    out: dict[str, Any] = {
        "endpoint": "multiSignRequest",
        "bodyForSign": body,
        "messageToSign": message_to_sign,
        "chainId": dest_chain,
        "count": 1,
        "eip712": full_msg,
        # 32-byte EIP-712 digest (no 0x) — same value as body.msgHash; for audit / scripts only.
        "eip712DigestHex": digest_hex,
        # Trigger: always omit txParams and messageHash for this recipe unless you use real EVM proposal fields.
        "triggerSignRequestByIdOmit": {
            "txParams": True,
            "messageHash": True,
            "reason": "EIP-712 PermitSingle; mpc-auth signs stored MessageHash; MessageRaw is JSON UTF-8 hex, not calldata",
        },
    }
    if body.get("txParams") or body.get("proposalTxParams"):
        out["triggerTxParams"] = c.trigger_tx_params_from_compose_body(body)
        out["triggerSignRequestByIdOmit"] = {
            "txParams": False,
            "messageHash": False,
            "reason": "bodyForSign includes proposal gas fields; merge with getSignRequestById and trigger as other compose flows",
        }
    return out


def main() -> None:
    ap = argparse.ArgumentParser(
        description=(
            "Build multiSignRequest JSON for Permit2 PermitSingle (EIP-712) — "
            "MPC signs msgHash; use signature in Permit2 flows, not as eth_sendRawTransaction alone."
        )
    )
    ap.add_argument(
        "--mpc-auth-url",
        default=(os.environ.get("MPC_AUTH_URL") or "http://127.0.0.1"),
        help="Management API host URL (env MPC_AUTH_URL, default: %(default)s)",
    )
    ap.add_argument(
        "--management-port",
        default=(os.environ.get("MANAGEMENT_PORT") or "8080"),
        help="Management API port (env MANAGEMENT_PORT, default: %(default)s)",
    )
    ap.add_argument("--key-gen-id", required=True, metavar="ID", help="KeyGen id")
    ap.add_argument(
        "--chain-id",
        required=True,
        help="Destination chain id (decimal or 0x hex); also EIP-712 domain.chainId",
    )
    ap.add_argument(
        "--permit2",
        required=True,
        metavar="ADDR",
        help="Permit2 contract (verifyingContract in EIP-712 domain)",
    )
    ap.add_argument("--token", required=True, metavar="ADDR", help="ERC-20 token address")
    ap.add_argument(
        "--amount",
        required=True,
        help="uint160 allowance amount (smallest token units, integer)",
    )
    ap.add_argument(
        "--expiration",
        required=True,
        help="uint48 expiration timestamp (PermitDetails.expiration)",
    )
    ap.add_argument(
        "--permit-nonce",
        required=True,
        help="uint48 Permit2 allowance nonce (PermitDetails.nonce)",
    )
    ap.add_argument("--spender", required=True, metavar="ADDR", help="Spender address")
    ap.add_argument(
        "--sig-deadline",
        required=True,
        help="uint256 sigDeadline (unix time or max uint — must fit uint256)",
    )
    ap.add_argument(
        "--domain-name",
        default="Permit2",
        help='EIP-712 domain.name (default: "Permit2")',
    )
    ap.add_argument(
        "--msg-raw",
        default="",
        metavar="HEX",
        help="Optional msgRaw (hex, no 0x) for API; default: UTF-8 hex of EIP-712 JSON audit blob",
    )
    ap.add_argument(
        "--destination-address",
        default="",
        metavar="ADDR",
        help="Optional destinationAddress on sign request",
    )
    ap.add_argument(
        "--extra-json",
        default="",
        metavar="JSON",
        help='Optional extraJSON string (merged with permit2 audit + optional uniswapTradeQuote)',
    )
    ap.add_argument(
        "--uniswap-quote-file",
        default="",
        metavar="FILE",
        help=(
            "JSON file: output of uniswap_trade_quote (or raw /v1/quote). "
            "Merged into extraJSON as uniswapTradeQuote for peer review."
        ),
    )
    ap.add_argument(
        "--purpose",
        default="",
        help=(
            f"POST body 'purpose' (max {PURPOSE_MAX_LEN} chars, API hard limit). If longer, the "
            "script truncates and warns on stderr. AI agent: keep within "
            f"{PURPOSE_MAX_LEN}; use extraJSON for long quote details. If empty, a default is used "
            "(see docs/references/API_IMPLEMENTATION.md § POST /multiSignRequest)."
        ),
    )
    ap.add_argument(
        "--signature-text",
        default="",
        metavar="STR",
        help='Optional signatureText (JSON string, e.g. {"signature":"Permit2 PermitSingle","names":[]})',
    )
    ap.add_argument(
        "--send-gas",
        action="store_true",
        help="Set sendGas true (multi-agree gas token flows)",
    )
    ap.add_argument(
        "--value",
        default="",
        metavar="WEI",
        help="Optional value (wei string) for send-gas / native value metadata",
    )
    ap.add_argument(
        "--tx-params-json",
        default="",
        metavar="JSON",
        help="Optional txParams object as JSON (single-tx proposal snapshot)",
    )
    ap.add_argument(
        "--proposal-tx-params-json",
        default="",
        metavar="JSON",
        help="Optional proposalTxParams array as JSON (do not combine with --tx-params-json)",
    )
    ap.add_argument(
        "--skip-message-hash-verification",
        action="store_true",
        help="Set skipMessageHashVerification true",
    )
    ap.add_argument(
        "--client-id",
        default="",
        help="Optional clientId (else from KeyGen ClientKeys)",
    )
    ap.add_argument(
        "--key-list-json",
        default="",
        metavar="JSON",
        help='Optional keyList JSON array; default: from getKeyGenResultById; "[]" uses API default',
    )
    ap.add_argument(
        "--ed25519-seed-hex",
        metavar="HEX",
        help="If set, sign messageToSign with Ed25519 and emit postBody",
    )
    ap.add_argument(
        "--eip191-private-key-hex",
        metavar="HEX",
        help="If set, sign with EIP-191 personal_sign and emit postBody",
    )
    args = ap.parse_args()

    def _parse_int(s: str, name: str) -> int:
        t = (s or "").strip()
        if t.startswith("0x") or t.startswith("0X"):
            return int(t, 16)
        return int(t, 10)

    try:
        amt = _parse_int(args.amount, "amount")
        exp = _parse_int(args.expiration, "expiration")
        pn = _parse_int(args.permit_nonce, "permit_nonce")
        sd = _parse_int(args.sig_deadline, "sig_deadline")

        tx_params = None
        if args.tx_params_json.strip():
            tx_params = json.loads(args.tx_params_json)
            if not isinstance(tx_params, dict):
                raise ValueError("--tx-params-json must be a JSON object")
        proposal_tx_params = None
        if args.proposal_tx_params_json.strip():
            proposal_tx_params = json.loads(args.proposal_tx_params_json)
            if not isinstance(proposal_tx_params, list):
                raise ValueError("--proposal-tx-params-json must be a JSON array")

        key_list = None
        if args.key_list_json.strip():
            kl = json.loads(args.key_list_json)
            if not isinstance(kl, list):
                raise ValueError("--key-list-json must be a JSON array")
            key_list = [str(x) for x in kl]

        extra_json = args.extra_json.strip() or None

        uq_path = (args.uniswap_quote_file or "").strip()
        uniswap_trade_quote: dict[str, Any] | None = None
        if uq_path:
            raw_uq = Path(uq_path).read_text(encoding="utf-8")
            uq_parsed = json.loads(raw_uq)
            uniswap_trade_quote = uniswap_quote_object_from_blob(uq_parsed)
            if uniswap_trade_quote is None:
                raise ValueError(
                    f"{uq_path}: could not find a Trade API quote (expect uniswapTradeQuote or tokenIn/tokenOut fields)"
                )

        purpose_use = (args.purpose or "").strip()
        if not purpose_use:
            purpose_use = default_multisign_purpose_for_permit2_swap(
                chain_id=args.chain_id,
                token=args.token,
                amount=amt,
                spender=args.spender,
                uniswap_context=uniswap_trade_quote,
            )
        if len(purpose_use) > PURPOSE_MAX_LEN:
            print(
                f"AI agent / operator: 'purpose' exceeds API maximum ({PURPOSE_MAX_LEN} characters); "
                f"truncating from {len(purpose_use)} to {PURPOSE_MAX_LEN} for POST /multiSignRequest. "
                "Move details to extraJSON (e.g. uniswapTradeQuote) or --extra-json.",
                file=sys.stderr,
            )
            purpose_use = purpose_use[:PURPOSE_MAX_LEN]

        sig_text: str | dict[str, Any] | None = None
        if args.signature_text.strip():
            raw = args.signature_text.strip()
            try:
                sig_text = json.loads(raw)
                if not isinstance(sig_text, dict):
                    sig_text = raw
            except json.JSONDecodeError:
                sig_text = raw

        out = permit2_approval_multisign_payload(
            mpc_auth_url=args.mpc_auth_url,
            management_port=args.management_port,
            key_gen_id=args.key_gen_id,
            destination_chain_id=args.chain_id,
            permit2_address=args.permit2,
            token=args.token,
            amount=amt,
            expiration=exp,
            permit_nonce=pn,
            spender=args.spender,
            sig_deadline=sd,
            domain_name=args.domain_name,
            msg_raw_hex=(args.msg_raw.strip() or None),
            destination_address=(args.destination_address.strip() or None),
            extra_json=extra_json,
            purpose=purpose_use,
            uniswap_trade_quote=uniswap_trade_quote,
            signature_text=sig_text,
            send_gas=True if args.send_gas else None,
            value_wei=(args.value.strip() or None),
            tx_params=tx_params,
            proposal_tx_params=proposal_tx_params,
            skip_message_hash_verification=True if args.skip_message_hash_verification else None,
            client_id=(args.client_id.strip() or None),
            key_list=key_list,
        )
    except (ValueError, json.JSONDecodeError, RuntimeError) as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)

    if args.ed25519_seed_hex:
        c = _compose()
        sig = c.sign_ed25519(out["messageToSign"], args.ed25519_seed_hex)
        out["postBody"] = {
            **out["bodyForSign"],
            "clientSig": sig,
            "signedMessage": out["messageToSign"],
        }
    elif args.eip191_private_key_hex:
        c = _compose()
        sig = c.sign_eip191(out["messageToSign"], args.eip191_private_key_hex)
        out["postBody"] = {
            **out["bodyForSign"],
            "clientSig": sig,
            "signedMessage": out["messageToSign"],
        }

    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
