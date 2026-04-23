#!/usr/bin/env python3
"""
Reserved hook for **non–unsigned-tx** trigger rules (typed-data digests, SSH, etc.).

The automation stack in this repo standardizes on **EVM unsigned-transaction** sign
requests (calldata + ``txParams`` / ``messageHash`` at trigger). Digest-only detection
is **disabled** so agents and ``executeSignResult.py`` always follow the broadcastable
EVM path documented in **API_IMPLEMENTATION.md**.

If a future sign-request kind needs trigger bodies **without** ``txParams``, extend
:func:`is_digest_only_trigger_sign_request` and keep **AI_AGENT_*** docs aligned.
"""

from __future__ import annotations

from typing import Any


def is_digest_only_trigger_sign_request(_sr: dict[str, Any]) -> bool:
    """
    When ``True``, ``POST /triggerSignRequestById`` should omit ``txParams`` /
    ``messageHash`` (worker signs the stored proposal ``MessageHash`` only).

    Currently always ``False``: all supported automation flows use standard EVM trigger
    fields.
    """
    return False
