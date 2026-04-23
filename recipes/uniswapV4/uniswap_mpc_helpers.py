#!/usr/bin/env python3
"""
Shared helpers for Uniswap Trade + MPC recipes: Universal Router addresses and KeyGen owner resolution.

Universal Router **2.0** addresses (``x-universal-router-version: 2.0``), aligned with
``CHAIN_CONFIGS`` → ``UniversalRouterVersion.V2_0`` in
https://github.com/Uniswap/sdks/blob/main/sdks/universal-router-sdk/src/utils/constants.ts
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

_scripts_dir = Path(__file__).resolve().parent.parent.parent / "scripts"
if str(_scripts_dir) not in sys.path:
    sys.path.insert(0, str(_scripts_dir))

import generateMultiSignRequestFromCompose as m

_ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")

# Same chain-id → router map as continuumdao-node-app Uniswap V4 router constants.
UNIVERSAL_ROUTER_V2_BY_CHAIN_ID: dict[int, str] = {
    1: "0x66a9893cc07d91d95644aedd05d03f95e1dba8af",
    10: "0x851116d9223fabed8e56c0e6b8ad0c31d98b3507",
    56: "0x1906c1d672b88cd1b9ac7593301ca990f94eae07",
    130: "0xef740bf23acae26f6492b10de645d6b98dc8eaf3",
    137: "0x1095692a6237d83c6a72f3f5efedb9a670c49223",
    143: "0x0d97dc33264bfc1c226207428a79b26757fb9dc3",
    196: "0x5507749f2c558bb3e162c6e90c314c092e7372ff",
    324: "0x28731BCC616B5f51dD52CF2e4dF0E78dD1136C06",
    480: "0x8ac7bee993bb44dab564ea4bc9ea67bf9eb5e743",
    1301: "0xf70536b3bcc1bd1a972dc186a2cf84cc6da6be5d",
    1868: "0x0e2850543f69f678257266e0907ff9a58b3f13de",
    4217: "0x1febb76be10aaf3a1402f04e8e835f2c382f7914",
    42161: "0xa51afafe0263b40edaef0df8781ea9aa03e381a3",
    42220: "0xcb695bc5D3Aa22cAD1E6DF07801b061a05A0233A",
    43114: "0x94b75331ae8d42c1b61065089b7d48fe14aa73b7",
    57073: "0x112908dac86e20e7241b0927479ea3bf935d1fa0",
    59144: "0x661e93cca42afacb172121ef892830ca3b70f08d",
    7777777: "0x3315ef7ca28db74abadc6c44570efdf06b04b020",
    81457: "0xeabbcb3e8e415306207ef514f660a3f820025be3",
    8453: "0x6ff5693b99212da76ad316178a184ab56d299b43",
    5: "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
    420: "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
    421613: "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
    44787: "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
    80001: "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
    84531: "0xd0872d928672ae2ff74bdb2f5130ac12229cafaf",
    84532: "0x492e6456d9528771018deb9e87ef7750ef184104",
    10143: "0x3ae6d8a282d67893e17aa70ebffb33ee5aa65893",
    11155111: "0x3a9d48ab9751398bbfa63ad67599bb04e4bdf98b",
}


def _addr(name: str, a: str) -> str:
    s = (a or "").strip()
    if not _ADDR_RE.match(s):
        raise ValueError(f"{name} must be a 40-hex EVM address with 0x prefix")
    return s


def resolve_owner_from_keygen(
    *,
    mpc_auth_url: str,
    management_port: str | int,
    key_gen_id: str,
    owner_checksum: str,
) -> tuple[str, str]:
    """
    **GET /getKeyGenResultById** → ``ethereumaddress`` for ``key_gen_id``.

    If ``owner_checksum`` is non-empty, it must match that address (case-insensitive).
    """
    kgid = (key_gen_id or "").strip()
    if not kgid:
        raise ValueError("KEYGEN_ID is required (env KEYGEN_ID or --key-gen-id).")
    mpc = (mpc_auth_url or "").strip()
    if not mpc:
        raise ValueError("MPC management URL is required (--mpc-auth-url or MPC_AUTH_URL).")
    base = m.resolve_mpc_auth_base(mpc, management_port)
    kg = m.fetch_keygen_bundle(base, kgid)
    eth = kg.get("ethereumaddress") or kg.get("EthereumAddress")
    if not eth or not isinstance(eth, str):
        raise ValueError("getKeyGenResultById: ethereumaddress missing for this KeyGen")
    derived = _addr("ethereumaddress from KeyGen", eth.strip())
    ovr = (owner_checksum or "").strip()
    if ovr and ovr.lower() != derived.lower():
        raise ValueError(
            f"--owner {ovr} does not match KeyGen ethereum address {derived}; remove --owner or fix KeyGen"
        )
    return derived, kgid
