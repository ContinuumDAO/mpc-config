---
name: continuum-dao-tokenomics
description: Live CTM circulating/escrowed/total supply, protocol addresses, and veCTM locks via catalog MCP continuumdao-tokenomics. Do not answer those figures from the White Paper. Do not auto-load etherscan.
---

# ContinuumDAO tokenomics (live)

Load when the operator asks for **live** CTM supply, circulating/escrowed amounts, protocol or veCTM contract addresses, voting power, unlock time, last vote, or locked CTM for holder addresses. White Paper / `search_continuum_docs` is **narrative only** (allocation story, “all locked” wording) — not the live figure.

## Load the catalog MCP

Tools are **`continuumdao-tokenomics__*`**, not `continuum__*`.

1. `continuum__list_mcp_servers` (`scope: active`). If **`continuumdao-tokenomics`** is missing, `scope: catalog` then **`add_mcp_server_from_catalog({ id: "continuumdao-tokenomics" })`** (operator management-signs).
2. **`agent_load_mcp_server({ serverId: "continuumdao-tokenomics" })`**.
3. Call the read tools in the same turn after load.

No API key. **`initialLoad` is false** — do not expect the tools at chat start.

## Which tool

| Ask | Tool |
|-----|------|
| Circulating / escrowed / total supply | `get_ctm_metrics` (or `get_ctm_tokenomics_snapshot`) |
| Contract / treasury / veCTM / NodeProperties addresses | `get_ctm_protocol_addresses` |
| One wallet: voting power, unlock, last vote, locked CTM | `get_ve_ctm_position` |
| Holder list locked CTM | `get_ve_ctm_locked_for_addresses` (after they have addresses; do not scrape etherscan yourself) |

`circulatingSupply` is **unlocked-outside-treasury** from app-api (`globalSupply − CTM at veCTM − CTM at Linea treasury`). That is not the White Paper “all circulating CTM is locked” sentence.

## Etherscan (ask first)

Every tool may include **`onChainFollowUp`**. If official **`etherscan`** is not loaded, tell the operator those extra tools exist after they add/load it (`ETHERSCAN_API_KEY`). **Do not auto-load etherscan.** Not an OHLCV source.
