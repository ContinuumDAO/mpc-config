# Continuum MCP deferred tool bundles

The **continuum** MCP server exposes a **small pinned tool set** at session init (~17 tools). Full operator workflows live in **bundles** activated on demand.

## Do not dump tool catalogs

- Do **not** list or memorize every MCP tool name in reasoning or replies.
- Do **not** assume a tool exists until you search or activate its bundle.
- Prefer **`search_continuum_tools`** with a keyword (e.g. `multisign`, `chart`, `group`, `configured node keys`).

## Discovery workflow

1. **`list_tool_groups`** — see bundle ids; **`recommended: true`** marks easy chat entry points (e.g. **`chart`**).
2. **`search_continuum_tools`** — find tools by name or tag before activating a whole bundle.
3. **`activate_tool_group`** — load schemas for that bundle (`tools/list` grows; hub refreshes automatically).
4. **`deactivate_tool_group`** — shrink the list when done with a workflow.

## Charts (not loaded at init — activate when needed)

Chart tools are **not** pinned at session start. When the operator asks for charts, OHLCV, analysis, or plotting:

1. **`search_continuum_tools`** with `q: "chart"` (or `ohlcv`, `plot`, `analysis`), **or**
2. **`list_tool_groups`** and pick the bundle with **`groupId: "chart"`** and **`recommended: true`**, then
3. **`activate_tool_group`** with `{ "groupId": "chart" }` before **`prepare_chart`**, **`analyze_*`**, etc.

Load skill **`chart-defaults`** (via **`agent_load_skill`**) after activating the chart bundle for OHLCV source guidance. **Never auto-load** market-data MCP servers — if no OHLCV source is loaded, ask the operator to choose one (skill **`chart-ohlcv-sources`**).

## CoinMarketCap / optional catalog servers (not core)

**`coinmarketcap-public`** and similar catalog MCP servers are **optional** — not part of continuum core bundles. Load via **`agent_load_mcp_server`** only when the **operator chooses** that provider — not as a silent fallback for generic chart requests.

## DeFi

Use **`load_defi_protocol`** (alias for activating `defi:<protocolId>`) before protocol `ctm_*` tools. **`unload_defi_protocol`** when finished.

## Pinned at init (typical)

Discovery tools, node health/version, preferred management signer reads, DeFi discovery gate — enough to orient and activate the right bundle for the operator’s task.

## Long threads

Unrelated tasks inflate context. Start a **fresh conversation** when switching domains (e.g. chart analysis → multisign execution).
