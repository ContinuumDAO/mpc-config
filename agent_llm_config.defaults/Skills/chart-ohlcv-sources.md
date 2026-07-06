# OHLCV source priority

Pair with **`chart-defaults`**, **`chart-periods`**, **`chart-analysis-menu`**. Reference: **`chart_docs`**, **`coinmarketcap_public_docs`**.

Continuum does **not** endorse third-party data providers. Pick sources from **operator intent** and **what is loaded in this chat** — not brand preference.

## Never auto-load data sources

**Do not** call **`agent_load_mcp_server`** for CoinMarketCap, CoinGecko, or any other market-data MCP unless the **operator explicitly chooses** that provider (by name, or by picking from options you offer).

If no OHLCV source is loaded and no fetch has run in this chat:

1. **Stop** — do not chart, analyze, or load catalog servers on your own.
2. **Ask the operator** which source to use (CoinGecko, CoinMarketCap public, Hyperliquid, GMX, another catalog MCP, etc.).
3. After they choose → **`agent_load_mcp_server`** → fetch OHLCV → pass full fetch JSON as **`toolResult`**.

Chart/analysis tools return a clear error when called without data; treat that as “ask the operator first”.

## Load MCP servers before fetch (after operator choice)

Most third-party servers have **`initialLoad: false`**. Call **`continuum__agent_load_mcp_server`** same turn, **before** fetch, only after the operator picks the provider:

```json
{ "serverId": "<id>" }
```

Use **`list_mcp_servers`** → **`activeServers`** before loading. Match **`serverId`** exactly (see below).

## Critical: two different CoinMarketCap server ids

| `serverId` | On node | API key | Use for OHLCV charts |
|------------|---------|---------|---------------------|
| **`coinmarketcap-public`** | Active on node (seed / add from catalog) | **Not** for keyless tools | **Yes** — `get_kline_candles`, etc. |
| **`coinmarketcap`** | Catalog (user-activated) | **`COINMARKETCAP_API_KEY`** required | Only if key configured; not a substitute for **`coinmarketcap-public`** |

When the operator says **“load CoinMarketCap”** or **“use CMC”** → load **`coinmarketcap-public`**, **not** **`coinmarketcap`**, unless they explicitly need catalog full MCP **and** the key is configured.

If **`agent_load_mcp_server({ serverId: "coinmarketcap" })`** returns *set environment variable COINMARKETCAP_API_KEY* → **load failed**. Do **not** tell the operator CMC is loaded. Offer **`coinmarketcap-public`** or **`coingecko`** as alternatives and let them choose.

If a chosen server is **missing** from **`activeServers`** → tell the operator to **Add from repository** once or check **`MCP_default_servers.json`** seed on new nodes.

## Rule 1 — Named venue or provider wins

| Operator says | Source |
|---------------|--------|
| Hyperliquid, perp, HL | **`hyperliquid`** → `ctm_hyperliquid_fetch_ohlcv` |
| GMX | **`gmx`** → `ctm_gmx_fetch_ohlcv` |
| CoinMarketCap / CMC | **`coinmarketcap-public`** only (unless catalog **`coinmarketcap`** + key already working) |
| CoinGecko | **`coingecko`** / **`coingecko-pro`** |
| DEX pool, Uniswap, on-chain venue | That protocol’s **`fetch_ohlcv`** or operator-chosen kline tool |

## Rule 2 — Generic spot (no venue or provider named)

Use the **first loaded OHLCV-capable MCP server** in this chat, in order:

1. **`coingecko-pro`** (if loaded and key configured)
2. **`coingecko`** (if loaded)
3. Any other **loaded** server that exposes spot OHLCV (future catalog sources)

**If no OHLCV source is loaded in this session** → **ask the operator** which provider to use. Offer concise options (e.g. CoinGecko, CoinMarketCap public, Hyperliquid). **Do not** silently load **`coinmarketcap-public`** or **`coingecko`**.

After the operator chooses and you load the server:

- **`coinmarketcap-public`**: keyless **`get_kline_candles`**, optional Pro **`get_crypto_ohlcv_historical`** when **`COINMARKETCAP_API_KEY`** is in Variables
- **`coingecko`** / **`coingecko-pro`**: **`coingecko__execute`** → **`coins.ohlc.get`** or market chart — see **`chart-periods`**

| When | Fetch |
|------|-------|
| **`coingecko`** / **`coingecko-pro`** loaded (operator chose) | **`coingecko__execute`** — see **`chart-periods`** |
| Operator chose CMC | **`coinmarketcap-public__get_kline_candles`** (or **`get_crypto_ohlcv_historical`** if Pro key on continuum-mcp) |

If fetch fails (429, empty, stale), report to the operator and offer **other sources** — do not auto-switch without their choice.

## Rule 3 — Fetch before analyze or chart (mandatory)

Fetch OHLCV first. Then branch on operator intent:

| Intent | After fetch |
|--------|-------------|
| **Analyze / interpret** (no chart requested) | **`analyze_*`** with full fetch as **`toolResult`**. **Do not** call **`prepare_chart_from_rows`**. |
| **Chart / plot / draw** | **`prepare_chart_from_rows`** with full fetch as **`toolResult`**. |

**Never** call **`prepare_chart_from_rows`** with only **`title`** / **`label`**. **Never** rewrite candle timestamps — pass fetch JSON verbatim (Hyperliquid uses **`timestampMs`**; do not add or replace with a generic **`time`** field).

Plot example:

```json
{
  "title": "ETH/USD 4H — last 7d",
  "label": "ETH/USD",
  "toolResult": { "... full output from fetch ..." }
}
```

Analysis example:

```json
{
  "title": "ETH/USD 4H — last 7d",
  "toolResult": { "... same full fetch output ..." }
}
```

→ pass to **`continuum__analyze_momentum`** (or other **`analyze_*`**), not **`prepare_chart_from_rows`**.

Order: **(1) operator chooses source → load MCP server if needed → (2) fetch → (3a) analyze_* OR (3b) prepare_chart_from_rows** — never both unless the operator asked for analysis **and** a chart.

## Rule 4 — Orchestration task split

- **Analysis sub-agent:** step 3a only; **`mpc-task-result`** body = analysis JSON; **no** chart attachment.
- **Plot sub-agent:** step 3b (optional drawings); attach chart via **`post_key_gen_chart_attachment`**.

Keeps KeyGen context lean — analysis prose in one task, chart JSON in another.

## Live chart ticks

| Source | Live binding |
|--------|----------------|
| CoinGecko | **`coinId`** + **`bucketSec`** on execute output |
| Other third-party klines | Static unless a live adapter exists |
| Hyperliquid / DeFi | Full fetch JSON; node may bind perp live |

## Adding future sources

Add a row to Rule 2’s loaded-server list. Document tool, bar shape, volume, keys in this file and **`chart-periods`**.
