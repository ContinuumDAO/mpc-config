# OHLCV source priority

Pair with **`chart-defaults`**, **`chart-periods`**, **`chart-analysis-menu`**. Reference: **`chart_docs`**, **`coinmarketcap_public_docs`**.

Continuum does **not** endorse third-party data providers. Pick sources from **operator intent** and **what is loaded in this chat** — not brand preference.

## Load MCP servers before fetch

Most third-party servers have **`initialLoad: false`**. Call **`continuum__agent_load_mcp_server`** same turn, before fetch:

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

If **`agent_load_mcp_server({ serverId: "coinmarketcap" })`** returns *set environment variable COINMARKETCAP_API_KEY* → **load failed**. Do **not** tell the operator CMC is loaded. Load **`coinmarketcap-public`** instead, or use **`coingecko`** if already loaded.

If **`coinmarketcap-public`** is **missing** from **`activeServers`** → use **`coingecko`** / **`coingecko-pro`** when loaded; tell the operator to **Add from repository** once or check **`MCP_default_servers.json`** seed on new nodes.

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

**If no other OHLCV source is loaded in this session** → load and use **`coinmarketcap-public`**:

```json
{ "serverId": "coinmarketcap-public" }
```

Catalog MCP server on continuum-mcp **`/mcp/cmc-public`**, usually already in **`activeServers`**; **`initialLoad: false`**. Load per chat via skills / **`agent_load_mcp_server`**. Tools are **`coinmarketcap-public__*`**, not **`continuum__*`**.

- **Keyless** (no API key): **`get_kline_candles`** (DEX pool OHLCV + volume), quotes, global metrics, Fear & Greed, etc.
- **Optional Pro** on continuum-mcp: **`get_crypto_ohlcv_historical`** (CEX aggregate candles + volume)
- **`coinmarketcap-public`** ≠ catalog **`coinmarketcap`**. Missing **`COINMARKETCAP_API_KEY`** on catalog **`coinmarketcap`** does **not** block keyless **`coinmarketcap-public`**. Do not ask for a key or switch to CoinGecko for that reason alone.

Prefer keyless **`get_kline_candles`** when Pro key is unset. See **`coinmarketcap_public_docs`** after load.

| When | Fetch |
|------|-------|
| **`coingecko`** / **`coingecko-pro`** loaded | **`coingecko__execute`** → **`coins.ohlc.get`** — see **`chart-periods`** |
| Nothing else loaded | **`coinmarketcap-public__get_kline_candles`** (or **`get_crypto_ohlcv_historical`** if Pro key on continuum-mcp) |

If fetch fails (429, empty), try the next applicable source only then.

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

Order: **(1) load MCP server if needed → (2) fetch → (3a) analyze_* OR (3b) prepare_chart_from_rows** — never both unless the operator asked for analysis **and** a chart.

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

Add a row to Rule 2’s loaded-server list (before the **`coinmarketcap-public`** fallback). Document tool, bar shape, volume, keys in this file and **`chart-periods`**.
