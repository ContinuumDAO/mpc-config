# OHLCV source priority

Pair with **`chart-defaults`**, **`chart-periods`**, **`chart-analysis-menu`**. Reference: **`chart_docs`**, **`coinmarketcap_public_docs`**.

Continuum does **not** endorse third-party data providers. Pick sources from **operator intent** and **what is loaded in this chat** — not brand preference.

## Load MCP servers before fetch

Most third-party servers have **`initialLoad: false`**. Call **`continuum__agent_load_mcp_server`** same turn, before fetch:

```json
{ "serverId": "<id>" }
```

Use **`list_mcp_servers`** → **`activeServers`** to see what exists on the node; session tool list shows what is **loaded** now.

## Rule 1 — Named venue or provider wins

| Operator says | Source |
|---------------|--------|
| Hyperliquid, perp, HL | **`hyperliquid`** → `ctm_hyperliquid_fetch_ohlcv` |
| GMX | **`gmx`** → `ctm_gmx_fetch_ohlcv` |
| CoinMarketCap / CMC | **`coinmarketcap-public`** (or catalog **`coinmarketcap`** if they mean full MCP) |
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

This server is **default active** on the node (not repository catalog). **`initialLoad: false`**.

- **Keyless** (no API key): **`get_kline_candles`** (DEX pool OHLCV + volume), quotes, global metrics, Fear & Greed, etc.
- **Optional Pro** on continuum-mcp: **`get_crypto_ohlcv_historical`** (CEX aggregate candles + volume)
- **`coinmarketcap-public`** ≠ catalog **`coinmarketcap`**. Missing **`COINMARKETCAP_API_KEY`** on catalog **`coinmarketcap`** does **not** block keyless **`coinmarketcap-public`**. Do not ask for a key or switch to CoinGecko for that reason alone.

Prefer keyless **`get_kline_candles`** when Pro key is unset. See **`coinmarketcap_public_docs`** after load.

| When | Fetch |
|------|-------|
| **`coingecko`** / **`coingecko-pro`** loaded | **`coins.ohlc.get`** — see **`chart-periods`** |
| Nothing else loaded | **`coinmarketcap-public__get_kline_candles`** (or **`get_crypto_ohlcv_historical`** if Pro key on continuum-mcp) |

If fetch fails (429, empty), try the next applicable source only then.

## Rule 3 — Same turn as chart / analysis

After fetch, **same turn**: **`continuum__prepare_chart_from_rows`** and/or **`analyze_*`**. Never `{}`.

## Live chart ticks

| Source | Live binding |
|--------|----------------|
| CoinGecko | **`coinId`** + **`bucketSec`** on execute output |
| Other third-party klines | Static unless a live adapter exists |
| Hyperliquid / DeFi | Full fetch JSON; node may bind perp live |

## Adding future sources

Add a row to Rule 2’s loaded-server list (before the **`coinmarketcap-public`** fallback). Document tool, bar shape, volume, keys in this file and **`chart-periods`**.
