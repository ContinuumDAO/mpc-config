# OHLCV source priority

Pair with **`chart-defaults`**, **`chart-periods`**, **`chart-analysis-menu`**. Reference: **`chart_docs`**, **`coinmarketcap_public_docs`**.

## Load MCP servers before fetch

**`coinmarketcap-public`** is **not** `initialLoad` — load it when you need OHLCV or other CMC data:

```json
{ "serverId": "coinmarketcap-public" }
```

Call **`continuum__agent_load_mcp_server`** (same turn, **before** CMC tool calls). Prefixed tools appear immediately (`coinmarketcap-public__get_kline_candles`, etc.).

Similarly load **`coingecko`** / **`coingecko-pro`** only when falling back to CoinGecko. Load **`coinmarketcap`** (catalog) for TA/news, not as the default OHLCV path.

## Rule 1 — Named venue wins

When the operator names a **venue**, **perp**, **DEX pool**, or **on-chain market**, use that source — not generic spot defaults.

| Operator says | Source | Tool |
|---------------|--------|------|
| Hyperliquid, perp, HL | DeFi **`hyperliquid`** | `ctm_hyperliquid_fetch_ohlcv` |
| GMX | DeFi **`gmx`** | `ctm_gmx_fetch_ohlcv` |
| Uniswap pool, DEX pair, on-chain | **`coinmarketcap-public`** (load first) | `get_kline_candles` (pool address) |
| Other loaded DeFi protocol | That protocol | `fetch_ohlcv` when available |

Do **not** use CoinGecko or CMC CEX aggregate for venue-specific requests.

## Rule 2 — Generic spot (no venue named)

Try sources **in order** until one succeeds. Stop at the first fetch that returns chartable OHLC bars.

| Priority | Server | When to use | CEX aggregate OHLCV | Volume |
|----------|--------|-------------|---------------------|--------|
| **1** | **`coinmarketcap-public`** | Load via **`agent_load_mcp_server`** | **`get_crypto_ohlcv_historical`** when **`COINMARKETCAP_API_KEY`** is on **continuum-mcp** | Yes |
| **2** | **`coinmarketcap-public`** | Same session after load | **`get_kline_candles`** — major DEX pool proxy (see below) | Yes |
| **3** | **`coinmarketcap`** (catalog) | Activated + API key; load if needed | Session tools only if an OHLCV/historical tool exists; else skip | Varies |
| **4** | **`coingecko-pro`** | Load + **`COINGECKO_API_KEY`** | `coins.ohlc.get` with `interval` | No |
| **5** | **`coingecko`** | Fallback; load if needed | `coins.ohlc.get` (auto granularity) | No |

**Default:** CoinMarketCap (**`coinmarketcap-public`**) before CoinGecko — **load CMC first**, then fetch. Use CoinGecko only when CMC paths fail (missing key, rate limit, unknown asset, empty response).

### CMC CEX aggregate — `get_crypto_ohlcv_historical`

Builtin on **`coinmarketcap-public`**. Requires **`COINMARKETCAP_API_KEY`** on the **continuum-mcp** container (same key as catalog **`coinmarketcap`** is fine — add it to continuum-mcp env on the node).

Known CMC ids: **1** = BTC, **1027** = ETH, **5426** = SOL. Resolve others via **`get_crypto_quotes_latest`** / map or catalog **`coinmarketcap__search_cryptos`**.

```json
{
  "id": "1027",
  "convert": "USD",
  "timePeriod": "hourly",
  "count": 400,
  "interval": "hourly"
}
```

Return shape includes **`result`** (CMC `quotes[]`) — pass full JSON to **`prepare_chart_from_rows`** or **`analyze_*`** as **`toolResult`**. SDK normalizes `{ time_open, quote: { USD: { open, high, low, close, volume } } }`.

**Intervals:** `timePeriod` / `interval` — `hourly`, `daily`, `weekly`, `monthly`. For **4H** when hourly is too dense, fetch hourly and trim to ~400 newest bars, or use **`daily`** for long windows (title must match).

### CMC DEX pool proxy (keyless)

When Pro OHLCV is unavailable, use **`get_kline_candles`** on a liquid Uniswap v3 pool (still CoinMarketCap data, includes **volume**):

1. **`get_dex_token_pools`** — `platform: "ethereum"`, token contract (WETH `0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2` for ETH spot proxy).
2. Pick highest-liquidity USDC (or USD stable) pool → **`addr`**.
3. **`get_kline_candles`** — `interval`: `1h`, `4h`, or `1d`; `limit` ≤ 400.

Well-known ETH/USDC pool (Uniswap v3 0.05%): `0x88e6a0c2ddd26feeb64f039a2c41296fcb3f5640`.

Title honestly: **`ETH/USDC Uniswap v3 — 4H`** (DEX spot proxy, not CEX index).

### Catalog **`coinmarketcap`** (external MCP)

Use for TA, news, narratives, quotes — not the default OHLCV path unless the session exposes an OHLCV/historical tool. Official CMC MCP may not include CEX candle tools; prefer builtin **`get_crypto_ohlcv_historical`** or DEX klines above.

## Rule 3 — Same turn as chart / analysis

After fetch, **same agent turn**: **`continuum__prepare_chart_from_rows`** and/or **`analyze_*`**. Never `{}`.

## Live chart ticks

| Source | Live binding |
|--------|----------------|
| CoinGecko | Return **`coinId`** + **`bucketSec`** on execute output |
| CMC CEX / DEX klines | Static unless a live adapter exists — do not invent `coinId` |
| Hyperliquid / DeFi | Full fetch JSON; node may bind perp live |

## Adding future sources

Insert new rows **above CoinGecko fallbacks**, below named-venue rules. Document: server id, tool name, when to use, bar shape, volume, live fields. Update **`chart-periods`** sizing examples when the new source has different interval limits.
