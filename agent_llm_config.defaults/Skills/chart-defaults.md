# Chart defaults (indicators & MCP)

Charts: SDK **`prepare_chart_from_rows`** (single OHLCV feed) or **`prepare_chart`** (advanced). Reference: **`chart_docs`**.

**Analysis without a chart:** use skill **`chart-analysis-menu`** and MCP **`chart_analysis_docs`** — call **`analyze_*`** tools, not **`prepare_chart*`**.

**OHLCV source priority:** skill **`chart-ohlcv-sources`** (CoinMarketCap before CoinGecko for generic spot).

## Source selection (generic “chart ETH/BTC”)

| Operator request | Data source | Avoid |
|------------------|-------------|--------|
| “Chart ETH 4h”, “BTC chart”, spot price (no venue named) | **CoinMarketCap** — **`coinmarketcap-public`** (`get_crypto_ohlcv_historical` with Pro key, or **`get_kline_candles`** DEX proxy); then **`coingecko-pro`** / **`coingecko`** only if CMC fails | **`load_defi_protocol`**, **`ctm_hyperliquid_fetch_ohlcv`**, other **`ctm_*_fetch_ohlcv`** |
| Names **Hyperliquid**, **perp**, **GMX**, a **DEX** / **Uniswap** pool, or on-chain venue | That venue’s **`fetch_ohlcv`**, or **`coinmarketcap-public__get_kline_candles`** for pool address | CMC CEX aggregate / CoinGecko for pool candles |

Hyperliquid OHLCV is **perpetual** market data, not generic spot USD index. Do not use it for undifferentiated “chart ETH”.

## Workflow

1. **Load** **`coinmarketcap-public`** via **`agent_load_mcp_server`** when using CMC (not `initialLoad`). Then **fetch OHLCV** per **`chart-ohlcv-sources`**. CMC CEX/DEX paths include **volume** when present.
2. **Same turn** — **`continuum__prepare_chart_from_rows`** with **`rows`** or **`toolResult`**. Do not start another LLM turn with 400+ bars only in chat history.

Never `{}`. **Do not describe the chart in markdown** — the UI only renders when the chart tool returns `continuum/chart/v1` (visible under **MCP result**, not the assistant bubble). Prose like “chart prepared” without a successful chart tool call means **nothing was rendered**.

### `prepare_chart_from_rows`

```json
{
  "title": "ETH/USD 4H — last 90d",
  "label": "ETH/USD",
  "toolResult": { "result": [ "... bars from fetch ..." ] }
}
```

CoinMarketCap DEX klines:

```json
{
  "title": "ETH/USDC Uniswap v3 — 4H",
  "toolResult": {
    "platform": "ethereum",
    "address": "0x88e6a0c2ddd26feeb64f039a2c41296fcb3f5640",
    "interval": "4h",
    "candles": [ "... from get_kline_candles ..." ]
  }
}
```

Hyperliquid / DeFi fetch shape is also accepted:

```json
{
  "title": "ETH-PERP 4H",
  "toolResult": { "ohlcv": { "candles": [ "... from ctm_hyperliquid_fetch_ohlcv ..." ] } }
}
```

GMX returns a flat shape (not nested under `ohlcv`):

```json
{
  "title": "ETH/USD 1H",
  "toolResult": { "symbol": "ETH/USD [WETH-USDC]", "timeframe": "1h", "candles": [ "... from ctm_gmx_fetch_ohlcv ..." ] }
}
```

Or pass **`rows`** directly. Default **`maxPoints`: 400** (newest bars kept).

### Advanced: `prepare_chart`

Multi-series or custom **`overlays`**. Shorthand: **`bars`**, **`toolResult`**, **`candles`**.

## Built-in defaults (no custom `overlays`)

| Element | Default |
|---------|---------|
| Main overlay | **EMA(50)** |
| Oscillator | **RSI(14)** |
| Volume | Separate pane below price when rows include **`volume`** (CMC, DeFi/Hyperliquid). **CoinGecko fallback:** no volume — pane omitted |

**CoinGecko** is **fallback only** — use **`coins.ohlc.get`** only (see **`chart-periods`**); no `marketChart`.

**“1 hour” on spot:** prefer CMC **`get_crypto_ohlcv_historical`** with `timePeriod: "hourly"` when Pro key is on continuum-mcp. DEX proxy: **`get_kline_candles`** with `interval: "1h"`. CoinGecko public: **4H** auto — title **4H**, explain limits.

**EMA(50) needs ≥50 bars** in the fetch (after any trim). Shorter lookback still charts candles + RSI(14) but **no EMA line** — extend lookback per **`chart-periods`**.

**`options.skipDefaultOverlays`: true** — candles + volume only.

## Customization

Operator overrides (preferred spot source, EMA period, etc.) go here when set on this node.
