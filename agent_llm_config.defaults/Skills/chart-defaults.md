# Chart defaults (indicators & MCP)

Charts: SDK **`prepare_chart_from_rows`** (single OHLCV feed) or **`prepare_chart`** (advanced). Reference: **`chart_docs`**.

**Analysis without a chart:** use skill **`chart-analysis-menu`** and MCP **`chart_analysis_docs`** — call **`analyze_*`** tools, not **`prepare_chart*`**.

## Source selection (generic “chart ETH/BTC”)

| Operator request | Data source | Avoid |
|------------------|-------------|--------|
| “Chart ETH 4h”, “BTC chart”, spot price (no venue named) | **Spot** — **`coingecko`** (or **`coingecko-pro`** if API key configured; see **`chart-periods`**) | **`load_defi_protocol`**, **`ctm_hyperliquid_fetch_ohlcv`**, other **`ctm_*_fetch_ohlcv`** |
| Names **Hyperliquid**, **perp**, **GMX**, a DEX, or on-chain venue | That protocol’s **`fetch_ohlcv`** (after **`load_defi_protocol`** if needed) | CoinGecko spot |

Hyperliquid OHLCV is **perpetual** market data, not generic spot USD index. Do not use it for undifferentiated “chart ETH”.

## Workflow

1. **Fetch OHLC** (source from table above). CoinGecko spot → **`coins.ohlc.get`** only (see **`chart-periods`**); no volume pane on spot charts.
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
| Volume | Separate pane below price when rows include **`volume`** (DeFi/Hyperliquid). **CoinGecko spot:** no volume — pane omitted |

CoinGecko spot charts use **`coins.ohlc.get`** only — real OHLC candles, no `marketChart` (see **`chart-periods`**).

**“1 hour” on public CoinGecko:** use **4H** candles (auto granularity), title **4H**, and tell the operator hourly spot needs Pro or DeFi. **Pro** (`coingecko-pro`): may use **`interval: 'hourly'`** for 1–90 day windows.

**EMA(50) needs ≥50 bars** in the fetch (after any trim). Shorter lookback still charts candles + RSI(14) but **no EMA line** — extend lookback per **`chart-periods`** (e.g. Hyperliquid **`lookbackDays` ≥ 14** for 4h, **`limit` ≥ 200** on GMX).

**`options.skipDefaultOverlays`: true** — candles + volume only.

## Customization

Operator overrides (preferred spot source, EMA period, etc.) go here when set on this node.
