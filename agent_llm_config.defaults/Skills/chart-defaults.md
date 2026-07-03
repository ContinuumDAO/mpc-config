# Chart defaults (indicators & MCP)

Charts: SDK **`prepare_chart_from_rows`** (single OHLCV feed) or **`prepare_chart`** (advanced). Reference: **`chart_docs`**.

## Source selection (generic “chart ETH/BTC”)

| Operator request | Data source | Avoid |
|------------------|-------------|--------|
| “Chart ETH 4h”, “BTC chart”, spot price (no venue named) | **Spot** — load **`coingecko`**, fetch via **`coingecko__execute`** (see **`chart-periods`**) | **`load_defi_protocol`**, **`ctm_hyperliquid_fetch_ohlcv`**, other **`ctm_*_fetch_ohlcv`** |
| Names **Hyperliquid**, **perp**, **GMX**, a DEX, or on-chain venue | That protocol’s **`fetch_ohlcv`** (after **`load_defi_protocol`** if needed) | CoinGecko spot |

Hyperliquid OHLCV is **perpetual** market data, not generic spot USD index. Do not use it for undifferentiated “chart ETH”.

## Workflow

1. **Fetch OHLCV** (source from table above).
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
| Volume | Separate pane below price when each row has **`volume`** |

Spot **`coins.ohlc.get`** has **no volume** — use **`coins.marketChart.get`** + **`total_volumes`** (see **`chart-periods`**) or the volume pane is omitted.

**`options.skipDefaultOverlays`: true** — candles + volume only.

## Customization

Operator overrides (preferred spot source, EMA period, etc.) go here when set on this node.
