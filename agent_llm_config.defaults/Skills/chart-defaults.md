# Chart defaults (indicators & MCP)

Charts are built in the SDK via **`prepare_chart_from_rows`** (simple OHLCV feed) or **`prepare_chart`** (multi-series / custom overlays). Reference: **`chart_docs`**.

## Workflow (any data source)

1. **Fetch OHLCV** with the operator’s preferred tool (CoinGecko, Hyperliquid, GMX, Binance, etc.).
2. **`continuum__prepare_chart_from_rows`** — pass the bar array **or** the full fetch JSON as **`toolResult`**.

Do **not** call either chart tool with `{}`.

### Preferred: `prepare_chart_from_rows`

After any successful OHLCV fetch:

```json
{
  "title": "ETH/USD 4H — last 90d",
  "label": "ETH/USD",
  "rows": [
    { "time": 1777262400, "open": 2393.67, "high": 2394.99, "low": 2321.74, "close": 2321.74, "volume": 53251163525 }
  ],
  "options": { "maxPoints": 400 }
}
```

Or pass the entire prior MCP result (any vendor):

```json
{
  "title": "ETH/USD 4H",
  "toolResult": { "result": [ "... same bar objects ..." ] }
}
```

### Advanced: `prepare_chart`

Use for multiple series, custom overlays, or non-OHLCV series. Shorthand: **`bars`**, **`result`**, **`candles`**, or **`toolResult`**.

## Built-in defaults (candlestick, no custom `overlays`)

| Element | Default |
|---------|---------|
| Main overlay | **EMA(50)** |
| Oscillator | **RSI(14)** |
| Volume | Separate pane below price when `volume` on rows |

Set **`options.skipDefaultOverlays`: true** for candles (+ volume) only. Pass non-empty **`overlays`** to replace defaults entirely.

## Customization

Edit examples below for this operator (EMA period, MACD, preferred data source, etc.) when they do not specify otherwise.
