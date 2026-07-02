# Chart defaults (indicators & MCP)

Generic spot charts: **CoinGecko** → **`prepare_chart`**. Tool reference: **`chart_docs`** and **`prepare_chart`**.

## Workflow

1. **`agent_load_mcp_server`** — `{ "serverId": "coingecko" }` if `coingecko__*` tools are missing.
2. **`coingecko__execute`** — fetch bars (`async function run(client) { ... }` — see **`chart-periods`**).
3. **`continuum__prepare_chart`** — **same turn**, pass the **`result`** array from step 2 (see below).

For generic “chart BTC/ETH”, use CoinGecko — not **`ctm_*_fetch_ohlcv`** / DeFi tools (unless the operator names that protocol).

## `prepare_chart` — required (never `{}`)

The UI does **not** link execute → chart automatically. You **must** include bar data **in the tool call**.

**Preferred shorthand** — copy the **`result`** array from **`coingecko__execute`**:

```json
{
  "title": "ETH/USD 4H — last 90d",
  "label": "ETH/USD",
  "bars": [
    { "time": 1777262400, "open": 2393.67, "high": 2394.99, "low": 2321.74, "close": 2321.74, "volume": 53251163525 }
  ],
  "options": { "maxPoints": 400 }
}
```

Also accepted: **`result`** or **`candles`** instead of **`bars`**; or full **`series`** form (see **`chart-periods`**).

| Call | Result |
|------|--------|
| `prepare_chart({})` | **Fails** — no data |
| Fetch only, no chart call | **No chart in UI** |
| `prepare_chart({ title, bars: <result array> })` | **Correct** |

## Built-in defaults (candlestick, no `overlays`)

| Element | Default |
|---------|---------|
| Main overlay | **EMA(50)** |
| Oscillator | **RSI(14)** |
| Volume | Histogram when `volume` on candle rows |

Set **`options.skipDefaultOverlays`: true** for candles (+ volume) only. Pass non-empty **`overlays`** to replace defaults entirely.

## Customization

Edit examples below for this operator (EMA period, MACD, etc.) when they do not specify otherwise.
