# Chart defaults (indicators & MCP)

Load this skill when the operator asks for a **chart, graph, or plot**. Pair with **`chart-periods`** for time-range rules. Tool reference: continuum MCP **`chart_docs`** (`chart.md`) and **`prepare_chart`**.

## Agent workflow

1. **`agent_load_skill`** — load **`chart-periods`** if you need lookback / bar-budget rules.
2. **`agent_load_mcp_server`** — for **generic spot charts**, load **`coingecko`** when `coingecko__*` tools are not in the session. **Do not** load Hyperliquid/GMX/DeFi for a plain “chart BTC” request.
3. **`agent_load_mcp_server`** — load **`technical-indicators`** only if **`technical-indicators__list_technical_indicators`** is missing **and** you need standalone indicator math outside **`prepare_chart`** (default EMA/RSI on charts do **not** require it).
4. Fetch OHLCV from **CoinGecko** (default) or another source only if the operator specified it (include **volume** on candle rows when available).
5. Call **`prepare_chart`** with candlestick **`series`** as a **native array** — defaults apply automatically (see below).

### `prepare_chart` arguments (required shape)

```json
{
  "title": "BTC/USD 4H — last 90d",
  "options": { "maxPoints": 400 },
  "series": [
    {
      "id": "btc",
      "type": "candlestick",
      "label": "BTC/USD",
      "data": [
        { "time": 1717200000, "open": 67000, "high": 67500, "low": 66800, "close": 67200, "volume": 1234 }
      ]
    }
  ]
}
```

**Wrong:** `"series": "[{\"id\":\"btc\",...}]"` (string) — validation fails. **Right:** `series` is a JSON **array** object in the tool call.

## Built-in defaults (`prepare_chart`, candlestick, no `overlays`)

| Element | Default |
|---------|---------|
| Main overlay | **EMA(50)** on the price pane |
| Oscillator pane | **RSI(14)** below price |
| Volume | **Histogram** on the left when `volume` is present on candle rows or a volume series is supplied |

Title should still reflect the window (see **`chart-periods`**), e.g. `BTC/USD 4H — last 90d`.

## Operator overrides (edit this skill or pass tool args)

### Disable all default indicators

```json
{
  "series": [ "... candlestick ..." ],
  "options": { "skipDefaultOverlays": true, "maxPoints": 400 }
}
```

### Replace defaults entirely (example: SMA 20 + MACD, no RSI)

Pass **`overlays`** — a non-empty array **replaces** EMA(50) and RSI(14):

```json
{
  "series": [ { "id": "btc", "type": "candlestick", "label": "BTC", "data": [] } ],
  "overlays": [
    { "type": "sma", "sourceSeriesId": "btc", "period": 20 },
    { "type": "macd", "sourceSeriesId": "btc" }
  ],
  "options": { "maxPoints": 400 }
}
```

### Example: EMA 20 instead of EMA 50

```json
"overlays": [
  { "type": "ema", "sourceSeriesId": "btc", "period": 20, "label": "EMA(20)" },
  { "type": "rsi", "sourceSeriesId": "btc", "period": 14 }
]
```

### Example: candles + volume only

```json
"options": { "skipDefaultOverlays": true }
```

Include volume on each candle `{ ..., "volume": 12345 }` or a aligned **`histogram`** series.

## When to use `technical-indicators` MCP

| Task | Tool |
|------|------|
| Standard chat chart with EMA / RSI | **`prepare_chart`** only (built-in) |
| List all indicator ids / params | **`technical-indicators__list_technical_indicators`** |
| One-off indicator values without charting | **`technical-indicators__calculate_technical_indicator`** |
| Bollinger / MACD / Stoch RSI on chart | **`prepare_chart` `overlays`** (preferred) |

## Customization for this node

Edit the **Operator overrides** examples above to match how this operator prefers charts (e.g. change default EMA to 20, add MACD, drop RSI). The agent should follow those examples when the operator does not specify otherwise.
