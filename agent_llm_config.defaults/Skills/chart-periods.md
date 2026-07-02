# Chart periods & data sizing

Load this skill when the operator asks for a **chart, graph, or plot** and you need to pick a time range or bar count. Also load **`chart-defaults`** for indicator defaults and MCP load workflow. Canonical tool reference: continuum MCP resource **`chart_docs`** (`chart.md`) and **`prepare_chart`**.

## Goals

1. **Sensible defaults** when the operator does not say how far back to look.
2. **Honor explicit ranges** (e.g. “6 months”, “YTD”, “since the last halving”).
3. **Newest data wins** whenever you must drop bars — never chart stale leading history because the download was too long.

## Quick defaults (no range specified)

| Target interval | Default window | Trim to ~bars |
|-----------------|----------------|---------------|
| 1m – 5m | 1 – 3 days | 300 – 400 |
| 15m | 5 – 10 days | 300 – 400 |
| 1h | 45 days | 400 |
| 4h | 90 days | 400 |
| 1d | 9 months | 270 |
| 1w | 2 years | 104 |

Always state the window in **`prepare_chart` `title`** (e.g. `ETH/USD 1h — last 45d`).

## Explicit operator range

| Operator says | You compute |
|---------------|-------------|
| “6 months” on 4h | ~1 080 bars → fetch/aggregate, then `slice(-400)` for chat (newest ~67 days visible unless they need full history in KeyGen) |
| “1 year” on 1d | ~365 bars → pass all if ≤400; else `slice(-400)` |
| “last 2 weeks” on 1h | ~336 bars → pass all |
| “YTD” on 1d | Jan 1 → now, daily bars |

If the operator’s range fits within ~400 bars, show **all of it**. If it exceeds the chat budget, show the **most recent** 400 bars and say so briefly in the reply.

## Newest-first trim (required)

After sort ascending by time:

```javascript
function tailBars(bars, maxBars = 400) {
  bars.sort((a, b) => a.time - b.time);
  return bars.length > maxBars ? bars.slice(-maxBars) : bars;
}
```

Use the same times for volume histogram series. Call **`prepare_chart`** with `"options": { "maxPoints": 400 }` as a backstop.

## Source-specific notes

### CoinGecko (`coingecko__execute`)

- **`coins.ohlc.getRange`**: returns **hourly or daily** candles depending on range length — not native 4h/15m.
- For **4h**: fetch hourly (keep request window minimal — e.g. 90 days, not 365), aggregate every 4 hours (open = first, close = last, high/low = extremes), then **`tailBars(..., 400)`**.
- For **1d**: prefer daily endpoint when range > 90 days; trim tail if needed.
- Do **not** pass raw hourly arrays of 720+ points straight to **`prepare_chart`** when a coarser interval was requested.

### Hyperliquid / GMX / protocol OHLCV

- Use the protocol’s native candle interval when available (1h, 4h, 1d).
- Request only the bar count you need (+ small buffer for indicator warmup), not “max history” by default.

### Indicators

- **`prepare_chart`** applies **EMA(50)** and **RSI(14)** automatically on candlestick charts when **`overlays`** is omitted — see skill **`chart-defaults`**.
- Prefer **`prepare_chart` `overlays`** for other indicators (`sma`, `macd`, …) over a separate **`calculate_technical_indicator`** call when building a chart.
- **`calculate_technical_indicator`**: pass **`input.candles`** as an array of **objects** `{ open, high, low, close, … }`, not arrays of numbers.

## Chat vs KeyGen

| Context | Bar budget |
|---------|------------|
| Agent chat UI | ~400 bars, `maxPoints: 400` |
| KeyGen chart attachment | Larger allowed — still **`slice(-N)`** newest if trimming |

## Checklist before `prepare_chart`

- [ ] **`agent_load_skill`** **`chart-defaults`** (and **`chart-periods`** if range unclear)
- [ ] Interval matches what the operator asked for (or sensible default above)
- [ ] Title includes asset + interval + window
- [ ] Series sorted ascending; **`tailBars`** applied if > ~400 points
- [ ] Volume on candle rows or histogram series when source provides it
- [ ] `"options": { "maxPoints": 400 }` for chat
- [ ] Omit **`overlays`** for default EMA(50)+RSI(14), or pass explicit **`overlays`** / **`skipDefaultOverlays`** per **`chart-defaults`**
