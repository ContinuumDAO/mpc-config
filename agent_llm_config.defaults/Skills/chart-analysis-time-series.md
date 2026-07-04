# Chart analysis: time-series (line-only)

Tool family: **`analyze_time_series_*`**. For metrics without OHLC — TVL, fees, index levels, custom `{ time, value }` feeds.

Reference: **`chart_analysis_docs`**.

## When to use

| Data shape | Analysis tools |
|------------|----------------|
| OHLC candles (open/high/low/close) | **`analyze_trend_structure`**, **`analyze_key_levels`**, **`analyze_momentum`**, **`analyze_range_volatility`** |
| Line only (`{ time, value }`, tuples, `{ time, close }`) | **`analyze_time_series_trend`**, **`analyze_time_series_momentum`**, **`analyze_time_series_stats`** |

Do **not** fake OHLC from line data. If an OHLCV tool returns *Line-only time series detected*, use the time-series tool instead.

## Input

Same as OHLCV analyses: **`toolResult`** or **`rows`**, optional **`title`**.

Accepted shapes:

```json
{ "series": [{ "time": 1700000000, "value": 1.2e9 }, { "time": 1700086400, "value": 1.25e9 }] }
```

```json
{ "result": [[1700000000000, 100], [1700086400000, 105]] }
```

## Tools

| Tool | Summarize |
|------|-----------|
| **`analyze_time_series_trend`** | `bias`, `changePct`, `slopePct`, recent `extrema` (peaks/troughs on values) |
| **`analyze_time_series_momentum`** | `rsi` zone, `roc` (rate of change %) |
| **`analyze_time_series_stats`** | `min`/`max`/`mean`, `changePct`, `returnVolatilityPct`, `compression` |

Plotting line data (optional): **`prepare_chart`** with a line series — separate from analysis JSON.
