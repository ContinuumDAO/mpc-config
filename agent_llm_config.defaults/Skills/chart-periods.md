# Chart periods & data sizing

Pair with **`chart-defaults`**. Reference: **`chart_docs`**, **`prepare_chart_from_rows`**.

## Quick defaults (no range specified)

| Interval | Window | ~Bars |
|----------|--------|-------|
| 1h | 45 days | 400 |
| 4h | 90 days | 400 |
| 1d | 9 months | 270 |

Trim newest-first when over ~400 bars. Put window in **`title`** (e.g. `ETH/USD 4H — last 90d`).

## Fetch + chart (vendor-agnostic)

1. Fetch OHLCV with the operator’s chosen source (see examples below).
2. **`prepare_chart_from_rows`** with **`rows`** = bar array, or **`toolResult`** = full fetch JSON.

Never `{}`. One fetch, one chart call with data.

### Example: CoinGecko spot (when that source is used)

Load **`coingecko`** if needed, then **`coingecko__execute`**. Use **`chart.total_volumes`** (plural). Aggregate to the target interval in your execute script, **`return bars`**, then:

```json
{
  "title": "ETH/USD 4H — last 90d",
  "toolResult": { "result": [ "... bars from execute ..." ] }
}
```

See **`chart-defaults`** for a worked 4h aggregation script (CoinGecko-only example).

### Example: DeFi / perp (`ctm_*_fetch_ohlcv`)

When the operator names Hyperliquid, GMX, etc.:

```json
{
  "title": "ETH-PERP 4H",
  "toolResult": { "result": [ "... fetch_ohlcv rows ..." ] }
}
```

## Checklist

- [ ] Fetch returned OHLCV rows (array), not summary-only `{ totalBars, first, last }`
- [ ] **`prepare_chart_from_rows`** includes **`rows`** or **`toolResult`**
- [ ] Title reflects asset + interval + window
