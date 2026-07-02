# Chart periods & data sizing

Pair with **`chart-defaults`**. Reference: **`chart_docs`**, **`prepare_chart_from_rows`**.

## Quick defaults (no range specified)

| Interval | Window | ~Bars |
|----------|--------|-------|
| 1h | 45 days | 400 |
| 4h | 90 days | 400 |
| 1d | 9 months | 270 |

Trim newest-first when over ~400 bars. Put window in **`title`**.

## Fetch + chart

1. Pick source per **`chart-defaults`** source table (spot vs named perp/DEX).
2. Fetch OHLCV.
3. **Immediately** call **`prepare_chart_from_rows`** — same agent turn.

Never `{}`.

### Spot example (CoinGecko)

Load **`coingecko`**, **`coingecko__execute`** (aggregate to interval in script — see below), then:

```json
{
  "title": "ETH/USD 4H — last 90d",
  "toolResult": { "result": [ "... bars ..." ] }
}
```

**Execute script notes:** `chart.total_volumes` (plural); bucket hourly → 4h; `return bars`; trim to ~400.

### Perp / DeFi example (Hyperliquid — only when operator names it)

```json
{
  "title": "ETH-PERP 4H — 90d",
  "toolResult": {
    "ohlcv": {
      "candles": [ "... from ctm_hyperliquid_fetch_ohlcv ..." ]
    }
  }
}
```

Do not paste 500+ candles into chat prose — pass **`toolResult`** to the chart tool only.

## Checklist

- [ ] Correct source (spot vs perp) for the request
- [ ] **`prepare_chart_from_rows`** in the **same turn** as fetch
- [ ] **`rows`** or **`toolResult`** present — not `{}`
- [ ] Title: asset + interval + window
