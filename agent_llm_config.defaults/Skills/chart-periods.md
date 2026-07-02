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

1. Pick source per **`chart-defaults`** source table.
2. Fetch OHLCV **with volume** when the default chart layout is used (volume pane below price).
3. **Immediately** call **`prepare_chart_from_rows`** — same agent turn.

Never `{}`.

### Spot with volume (CoinGecko — preferred for “chart ETH 4h”)

**Do not use `coins.ohlc.get` alone** — it returns OHLC tuples **without volume**. Use **`coins.marketChart.get`** and build candles from **`prices`** + **`total_volumes`**:

```javascript
async function run(client) {
  const id = 'ethereum';
  const chart = await client.coins.marketChart.get(id, {
    days: '90',
    vs_currency: 'usd',
  });
  const prices = chart.prices || [];
  const volumes = chart.total_volumes || [];
  const volByMs = new Map(volumes.map(([ms, v]) => [ms, v]));
  const hourly = [];
  for (let i = 0; i < prices.length; i++) {
    const [ms, close] = prices[i];
    const prevClose = i > 0 ? prices[i - 1][1] : close;
    hourly.push({
      time: Math.floor(ms / 1000),
      open: prevClose,
      high: Math.max(prevClose, close),
      low: Math.min(prevClose, close),
      close,
      volume: volByMs.get(ms) ?? 0,
    });
  }
  const FOUR_H = 4 * 3600;
  const buckets = new Map();
  for (const bar of hourly) {
    const bucket = Math.floor(bar.time / FOUR_H) * FOUR_H;
    const b = buckets.get(bucket);
    if (!b) buckets.set(bucket, { ...bar, time: bucket });
    else {
      b.high = Math.max(b.high, bar.high);
      b.low = Math.min(b.low, bar.low);
      b.close = bar.close;
      b.volume += bar.volume;
    }
  }
  let bars = [...buckets.values()].sort((a, b) => a.time - b.time);
  if (bars.length > 400) bars = bars.slice(-400);
  return bars;
}
```

Then:

```json
{
  "title": "ETH/USD 4H — last 90d",
  "rows": [ "... bars with volume field ..." ]
}
```

Or pass the raw **`marketChart`** response as **`toolResult`** (SDK builds OHLCV + volume automatically; optional **`options.bucketSec`: 14400** for 4h):

```json
{
  "title": "ETH/USD 4H — last 90d",
  "toolResult": { "result": { "prices": "...", "total_volumes": "..." } },
  "options": { "bucketSec": 14400 }
}
```

Prefer **`rows`** (array) over a stringified **`toolResult`** — avoids JSON truncation errors.

### Spot OHLC only (no volume pane)

`client.coins.ohlc.get(...)` — acceptable only if the operator explicitly does not want volume.

### Perp / DeFi (Hyperliquid — when operator names it)

```json
{
  "title": "ETH-PERP 4H — 90d",
  "toolResult": { "ohlcv": { "candles": [ "... fetch_ohlcv ..." ] } }
}
```

## Checklist

- [ ] Spot default charts: rows include **`volume`** (use `marketChart`, not `ohlc.get` alone)
- [ ] **`prepare_chart_from_rows`** in the **same turn** as fetch
- [ ] **`rows`** or complete **`toolResult`** — not `{}` or truncated JSON
- [ ] Title: asset + interval + window
