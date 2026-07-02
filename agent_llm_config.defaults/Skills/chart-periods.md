# Chart periods & data sizing

Spot charts: **CoinGecko** → **`prepare_chart`**. Pair with **`chart-defaults`**. Reference: **`chart_docs`**, **`prepare_chart`**.

## Quick defaults (no range specified)

| Interval | Window | ~Bars |
|----------|--------|-------|
| 1h | 45 days | 400 |
| 4h | 90 days | 400 |
| 1d | 9 months | 270 |

Trim newest-first when over ~400 bars (`slice(-400)`). Put window in **`title`** (e.g. `ETH/USD 4H — last 90d`).

## CoinGecko fetch + chart (generic spot)

1. Load **`coingecko`** if needed.
2. **`coingecko__execute`** with **`async function run(client) { ... }`**.
3. **`prepare_chart`** with **`bars`** (or **`result`**) = the execute **`result`** array — **never `{}`**.

### ETH 4h example (~90d)

**Execute** — use **`chart.total_volumes`** (plural), aggregate hourly → 4h, **`return bars`**:

```javascript
async function run(client) {
  const id = 'ethereum';
  const chart = await client.coins.marketChart.get(id, { days: '90', vs_currency: 'usd' });
  const prices = chart.prices;
  const volumes = chart.total_volumes;
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

**Chart** — pass the returned array as **`bars`** (same objects as **`result`**, inlined in the tool call):

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

Do **not** call **`prepare_chart({})`** after a successful fetch. One execute, one chart call with data.

## DeFi / perp OHLCV

Use **`ctm_*_fetch_ohlcv`** only when the operator asks for that protocol (Hyperliquid perp, GMX, etc.) — not for generic “chart ETH”.

## Checklist

- [ ] CoinGecko fetch returned a **`result`** array (not `{ totalBars, first, last }` only)
- [ ] **`prepare_chart`** includes **`bars`** or **`series`** — not empty
- [ ] Title reflects asset + interval + window
