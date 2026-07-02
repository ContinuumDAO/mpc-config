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

Load **`coingecko`**, then **`coingecko__execute`**. Preferred API:

```javascript
async function run(client) {
  const ohlcs = await client.coins.ohlc.get('ethereum', {
    days: '90',
    vs_currency: 'usd',
    interval: 'hourly',
  });
  // ohlcs is [ [timestampMs, open, high, low, close], ... ] — aggregate to 4h if needed
  return ohlcs;
}
```

Spot market chart (prices + volumes, no native OHLC): `await client.coins.marketChart.get('ethereum', { days: '90', vs_currency: 'usd' })` — build candles from `prices` / `total_volumes` (see **`chart-periods`**).

Then **`prepare_chart_from_rows`** with **`toolResult`** (object or stringified JSON is OK):

```json
{
  "title": "ETH/USD 4H — last 90d",
  "toolResult": { "result": [ "... bars or tuples ..." ] }
}
```

Bar shapes accepted: `{ time, open, high, low, close }`, `{ t, o, h, l, c, v }`, or `[timestampMs, o, h, l, c]`.

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
