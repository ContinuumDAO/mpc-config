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
  return {
    title: 'ETH/USD 4H — last 90d',
    label: 'ETH/USD',
    result: bars,
  };
}
```

**`title` is required** on `prepare_chart_from_rows` — it must describe **what you fetched** (asset, interval, window), not copy the user chat. Either pass it on the chart call or return it from execute (SDK reads `title` / `label` from fetch JSON).

```json
{
  "title": "ETH/USD 4H — last 90d",
  "label": "ETH/USD",
  "rows": [ "... bars with volume field ..." ]
}
```

Or pass fetch output as **`toolResult`** when execute returned `{ title, label, result }`:

```json
{
  "title": "ETH/USD 4H — last 90d",
  "toolResult": { "result": { "prices": "...", "total_volumes": "..." } },
  "options": { "bucketSec": 14400 }
}
```

Prefer **`rows`** (array) over a stringified **`toolResult`** — avoids JSON truncation errors.

### Spot analysis only (CoinGecko — `analyze_*`, no chart)

Use **`coins.ohlc.get`** — real OHLC candles; **no volume** (analysis tools do not need it). **Do not** merge `ohlc.get` + `marketChart` in one script.

CoinGecko auto-granularity (approximate): 1–2d → 30m; 3–30d → **4H**; 31d+ → 4d. Set **`title`** to match (e.g. 7d → `ETH/USD 4H — last 7d`, not “1H”).

```javascript
async function run(client) {
  const id = 'ethereum';
  const days = 7;
  const ohlc = await client.coins.ohlc.get(id, { vs_currency: 'usd', days: String(days) });
  const bars = (ohlc || []).map(([ms, open, high, low, close]) => ({
    time: Math.floor(ms / 1000),
    open,
    high,
    low,
    close,
  }));
  return {
    title: 'ETH/USD 4H — last 7d',
    label: 'ETH/USD',
    result: bars,
  };
}
```

Pass the execute return as **`toolResult`** to **`analyze_*`** (same turn). For chart + volume, use **`marketChart`** above instead.

### Spot OHLC only (chart without volume pane)

`client.coins.ohlc.get(...)` — when the operator explicitly does not want a volume pane on the chart.

### Perp / DeFi (Hyperliquid or GMX — when operator names the venue)

**Hyperliquid** — fetch returns `{ ohlcv: { coin, interval, candles }, resolvedCoin }`:

1. `ctm_hyperliquid_fetch_ohlcv` (after `load_defi_protocol({ protocolId: "hyperliquid" })`).
2. **`continuum__prepare_chart_from_rows`** — same turn; pass **full fetch JSON** as **`toolResult`**.

```json
{
  "title": "ETH-PERP 1H — last 3d",
  "toolResult": { "ohlcv": { "coin": "ETH", "interval": "1h", "candles": [ "... from fetch ..." ] }, "resolvedCoin": "ETH" }
}
```

**GMX** — fetch returns `{ symbol, timeframe, candles }` (no volume on rows):

1. `ctm_gmx_fetch_ohlcv` (after `load_defi_protocol({ protocolId: "gmx" })`); set **`limit`** for enough bars.
2. **`continuum__prepare_chart_from_rows`** — same turn; pass **full fetch JSON** as **`toolResult`**.

```json
{
  "title": "ETH/USD 1H — last 7d",
  "toolResult": { "symbol": "ETH/USD [WETH-USDC]", "timeframe": "1h", "candles": [ "... from fetch ..." ] }
}
```

See **`get_defi_protocol_skill`** for fetch params. **`load_defi_protocol`** also returns **`chartWorkflow`**. Never skip step 2 when the user asked to chart.

## Checklist

- [ ] **`title`** on chart call matches fetched asset/interval/window (or returned from execute)
- [ ] Spot **charts**: rows include **`volume`** (use `marketChart`, not `ohlc.get` alone)
- [ ] Spot **analysis**: use `ohlc.get` (real OHLC; honest interval in title)
- [ ] **`prepare_chart_from_rows`** in the **same turn** as fetch
- [ ] **`rows`** or complete **`toolResult`** — not `{}` or truncated JSON
- [ ] Title: asset + interval + window
- [ ] Chart tool succeeded — MCP result shows `[Chart prepared: … · continuum/chart/v1]`; if missing, **do not claim the chart rendered**
