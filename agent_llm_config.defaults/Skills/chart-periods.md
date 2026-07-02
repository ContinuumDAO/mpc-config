# Chart periods & data sizing

Load this skill when the operator asks for a **chart, graph, or plot** and you need to pick a time range or bar count. Also load **`chart-defaults`** for indicator defaults and MCP load workflow. Canonical tool reference: continuum MCP resource **`chart_docs`** (`chart.md`) and **`prepare_chart`**.

## Default OHLCV source (spot / generic charts)

For **generic** requests (“chart BTC”, “4h ETH candlesticks”, “plot SOL”) **without** naming a perp DEX or on-chain venue:

1. **`agent_load_mcp_server`** with `{ "serverId": "coingecko" }` when **`coingecko__execute`** (or similar) is **not** already in the tool list. Use catalog id **`coingecko`** (public HTTP MCP — no API key).
2. Fetch OHLC via **`coingecko__execute`** (see **CoinGecko** below). Resolve coin id (e.g. `bitcoin`, `ethereum`) when the operator says “BTC” / “ETH”.
3. **Do not** call **`load_defi_protocol`**, **Hyperliquid**, **GMX**, or other DeFi OHLCV tools unless the operator explicitly asks for perp positions, vault context, or that protocol’s market.

Use DeFi/protocol OHLCV only when the operator’s goal is tied to that venue (e.g. “chart my Hyperliquid BTC perp”, “GMX ETH candles for this wallet”).

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

### CoinGecko (`coingecko__execute`) — **default**

- Catalog MCP id: **`coingecko`** (public). Load with **`agent_load_mcp_server`** if tools are missing.
- **`coingecko__execute`** requires a top-level **`async function run(client) { ... }`** — wrap all code in that template (see **Worked example: BTC 4h** below).
- **`coingecko__search_docs`** — optional; use when unsure of method names. Then **`execute`** with the `run` wrapper.
- **Do not** use **`client.coins.ohlc.get(..., { days: '90' })`** for 4h — CoinGecko returns **sparse daily/4-day** bars for long ranges. For **~90d at 4h**, use **`marketChart.get`** hourly and aggregate (example below). For **~30d native 4h**, use **`coins.ohlc.get(..., { days: '30' })`** (CoinGecko returns 4h bars for 2–30 days).
- After **`execute`** returns bars, you **must** call **`continuum__prepare_chart`** in the **same turn** with a full payload — **never** `{}` and **never** skip **`series`**.

#### Worked example: BTC 4h (~90d, with volume)

**Step 1 — fetch** (`coingecko__execute`):

```javascript
async function run(client) {
  const id = 'bitcoin';
  const chart = await client.coins.marketChart.get(id, {
    days: '90',
    vs_currency: 'usd',
  });
  const prices = chart.prices;       // [[ms, close], ...] hourly
  const volumes = chart.total_volumes; // [[ms, vol], ...]
  const volByMs = new Map(volumes.map(([ms, v]) => [ms, v]));

  // Hourly pseudo-OHLC from close series (open = previous close)
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

  // Aggregate hourly → 4h
  const FOUR_H = 4 * 3600;
  const buckets = new Map();
  for (const bar of hourly) {
    const bucket = Math.floor(bar.time / FOUR_H) * FOUR_H;
    const b = buckets.get(bucket);
    if (!b) {
      buckets.set(bucket, { ...bar, time: bucket });
    } else {
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

**Step 2 — chart** (`continuum__prepare_chart`) — use the **`result`** array from step 1 as **`series[0].data`**:

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
        { "time": 1777262400, "open": 79096, "high": 79096, "low": 77728, "close": 77728, "volume": 117403486572 }
      ]
    }
  ]
}
```

- **`time`**: Unix **seconds** (convert from CoinGecko ms with `Math.floor(ms / 1000)`).
- **`data`**: at least **15+ bars** for RSI, **50+** for default EMA(50) — fetch enough history before trim.
- **Wrong:** calling **`prepare_chart`** with **`{}`** or before fetch completes. **Right:** one fetch, then one **`prepare_chart`** with populated **`series`**.

### Hyperliquid / GMX / protocol OHLCV — **only when operator asks**

- Use when the chart is **about that protocol** (perp book, vault, wallet on that venue).
- Use the protocol’s native candle interval when available (1h, 4h, 1d).
- Request only the bar count you need (+ small buffer for indicator warmup), not “max history” by default.
- Requires **`load_defi_protocol`** first — avoid for generic spot charts.

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
- [ ] **CoinGecko** loaded for generic spot charts (not DeFi OHLCV unless operator asked)
- [ ] **`coingecko__execute`** completed and **`result`** parsed into candle objects
- [ ] **`prepare_chart` called with non-empty `series`** — never `{}`
- [ ] Interval matches what the operator asked for (or sensible default above)
- [ ] Title includes asset + interval + window
- [ ] Series sorted ascending; **`tailBars`** applied if > ~400 points
- [ ] Volume on candle rows or histogram series when source provides it
- [ ] **`prepare_chart` `series`** is a **JSON array** of series objects — never a stringified JSON blob
- [ ] `"options": { "maxPoints": 400 }` for chat
- [ ] Omit **`overlays`** for default EMA(50)+RSI(14), or pass explicit **`overlays`** / **`skipDefaultOverlays`** per **`chart-defaults`**
