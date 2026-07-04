# Chart periods & data sizing

Pair with **`chart-defaults`**. Reference: **`chart_docs`**, **`prepare_chart_from_rows`**.

## Quick defaults (no range specified)

| Interval | Window | ~Bars | Spot CoinGecko (public) |
|----------|--------|-------|-------------------------|
| 1h | 45 days | 400 | **Pro only** (`interval: hourly`) or use **4H** on public |
| 4h | 90 days | 400 | **Default for public** (auto for 3–30d windows) |
| 1d | 9 months | 270 | Long windows (31d+ auto → coarser) |

Trim newest-first when over ~400 bars. Put window in **`title`**.

**Operator asks “1 hour” on spot CoinGecko:** if only **`coingecko`** (public) is loaded → fetch **4H** data (auto granularity), title **`4H`**, and **tell the operator** hourly spot needs **CoinGecko Pro** or a DeFi venue (Hyperliquid/GMX). Do not pretend the chart is 1H.

## Fetch + chart

1. Pick source per **`chart-defaults`** source table.
2. Fetch OHLC bars. **CoinGecko spot:** **`coins.ohlc.get`** only — real candles, **no volume** (volume pane omitted). **DeFi / Hyperliquid / GMX:** native **`fetch_ohlcv`** when available (volume when rows include it).
3. **Immediately** call **`prepare_chart_from_rows`** — same agent turn.

Never `{}`. **Do not use `coins.marketChart.get`** for spot charts — it synthesizes fake candles from price points and poor volume.

### Spot OHLC (CoinGecko — chart and analysis)

Always **`coins.ohlc.get`**. One call; map tuples to `{ time, open, high, low, close }` — **omit `volume`**. Do **not** merge with `marketChart`.

#### Public API (`coingecko` — default)

No `interval` parameter. Auto-granularity (approximate): 1–2d → 30m; **3–30d → 4H**; 31d+ → 4d.

When the operator asks for **1H** / **1 hour** but only public CoinGecko is available → **still fetch with default auto granularity (4H for 7d)**. Use title **`ETH/USD 4H — last 7d`**. In reply, note that **true hourly spot OHLC** needs **`coingecko-pro`** (paid) or **Hyperliquid/GMX** for venue candles — do not label the chart “1H”.

```javascript
async function run(client) {
  const id = 'ethereum';
  const days = 7;
  const ohlc = await client.coins.ohlc.get(id, { vs_currency: 'usd', days: String(days) });
  let bars = (ohlc || []).map(([ms, open, high, low, close]) => ({
    time: Math.floor(ms / 1000),
    open,
    high,
    low,
    close,
  }));
  if (bars.length > 400) bars = bars.slice(-400);
  return {
    title: 'ETH/USD 4H — last 7d',
    label: 'ETH/USD',
    coinId: id,
    bucketSec: 4 * 3600,
    result: bars,
  };
}
```

Include **`coinId`** (and **`bucketSec`** matching the chart interval) on every CoinGecko execute return so the chart can **live-update** (~4s spot price ticks). Without `coinId`, the chart is static.

#### CoinGecko Pro (`coingecko-pro` — optional)

When **`COINGECKO_API_KEY`** is set on the node, prefer **`agent_load_mcp_server({ serverId: "coingecko-pro" })`** over public **`coingecko`**.

Paid plans may pass **`interval: 'hourly'`** on **`coins.ohlc.get`** for **`days`** in **`1` / `7` / `14` / `30` / `90`** only. Then an **1H** title is honest (e.g. `ETH/USD 1H — last 7d`). Still **no volume** on OHLC.

```javascript
async function run(client) {
  const id = 'ethereum';
  const days = 7;
  const ohlc = await client.coins.ohlc.get(id, {
    vs_currency: 'usd',
    days: String(days),
    interval: 'hourly',
  });
  let bars = (ohlc || []).map(([ms, open, high, low, close]) => ({
    time: Math.floor(ms / 1000),
    open,
    high,
    low,
    close,
  }));
  if (bars.length > 400) bars = bars.slice(-400);
  return {
    title: 'ETH/USD 1H — last 7d',
    label: 'ETH/USD',
    coinId: id,
    bucketSec: 3600,
    result: bars,
  };
}
```

For **90d+** spot on Pro, use **`interval: 'daily'`** or auto — not hourly.

**`title` is required** on `prepare_chart_from_rows` — describe **what you fetched** (asset, interval, window), not copy the user chat verbatim if granularity differs.

```json
{
  "title": "ETH/USD 4H — last 90d",
  "label": "ETH/USD",
  "rows": [ "... OHLC bars, no volume field ..." ]
}
```

Or pass execute output as **`toolResult`** when it returned `{ title, label, result }`.

Prefer **`rows`** (array) over a stringified **`toolResult`** — avoids JSON truncation errors.

For **`analyze_*`**, use the same fetch and pass **`toolResult`** — same turn, no chart call unless the operator also asked to plot.

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
- [ ] Spot **CoinGecko**: **`ohlc.get`** only — real OHLC, no volume, no `marketChart`; return includes **`coinId`** (+ **`bucketSec`**) for live ticks
- [ ] Spot **public** + operator said “1H”: chart **4H** data, title says **4H**, explain Pro/DeFi for hourly
- [ ] Spot **Pro** loaded: may use **`interval: 'hourly'`** for 1–90d; title may say **1H**
- [ ] **`prepare_chart_from_rows`** in the **same turn** as fetch
- [ ] **`rows`** or complete **`toolResult`** — not `{}` or truncated JSON
- [ ] Title: asset + interval + window
- [ ] Chart tool succeeded — MCP result shows `[Chart prepared: … · continuum/chart/v1]`; if missing, **do not claim the chart rendered**
