# Chart periods & data sizing

Pair with **`chart-defaults`**, **`chart-ohlcv-sources`**. Reference: **`chart_docs`**, **`prepare_chart_from_rows`**.

## Quick defaults (no range specified)

| Interval | Window | ~Bars | Spot CoinGecko (public) |
|----------|--------|-------|-------------------------|
| 1h | 45 days | 400 | **Pro only** (`interval: hourly`) or use **4H** on public |
| 4h | 90 days | 400 | **Default for public** (auto for 3–30d windows) |
| 1d | 9 months | 270 | Long windows (31d+ auto → coarser) |

Trim newest-first when over ~400 bars. Put window in **`title`**.

**Operator asks “1 hour” on spot CoinGecko:** if only **`coingecko`** (public) is loaded → fetch **4H** data (auto granularity), title **`4H`**, and **tell the operator** hourly spot needs **CoinGecko Pro** or a DeFi venue. Do not pretend the chart is 1H.

## Fetch + chart

1. Pick source per **`chart-ohlcv-sources`**: loaded **`coingecko`** if available; else load **`coinmarketcap-public`** (not catalog **`coinmarketcap`**).
2. **Load** via **`agent_load_mcp_server`** if not in session.
3. **Fetch** OHLC bars (required — see below).
4. **`prepare_chart_from_rows`** with **`toolResult`** from step 3 — **same turn**.

Never skip step 3. Never `{}`. **Do not use `coins.marketChart.get`** for spot charts.

### Spot OHLC — CoinGecko (when loaded in session)

Tool: **`coingecko__execute`**. Pass TypeScript with **`async function run(client) { ... }`**. Return **`{ title, label, coinId, bucketSec, result: bars }`**.

Example MCP call for **7d ETH** (public API → **4H** bars even if operator said 1H):

```json
{
  "code": "async function run(client) {\n  const id = 'ethereum';\n  const days = 7;\n  const ohlc = await client.coins.ohlc.get(id, { vs_currency: 'usd', days: String(days) });\n  let bars = (ohlc || []).map(([ms, open, high, low, close]) => ({\n    time: Math.floor(ms / 1000), open, high, low, close,\n  }));\n  if (bars.length > 400) bars = bars.slice(-400);\n  return {\n    title: 'ETH/USD 4H — last 7d',\n    label: 'ETH/USD',\n    coinId: id,\n    bucketSec: 4 * 3600,\n    result: bars,\n  };\n}"
}
```

Then **`prepare_chart_from_rows`**:

```json
{
  "title": "ETH/USD 4H — last 7d",
  "label": "ETH/USD",
  "toolResult": { "... entire coingecko__execute result object ..." }
}
```

Always **`coins.ohlc.get`** inside execute — one call; map tuples to `{ time, open, high, low, close }` — **omit `volume`**. Do **not** merge with `marketChart`.

#### Public API (`coingecko`) — interval notes

No `interval` parameter. Auto-granularity (approximate): 1–2d → 30m; **3–30d → 4H**; 31d+ → 4d.

When the operator asks for **1H** / **1 hour** but only public CoinGecko is available → **still fetch with default auto granularity (4H for 7d)**. Use title **`ETH/USD 4H — last 7d`**. In reply, note that **true hourly spot OHLC** needs **`coingecko-pro`** (paid) or a **DeFi venue** — do not label the chart “1H”.

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

Include **`coinId`** (and **`bucketSec`** matching the chart interval) on every CoinGecko execute return so the chart can **live-update** (~4s spot price ticks).

#### CoinGecko Pro (`coingecko-pro`)

When **`COINGECKO_API_KEY`** is set on the node, prefer **`agent_load_mcp_server({ serverId: "coingecko-pro" })`** over public **`coingecko`**.

Paid plans may pass **`interval: 'hourly'`** on **`coins.ohlc.get`** for **`days`** in **`1` / `7` / `14` / `30` / `90`** only. Still **no volume** on OHLC.

**`title` is required** on `prepare_chart_from_rows` — describe **what you fetched** (asset, interval, window).

For **`analyze_*`**, use the same fetch and pass **`toolResult`** — same turn, no chart call unless the operator also asked to plot.

### Spot OHLC — CoinMarketCap (`coinmarketcap-public`)

**When no other OHLCV source is loaded** in this chat (or operator names CMC). Load **`coinmarketcap-public`**. Keyless **`get_kline_candles`** needs no API key; **`get_crypto_ohlcv_historical`** needs **`COINMARKETCAP_API_KEY`** on continuum-mcp. **`coinmarketcap-public`** ≠ catalog **`coinmarketcap`**. See MCP **`coinmarketcap_public_docs`**.

```json
{
  "platform": "ethereum",
  "address": "0x88e6a0c2ddd26feeb64f039a2c41296fcb3f5640",
  "interval": "4h",
  "limit": 400
}
```

Title e.g. **`ETH/USDC Uniswap v3 — 4H — last 90d`**.

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

See **`get_defi_protocol_skill`** for fetch params. Never skip chart prepare when the user asked to chart.

## Checklist

- [ ] Source per **`chart-ohlcv-sources`**: loaded CoinGecko, else **`coinmarketcap-public`**
- [ ] MCP server **loaded** in session before fetch when `initialLoad` is false
- [ ] **`title`** on chart call matches fetched asset/interval/window
- [ ] Spot **CoinGecko**: **`ohlc.get`** only; **`coinId`** + **`bucketSec`** for live ticks
- [ ] **`prepare_chart_from_rows`** in the **same turn** as fetch
- [ ] Chart tool succeeded — MCP result shows `[Chart prepared: … · continuum/chart/v1]`
