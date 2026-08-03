---
name: chart-periods
description: Default lookback by bar interval, newest-first trim, and source-specific fetch notes for **`prepare_chart`** (host auto-loads on chart intents)
---

# Chart periods & data sizing

Pair with **`chart-defaults`**, **`chart-ohlcv-sources`**. Reference: **`chart_docs`**, **`prepare_chart_from_rows`**.

## Quick defaults (no range specified)

| Interval | Window | ~Bars | Spot CoinGecko (public) |
|----------|--------|-------|-------------------------|
| 1h | 7 – 30 days | 168 – 720 | **Pro only** (`interval: hourly`) or use **4H** on public |
| 4h | 30 – 90 days | 180 – 540 | **Default for public** (auto for 3–30d windows) |
| 1d | 6 – 12 months | 180 – 365 | Long windows (31d+ auto → coarser) |

Put window in **`title`** (interval + lookback, e.g. `ETH-PERP 1H — last 7d`).

### Bar sizing — two different rules

| Path | Trim candles? |
|------|----------------|
| **`prepare_chart_from_rows`** + vendor **`toolResult`** (Hyperliquid, GMX, CMC, CoinGecko execute return, Binance klines JSON) | **Never.** Pass the **full, unmodified** fetch JSON. Chart downsamples for **display** via `maxPoints` (default 400) — that is not deleting history. |
| **`coingecko__execute`** building `result: bars` inside your script | May `slice(-400)` **only inside execute** when the API returns far more bars than needed — then pass the **whole execute object** as `toolResult`. Do **not** slice again before `prepare_chart_from_rows`. |
| **`prepare_chart`** with hand-built `series[].data` | May cap at ~400 bars (newest-first) — see **`chart_docs`**. |

**Common requests (vendor fetch — pass full `toolResult`):**

| Operator request | ~Bars | Action |
|------------------|-------|--------|
| ETH-PERP **1H — last 7d** (Hyperliquid) | ~168–169 | Title `ETH-PERP 1H — last 7d`; **do not** shorten to 24h or switch to 4H |
| ETH-PERP **1H — last 30d** (Hyperliquid) | ~721 | Title `ETH-PERP 1H — last 30d`; **do not** switch to 1D |
| **15m — last 24h** | ~96 | Full `toolResult` |
| **4H — last 30d** | ~181 | Full `toolResult` |

There is **no** chart-builder bar-count limit for normal fetch windows. If `prepare_chart_from_rows` fails, quote the tool **`reason`** exactly — do not invent “payload too large” or substitute a coarser interval than the operator requested.

**Operator asks “1 hour” on spot CoinGecko:** if only **`coingecko`** (public) is loaded → fetch **4H** data (auto granularity), title **`4H`**, and **tell the operator** hourly spot needs **CoinGecko Pro** or a DeFi venue. Do not pretend the chart is 1H.

## Fetch + chart

1. Pick source per **`chart-ohlcv-sources`**: use loaded **`coingecko`** if available; **if none loaded, ask the operator** — do not auto-load **`coinmarketcap-public`** or **`coingecko`**.
2. Enable source: **`load_defi_protocol`** for Hyperliquid/GMX/DeFi, or **`agent_load_mcp_server`** for catalog MCP — only after the operator chooses.
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

**When the operator chooses CMC** (or names CoinMarketCap). Load **`coinmarketcap-public`** only after that choice. Keyless **`get_kline_candles`** needs no API key; **`get_crypto_ohlcv_historical`** needs **`COINMARKETCAP_API_KEY`** on continuum-mcp. **`coinmarketcap-public`** ≠ catalog **`coinmarketcap`**. See MCP **`coinmarketcap_public_docs`**.

```json
{
  "platform": "ethereum",
  "address": "0x88e6a0c2ddd26feeb64f039a2c41296fcb3f5640",
  "interval": "4h",
  "limit": 400
}
```

Title e.g. **`ETH/USDC Uniswap v3 — 4H — last 90d`**.

### Spot / CEX OHLC — Binance (`binance`)

**When the operator chooses Binance.** Load **`binance`** only after that choice (`initialLoad: false`).

1. **`binance_get_klines`** (or the loaded server’s klines tool) with **`response_format: "json"`** — default markdown is **not** chartable. Set **`symbol`**, **`interval`**, and **`limit`** (and optional **`start_time`** / **`end_time`** ms) for the requested window.
2. Parse the tool text into a JSON **object** if needed (`{ symbol, interval, klines, count }`).
3. **`continuum__prepare_chart_from_rows`** — same turn; pass that **object** as **`toolResult`**. Keep **`openTime`** on rows — Continuum normalizes it. Chart may attach **`live.providerId: "binance.tickerPrice"`**.

```json
{
  "symbol": "BTCUSDT",
  "interval": "1h",
  "limit": 168,
  "response_format": "json"
}
```

Then:

```json
{
  "title": "BTCUSDT 1H — last 7d",
  "label": "BTCUSDT",
  "toolResult": { "symbol": "BTCUSDT", "interval": "1h", "klines": [ "... full klines from fetch ..." ], "count": 168 }
}
```

**Never** skip prepare because the chart renderer is on Continuum MCP. **Never** rewrite **`openTime`** to **`time`** / **`timestampMs`**.

### Spot / CEX OHLC — Coinbase Advanced Trade (`coinbase-public`)

**When the operator chooses Coinbase.** Load **`coinbase-public`** only after that choice (`initialLoad: false`). Keyless public market API; optional CDP Variables for authenticated routes — see **`coinbase_public_docs`**.

1. **`coinbase-public__get_product_candles`** with **`productId`** (e.g. `BTC-USD`), **`interval`** (`1m`/`5m`/`15m`/`30m`/`1h`/`2h`/`4h`/`6h`/`1d`) or **`granularity`**, and **`lookbackDays`** or **`limit`** (max 350).
2. Tool returns Continuum-normalized bars: `{ dataSource: "coinbase_candles", productId, interval, candles: [{ time, open, high, low, close, volume? }] }`.
3. **`continuum__prepare_chart_from_rows`** — same turn; pass that **object** as **`toolResult`**. Do **not** rewrite bars. Chart may attach **`live.providerId: "coinbase.productTicker"`**.

```json
{
  "productId": "BTC-USD",
  "interval": "1h",
  "lookbackDays": 7
}
```

Then:

```json
{
  "title": "BTC-USD 1H — last 7d",
  "label": "BTC-USD",
  "toolResult": { "dataSource": "coinbase_candles", "productId": "BTC-USD", "interval": "1H", "candles": [ "... full candles from fetch ..." ], "count": 168 }
}
```

For liquidity depth on the same session: **`analyze_liquidity_depth`** (defaults to **`depthExchangeId: coinbase`** when `dataSource` is `coinbase_candles`).

### Perp / DeFi (Hyperliquid, Arcus, or GMX — when operator names the venue)

**Never slice or shorten `candles` from the fetch** before `prepare_chart_from_rows`. Honor the operator’s interval and lookback exactly (e.g. 7d @ 1h ≈ 168–169 bars — chart as-is).

**Hyperliquid** — fetch returns `{ ohlcv: { coin, interval, candles, lookbackDays?, startTimeMs?, endTimeMs? }, resolvedCoin }`:

1. `ctm_hyperliquid_fetch_ohlcv` (after `load_defi_protocol({ protocolId: "hyperliquid" })`) with the requested interval and lookback (e.g. `interval: "1h"`, `lookbackDays: 7`).
2. **`continuum__prepare_chart_from_rows`** — same turn; pass **full fetch JSON** as **`toolResult`**.

```json
{
  "title": "ETH-PERP 1H — last 30d",
  "toolResult": { "ohlcv": { "coin": "ETH", "interval": "1h", "lookbackDays": 30, "candles": [ "... all ~721 candles from fetch ..." ] }, "resolvedCoin": "ETH" }
}
```

**Never** re-fetch at a coarser interval because the loaded bar count “won’t fit” — the chart tool loads the full window and downsamples display only (`meta.loadStatus.barCount` vs `displayBarCount`, `meta.windowExpectation`).

**Arcus** — perp fetch returns `{ ohlcv: { market, interval, candles, dataSource: "arcus" }, chainId: 4663 }`; spot uses `ctm_arcus_spot_fetch_ohlcv`:

1. `ctm_arcus_fetch_ohlcv` or `ctm_arcus_spot_fetch_ohlcv` (after `load_defi_protocol({ protocolId: "arcus" })`, chain **4663**).
2. **`continuum__prepare_chart_from_rows`** — same turn; pass **full fetch JSON** as **`toolResult`**.

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

- [ ] Source per **`chart-ohlcv-sources`**: operator chose one — never auto-load
- [ ] **DeFi:** **`load_defi_protocol`** before **`ctm_*_fetch_ohlcv`** | **Catalog:** **`agent_load_mcp_server`** before fetch when `initialLoad` is false
- [ ] **`title`** matches fetched asset, interval, and window (e.g. `last 7d` when `lookbackDays: 7`)
- [ ] **Hyperliquid / GMX:** full fetch **`toolResult`** — never hand-trimmed candles or “last 24h” substitute for a 7d request
- [ ] Spot **CoinGecko**: **`ohlc.get`** only; **`coinId`** + **`bucketSec`** for live ticks
- [ ] Spot **Binance**: **`response_format: "json"`**; full parsed object as **`toolResult`**; keep **`openTime`**
- [ ] Spot **Coinbase**: **`get_product_candles`**; full object as **`toolResult`**; keep Continuum **`time`** bars
- [ ] **`prepare_chart_from_rows`** in the **same turn** as fetch
- [ ] Chart tool succeeded — MCP result shows `[Chart prepared: … · continuum/chart/v1]`
