# Chart periods & data sizing

Pair with **`chart-defaults`**, **`chart-ohlcv-sources`**. Reference: **`chart_docs`**, **`prepare_chart_from_rows`**.

## Quick defaults (no range specified)

| Interval | Window | ~Bars | Generic spot (CMC first) |
|----------|--------|-------|---------------------------|
| 1h | 45 days | 400 | CMC Pro **`get_crypto_ohlcv_historical`** (`timePeriod: hourly`) or DEX **`get_kline_candles`** `1h` |
| 4h | 90 days | 400 | CMC Pro hourly + trim, DEX **`4h`**, or CoinGecko fallback (public auto **4H**) |
| 1d | 9 months | 270 | CMC **`timePeriod: daily`** or DEX **`1d`** |

Trim newest-first when over ~400 bars. Put window in **`title`**.

**Operator asks “1 hour” on generic spot:** try CMC hourly first. If only CoinGecko is available → **4H** auto, title **`4H`**, explain CMC/Pro/DeFi for true hourly.

## Fetch + chart

1. Pick source per **`chart-ohlcv-sources`** (CoinMarketCap before CoinGecko). **Load** **`coinmarketcap-public`** (or CoinGecko fallback servers) via **`agent_load_mcp_server`** before fetch.
2. Fetch OHLC bars. **CMC:** volume when present. **CoinGecko fallback:** **`coins.ohlc.get`** only — no volume.
3. **Immediately** call **`prepare_chart_from_rows`** — same agent turn.

Never `{}`. **Do not use `coins.marketChart.get`** for spot charts.

### Spot OHLC — CoinMarketCap (default)

See **`chart-ohlcv-sources`**. Preferred path for chart and **`analyze_*`**.

#### CEX aggregate — `coinmarketcap-public__get_crypto_ohlcv_historical`

Requires **`COINMARKETCAP_API_KEY`** on **continuum-mcp**. Returns CMC **`quotes[]`** in **`result`** — chart-ready after SDK normalization; includes **volume**.

```json
{
  "id": "1027",
  "convert": "USD",
  "timePeriod": "hourly",
  "count": 400,
  "interval": "hourly"
}
```

```javascript
// Example execute return shape (agent or script)
return {
  title: 'ETH/USD 1H — last 45d',
  label: 'ETH/USD',
  id: '1027',
  timePeriod: 'hourly',
  result: quotes, // from tool response
};
```

#### DEX pool proxy — `get_kline_candles` (keyless)

When Pro OHLCV is unavailable:

```json
{
  "platform": "ethereum",
  "address": "0x88e6a0c2ddd26feeb64f039a2c41296fcb3f5640",
  "interval": "4h",
  "limit": 400
}
```

Title: **`ETH/USDC Uniswap v3 — 4H — last 90d`** (not “CEX index”).

### Spot OHLC — CoinGecko (fallback only)

Use only when CMC paths fail. Always **`coins.ohlc.get`**. One call; map tuples to `{ time, open, high, low, close }` — **omit `volume`**.

#### Public API (`coingecko`)

No `interval` parameter. Auto-granularity: 1–2d → 30m; **3–30d → 4H**; 31d+ → 4d.

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
    title: 'ETH/USD 4H — last 7d (CoinGecko fallback)',
    label: 'ETH/USD',
    coinId: id,
    bucketSec: 4 * 3600,
    result: bars,
  };
}
```

Include **`coinId`** + **`bucketSec`** on CoinGecko returns for live spot ticks.

#### CoinGecko Pro (`coingecko-pro`)

When **`COINGECKO_API_KEY`** is set and CMC failed: **`agent_load_mcp_server({ serverId: "coingecko-pro" })`**.

May pass **`interval: 'hourly'`** on **`coins.ohlc.get`** for **`days`** in **`1` / `7` / `14` / `30` / `90`**. Still **no volume**.

**`title` is required** on `prepare_chart_from_rows` — describe **what you fetched** (asset, interval, window, source if fallback).

```json
{
  "title": "ETH/USD 4H — last 90d",
  "label": "ETH/USD",
  "rows": [ "... OHLC bars ..." ]
}
```

Or pass execute output as **`toolResult`** when it returned `{ title, label, result }`.

Prefer **`rows`** (array) over a stringified **`toolResult`**.

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

- [ ] **`coinmarketcap-public`** loaded via **`agent_load_mcp_server`** before CMC fetch (not initialLoad)
- [ ] Source picked per **`chart-ohlcv-sources`** (CMC before CoinGecko for generic spot)
- [ ] **`title`** matches asset, interval, window, and source (DEX proxy vs CEX vs fallback)
- [ ] **`prepare_chart_from_rows`** in the **same turn** as fetch
- [ ] **`rows`** or complete **`toolResult`** — not `{}` or truncated JSON
- [ ] CoinGecko fallback only: **`ohlc.get`**, **`coinId`** + **`bucketSec`** for live ticks
- [ ] Chart tool succeeded — MCP result shows `[Chart prepared: … · continuum/chart/v1]`
