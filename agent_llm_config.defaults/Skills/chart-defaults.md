# Chart defaults (plotting only)

**This skill is for charting/plotting — not analysis-only workflows.** For interpret/analyze without a chart, use **`chart-analysis-menu`** and **`analyze_*`** tools instead of **`prepare_chart*`**.

Charts: SDK **`prepare_chart_from_rows`** (single OHLCV feed) or **`prepare_chart`** (advanced). Reference: **`chart_docs`**.

**OHLCV sources:** skill **`chart-ohlcv-sources`** — use loaded providers; **`coinmarketcap-public`** only when no other OHLCV source is loaded in the session.

## Source selection (generic “chart ETH/BTC”)

| Operator request | Data source | Avoid |
|------------------|-------------|--------|
| “Chart ETH 4h”, “BTC chart”, spot (no venue/provider named) | **`coingecko`** / **`coingecko-pro`** if **loaded** in session; else **`coinmarketcap-public`** (load via **`agent_load_mcp_server`**) | Hyperliquid/GMX/`ctm_*_fetch_ohlcv` unless venue named |
| Names **CoinMarketCap** / **CMC** | **`coinmarketcap-public`** (`serverId` exact) — **not** catalog **`coinmarketcap`** unless API key configured | Claiming CMC loaded when load returned key error |
| Names **Hyperliquid**, **perp**, **GMX**, DEX pool, on-chain venue | That protocol’s **`fetch_ohlcv`** | Unrelated spot aggregators |

Hyperliquid OHLCV is **perpetual** market data, not generic spot USD index. Do not use it for undifferentiated “chart ETH”.

## Workflow (strict order)

1. **`list_mcp_servers`** — pick correct **`serverId`** (see **`chart-ohlcv-sources`**: **`coinmarketcap-public`** ≠ **`coinmarketcap`**).
2. **`agent_load_mcp_server`** if the fetch server is not in session.
3. **Fetch OHLCV** — e.g. **`coingecko__execute`** or **`coinmarketcap-public__get_kline_candles`**. Must succeed before charting.
4. **`continuum__prepare_chart_from_rows`** with the **full, unmodified fetch JSON** as **`toolResult`** (keep Hyperliquid **`timestampMs`** on each candle — **never rewrite `time`**). When both **`toolResult`** and **`rows`** are present, the server uses **`toolResult`**.

**Never skip step 3.** Never pass a hand-edited subset of candles. Calling **`prepare_chart_from_rows`** with only **`title`** / **`label`** always fails validation.

Never `{}`. **Do not describe the chart in markdown** — the UI only renders when the chart tool returns `continuum/chart/v1` (visible under **MCP result**, not the assistant bubble). Prose like “chart prepared” without a successful chart tool call means **nothing was rendered**.

### `prepare_chart_from_rows`

```json
{
  "title": "ETH/USD 4H — last 90d",
  "label": "ETH/USD",
  "toolResult": { "result": [ "... bars from fetch ..." ] }
}
```

Hyperliquid / DeFi fetch shape (pass **full** fetch JSON — example 7d @ 1h):

```json
{
  "title": "ETH-PERP 1H — last 7d",
  "toolResult": { "ohlcv": { "coin": "ETH", "interval": "1h", "lookbackDays": 7, "candles": [ "... from ctm_hyperliquid_fetch_ohlcv ..." ] } }
}
```

GMX returns a flat shape (not nested under `ohlcv`):

```json
{
  "title": "ETH/USD 1H",
  "toolResult": { "symbol": "ETH/USD [WETH-USDC]", "timeframe": "1h", "candles": [ "... from ctm_gmx_fetch_ohlcv ..." ] }
}
```

Or pass **`rows`** only when you also have fetch **`toolResult`** (preferred). **`options.maxPoints`** (default **400**) caps **on-screen** points only — it does **not** require pre-trimming vendor fetch candles. Never slice Hyperliquid/GMX `toolResult` to “last 24h” when the operator asked for 7d.

If `prepare_chart_from_rows` fails, read **`reason`** from the tool response and fix the payload — do not switch interval (e.g. 4H) or invent “payload too large” errors.

### Advanced: `prepare_chart`

Multi-series or custom **`overlays`**. Shorthand: **`bars`**, **`toolResult`**, **`candles`**.

## Built-in defaults (no custom `overlays`)

| Element | Default |
|---------|---------|
| Main overlay | **EMA(50)** |
| Oscillator | **RSI(14)** |
| Volume | Separate pane below price when rows include **`volume`** (DeFi/Hyperliquid, or third-party feeds that include it). **CoinGecko spot:** no volume — pane omitted |

CoinGecko spot charts use **`coins.ohlc.get`** only — real OHLC candles, no `marketChart` (see **`chart-periods`**).

**“1 hour” on public CoinGecko:** use **4H** candles (auto granularity), title **4H**, and tell the operator hourly spot needs Pro or a DeFi venue. **Pro** (`coingecko-pro`): may use **`interval: 'hourly'`** for 1–90 day windows.

**EMA(50) needs ≥50 bars** in the loaded series. For 7d @ 1h (~169 bars) EMA applies. Shorter lookback (e.g. 24h) still charts candles + RSI(14) but **no EMA line** — extend lookback per **`chart-periods`** when the operator wanted a longer window.

**`options.skipDefaultOverlays`: true** — candles + volume only.

## Customization

Operator overrides (preferred spot source, EMA period, etc.) go here when set on this node.
