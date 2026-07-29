# Chart defaults (plotting only)

**This skill is for charting/plotting — not analysis-only workflows.** For interpret/analyze without a chart, use **`chart-analysis-menu`** and **`analyze_*`** tools instead of **`prepare_chart*`**.

Charts: SDK **`prepare_chart_from_rows`** (single OHLCV feed) or **`prepare_chart`** (advanced). Reference: **`chart_docs`**.

**OHLCV sources:** skill **`chart-ohlcv-sources`** — **never auto-load** catalog servers; ask the operator to choose a provider when none is loaded in the session.

## Source selection (generic “chart ETH/BTC”)

| Operator request | Data source | Avoid |
|------------------|-------------|--------|
| “Chart ETH 4h”, “BTC chart”, spot (no venue/provider named) | **`coingecko`** / **`coingecko-pro`** if **loaded** in session; **else ask operator** (CoinGecko, CMC public, etc.) — do not auto-load | Hyperliquid/GMX/`ctm_*_fetch_ohlcv` unless venue named; silent **`agent_load_mcp_server`** |
| Names **CoinMarketCap** / **CMC** | **`coinmarketcap-public`** (`serverId` exact) — **not** catalog **`coinmarketcap`** unless API key configured | Claiming CMC loaded when load returned key error |
| Names **Hyperliquid**, **perp**, **GMX**, DEX pool, on-chain venue | **`load_defi_protocol`** then that protocol’s **`fetch_ohlcv`** — **not** **`agent_load_mcp_server`** | Treating DeFi **`protocolId`** as an MCP **`serverId`** |

Hyperliquid OHLCV is **perpetual** market data, not generic spot USD index. Do not use it for undifferentiated “chart ETH”.

## Workflow (strict order)

1. **Pick source type** (see **`chart-ohlcv-sources`**):
   - **DeFi venue** (Hyperliquid, GMX, …) → **`continuum__load_defi_protocol`** `{ "protocolId": "…" }`
   - **Catalog MCP** (CoinGecko, CMC public, …) → **`list_mcp_servers`** → **`continuum__agent_load_mcp_server`** for operator’s choice only
2. If no source enabled yet → **ask the operator** which provider to use; then step 1 for their choice.
3. **Fetch OHLCV** — e.g. **`ctm_hyperliquid_fetch_ohlcv`**, **`coingecko__execute`**, or **`coinmarketcap-public__get_kline_candles`**. Must succeed before charting.
4. **`continuum__prepare_chart_from_rows`** — first call: full fetch **object** as **`toolResult`**; follow-ups: **`{ title, ohlcvDigest }`** from **`meta.sessionBind`** (keep Hyperliquid **`timestampMs`** — never rewrite **`time`**).

**Never skip step 3.** Never pass a hand-edited subset of candles. Calling **`prepare_chart_from_rows`** with only **`title`** / **`label`** always fails validation.

Never `{}`. **Do not describe the chart in markdown** — the UI only renders when the chart tool returns `continuum/chart/v1` (visible under **MCP result**, not the assistant bubble). Prose like “chart prepared” without a successful chart tool call means **nothing was rendered**.

### After plotting — do not offer prose-only analysis

A successful **`prepare_chart_from_rows`** does **not** authorize interpretive analysis from memory. When the operator asks to **analyze**, **interpret**, or you want to offer follow-up analysis:

1. **Do not** invent phased narratives (“breakout mid-week”, “double top forming”) or numbered analysis menus without tool names.
2. **Do** call **`list_chart_analysis_options`** and present its catalog, **or** name the specific **`analyze_*`** tool for each option (see **`chart-analysis-menu`**).
3. **Do** call the matching **`analyze_*`** with the same OHLCV **`toolResult`** / **`ohlcvDigest`** before summarizing patterns, momentum, levels, or trend structure.
4. Factual one-liners (period high/low, bar count) may quote **`meta.ohlcvSummary`** from the chart tool only — nothing else.

### `prepare_chart_from_rows`

```json
{
  "title": "ETH/USD 4H — last 90d",
  "label": "ETH/USD",
  "toolResult": { "result": [ "... bars from fetch ..." ] }
}
```

Hyperliquid / DeFi fetch shape (pass **full** fetch JSON — examples):

```json
{
  "title": "ETH-PERP 1H — last 30d",
  "toolResult": { "ohlcv": { "coin": "ETH", "interval": "1h", "lookbackDays": 30, "candles": [ "... from ctm_hyperliquid_fetch_ohlcv ..." ] } }
}
```

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

Or pass **`rows`** only when you also have fetch **`toolResult`** (preferred). **`options.maxPoints`** (default **400**) caps **on-screen** candle points only — the full fetch window stays in **`meta.loadStatus.barCount`** (see **`meta.windowExpectation`** for interval × lookback). Never slice vendor `toolResult` or re-fetch at a coarser interval because the loaded bar count seems large.

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

Operator overrides (preferred spot source, EMA period, Bollinger overlay, etc.) go here when set on this node.

### Optional Bollinger overlay (when operator asks or after Bollinger analysis)

Merge into **`prepareReplay.overlays`** (does not replace default EMA/RSI unless you pass a full **`overlays`** array):

```json
{ "type": "bollinger", "sourceSeriesId": "<primary series id>", "period": 20, "stdDev": 2, "fill": true }
```

| Field | Default |
|-------|---------|
| `period` | 20 |
| `stdDev` | 2 |
| `fill` | true (shaded area between bands) |

Pass overrides on the tool call or in **`prepareReplay.overlays`** when the operator asks (e.g. “BB(14, 2.5)”).

Analysis workflow: **`chart-analysis-bollinger`**. Trade build / prefill: **`trade-defaults`** (`bb-fade`).

### Optional Donchian overlay (when operator asks or after Donchian breakout analysis)

Merge into **`prepareReplay.overlays`** (does not replace default EMA/RSI unless you pass a full **`overlays`** array). **`period`** is owned by **`trade-desk.yaml`** `universal.donchianPeriod` (default **20**); the node injects it on analyze/overlay apply when unset:

```json
{ "type": "donchian", "sourceSeriesId": "<primary series id>", "period": 20, "fill": true }
```

| Field | Default |
|-------|---------|
| `period` | **20** from **`trade-desk.yaml`** `donchianPeriod` (override in YAML or tool args) |
| `fill` | true (shaded area between channels) |

Requires a **candlestick** primary series. Analysis workflow: **`chart-analysis-donchian`**. Trade build: **`trade-defaults`** (`dc-ret` / `dc-brk`).

### Optional Z-score overlay (when operator asks or after Z-score analysis)

Merge into **`prepareReplay.overlays`**. **`period` / `entryZ` / `exitZ`** are owned by **`trade-desk.yaml`** (`zScorePeriod`, `zScoreEntry`, `zScoreExit`):

```json
{ "type": "zscore", "sourceSeriesId": "<primary series id>", "period": 20, "entryZ": 2, "exitZ": 0.5 }
```

| Field | Default |
|-------|---------|
| `period` | **20** from **`zScorePeriod`** |
| `entryZ` | **2** from **`zScoreEntry`** (horizontal guides at ±entry) |
| `exitZ` | **0.5** from **`zScoreExit`** (guides at ±exit) |

Renders in a **separate oscillator pane** (Z line + guides). Analysis workflow: **`chart-analysis-z-score`**. Trade build: **`trade-defaults`** (`zs-fade`).

### Optional moving averages overlay (when operator asks or after Moving averages analysis)

Requires **≥200** bars for SMA(200). Merge into **`prepareReplay.overlays`**:

```json
[
  { "type": "sma", "sourceSeriesId": "<primary series id>", "period": 50 },
  { "type": "sma", "sourceSeriesId": "<primary series id>", "period": 200 }
]
```

| Field | Default |
|-------|---------|
| `fastPeriod` | 50 |
| `slowPeriod` | 200 |
| `maType` | `sma` (or `ema` when overridden) |

Analysis workflow: **`chart-analysis-moving-averages`**. Trade build / prefill: **`trade-defaults`** (`ma-cross` / `ma-ret`).

### Divergence overlay (after Divergence detector analysis)

Do **not** hand-build divergence lines. After **`analyze_divergence`**, call **`apply_divergence_drawings`** with **`prepareReplay`** + **`live`** + `{ title, ohlcvDigest }` and the analysis JSON. That tool draws price + oscillator segments and **always ensures Stochastic RSI** is on the chart (plus RSI when needed). Analysis workflow: **`chart-analysis-divergence`**.
