# Chart analysis menu

Reference: MCP resource **`chart_analysis_docs`**.

## Analysis vs plotting

| Operator intent | Use | Do not use |
|-----------------|-----|------------|
| Load/fetch OHLCV **and analyze** (no “chart” / “plot”) | Fetch → **`analyze_*`** with `toolResult` | `prepare_chart*` |
| Interpret, analyze, outlook, “what does it mean” (no specific type) | **`list_chart_analysis_options`** → numbered **text menu** → one **`analyze_*`** | `prepare_chart*`, `apply_chart_drawings`, `calculate_*` |
| Named analysis (“momentum analysis”, “trend structure”) | Matching **`analyze_*`** after OHLCV fetch | Chart prepare unless they also asked to plot |
| Chart, plot, draw on chart, show trend lines | **`chart-defaults`** plotting workflow | `analyze_*` unless they also asked for analysis prose |

## Vague analysis workflow

1. Call **`continuum__list_chart_analysis_options`**.
2. Present a numbered list from `analyses[]` (label + description). Group mentally by **`dataKind`**: `ohlcv` vs `time_series`.
3. Ask the operator to pick a number or id.
4. After selection: fetch data per operator request (OHLCV or line metric — use **`chart-periods`** for lookback heuristics on candles).
5. Call **one** matching `analyze_*` with `toolResult` from the fetch.
6. Summarize from the tool JSON in the reply.

### OHLCV vs time-series routing

| Fetch result | Analysis tools |
|--------------|----------------|
| Candles / OHLCV | `analyze_trend_structure`, `analyze_key_levels`, `analyze_momentum`, `analyze_range_volatility`, `analyze_candlestick_patterns`, `analyze_chart_patterns` |
| Line-only `{ time, value }` metrics | `analyze_time_series_trend`, `analyze_time_series_momentum`, `analyze_time_series_stats` |

Load skill **`chart-analysis-time-series`** when interpreting TVL, fees, or custom metrics.

**Never** auto-run trend line drawing or replot a chart for vague “interpret” / “analyze” prompts.

## Spot data source (when DeFi not named)

Per **`chart-ohlcv-sources`**:

1. Use **`coingecko`** / **`coingecko-pro`** if **loaded** in this chat → **`coingecko__execute`** (`coins.ohlc.get`).
2. If **no other OHLCV source loaded**, load **`coinmarketcap-public`** (id exact) — **not** catalog **`coinmarketcap`** without API key.

| Goal | When CoinGecko loaded | When nothing else loaded |
|------|----------------------|---------------------------|
| **`analyze_*` only** | fetch → **`analyze_*`** with `toolResult` | **`coinmarketcap-public`** klines → **`analyze_*`** |
| **Chart / plot** | fetch → **`prepare_chart_from_rows`** | fetch → **`prepare_chart_from_rows`** |

If load of **`coinmarketcap`** fails on missing key → load **`coinmarketcap-public`** or use **`coingecko`**; do not claim CMC is loaded.

**Do not use `coins.marketChart.get`** — synthetic candles and unreliable volume.

**Interval honesty (spot):**

- **CoinGecko public:** 3–30d → **~4H** auto; if operator asked **1H** → title **`4H`**, explain Pro/DeFi/CMC hourly options.
- **`coingecko-pro`:** may use **`interval: 'hourly'`** for 1–90d.
- **CMC klines / Pro OHLCV:** title matches fetched interval.

See **`chart-periods`**.

If **`hyperliquid`** / **`gmx`** is loaded and the operator names the venue → use that protocol’s **`fetch_ohlcv`**.

## Optional per-type skills

Load with **`agent_load_skill`** when the operator picks a type or for richer narrative:

- `chart-analysis-trend`
- `chart-analysis-levels`
- `chart-analysis-momentum`
- `chart-analysis-range`
- `chart-analysis-patterns` (1–3 bar candlestick recognition)
- `chart-analysis-classic-patterns` (multi-bar H&S, doubles, triangles, cup & handle, trendline breakout/retest)
- `chart-analysis-time-series` (line-only metrics)

For orchestration plan drafts involving charts, load **`orchestration-chart-analysis`** (optional, on demand).
