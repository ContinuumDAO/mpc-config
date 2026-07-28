# Chart analysis menu

Reference: MCP resource **`chart_analysis_docs`**.

## Hard rule — analysis requires tools

**Never perform or offer chart/OHLCV analysis in prose alone.** Every interpretive claim (trend, momentum, key levels, candlestick patterns, classic patterns, range/volatility, outlook) must come from a matching **`analyze_*`** tool result on **this turn**, or from **`meta.ohlcvSummary`** / **`analysis.*`** fields in that JSON — not from visual guessing or memory.

| Forbidden | Required instead |
|-----------|------------------|
| Invented “quick read” of price action after plotting | Quote **`meta.ohlcvSummary`** from the chart tool only, **or** call **`analyze_*`** |
| Numbered menu of analysis types you made up (“1. Momentum 2. Key levels …”) | **`list_chart_analysis_options`** → numbered menu from **`analyses[]`** (each row names its **`id`** / tool) |
| Classic pattern names, channels, double tops, etc. without a tool | **`analyze_chart_patterns`** → summarize **`analysis.patternMenu`** |
| “Want me to layer on RSI / key levels / patterns?” without naming tools | Offer **`list_chart_analysis_options`**, or list options with explicit tool names (e.g. **`analyze_momentum`**, **`analyze_key_levels`**, **`analyze_key_level_fibonacci`**, **`analyze_chart_patterns`**) |
| Analysis prose after the operator picks an option | Call the matching **`analyze_*`** first, then summarize tool JSON |

**After a chart is already on screen:** reuse the same OHLCV session (`toolResult` or `{ title, ohlcvDigest }` from **`meta.sessionBind`**) and call the appropriate **`analyze_*`** — do **not** skip tools because the candles are visible in the UI.

**Allowed without `analyze_*`:** routing only (ask operator to pick analysis type via **`list_chart_analysis_options`**), quoting **`meta.ohlcvSummary`** high/low/lastClose/barCount from the last chart or fetch tool, and plotting/drawing via **`prepare_chart*`** / **`apply_*`** tools.

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
| Candles / OHLCV | `analyze_trend_structure`, `analyze_key_levels`, `analyze_key_level_fibonacci`, `analyze_momentum`, `analyze_range_volatility`, `analyze_bollinger_bands`, `analyze_donchian_breakout`, `analyze_z_score`, `analyze_moving_averages`, `analyze_candlestick_patterns`, `analyze_chart_patterns` |
| Line-only `{ time, value }` metrics | `analyze_time_series_trend`, `analyze_time_series_momentum`, `analyze_time_series_stats`, `analyze_bollinger_bands` |

Load skill **`chart-analysis-time-series`** when interpreting TVL, fees, or custom metrics.

**Never** auto-run trend line drawing or replot a chart for vague “interpret” / “analyze” prompts.

## Spot data source (when DeFi not named)

Per **`chart-ohlcv-sources`** — **never auto-load** market-data MCP servers.

1. Use **`coingecko`** / **`coingecko-pro`** if **loaded** in this chat → **`coingecko__execute`** (`coins.ohlc.get`).
2. If **no OHLCV source loaded** → **ask the operator** which provider to use (CoinGecko, **`coinmarketcap-public`**, etc.); load only after they choose.

| Goal | When CoinGecko loaded | When nothing else loaded |
|------|----------------------|---------------------------|
| **`analyze_*` only** | fetch → **`analyze_*`** with `toolResult` | Ask operator → load chosen source → fetch → **`analyze_*`** |
| **Chart / plot** | fetch → **`prepare_chart_from_rows`** | Ask operator → load → fetch → **`prepare_chart_from_rows`** |

If load of **`coinmarketcap`** fails on missing key → offer **`coinmarketcap-public`** or **`coingecko`**; let the operator pick — do not claim CMC is loaded.

**Do not use `coins.marketChart.get`** — synthetic candles and unreliable volume.

**Interval honesty (spot):**

- **CoinGecko public:** 3–30d → **~4H** auto; if operator asked **1H** → title **`4H`**, explain Pro/DeFi/CMC hourly options.
- **`coingecko-pro`:** may use **`interval: 'hourly'`** for 1–90d.
- **CMC klines / Pro OHLCV:** title matches fetched interval.

See **`chart-periods`**.

If **`hyperliquid`** / **`arcus`** / **`gmx`** (or operator names the venue) → **`continuum__load_defi_protocol`** `{ "protocolId": "hyperliquid" | "arcus" | "gmx" }`, then that protocol’s **`fetch_ohlcv`**. **Do not** use **`agent_load_mcp_server`** for DeFi protocol ids.

## Optional per-type skills

Load with **`agent_load_skill`** when the operator picks a type or for richer narrative:

- `chart-analysis-trend`
- `chart-analysis-levels`
- `chart-analysis-momentum`
- `chart-analysis-range`
- `chart-analysis-bollinger` (summarize `analyze_bollinger_bands`; defaults in **`chart-defaults`** / **`trade-defaults`**)
- `chart-analysis-donchian` (summarize `analyze_donchian_breakout`; period/mode from **`trade-desk.yaml`**; overlay in **`chart-defaults`**)
- `chart-analysis-z-score` (summarize `analyze_z_score`; knobs from **`trade-desk.yaml`**; overlay in **`chart-defaults`**)
- `chart-analysis-moving-averages` (summarize `analyze_moving_averages`; crossover + proximity retest; defaults in **`chart-defaults`** / **`trade-defaults`**)
- `chart-analysis-patterns` (1–3 bar candlestick recognition)
- `chart-analysis-classic-patterns` (multi-bar H&S, doubles, triangles, cup & handle, trendline breakout/retest — **ask which menu # to draw** unless operator picked one)
- `chart-analysis-time-series` (line-only metrics)

For orchestration plan drafts involving charts, load **`orchestration-chart-analysis`** (optional, on demand).

## Trade ideas — operator conclusion

When the operator asks for a **conclusion**, **consensus**, or **verdict** across analyses (e.g. “should I trade now?”):

1. Call **`continuum__list_trade_ideas`** first.
2. Cite **`tradeIdeaNumber`** from `items[]` (menu order — not analysis run order).
3. Quote **`chartDataSource`**, **`chartInterval`**, **`chartBarCount`** from each item — do not guess from chart title.

See **`trade-defaults`** §8.
