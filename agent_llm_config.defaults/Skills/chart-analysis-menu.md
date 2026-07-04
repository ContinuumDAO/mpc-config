# Chart analysis menu

Reference: MCP resource **`chart_analysis_docs`**.

## Analysis vs plotting

| Operator intent | Use | Do not use |
|-----------------|-----|------------|
| Interpret, analyze, outlook, “what does it mean” (no specific type) | **`list_chart_analysis_options`** → numbered **text menu** → one **`analyze_*`** | `prepare_chart*`, `apply_chart_drawings`, `calculate_*` |
| Named analysis (“momentum analysis”, “trend structure”) | Matching **`analyze_*`** after OHLCV fetch | Chart prepare unless they also asked to plot |
| Chart, plot, draw on chart, show trend lines | **`chart-defaults`** plotting workflow | `analyze_*` unless they also asked for analysis prose |

## Vague analysis workflow

1. Call **`continuum__list_chart_analysis_options`**.
2. Present a numbered list from `analyses[]` (label + description).
3. Ask the operator to pick a number or id.
4. After selection: fetch OHLCV per operator request (symbol, source, interval, lookback — use **`chart-periods`** for lookback heuristics).
5. Call **one** `analyze_*` with `toolResult` from the fetch.
6. Summarize from the tool JSON in the reply.

**Never** auto-run trend line drawing or replot a chart for vague “interpret” / “analyze” prompts.

## Spot data source (default when DeFi not loaded)

Per **`chart-defaults`**: generic spot (no venue named) → load **`coingecko`**, or **`coingecko-pro`** when the node has **`COINGECKO_API_KEY`**. Do **not** load Hyperliquid/GMX unless the operator names that venue or perp.

| Goal | CoinGecko fetch | Notes |
|------|-----------------|-------|
| **Chart / plot** or **analysis** (`analyze_*`) | **`coins.ohlc.get`** | Real OHLC; one call; **no volume** |

**Do not use `coins.marketChart.get`** — synthetic candles and unreliable volume.

**Interval honesty (spot):**

- **Public `coingecko`:** 3–30d windows → **~4H** auto. If the operator asked for **1H** → fetch **4H anyway**, title **`4H`**, and **explain** that hourly spot needs **Pro** or **Hyperliquid/GMX**.
- **`coingecko-pro`:** may pass **`interval: 'hourly'`** on `ohlc.get` for 1 / 7 / 14 / 30 / 90 days — then **1H** title is OK.

See **`chart-periods`** for execute examples.

If **`hyperliquid`** / **`gmx`** is already loaded and the operator names the venue or a specific interval → use that protocol’s **`fetch_ohlcv`** instead of CoinGecko.

## Optional per-type skills

Load with **`agent_load_skill`** when the operator picks a type or for richer narrative:

- `chart-analysis-trend`
- `chart-analysis-levels`
- `chart-analysis-momentum`
- `chart-analysis-range`

For orchestration plan drafts involving charts, load **`orchestration-chart-analysis`** (optional, on demand).
