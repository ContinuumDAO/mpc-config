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

## Spot data source (when DeFi not named)

Per **`chart-ohlcv-sources`**:

1. Use **`coingecko`** / **`coingecko-pro`** if **loaded** in this chat.
2. If **no other OHLCV source is loaded**, load **`coinmarketcap-public`** and fetch (keyless **`get_kline_candles`** works without API key).

Do **not** treat missing **`COINMARKETCAP_API_KEY`** on catalog **`coinmarketcap`** as blocking **`coinmarketcap-public`**.

| Goal | When CoinGecko loaded | When nothing else loaded |
|------|----------------------|---------------------------|
| **Chart / plot** or **`analyze_*`** | **`coins.ohlc.get`** | **`coinmarketcap-public`** klines (or Pro OHLCV if key on continuum-mcp) |

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

For orchestration plan drafts involving charts, load **`orchestration-chart-analysis`** (optional, on demand).
