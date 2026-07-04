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

Per **`chart-ohlcv-sources`**: generic spot (no venue named) → **`agent_load_mcp_server({ serverId: "coinmarketcap-public" })`**, then CMC fetch (`get_crypto_ohlcv_historical` when Pro key on continuum-mcp, else **`get_kline_candles`** DEX proxy). **CoinGecko** only if CMC fails (load **`coingecko`** / **`coingecko-pro`** then). Do **not** load Hyperliquid/GMX unless the operator names that venue or perp.

| Goal | Default fetch | Fallback |
|------|---------------|----------|
| **Chart / plot** or **analysis** (`analyze_*`) | CMC OHLCV (CEX or DEX klines) | **`coins.ohlc.get`** (CoinGecko) |

**Do not use `coins.marketChart.get`** — synthetic candles and unreliable volume.

**Interval honesty (spot):**

- **CMC Pro hourly** or **DEX `1h`**: **1H** title is OK.
- **CoinGecko public fallback:** 3–30d → **~4H** auto; if operator asked **1H** → title **`4H`**, explain CMC/Pro/DeFi.
- **`coingecko-pro` fallback:** may use **`interval: 'hourly'`** for 1–90d.

See **`chart-periods`** for fetch examples.

If **`hyperliquid`** / **`gmx`** is already loaded and the operator names the venue or a specific interval → use that protocol’s **`fetch_ohlcv`** instead of CMC/CoinGecko.

## Optional per-type skills

Load with **`agent_load_skill`** when the operator picks a type or for richer narrative:

- `chart-analysis-trend`
- `chart-analysis-levels`
- `chart-analysis-momentum`
- `chart-analysis-range`

For orchestration plan drafts involving charts, load **`orchestration-chart-analysis`** (optional, on demand).
