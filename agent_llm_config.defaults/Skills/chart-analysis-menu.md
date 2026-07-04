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

## Optional per-type skills

Load with **`agent_load_skill`** when the operator picks a type or for richer narrative:

- `chart-analysis-trend`
- `chart-analysis-levels`
- `chart-analysis-momentum`

For orchestration plan drafts involving charts, load **`orchestration-chart-analysis`** (optional, on demand).
