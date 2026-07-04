# Orchestration: chart analysis and plotting

Load with **`agent_load_skill("orchestration-chart-analysis")`** when drafting a manifest whose operator goal involves charts or market analysis. **Do not** assume charts are required for every plan.

Reference: **`chart_analysis_docs`**, **`chart_docs`**.

## Task-shape patterns (no hardcoded symbols or intervals)

All **symbol, venue, candle interval, and lookback** come from the operator’s stated goal — document your choices in each `tasks[].prompt`.

### Analysis-only sub-agent

- Fetch OHLCV or line time-series per task prompt parameters.
- Run chosen **`analyze_*`** or **`analyze_time_series_*`** tool(s).
- Return **`mpc-task-result v1`** with analysis JSON in the body.
- **Must not** call `prepare_chart*` or attach `continuum/chart/v1`.

Suggested skills on task: `chart-analysis-<type>`, `chart-analysis-time-series` (metrics), `chart-periods`, `chart-ohlcv-sources`.

### Plot-only sub-agent

- Fetch OHLCV with the same parameters as the analysis task (or operator goal if no analysis task).
- **`prepare_chart_from_rows`** → optional **`apply_chart_drawings`** if visuals requested or prior analysis is in the KeyGen thread.
- Attach chart via **`post_key_gen_chart_attachment`**; reference in task result.

Suggested skills on task: `chart-defaults`, `chart-periods`, `chart-ohlcv-sources`.

### Optional handoff

A plot task may read sibling analysis from the KeyGen thread and deliberately apply related drawings — still a **separate plot step**, not automatic.

The planner decides: one task vs two, which analysis types, whether a chart task is needed at all.

## Illustrative manifest (placeholders only)

```yaml
tasks:
  - id: "<id>-analysis"
    prompt: |
      Using the symbol, data source, interval, and lookback from the operator goal above,
      fetch OHLCV and run <analyze_* tool>. Return mpc-task-result v1 with analysis JSON only.
      Do not prepare or attach a chart.
    mcpServers: ["<fetch-server>", "continuum"]
    skills: ["chart-analysis-<type>", "chart-periods"]

  - id: "<id>-chart"
    prompt: |
      Using the same parameters as the analysis task (or operator goal if no analysis task),
      fetch OHLCV and prepare_chart_from_rows. Attach chart via post_key_gen_chart_attachment.
      Apply drawings only if the operator requested visuals or prior analysis is on the thread.
    mcpServers: ["<fetch-server>", "continuum"]
    skills: ["chart-defaults", "chart-periods"]
```
