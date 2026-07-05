# Chart analysis: classic chart patterns

Use after OHLCV fetch. Tool: **`continuum__analyze_chart_patterns`**.

Reference: **`chart_analysis_docs`** (pattern ids, smoothing, trendline breakout options).

Input: `{ "title": "<from fetch>", "toolResult": { ... } }` — optional **`patterns[]`**, **`focusWindow`**, **`minConfidence`** (default 0.45), **`smoothHeadShoulders`** (default **true**), **`smoothWindow`** (`3`|`5`), **`retestTolerancePct`** (default **0.10**), **`retestAtrPeriod`** (default **14**), **`retestAtrMultiplier`** (default **1.0**).

Requires **25–40** bars depending on pattern (cup & handle ~40; trendline patterns ~20). OHLC only — volume not required.

## Output fields

Read **`analysis.interpretation`** first (agent digest), then **`analysis.pattern`** for geometry.

- **`analysis.summary`**: one-line headline or *No obvious recent pattern found*.
- **`analysis.classification`**: `bullish` | `moderately_bullish` | `neutral` | `moderately_bearish` | `bearish` | `null`.
- **`analysis.pattern`**: `points`, `lines`, `levels`, `confidence`, `completionState`.
- **`analysis.patterns[]`**: all hits; **`analysis.primaryPattern`** is the top hit.

When empty: **`classification`** and **`pattern`** are **`null`** — say no credible pattern met threshold; do not invent geometry.

## Narrative template

1. Lead with **`summary`** and **`classification`** in plain language.
2. Summarize from **`interpretation`** (2–4 sentences on implication and completion state).
3. Mention pattern name, confidence, and key labeled points (neckline, rim, break level) if present.
4. Note standalone chart patterns are historically moderate signals (~55–65%); combine with trend, momentum, and key levels.

## Plotting (separate step)

Only if the operator asks to **draw** or **show on chart**:

1. **`calculate_chart_pattern_drawings`** with the **same OHLCV `toolResult`** as the original chart.
2. **`apply_chart_pattern_drawings`** — **do not** call `prepare_chart_from_rows` again.

```json
{
  "title": "ETH-PERP 1H — last 7d",
  "toolResult": { "... same hyperliquid fetch_ohlcv JSON as original chart ..." },
  "prepareReplay": { "... from prepare_chart_from_rows output ..." },
  "live": { "... from prepare_chart_from_rows output when present ..." },
  "drawings": { "... entire drawings object from calculate_chart_pattern_drawings ..." }
}
```

Pass the **`drawings` object verbatim** — do **not** rebuild `horizontalLevels` from `pattern.levels`.

Or pass **`analysis: { "pattern": { ... } }`** from **`analyze_chart_patterns`** (object, not string) — geometry is rebuilt server-side.

**Do not** re-fetch OHLCV, use `fetch_market_snapshot`, or pass analysis JSON as `toolResult`.

Prose-only replies are wrong when the operator asked to draw on the chart — the MCP tool must return `continuum/chart/v1`.
