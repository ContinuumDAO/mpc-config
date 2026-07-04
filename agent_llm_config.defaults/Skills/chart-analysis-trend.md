# Chart analysis: trend structure

Use after OHLCV fetch. Tool: **`continuum__analyze_trend_structure`**.

Input: `{ "title": "<from fetch>", "toolResult": { ... } }` — optional **`label`** from fetch metadata is accepted (ignored by the tool).

## Output fields

- **`analysis.bias`**: `bullish` | `bearish` | `neutral` (price vs swing mid-range).
- **`analysis.structure`**: `higher_highs` | `lower_lows` | `range` | `mixed`.
- **`analysis.swingHigh` / `swingLow`**: recent swing pivot prices and times.
- **`analysis.phases`**: early / mid / recent segment direction.
- **`analysis.trendLines`**: scored support/resistance line summaries (not chart geometry).

## Narrative template

1. State bias and structure in plain language.
2. Mention swing high/low as key reference levels.
3. Summarize phase progression (e.g. decline → base → consolidation).
4. Note strongest trend-line scores if present.

## Plotting (separate step)

Only if the operator asks to **draw** or **show on chart**: `calculate_trend_lines` → `apply_chart_drawings`. Do not call prepare tools for analysis-only requests.
