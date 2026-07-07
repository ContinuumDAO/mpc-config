# Chart analysis: classic chart patterns

Use after OHLCV fetch. Tool: **`continuum__analyze_chart_patterns`**.

Reference: **`chart_analysis_docs`** (pattern ids, smoothing, trendline breakout options).

Input: `{ "title": "<from fetch>", "toolResult": { ... } }` — optional **`patterns[]`**, **`focusWindow`**, **`minConfidence`** (default 0.45), **`smoothHeadShoulders`** (default **true**), **`smoothWindow`** (`3`|`5`), **`retestTolerancePct`** (default **0.10**), **`retestAtrPeriod`** (default **14**), **`retestAtrMultiplier`** (default **1.0**).

You may also pass **`label`** (ignored by the tool). Prefer full fetch **`toolResult`** over hand-copied **`rows`**. If using **`rows`**, pass a candle **array** (stringified JSON arrays are accepted).

Requires **25–40** bars depending on pattern (cup & handle ~40; trendline patterns ~20). OHLC only — volume not required.

## Output fields

Read **`analysis.interpretation`** first (agent digest), then **`analysis.pattern`** for geometry.

- **`analysis.summary`**: one-line headline or *No obvious recent pattern found*.
- **`analysis.classification`**: `bullish` | `moderately_bullish` | `neutral` | `moderately_bearish` | `bearish` | `null`.
- **`analysis.pattern`**: `points`, `lines`, `levels`, `confidence`, `completionState`.
- **`analysis.patterns[]`**: all hits (full geometry in **`structuredContent`** only; slim agent view exposes **`patternMenu`** + **`patternCount`**).
- **`analysis.patternMenu[]`**: numbered picks — each row includes **`barSpan`** (UTC window) and **`keyLevels`** (labeled price/time anchors). Summarize **both time and price** per pattern; use **`patternNumber`** (1-based) on **`apply_chart_pattern_drawings`**. Ask the operator which row unless they already named one.
- **`analysis.applyHint`**: reminder to call apply tool, not prose, when drawing.
- **`analysis.primaryPattern`**: top hit summary with **`barSpan`** + **`keyLevels`** (not always highest confidence).

When empty: **`classification`** and **`pattern`** are **`null`** — say no credible pattern met threshold; do not invent geometry.

## Narrative template

1. Lead with **`summary`** and **`classification`** in plain language.
2. Summarize from **`interpretation`** (2–4 sentences on implication and completion state).
3. Present **`analysis.patternMenu`** as a **numbered table** (#, name, classification, confidence). For **each row**, quote from tool JSON:
   - **Time window:** `barSpan.fromTimeSec` → `barSpan.toTimeSec` as UTC (convert unix seconds to ISO, e.g. `2026-07-01T12:00:00Z`) plus `barSpan.barCount` bars
   - **Key levels:** every `keyLevels[]` item as **label @ price** and **time** when `timeSec` is set (e.g. neckline ~1720 at `2026-07-06T08:00:00Z`) — never invent timestamps or prices
4. Mention completion state and directional read from **`interpretation`** / **`classification`**.
5. Note standalone chart patterns are historically moderate signals (~55–65%); combine with trend, momentum, and key levels.
6. **Ask which menu row to draw on the chart** — unless the operator already picked one (e.g. “add pattern 1”, “draw the falling wedge”). Example: *“Which pattern should I overlay? (#1 Falling Wedge, #2 Rounding Bottom, …)”*

## Drawing on chart (mandatory tool — not prose)

When the operator asks to **draw**, **add**, **show**, or **overlay** a pattern on an **existing chart**:

**Hard rules**

- Call **`continuum__apply_chart_pattern_drawings`** — prose describing trendlines does **not** update the chart.
- **Never** claim a pattern is on the chart until **`apply_chart_pattern_drawings`** succeeds (`meta.warnings` mentions overlay applied; chart has `pattern_*` series).
- **Never** call **`prepare_chart_from_rows`** again for overlay-only requests — that recreates the chart and may change interval/window.
- Reuse the **same OHLCV session** — `{ title, ohlcvDigest }` from **`meta.sessionBind`** on follow-ups; do not re-fetch unless the operator changed symbol, interval, or lookback.

**Agent-facing analysis is slim** — chat JSON lists **`patternMenu`** (with **`patternNumber`**, 1-based) but omits full **`patterns[]`** geometry. The node keeps geometry server-side after **`analyze_chart_patterns`**. You do **not** need to paste `patterns[]` back on apply.

### When the operator picks a menu row

Use **`patternNumber`** (matches your table: row **#1** → `patternNumber: 1`):

```json
{
  "title": "ETH-PERP 1H — last 7d",
  "ohlcvDigest": "<from meta.sessionBind>",
  "patternNumber": 1
}
```

Also accepted: **`patternId`**, **`patternIndex`** (0-based), **`selectionMode`**: `primary` | `highest_confidence`.

The node injects **`prepareReplay`** + **`live`** from the bound chart when available. If apply fails, fix the payload — do **not** re-fetch at a different interval.

### Alternative: explicit geometry

Optional two-step when you need toggles or pasted geometry:

1. **`continuum__calculate_chart_pattern_drawings`** — same session `{ title, ohlcvDigest }` or full **`toolResult`** once.
2. **`continuum__apply_chart_pattern_drawings`** with **`drawings`** from step 1, plus **`prepareReplay`** + **`live`** from the prior chart.

Or pass **`analysis: { "pattern": { ... } }`** from full analysis output (object, not string) when geometry is available.

**Do not** re-fetch OHLCV, use `fetch_market_snapshot`, or pass analysis JSON as `toolResult`.

Prose-only replies are wrong when the operator asked to draw on the chart — the MCP tool must return `continuum/chart/v1`.
