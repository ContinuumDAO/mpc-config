# Chart analysis: trend structure

Use after OHLCV fetch. Tool: **`continuum__analyze_trend_structure`**.

Input: `{ "title": "<from fetch>", "toolResult": { ... } }` — optional **`label`** from fetch metadata is accepted (ignored by the tool).

## Output fields

- **`analysis.bias`**: `bullish` | `bearish` | `neutral` (price vs swing mid-range).
- **`analysis.structure`**: `higher_highs` | `lower_lows` | `range` | `mixed`.
- **`analysis.swingHigh` / `swingLow`**: recent swing pivot prices and times.
- **`analysis.phases`**: early / mid / recent segment direction.
- **`analysis.trendLines`**: scored support/resistance line summaries (**not drawable** — no `pointA`/`pointB`).
- **`analysis.trendLineMenu`**: ranked drawable lines (for **`apply_trend_line_drawings`** by menu #).
- **`analysis.trendStructureTradeSetup`**: auto-upserted trade idea — **`trend-ret`** limit at primary support (long bias) or resistance (short bias) trend-line **retest**; invalidation at recent swing; target at opposing swing when available.

## Trade idea (`trend_structure`)

| Field | Meaning |
|-------|---------|
| `setupPurposeCode` | **`trend-ret`** |
| `entryOffsetMode` | Always **`retest`** |
| `trendLineNumber` | 1-based menu index for bias-aligned entry line |
| `primaryTrendKind` | `support` (long) or `resistance` (short) |
| `status` | `clear` when bias, line kind, and swing invalidation align |

Build/prefill: skill **`trade-defaults`** §6 (perp limit on **hyperliquid** / **gmx**; **uniswap** spot only when price is at entry).

## Narrative template

1. State bias and structure in plain language.
2. Mention swing high/low as key reference levels.
3. Summarize phase progression (e.g. decline → base → consolidation).
4. Note strongest trend-line scores if present.
5. If `trendStructureTradeSetup.status === 'clear'`, summarize side, retest entry, target, and invalidation from setup fields.

## Plotting (separate step)

Only if the operator asks to **draw** or **show on chart**:

1. **`calculate_trend_lines`** with the **same OHLCV `toolResult`** as the original chart.
2. **`apply_chart_drawings`** — **do not** call `prepare_chart_from_rows` again.

Or apply one menu row directly after analyze:

- **`apply_trend_line_drawings`** with **`trendLineNumber`** from **`trendLineMenu`**.

```json
{
  "title": "BTC-PERP 1H — last 7d",
  "toolResult": { "... same hyperliquid fetch_ohlcv JSON as original chart ..." },
  "prepareReplay": { "... from prepare_chart_from_rows output ..." },
  "live": { "... from prepare_chart_from_rows output when present ..." },
  "trendLines": [ "... entire trendLines array from calculate_trend_lines ..." ]
}
```

**Do not** pass `analyze_trend_structure` JSON as `toolResult` — it has no candles. **Do not** re-fetch OHLCV or use `fetch_market_snapshot` unless the operator changed symbol/interval/lookback.

Prose-only replies are wrong when the operator asked to draw on the chart — the MCP tool must return `continuum/chart/v1`.
