# Chart analysis: range / volatility

Tool: **`continuum__analyze_range_volatility`**.

Summarize **`analysis.rangeHigh`**, **`analysis.rangeLow`**, **`analysis.rangePct`**, and **`analysis.compression`** (`compressing` | `expanding` | `stable`).

When present, mention **`analysis.atr`** / **`analysis.atrPct`** and compare **`analysis.recentRangePct`** vs **`analysis.priorRangePct`**.

Optional **`analysis.fibRange`** gives swing high/low bounds for the recent trend leg.

For on-chart fib levels (separate step): `calculate_fibonacci_range` → `apply_chart_drawings`.
