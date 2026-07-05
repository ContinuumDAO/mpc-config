# Chart analysis: candlestick patterns

Use after OHLCV fetch. Tool: **`continuum__analyze_candlestick_patterns`**.

Reference: **`chart_analysis_docs`** (supported pattern ids, TA-Lib mapping).

Input: `{ "title": "<from fetch>", "toolResult": { ... } }` — optional **`patterns[]`** filter, **`focusBar`** (default last bar), **`minConfidence`** (0–1).

Requires at least **14** OHLCV bars.

## Output fields

- **`analysis.primaryPattern`**: strongest hit (name, description, direction, confidence).
- **`analysis.patterns[]`**: all hits above threshold.
- **`analysis.recommendation`**: buy / sell / hold aggregate.
- **`analysis.recommendationConfidence`**, **`analysis.rationale`**.

Direction is **bullish** / **bearish** / **neutral** (indecision) / **signal** (engulfing, marubozu, harami — read sign from hit).

## Narrative template

1. Name the primary pattern and whether it is bullish, bearish, or indecision.
2. State confidence and which bar it applies to (usually the last bar).
3. Quote the tool **`description`** for geometry; add trend/level context from sibling analyses if available.
4. Note standalone candlestick hit rates are weak (~50–55%); do not treat as sole trade signal.

## Plotting (separate step)

Analysis-only by default. Do **not** call `prepare_chart*` unless the operator asked to plot. Candlestick patterns have no dedicated overlay tool — use a normal candlestick chart if plotting.
