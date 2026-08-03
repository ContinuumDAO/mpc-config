---
name: chart-analysis-divergence
description: Use for momentum/price divergence analysis. Skip otherwise.
---

# Chart analysis: divergence detector

Tool: **`continuum__analyze_divergence`**.

Detects **regular** and **hidden** bullish/bearish divergences between price and **RSI** and/or **Stochastic RSI** (%K). Default `oscillator: both`.

## Summarize

1. Quote **`analysis.divergenceHighlight.summary`** (PRIMARY kind, oscillator, long/short, confidence).
2. Note **`analysis.primary`** (`kind`, `side`, `confidence`, pivot times) when present.
3. Mention secondary count from **`analysis.divergences`** only briefly — PRIMARY drives bias.
4. When **`divergenceTradeSetup.status === "clear"`**, cite entry / target / invalidation (pivot-structure measured move: swing size projected from last close).

Do **not** invent divergences from a visible chart — call the tool first.

## Draw on chart

**`analyze_divergence` alone does not update the chart** (Telegram Mini App / node chat). When the operator asks to overlay/draw divergences:

1. Call **`continuum__apply_divergence_drawings`** with `{ title, ohlcvDigest }` + **`prepareReplay`** + **`live`** from the existing chart, and **`analysis`** from this tool (includes **`divergenceOverlay`**).
2. The apply tool **always adds Stochastic RSI** if missing, and RSI when segments need it.
3. Do **not** call **`prepare_chart_from_rows`** again. Confirm drawn only after apply succeeds and the chart tool result returns.

## Trade

Clear setups upsert **`divergence`** trade ideas (`setupPurposeCode: div`). Build with **`continuum__build_trade_from_divergence`** / **`build_trade_from_trade_idea`**. Prefill policy: skill **`trade-defaults`**.
