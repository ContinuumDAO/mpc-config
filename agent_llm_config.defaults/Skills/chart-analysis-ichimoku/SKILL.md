---
name: chart-analysis-ichimoku
description: Use for Ichimoku cloud analysis. Skip otherwise.
---

# Chart analysis: Ichimoku cloud

Tool: **`continuum__analyze_ichimoku`**.

Works on **OHLCV candles** only (not line-only series). Same session binding as other analyses (`toolResult` or `{ title, ohlcvDigest }`). Needs enough bars for span + displacement (classic defaults need **~80+** bars).

**Defaults** (from **`trade-desk.yaml`** `universal`, injected by the node when tool args omit them):

| Field | Default | Role |
|-------|---------|------|
| `ichimokuConversionPeriod` | **9** | Tenkan-sen length |
| `ichimokuBasePeriod` | **26** | Kijun-sen length |
| `ichimokuSpanPeriod` | **52** | Senkou Span B length |
| `ichimokuDisplacement` | **26** | Cloud / Chikou displacement |
| `ichimokuTargetAtrMultiple` | **3** | Target = entry ± (multiple × ATR) |
| `entryProximityAtrPeriod` | **14** | ATR lookback used for that target |

Desk **`entryProximityPct`** (price %) gates cloud/kijun retest `clear` vs `unclear`. **Invalidation** is the cloud edge against the trade (and/or kijun). Overlay JSON shape: **`chart-defaults`**. Trade build: **`trade-defaults`**.

## Summarize from tool JSON

Quote **`analysis.conversion`**, **`analysis.base`**, **`analysis.cloudTop`**, **`analysis.cloudBottom`**, **`analysis.tkState`**, **`analysis.cloudPosition`**, periods/displacement, and **`analysis.ichimokuHighlight.summary`**.

Trade setup: **`analysis.ichimokuTradeSetup`** — summarize **`side`**, **`status`**, **`setupPurposeCode`**, **`strategy`**, entry/target/invalidation, and **`unclearReason`** when present. Nested alternate:

- Primary **tk_cross** (`ichi-tk`) → optional **`cloudAlternative`** (`ichi-cloud`)
- Primary **cloud** → optional **`tkCrossAlternative`** (`ichi-tk`)

| Signal | Report as |
|--------|-----------|
| Fresh TK cross with price outside cloud (aligned) | **`clear`** — `ichi-tk` |
| Price above/below cloud retesting kijun or cloud edge | **`clear`** — `ichi-cloud` |
| Price inside cloud / no cross / extended | **`unclear`** |

## Chart overlay (separate plotting step)

Analysis does **not** draw the cloud. When a chart is already prepared, merge the Ichimoku overlay per **`chart-defaults`** (params from **`trade-desk.yaml`**) into **`prepareReplay.overlays`**, then **`prepare_chart_from_rows`** with the same OHLCV session. The UI also offers an Ichimoku row in chat / Mini App overlays after analysis.
