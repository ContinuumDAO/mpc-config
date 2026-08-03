---
name: chart-analysis-donchian
description: Use for Donchian breakout analysis. Skip otherwise.
---

# Chart analysis: Donchian breakout

Tool: **`continuum__analyze_donchian_breakout`**.

Works on **OHLCV candles** only (not line-only series). Same session binding as other analyses (`toolResult` or `{ title, ohlcvDigest }`).

**Defaults** (from **`trade-desk.yaml`** `universal`, injected by the node when tool args omit them):

| Field | Default | Role |
|-------|---------|------|
| `donchianPeriod` / `period` | **20** | Channel length (bars) for analyze **and** chart overlay |
| `donchianEntryMode` | **`retest`** | Primary setup: post-breakout retest (`dc-ret`) |
| | `immediate` | Primary setup: channel break (`dc-brk`) |
| `donchianTargetAtrMultiple` | **3** | Target = entry ± (multiple × ATR) |
| `entryProximityAtrPeriod` | **14** | ATR lookback used for that target |

Desk **`entryProximityPct`** (price %) gates `clear` vs `unclear`. **Invalidation** is the Donchian mid-channel. Overlay JSON shape: **`chart-defaults`**. Trade build: **`trade-defaults`**.

## Summarize from tool JSON

Quote **`analysis.upper`**, **`analysis.middle`**, **`analysis.lower`**, **`analysis.priorUpper`**, **`analysis.priorLower`**, **`analysis.period`**, **`analysis.entryMode`**, and **`analysis.donchianHighlight.summary`**.

Trade setup: **`analysis.donchianTradeSetup`** — summarize **`side`**, **`status`**, **`setupPurposeCode`**, **`entryMode`**, entry/target/invalidation, and **`unclearReason`** when present. Nested alternate:

- Primary **retest** → optional **`immediateAlternative`** (`dc-brk`)
- Primary **immediate** → optional **`breakRetestAlternative`** (`dc-ret`)

| Signal | Report as |
|--------|-----------|
| Retest near broken band (default mode) | **`clear`** — `dc-ret` |
| Fresh/holding breakout near band (immediate mode) | **`clear`** — `dc-brk` |
| No break / no retest / extended | **`unclear`** |
| Failed retest (close back through broken band) | **`invalidated: true`** |

## Chart overlay (separate plotting step)

Analysis does **not** draw channels. When a chart is already prepared, merge the Donchian overlay per **`chart-defaults`** (period from **`trade-desk.yaml` `donchianPeriod`**) into **`prepareReplay.overlays`**, then **`prepare_chart_from_rows`** with the same OHLCV session. The UI also offers a Donchian row in chat / Mini App overlays after analysis.
