---
name: chart-analysis-bollinger
description: Use for Bollinger Bands analysis workflows on OHLCV charts. Skip for unrelated plotting-only or non-BB tasks.
---

# Chart analysis: Bollinger bands

Tool: **`continuum__analyze_bollinger_bands`**.

Works on **OHLCV candles** or **line-only time series** (`{ time, value }`). Same session binding as other analyses (`toolResult` or `{ title, ohlcvDigest }`).

**Defaults** (from **`trade-desk.yaml`** `universal`, injected by the node when tool args omit them):

| Desk key | Default | Role |
|----------|---------|------|
| `bollingerPeriod` / `period` | **20** | Lookback (bars) for analyze **and** chart overlay |
| `bollingerStdDev` / `stdDev` | **2** | Standard-deviation multiplier |
| `bollingerEntryProximityMode` | **bandWidth** | Fade gate: **bandWidth** (% of upper−lower) or **atr** (% of one ATR bar) |
| `bollingerEntryProximityPct` | **5** | Proximity threshold (meaning depends on mode) |
| `entryProximityAtrPeriod` | **14** | ATR lookback when mode is **atr** |

**Trade fade rules** (`bb-fade`, build offsets): **`trade-defaults`**.

## Summarize from tool JSON

Quote **`analysis.upper`**, **`analysis.middle`**, **`analysis.lower`**, **`analysis.percentB`**, and **`analysis.bollingerHighlight.summary`**.

Trade setup: **`analysis.bollingerTradeSetup`** — summarize **`side`**, **`status`**, **`invalidated`**, entry/target bands, and **`unclearReason`** when present. Do not restate full fade rules here; they are in **`trade-defaults`** §1.

| Signal | Report as |
|--------|-----------|
| Within proximity of entry band, not invalidated | **`clear`** — entry at outer band, target opposite band |
| Mid-band / away from outer band | **`unclear`** — no entry price; not buildable until fade setup |
| Close beyond breached band | **`invalidated: true`** — **Invalid**, not buildable |

## Chart overlay (separate plotting step)

Analysis does **not** draw bands. When a chart is already prepared, merge the Bollinger overlay per **`chart-defaults`** (params from **`trade-desk.yaml`**) into **`prepareReplay.overlays`**, then **`prepare_chart_from_rows`** with the same OHLCV session. The UI also offers a Bollinger row in chat after analysis.
