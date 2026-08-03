---
name: chart-analysis-moving-averages
description: Use for moving-average analysis workflows. Skip otherwise.
---

# Chart analysis: Moving averages

Tool: **`continuum__analyze_moving_averages`**.

Works on **OHLCV candles** only. Same session binding as other analyses (`toolResult` or `{ title, ohlcvDigest }`).

**Defaults** (`fastPeriod` **50**, `slowPeriod` **200**, `maType` **sma**, overlay JSON): **`chart-defaults`**. **Trade rules** (`ma-cross`, `ma-ret`, proximity, build offsets): **`trade-defaults`**.

## Summarize from tool JSON

Quote **`analysis.fastMa`**, **`analysis.slowMa`**, **`analysis.crossoverState`**, **`analysis.barsSinceCrossover`**, and **`analysis.movingAveragesHighlight.summary`**.

Trade setup: **`analysis.movingAveragesTradeSetup`** — always quote **`tradeSummary`** (states crossover vs proximity+retest). Also summarize **`strategy`**, **`side`**, **`status`**, **`confidence`**, and **`unclearReason`** when present.

| Signal | Report as |
|--------|-----------|
| Fresh golden/death cross within window, `status: clear` | **Crossover** — quote golden cross or death cross; entry at last close |
| Established regime, price within proximity of slow MA, `status: clear` | **Proximity + retest** — quote bullish/bearish regime; limit at slow MA |
| Stale crossover or price away from entry | **`unclear`** — quote `tradeSummary`; no entry price; not buildable |
| `fastMa ≈ slowMa` / insufficient bars | **`unclear`** — no directional regime |

Do not restate full trade rules here; they are in **`trade-defaults`** §1.

## Chart overlay (separate plotting step)

Analysis does **not** draw MAs. When a chart is already prepared, merge two SMA/EMA overlays per **`chart-defaults`** into **`prepareReplay.overlays`**, then **`prepare_chart_from_rows`** with the same OHLCV session. The UI also offers a moving averages row in chat after analysis.
