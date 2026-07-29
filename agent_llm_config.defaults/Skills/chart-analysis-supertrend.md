# Chart analysis: Supertrend

Tool: **`continuum__analyze_supertrend`**.

Works on **OHLCV candles** only (not line-only series). Same session binding as other analyses (`toolResult` or `{ title, ohlcvDigest }`).

**Defaults** (from **`trade-desk.yaml`** `universal`, injected by the node when tool args omit them):

| Field | Default | Role |
|-------|---------|------|
| `supertrendPeriod` / `period` | **10** | ATR length for analyze **and** chart overlay |
| `supertrendMultiplier` / `multiplier` | **3** | ATR multiplier for trail width |
| `supertrendEntryMode` | **`flip`** | Primary setup: direction flip (`st-flip`) |
| | `retest` | Primary setup: price near trail in trend direction (`st-ret`) |
| `supertrendTargetAtrMultiple` | **3** | Target = entry ± (multiple × ATR) |
| `entryProximityAtrPeriod` | **14** | ATR lookback used for that target |

Desk **`entryProximityPct`** (price %) gates `clear` vs `unclear`. **Invalidation** is the Supertrend trail. Overlay JSON shape: **`chart-defaults`**. Trade build: **`trade-defaults`**.

## Summarize from tool JSON

Quote **`analysis.supertrend`**, **`analysis.direction`**, **`analysis.period`**, **`analysis.multiplier`**, **`analysis.entryMode`**, and **`analysis.supertrendHighlight.summary`**.

Trade setup: **`analysis.supertrendTradeSetup`** — summarize **`side`**, **`status`**, **`setupPurposeCode`**, **`entryMode`**, entry/target/invalidation, and **`unclearReason`** when present. Nested alternate:

- Primary **flip** → optional **`retestAlternative`** (`st-ret`)
- Primary **retest** → optional **`flipAlternative`** (`st-flip`)

| Signal | Report as |
|--------|-----------|
| Fresh/recent direction flip (default mode) | **`clear`** — `st-flip` |
| Price retesting trail in trend direction | **`clear`** — `st-ret` |
| No flip / no retest / extended | **`unclear`** |
| Close on wrong side of trail (retest mode) | **`invalidated: true`** |

## Chart overlay (separate plotting step)

Analysis does **not** draw Supertrend. When a chart is already prepared, merge the Supertrend overlay per **`chart-defaults`** (period/multiplier from **`trade-desk.yaml`**) into **`prepareReplay.overlays`**, then **`prepare_chart_from_rows`** with the same OHLCV session. The UI also offers a Supertrend row in chat / Mini App overlays after analysis.
