# Chart analysis: Z-score mean reversion

Tool: **`continuum__analyze_z_score`**.

Works on **OHLCV candles** only (not line-only series). Same session binding as other analyses (`toolResult` or `{ title, ohlcvDigest }`).

**Defaults** (from **`trade-desk.yaml`** `universal`, injected by the node when tool args omit them):

| Field | Default | Role |
|-------|---------|------|
| `zScorePeriod` / `period` | **20** | SMA / SD lookback (bars) for analyze **and** chart overlay |
| `zScoreEntry` | **2** | Enter long when Z ≤ −entry; short when Z ≥ +entry |
| `zScoreExit` | **0.5** | Target when Z returns to ±exit vs mean (price = SMA ± exit×SD) |
| `zScoreStopAtrMultiple` | **2** | Invalidation = entry ± (multiple × ATR) |
| `zScoreAtrFilter` | **`none`** | `none` \| `contracting` (ATR\[t\] \< ATR\[t−1\]) |
| `entryProximityAtrPeriod` | **14** | ATR lookback for stop / filter |

Purpose code: **`zs-fade`**. Overlay JSON shape: **`chart-defaults`**. Trade build: **`trade-defaults`**.

## Summarize from tool JSON

Quote **`analysis.z`**, **`analysis.sma`**, **`analysis.sd`**, **`analysis.atr`**, **`analysis.period`**, **`analysis.entryZ`**, **`analysis.exitZ`**, **`analysis.stopAtrMultiple`**, and **`analysis.zScoreHighlight.summary`**.

Trade setup: **`analysis.zScoreTradeSetup`** — summarize **`side`**, **`status`**, **`setupPurposeCode`**, entry/target/invalidation, and **`unclearReason`** when present.

| Signal | Report as |
|--------|-----------|
| \|Z\| ≥ entry, ATR available, filter OK | **`clear`** — `zs-fade` |
| Inside threshold / filter blocked / no ATR | **`unclear`** |
| Last close already through ATR stop | **`invalidated: true`** |

## Chart overlay (separate plotting step)

Analysis does **not** draw the Z pane. When a chart is already prepared, merge the Z-score overlay per **`chart-defaults`** (period/entry/exit from **`trade-desk.yaml`**) into **`prepareReplay.overlays`**, then **`prepare_chart_from_rows`** with the same OHLCV session. The UI also offers a Z-score row in chat / Mini App overlays after analysis.
