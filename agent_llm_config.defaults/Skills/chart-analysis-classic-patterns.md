# Chart analysis: classic chart patterns

Use after OHLCV fetch. Tool: **`continuum__analyze_chart_patterns`**.

**Do not name or interpret classic patterns in prose without calling this tool first.** If the operator asks for classic / multi-bar pattern analysis, run **`analyze_chart_patterns`** and summarize **`analysis.patternMenu`** — never invent patterns from a visible chart alone.

Reference: **`chart_analysis_docs`** (pattern ids, smoothing, trendline breakout options).

Input: `{ "title": "<from fetch>", "toolResult": { ... } }` — optional **`patterns[]`**, **`focusWindow`**, **`minConfidence`** (default 0.45), **`smoothHeadShoulders`** (default **true**), **`smoothWindow`** (`3`|`5`), **`retestTolerancePct`** (default **0.10**), **`retestAtrPeriod`** (default **14**), **`retestAtrMultiplier`** (default **1.0**).

You may also pass **`label`** (ignored by the tool). Prefer full fetch **`toolResult`** over hand-copied **`rows`**. If using **`rows`**, pass a candle **array** (stringified JSON arrays are accepted).

Requires **25–40** bars depending on pattern (cup & handle ~40; trendline patterns ~20). OHLC only — volume not required.

## Output fields

Read **`analysis.interpretation`** first (agent digest), then **`analysis.pattern`** for geometry.

- **`analysis.summary`**: one-line headline or *No obvious recent pattern found*.
- **`analysis.classification`**: `bullish` | `moderately_bullish` | `neutral` | `moderately_bearish` | `bearish` | `null`.
- **`analysis.pattern`**: `points`, `lines`, `levels`, `confidence`, `completionState`.
- **`analysis.patterns[]`**: all hits (full geometry in **`structuredContent`** only; slim agent view exposes **`patternMenu`** + **`patternCount`**).
- **`analysis.patternMenu[]`**: numbered picks — each row includes **`barSpan`** (UTC window) and **`keyLevels`** (labeled price/time anchors). Summarize **both time and price** per pattern; use **`patternNumber`** (1-based) on **`apply_chart_pattern_drawings`**. Ask the operator which row unless they already named one.
- **`analysis.applyHint`**: reminder to call apply tool, not prose, when drawing.
- **`analysis.primaryPattern`**: top hit summary with **`barSpan`** + **`keyLevels`** — **most recent** pattern (not always highest confidence)
- **`analysis.highestConfidencePattern`**: highest-scoring hit summary (tie-break: most recent)
- **`analysis.selectionHint`**: `Primary=menu #N; highest confidence=menu #M` — default apply uses primary unless operator picks a menu #

When empty: **`classification`** and **`pattern`** are **`null`** — say no credible pattern met threshold; do not invent geometry.

## Narrative template

1. Lead with **`summary`** and **`classification`** in plain language.
2. Summarize from **`interpretation`** (2–4 sentences on implication and completion state).
3. Present **`analysis.patternMenu`** as a **numbered table** (#, name, classification, confidence). For **each row**, quote from tool JSON (the node's LLM tool-result summary includes UTC windows and key levels when available):
   - **Time window:** `barSpan.fromTimeSec` → `barSpan.toTimeSec` as UTC (convert unix seconds to ISO, e.g. `2026-07-01T12:00:00Z`) plus `barSpan.barCount` bars
   - **Key levels:** every `keyLevels[]` item as **label @ price** and **time** when `timeSec` is set
   - **Measured move:** when `measuredMove` is present, quote **targetPrice**, **referencePrice**, **status** (`projected` \| `active`), and **direction** from tool JSON — do not invent targets
4. Mention completion state and directional read from **`interpretation`** / **`classification`**.
5. Note standalone chart patterns are historically moderate signals (~55–65%); combine with trend, momentum, and key levels.
6. **Ask which menu row to draw on the chart** — unless the operator already picked one (e.g. “1”, “add pattern 1”, “draw the falling wedge”). When they pick a number, **`apply_chart_pattern_drawings` is mandatory in that turn** — do not confirm in prose first.

## Trade setup / buy–sell levels (when the operator asks)

**Only** when the operator asks for **levels**, **entry/target/stop**, **trade setup**, **where to buy/sell**, or similar — not after every pattern scan by default.

Prefer **`analysis.chartPatternTradeSetup`** from tool JSON (SDK-resolved pattern-limit levels). Do **not** derive entry from **`measuredMove.referencePrice`** alone — for wedges/triangles/channels that field is the breakout reference, not the resting limit while price is still inside the pattern.

| Role | Source (tool JSON) |
|------|---------------------|
| **Bias / side** | **`chartPatternTradeSetup.side`** (`long` \| `short` \| `neutral`) |
| **Entry (base limit)** | **`chartPatternTradeSetup.triggerPrice`** / **`triggerLabel`** — support bounce (**inside**) or broken-boundary retest (**post-breakout**) |
| **Target** | **`chartPatternTradeSetup.targetPrice`** when present (measured move — unchanged) |
| **Invalidation (pattern fail)** | **`chartPatternTradeSetup.invalidationPrice`** / **`invalidationLabel`** — opposite boundary where the thesis fails |
| **Phase** | **`entryPhase`**: `inside_pattern` \| `post_breakout_retest`; **`entryOffsetMode`**: `bounce` \| `retest` |
| **Setup code** | **`setupPurposeCode`** (e.g. `fw-bnc`, `fw-ret`, `sym-ret`) — used in multisign Purpose |

**Rules**

- If **`chartPatternTradeSetup.status`** is **`unclear`**, quote **`unclearReason`** (e.g. symmetrical triangle still inside, price too far from inside bounce for **`entryProximityPct`**).
- Compare entry/invalidation vs **`chartPatternTradeSetup.lastClose`** (same as **`meta.ohlcvSummary.lastClose`** on the analyze turn).
- **`measuredMove.referencePrice`** may still be quoted in the pattern table for context — it is **not** the trade entry when **`chartPatternTradeSetup`** is present.
- If **`targetPrice`** is absent, state measured target was **not computed** — do not guess from pattern name.
- **Symmetrical triangle:** trade idea only **after breakout** (long above upper / short below lower); no setup while price is inside the triangle.
- One setup **per pattern row**. If multiple menu rows conflict, present separate setups or ask which row to trade.
- Classic patterns are historically **moderate** signals (~55–65%). Cross-check with **`analyze_trend_structure`**, **`analyze_key_levels`**, **`analyze_momentum`** on the same session when helpful.
- **Technical framing only** — not financial advice.

**Example (falling wedge inside, clear setup)**

> Long setup (Falling Wedge, forming): entry **1700** (S2 bounce), invalidation **1700** (lower wedge fail — offset widens stop at build), target **1940** (measured move, projected) — last close **1705**, `setupPurposeCode` **fw-bnc**.

For **horizontal support/resistance ranking** without pattern geometry, use skill **`chart-analysis-levels`** → **`analyze_key_levels`**.

## Orders / multisign (analyze → trade)

Use when the operator asks to **trade** the pattern, or when the task is combined (e.g. *“Analyse chart patterns and if a clear trade setup from the primary pattern is apparent, generate a multiSignRequest to trade it”*).

### `analysis.chartPatternTradeSetup` → `conversation.tradeIdeas[]`

After **`analyze_chart_patterns`**, read **`analysis.chartPatternTradeSetup`** from tool JSON. When **`status === "clear"`**, the node upserts a numbered **trade idea** (menu **`#N`**) for **`continuum__build_trade_from_chart_pattern`** / **`continuum__build_trade_from_trade_idea`**.

| Field | Meaning |
|-------|---------|
| `status` | `clear` \| `unclear` — only auto-build when **`clear`** unless operator overrides |
| `patternNumber` | 1-based primary menu row |
| `side` | `long` \| `short` \| `neutral` |
| `triggerPrice` / `triggerLabel` | **Base** entry (pattern boundary) |
| `targetPrice` / `targetStatus` / `targetDirection` | Measured-move target |
| `invalidationPrice` / `invalidationLabel` | **Base** pattern-failure level |
| `entryPhase` / `entryOffsetMode` | Phase-aware limit rules |
| `setupPurposeCode` | Short code for ctm1 Purpose (e.g. `fw-ret`) |
| `lastClose` | From analyze turn |
| `unclearReason` | Why auto-trade should not proceed |

**Rules**

- Prices must come from **`chartPatternTradeSetup`** / persisted **trade ideas** — never invent levels.
- Re-run **`analyze_chart_patterns`** on the same OHLCV session if data is stale.
- **No separate chat confirmation** before multisign — MPC **`signRequestAgree`** is the gate.
- At **build** time, use skill **`trade-defaults`**: **`entryOffsetPct`** and **`invalidationOffsetPct`** adjust limit and pattern-failure reference; Purpose uses compact **`ctm1|…|eE=…|pfE=…`** meta (≤256 runes). Do not put menu **`#N`** in Purpose.

### Protocol-specific build (DeFi MCP loaded)

Prefer **`continuum__build_trade_from_trade_idea`** (or chart-pattern alias) with **`tradeIdeaNumber`** / **`tradeIdeaId`** from the menu — not raw protocol builders with hand-picked prices unless the operator overrides.

| Protocol | Notes |
|----------|--------|
| **Hyperliquid** | Limit from adjusted entry; `szHuman` from open-context |
| **GMX** | `orderType: limit`; `triggerPriceUsdHuman` from adjusted entry; size/collateral from GMX context |
| **Uniswap** | Spot swap; entry proximity required |

**Workflow (same turn when possible)**

1. OHLCV fetch → **`analyze_chart_patterns`**
2. If **`chartPatternTradeSetup.status === "clear"`** (or operator asked to trade): **`load_defi_protocol`** when not loaded
3. Protocol context tools for size/market; load **`trade-defaults`** for prefill offsets
4. **`continuum__build_trade_from_trade_idea`** with `keyGenId`, `chainId`, sizing fields
5. Return `{ requestId }` — operator signs in MPC UI

If **`status === "unclear"`**, explain **`unclearReason`** and do **not** submit multisign unless the operator supplies explicit levels or asks to re-analyze.

## Drawing on chart (mandatory tool — not prose)

When the operator asks to **draw**, **add**, **show**, or **overlay** a pattern on an **existing chart**:

**Hard rules**

- Call **`continuum__apply_chart_pattern_drawings`** — prose describing trendlines does **not** update the chart.
- **Never** claim a pattern is on the chart until **`apply_chart_pattern_drawings`** succeeds (`meta.warnings` mentions overlay applied; chart has `pattern_*` series).
- **Never** call **`prepare_chart_from_rows`** again for overlay-only requests — that recreates the chart and may change interval/window.
- Reuse the **same OHLCV session** — `{ title, ohlcvDigest }` from **`meta.sessionBind`** on follow-ups; do not re-fetch unless the operator changed symbol, interval, or lookback.

**Agent-facing analysis is slim** — chat JSON lists **`patternMenu`** (with **`patternNumber`**, 1-based) but omits full **`patterns[]`** geometry. The node keeps geometry server-side after **`analyze_chart_patterns`**. You do **not** need to paste `patterns[]` back on apply.

### When the operator picks a menu row

Use **`patternNumber`** (matches your table: row **#1** → `patternNumber: 1`). Do **not** invent `patternId` strings (e.g. `head-and-shoulders-top-1`).

```json
{
  "title": "ETH-PERP 1H — last 7d",
  "ohlcvDigest": "<from meta.sessionBind>",
  "patternNumber": 1
}
```

Also accepted: **`patternId`**, **`patternIndex`** (0-based), **`selectionMode`**: `primary` | `highest_confidence`.

The node injects **`prepareReplay`** + **`live`** from the bound chart when available. If apply fails, fix the payload — do **not** re-fetch at a different interval.

### Alternative: explicit geometry

Optional two-step when you need toggles or pasted geometry:

1. **`continuum__calculate_chart_pattern_drawings`** — same session `{ title, ohlcvDigest }` or full **`toolResult`** once.
2. **`continuum__apply_chart_pattern_drawings`** with **`drawings`** from step 1, plus **`prepareReplay`** + **`live`** from the prior chart.

Or pass **`analysis: { "pattern": { ... } }`** from full analysis output (object, not string) when geometry is available.

**Do not** re-fetch OHLCV, use `fetch_market_snapshot`, or pass analysis JSON as `toolResult`.

Prose-only replies are wrong when the operator asked to draw on the chart — the MCP tool must return `continuum/chart/v1`.
