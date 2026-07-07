# Chart analysis: classic chart patterns

Use after OHLCV fetch. Tool: **`continuum__analyze_chart_patterns`**.

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
6. **Ask which menu row to draw on the chart** — unless the operator already picked one (e.g. “add pattern 1”, “draw the falling wedge”). Example: *“Which pattern should I overlay? (#1 Falling Wedge, #2 Rounding Bottom, …)”*

## Trade setup / buy–sell levels (when the operator asks)

**Only** when the operator asks for **levels**, **entry/target/stop**, **trade setup**, **where to buy/sell**, or similar — not after every pattern scan by default.

Derive a **conditional setup from one pattern row** (primary, or the menu # the operator picked). Every price must come from tool JSON on **this turn** — chiefly **`patternMenu[]`**, **`meta.ohlcvSummary.lastClose`**, and **`measuredMove`**.

| Role | Source (tool JSON) |
|------|---------------------|
| **Bias** | Row **`classification`** + pattern direction (bullish → long-bias framing; bearish → short-bias; neutral → range/breakout both sides) |
| **Trigger / reference** | **`measuredMove.referencePrice`** when present, else the labeled **neckline / break / rim** row in **`keyLevels[]`** |
| **Target** | **`measuredMove.targetPrice`** when present — quote **`status`** (`projected` \| `active`) and **`direction`** |
| **Invalidation (stop)** | Opposite pattern boundary from **`keyLevels[]`** (e.g. support trendline, trough, pattern low, below neckline) — **name the label** you use |

**Rules**

- Compare distance to trigger/target vs **`meta.ohlcvSummary.lastClose`** — do not invent “current price”.
- If **`measuredMove`** is **absent**, state that a measured target was **not computed** — do not guess a target from pattern name alone.
- If **`completionState`** is **`forming`**, frame as **conditional** (*if* price breaks above/below reference…) — not as an executed signal.
- One setup **per pattern row**. If multiple menu rows conflict (e.g. bullish double bottom vs bearish double top), present **separate conditional setups** or ask which pattern to trade — do not merge into one buy and one sell without labeling the source row.
- Classic patterns are historically **moderate** signals (~55–65%). Offer to cross-check on the **same OHLCV session**: **`analyze_trend_structure`**, **`analyze_key_levels`**, **`analyze_momentum`** — dedicated key-level analysis is often better for ranked horizontal S/R than pattern geometry alone.
- **Technical framing only** — not financial advice. Do not place orders or size positions.

**Example (double bottom, menu row with measured move)**

> Long-bias conditional setup (Double Bottom, forming): trigger/reference **1834.0** (neckline), invalidation below **1757.8** (trough from keyLevels), measured target **1940.2** (projected, up) — last close **1777.2** from ohlcvSummary.

For **horizontal support/resistance ranking** without pattern geometry, use skill **`chart-analysis-levels`** → **`analyze_key_levels`**.

## Orders / multisign (analyze → trade)

Use when the operator asks to **trade** the pattern, or when the task is combined (e.g. *“Analyse chart patterns and if a clear trade setup from the primary pattern is apparent, generate a multiSignRequest to trade it”*).

### `analysis.lastTradeSetup` (persisted on conversation)

After **`analyze_chart_patterns`**, read **`analysis.lastTradeSetup`** from tool JSON (also in the persisted conversation system hint on later turns):

| Field | Meaning |
|-------|---------|
| `status` | `clear` \| `unclear` — only auto-submit multisign when **`clear`** unless the operator overrides with explicit prices |
| `patternNumber` | 1-based primary menu row this setup derives from |
| `side` | `long` \| `short` \| `neutral` |
| `triggerPrice` / `triggerLabel` | Entry / breakout reference |
| `targetPrice` / `targetStatus` / `targetDirection` | Measured-move target when computed |
| `invalidationPrice` / `invalidationLabel` | Opposite boundary (stop reference) |
| `lastClose` | From `meta.ohlcvSummary.lastClose` on the analyze turn |
| `unclearReason` | Why auto-trade should not proceed |

**Rules**

- Prices must come from **`lastTradeSetup`** or fresh **`analyze_chart_patterns`** — never invent levels.
- Re-run **`analyze_chart_patterns`** on the same OHLCV session if data is stale (new fetch clears persisted setup).
- **No separate chat confirmation** before multisign — MPC **`signRequestAgree`** / reject-with-Thoughts is the gate.
- Apply **operator proximity tweaks** from their message when choosing limit prices (e.g. *“limit buy 0.1% below neckline”* → offset `triggerPrice` for `limitPxHuman` / GMX trigger fields).

### Protocol-specific multisign (DeFi MCP loaded)

Order shape depends on the **loaded DeFi protocol** (`load_defi_protocol`). Typical perp entry mapping from **`lastTradeSetup`**:

| Protocol | Tool | Map from setup |
|----------|------|----------------|
| **Hyperliquid** | `ctm_hyperliquid_build_limit_order_multisign` | `isBuy` ← `side==long`; `limitPxHuman` ← trigger (± operator offset); `szHuman` ← from `fetch_open_context`; `coin` ← OHLCV symbol; `chainId` **999** / **998** |
| **GMX** | `ctm_gmx_build_increase_multisign` | `direction` ← `side`; `triggerPriceUsdHuman` ← trigger; `orderType: limit`; size/collateral from GMX context tools |

**Workflow (same turn when possible)**

1. OHLCV fetch → **`analyze_chart_patterns`**
2. If **`lastTradeSetup.status === "clear"`** (or operator explicitly asked to trade): **`load_defi_protocol`** when not loaded
3. Protocol context tools (e.g. **`fetch_open_context`**, **`fetch_market_snapshot`**) for size/market
4. **`get_multi_sign_gas_options`** if needed → **`build_*_multisign`** with `keyGenId`, `chainId`, `purposeText`
5. Return `{ requestId }` — operator signs or rejects in MPC UI

If **`status === "unclear"`**, explain **`unclearReason`** and do **not** submit multisign unless the operator supplies explicit levels or asks to re-analyze.

Spot swaps (Uniswap/Curve) are **not** pattern-breakout tools — use perp protocols above for directional pattern trades unless the operator directs otherwise.

## Drawing on chart (mandatory tool — not prose)

When the operator asks to **draw**, **add**, **show**, or **overlay** a pattern on an **existing chart**:

**Hard rules**

- Call **`continuum__apply_chart_pattern_drawings`** — prose describing trendlines does **not** update the chart.
- **Never** claim a pattern is on the chart until **`apply_chart_pattern_drawings`** succeeds (`meta.warnings` mentions overlay applied; chart has `pattern_*` series).
- **Never** call **`prepare_chart_from_rows`** again for overlay-only requests — that recreates the chart and may change interval/window.
- Reuse the **same OHLCV session** — `{ title, ohlcvDigest }` from **`meta.sessionBind`** on follow-ups; do not re-fetch unless the operator changed symbol, interval, or lookback.

**Agent-facing analysis is slim** — chat JSON lists **`patternMenu`** (with **`patternNumber`**, 1-based) but omits full **`patterns[]`** geometry. The node keeps geometry server-side after **`analyze_chart_patterns`**. You do **not** need to paste `patterns[]` back on apply.

### When the operator picks a menu row

Use **`patternNumber`** (matches your table: row **#1** → `patternNumber: 1`):

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
