---
name: trade-defaults
description: Use for trade idea / trade desk defaults and build-trade guidance. Skip for chart-only work.
---

# Trade defaults (build form prefill)

Load when the operator opens **Trade ideas**, selects a numbered idea, or before **`continuum__build_trade_from_trade_idea`**.

**Desk numeric defaults** (offsets, proximity, protocol sizing, `marketKind`, `tif`, `autoSubmitMultisign`) are machine-parsed from **`trade-desk.yaml`** beside `agent_llm_config/` (seeded from `agent_llm_config.defaults/trade-desk.yaml`). The node applies them on a **deterministic fast path** for clear ideas — no LLM round-trip.

**This skill** is for **policy-only** cases the fast path cannot decide: nearest-level break+retest alternates (`kl-ret`), Donchian primary vs nested alternate (`dc-ret` / `dc-brk`), unclear status with a clear alternate, and discretionary `purposeTextAdditional`. When the fast path applies, the operator still reviews the prefilled form unless **`autoSubmitMultisign`** is enabled in `trade-desk.yaml` or cron **`tradeBuild`** YAML.

Cron jobs may still set overrides in a fenced **`tradeBuild`** YAML block (see **`scheduled-automation`**).

---

## 1. Scope (all protocols)

- Apply rules to the **selected idea only** — use its `symbol`, `side`, `confidence`, `status`, `entry`, `target`, `invalidation`, and `analysisSetup`:
  - **chart_pattern:** `patternName`, `entryPhase`, `entryOffsetMode`, `setupPurposeCode`
  - **momentum:** RSI zone, MACD crossover, `side` long/short/neutral — often **`partial`**; use as **confirmation** for structural primaries in cron (see **`scheduled-automation`**)
  - **divergence:** PRIMARY regular/hidden RSI or Stochastic RSI divergence; `setupPurposeCode` **`div`**; pivot-structure **entry** (last close), **target** (measured move of \|p1−p2\| from p2), **invalidation** (beyond swing extreme) → usually **`full`** when clear. Buildable standalone primary **or** cron **confirmation** (side match) alongside momentum/candlestick
  - **candlestick:** `patternName`, `signal` (`buy` | `sell` | `hold`), `side` long/short/neutral, `setupPurposeCode` **`candle`** — **confirmation** alongside momentum in trade-analysis cron; requires **≥14** OHLCV bars
  - **trend_structure:** `bias`, `structure`, `primaryTrendKind`, `primaryTrendTouchCount`, `entryOffsetMode` (always **`retest`**), `setupPurposeCode` (**`trend-ret`**)
  - **key_levels:** `levelNumber`, `framing`, `entryOffsetMode` (**`bounce`** default), `setupPurposeCode` (**`kl-bnc`** long bounce / **`kl-brk`** short rejection), `targetSource`, optional nested **`breakRetestAlternative`** (**`kl-ret`** when selected)
  - **key_level_fibonacci:** `fibPairNumber`, `priceRegime` (**`inside_range`** when valid), `framing` (**`retrace`**), `entryOffsetMode` (**`bounce`**), `setupPurposeCode` (**`kl-fib`**), `targetSource` (`retrace_618` | `range_leg`); quote both bracket Level #s. Break+retest of a level is **`key_levels`** / **`kl-ret`**, not Fib.
  - **bollinger_bands:** `setupPurposeCode` (**`bb-fade`**), `entryOffsetMode` (**`bounce`**), desk **`bollingerPeriod`** **20**, **`bollingerStdDev`** **2**, **`bollingerEntryProximityPct`** / **`bollingerEntryProximityMode`** (**bandWidth** default, **atr** optional — gates `clear` vs `unclear`)
  - **donchian_breakout:** `setupPurposeCode` (**`dc-ret`** retest default / **`dc-brk`** immediate), `entryMode` from desk **`donchianEntryMode`**, channel **`period`** from desk **`donchianPeriod`** (default **20**), `entryOffsetMode` (**`retest`** or **`bounce`**), desk **`entryProximityPct`** (price %); **target** = entry ± (**`donchianTargetAtrMultiple`** × ATR, default **3**); **invalidation** = Donchian mid; nested **`immediateAlternative`** or **`breakRetestAlternative`**
  - **supertrend:** `setupPurposeCode` (**`st-flip`** flip default / **`st-ret`** retest), `entryMode` from desk **`supertrendEntryMode`**, **`period`/`multiplier`** from desk **`supertrendPeriod`**/**`supertrendMultiplier`** (default **10**/**3**), `entryOffsetMode` (**`bounce`** or **`retest`**); **target** = entry ± (**`supertrendTargetAtrMultiple`** × ATR, default **3**); **invalidation** = Supertrend trail; nested **`retestAlternative`** or **`flipAlternative`**
  - **ichimoku:** `setupPurposeCode` (**`ichi-tk`** TK cross / **`ichi-cloud`** cloud retest), periods from desk **`ichimokuConversionPeriod`/`ichimokuBasePeriod`/`ichimokuSpanPeriod`/`ichimokuDisplacement`** (default **9/26/52/26**); **target** = entry ± (**`ichimokuTargetAtrMultiple`** × ATR, default **3**); **invalidation** = cloud edge / kijun; nested **`cloudAlternative`** or **`tkCrossAlternative`**
  - **z_score:** `setupPurposeCode` (**`zs-fade`**), `entryOffsetMode` (**`bounce`**); enter when \|Z\| ≥ desk **`zScoreEntry`** (default **2**); **target** = SMA ± **`zScoreExit`**×SD (default **0.5**); **invalidation** = entry ± **`zScoreStopAtrMultiple`**×ATR (default **2**); optional **`zScoreAtrFilter: contracting`**
  - **elliott_waves:** `patternType` (`impulse` | `diagonal` | `corrective`), `setupPurposeCode` (**`ew-imp`** | **`ew-dia`** | **`ew-corr`**), `waveMenuNumber` (default **1**), `confirmedWaveCount`, in-progress wave projection target/invalidation. **`corrective`** (`ew-corr`) is **`unclear`** — no directional build. Requires **≥50** OHLCV bars (hard minimum); **≥200** recommended; **≥400** for primary degree (see **`scheduled-automation`** / template bar-count note).
  - **moving_averages:** `strategy` (**`crossover`** | **`proximity_retest`**), `setupPurposeCode` (**`ma-cross`** crossover at last close | **`ma-ret`** slow-MA retest), desk **`maFastPeriod`** **50**, **`maSlowPeriod`** **200**, **`maType`** **`sma`**, **`maFreshCrossoverMaxBars`** **5**, `entryOffsetMode` (**`bounce`** for crossover, **`retest`** for proximity), **`entryProximityPct`** **1** with desk **`entryProximityMode`** (**`price`** | **`atr`**)
- Do **not** pick a different idea or invent a new setup.
- If this skill is not installed, prefill is skipped.

Chart-pattern ideas store **base** entry and invalidation at pattern boundaries (inside bounce or post-breakout retest). **Target** comes from measured move.

**Trend-structure** ideas (`analyze_trend_structure`) store **base entry** at the primary **support** (long bias) or **resistance** (short bias) trend-line retest; **invalidation** at the recent swing low/high; **swing target** (`targetPrice` / `idea.target`) at the opposing swing when available. **`measuredMove`** is the **impulse-leg** projection (`entry ± (swingHigh − swingLow)`). **Default take-profit at build is the impulse-leg measured move** (`takeProfitSource: impulse_leg`); falls back to swing when `measuredMove` is absent. Pass **`takeProfitSource: swing`** for the nearer swing target only. Offsets below apply at **build** time on top of those base prices.

**Key-levels (nearest)** ideas (`analyze_key_levels`) auto-upsert the **primary** setup only — **bounce** at nearest support (`kl-bnc`, long) or **rejection** at nearest resistance (`kl-brk`, short). Base entry sits at the menu level price; target is the **next key level** in trade direction when available (`targetSource: next_level`). A nested **`breakRetestAlternative`** may be present for operator/agent selection — it is **not** used unless this skill directs you to switch (see §1.1).

**Key-level Fibonacci** ideas (`analyze_key_level_fibonacci`) use the **strongest-bracket** range: strongest key level below last close × strongest key level above last close, each with confidence (`strength/100`) ≥ desk **`fibKeyLevelMinConfidence`** (default **0.35**). If either leg is missing or weak, the analysis is invalid (no `primaryFibPair` / no trade setup). A valid bracket always places last close **between** the legs (`priceRegime: inside_range`). Always quote both Level #s, prices, strengths, and confidences when reporting.

| Regime | Last close | Primary setup | Target |
|--------|------------|---------------|--------|
| **`inside_range`** | Between strongest bracket low and high | Bounce at **Fib leg** (`kl-fib`, `entryOffsetMode: bounce`): **upper half → short at Fib 1.0 (range high)** toward 0.618; **lower half → long at Fib 1.0 inverted (range low)** toward inverted 0.618. Opposite-side variant uses the other leg (long at Fib 0 / short at Fib 0 inverted) toward the opposite range leg. | Default variant: **Fib 0.618** retrace (`retrace_618`); opposite variant: opposite range leg (`range_leg`) |

Fib analyze does **not** emit outside-range extension or Fib break+retest setups. For break+retest of a broken menu level, use **`analyze_key_levels`** (§1.1).

### 1.1 Key levels (nearest) — default vs break+retest alternate

**Default (auto-upserted idea):** use **primary** `keyLevelsTradeSetup` fields on the selected idea — do **not** substitute `breakRetestAlternative` unless the operator explicitly requests break+retest or the conditions below match.

| Path | When | `setupPurposeCode` | `entryOffsetMode` |
|------|------|--------------------|-------------------|
| **Primary bounce / rejection** | Default for all key-level ideas | **`kl-bnc`** (long at support) or **`kl-brk`** (short at resistance) | **`bounce`** |
| **Break + retest alternate** | Operator asks for “break retest”, “post-break entry”, or “trade the broken level”; **or** primary bounce is **`unclear`** but `breakRetestAlternative.status === 'clear'`; **or** structure favors post-break retest (close through level, retest in band) | **`kl-ret`** | **`retest`** |

**Switching to the alternate (prefill LLM):**

1. Read `breakRetestAlternative` from `analysisSetup.setup` on the **same** selected idea.
2. Use its `entryPrice`, `targetPrice`, `invalidationPrice`, `brokenLevelNumber`, and `setupPurposeCode: kl-ret`.
3. Apply **retest** offsets from §3; **skip proximity gate** on perp limit venues (same as pattern/trend retests).
4. Optional `purposeTextAdditional`: e.g. `kl break retest` or `Level #N retest`.

**Break level selection (multiple candidates):**

- **Default:** strongest broken level (`alternateBreakCandidates[0]`, `selectionHint: strongest`).
- **Alternates:** most recent break; nearest to last close — operator may pick from `alternateBreakCandidates[]`.

### 1.2 Key level Fibonacci — inside-range 0.618 fade

**Default (auto-upserted fib idea):** use **primary** `keyLevelFibTradeSetup` with **`setupPurposeCode: kl-fib`**, **`priceRegime: inside_range`**, **`entryOffsetMode: bounce`**.

| Path | When | `setupPurposeCode` | `entryOffsetMode` |
|------|------|--------------------|-------------------|
| **Inside range — 0.618 fade** | Valid strongest-bracket (`priceRegime: inside_range`) | **`kl-fib`** | **`bounce`** |

**Chart apply:** `apply_key_fib_drawings` with **`fibPairNumber`** draws the Fib overlay (**0 / 0.618 / 1**) plus leg horizontals. Lower-half setups use inverted Fib orientation (`displayTrend: up`).

**Desk percentages on setup (match §2 defaults):** each `keyLevelFibTradeSetup` includes **`entryProximityPct: 1`**, **`entryOffsetPct: 1`**, **`invalidationOffsetPct: 1`**. Bracket formation also uses desk **`fibKeyLevelMinConfidence: 0.35`** (per-leg `strength/100`). Analysis uses proximity/offsets when assessing entry actionability: last close within **`entryProximityPct`** of the **Fib leg entry** (Fib 1.0 / Fib 0 per variant — not the 0.618 target). At **build**, **`entryOffsetPct`** (bounce mode) shifts the resting limit slightly beyond that leg (§3).

Same desk fields are on **`keyLevelsTradeSetup`** for nearest analysis (bounce uses **`entryProximityPct`**).

**Bollinger bands** ideas (`analyze_bollinger_bands`) are **band-to-band fades**: above middle → **short** at **upper** band toward **lower**; below middle → **long** at **lower** band toward **upper**. Base entry is the outer band price; target is the **opposite** band. Invalidation is band breach (above upper for short, below lower for long). Idea is **`clear`** only when last close is within the desk fade gate (**`bollingerEntryProximityPct`**, default **5**; mode **`bollingerEntryProximityMode`**: **bandWidth** = % of band width, **atr** = % of one ATR bar). Use **`setupPurposeCode: bb-fade`**, **`entryOffsetMode: bounce`**, and desk **`entryOffsetPct` / `invalidationOffsetPct`** from §2 at build time. Analysis/overlay **`period` / `stdDev`** come from **`trade-desk.yaml`** **`bollingerPeriod` / `bollingerStdDev`**.

**Donchian breakout** ideas (`analyze_donchian_breakout`) use channel length **`donchianPeriod`** (default **20**) and primary **`donchianEntryMode`** from **`trade-desk.yaml`**. Default **`retest`**: after a channel break, enter on pullback to the broken band (`dc-ret`, `entryOffsetMode: retest`). Alternate **`immediate`**: enter on break/hold beyond the prior channel (`dc-brk`). **Target** = breakout entry ± (**`donchianTargetAtrMultiple`** × ATR) — default multiple **3**, ATR period from **`entryProximityAtrPeriod`**. **Invalidation** = Donchian mid-channel. Desk **`entryProximityPct`** (price %) gates `clear`. Nested alternate setups may be present — switch only when the operator asks or primary is unclear and the alternate is clear (mirror §1.1). Overlay period matches desk **`donchianPeriod`** (see **`chart-defaults`**).

**Supertrend** ideas (`analyze_supertrend`) use ATR length **`supertrendPeriod`** (default **10**), multiplier **`supertrendMultiplier`** (default **3**), and primary **`supertrendEntryMode`** from **`trade-desk.yaml`**. Default **`flip`**: enter on direction change (`st-flip`, `entryOffsetMode: bounce`). Alternate **`retest`**: enter when price tags the trail in trend direction (`st-ret`). **Target** = entry ± (**`supertrendTargetAtrMultiple`** × ATR) — default multiple **3**. **Invalidation** = Supertrend trail. Desk **`entryProximityPct`** gates `clear`. Nested alternate setups may be present — switch only when the operator asks or primary is unclear and the alternate is clear (mirror §1.1). Overlay params match desk (see **`chart-defaults`**).

**Ichimoku** ideas (`analyze_ichimoku`) use classic periods from desk (**`ichimokuConversionPeriod`/`ichimokuBasePeriod`/`ichimokuSpanPeriod`/`ichimokuDisplacement`**, default **9/26/52/26**). Primary **TK cross** (`ichi-tk`): fresh Tenkan/Kijun cross with price outside the cloud. Alternate **cloud retest** (`ichi-cloud`): price above/below cloud near kijun or cloud edge. **Target** = entry ± (**`ichimokuTargetAtrMultiple`** × ATR). **Invalidation** = cloud edge / kijun. Nested alternate setups may be present — switch only when the operator asks or primary is unclear and the alternate is clear. Overlay: **`chart-defaults`**.

**Z-score mean reversion** ideas (`analyze_z_score`) use **`Z = (close − SMA) / SD`** with desk **`zScorePeriod`** (default **20**). Enter long when Z ≤ −**`zScoreEntry`**, short when Z ≥ +**`zScoreEntry`** (default **2**). **Target** = SMA ± **`zScoreExit`**×SD (default **0.5**). **Invalidation** = entry ± **`zScoreStopAtrMultiple`**×ATR (default **2**, ATR from **`entryProximityAtrPeriod`**). Optional **`zScoreAtrFilter: contracting`**. Use **`setupPurposeCode: zs-fade`**, **`entryOffsetMode: bounce`**. Overlay: **`chart-defaults`**.

**Elliott waves** ideas (`analyze_elliott_waves`) bind to a **`waveMenuNumber`** (default **1**). **Impulse** / **diagonal** counts with confirmed structure and projection targets can be **`clear`** with **`setupPurposeCode: ew-imp`** or **`ew-dia`**. Base entry is **last close** (`triggerPrice`); target is the highest-probability in-progress wave projection above/below last close; invalidation is the wave **`invalidationPoint`**. **`corrective`** A–B–C counts (`ew-corr`) stay **`unclear`**. Cron and prefill skip when `dataStatus: insufficient_data` — widen OHLCV lookback per tool **`dataGuidance`**. Offsets from §2 apply at build on perp limit venues. Optional chart labels: **`apply_elliott_wave_drawings`** (not required for submit).

**Candlestick** ideas (`analyze_candlestick_patterns`) reflect the last-bar primary pattern: **`signal: buy`** → **`side: long`**, **`signal: sell`** → **`side: short`**, **`hold`** / neutral → **`unclear`**. In trade-analysis cron, use **`candlestick`** as **confirmation** for a structural primary — **momentum OR candlestick OR divergence** must match the primary side before submit (see **`trade_analysis_cron.example.md`**). Standalone candlestick builds are possible but weak (~50–55% hit rate); skill **`chart-analysis-patterns`** for narrative rules.

**Divergence** ideas (`analyze_divergence`) use the PRIMARY regular/hidden RSI or Stochastic RSI hit: **`side`** long/short from bullish/bearish kind, **`setupPurposeCode: div`**. Entry = last close; target = measured move of the divergence price swing; invalidation beyond the swing extreme. Prefer **`hyperliquid`**, **`arcus`**, or **`gmx`** for limit builds. Optional `purposeTextAdditional`: e.g. `rsi div` / `stoch div`. Skill **`chart-analysis-divergence`** for narrative and chart overlay (`apply_divergence_drawings` always adds Stoch RSI).

**Moving averages** ideas (`analyze_moving_averages`) support two strategies from the same fast/slow pair (desk **`maFastPeriod` / `maSlowPeriod` / `maType`**, defaults **SMA 50/200**):

| Strategy | `setupPurposeCode` | Entry | When `clear` |
|----------|-------------------|-------|--------------|
| **Crossover** | **`ma-cross`** | Last close | Fresh golden/death cross within **`freshCrossoverMaxBars`** (**5** default) |
| **Proximity + retest** | **`ma-ret`** | Slow MA | Established regime; last close within desk **`entryProximityPct`** (**1** default) using **`entryProximityMode`** (**`price`** or **`atr`**) |

Quote **`tradeSummary`** in operator-facing prose (e.g. “Golden cross · SMA(50)/SMA(200)” or “Proximity + retest · bullish regime”). Crossover uses **`entryOffsetMode: bounce`**; proximity retest uses **`retest`** (perp resting limits skip proximity at build per §2). Target is fast MA; invalidation is slow MA breach. Chart overlay defaults live in **`chart-defaults`**.

---

## 2. Universal prefill fields (trade-desk.yaml)

Edit **`trade-desk.yaml`** → `universal:` and per-protocol `protocols:` blocks. The node prefill fast path reads these directly.

| Field | Meaning |
|-------|---------|
| `entryOffsetPct` | Perp entry limit band — always **price %** (see §3) |
| `invalidationOffsetPct` / `invalidationOffsetMode` | Perp invalidation / SL band — `price` (default) or `atr` (% of one ATR bar; default pct **25** when atr and omitted) |
| `targetOffsetPct` | Hyperliquid only — TP trigger band **inside** idea target (see §3) |
| `targetOffsetMode` | Hyperliquid only — `price` (% of target) or `atr` (% of one ATR bar) |
| `takeProfitSource` | **Trend structure only** — `impulse_leg` (default; `measuredMove.targetPrice`, falls back to swing) or `swing` (nearer swing target) |
| `useCustomGas` | EVM Custom Gas Config (ignored when Hyperliquid bracket uses EIP-712) |
| `entryProximityMode` / `entryProximityPct` | Idea surfacing gates (`price` \| `atr`; Bollinger uses band-width % on the setup) |
| `autoSubmitMultisign` | Submit without operator review (cron only when explicitly allowed) |
| `expiryMinutesFromNow` | Optional multisign expiry (Unix seconds computed at prefill time) |

**Protocol blocks** (`hyperliquid`, `arcus`, `gmx`, `uniswap`): `marketKind`, `tif`, `collateralToken`, `sizing` (`fixed` or `marginPct` for Hyperliquid), optional `purposeSuffix` per analysis kind.

**Hyperliquid-only** (`protocols.hyperliquid` in `trade-desk.yaml`):

| Field | Meaning |
|-------|---------|
| `targetOffsetPct` | Conservative TP band inside analysis target (default **0.1**) |
| `targetOffsetMode` | `price` (default) or `atr` — see §3 |
| `tpslExecMode` | `limit_at_trigger` (default) or `market` when bracket TP/SL is included at build |

When a trade idea has **target** and/or **invalidation**, **`build_trade_from_*`** for Hyperliquid auto-includes bracket fields (`takeProfitTriggerPxHuman`, `stopLossTriggerPxHuman`) via one L1 EIP-712 `normalTpsl` action — not CoreWriter. **Arcus perp** uses the same bracket geometry via `ctm_arcus_build_place_order_multisign` (ed25519-signed API payload). Geometry: long → SL < entry < TP; short → TP < entry < SL. See **`ctm-mpc-defi`** Hyperliquid / Arcus skills.

**LLM fallback** (this skill): `llmFallback` in `trade-desk.yaml` lists when the fast path is skipped — e.g. `status: unclear`, `setupPurposeCode` **`kl-ret`**, or primary unclear with a clear nearest-level **`breakRetestAlternative`**.

---

## 3. Price offsets (perp limit protocols only)

Read `entryOffsetMode` from `analysisSetup.setup` (`bounce` | `retest`).

**Trend-structure** ideas always use **`retest`** — same offset table as post-breakout pattern retests. Do not treat them as bounce.

### entryOffsetPct

| Mode | Long limit | Short limit |
|------|------------|-------------|
| **retest** (post-breakout) | entry × (1 + pct/100) | entry × (1 − pct/100) |
| **bounce** (inside pattern) | entry × (1 − pct/100) | entry × (1 + pct/100) |

If `entryOffsetMode` is absent, treat as **bounce** — except when `analysisSetup.kind` is **`trend_structure`**, then always use **retest**.

### invalidationOffsetPct / invalidationOffsetMode

On **Hyperliquid**, when the idea has an **invalidation** level, the effective level maps to **`stopLossTriggerPxHuman`** on bracket builds (L1 `normalTpsl`). On **GMX**, still informational in Purpose only (pattern-failure reference).

Configure in **`trade-desk.yaml` → `universal`**. Override per build via `invalidationOffsetPct` / `invalidationOffsetMode` on `build_trade_from_*` or the Build Trade form.

| `invalidationOffsetMode` | `invalidationOffsetPct` meaning | Long effective SL | Short effective SL |
|--------------------------|---------------------------------|-------------------|--------------------|
| **`price`** (default) | % of invalidation price (typical 0.5–2; default **1**) | invalidation × (1 − pct/100) | invalidation × (1 + pct/100) |
| **`atr`** | % of one ATR bar (typical 15–50; default **25** when omitted) | invalidation − (ATR × pct/100) | invalidation + (ATR × pct/100) |

ATR comes from the analysis session (`atrAtLastBar` on the trade idea setup). When `invalidationOffsetMode: atr` but ATR is unavailable, the SDK falls back to **price** mode with a **price-scale** pct (omitted → **1**, not the atr default 25 applied as a price %).

### targetOffsetPct / targetOffsetMode (Hyperliquid bracket only)

Conservative take-profit: exit **before** the full analysis target is reached (long TP below target, short TP above target). Configure in **`trade-desk.yaml` → `protocols.hyperliquid`**. Override per build via `targetOffsetPct` / `targetOffsetMode` on `build_trade_from_*` or the Build Trade form.

| `targetOffsetMode` | `targetOffsetPct` meaning | Long effective TP | Short effective TP |
|--------------------|---------------------------|-------------------|------------------|
| **`price`** (default) | % of target price | target × (1 − pct/100) | target × (1 + pct/100) |
| **`atr`** | % of one ATR bar | target − (ATR × pct/100) | target + (ATR × pct/100) |

ATR comes from the analysis session (`atrAtLastBar` on the trade idea setup, or `atr` on range/volatility ideas). When `targetOffsetMode: atr` but ATR is unavailable at build, the SDK falls back to **price** mode with the same pct.

Example (price mode, 1%): target **3100** long → TP **3069**; target **3100** short → TP **3131**.

Example (atr mode, 25%, ATR **40**): long → **3090**; short → **3110**.

Default from desk: **`targetOffsetPct: 0.1`**, **`targetOffsetMode: price`**. Set **`targetOffsetPct: 0`** for TP exactly at the analysis target.

### tpslExecMode (Hyperliquid bracket only)

| Value | Behavior |
|-------|----------|
| **`limit_at_trigger`** (default) | Resting limit at trigger price when TP/SL fires |
| **`market`** | Market order with HL slippage tolerance when triggered |

Configure default in **`trade-desk.yaml` → `protocols.hyperliquid.tpslExecMode`**. Bracket orders use **EIP-712** `/exchange` — not CoreWriter; **`useCustomGas`** does not apply.

### Worked examples (any perp limit protocol)

Falling wedge **long retest**: base entry **1831** (upper wedge), base invalidation **1700** (lower wedge), both offsets **1%** → effective entry **~1849**, effective `pfE` **1683**.

Bullish **trend-structure long retest**: base entry **2950** (support trend line), base invalidation **2800** (recent swing low), both offsets **1%** → effective entry **~2979.5**, effective `pfE` **2772**. Purpose setup code **`trend-ret`**.

---

## 4. Purpose text — ctm1 (all protocols)

Auto-composed first; optional `purposeTextAdditional` after ` · ` if runes remain.

```
ctm1|{proto}|{L|S}|{setup}|eE={px}|pfE={px}|tpE={px}|slE={px}|ds={src}|iv={interval}|n={bars}|sz={coinUnits}|szUsd={usdNotional}|{symShort}
```

Optional **`purposeTextAdditional`** after ` · ` (e.g. `trend retest`, `Generated by cron`). Peer **conditional-accept-sign-request** cron reads both the ctm1 prefix and additional prose.

| Token | Meaning |
|-------|---------|
| `{proto}` | Protocol short code — see protocol table in §5 (`hl`, `arc`, `gmx`, `uni`, …) |
| `{setup}` | From analysis (`fw-ret`, `fw-bnc`, `sym-ret`, **`trend-ret`**, **`kl-bnc`**, **`kl-brk`**, **`kl-ret`**, **`kl-fib`**, **`bb-fade`**, **`dc-ret`**, **`dc-brk`**, **`zs-fade`**, **`ma-cross`**, **`ma-ret`**, **`ew-imp`**, **`ew-dia`**, **`candle`**, **`mom`**, **`div`**, …) — never menu `#N` |
| `eE` / `pfE` | Effective entry / pattern-failure after offsets |
| `tpE` / `slE` | Effective take-profit / stop-loss triggers (Hyperliquid bracket builds when target/invalidation present) |
| `eB` / `pfB` | Optional base prices when rune budget allows |
| `ds` | Chart data source short code (`hl`, `arc`, `gmx`, `uni`, `cg`, `cmc`, `ts`, …) |
| `iv` | Chart interval / timeframe (`4h`, `1h`, `1d`, …) |
| `n` | Bar / candle count used for analysis |
| **`sz`** | Position size in coin units (Hyperliquid / Arcus perp) — for conditional-accept amount limits |
| **`szUsd`** | Position size in USD notional (GMX / Uniswap) — for conditional-accept amount limits |

**Cron:** prefix `ctm1|`; side = field 3; `pfE=([0-9.]+)`; long fail if mark ≤ pfE, short fail if mark ≥ pfE.

---

## 5. Protocol reference (trade-desk.yaml)

Protocol-specific defaults and sizing live under **`trade-desk.yaml` → `protocols:`**. Required build fields:

| `protocolId` | Required prefill fields |
|--------------|-------------------------|
| **`hyperliquid`** | `szHuman` (coin units; fast path uses `sizing.marginPct` + one `fetch_open_context` call, or `sizing.fixed`); optional bracket via idea target/invalidation + desk `targetOffsetPct` / `tpslExecMode` |
| **`arcus`** | `szHuman` (coin units); **`ed25519KeyGenId`** (paired ed25519 KeyGen, same `GroupId` as `keyGenId`); `marketKind` (`perp` \| `spot`); perp optional bracket via idea target/invalidation + desk `targetOffsetPct` / `tpslExecMode`; spot uses RFQ (no TP/SL at build) |
| **`gmx`** | `sizeUsdHuman`, `collateralToken`, `collateralAmountHuman` |
| **`uniswap`** | `sizeUsdHuman` (spot swap; proximity enforced at build) |

ctm1 `{proto}` codes: `hl`, `arc`, `gmx`, `uni`. Default chainIds: Hyperliquid **999**, Arcus **4663**, GMX / Uniswap **42161**.

Build path: **`continuum__build_trade_from_trade_idea`** with matching `protocolId`.

---

## 6. Desk policies (edit per protocol)

Structure: **when** (idea filter) → **which protocol** → **prefill from that protocol’s §5 defaults** → sizing steps from that protocol’s sizing notes.

### Policy: falling wedge retest → GMX

**When:** selected idea is **chart_pattern** with `setupPurposeCode` **`fw-ret`** (or falling wedge + `entryPhase: post_breakout_retest`).

**Protocol:** `gmx` (§5 gmx).

1. GMX context tools → `sizeUsdHuman`, `collateralToken`, `collateralAmountHuman`.
2. Set offsets and flags from **gmx defaults** table above.
3. Optional `purposeTextAdditional`: `fw retest`.
4. `autoSubmitMultisign`: **false**.

### Policy: chart-pattern clear idea → Hyperliquid perp

**When:** selected idea is **chart_pattern**, `status: clear`, operator UI protocol is **hyperliquid**.

**Protocol:** `hyperliquid` (§5 hyperliquid).

1. Hyperliquid open-context → `szHuman` (desk rule: e.g. fixed size or % of margin — **define your rule here**).
2. Set fields from **hyperliquid defaults** table above.
3. `autoSubmitMultisign`: **false**.

### Policy: trend-structure clear idea → perp limit (HL, Arcus, or GMX)

**When:** selected idea is **`trend_structure`**, `setupPurposeCode` **`trend-ret`**, `status: clear`, `side` is **long** or **short**.

**Protocol:** operator UI **`hyperliquid`**, **`arcus`**, or **`gmx`** (§5) — **not Uniswap** unless price is already at the retest entry.

1. Use **retest** offsets from §3 (`entryOffsetPct` / `invalidationOffsetPct` from desk defaults).
2. **Take-profit:** default **`takeProfitSource: impulse_leg`** (measured-move target; falls back to swing). Use **`swing`** only when the operator asks for the nearer swing target.
3. **Hyperliquid / Arcus:** open-context → `szHuman` (+ **`ed25519KeyGenId`** for Arcus). **GMX:** open-context → `sizeUsdHuman`, `collateralToken`, `collateralAmountHuman`.
4. Optional `purposeTextAdditional`: e.g. `trend retest` or `{primaryTrendKind} trend`.
5. `autoSubmitMultisign`: **false**.

### Policy: key-level bounce default → perp limit (HL, Arcus, or GMX)

**When:** selected idea is **`key_levels`**, primary `setupPurposeCode` **`kl-bnc`** or **`kl-brk`**, `status: clear`, operator UI protocol is **hyperliquid**, **arcus**, or **gmx**.

**Protocol:** operator UI **`hyperliquid`**, **`arcus`**, or **`gmx`** (§5) — **not Uniswap** unless last price is within **`entryProximityPct`** of the bounce entry.

1. Use **bounce** offsets from §3 (`entryOffsetPct` / `invalidationOffsetPct` from desk defaults).
2. **Hyperliquid / Arcus:** open-context → `szHuman` (+ **`ed25519KeyGenId`** for Arcus). **GMX:** open-context → `sizeUsdHuman`, `collateralToken`, `collateralAmountHuman`.
3. Optional `purposeTextAdditional`: e.g. `kl bounce` or `Level #N support`.
4. `autoSubmitMultisign`: **false**.

### Policy: key-level Fibonacci 0.618 fade → perp limit (HL, Arcus, or GMX)

**When:** selected idea is **`key_level_fibonacci`**, `priceRegime: inside_range`, `setupPurposeCode` **`kl-fib`**, `status: clear`.

**Protocol:** **hyperliquid**, **arcus**, or **gmx** (§5) — not Uniswap unless last price is within **`entryProximityPct`** of the **Fib leg entry** (range high for upper-half short, range low for lower-half long, etc.).

1. Use **bounce** offsets from §3 ( **`entryOffsetPct`** adjusts the limit relative to the leg base entry).
2. Size from protocol open-context tools.
3. Optional `purposeTextAdditional`: e.g. `fib 618 fade`.
4. `autoSubmitMultisign`: **false**.

### Policy: Donchian breakout → perp limit (HL, Arcus, or GMX)

**When:** selected idea is **`donchian_breakout`**, `status: clear`, not **`invalidated`**, `setupPurposeCode` **`dc-ret`** or **`dc-brk`**.

**Protocol:** **`hyperliquid`**, **`arcus`**, or **`gmx`** (§5) — not Uniswap unless last price is within **`entryProximityPct`** of entry.

1. Prefer the **primary** setup from desk **`donchianEntryMode`**. Switch to nested **`immediateAlternative`** / **`breakRetestAlternative`** only when the operator asks or primary is **`unclear`** and the alternate is **`clear`** (mirror §1.1).
2. **`dc-ret`:** use **retest** offsets from §3; skip proximity gate on perp venues. **`dc-brk`:** use **bounce** offsets from §3.
3. Size from protocol open-context tools (same as trend-structure policy).
4. Optional `purposeTextAdditional`: e.g. `dc breakout` or `dc retest`.
5. `autoSubmitMultisign`: **false**.

### Policy: Supertrend → perp limit (HL, Arcus, or GMX)

**When:** selected idea is **`supertrend`**, `status: clear`, not **`invalidated`**, `setupPurposeCode` **`st-flip`** or **`st-ret`**.

**Protocol:** **`hyperliquid`**, **`arcus`**, or **`gmx`** (§5) — not Uniswap unless last price is within **`entryProximityPct`** of entry.

1. Prefer the **primary** setup from desk **`supertrendEntryMode`**. Switch to nested **`retestAlternative`** / **`flipAlternative`** only when the operator asks or primary is **`unclear`** and the alternate is **`clear`** (mirror §1.1).
2. **`st-flip`:** use **bounce** offsets from §3. **`st-ret`:** use **retest** offsets from §3; skip proximity gate on perp venues.
3. Size from protocol open-context tools (same as trend-structure policy).
4. Optional `purposeTextAdditional`: e.g. `st trail` or `st flip`.
5. `autoSubmitMultisign`: **false**.

### Policy: Ichimoku → perp limit (HL, Arcus, or GMX)

**When:** selected idea is **`ichimoku`**, `status: clear`, `setupPurposeCode` **`ichi-tk`** or **`ichi-cloud`**.

**Protocol:** **`hyperliquid`**, **`arcus`**, or **`gmx`** (§5) — not Uniswap unless last price is within **`entryProximityPct`** of entry.

1. Prefer primary **TK cross** (`ichi-tk`). Switch to nested **`cloudAlternative`** only when the operator asks or primary is **`unclear`** and the alternate is **`clear`** (mirror §1.1).
2. **`ichi-tk`:** use **bounce** offsets from §3. **`ichi-cloud`:** use **retest** offsets from §3; skip proximity gate on perp venues.
3. Size from protocol open-context tools (same as trend-structure policy).
4. Optional `purposeTextAdditional`: e.g. `ichi cloud` or `ichi tk`.
5. `autoSubmitMultisign`: **false**.

### Policy: Z-score mean reversion → perp limit (HL, Arcus, or GMX)

**When:** selected idea is **`z_score`**, `status: clear`, not **`invalidated`**, `setupPurposeCode` **`zs-fade`**.

**Protocol:** **`hyperliquid`**, **`arcus`**, or **`gmx`** (§5) — not Uniswap unless last price is within **`entryProximityPct`** of entry.

1. Use **bounce** offsets from §3 (`entryOffsetPct` / `invalidationOffsetPct` from desk defaults).
2. Size from protocol open-context tools.
3. Optional `purposeTextAdditional`: e.g. `zs fade`.
4. `autoSubmitMultisign`: **false**.

### Policy: Elliott wave impulse/diagonal → perp limit (HL, Arcus, or GMX)

**When:** selected idea is **`elliott_waves`**, `setupPurposeCode` **`ew-imp`** or **`ew-dia`**, `patternType` **`impulse`** or **`diagonal`**, `status: clear`, `side` is **long** or **short**.

**Protocol:** **`hyperliquid`**, **`arcus`**, or **`gmx`** (§5) — not Uniswap (limit-style projection entry).

1. Respect **`waveMenuNumber`** on the selected idea (default **1**).
2. Use desk **`entryOffsetPct` / `invalidationOffsetPct`** from §3 on perp limit venues; entry base is last close / trigger price from the setup.
3. Size from protocol open-context tools (same as trend-structure policy).
4. Optional `purposeTextAdditional`: e.g. `ew impulse` or `ew diagonal`.
5. `autoSubmitMultisign`: **false** unless cron policy below applies.

### Policy: key-level break retest alternate → perp limit (HL, Arcus, or GMX)

**When:** operator explicitly selects **`breakRetestAlternative`** (or asks for break+retest) on a **`key_levels`** idea with alternate `status: clear` and `setupPurposeCode` **`kl-ret`**.

**Protocol:** **`hyperliquid`**, **`arcus`**, or **`gmx`** (§5) — not Uniswap unless price is already at the retest entry.

1. Use **retest** offsets from §3; skip proximity gate on perp venues.
2. Size from protocol open-context tools (same as trend-structure policy).
3. Optional `purposeTextAdditional`: e.g. `kl break retest` or `broken Level #N`.
4. `autoSubmitMultisign`: **false**.

### Policy: cron auto-submit

**When:** operator message includes `tradeBuild` with fixed `tradeIdeaNumber` and sizing is inferable.

- Set **`autoSubmitMultisign`: true** only if this subsection explicitly allows it for that cron class.
- Cron YAML may set `protocolId`, `entryOffsetPct`, `invalidationOffsetPct`, and protocol-specific sizing fields from §5.
- Trade-analysis cron: before submit, enforce **momentum OR candlestick OR divergence** confirmation with matching side on the selected primary idea (template prose in **`trade_analysis_cron.example.md`**).
- End the cron turn with a concise operator summary (ideas found, selected `tradeIdeaId`, submitted or skipped). If the job has **`telegramNotify: true`**, the host sends that final answer to Telegram — do not call **`send_telegram_message`**.

### Policy template — new protocol

**When:** {describe idea filter — e.g. chart_pattern + setupPurposeCode}.

**Protocol:** `{protocol_id}` (§5 `{protocol_id}` or §5 template).

1. {Protocol} context tools → required prefill fields from §5 table.
2. Set offsets and flags from that protocol’s **defaults** table.
3. Optional `purposeTextAdditional`: `{short label}`.
4. `autoSubmitMultisign`: **false** (unless cron policy above applies).

---

## 7. Workflow

1. **`analyze_*`** → trade ideas upsert.
2. Operator selects **#N** (or cron sets `tradeIdeaNumber`).
3. Node loads **`trade-desk.yaml`** → deterministic prefill when eligible (SSE `trade_idea_prefill`); otherwise loads this skill → LLM prefill.
4. Operator submits, or **`autoSubmitMultisign`** → **`continuum__build_trade_from_trade_idea`**.
5. Approve in Sign Requests.

---

## 8. Trade ideas — conclusion / consensus (operator chat)

When the operator asks for a **conclusion**, **consensus**, **summary**, or **verdict** across trade ideas (e.g. “should I trade ETH now?”, “what’s your view from the trade ideas?”):

1. **Call `continuum__list_trade_ideas` first** — `tradeIdeas[]` is bound from the session; do not synthesize from memory or analysis run order alone.
2. **Cite `tradeIdeaNumber`** from `items[]` exactly (menu order: newest analysis first). Do **not** renumber by the order analyses were run.
3. **Quote chart lineage** from each item when present:
   - `chartDataSource` (`hl`, `cg`, `cmc`, `cb`, `bn`, …)
   - `chartInterval` (`1h`, `4h`, …)
   - `chartBarCount`
   Do **not** guess interval from chart title or operator phrasing.
4. Compare **`side`**, **`status`**, and **`confidence`** from tool JSON. State **hold** vs **build** clearly.
5. Do **not** call **`build_trade_from_*`** unless the operator explicitly asks to submit a multisign draft.

For cron-only automated submission after consensus gates, use **`submit_trade_from_consensus`** (see **`scheduled-automation`**).
