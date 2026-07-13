# Trade defaults (build form prefill)

Load when the operator opens **Trade ideas**, selects a numbered idea, or before **`continuum__build_trade_from_trade_idea`**.

**Desk numeric defaults** (offsets, proximity, protocol sizing, `marketKind`, `tif`, `autoSubmitMultisign`) are machine-parsed from **`trade-desk.yaml`** beside `agent_llm_config/` (seeded from `agent_llm_config.defaults/trade-desk.yaml`). The node applies them on a **deterministic fast path** for clear ideas — no LLM round-trip.

**This skill** is for **policy-only** cases the fast path cannot decide: break+retest alternates, fib regime switching, unclear status with a clear alternate, and discretionary `purposeTextAdditional`. When the fast path applies, the operator still reviews the prefilled form unless **`autoSubmitMultisign`** is enabled in `trade-desk.yaml` or cron **`tradeBuild`** YAML.

Cron jobs may still set overrides in a fenced **`tradeBuild`** YAML block (see **`scheduled-automation`**).

---

## 1. Scope (all protocols)

- Apply rules to the **selected idea only** — use its `symbol`, `side`, `confidence`, `status`, `entry`, `target`, `invalidation`, and `analysisSetup`:
  - **chart_pattern:** `patternName`, `entryPhase`, `entryOffsetMode`, `setupPurposeCode`
  - **trend_structure:** `bias`, `structure`, `primaryTrendKind`, `primaryTrendTouchCount`, `entryOffsetMode` (always **`retest`**), `setupPurposeCode` (**`trend-ret`**)
  - **key_levels:** `levelNumber`, `framing`, `entryOffsetMode` (**`bounce`** default), `setupPurposeCode` (**`kl-bnc`** long bounce / **`kl-brk`** short rejection), `targetSource`, optional nested **`breakRetestAlternative`** (**`kl-ret`** when selected)
  - **key_level_fibonacci:** `fibPairNumber`, `priceRegime` (`inside_range` | `above_range` | `below_range`), `framing`, `entryOffsetMode`, `setupPurposeCode` (**`kl-fib`** 0.618 retrace / **`kl-fib-ext`** range extension / **`kl-fib-ret`** when break+retest alternate selected), `targetSource` (`retrace_618` | `range_leg` | `fib_extension`), optional nested **`breakRetestAlternative`**
  - **bollinger_bands:** `setupPurposeCode` (**`bb-fade`**), `entryOffsetMode` (**`bounce`**), band **`period`** **20**, **`stdDev`** **2**, **`entryProximityPct`** **5** (% of **band width** — gates `clear` vs `unclear`)
  - **moving_averages:** `strategy` (**`crossover`** | **`proximity_retest`**), `setupPurposeCode` (**`ma-cross`** crossover at last close | **`ma-ret`** slow-MA retest), `fastPeriod` **50**, `slowPeriod` **200**, `maType` **`sma`**, `entryOffsetMode` (**`bounce`** for crossover, **`retest`** for proximity), **`entryProximityPct`** **1** with desk **`entryProximityMode`** (**`price`** | **`atr`**)
- Do **not** pick a different idea or invent a new setup.
- If this skill is not installed, prefill is skipped.

Chart-pattern ideas store **base** entry and invalidation at pattern boundaries (inside bounce or post-breakout retest). **Target** comes from measured move.

**Trend-structure** ideas (`analyze_trend_structure`) store **base entry** at the primary **support** (long bias) or **resistance** (short bias) trend-line retest; **invalidation** at the recent swing low/high; **target** at the opposing swing when available. Offsets below apply at **build** time on top of those base prices.

**Key-levels (nearest)** ideas (`analyze_key_levels`) auto-upsert the **primary** setup only — **bounce** at nearest support (`kl-bnc`, long) or **rejection** at nearest resistance (`kl-brk`, short). Base entry sits at the menu level price; target is the **next key level** in trade direction when available (`targetSource: next_level`). A nested **`breakRetestAlternative`** may be present for operator/agent selection — it is **not** used unless this skill directs you to switch (see §1.1).

**Key-level Fibonacci** ideas (`analyze_key_level_fibonacci`) use the **outer concentric** swing range. Regime depends on last close vs range legs:

| Regime | Last close | Primary setup | Target |
|--------|------------|---------------|--------|
| **`inside_range`** | Between range low and high | Bounce at **Fib leg** (`kl-fib`, `entryOffsetMode: bounce`): **upper half → short at Fib 1.0 (range high)** toward 0.618; **lower half → long at Fib 1.0 inverted (range low)** toward inverted 0.618. Opposite-side variant uses the other leg (long at Fib 0 / short at Fib 0 inverted) toward the opposite range leg. | Default variant: **Fib 0.618** retrace (`retrace_618`); opposite variant: opposite range leg (`range_leg`) |
| **`above_range`** | Above range high | **Long** retest at **Fib 1.0** (range high; `kl-fib-ext`, `entryOffsetMode: retest`) — actionable when last close is within **`entryProximityPct`** of the leg or inside the **`entryOffsetPct`** retest band (§3) | **Fib 1.618 extension above** high (`fib_extension`) |
| **`below_range`** | Below range low | **Short** retest at **Fib 1.0 inverted** (range low; `kl-fib-ext`, `entryOffsetMode: retest`) — same proximity / retest-band gates | **Fib 1.618 extension below** low (`fib_extension`; chart Fib overlay reversed) |

Nested **`breakRetestAlternative`** on fib ideas (`kl-fib-ret`) waits for **retest at the broken range leg** before the same 1.618 extension target — mirror §1.1 switching rules (§1.2).

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

**Extension targets:** when `targetSource: fib_extension` (nearest alternate only, or fib primary/alternate), prefer **hyperliquid** or **gmx** for resting limits; add HTF re-analysis note in `purposeTextAdditional` (e.g. `fib ext — HTF confirm`).

### 1.2 Key level Fibonacci — default vs break+retest alternate

**Default (auto-upserted fib idea):** use **primary** `keyLevelFibTradeSetup` — do **not** substitute `breakRetestAlternative` unless the operator explicitly requests break+retest or the conditions below match.

| Path | When | `setupPurposeCode` | `entryOffsetMode` |
|------|------|--------------------|-------------------|
| **Inside range — 0.618 retrace** | `priceRegime: inside_range` | **`kl-fib`** | **`bounce`** |
| **Above range — extension long** | `priceRegime: above_range` | **`kl-fib-ext`** | **`retest`** |
| **Below range — extension short** | `priceRegime: below_range` | **`kl-fib-ext`** | **`retest`** |
| **Break + retest alternate** | Operator asks for “fib break retest”, “retest broken range leg”, or primary extension is **`unclear`** but `breakRetestAlternative.status === 'clear'`; **or** desk policy favors retest over continuation at the broken high/low | **`kl-fib-ret`** | **`retest`** |

**Switching to the fib alternate (prefill LLM):**

1. Read `breakRetestAlternative` from `analysisSetup.setup` on the **same** selected **`key_level_fibonacci`** idea.
2. Use its `entryPrice`, `targetPrice`, `invalidationPrice`, `brokenLevelNumber`, and `setupPurposeCode: kl-fib-ret`.
3. Apply **retest** offsets from §3; **skip proximity gate** on perp limit venues.
4. Optional `purposeTextAdditional`: e.g. `fib break retest` or `Level #N range leg retest`.

**Chart apply:** `apply_key_fib_drawings` with **`fibPairNumber`** draws the Fib overlay (0 / 0.618 / 1) plus leg levels; when `targetSource: fib_extension`, also draws the bold **1.618 extension** target line. Below-range setups use **reversed** Fib orientation on chart (`displayTrend: down`).

**Desk percentages on setup (match §2 defaults):** each `keyLevelFibTradeSetup` includes **`entryProximityPct: 1`**, **`entryOffsetPct: 1`**, **`invalidationOffsetPct: 1`**. Analysis uses these when assessing entry actionability:

| Regime | Entry assessment |
|--------|------------------|
| **`inside_range`** (`kl-fib`, bounce) | Last close within **`entryProximityPct`** of the **Fib leg entry** (Fib 1.0 / Fib 0 per variant — not the 0.618 target). At **build**, **`entryOffsetPct`** (bounce mode) shifts the resting limit slightly beyond that leg (§3). |
| **`above_range` / `below_range`** (`kl-fib-ext`, retest) | Last close within **`entryProximityPct`** of **Fib 1.0 leg entry**, or inside the **`entryOffsetPct`** retest band between the broken leg and the offset limit (§3). At **build**, resting limit uses **retest** offsets on perp venues (proximity skipped on perp prefill per §2). |
| **`breakRetestAlternative`** (`kl-fib-ret`) | Bar retest at broken leg (break detect); prefill uses **retest** offsets, skips proximity on perp |

Same desk fields are on **`keyLevelsTradeSetup`** for nearest analysis (bounce uses **`entryProximityPct`**).

**Bollinger bands** ideas (`analyze_bollinger_bands`) are **band-to-band fades**: above middle → **short** at **upper** band toward **lower**; below middle → **long** at **lower** band toward **upper**. Base entry is the outer band price; target is the **opposite** band. Invalidation is band breach (above upper for short, below lower for long). Idea is **`clear`** only when last close is within **`entryProximityPct`** (**5** by default, % of band width). Use **`setupPurposeCode: bb-fade`**, **`entryOffsetMode: bounce`**, and desk **`entryOffsetPct` / `invalidationOffsetPct`** from §2 at build time. Chart overlay defaults (`period`, `stdDev`, shaded fill) live in **`chart-defaults`**.

**Moving averages** ideas (`analyze_moving_averages`) support two strategies from the same fast/slow pair (default **SMA 50/200**):

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
| `entryOffsetPct` / `invalidationOffsetPct` | Perp limit bands (see §3) |
| `useCustomGas` | EVM Custom Gas Config |
| `entryProximityMode` / `entryProximityPct` | Idea surfacing gates (`price` \| `atr`; Bollinger uses band-width % on the setup) |
| `autoSubmitMultisign` | Submit without operator review (cron only when explicitly allowed) |
| `expiryMinutesFromNow` | Optional multisign expiry (Unix seconds computed at prefill time) |

**Protocol blocks** (`hyperliquid`, `gmx`, `uniswap`): `marketKind`, `tif`, `collateralToken`, `sizing` (`fixed` or `marginPct` for Hyperliquid), and optional `purposeSuffix` per analysis kind.

**LLM fallback** (this skill): `llmFallback` in `trade-desk.yaml` lists when the fast path is skipped — e.g. `status: unclear`, `setupPurposeCode` **`kl-ret`** / **`kl-fib-ret`**, or primary unclear with a clear **`breakRetestAlternative`**.

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

### invalidationOffsetPct

Informational in Purpose / cron — not an automatic stop order yet.

| Side | Effective pattern-failure level |
|------|----------------------------------|
| Long | invalidation × (1 − pct/100) |
| Short | invalidation × (1 + pct/100) |

### Worked examples (any perp limit protocol)

Falling wedge **long retest**: base entry **1831** (upper wedge), base invalidation **1700** (lower wedge), both offsets **1%** → effective entry **~1849**, effective `pfE` **1683**.

Bullish **trend-structure long retest**: base entry **2950** (support trend line), base invalidation **2800** (recent swing low), both offsets **1%** → effective entry **~2979.5**, effective `pfE` **2772**. Purpose setup code **`trend-ret`**.

---

## 4. Purpose text — ctm1 (all protocols)

Auto-composed first; optional `purposeTextAdditional` after ` · ` if runes remain.

```
ctm1|{proto}|{L|S}|{setup}|eE={px}|pfE={px}|{symShort}
```

| Token | Meaning |
|-------|---------|
| `{proto}` | Protocol short code — see protocol table in §5 (`hl`, `gmx`, `uni`, …) |
| `{setup}` | From analysis (`fw-ret`, `fw-bnc`, `sym-ret`, **`trend-ret`**, **`kl-bnc`**, **`kl-brk`**, **`kl-ret`**, **`kl-fib`**, **`kl-fib-ext`**, **`kl-fib-ret`**, **`bb-fade`**, **`ma-cross`**, **`ma-ret`**, …) — never menu `#N` |
| `eE` / `pfE` | Effective entry / pattern-failure after offsets |
| `eB` / `pfB` | Optional base prices when rune budget allows |

**Cron:** prefix `ctm1|`; side = field 3; `pfE=([0-9.]+)`; long fail if mark ≤ pfE, short fail if mark ≥ pfE.

---

## 5. Protocol reference (trade-desk.yaml)

Protocol-specific defaults and sizing live under **`trade-desk.yaml` → `protocols:`**. Required build fields:

| `protocolId` | Required prefill fields |
|--------------|-------------------------|
| **`hyperliquid`** | `szHuman` (coin units; fast path uses `sizing.marginPct` + one `fetch_open_context` call, or `sizing.fixed`) |
| **`gmx`** | `sizeUsdHuman`, `collateralToken`, `collateralAmountHuman` |
| **`uniswap`** | `sizeUsdHuman` (spot swap; proximity enforced at build) |

ctm1 `{proto}` codes: `hl`, `gmx`, `uni`. Default chainIds: Hyperliquid **999**, GMX / Uniswap **42161**.

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

### Policy: trend-structure clear idea → perp limit (HL or GMX)

**When:** selected idea is **`trend_structure`**, `setupPurposeCode` **`trend-ret`**, `status: clear`, `side` is **long** or **short**.

**Protocol:** operator UI **`hyperliquid`** or **`gmx`** (§5) — **not Uniswap** unless price is already at the retest entry.

1. Use **retest** offsets from §3 (`entryOffsetPct` / `invalidationOffsetPct` from desk defaults).
2. **Hyperliquid:** open-context → `szHuman`. **GMX:** open-context → `sizeUsdHuman`, `collateralToken`, `collateralAmountHuman`.
3. Optional `purposeTextAdditional`: e.g. `trend retest` or `{primaryTrendKind} trend`.
4. `autoSubmitMultisign`: **false**.

### Policy: key-level bounce default → perp limit (HL or GMX)

**When:** selected idea is **`key_levels`**, primary `setupPurposeCode` **`kl-bnc`** or **`kl-brk`**, `status: clear`, operator UI protocol is **hyperliquid** or **gmx**.

**Protocol:** operator UI **`hyperliquid`** or **`gmx`** (§5) — **not Uniswap** unless last price is within **`entryProximityPct`** of the bounce entry.

1. Use **bounce** offsets from §3 (`entryOffsetPct` / `invalidationOffsetPct` from desk defaults).
2. **Hyperliquid:** open-context → `szHuman`. **GMX:** open-context → `sizeUsdHuman`, `collateralToken`, `collateralAmountHuman`.
3. Optional `purposeTextAdditional`: e.g. `kl bounce` or `Level #N support`.
4. When `targetSource: fib_extension`, note HTF confirmation in `purposeTextAdditional`.
5. `autoSubmitMultisign`: **false**.

### Policy: key-level Fibonacci extension → perp limit (HL or GMX)

**When:** selected idea is **`key_level_fibonacci`**, `setupPurposeCode` **`kl-fib-ext`** or **`kl-fib-ret`**, `targetSource: fib_extension`, `status: clear`, operator UI protocol is **hyperliquid** or **gmx**.

**Protocol:** operator UI **`hyperliquid`** or **`gmx`** (§5) — not Uniswap unless price is already at the retest entry.

1. Use **retest** offsets from §3; skip proximity gate on perp venues.
2. Size from protocol open-context tools (same as trend-structure policy).
3. Optional `purposeTextAdditional`: e.g. `fib 1.618 ext` or `fib range break`.
4. Note HTF confirmation when `higherTimeframeAdvisory` is set on the idea.
5. `autoSubmitMultisign`: **false**.

### Policy: key-level Fibonacci 0.618 retrace → perp limit (HL or GMX)

**When:** selected idea is **`key_level_fibonacci`**, `priceRegime: inside_range`, `setupPurposeCode` **`kl-fib`**, `status: clear`.

**Protocol:** **hyperliquid** or **gmx** (§5) — not Uniswap unless last price is within **`entryProximityPct`** of the **Fib leg entry** (range high for upper-half short, range low for lower-half long, etc.).

1. Use **bounce** offsets from §3 ( **`entryOffsetPct`** adjusts the limit relative to the leg base entry).
2. Size from protocol open-context tools.
3. Optional `purposeTextAdditional`: e.g. `fib 0.618 retrace`.
4. `autoSubmitMultisign`: **false**.

### Policy: key-level break retest alternate → perp limit (HL or GMX)

**When:** operator explicitly selects **`breakRetestAlternative`** (or asks for break+retest) on a **`key_levels`** idea with alternate `status: clear` and `setupPurposeCode` **`kl-ret`**.

**Protocol:** **`hyperliquid`** or **`gmx`** (§5) — not Uniswap unless price is already at the retest entry.

1. Use **retest** offsets from §3; skip proximity gate on perp venues.
2. Size from protocol open-context tools (same as trend-structure policy).
3. Optional `purposeTextAdditional`: e.g. `kl break retest` or `broken Level #N`.
4. When alternate `targetSource: fib_extension`, note HTF confirmation.
5. `autoSubmitMultisign`: **false**.

### Policy: cron auto-submit

**When:** operator message includes `tradeBuild` with fixed `tradeIdeaNumber` and sizing is inferable.

- Set **`autoSubmitMultisign`: true** only if this subsection explicitly allows it for that cron class.
- Cron YAML may set `protocolId`, `entryOffsetPct`, `invalidationOffsetPct`, and protocol-specific sizing fields from §5.

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
