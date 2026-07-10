# Trade defaults (build form prefill)

Load when the operator opens **Trade ideas**, selects a numbered idea, or before **`continuum__build_trade_from_trade_idea`**.

The node runs a focused LLM turn that **interprets this skill** for the **one trade idea already selected** (UI menu `#N`, or cron `tradeBuild.tradeIdeaNumber`). The model may call balance / open-context / quote MCP tools, then returns JSON to **prefill the build form**. The operator reviews and submits — unless **`autoSubmitMultisign`** is enabled below.

This skill is **not** machine-parsed YAML on the host. Cron jobs may still set overrides in a fenced **`tradeBuild`** YAML block (see **`scheduled-automation`**).

---

## 1. Scope (all protocols)

- Apply rules to the **selected idea only** — use its `symbol`, `side`, `confidence`, `status`, `entry`, `target`, `invalidation`, and `analysisSetup`:
  - **chart_pattern:** `patternName`, `entryPhase`, `entryOffsetMode`, `setupPurposeCode`
  - **trend_structure:** `bias`, `structure`, `primaryTrendKind`, `primaryTrendTouchCount`, `entryOffsetMode` (always **`retest`**), `setupPurposeCode` (**`trend-ret`**)
  - **key_levels:** `levelNumber`, `framing`, `entryOffsetMode` (**`bounce`** default), `setupPurposeCode` (**`kl-bnc`** long bounce / **`kl-brk`** short rejection), `targetSource`, optional nested **`breakRetestAlternative`** (**`kl-ret`** when selected)
- Do **not** pick a different idea or invent a new setup.
- If this skill is not installed, prefill is skipped.

Chart-pattern ideas store **base** entry and invalidation at pattern boundaries (inside bounce or post-breakout retest). **Target** comes from measured move.

**Trend-structure** ideas (`analyze_trend_structure`) store **base entry** at the primary **support** (long bias) or **resistance** (short bias) trend-line retest; **invalidation** at the recent swing low/high; **target** at the opposing swing when available. Offsets below apply at **build** time on top of those base prices.

**Key-levels** ideas (`analyze_key_levels`) auto-upsert the **primary** setup only — **bounce** at nearest support (`kl-bnc`, long) or **rejection** at nearest resistance (`kl-brk`, short). Base entry sits at the menu level price; target is the next key level in trade direction when available, else a **Fibonacci 1.618 extension** from the bracketing fib pair (`targetSource: fib_extension`) with an HTF re-analysis advisory. A nested **`breakRetestAlternative`** may be present for operator/agent selection — it is **not** used unless this skill directs you to switch (see §1.1).

### 1.1 Key levels — default vs break+retest alternate

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

**Extension targets:** when `targetSource: fib_extension` (primary or alternate), prefer **hyperliquid** or **gmx** for resting limits; add HTF re-analysis note in `purposeTextAdditional` (e.g. `fib ext — HTF confirm`).

---

## 2. Universal prefill fields (every protocol)

These apply regardless of `protocolId`:

| Field | Applies to | Meaning |
|-------|------------|---------|
| `entryOffsetPct` | Perp limit protocols | Band beyond **base entry** at build (see §3) |
| `invalidationOffsetPct` | Perp limit protocols | Band beyond **base invalidation** / pattern-failure level (see §3) |
| `useCustomGas` | EVM protocols | Use node Custom Gas Config when **true** |
| `purposeTextAdditional` | All | Human suffix after auto **ctm1** meta (§4); **256** runes total; no `\|` or `=` |
| `autoSubmitMultisign` | All | **true** = submit without operator review (cron only when explicitly allowed here) |

**Desk defaults** (use when prefill JSON omits them):

```yaml
entryOffsetPct: 1
invalidationOffsetPct: 1
```

`entryProximityPct: 1` affects **idea surfacing** only (inside bounces, key levels, Uniswap) — not prefill JSON. Post-breakout retest limits and **trend-structure retest** limits skip proximity on perp venues. Uniswap still enforces proximity at **build** time (spot swap, not a resting limit at the trend line).

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
| `{setup}` | From analysis (`fw-ret`, `fw-bnc`, `sym-ret`, **`trend-ret`**, **`kl-bnc`**, **`kl-brk`**, **`kl-ret`**, …) — never menu `#N` |
| `eE` / `pfE` | Effective entry / pattern-failure after offsets |
| `eB` / `pfB` | Optional base prices when rune budget allows |

**Cron:** prefix `ctm1|`; side = field 3; `pfE=([0-9.]+)`; long fail if mark ≤ pfE, short fail if mark ≥ pfE.

---

## 5. Protocol reference

Pick **one row** based on UI `protocolId` or cron `tradeBuild.protocolId`. Only prefill fields listed for that protocol.

| `protocolId` | ctm1 `{proto}` | Order type | Default `chainId` | Required prefill fields | Optional prefill fields |
|--------------|----------------|------------|-------------------|-------------------------|-------------------------|
| **`hyperliquid`** | `hl` | Perp or spot **limit** | **999** (mainnet) / **998** (testnet) | `szHuman` | `marketKind` (`perp` \| `spot`), `tif` (`gtc` \| `alo` \| `ioc`) |
| **`gmx`** | `gmx` | Perp **limit increase** | **42161** (Arbitrum) | `sizeUsdHuman`, `collateralToken`, `collateralAmountHuman` | — |
| **`uniswap`** | `uni` | Spot **swap** (no limit entry) | **42161** (typical) | `sizeUsdHuman` | `slippageBps` (via build if set) |

Add new protocols: **(1)** one row in this table, **(2)** one subsection below (copy **§5 template**), **(3)** optional desk policy in §6. Keep universal fields (§2–§4) unchanged.

### hyperliquid

**Sizing:** call Hyperliquid open-context / balance tools for the idea’s **coin**; set **`szHuman`** in coin units (respect margin and leverage).

**Defaults for this desk:**

| Field | Value |
|-------|-------|
| `marketKind` | `perp` |
| `tif` | `gtc` |
| `entryOffsetPct` | `1` |
| `invalidationOffsetPct` | `1` |
| `useCustomGas` | `false` |

**Build path:** `continuum__build_trade_from_trade_idea` with `protocolId: hyperliquid`.

### gmx

**Sizing:** call GMX open-context / balance tools; set **`sizeUsdHuman`** (position notional USD) and **`collateralToken`** + **`collateralAmountHuman`**. Leverage = size ÷ collateral (market max applies). No separate leverage field.

**Defaults for this desk:**

| Field | Value |
|-------|-------|
| `collateralToken` | `USDC` (unless operator policy says otherwise) |
| `entryOffsetPct` | `1` |
| `invalidationOffsetPct` | `1` |
| `useCustomGas` | `false` |

**Build path:** `continuum__build_trade_from_trade_idea` with `protocolId: gmx`.

### uniswap

**Not a perp limit** — no `entryOffsetPct` on entry price for execution (proximity gate still applies to the idea). Set **`sizeUsdHuman`** as approximate swap USD.

**Trend-structure:** prefer **hyperliquid** or **gmx** for resting retest limits. Use Uniswap only when last price is already within **`entryProximityPct`** of the idea entry — otherwise the build will fail.

**Defaults for this desk:**

| Field | Value |
|-------|-------|
| `useCustomGas` | `false` |

**Build path:** `continuum__build_trade_from_trade_idea` with `protocolId: uniswap`.

### Template — new protocol (copy and fill in)

Duplicate this block when adding a venue. Replace `{placeholders}`. Register `protocolId` in the node/SDK build bridge before use.

| Item | Fill in |
|------|---------|
| **`protocolId`** | `{protocol_id}` — must match UI + `continuum__build_trade_from_trade_idea` |
| **ctm1 `{proto}`** | `{proto}` — 2–4 char code in Purpose (e.g. `hl`, `gmx`, `uni`) |
| **Order type** | `{order_type}` — e.g. perp limit, spot swap, limit increase |
| **Limit offsets (§3)** | `{yes \| no}` — **yes** if build uses `entryOffsetPct` / limit price from idea entry |
| **Default `chainId`** | `{chain_id}` (+ testnet if applicable) |
| **Required prefill fields** | `{field_a}`, `{field_b}`, … |
| **Optional prefill fields** | `{field_c}`, … or — |
| **MCP sizing tools** | `{tool_names}` — e.g. `ctm_{protocol}_fetch_open_context` |
| **Build path** | `continuum__build_trade_from_trade_idea` with `protocolId: {protocol_id}` |

**Sizing:** {Describe how to derive required fields from open-context / balance / quote tools for this protocol.}

**Defaults for this desk:**

| Field | Value |
|-------|-------|
| `entryOffsetPct` | `{1 \| omit if not limit}` |
| `invalidationOffsetPct` | `{1 \| omit if not limit}` |
| `useCustomGas` | `{true \| false}` |
| `{protocol_field}` | `{default}` |

**Build path:** `continuum__build_trade_from_trade_idea` with `protocolId: {protocol_id}`.

**Policy stub (§6):** When {idea filter} → protocol `{protocol_id}` → sizing from above → `autoSubmitMultisign: false`.

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
3. Node loads this skill → LLM prefills form (SSE `trade_idea_prefill`) using **§5 for the active protocol**.
4. Operator submits, or **`autoSubmitMultisign`** → **`continuum__build_trade_from_trade_idea`**.
5. Approve in Sign Requests.
