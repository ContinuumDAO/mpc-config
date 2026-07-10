# Trade defaults (build form prefill)

Load this skill when the operator opens the **Trade ideas** panel, selects a numbered trade idea, or before **`continuum__build_trade_from_trade_idea`**.

The node runs a focused LLM turn that **interprets this prose** against the **one trade idea the operator already selected** (menu `#N` from the UI, or `tradeIdeaNumber` from a cron `tradeBuild` block). The model may call balance / open-context / quote MCP tools (use **`continuum__`-prefixed** names from the chat tools list), then returns JSON that **prefills the build form**. The operator reviews, edits, and clicks **Submit multisign draft** — unless this skill explicitly enables automatic submission (below).

This skill is **not** machine-parsed YAML on the host. Do not put `tradeBuildDefaults` blocks here. Cron jobs may still set deterministic overrides in a fenced **`tradeBuild`** YAML block (see **`scheduled-automation`**).

## Scope

- Apply rules to the **selected** idea only — use its `symbol`, `side`, `confidence`, `status`, `entry`, `target`, `invalidation`, and `analysisSetup` (e.g. `patternName`, `entryPhase`, `entryOffsetMode`, `setupPurposeCode` for chart patterns).
- Do **not** pick a different idea or synthesize a new setup (that belongs in a future consensus skill).
- If this file is empty or not installed, prefill is skipped and behaviour is unchanged.

Chart-pattern trade ideas store **base** entry and invalidation at pattern boundaries (support bounce or broken-boundary retest). Measured-move **target** is unchanged. Use `entryPhase` and `entryOffsetMode` from `analysisSetup.setup` when choosing offset defaults.

## Build fields the model may prefill

| Field | Meaning |
|-------|---------|
| `protocolId` | Usually fixed by the UI (`hyperliquid`, `gmx`, `uniswap`) |
| `chainId` | EVM chain for multisign (999 Hyperliquid, 42161 GMX/Uni on Arbitrum) |
| `szHuman` | Hyperliquid size in coin units |
| `sizeUsdHuman` | GMX position USD or Uniswap approximate swap USD |
| `collateralToken` / `collateralAmountHuman` | GMX collateral |
| `marketKind` | Hyperliquid `perp` or `spot` |
| `tif` | Hyperliquid time-in-force: `alo`, `gtc`, or `ioc` |
| `entryOffsetPct` | Limit band beyond analysis **entry** at build time (see below) |
| `invalidationOffsetPct` | Stop band beyond analysis **invalidation** (pattern-failure level) |
| `useCustomGas` | Apply node Custom Gas Config when true |
| `purposeTextAdditional` | Extra multisign purpose suffix (ctm1 meta is prepended; **256** runes total; must not contain `\|` or `=`) |
| `autoSubmitMultisign` | When **true**, skip operator review and submit the multisign draft immediately (cron or UI) |

## Recommended desk defaults

Use these as starting values when prefill JSON does not specify otherwise:

```yaml
entryProximityPct: 1      # idea surfacing only — suppress inside bounces / Uni when price too far
entryOffsetPct: 1         # limit band beyond pattern entry at build
invalidationOffsetPct: 1  # stop band beyond pattern-failure invalidation
```

`entryProximityPct` is enforced when trade ideas are built from analysis (inside-pattern bounces, key levels, candlestick, Uniswap). It is **not** applied to post-breakout retest limits.

## entryOffsetPct (phase-aware)

Adjusts the limit/trigger price from trade idea **`entry.price`**. The node reads `entryOffsetMode` from the chart-pattern setup (`bounce` or `retest`):

| Mode | Long | Short |
|------|------|-------|
| **retest** (post-breakout) | entry × (1 + pct/100) — above broken level | entry × (1 − pct/100) — below broken level |
| **bounce** (inside pattern) | entry × (1 − pct/100) — below support | entry × (1 + pct/100) — above resistance |

Default **1.0** for chart-pattern limit builds unless this skill says otherwise.

Legacy behaviour (when `entryOffsetMode` is absent): long below entry, short above entry — same as **bounce**.

## invalidationOffsetPct

Widens the pattern-failure stop reference from **`invalidation.price`** (informational in Purpose / cron; not an automatic stop order yet):

| Side | Effective pattern-failure level |
|------|----------------------------------|
| **long** | invalidation × (1 − pct/100) — stop **below** failure level |
| **short** | invalidation × (1 + pct/100) — stop **above** failure level |

Default **1.0**.

### Example — falling wedge long retest

- Base entry (upper wedge / broken boundary): **1831**
- Base invalidation (lower wedge): **1700**
- `entryOffsetPct: 1` (retest) → effective entry **~1849**
- `invalidationOffsetPct: 1` → effective pattern-failure stop **1683**

Inside-pattern bounce at **S2 ≈ 1700** uses the same invalidation base; offset pushes the stop slightly below support.

## Purpose text (ctm1, ≤256 runes)

Multisign **Purpose** is auto-composed as compact pipe meta first, then optional human suffix:

```
ctm1|{proto}|{L|S}|{setup}|eE={px}|pfE={px}|{symShort}
```

| Token | Meaning | Example |
|-------|---------|---------|
| `ctm1` | Format version | fixed |
| `{proto}` | Protocol | `gmx`, `hl`, `uni` |
| `{L\|S}` | Side | `L` |
| `{setup}` | Setup code from analysis (not menu `#N`) | `fw-ret`, `fw-bnc`, `sym-ret` |
| `eE` | Effective entry (after `entryOffsetPct`) | `1849` |
| `pfE` | Effective pattern-failure invalidation (after `invalidationOffsetPct`) — **cron trigger** | `1683` |
| `{symShort}` | Index symbol only | `ETH` |

Optional when rune budget allows: `eB={base entry}`, `pfB={base invalidation}`.

Example:

```
ctm1|gmx|L|fw-ret|eE=1849|pfE=1683|ETH
```

With bases:

```
ctm1|gmx|L|fw-ret|eB=1831|eE=1849|pfB=1700|pfE=1683|ETH
```

**Cron scanning:** require prefix `ctm1|`. Side = field 3 (`L` / `S`). Extract `pfE=([0-9.]+)`. Long fail when mark ≤ pfE; short fail when mark ≥ pfE. Ignore legacy Purpose without `ctm1|`.

Common setup codes: `fw-ret` / `fw-bnc` (falling wedge), `sym-ret` (symmetrical triangle breakout-only), `kl-bnc` / `kl-brk`, `mom`, `candle`.

Trade idea menu **`#N`** stays in UI and agent chat only — never in Purpose.

## Example policies (edit for your desk)

**Falling wedge retest (GMX limit increase)**

When the selected idea is **chart_pattern** with `setupPurposeCode` **`fw-ret`** (or falling wedge + `entryPhase: post_breakout_retest`):

1. Call GMX open-context / balance tools for the idea’s symbol.
2. Set **`sizeUsdHuman`** and **`collateralToken`** / **`collateralAmountHuman`** from available collateral (respect market max leverage).
3. Set **`entryOffsetPct`** to **1.0**, **`invalidationOffsetPct`** to **1.0**.
4. Set **`useCustomGas`** to **false**.
5. Set **`purposeTextAdditional`** to `fw retest` (optional; ctm1 meta already encodes setup).
6. Leave **`autoSubmitMultisign`** **false**.

**Head & shoulders with high confidence (Hyperliquid perp)**

When the selected idea is a **chart_pattern** setup with `patternName` containing “head” and “shoulder”, and `confidence` ≥ **0.75**:

1. Call Hyperliquid open-context / balance tools for the idea’s symbol.
2. Set **`szHuman`** to **10%** of available margin allocated to that coin (respect leverage).
3. Set **`entryOffsetPct`** to **0.25** when `entryOffsetMode` is **bounce**; use **1.0** for **retest**.
4. Set **`invalidationOffsetPct`** to **1.0** when invalidation is present.
5. Set **`marketKind`** to **`perp`**, **`tif`** to **`gtc`**, **`useCustomGas`** to **false**.
6. Set **`purposeTextAdditional`** to `H&S rule`.
7. Leave **`autoSubmitMultisign`** **false** so the operator confirms size in the UI.

**Cron auto-submit**

When the operator message includes `tradeBuild` with a fixed `tradeIdeaNumber`, and sizing can be inferred from balance:

- Set **`autoSubmitMultisign`** to **true** only when this section explicitly says **“automatically submit multisign without operator review”** for that cron job class.
- Cron `tradeBuild` YAML may also set `entryOffsetPct` and `invalidationOffsetPct`.

## Workflow

1. Run **`analyze_*`** → trade ideas upsert (pattern-limit entry + proximity gate applied).
2. Operator selects idea **#N** in the UI (or cron sets `tradeIdeaNumber`).
3. Node loads this skill → LLM prefills the form (SSE `trade_idea_prefill`).
4. Operator edits and submits, **or** `autoSubmitMultisign` triggers **`continuum__build_trade_from_trade_idea`** directly.
5. Approve in Sign Requests.
