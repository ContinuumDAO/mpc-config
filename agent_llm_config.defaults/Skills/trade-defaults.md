# Trade defaults (build form prefill)

Load this skill when the operator opens the **Trade ideas** panel, selects a numbered trade idea, or before **`continuum__build_trade_from_trade_idea`**.

The node runs a focused LLM turn that **interprets this prose** against the **one trade idea the operator already selected** (menu `#N` from the UI, or `tradeIdeaNumber` from a cron `tradeBuild` block). The model may call balance / open-context / quote MCP tools (use **`continuum__`-prefixed** names from the chat tools list), then returns JSON that **prefills the build form**. The operator reviews, edits, and clicks **Submit multisign draft** — unless this skill explicitly enables automatic submission (below).

This skill is **not** machine-parsed YAML on the host. Do not put `tradeBuildDefaults` blocks here. Cron jobs may still set deterministic overrides in a fenced **`tradeBuild`** YAML block (see **`scheduled-automation`**).

## Scope

- Apply rules to the **selected** idea only — use its `symbol`, `side`, `confidence`, `status`, `entry`, `target`, `invalidation`, and `analysisSetup` (e.g. `patternName` for chart patterns).
- Do **not** pick a different idea or synthesize a new setup (that belongs in a future consensus skill).
- If this file is empty or not installed, prefill is skipped and behaviour is unchanged.

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
| `entryOffsetPct` | Limit price offset from analysis entry (see below) |
| `useCustomGas` | Apply node Custom Gas Config when true |
| `purposeTextAdditional` | Extra multisign purpose suffix (auto summary is prepended; **256** chars total) |
| `autoSubmitMultisign` | When **true**, skip operator review and submit the multisign draft immediately (cron or UI) |

## entryOffsetPct

Adjusts the limit/trigger price derived from the trade idea **`entry.price`**:

| Side | Effect |
|------|--------|
| **long** | Limit = entry × (1 − entryOffsetPct/100) — below analysis entry |
| **short** | Limit = entry × (1 + entryOffsetPct/100) — above analysis entry |

Default **0.0** — use the analysis entry exactly.

## Example policies (edit for your desk)

**Head & shoulders with high confidence (Hyperliquid perp)**

When the selected idea is a **chart_pattern** setup with `patternName` containing “head” and “shoulder”, and `confidence` ≥ **0.75**:

1. Call Hyperliquid open-context / balance tools for the idea’s symbol.
2. Set **`szHuman`** to **10%** of available margin allocated to that coin (respect leverage).
3. Set **`entryOffsetPct`** to **0.25** (slightly inside the neckline trigger).
4. Set **`marketKind`** to **`perp`**, **`tif`** to **`gtc`**, **`useCustomGas`** to **false**.
5. Set **`purposeTextAdditional`** to `H&S rule`.
6. Leave **`autoSubmitMultisign`** **false** so the operator confirms size in the UI.

**Cron auto-submit**

When the operator message includes `tradeBuild` with a fixed `tradeIdeaNumber`, and sizing can be inferred from balance:

- Set **`autoSubmitMultisign`** to **true** only when this section explicitly says **“automatically submit multisign without operator review”** for that cron job class.

## Workflow

1. Run **`analyze_*`** → trade ideas upsert.
2. Operator selects idea **#N** in the UI (or cron sets `tradeIdeaNumber`).
3. Node loads this skill → LLM prefills the form (SSE `trade_idea_prefill`).
4. Operator edits and submits, **or** `autoSubmitMultisign` triggers **`continuum__build_trade_from_trade_idea`** directly.
5. Approve in Sign Requests.
