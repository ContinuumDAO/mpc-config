## Analysis + optional trade submit (multi-protocol)

### How to use this template

This file is a **read-only copy-paste guide** — it is **not** a bundled catalog job. In continuumdao-node-app open **Agent → Cron → View template**, or copy from **`agent_llm_config.defaults/cron/trade_analysis_cron.example.md`** in mpc-config. Paste into a **custom cron job** (**+** on the Cron tab) as the job **`message`**.

**Do not paste this entire document unchanged.** Customize it for one symbol, one schedule, and **one execution protocol**. The agent runs non-interactively — every choice (symbol, interval, lookback, protocol, sizing) must be **frozen in the message** or in node defaults before the job runs.

#### Two configuration layers

| Layer | Where | What it holds |
|-------|--------|----------------|
| **Node-wide defaults** | **`agent_llm_config/cron/trade-cron.yaml`** — edit on **Cron → Trade cron** (or bundled defaults until installed) | Default **`tradeConsensus`** + **`tradeBuild`** for every trade-analysis cron on this node |
| **Per-job message** | Custom cron job **`message`** field | Workflow prose + optional fenced YAML that **overrides** `trade-cron.yaml` for **this job only** |

On each run, mpc-auth uses YAML fences **in the job message** when present; otherwise it falls back to **`trade-cron.yaml`**.

#### What to put in the custom cron message

| Include | Notes |
|---------|--------|
| **Workflow prose** | **Steps** below — edit step 1 with your symbol, interval, and lookback; drop optional `analyze_*` steps you do not want |
| **Selection guidance** | How to pick **`tradeIdeaId`** before **`submit_trade_from_consensus`** — trim if you only care about one idea type |
| **One** **`tradeConsensus`** YAML fence | Pick **one** example block below — not all examples |
| **One** **`tradeBuild`** YAML fence | Pick **one** protocol block below (Hyperliquid, GMX, Arcus, or Uniswap) — **delete the other protocol examples** |

**Reference only (do not need to paste):** the protocol table, chain-ID notes, and Arcus/Uniswap caveats — unless you want them inline for the agent.

#### Recommended setup patterns

**Pattern A — split (good when you run several trade crons on one node)**

1. Configure **`tradeConsensus`** + **`tradeBuild`** once under **Cron → Trade cron** for your venue and sizing.
2. Custom job **`message`** = opening instructions + customized **Steps** + **Selection guidance** only (no YAML fences unless this job needs different gates than the node file).
3. Create the job, **Run now** once, then enable on schedule.

**Pattern B — self-contained (good for one-off or per-job overrides)**

1. Copy **Steps** + **Selection guidance** into the job **`message`**.
2. Append **one** **`tradeConsensus`** fence and **one** **`tradeBuild`** fence for your protocol.
3. Remove every other protocol’s **`tradeBuild`** example from the pasted text.

**Pattern C — spawn strands (multi-analyze; uses cron supervisor tools)**

Use when the job runs **several** `analyze_*` families and you want pack-scoped leaf specialists instead of one fat tool loop. Host exposes `agent_spawn_sub_agent` / `agent_join_sub_agents` on cron turns.

1. **Parent (cron supervisor):** load OHLCV source + execution protocol; **`fetch_ohlcv`** once; keep the session on this **`[Cron]`** conversation. Do **not** spawn before fetch.
2. **Spawn 2–3 specialists** (leaves) with `toolGroups: ["chart:analyze"]` (add `defi:<protocol>:market-data` only if a strand must re-fetch). Example strands:
   - Structure: `analyze_chart_patterns`, `analyze_trend_structure`, `analyze_key_levels`, `analyze_key_level_fibonacci`, `analyze_elliott_waves`
   - Momentum / confirmation: `analyze_momentum`, `analyze_candlestick_patterns`, `analyze_divergence`
   - Oscillators / channels: `analyze_bollinger_bands`, `analyze_donchian_breakout`, `analyze_supertrend`, `analyze_ichimoku`, `analyze_z_score`, `analyze_moving_averages`
3. **`agent_join_sub_agents`** — specialists upsert **`tradeIdeas[]`** on the parent conversation; compress summaries return as tool results.
4. **Parent only:** selection guidance → **`submit_trade_from_consensus`** when enabled. Specialists must **not** submit, build trades, or prepare/apply charts.

Stay on Pattern A/B (single-loop) for jobs with **one** primary `analyze_*` or when you want maximum simplicity.

#### Operator checklist

- [ ] Symbol, interval, and lookback are explicit in step 1 (Elliott needs **≥200** bars when possible; **≥50** hard minimum)
- [ ] Exactly **one** execution **`protocolId`** in **`tradeBuild`** (or in **Trade cron** defaults)
- [ ] **`submitTradeFromConsensus: false`** for the first **Run now** (hint-only dry-run); set **`true`** only after you trust selection + sizing
- [ ] Arcus: **`ed25519KeyGenId`** filled in; API key registered before live cron
- [ ] Uniswap build: only for proximity-gated ideas — prefer HL / Arcus / GMX for trend, levels, and fib limits

Load skill **`scheduled-automation`** for schedule kinds and non-interactive rules.

---

Load MCP: **continuum** (chart bundle) + **one DeFi protocol for execution** (see **`tradeBuild.protocolId`** below). Non-interactive. Load skill **`trade-defaults`** when prefill/build runs.

Embed **frozen** operator choices in the cron **`message`**: symbol, candle interval, lookback, **`tradeBuild.protocolId`**, chain, and sizing defaults — do not ask mid-run.

### Protocol setup (pick one execution venue)

| `tradeBuild.protocolId` | Load for **build/submit** | OHLCV for **`analyze_*`** | Sizing fields (prefill / `tradeBuild`) |
|-------------------------|---------------------------|-----------------------------|----------------------------------------|
| **`hyperliquid`** | `load_defi_protocol` **hyperliquid** | Same — `ctm_hyperliquid_fetch_ohlcv` | `szHuman`, optional `marketKind` (`perp`\|`spot`), `tif` |
| **`arcus`** | `load_defi_protocol` **arcus** | Perp: `ctm_arcus_fetch_ohlcv`; spot: `ctm_arcus_spot_fetch_ohlcv` (chain **4663**) | `szHuman`, `marketKind` (`perp`\|`spot`), `tif` (perp); **`ed25519KeyGenId`** (paired KeyGen, same GroupId as `keyGenId`) |
| **`gmx`** | `load_defi_protocol` **gmx** | Same — `ctm_gmx_fetch_ohlcv` (explicit **`chainId`**) | `sizeUsdHuman`, `collateralToken`, `collateralAmountHuman` |
| **`uniswap`** | `load_defi_protocol` **uniswap** (V4) | **Separate source required** — Uniswap has no protocol OHLCV. Cron message must name one: load **hyperliquid**, **arcus**, or **gmx** for perp candles, **or** load **coingecko** / **coinmarketcap-public** / **coinbase-public** for spot series (trend/levels/patterns need **`dataKind: ohlcv`** — prefer HL/Arcus/GMX for full menu). | `sizeUsdHuman` (spot swap USD) |

**Chain IDs (typical):** Hyperliquid **999** (mainnet) / **998** (testnet); Arcus (Robinhood Chain) **4663**; GMX & Uniswap on Arbitrum **42161** — confirm via protocol supported-chains in staging.

**Trend / limit-style ideas on Uniswap:** spot swap only — no resting limit at structure. Prefer **`hyperliquid`**, **`arcus`**, or **`gmx`** in `tradeBuild` for **`trend_structure`**, **`key_levels`**, fib **618 fade**, **Donchian** (`dc-ret` / `dc-brk`), and **Z-score** (`zs-fade`) ideas. Use **`uniswap`** only when last price is already within desk **`entryProximityPct`** of the idea entry — per **`entryProximityMode`** in **`trade-defaults`** §2 (`price` = % of entry; `atr` = % of ATR).

**Arcus trading:** requires paired KeyGens (secp256k1 custody + ed25519 API signing, same `GroupId`). Register API key once via multisign before orders. Spot RFQ has no bracket TP/SL at build.

### Steps (prose — customize)

1. Load OHLCV source per table above; **`fetch_ohlcv`** (or equivalent) for operator symbol/interval/lookback. Keep the same session for all analysis tools (`toolResult` / `ohlcvDigest`). When this cron includes **`analyze_elliott_waves`**, load **≥200** bars when possible (hard minimum **50**; **≥400** preferred for primary-degree counts — e.g. 4H × 60d or 1D × 90d). If `dataStatus` is **`insufficient_data`**, quote **`dataGuidance`** and skip Elliott-based submit for that run. **`analyze_candlestick_patterns`** needs **≥14** bars (same fetch).
2. `analyze_chart_patterns` on the session-bound OHLCV.
3. `analyze_momentum` on the same session (upserts **`momentum`** / `momentumTradeSetup` — RSI/MACD bias; often **`partial`**).
3b. Optional: `analyze_divergence` on the same session (upserts **`divergence`** / `divergenceTradeSetup` — regular/hidden RSI & Stoch RSI; pivot-structure entry/target/invalidation when **`clear`**).
4. `analyze_candlestick_patterns` on the same session (upserts **`candlestick`** / `candlestickTradeSetup`; **`signal`** buy/sell/hold, **`side`** long/short/neutral from bullish/bearish primary hit). Requires **≥14** bars.
5. `analyze_trend_structure` on the same session (upserts **`trend_structure`** / `trendStructureTradeSetup`, `setupPurposeCode` **`trend-ret`**).
6. `analyze_key_levels` on the same session (nearest bounce/rejection — upserts **`key_levels`** / `keyLevelsTradeSetup`).
7. `analyze_key_level_fibonacci` on the same session (strongest-bracket **0.618** fade — upserts **`key_level_fibonacci`** / `keyLevelFibTradeSetup`; quote both leg Level #s).
8. `analyze_elliott_waves` on the same session (upserts **`elliott_waves`** / `elliottWaveTradeSetup`; optional `waveMenuNumber`, default **1** — use menu # from **`waveMenu`** when pinning). **`corrective`** (`ew-corr`) stays **`unclear`**; cron submit uses **`ew-imp`** / **`ew-dia`** only when **`status=clear`**. Chart labels are optional in cron — **`apply_elliott_wave_drawings`** is not required for trade submit.
9. Optional: `analyze_bollinger_bands` on the same session (upserts **`bollinger_bands`** / `bollingerTradeSetup`, `setupPurposeCode` **`bb-fade`**).
9b. Optional: `analyze_donchian_breakout` on the same session (upserts **`donchian_breakout`** / `donchianTradeSetup`; period/mode from **`trade-desk.yaml`** `donchianPeriod` / `donchianEntryMode`; `dc-ret` or `dc-brk`).
9c. Optional: `analyze_z_score` on the same session (upserts **`z_score`** / `zScoreTradeSetup`; knobs from **`trade-desk.yaml`**; `zs-fade`).
9d. Optional: `analyze_supertrend` on the same session (upserts **`supertrend`** / `supertrendTradeSetup`; knobs from **`trade-desk.yaml`** `supertrendPeriod` / `supertrendMultiplier` / `supertrendEntryMode`; `st-flip` or `st-ret`).
9e. Optional: `analyze_ichimoku` on the same session (upserts **`ichimoku`** / `ichimokuTradeSetup`; knobs from **`trade-desk.yaml`** 9/26/52/26; `ichi-tk` or `ichi-cloud`).
10. Optional: `analyze_moving_averages` on the same session (upserts **`moving_averages`** / `movingAveragesTradeSetup`, `setupPurposeCode` **`ma-cross`** or **`ma-ret`** per `tradeSummary`).
11. If consensus gate **ALLOWED** and submit enabled, call **`submit_trade_from_consensus`** with **`tradeIdeaId`** per selection rules below. Resolve sizing from **execution** protocol open-context (Hyperliquid / GMX / Uniswap quote tools per **`trade-defaults`** §5).

Steps 5–10 share the same OHLCV session; each upserts a **separate** trade idea (`analysisType` distinct). Steps 3–4 (and optional 3b) are **confirmation** sources (momentum and/or candlestick and/or divergence), not substitutes for a structural primary idea unless you retarget the cron (see **`tradeConsensus`** examples).

### Selection guidance (prose — agent decides tradeIdeaId)

#### Confirmation rule — momentum **OR** candlestick **OR** divergence (required before submit)

Every **primary** structural idea you submit (**chart_pattern**, **trend_structure**, **elliott_waves**, **key_levels**, **key_level_fibonacci**, **bollinger_bands**, **donchian_breakout**, **supertrend**, **ichimoku**, **z_score**, **moving_averages**) must be **confirmed** by **at least one** of **`momentum`**, **`candlestick`**, or **`divergence`** with **matching side**:

| Primary `side` | Accept when **any** supporter is **`clear`** (or momentum **`partial`** / divergence **`clear`** with matching side when `allowPartial: true`) |
|----------------|-----------------------------------------------------------------------------------------------------------------------------|
| **long** | **`momentum`** `side: long` **OR** **`candlestick`** `side: long` **OR** **`divergence`** `side: long` |
| **short** | **`momentum`** `side: short` **OR** **`candlestick`** `side: short` **OR** **`divergence`** `side: short` |

- If **both** supporters are present and **conflict** (one long, one short), **do not submit**.
- If **neither** supporter matches the primary side, **do not submit** — even when the YAML consensus gate is **ALLOWED**.
- **`candlestick`**, **`momentum`**, and **`divergence`** are **confirmation only** in this template by default — do not submit them as the primary **`tradeIdeaId`** unless you retarget the cron (see **`tradeConsensus`** examples). Divergence may also be selected as a standalone primary when `status=clear` and `completeness: full`.
- Standalone candlestick hit rates are weak (~50–55%); pairing with structure is intentional (see skill **`chart-analysis-patterns`**).

#### Primary idea priority (after confirmation passes)

Prefer **chart_pattern** when `status=clear` and confirmation rule passes.

Else prefer **elliott_waves** when `status=clear`, `patternType` is **`impulse`** or **`diagonal`** (not **`corrective`**), `setupPurposeCode` **`ew-imp`** or **`ew-dia`**, and confirmation rule passes. Prefer the primary **`waveMenuNumber`** (default **1**) unless cron prose pins another menu index. Skip when `dataStatus` was **`insufficient_data`** or `unclearReason` cites low confidence / unconfirmed waves.

Else prefer **trend_structure** when `status=clear`, `setupPurposeCode` **`trend-ret`**, `side` matches **`analysis.bias`** (support-line long / resistance-line short), and confirmation rule passes. Skip if **`tradeBuild.protocolId`** is **`uniswap`** unless last close is within **`entryProximityPct`** of entry (retest limit not actionable as spot otherwise).

Else prefer **key_level_fibonacci** when `status=clear`, `priceRegime: inside_range`, and both bracket legs are quoted (strongest Level # below and above last close). Primary is **`kl-fib`** (0.618 fade). Skip when analysis is invalid (no strong legs on both sides of last close / below desk **`fibKeyLevelMinConfidence`**).

Else prefer **key_levels** (nearest): rank-1 **bounce** (`kl-bnc`) or **rejection** (`kl-brk`). For historical break+retest, use nested **`breakRetestAlternative`** (`kl-ret`) per **`trade-defaults`** §1.1 when prose favors it or primary is unclear and alternate is clear.

Else prefer **bollinger_bands** when `status=clear`, not **`invalidated`**, last close was within **`entryProximityPct`** (**5**, band-width %) of the entry band (`bb-fade`; see **`trade-defaults`**), and confirmation rule passes.

Else prefer **donchian_breakout** when `status=clear`, not **`invalidated`**, and confirmation rule passes. Primary follows desk **`donchianEntryMode`**: **`dc-ret`** (retest default) or **`dc-brk`** (immediate). Skip if **`tradeBuild.protocolId`** is **`uniswap`** unless last close is within **`entryProximityPct`** of entry.

Else prefer **supertrend** when `status=clear`, not **`invalidated`**, and confirmation rule passes. Primary follows desk **`supertrendEntryMode`**: **`st-flip`** (flip default) or **`st-ret`** (retest). Skip if **`tradeBuild.protocolId`** is **`uniswap`** unless last close is within **`entryProximityPct`** of entry.

Else prefer **ichimoku** when `status=clear` and confirmation rule passes. Prefer **`ichi-tk`** (TK cross) then **`ichi-cloud`**. Skip if **`tradeBuild.protocolId`** is **`uniswap`** unless last close is within **`entryProximityPct`** of entry.

Else prefer **z_score** when `status=clear`, not **`invalidated`**, `setupPurposeCode` **`zs-fade`**, and confirmation rule passes (ATR filter OK when desk **`zScoreAtrFilter: contracting`**). Skip if **`tradeBuild.protocolId`** is **`uniswap`** unless last close is within **`entryProximityPct`** of entry.

Skip **partial** structural setups unless **momentum, candlestick, or divergence** confirms the same side. When multiple level/trend ideas qualify, prefer the one whose **side** matches the confirming supporter.

### tradeConsensus (YAML fence — pick **one** example below, or configure node file `cron/trade-cron.yaml`)

If **`tradeConsensus`** is already set under **Cron → Trade cron**, you can omit this section from the job message unless this job needs a different gate.

Default — chart pattern primary with **momentum OR candlestick** confirmation; level and trend ideas are **fallback** selection unless listed in `requiredSources`. The YAML gate ensures all three analysis types ran and at least two pass filters; **side-match confirmation** is enforced in prose above (OR logic is not expressible in `requiredSources` alone).

```yaml
tradeConsensus:
  requiredSources: [chart_pattern, momentum, candlestick]
  minAgree: 2
  minConfidence: 0.45
  allowPartial: true
  blockOnConflict: true
  submitTradeFromConsensus: true
```

Example — require clear **trend_structure** primary with the same confirmation sources (perp cron):

```yaml
tradeConsensus:
  requiredSources: [trend_structure, momentum, candlestick]
  minAgree: 2
  minConfidence: 0.45
  allowPartial: true
  blockOnConflict: true
  submitTradeFromConsensus: true
```

Example — fib + momentum **or** candlestick confirmation:

```yaml
tradeConsensus:
  requiredSources: [key_level_fibonacci, momentum, candlestick]
  minAgree: 2
  minConfidence: 0.45
  allowPartial: true
  blockOnConflict: true
  submitTradeFromConsensus: true
```

Example — Donchian breakout + momentum **or** candlestick confirmation (desk `donchianEntryMode` / `donchianPeriod`):

```yaml
tradeConsensus:
  requiredSources: [donchian_breakout, momentum, candlestick]
  minAgree: 2
  minConfidence: 0.45
  allowPartial: true
  blockOnConflict: true
  submitTradeFromConsensus: true
```

Example — Supertrend + momentum **or** candlestick confirmation (desk `supertrendEntryMode` / `supertrendPeriod`):

```yaml
tradeConsensus:
  requiredSources: [supertrend, momentum, candlestick]
  minAgree: 2
  minConfidence: 0.45
  allowPartial: true
  blockOnConflict: true
  submitTradeFromConsensus: true
```

Example — Ichimoku + momentum **or** candlestick confirmation (desk 9/26/52/26):

```yaml
tradeConsensus:
  requiredSources: [ichimoku, momentum, candlestick]
  minAgree: 2
  minConfidence: 0.45
  allowPartial: true
  blockOnConflict: true
  submitTradeFromConsensus: true
```

Example — Z-score fade + momentum **or** candlestick confirmation:

```yaml
tradeConsensus:
  requiredSources: [z_score, momentum, candlestick]
  minAgree: 2
  minConfidence: 0.45
  allowPartial: true
  blockOnConflict: true
  submitTradeFromConsensus: true
```

Example — Elliott wave + momentum **or** candlestick confirmation:

```yaml
tradeConsensus:
  requiredSources: [elliott_waves, momentum, candlestick]
  minAgree: 2
  minConfidence: 0.45
  allowPartial: true
  blockOnConflict: true
  submitTradeFromConsensus: true
```

Example — candlestick-primary (unusual; no structural idea required in `requiredSources`):

```yaml
tradeConsensus:
  requiredSources: [candlestick, momentum]
  minAgree: 1
  minConfidence: 0.45
  allowPartial: false
  blockOnConflict: true
  submitTradeFromConsensus: true
```

Example — chart pattern + divergence confirmation:

```yaml
tradeConsensus:
  requiredSources: [chart_pattern, divergence]
  minAgree: 2
  minConfidence: 0.45
  allowPartial: true
  blockOnConflict: true
  submitTradeFromConsensus: true
```

Raise **`minAgree`** when adding sources. **`requiredSources`** values must match upserted `analysisType` (`chart_pattern`, `momentum`, `candlestick`, `divergence`, `trend_structure`, `key_levels`, `key_level_fibonacci`, `elliott_waves`, `bollinger_bands`, `donchian_breakout`, `supertrend`, `ichimoku`, `z_score`, `moving_averages`, …).

### tradeBuild (YAML fence — pick **one** protocol block below, or configure node file `cron/trade-cron.yaml`)

If **`tradeBuild`** is already set under **Cron → Trade cron**, omit this section from the job message unless this job overrides protocol or sizing. **Do not paste more than one protocol block** into a single job.

Set **`protocolId`** and protocol-specific sizing. Agent still picks **`tradeIdeaId`** from selection rules unless you also pin **`tradeIdeaNumber`** after a dry-run.

**Hyperliquid perp** (copy this block only if HL is your execution venue):

```yaml
tradeBuild:
  protocolId: hyperliquid
  chainId: 999
  szHuman: "0.5"
  marketKind: perp
  tif: gtc
  entryProximityMode: price
  entryProximityPct: 1
  entryProximityAtrPeriod: 14
  entryOffsetPct: 1
  invalidationOffsetPct: 1
  useCustomGas: false
  purposeText: Generated by cron.
  # Optional multisign expiry (omit for DeFi 30-minute default):
  # expiryMinutesFromNow: 60
  # expiryDate: 1735689600
```

**GMX perp (Arbitrum)** — copy only if GMX is your execution venue; otherwise delete:

```yaml
tradeBuild:
  protocolId: gmx
  chainId: 42161
  sizeUsdHuman: "500"
  collateralToken: USDC
  collateralAmountHuman: "100"
  entryProximityMode: price
  entryProximityPct: 1
  entryProximityAtrPeriod: 14
  entryOffsetPct: 1
  invalidationOffsetPct: 1
  useCustomGas: false
  purposeText: Generated by cron.
```

**Uniswap V4 spot (proximity-gated ideas only)** — copy only if Uniswap is your execution venue; otherwise delete:

```yaml
tradeBuild:
  protocolId: uniswap
  chainId: 42161
  sizeUsdHuman: "500"
  useCustomGas: false
  purposeText: Generated by cron.
```

**Arcus perp (Robinhood Chain 4663)** — copy only if Arcus perp is your execution venue; otherwise delete:

```yaml
tradeBuild:
  protocolId: arcus
  chainId: 4663
  szHuman: "0.5"
  marketKind: perp
  tif: gtc
  ed25519KeyGenId: "<paired ed25519 KeyGen id — same GroupId as keyGenId>"
  entryOffsetPct: 1
  invalidationOffsetPct: 1
  purposeText: Generated by cron.
```

**Arcus spot RFQ** — copy only if Arcus spot is your execution venue; otherwise delete:

```yaml
tradeBuild:
  protocolId: arcus
  chainId: 4663
  szHuman: "10"
  marketKind: spot
  ed25519KeyGenId: "<paired ed25519 KeyGen id>"
  purposeText: Generated by cron.
```

Optional: **`tradeIdeaNumber`** — fixed menu index after you know which idea the cron should build (skips prose selection when combined with prefill policy).

### Hint-only variant

Set `submitTradeFromConsensus: false` (or omit) to inject the consensus matrix without requiring **`submit_trade_from_consensus`**.

Prefill/build for trend and level ideas follows skill **`trade-defaults`** (desk **`entryOffsetPct` / `invalidationOffsetPct`** = 1% on perp limit venues; **`entryProximityMode: price`** with **`entryProximityPct: 1`** unless you switch the whole desk to **`atr`**; trend always **`entryOffsetMode: retest`**).
