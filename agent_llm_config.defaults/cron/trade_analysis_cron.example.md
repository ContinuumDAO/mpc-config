## Analysis + optional trade submit (multi-protocol)

Load MCP: **continuum** (chart bundle) + **one DeFi protocol for execution** (see **`tradeBuild.protocolId`** below). Non-interactive. Load skill **`trade-defaults`** when prefill/build runs.

Embed **frozen** operator choices in the cron **`message`**: symbol, candle interval, lookback, **`tradeBuild.protocolId`**, chain, and sizing defaults — do not ask mid-run.

### Protocol setup (pick one execution venue)

| `tradeBuild.protocolId` | Load for **build/submit** | OHLCV for **`analyze_*`** | Sizing fields (prefill / `tradeBuild`) |
|-------------------------|---------------------------|-----------------------------|----------------------------------------|
| **`hyperliquid`** | `load_defi_protocol` **hyperliquid** | Same — `ctm_hyperliquid_fetch_ohlcv` | `szHuman`, optional `marketKind` (`perp`\|`spot`), `tif` |
| **`arcus`** | `load_defi_protocol` **arcus** | Perp: `ctm_arcus_fetch_ohlcv`; spot: `ctm_arcus_spot_fetch_ohlcv` (chain **4663**) | `szHuman`, `marketKind` (`perp`\|`spot`), `tif` (perp); **`ed25519KeyGenId`** (paired KeyGen, same GroupId as `keyGenId`) |
| **`gmx`** | `load_defi_protocol` **gmx** | Same — `ctm_gmx_fetch_ohlcv` (explicit **`chainId`**) | `sizeUsdHuman`, `collateralToken`, `collateralAmountHuman` |
| **`uniswap`** | `load_defi_protocol` **uniswap** (V4) | **Separate source required** — Uniswap has no protocol OHLCV. Cron message must name one: load **hyperliquid**, **arcus**, or **gmx** for perp candles, **or** load **coingecko** / **coinmarketcap-public** for spot series (trend/levels/patterns need **`dataKind: ohlcv`** — prefer HL/Arcus/GMX for full menu). | `sizeUsdHuman` (spot swap USD) |

**Chain IDs (typical):** Hyperliquid **999** (mainnet) / **998** (testnet); Arcus (Robinhood Chain) **4663**; GMX & Uniswap on Arbitrum **42161** — confirm via protocol supported-chains in staging.

**Trend / limit-style ideas on Uniswap:** spot swap only — no resting limit at trend line. Prefer **`hyperliquid`**, **`arcus`**, or **`gmx`** in `tradeBuild` for **`trend_structure`**, **`key_levels`**, and fib **extension/retest** ideas. Use **`uniswap`** only when last price is already within desk **`entryProximityPct`** of the idea entry — per **`entryProximityMode`** in **`trade-defaults`** §2 (`price` = % of entry; `atr` = % of ATR).

**Arcus trading:** requires paired KeyGens (secp256k1 custody + ed25519 API signing, same `GroupId`). Register API key once via multisign before orders. Spot RFQ has no bracket TP/SL at build.

### Steps (prose — customize)

1. Load OHLCV source per table above; **`fetch_ohlcv`** (or equivalent) for operator symbol/interval/lookback. Keep the same session for all analysis tools (`toolResult` / `ohlcvDigest`).
2. `analyze_chart_patterns` on the session-bound OHLCV.
3. `analyze_momentum` on the same session.
4. `analyze_trend_structure` on the same session (upserts **`trend_structure`** / `trendStructureTradeSetup`, `setupPurposeCode` **`trend-ret`**).
5. `analyze_key_levels` on the same session (nearest bounce/rejection — upserts **`key_levels`** / `keyLevelsTradeSetup`).
6. `analyze_key_level_fibonacci` on the same session (outer range 0.618 / 1.618 — upserts **`key_level_fibonacci`** / `keyLevelFibTradeSetup`).
7. Optional: `analyze_bollinger_bands` on the same session (upserts **`bollinger_bands`** / `bollingerTradeSetup`, `setupPurposeCode` **`bb-fade`**).
8. Optional: `analyze_moving_averages` on the same session (upserts **`moving_averages`** / `movingAveragesTradeSetup`, `setupPurposeCode` **`ma-cross`** or **`ma-ret`** per `tradeSummary`).
8. If consensus gate **ALLOWED** and submit enabled, call **`submit_trade_from_consensus`** with **`tradeIdeaId`** per selection rules below. Resolve sizing from **execution** protocol open-context (Hyperliquid / GMX / Uniswap quote tools per **`trade-defaults`** §5).

Steps 4–7 share the same OHLCV session; each upserts a **separate** trade idea (`analysisType` distinct).

### Selection guidance (prose — agent decides tradeIdeaId)

Prefer **chart_pattern** when `status=clear` and consensus agrees.

Else prefer **trend_structure** when `status=clear`, `setupPurposeCode` **`trend-ret`**, and `side` matches **`analysis.bias`** (support-line long / resistance-line short). Skip if **`tradeBuild.protocolId`** is **`uniswap`** unless last close is within **`entryProximityPct`** of entry (retest limit not actionable as spot otherwise).

Else prefer **key_level_fibonacci** when `status=clear` and `priceRegime` matches structure:

| Regime | Prefer when |
|--------|-------------|
| **`inside_range`** | Last close between outer range legs; primary **`kl-fib`** (0.618 retrace) |
| **`above_range`** | Last close above range high; primary **`kl-fib-ext`** (long, 1.618 extension target) |
| **`below_range`** | Last close below range low; primary **`kl-fib-ext`** (short, 1.618 extension target) |

Use nested **`breakRetestAlternative`** (`kl-fib-ret`) only when cron prose explicitly favors break+retest, or primary extension is **`unclear`** and alternate is **`clear`** ( **`trade-defaults`** §1.2).

Else prefer **key_levels** (nearest): rank-1 **bounce** (`kl-bnc`) or **rejection** (`kl-brk`).

Else prefer **bollinger_bands** when `status=clear`, not **`invalidated`**, and last close was within **`entryProximityPct`** (**5**, band-width %) of the entry band (`bb-fade`; see **`trade-defaults`**).

Skip **partial** setups unless **momentum** agrees. When multiple level/trend ideas qualify, prefer the one whose **side** matches momentum / pattern / trend bias.

### tradeConsensus (YAML fence — paste into cron message, or edit node file `cron/trade-cron.yaml`)

Default — pattern + momentum gate; level and trend ideas are **fallback** selection unless listed in `requiredSources`:

```yaml
tradeConsensus:
  requiredSources: [chart_pattern, momentum]
  minAgree: 2
  minConfidence: 0.45
  allowPartial: false
  blockOnConflict: true
  submitTradeFromConsensus: true
```

Example — require clear **trend_structure** + **momentum** (perp cron):

```yaml
tradeConsensus:
  requiredSources: [trend_structure, momentum]
  minAgree: 2
  minConfidence: 0.45
  allowPartial: false
  blockOnConflict: true
  submitTradeFromConsensus: true
```

Example — fib + momentum:

```yaml
tradeConsensus:
  requiredSources: [key_level_fibonacci, momentum]
  minAgree: 2
  minConfidence: 0.45
  allowPartial: false
  blockOnConflict: true
  submitTradeFromConsensus: true
```

Raise **`minAgree`** when adding sources. **`requiredSources`** values must match upserted `analysisType` (`chart_pattern`, `momentum`, `trend_structure`, `key_levels`, `key_level_fibonacci`, …).

### tradeBuild (YAML fence — paste into cron message, or edit node file `cron/trade-cron.yaml`)

Set **`protocolId`** and protocol-specific sizing. Agent still picks **`tradeIdeaId`** from selection rules unless you also pin **`tradeIdeaNumber`** after a dry-run.

**Hyperliquid perp:**

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

**GMX perp (Arbitrum):**

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

**Uniswap V4 spot (proximity-gated ideas only):**

```yaml
tradeBuild:
  protocolId: uniswap
  chainId: 42161
  sizeUsdHuman: "500"
  useCustomGas: false
  purposeText: Generated by cron.
```

**Arcus perp (Robinhood Chain 4663):**

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

**Arcus spot RFQ:**

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
