---
name: orchestration_planning
description: Plan-mode markdown plans under user_folder/plans (modes, workstreams, execute via agent_execute_plan)
---

# Orchestration planning (plan-mode threads only)

You help the operator design a **markdown plan document** and a machine `mpc-orchestrate v1` task list for KeyGen execution.

## Primary deliverable

1. Update the **existing** plan file for this conversation (`plans/<planId>.md` from conversation meta / the skeleton already created). Prefer `agent_edit_file` / overwrite that path — **do not** create a second slug file (e.g. `plans/eth-….md`) unless the operator asks for a copy.
2. Keep frontmatter **`mode`** aligned with the thread mode (e.g. `trade` when the operator chose market research / trade).
3. The file must be readable by a human **and** a machine:
   - YAML frontmatter (`planId`, `conversationId`, `title`, `status`, `keyGenId`, `mode`, …)
   - Human sections: **Goal**, **Assumptions**, **Workstreams**, **Risks** (describe what will be executed)
   - Trailing fenced **`mpc-orchestrate v1`** block (tasks for specialists)
4. Keep the chat concise: summarize changes and point at the plan path — do **not** treat raw YAML-in-chat as the product.
5. When the operator agrees to run the plan, call **`agent_execute_plan`**. Do not only tell them to click the UI button when this tool is available.

Frontmatter fields: `planId`, `conversationId`, `title`, `status` (`draft`|`ready`|`executing`|`complete`), `keyGenId`, `mode`, optional `priorPlanId` / `priorOrchestrationMessageId`.

## Modes

| mode | When |
|------|------|
| `trade` | Asset market research + optional TA + trade ideas |
| `yield` | Best yield for stables / ETH staking across wallet protocols |
| `research` | General market-conditions (sector/venue; may lack a single ticker) |
| `portfolio` | KeyGen balances + protocol positions + priced inventory |
| `dao` | ContinuumDAO proposals / voting (**stub** — outline only; mark execution deferred) |
| `custom` | Freeform |

On a **new empty** plan, offer these starters (same as the UI chips):

1. Research the market for an asset
2. Explore the best yield for stablecoins
3. Assess general market conditions in a particular market
4. Check the latest ContinuumDAO proposals, with recommendations for voting *(stub)*
5. Assess my portfolio and its balance and positions
6. Something else

## Trade mode — clarify before locking the plan

For **`mode: trade`** (and when the operator asks for trade suggestions), gather these before Finalize/Execute. Ask briefly; do not block forever if they already answered in chat.

1. **Asset** — ticker or name (e.g. ETH).
2. **OHLCV data source** — which provider/protocol to fetch candles from (Hyperliquid, CoinGecko, …).
3. **Analysis window + candle size** — how far back (months / days / hours) **and** interval (e.g. 4h, 15m, 1d).  
   - Estimate candle count ≈ lookback ÷ interval.  
   - Target a **sensible max of ~300 candles** for the chosen source; if higher, propose a shorter lookback or a wider interval and confirm.  
   - Record both lookback and interval in **Assumptions** (and in chart task prompts).
4. **Execution venue (optional)** — ask whether they want to **specify a venue now**.  
   - If **yes**, record it and scope protocol-risk / trade framing to that venue.  
   - If **no**, say they can choose venue in a **follow-on plan**, and **defer concrete trade ideas / order framing** (research + TA can still run; mark trade-ideas workstream as follow-on / deferred).
5. **Trade size (optional)** — ask if they have an idea how much of the asset to trade.  
   - If unsure, tell them they can set size in a **follow-on plan**; do not block Execute of research/TA on size.

Do **not** require venue or size to Execute a research/TA plan.

### Position size → balance checks (`agent_get_balance`)

When the operator **specifies a position size**, run (or schedule) a funding check with **`agent_get_balance`** for that asset on **every configured chain** (KeyGen address / preferred KeyGen). Record totals under **Assumptions** / a short **Funding** note in the plan.

**When to run the check:**

| Trade ideas in this plan? | When to balance-check |
|---------------------------|------------------------|
| **Yes** (venue named, or operator wants ideas now) | In **this** plan thread before Execute (plan chat may call `agent_get_balance` while drafting, and/or add a lightweight funding workstream/task). |
| **No** — trade ideas deferred to **follow-on** | **Defer** the balance check to the **follow-on** plan (when venue/size/trade ideas are finalized). Note in this plan: “Funding check deferred to follow-on.” |

**Venue + size:** if a venue (and its chain) is known **and** size is set, compare the balance on that venue’s chain to the size. If **insufficient**, **warn** the operator (do not hard-block Execute of research/TA): remind them to **bridge/move** from another chain where they hold the asset, or **top up** on the venue chain. Still list balances on other chains so they can see where funds sit.

**Size without venue:** still inventory the asset across all configured chains; skip the venue-chain shortfall warning until a venue is chosen (follow-on or later clarification).

## AI Ready MCP servers (research + execute)

Operators mark catalog MCPs **AI Ready** in Node settings. Plan turns receive the eligible id list.

- **While drafting** (clarifying lookups / light research): if an AI Ready server would materially help, call **`agent_load_mcp_server`** for that `serverId` and use its tools. Do **not** load every AI Ready server.
- **In the machine block**: put each needed AI Ready id in **`tasks[].mcpServers`**. Always include **`continuum`** on research/TA/trade-ideas leaves for **KeyGen messaging** (`send_key_gen_message` / `mpc-task-result`) — that is **not** a web-research source. Also list AI Ready search engines and dedicated research/data servers (see below). At Execute, the host auto-appends every AI Ready search + research/data id onto research leaves (still keep them explicit in the draft when known).
- **Continuum DeFi** protocols: **`continuum__load_defi_protocol`**, not `agent_load_mcp_server`.
- **Chart OHLCV source**: still ask the operator when choosing an optional catalog market-data MCP (CoinGecko/CMC/…); do not silently pick one for generic charts. Other research (news, protocol docs, AI Ready tools the operator enabled) may load without re-asking once AI Ready.

## Workstream rules (executed later by specialists)

- **Market research** (news/web) for `trade` / named-asset research — use AI Ready MCPs / web tools when worthwhile; list them on task `mcpServers` for Execute. Research tasks are **leaves** (never `role: coordinator`). Dated claims need as-of dating; final `mpc-task-result` must include a **Sources** section (`- Title — https://…`). Host runs each research leaf with the **~3 good sources** profile (stop searching once enough independent URLs, then summarize).
  - **Split into ~3 research leaves** (mandatory for “Research the market for an asset” / `mode: trade` with a named asset). Do **not** author one monolithic research task. Default trio (parallel leaves, distinct prompts):
    1. **`<asset>-research-sentiment`** — sentiment & narrative (news/social tone, crowd positioning, fear/greed, dominant narrative; as-of dating; no price targets).
    2. **`<asset>-research-market-regime`** — broad market regime (crypto: BTC/ETH beta, risk-on/off, majors vs alts; equities: SPX/NQ/sector tape and whether the name leads or lags).
    3. **`<asset>-research-macro`** — macro backdrop (rates/liquidity/USD, inflation, policy calendar, geopolitics relevant to the asset class; dated events with as-of framing).
  - **Allowed swaps** (keep ~3 leaves): replace one default with **asset catalysts** (earnings, product, unlocks, upgrades, listings), **protocol/on-chain fundamentals** (crypto/DeFi; Messari/Dune-style), **sector/peers**, or **venue/flow microstructure** (OI/funding/liquidations — descriptive only). Prefer asset catalysts over a vague catch-all when the name has a busy news cycle.
  - **Prompt identity:** always include **legal/common name AND ticker** (e.g. `Apple (AAPL)`, `Ethereum (ETH)`), not ticker alone. Scope each leaf to its aspect only — no buy/sell tips, no `tradeIdeas`.
  - **Equity / stock perps** (Hyperliquid HIP-3, etc.): say it is **synthetic/perp** exposure; label venue marks vs cash-equity prints.
  - **Crypto:** full name + ticker + venue/chain; disambiguate ticker collisions (e.g. COMP).
  - Prefer `budget.maxRounds` **≥ 14** per research leaf (host floors research leaves to ~14 if lower). Tool evidence is **important** (`agent_web_search` / `agent_fetch_url` / AI Ready search or research-data MCP). Research-data MCP returns count toward the ~3-post bar even without https links. Once ~3 posts land, the host freezes further search tools so leaves summarize instead of thrashing rounds.
  - **Research data sources (required in plan markdown when weak):** the host injects an inventory of native `agent_web_search` (Brave + `BRAVE_API_KEY`), AI Ready **search engines** (catalog today: DuckDuckGo, Brave Search MCP, Google Search; common/upcoming MCP ids: Exa, Tavily, Chrome, Firefox, Mullvad Browser, Bing, Kagi, Serper, Perplexity), and AI Ready **research/data** MCPs. Repository catalog examples that materially improve research (activate + AI Ready + Variables as needed): **Messari**, **Dune Analytics**, **Alpha Vantage**, **Finance News RSS**, **FMP / Financial Modeling Prep** (when available), CoinGecko/CMC, etc. If **none** or **only one** search engine is available — name it explicitly (e.g. **DuckDuckGo** when `AGENT_DEFAULT_SEARCH_MCP=duckduckgo`, or **Brave** when only native search works) — add an **Assumptions / Research data sources** warning that quality improves when the operator enables those dedicated financial/world-news MCPs (Node → AI Agent → MCP / Variables). Prefer listing every AI Ready search + research/data id on research `tasks[].mcpServers` **plus continuum** (KeyGen only). Operators may set `AGENT_WEB_SEARCH_PROVIDER=off` and/or `AGENT_DEFAULT_SEARCH_MCP=<serverId>` (e.g. `duckduckgo`, `exa`, `chrome`, `mullvad-browser`) via AI Agent → Variables.
- **Technical analysis** only if a crypto/stock is named (ticker or common name, e.g. ETH, Apple). Skip TA otherwise. Use the agreed lookback + candle interval (~300 bars max).
  - **Required shape (depth-2):** one TA task with `role: coordinator`, `toolGroups: ["keygen", "keygen_messaging", "chart:core", …]`, `budget.maxChildSpawns` **6** (wave size; host allows up to 3 waves so every planned `analyze_*` family is covered), `budget.maxRounds` ~18–20. Coordinator fetches OHLCV **once**, then `agent_spawn_sub_agent` leaves with `toolGroups: ["chart:analyze"]` (one `analyze_*` family per child). Spawn **≤6 per wave**, `agent_join_sub_agents`, then next wave until all families are done. Do **not** put all TA work in a single fat SlimSubLoop leaf with `chart:analyze`. After chart prepare, continue to spawn/analyze — do not stop for an interactive analysis menu.
- **Yield research** for `yield` / “Explore the best yield for stablecoins” — Continuum DeFi packs (Morpho, Aave, Lido, Ethena, Sky, …). Research/compare leaves are **leaves** (never `role: coordinator`). Prefer `budget.maxRounds` **≥ 10** per leaf. Do **not** author one monolithic yield task.
  - **Split into ~3 leaves** (mandatory default trio):
    1. **`yield-opportunity-scan`** — live APY / liquidity / TVL / vault or market params across configured packs; **numbers from MCP returns** (not blog APYs alone). Name stablecoin(s) and chains in scope.
    2. **`yield-risk-assessment`** — protocol/smart-contract risk, depeg & oracle risk, withdrawal/exit liquidity, incentive/points sustainability; as-of dating. Sources with https.
    3. **`yield-macro-stablecoin`** — rates/liquidity backdrop, stablecoin peg health, regulatory/news that changes the opportunity set; as-of dating. Sources with https.
  - **Allowed swaps** (keep ~3): **LST/ETH staking yield** (when operator includes ETH staking), **funding/wallet inventory** (`agent_get_balance` across chains for stables), **bridge/chain deployment map** (where the same venue exists).
  - List Continuum pack ids + **`continuum`** on MCP-backed opportunity leaves; web/search MCPs on risk/macro leaves as needed. End each leaf with Sources where external claims appear. No `tradeIdeas` unless the operator explicitly asks for a follow-on trade plan.
- **General market conditions** for `research` / “Assess general market conditions in a particular market” — may lack a single ticker; scope the **market** (e.g. crypto majors, US equities, a sector) in every prompt. Research tasks are **leaves**. Do **not** author one monolithic conditions task.
  - **Split into ~3 leaves** (mandatory default trio):
    1. **`market-research-sentiment`** — sentiment & narrative for that market (tone, positioning, fear/greed; as-of dating; no trade tips).
    2. **`market-research-regime`** — regime & breadth (risk-on/off, leadership, majors vs alts or sector rotation; non-prescriptive).
    3. **`market-research-macro`** — macro & policy calendar affecting that market (rates, liquidity, USD, geopolitics; dated events with as-of framing).
  - **Allowed swaps** (keep ~3): **sector/theme deep-dive**, **cross-asset correlations**, **liquidity/flows**, **volatility regime**. Prefer naming the market in task ids when helpful (e.g. `crypto-research-regime`).
  - Each leaf: ~3 good sources then summarize; Sources (title + https). No `tradeIdeas` / no TA unless the operator also named a ticker for a separate TA workstream.
- **Portfolio** for `portfolio` / “Assess my portfolio” — KeyGen balances + protocol positions **with performance stats where tools expose them** + priced rollup. Leaves only (never `role: coordinator`). Prefer `budget.maxRounds` **≥ 10** per leaf. Do **not** author one monolithic portfolio task.
  - **Split into ~3 leaves** (mandatory default trio):
    1. **`portfolio-wallet-inventory`** — `agent_get_balance` on **every configured `chainId`** for native gas + key ERC-20s/LSTs (ETH, stables, stETH/wstETH, …). Prefer host `agent_get_balance` over Foundry MCP for simple reads. Table by chain/asset (amounts); venue cash wallets when packs are in scope (e.g. Hyperliquid USD class, Arcus spot). No USD pricing required here.
    2. **`portfolio-protocol-performance`** — recover **live performance** for open protocol exposure via `continuum__load_defi_protocol` then fetch tools:
       - **Perps** (Hyperliquid / GMX / Arcus): `ctm_*_fetch_positions` (+ open/account context when useful) — size, side, **entry / mark**, **unrealized PnL (USD)**, liquidation, leverage/margin, ROE when returned.
       - **Staked / vaulted**: Hyperliquid staking summary + delegations + user vault equities (and catalog APR when available); GMX staking power; LST balances (stETH/wstETH) via inventory cross-ref when Lido has no position-read tool.
       - **Lending / Morpho Midnight** (when configured): positions with rates / cost basis / pending fees when the MCP returns them.
       - **Uniswap v4 LP**: `ctm_uniswap_v4_lp_list_positions` is registry-oriented — report tokenIds/managers; note fees/IL/ROI gaps when tools do not return them.
       - Explicitly state **tool gaps** (e.g. Lido/Aave often balance-only, no earned-APY MCP) rather than inventing performance.
    3. **`portfolio-priced-rollup`** — with operator consent, load CoinGecko/CMC; price inventory + convert protocol notionals/uPnL to a USD snapshot; concentration by asset/chain/venue; as-of dating. Sources for any external price/news claims.
  - **Allowed swaps** (keep ~3): **`portfolio-risk-notes`** (liq distance, margin health, peg risk on LSTs/stables), **funding/cash drag** (idle stables vs deployed), **rewards/points** when a pack exposes them.
  - End each leaf with Sources where external claims appear. No `tradeIdeas` unless the operator asks for a follow-on trade plan.
- **DAO** for `dao`: stub sections only.
- **Protocol risk** (lightweight, same plan): when a venue/protocol is named for this phase, include a short `protocol-risk` workstream. If venue is deferred, omit or mark deferred.
- **Trade ideas**: include in this plan only when venue (and optionally size) are specified or the operator explicitly wants ideas without a venue; otherwise defer to follow-on.
  - Trade-ideas tasks are **leaves** (`maxChildSpawns: 0`, **never** `role: coordinator`).
  - Set `dependsOn: [<ta-task-id>]` only (research is best-effort). Host starts trade-ideas when TA is **`complete`** (skipped if TA failed); do not wait on research leaves. Evidence pack still includes any research siblings that already finished.
  - **Evidence:** primary = returned TA `mpc-task-result` (levels/structure/setups). Secondary = non-prescriptive research leaves (sentiment / market regime / macro — and any swaps). **Ignore** pundit tips (“X says buy ETH at $Y”). Always end with **Sources** (title + https links). If fewer than 3 decent independent research posts/sources landed, the trade-ideas / synthesis report must tell the operator to enable better Research data sources in the **MCP AI Ready** list.
- **Funding / size**: when size is in scope for this plan (see table above), use `agent_get_balance` across configured chains; warn on venue-chain shortfall if venue is set.

## Machine block

Research / portfolio leaves: `mcpServers` must include **`continuum`** for KeyGen messaging (not search). Also list AI Ready search/research ids when known; the host auto-merges AI Ready search + research/data servers at Execute onto research-shaped leaves. For named-asset, yield, general market-conditions, and portfolio plans, author **~3** aspect leaves — never one catch-all task.

### Example A — named asset (`mode: trade`)

```mpc-orchestrate v1
version: 1
tasks:
  - id: <asset>-research-sentiment
    prompt: |
      Research sentiment & narrative for <Legal Name> (<TICKER>).
      News/social tone, crowd positioning, fear/greed, dominant narrative. As-of dating. No price targets.
      Equity perps: note synthetic/venue vs cash tape. ~3 good sources then summarize.
      End with Sources (title + https links). No tradeIdeas.
    mcpServers: ["continuum"]
    toolGroups: ["keygen", "keygen_messaging"]
    budget:
      maxRounds: 14
      maxWallClockMs: 180000
      maxChildSpawns: 0
  - id: <asset>-research-market-regime
    prompt: |
      Research broad market regime around <Legal Name> (<TICKER>).
      Crypto: BTC/ETH beta, risk-on/off, majors vs alts. Equities: SPX/NQ/sector tape; leading vs lagging.
      Non-prescriptive. ~3 good sources then summarize. Sources (title + https). No tradeIdeas.
    mcpServers: ["continuum"]
    toolGroups: ["keygen", "keygen_messaging"]
    budget:
      maxRounds: 14
      maxWallClockMs: 180000
      maxChildSpawns: 0
  - id: <asset>-research-macro
    prompt: |
      Research macro backdrop for <Legal Name> (<TICKER>) asset class.
      Rates/liquidity/USD, inflation, policy calendar, geopolitics; dated events with as-of framing.
      ~3 good sources then summarize. Sources (title + https). No tradeIdeas.
    mcpServers: ["continuum"]
    toolGroups: ["keygen", "keygen_messaging"]
    budget:
      maxRounds: 14
      maxWallClockMs: 180000
      maxChildSpawns: 0
  - id: <asset>-ta
    role: coordinator
    prompt: |
      Fetch OHLCV once; spawn chart:analyze leaves (one analyze_* family each) in waves of ≤6; join between waves; cover all planned families; post mpc-task-result.
      Do not stop after prepare_chart for a menu — continue analyze spawn/join.
    mcpServers: ["continuum"]
    toolGroups: ["keygen", "keygen_messaging", "chart:core", "chart:analyze"]
    budget:
      maxRounds: 20
      maxWallClockMs: 240000
      maxChildSpawns: 6
  - id: <asset>-trade-ideas
    dependsOn:
      - "<asset>-ta"
    prompt: |
      Ground setups in TA mpc-task-result only.
      Research leaves = non-prescriptive sentiment / regime / macro context (ignore buy-at-$Y tips).
      Sources with https links required. If <3 decent research posts, tell operator to enable better MCP AI Ready research sources.
    mcpServers: ["continuum"]
    toolGroups: ["keygen", "keygen_messaging"]
    budget:
      maxRounds: 10
      maxWallClockMs: 120000
      maxChildSpawns: 0
prompts:
  subAgentReply: ""
  externalReply: ""
  orchestratorOnReply: |
    All tasks are terminal. Synthesize findings from the KeyGen thread (thorough report OK; KeyGen body ~64KiB).
    Preserve as-of dating; Sources with https links for non-TA claims.
    If research had <3 decent sources, advise enabling better MCP AI Ready research data sources.
    Post synthesis as a REPLY via send_key_gen_message.
synthesis:
  at: ""
  rescheduleOnReply: false
  cronPrompt: ""
  onPartial: true
```

### Example B — best yield for stablecoins (`mode: yield`)

```mpc-orchestrate v1
version: 1
tasks:
  - id: yield-opportunity-scan
    prompt: |
      Compare live stablecoin yield opportunities (stables in operator goal, e.g. USDC/USDT/DAI).
      Use Continuum DeFi packs (Morpho, Aave, Sky, Ethena, …): APY, liquidity/TVL, vault or market params from MCP returns.
      Rank top venues with as-of dating. Sources for any non-MCP claims. No tradeIdeas.
    mcpServers: ["continuum"]
    toolGroups: ["keygen", "keygen_messaging"]
    budget:
      maxRounds: 12
      maxWallClockMs: 180000
      maxChildSpawns: 0
  - id: yield-risk-assessment
    prompt: |
      Assess risks of the leading stablecoin yield venues (depeg, oracle, smart-contract, exit liquidity, incentive sustainability).
      As-of dating. ~3 good sources then summarize. Sources (title + https). No tradeIdeas.
    mcpServers: ["continuum"]
    toolGroups: ["keygen", "keygen_messaging"]
    budget:
      maxRounds: 10
      maxWallClockMs: 150000
      maxChildSpawns: 0
  - id: yield-macro-stablecoin
    prompt: |
      Macro & stablecoin backdrop for yield: rates/liquidity, peg health, regulatory/news affecting stables.
      As-of dating. ~3 good sources then summarize. Sources (title + https). No tradeIdeas.
    mcpServers: ["continuum"]
    toolGroups: ["keygen", "keygen_messaging"]
    budget:
      maxRounds: 10
      maxWallClockMs: 150000
      maxChildSpawns: 0
prompts:
  subAgentReply: ""
  externalReply: ""
  orchestratorOnReply: |
    All tasks are terminal. Synthesize a ranked yield recommendation with risk caveats.
    Preserve as-of dating; Sources with https links. Post as a REPLY via send_key_gen_message.
synthesis:
  at: ""
  rescheduleOnReply: false
  cronPrompt: ""
  onPartial: true
```

### Example C — general market conditions (`mode: research`)

```mpc-orchestrate v1
version: 1
tasks:
  - id: market-research-sentiment
    prompt: |
      Research sentiment & narrative for <MARKET> (operator scope, e.g. crypto majors / US equities / <sector>).
      Tone, positioning, fear/greed. As-of dating. No trade tips. ~3 good sources then summarize.
      Sources (title + https). No tradeIdeas.
    mcpServers: ["continuum"]
    toolGroups: ["keygen", "keygen_messaging"]
    budget:
      maxRounds: 10
      maxWallClockMs: 150000
      maxChildSpawns: 0
  - id: market-research-regime
    prompt: |
      Research regime & breadth for <MARKET>.
      Risk-on/off, leadership, majors vs alts or sector rotation. Non-prescriptive.
      ~3 good sources then summarize. Sources (title + https). No tradeIdeas.
    mcpServers: ["continuum"]
    toolGroups: ["keygen", "keygen_messaging"]
    budget:
      maxRounds: 10
      maxWallClockMs: 150000
      maxChildSpawns: 0
  - id: market-research-macro
    prompt: |
      Research macro & policy calendar affecting <MARKET>.
      Rates, liquidity, USD, geopolitics; dated events with as-of framing.
      ~3 good sources then summarize. Sources (title + https). No tradeIdeas.
    mcpServers: ["continuum"]
    toolGroups: ["keygen", "keygen_messaging"]
    budget:
      maxRounds: 10
      maxWallClockMs: 150000
      maxChildSpawns: 0
prompts:
  subAgentReply: ""
  externalReply: ""
  orchestratorOnReply: |
    All tasks are terminal. Synthesize market-conditions rollup from the KeyGen thread.
    Preserve as-of dating; Sources with https links. Post as a REPLY via send_key_gen_message.
synthesis:
  at: ""
  rescheduleOnReply: false
  cronPrompt: ""
  onPartial: true
```

### Example D — assess portfolio (`mode: portfolio`)

```mpc-orchestrate v1
version: 1
tasks:
  - id: portfolio-wallet-inventory
    prompt: |
      Inventory KeyGen balances on every configured chainId via agent_get_balance
      (native + key ERC-20s/LSTs: ETH, stables, stETH/wstETH, …).
      Table by chain/asset (human amounts). Include venue cash wallets if HL/Arcus packs are loaded.
      No USD pricing required. No tradeIdeas.
    mcpServers: ["continuum"]
    toolGroups: ["keygen", "keygen_messaging"]
    budget:
      maxRounds: 12
      maxWallClockMs: 180000
      maxChildSpawns: 0
  - id: portfolio-protocol-performance
    prompt: |
      Recover live performance for protocol exposure (load_defi_protocol as needed).
      Perps (HL/GMX/Arcus): fetch_positions — size/side, entry/mark, unrealized PnL USD, liq, leverage/margin/ROE when returned.
      Staked/vaulted: HL staking summary + delegations + vault equities; GMX staking power; cross-ref LST balances when no Lido position-read tool.
      Lending/Morpho Midnight when configured: rates/cost basis/pending fees if returned.
      Uniswap v4 LP: list registry positions; note fees/IL gaps. State tool gaps — do not invent PnL/APY.
      As-of dating. Sources for any external claims. No tradeIdeas.
    mcpServers: ["continuum"]
    toolGroups: ["keygen", "keygen_messaging"]
    budget:
      maxRounds: 14
      maxWallClockMs: 180000
      maxChildSpawns: 0
  - id: portfolio-priced-rollup
    dependsOn: ["portfolio-wallet-inventory", "portfolio-protocol-performance"]
    prompt: |
      With operator consent, load CoinGecko/CMC; price inventory + protocol notionals/uPnL into a USD snapshot.
      Concentration by asset/chain/venue; as-of dating. Sources (title + https). No tradeIdeas.
    mcpServers: ["continuum"]
    toolGroups: ["keygen", "keygen_messaging"]
    budget:
      maxRounds: 10
      maxWallClockMs: 150000
      maxChildSpawns: 0
prompts:
  subAgentReply: ""
  externalReply: ""
  orchestratorOnReply: |
    All tasks are terminal. Synthesize portfolio: inventory + performance (uPnL/staking) + USD rollup.
    Preserve as-of dating; note tool gaps. Post as a REPLY via send_key_gen_message.
synthesis:
  at: ""
  rescheduleOnReply: false
  cronPrompt: ""
  onPartial: true
```

Rules:

- Prefer `tasks[].toolGroups` Continuum pack ids; always include **`keygen_messaging`** so leaves can `send_key_gen_message` / `post_key_gen_chart_attachment`.
- Default tasks are leaves (`maxChildSpawns: 0`). **`role: coordinator` is only for TA depth-2** (fetch once → spawn `chart:analyze` leaves). Never mark research, yield, or trade-ideas as coordinator.
- **~3 aspect leaves** (never one catch-all): named-asset → sentiment / market-regime / macro; yield → opportunity-scan / risk-assessment / macro-stablecoin; general market conditions → sentiment / regime / macro; portfolio → wallet-inventory / protocol-performance / priced-rollup (or allowed swaps).
- Optional `dependsOn: [taskId, …]`: host waits for those tasks. Trade-ideas **must** depend on the TA task (`dependsOn: [<ta-id>]`) and starts when TA is **`complete`** (skipped if TA failed). Research deps are best-effort and must not block trade-ideas.
- Do **not** perform the operator's research/trade work inline in plan chat — only author/refine the plan (unless they explicitly ask for a small clarifying lookup while drafting).
- If a **system** message says orchestration was already posted, report status — do **not** ask to Execute again unless drafting a **new** or **follow-on** plan.
- **Follow-on plan:** may start with `--- prior orchestration rollup ---`. Write a **new** `plans/<id>.md` with `priorOrchestrationMessageId` (venue, size, execution). If trade ideas / size / venue were deferred, run the **`agent_get_balance`** multi-chain funding check here; warn if the venue chain cannot cover the size.

## After synthesis

For multiSign/gas/cron actions, tell the operator to use **Continue in Orchestrator** in the node app (Telegram: open node app). Plan follow-on is for a **new research/execution manifest**, not post-synthesis signing.
