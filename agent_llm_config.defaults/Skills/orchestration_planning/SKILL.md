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

- **Market research** (news/web) for `trade` / `research` — use AI Ready MCPs / web tools when worthwhile; list them on task `mcpServers` for Execute. Research tasks are **leaves** (never `role: coordinator`). Dated claims need as-of dating; final `mpc-task-result` must include a **Sources** section (`- Title — https://…`). Host runs research leaves with the **~3 good sources** profile (stop searching once enough independent URLs, then summarize).
  - **Prompt identity:** always include **legal/common name AND ticker** (e.g. `Apple (AAPL)`, `Ethereum (ETH)`), not ticker alone.
  - **Equity / stock perps** (Hyperliquid HIP-3, etc.): say it is **synthetic/perp** exposure; label venue marks vs cash-equity prints; cover earnings, product cycle, sector/macro catalysts with as-of dating.
  - **Crypto:** full name + ticker + venue/chain; disambiguate ticker collisions (e.g. COMP).
  - Prefer `budget.maxRounds` **≥ 10** (host floors research leaves to ~9 if lower).
  - **Research data sources (required in plan markdown when weak):** the host injects an inventory of native `agent_web_search` (Brave + `BRAVE_API_KEY`), AI Ready **search engines** (catalog today: DuckDuckGo, Brave Search MCP, Google Search; common/upcoming MCP ids: Exa, Tavily, Chrome, Firefox, Mullvad Browser, Bing, Kagi, Serper, Perplexity), and AI Ready **research/data** MCPs. Repository catalog examples that materially improve research (activate + AI Ready + Variables as needed): **Messari**, **Dune Analytics**, **Alpha Vantage**, **Finance News RSS**, **FMP / Financial Modeling Prep** (when available), CoinGecko/CMC, etc. If **none** or **only one** search engine is available — name it explicitly (e.g. **DuckDuckGo** when `AGENT_DEFAULT_SEARCH_MCP=duckduckgo`, or **Brave** when only native search works) — add an **Assumptions / Research data sources** warning that quality improves when the operator enables those dedicated financial/world-news MCPs (Node → AI Agent → MCP / Variables). Prefer listing every AI Ready search + research/data id on research `tasks[].mcpServers` **plus continuum** (KeyGen only). Operators may set `AGENT_WEB_SEARCH_PROVIDER=off` and/or `AGENT_DEFAULT_SEARCH_MCP=<serverId>` (e.g. `duckduckgo`, `exa`, `chrome`, `mullvad-browser`) via AI Agent → Variables.
- **Technical analysis** only if a crypto/stock is named (ticker or common name, e.g. ETH, Apple). Skip TA otherwise. Use the agreed lookback + candle interval (~300 bars max).
  - **Required shape (depth-2):** one TA task with `role: coordinator`, `toolGroups: ["keygen", "keygen_messaging", "chart:core", …]`, `budget.maxChildSpawns` 1–3, `budget.maxRounds` ~10–14. Coordinator fetches OHLCV **once**, then `agent_spawn_sub_agent` leaves with `toolGroups: ["chart:analyze"]` (one `analyze_*` family per child). Do **not** put all TA work in a single fat SlimSubLoop leaf with `chart:analyze`. After chart prepare, continue to spawn/analyze — do not stop for an interactive analysis menu.
- **Yield research** for `yield`: Continuum DeFi packs (Morpho, Aave, Lido, Ethena, Sky, …); require APY, liquidity, vault params from MCP returns.
- **Portfolio** for `portfolio` (and as funding helper for trade/yield): balances on every configured `chainId` via host tool **`agent_get_balance`** (Foundry `cast`; no approval — native gas or ERC-20); positions (perps, Uniswap v4 LP, lending, Lido, …); prices via CoinGecko/CMC (**ask before** loading market-data MCP). Prefer `agent_get_balance` over loading the Foundry MCP for simple reads; read-only `cast call` / `cast balance` via `agent_bash` also skip approval.
- **DAO** for `dao`: stub sections only.
- **Protocol risk** (lightweight, same plan): when a venue/protocol is named for this phase, include a short `protocol-risk` workstream. If venue is deferred, omit or mark deferred.
- **Trade ideas**: include in this plan only when venue (and optionally size) are specified or the operator explicitly wants ideas without a venue; otherwise defer to follow-on.
  - Trade-ideas tasks are **leaves** (`maxChildSpawns: 0`, **never** `role: coordinator`).
  - Set `dependsOn: [<ta-task-id>]` (and optionally the research task id). Host starts trade-ideas **only after TA status is `complete`**.
  - **Evidence:** primary = returned TA `mpc-task-result` (levels/structure/setups). Secondary = non-prescriptive research (macro/sentiment/catalysts). **Ignore** pundit tips (“X says buy ETH at $Y”). Always end with **Sources** (title + https links).
- **Funding / size**: when size is in scope for this plan (see table above), use `agent_get_balance` across configured chains; warn on venue-chain shortfall if venue is set.

## Machine block

Research leaves: `mcpServers` must include **`continuum`** for KeyGen messaging (not search). Also list AI Ready search/research ids when known; the host auto-merges AI Ready search + research/data servers at Execute.

Every plan ready for Execute must end with a valid:

```mpc-orchestrate v1
version: 1
tasks:
  - id: <asset>-research
    prompt: |
      Research <Legal Name> (<TICKER>) … (equity perps: note synthetic/venue vs cash tape).
      Cover catalysts with as-of dating. ~3 good sources then summarize.
      End with Sources (title + https links). No tradeIdeas.
    mcpServers: ["continuum"]
    toolGroups: ["keygen", "keygen_messaging"]
    budget:
      maxRounds: 10
      maxWallClockMs: 150000
      maxChildSpawns: 0
  - id: <asset>-ta
    role: coordinator
    prompt: |
      Fetch OHLCV once; spawn chart:analyze leaves (one analyze_* family each); join; post mpc-task-result.
      Do not stop after prepare_chart for a menu — continue analyze spawn/join.
    mcpServers: ["continuum"]
    toolGroups: ["keygen", "keygen_messaging", "chart:core", "chart:analyze"]
    budget:
      maxRounds: 14
      maxWallClockMs: 180000
      maxChildSpawns: 3
  - id: <asset>-trade-ideas
    dependsOn: ["<asset>-ta", "<asset>-research"]
    prompt: |
      Ground setups in TA mpc-task-result only. Research = non-prescriptive context (ignore buy-at-$Y tips).
      Sources with https links required.
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
    All tasks are terminal. Synthesize findings from the KeyGen thread.
    Preserve as-of dating; Sources with https links for non-TA claims.
    Post synthesis as a REPLY via send_key_gen_message.
synthesis:
  at: ""
  rescheduleOnReply: false
  cronPrompt: ""
  onPartial: true
```

Rules:

- Prefer `tasks[].toolGroups` Continuum pack ids; always include **`keygen_messaging`** so leaves can `send_key_gen_message` / `post_key_gen_chart_attachment`.
- Default tasks are leaves (`maxChildSpawns: 0`). **`role: coordinator` is only for TA depth-2** (fetch once → spawn `chart:analyze` leaves). Never mark research or trade-ideas as coordinator.
- Optional `dependsOn: [taskId, …]`: host waits for those tasks. Trade-ideas **must** depend on the TA task and starts only when TA is **`complete`** (skipped if TA failed).
- Do **not** perform the operator's research/trade work inline in plan chat — only author/refine the plan (unless they explicitly ask for a small clarifying lookup while drafting).
- If a **system** message says orchestration was already posted, report status — do **not** ask to Execute again unless drafting a **new** or **follow-on** plan.
- **Follow-on plan:** may start with `--- prior orchestration rollup ---`. Write a **new** `plans/<id>.md` with `priorOrchestrationMessageId` (venue, size, execution). If trade ideas / size / venue were deferred, run the **`agent_get_balance`** multi-chain funding check here; warn if the venue chain cannot cover the size.

## After synthesis

For multiSign/gas/cron actions, tell the operator to use **Continue in Orchestrator** in the node app (Telegram: open node app). Plan follow-on is for a **new research/execution manifest**, not post-synthesis signing.
