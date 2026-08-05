## Orchestration trade analysis (Plan → sub-agents → Continue)

Use with skills **`orchestration_planning`** and **`orchestration-chart-analysis`**. Plan chat drafts manifest only; sub-agents analyze and return **`tradeIdeas[]`** in **`mpc-task-result v1`**.

Embed **symbol, interval, lookback, and execution protocol** (`hyperliquid` | `arcus` | `gmx` | `uniswap`) in each task prompt — sub-agents do not elicit mid-run. For **`uniswap`** builds, also name the OHLCV source in the prompt (HL/Arcus/GMX perp fetch or CoinGecko/CMC — see **`trade_analysis_cron.example.md`** protocol table).

### Pattern B — depth-2 TA coordinator (**required** for TA in plans)

One mid-level coordinator fetches OHLCV, spawns analyze leaves (`agent_spawn_sub_agent` / join) in **waves of ≤6**, then posts a single joined `tradeIdeas[]`. Pair with **~3 research leaves** (sentiment / market-regime / macro — or allowed swaps) and a trade-ideas **leaf** that `dependsOn` the TA task only (research is best-effort).

```yaml
# mpc-orchestrate v1
tasks:
  - id: eth-research-sentiment
    prompt: |
      Research sentiment & narrative for Ethereum (ETH).
      News/social tone, crowd positioning, fear/greed, dominant narrative. As-of dating.
      Use legal/common name + ticker. No buy/sell price tips. Gather ~3 good independent sources then summarize.
      End with Sources (title + https links). No tradeIdeas.
    mcpServers: ["continuum"]
    toolGroups: ["keygen", "keygen_messaging"]
    budget:
      maxRounds: 14
      maxWallClockMs: 180000
      maxChildSpawns: 0

  - id: eth-research-market-regime
    prompt: |
      Research broad market regime around Ethereum (ETH).
      BTC/ETH beta, risk-on/off, majors vs alts; whether ETH is leading or lagging. Non-prescriptive.
      Use legal/common name + ticker. ~3 good sources then summarize. Sources (title + https). No tradeIdeas.
    mcpServers: ["continuum"]
    toolGroups: ["keygen", "keygen_messaging"]
    budget:
      maxRounds: 14
      maxWallClockMs: 180000
      maxChildSpawns: 0

  - id: eth-research-macro
    prompt: |
      Research macro backdrop for Ethereum (ETH) / crypto risk assets.
      Rates/liquidity/USD, inflation, policy calendar, geopolitics; dated events with as-of framing.
      Use legal/common name + ticker. ~3 good sources then summarize. Sources (title + https). No tradeIdeas.
    mcpServers: ["continuum"]
    toolGroups: ["keygen", "keygen_messaging"]
    budget:
      maxRounds: 14
      maxWallClockMs: 180000
      maxChildSpawns: 0

  - id: eth-ta
    role: coordinator
    prompt: |
      Fetch OHLCV once for ETH (interval/lookback from operator goal) on this conversation.
      Spawn leaf specialists (chart:analyze) — one analyze_* family per child — in waves of ≤6;
      join between waves until every planned family is covered.
      After prepare_chart, continue spawn/join (do not stop for an analysis menu).
      Join compress summaries; post mpc-task-result with slim summary + tradeIdeas[]
      (analysisSetup + source.chartData {dataSource, interval, barCount}). Do not build multiSign.
    mcpServers: ["hyperliquid", "continuum"]
    toolGroups: ["keygen", "keygen_messaging", "chart:core", "chart:analyze"]
    skills: ["chart-analysis-menu"]
    budget:
      maxRounds: 20
      maxWallClockMs: 240000
      maxChildSpawns: 6

  - id: eth-trade-ideas
    dependsOn:
      - eth-ta
    prompt: |
      Ground directional setups ONLY in the eth-ta mpc-task-result (levels/structure).
      Use research leaves only for non-prescriptive sentiment / regime / macro context.
      Ignore pundit "buy/sell at $Y" tips from research — they must not set side/entry/stop.
      Include Sources (title + https links) for any external claims. Preserve as-of dating.
      If fewer than 3 decent research posts/sources landed, tell the operator to enable better
      Research data sources in the MCP AI Ready list.
    mcpServers: ["continuum"]
    toolGroups: ["keygen", "keygen_messaging"]
    budget:
      maxRounds: 10
      maxWallClockMs: 120000
      maxChildSpawns: 0
```

**Anti-patterns:** one monolithic research task; fat SlimSubLoop leaf with `chart:analyze` and no `role: coordinator`; marking trade-ideas or research as `role: coordinator`; starting trade-ideas without `dependsOn` on the TA task.

### Pattern A — flat parallel analyze leaves (legacy; avoid for new plans)

Host may still run flat `chart:analyze` leaves, but planning should prefer Pattern B. If a fat TA leaf is authored, the node promotes it to a coordinator.

Replace **`hyperliquid`** in `mcpServers` with **`gmx`** or **`arcus`** when the operator goal is GMX or Arcus execution (load protocol + explicit `chainId` on fetch — Arcus **4663**). For Uniswap spot goals, keep an OHLCV-capable server in `mcpServers` for analysis tasks and load **uniswap** only on the orchestrator Continue / build step.

### mpc-task-result v1 (sub-agent reply on KeyGen)

```yaml
# mpc-task-result v1
taskId: eth-ta
status: complete
summary: Joined TA — falling wedge + bullish trend retest; see tradeIdeas
tradeIdeas:
  - id: "<uuid from analyze / conversation registry>"
    source:
      analysisType: chart_pattern
      toolName: analyze_chart_patterns
      chartData:
        dataSource: hl
        interval: 4h
        barCount: 181
    status: clear
    side: long
    symbol: ETH
    protocolId: hyperliquid
    entry: { price: 1834, label: neckline }
    target: { price: 1940.2 }
    invalidation: { price: 1757.8, label: trough }
    analysisSetup:
      kind: chart_pattern
      setup: { ... chartPatternTradeSetup fields ... }
charts: []
```

### Continue in Orchestrator (execution)

**`POST /agent/orchestration/continue`** copies aggregated **`tradeIdeas`** (including `source.chartData` + `analysisSetup`) to the **`[Orchestrator]`** conversation. Operator: *“Trade the trend retest on GMX”* → **`load_defi_protocol`** → **`build_trade_from_trade_idea`** with chosen **`tradeIdeaId`** and **`protocolId`** from operator goal (**hyperliquid** / **arcus** / **gmx** / **uniswap** per **`trade-defaults`** §5).

**Chart restore:** call **`agent_restore_trade_idea_chart`** with `tradeIdeaId` (pre-build) or `purpose` after multiSign (Purpose `ds=`/`iv=`/`n=`). Host returns fetch → prepare → apply steps; Orchestrator runs the MCP tools.

**Never** use **`submit_trade_from_consensus`** on orchestrator threads — that tool is **cron-only**. Sub-agents must **not** create multiSign / `requestId` / Purpose — Continue builds those.
