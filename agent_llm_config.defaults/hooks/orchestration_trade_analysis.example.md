## Orchestration trade analysis (Plan → sub-agents → Continue)

Use with skills **`orchestration_planning`** and **`orchestration-chart-analysis`**. Plan chat drafts manifest only; sub-agents analyze and return **`tradeIdeas[]`** in **`mpc-task-result v1`**.

Embed **symbol, interval, lookback, and execution protocol** (`hyperliquid` | `arcus` | `gmx` | `uniswap`) in each task prompt — sub-agents do not elicit mid-run. For **`uniswap`** builds, also name the OHLCV source in the prompt (HL/Arcus/GMX perp fetch or CoinGecko/CMC — see **`trade_analysis_cron.example.md`** protocol table).

### Pattern B — depth-2 TA coordinator (**required** for TA in plans)

One mid-level coordinator fetches OHLCV, spawns analyze leaves (`agent_spawn_sub_agent` / join), then posts a single joined `tradeIdeas[]`. Pair with a news/research **leaf** and a trade-ideas **leaf** that `dependsOn` the TA task.

```yaml
# mpc-orchestrate v1
tasks:
  - id: eth-news-research
    prompt: |
      Summarize recent ETH catalyst/news for the operator goal.
      Macro/sentiment/catalysts only — no buy/sell price tips.
      End with Sources (title + https links). No tradeIdeas. Prefer as-of dating for "today/this week".
    mcpServers: ["continuum"]
    toolGroups: ["keygen", "keygen_messaging"]
    budget:
      maxRounds: 8
      maxWallClockMs: 120000
      maxChildSpawns: 0

  - id: eth-ta
    role: coordinator
    prompt: |
      Fetch OHLCV once for ETH (interval/lookback from operator goal) on this conversation.
      Spawn leaf specialists (chart:analyze) for patterns, trend, key levels as needed — one analyze_* family per child.
      Join compress summaries; post mpc-task-result with slim summary + tradeIdeas[]
      (analysisSetup + source.chartData {dataSource, interval, barCount}). Do not build multiSign.
    mcpServers: ["hyperliquid", "continuum"]
    toolGroups: ["keygen", "keygen_messaging", "chart:core", "chart:analyze"]
    skills: ["chart-analysis-menu"]
    budget:
      maxRounds: 14
      maxWallClockMs: 180000
      maxChildSpawns: 3

  - id: eth-trade-ideas
    dependsOn: ["eth-ta", "eth-news-research"]
    prompt: |
      Ground directional setups ONLY in the eth-ta mpc-task-result (levels/structure).
      Use eth-news-research only for non-prescriptive macro/sentiment context.
      Ignore pundit "buy/sell at $Y" tips from research — they must not set side/entry/stop.
      Include Sources (title + https links) for any external claims. Preserve as-of dating.
    mcpServers: ["continuum"]
    toolGroups: ["keygen", "keygen_messaging"]
    budget:
      maxRounds: 10
      maxWallClockMs: 120000
      maxChildSpawns: 0
```

**Anti-patterns:** fat SlimSubLoop leaf with `chart:analyze` and no `role: coordinator`; marking trade-ideas or research as `role: coordinator`; starting trade-ideas without `dependsOn` on the TA task.

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
