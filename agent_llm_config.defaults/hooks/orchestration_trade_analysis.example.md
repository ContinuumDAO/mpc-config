## Orchestration trade analysis (Plan → sub-agents → Continue)

Use with skills **`orchestration_planning`** and **`orchestration-chart-analysis`**. Plan chat drafts manifest only; sub-agents analyze and return **`tradeIdeas[]`** in **`mpc-task-result v1`**.

Embed **symbol, interval, lookback, and execution protocol** (`hyperliquid` | `arcus` | `gmx` | `uniswap`) in each task prompt — sub-agents do not elicit mid-run. For **`uniswap`** builds, also name the OHLCV source in the prompt (HL/Arcus/GMX perp fetch or CoinGecko/CMC — see **`trade_analysis_cron.example.md`** protocol table).

### Pattern A — flat parallel analyze leaves (still valid)

```yaml
# mpc-orchestrate v1
tasks:
  - id: eth-pattern-analysis
    prompt: |
      Fetch OHLCV per operator goal. Run analyze_chart_patterns.
      In mpc-task-result v1 include tradeIdeas[] with analysisSetup and source.chartData
      {dataSource, interval, barCount}. Analysis only — no multiSign / Purpose.
    mcpServers: ["hyperliquid", "continuum"]
    toolGroups: ["keygen", "chart:core", "chart:analyze"]
    skills: ["chart-analysis-classic-patterns", "chart-analysis-menu"]

  - id: eth-trend-analysis
    prompt: |
      Same symbol/session. Run analyze_trend_structure.
      Include tradeIdeas[] (trendStructureTradeSetup, analysisType trend_structure, chartData).
    mcpServers: ["hyperliquid", "continuum"]
    toolGroups: ["keygen", "chart:core", "chart:analyze"]
    skills: ["chart-analysis-trend"]
```

### Pattern B — depth-2 TA coordinator (preferred for many analyzes on one session)

One mid-level coordinator fetches OHLCV, spawns analyze leaves (`agent_spawn_sub_agent` / join), then posts a single joined `tradeIdeas[]`. Pair with a news/research **leaf** when needed.

```yaml
# mpc-orchestrate v1
tasks:
  - id: eth-news-research
    prompt: |
      Summarize recent ETH catalyst/news for the operator goal. No charts / no tradeIdeas required.
    mcpServers: ["continuum"]
    toolGroups: ["keygen"]
    budget:
      maxChildSpawns: 0

  - id: eth-ta-coordinator
    role: coordinator
    prompt: |
      Fetch OHLCV once for ETH (interval/lookback from operator goal) on this conversation.
      Spawn leaf specialists (chart:analyze) for patterns, trend, key levels as needed — one analyze_* family per child.
      Join compress summaries; post mpc-task-result with slim summary + tradeIdeas[]
      (analysisSetup + source.chartData {dataSource, interval, barCount}). Do not build multiSign.
    mcpServers: ["hyperliquid", "continuum"]
    toolGroups: ["keygen", "chart:core", "chart:analyze"]
    skills: ["chart-analysis-menu"]
    budget:
      maxRounds: 10
      maxWallClockMs: 120000
      maxChildSpawns: 3
```

Replace **`hyperliquid`** in `mcpServers` with **`gmx`** or **`arcus`** when the operator goal is GMX or Arcus execution (load protocol + explicit `chainId` on fetch — Arcus **4663**). For Uniswap spot goals, keep an OHLCV-capable server in `mcpServers` for analysis tasks and load **uniswap** only on the orchestrator Continue / build step.

### mpc-task-result v1 (sub-agent reply on KeyGen)

```yaml
# mpc-task-result v1
taskId: eth-ta-coordinator
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

Trend idea example (truncated):

```yaml
# mpc-task-result v1
taskId: eth-trend-analysis
status: complete
summary: Bullish HH — support trend retest long clear
tradeIdeas:
  - id: "<uuid>"
    source:
      analysisType: trend_structure
      toolName: analyze_trend_structure
      chartData: { dataSource: hl, interval: 4h, barCount: 181 }
    status: clear
    side: long
    symbol: ETH
    analysisSetup:
      kind: trend_structure
      setup: { setupPurposeCode: trend-ret, trendLineNumber: 1, primaryTrendKind: support, ... }
charts: []
```

### Continue in Orchestrator (execution)

**`POST /agent/orchestration/continue`** copies aggregated **`tradeIdeas`** (including `source.chartData` + `analysisSetup`) to the **`[Orchestrator]`** conversation. Operator: *“Trade the trend retest on GMX”* → **`load_defi_protocol`** → **`build_trade_from_trade_idea`** with chosen **`tradeIdeaId`** and **`protocolId`** from operator goal (**hyperliquid** / **arcus** / **gmx** / **uniswap** per **`trade-defaults`** §5).

**Chart restore:** call **`agent_restore_trade_idea_chart`** with `tradeIdeaId` (pre-build) or `purpose` after multiSign (Purpose `ds=`/`iv=`/`n=`). Host returns fetch → prepare → apply steps; Orchestrator runs the MCP tools.

**Never** use **`submit_trade_from_consensus`** on orchestrator threads — that tool is **cron-only**. Sub-agents must **not** create multiSign / `requestId` / Purpose — Continue builds those.
