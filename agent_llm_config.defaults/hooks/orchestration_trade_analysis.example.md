## Orchestration trade analysis (Plan → sub-agents → Continue)

Use with skills **`orchestration_planning`** and **`orchestration-chart-analysis`**. Plan chat drafts manifest only; sub-agents analyze and return **`tradeIdeas[]`** in **`mpc-task-result v1`**.

```yaml
# mpc-orchestrate v1
tasks:
  - id: eth-pattern-analysis
    prompt: |
      Fetch OHLCV per operator goal. Run analyze_chart_patterns.
      In mpc-task-result v1 include tradeIdeas[] copied from tool JSON
      (chartPatternTradeSetup wrapped as TradeIdea). Analysis only — no chart attach.
    mcpServers: ["hyperliquid", "continuum"]
    skills: ["chart-analysis-classic-patterns", "chart-analysis-menu"]

  - id: eth-levels-analysis
    prompt: |
      Same OHLCV session. Run analyze_key_levels.
      Include tradeIdeas[] in mpc-task-result (keyLevelsTradeSetup).
    mcpServers: ["hyperliquid", "continuum"]
    skills: ["chart-analysis-levels"]
```

### mpc-task-result v1 (sub-agent reply on KeyGen)

```yaml
# mpc-task-result v1
taskId: eth-pattern-analysis
status: complete
summary: Falling wedge clear long; see tradeIdeas
tradeIdeas:
  - id: "<uuid from analyze / conversation registry>"
    source: { analysisType: chart_pattern, toolName: analyze_chart_patterns }
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

**`POST /agent/orchestration/continue`** copies aggregated **`tradeIdeas`** to the **`[Orchestrator]`** conversation. Operator: *“Trade the pattern setup on Hyperliquid”* → **`load_defi_protocol`** → **`build_trade_from_chart_pattern`** with chosen **`tradeIdeaId`**.

**Never** use **`submit_trade_from_consensus`** on orchestrator threads — that tool is **cron-only**.
