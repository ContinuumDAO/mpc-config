## Orchestration trade analysis (Plan → sub-agents → Continue)

Use with skills **`orchestration_planning`** and **`orchestration-chart-analysis`**. Plan chat drafts manifest only; sub-agents analyze and return **`tradeIdeas[]`** in **`mpc-task-result v1`**.

Embed **symbol, interval, lookback, and execution protocol** (`hyperliquid` | `arcus` | `gmx` | `uniswap`) in each task prompt — sub-agents do not elicit mid-run. For **`uniswap`** builds, also name the OHLCV source in the prompt (HL/Arcus/GMX perp fetch or CoinGecko/CMC — see **`trade_analysis_cron.example.md`** protocol table).

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

  - id: eth-trend-analysis
    prompt: |
      Same OHLCV session. Run analyze_trend_structure.
      Include tradeIdeas[] in mpc-task-result (trendStructureTradeSetup, analysisType trend_structure).
    mcpServers: ["hyperliquid", "continuum"]
    skills: ["chart-analysis-trend"]

  - id: eth-levels-nearest-analysis
    prompt: |
      Same OHLCV session. Run analyze_key_levels (nearest bounce/rejection only).
      Include tradeIdeas[] in mpc-task-result (keyLevelsTradeSetup, analysisType key_levels).
    mcpServers: ["hyperliquid", "continuum"]
    skills: ["chart-analysis-levels"]

  - id: eth-fib-levels-analysis
    prompt: |
      Same OHLCV session. Run analyze_key_level_fibonacci (outer range 0.618 / 1.618 extension).
      Include tradeIdeas[] in mpc-task-result (keyLevelFibTradeSetup, analysisType key_level_fibonacci).
    mcpServers: ["hyperliquid", "continuum"]
    skills: ["chart-analysis-levels"]
```

Replace **`hyperliquid`** in `mcpServers` with **`gmx`** or **`arcus`** when the operator goal is GMX or Arcus execution (load protocol + explicit `chainId` on fetch — Arcus **4663**). For Uniswap spot goals, keep an OHLCV-capable server in `mcpServers` for analysis tasks and load **uniswap** only on the orchestrator Continue / build step.

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

Trend sub-agent example (truncated):

```yaml
# mpc-task-result v1
taskId: eth-trend-analysis
status: complete
summary: Bullish HH — support trend retest long clear
tradeIdeas:
  - id: "<uuid>"
    source: { analysisType: trend_structure, toolName: analyze_trend_structure }
    status: clear
    side: long
    symbol: ETH
    analysisSetup:
      kind: trend_structure
      setup: { setupPurposeCode: trend-ret, trendLineNumber: 1, primaryTrendKind: support, ... }
charts: []
```

Fib sub-agent example (truncated):

```yaml
# mpc-task-result v1
taskId: eth-fib-levels-analysis
status: complete
summary: Above outer range — kl-fib-ext long clear
tradeIdeas:
  - id: "<uuid>"
    source: { analysisType: key_level_fibonacci, toolName: analyze_key_level_fibonacci }
    status: clear
    side: long
    symbol: ETH
    analysisSetup:
      kind: key_level_fibonacci
      setup: { priceRegime: above_range, setupPurposeCode: kl-fib-ext, fibPairNumber: 1, ... }
charts: []
```

### Continue in Orchestrator (execution)

**`POST /agent/orchestration/continue`** copies aggregated **`tradeIdeas`** to the **`[Orchestrator]`** conversation. Operator: *“Trade the trend retest on GMX”* → **`load_defi_protocol`** → **`build_trade_from_trade_idea`** with chosen **`tradeIdeaId`** and **`protocolId`** from operator goal (**hyperliquid** / **arcus** / **gmx** / **uniswap** per **`trade-defaults`** §5).

**Never** use **`submit_trade_from_consensus`** on orchestrator threads — that tool is **cron-only**.
