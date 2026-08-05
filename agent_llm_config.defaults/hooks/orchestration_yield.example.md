## Orchestration yield research (Plan → sub-agents)

Use with skill **`orchestration_planning`** for **`mode: yield`** / “Explore the best yield for stablecoins”. Plan chat drafts the manifest only; specialists post **`mpc-task-result v1`** on KeyGen.

Split into **~3 leaves** (not one monolithic yield task). Opportunity scan should use Continuum DeFi packs for live APY/liquidity; risk and macro leaves use web/research sources with as-of dating.

```yaml
# mpc-orchestrate v1
tasks:
  - id: yield-opportunity-scan
    prompt: |
      Compare live stablecoin yield opportunities (e.g. USDC/USDT/DAI on operator chains).
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
      As-of dating. Gather ~3 good independent sources then summarize.
      End with Sources (title + https links). No tradeIdeas.
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
```

**Allowed swaps** (keep ~3): LST/ETH staking yield; wallet funding inventory via `agent_get_balance`; bridge/chain deployment map.

**Anti-patterns:** one catch-all “find best yield” leaf; marking yield tasks `role: coordinator`; inventing APYs without MCP/tool evidence.

### Synthesis

`orchestratorOnReply` should rank opportunities with risk caveats, preserve as-of dating, and post a KeyGen **REPLY** via `send_key_gen_message`. Execution / deposits stay for **Continue in Orchestrator** or a follow-on plan.
