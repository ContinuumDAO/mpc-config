## Orchestration general market conditions (Plan → sub-agents)

Use with skill **`orchestration_planning`** for **`mode: research`** / “Assess general market conditions in a particular market”. Plan chat drafts the manifest only; specialists post **`mpc-task-result v1`** on KeyGen.

Name the **market** in every prompt (e.g. crypto majors, US equities, a sector). Split into **~3 leaves** — never one monolithic conditions task.

```yaml
# mpc-orchestrate v1
tasks:
  - id: market-research-sentiment
    prompt: |
      Research sentiment & narrative for <MARKET> (e.g. crypto majors).
      Tone, positioning, fear/greed. As-of dating. No trade tips.
      Gather ~3 good independent sources then summarize.
      End with Sources (title + https links). No tradeIdeas.
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
```

**Allowed swaps** (keep ~3): sector/theme deep-dive; cross-asset correlations; liquidity/flows; volatility regime. Task ids may include the market slug (e.g. `crypto-research-regime`).

**Anti-patterns:** one catch-all “market conditions” leaf; adding TA/`tradeIdeas` unless the operator also named a ticker for a separate trade plan; marking research leaves `role: coordinator`.

### Synthesis

`orchestratorOnReply` rolls up sentiment + regime + macro with as-of dating and Sources, posted as a KeyGen **REPLY** via `send_key_gen_message`.
