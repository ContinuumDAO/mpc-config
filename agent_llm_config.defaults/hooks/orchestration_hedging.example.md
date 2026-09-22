## Orchestration hedging research (Plan → sub-agents)

Use with skills **`orchestration_planning`** and **`hedging-trade`** for **`mode: hedging`**. Plan chat drafts the manifest only; specialists post **`mpc-task-result v1`** on KeyGen.

First Execute is **research-only** (~3 leaves). Hedge design, capital path, and Unwind stay in the human plan markdown. Compose MultiSign in **Continue in Orchestrator** or a follow-on plan. After open-hedge legs exist, load **`hedging-monitor`** — do not invent unwind rules here.

```yaml
# mpc-orchestrate v1
tasks:
  - id: hedge-inventory-exposure
    prompt: |
      Inventory KeyGen balances on every configured chainId via agent_get_balance
      (native + key ERC-20s/LSTs/stables). Discover and read open perps (HL / GMX / Arcus),
      Derive options, Aave/Morpho/Euler loans + HF, Morpho Earn shares + Exposure,
      Euler curated Earn + Strategies, Uniswap v4 / Curve / Aerodrome / Pendle LP,
      Pendle PT/YT. Report units, venues, wrappers. Do not invent positions, IL, or PnL.
      As-of dating. No tradeIdeas.
    mcpServers: ["continuum"]
    toolGroups: ["keygen", "keygen_messaging"]
    budget:
      maxRounds: 14
      maxWallClockMs: 180000
      maxChildSpawns: 0

  - id: hedge-venue-market
    prompt: |
      For the inherited hedge asset(s): mark, funding, open interest, 2% depth vs the
      planned notional on Hyperliquid / GMX / Arcus as relevant. If options are in scope:
      Derive IV/skew, listed expiries, premium as % of notional. If Pendle is in scope:
      market, expiry, implied APY vs floating. If curated Earn is opted in: Morpho
      Exposure and Euler Strategies (labels + % of TVL). Cite sources. No tradeIdeas.
    mcpServers: ["continuum"]
    toolGroups: ["keygen", "keygen_messaging"]
    budget:
      maxRounds: 12
      maxWallClockMs: 180000
      maxChildSpawns: 0

  - id: hedge-protocol-risk
    prompt: |
      Short protocol-risk notes for every named venue/curator/asset class in this plan
      (oracle, listing, bridge/CCTP, cooldown, allocation drift, RWA/reinsurance class risk).
      As-of dating. ~3 good independent sources then summarize. Sources (title + https).
      No tradeIdeas.
    mcpServers: ["continuum"]
    toolGroups: ["keygen", "keygen_messaging"]
    budget:
      maxRounds: 10
      maxWallClockMs: 150000
      maxChildSpawns: 0
```

**Anti-patterns:** compose / `ctm_*_build_*_multisign` in the first fence; one catch-all hedge leaf; inventing positions or IL; treating HLP/GM or a Re/RWA Earn vault as a delta hedge; marking hedge tasks `role: coordinator`.

### Synthesis

`orchestratorOnReply` ranks **one primary overlay** plus a fallback (e.g. Pendle PT if HL depth fails), cites inventory + venue + risk leaves, preserves as-of dating, and posts a KeyGen **REPLY** via `send_key_gen_message`. Execution / MultiSign stay for **Continue in Orchestrator** or a follow-on plan.

```yaml
synthesis:
  at: ""
  rescheduleOnReply: false
  cronPrompt: |
    Load hedging-monitor. Do not invent unwind rules — copy Unwind + Hedge design
    from the plan file. If the hedge is not live yet, say so and stop.
```
