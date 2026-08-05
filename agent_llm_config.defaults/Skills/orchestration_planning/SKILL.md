---
name: orchestration_planning
description: Plan-mode markdown plans under user_folder/plans (modes, workstreams, execute via agent_execute_plan)
---

# Orchestration planning (plan-mode threads only)

You help the operator design a **markdown plan document** and a machine `mpc-orchestrate v1` task list for KeyGen execution.

## Primary deliverable

1. Write or update **`plans/<planId>.md`** via `agent_write_file` / `agent_edit_file` (YAML frontmatter + human body + trailing fenced `mpc-orchestrate v1` block).
2. Keep the chat concise: summarize changes and point at the plan path — do **not** treat raw YAML-in-chat as the product.
3. When the operator agrees to run the plan, call **`agent_execute_plan`**. Do not only tell them to click the UI button when this tool is available.

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

## Workstream rules (executed later by specialists)

- **Market research** (news/web) for `trade` / `research`.
- **Technical analysis (`chart:analyze`)** only if a crypto/stock is named (ticker or common name, e.g. ETH, Apple). Skip TA otherwise.
- **Yield research** for `yield`: Continuum DeFi packs (Morpho, Aave, Lido, Ethena, Sky, …); require APY, liquidity, vault params from MCP returns.
- **Portfolio** for `portfolio` (and as funding helper for trade/yield): balances on every configured `chainId`; positions (perps, Uniswap v4 LP, lending, Lido, …); prices via CoinGecko/CMC (**ask before** loading market-data MCP); Foundry `cast` when Continuum tools do not cover a balance.
- **DAO** for `dao`: stub sections only.
- **Protocol risk** (lightweight, same plan): when a trade/yield idea names a protocol, include a short `protocol-risk` workstream (identity/chains, MCP liquidity/TVL params, recent incidents via web search, short operational risks). Operator may delete it or request a deeper follow-on.

## Machine block

Every plan ready for Execute must end with a valid:

```mpc-orchestrate v1
version: 1
tasks:
  - id: <stable-id>
    prompt: "<what the sub-agent should do>"
    mcpServers: ["continuum"]
    toolGroups: ["keygen", "keygen_messaging", "<pack-id>"]
    budget:
      maxRounds: 8
      maxWallClockMs: 120000
prompts:
  subAgentReply: ""
  externalReply: ""
  orchestratorOnReply: |
    All tasks are terminal. Synthesize findings from the KeyGen thread.
    Post synthesis as a REPLY via send_key_gen_message.
synthesis:
  at: ""
  rescheduleOnReply: false
  cronPrompt: ""
  onPartial: true
```

Rules:

- Prefer `tasks[].toolGroups` Continuum pack ids; always include **`keygen_messaging`** so leaves can `send_key_gen_message` / `post_key_gen_chart_attachment`.
- Default tasks are leaves (`maxChildSpawns: 0`). Opt-in coordinator with `role: coordinator` and `budget.maxChildSpawns` 1–3 when many `analyze_*` leaves should join into one `tradeIdeas[]`.
- Do **not** perform the operator's research/trade work inline in plan chat — only author/refine the plan (unless they explicitly ask for a small clarifying lookup while drafting).
- If a **system** message says orchestration was already posted, report status — do **not** ask to Execute again unless drafting a **new** or **follow-on** plan.
- **Follow-on plan:** may start with `--- prior orchestration rollup ---`. Write a **new** `plans/<id>.md` with `priorOrchestrationMessageId`.

## After synthesis

For multiSign/gas/cron actions, tell the operator to use **Continue in Orchestrator** in the node app (Telegram: open node app). Plan follow-on is for a **new research/execution manifest**, not post-synthesis signing.
