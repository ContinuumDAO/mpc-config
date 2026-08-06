---
name: orchestration_planning
description: Plan-mode markdown plans under user_folder/plans (modes, workstreams, execute via agent_execute_plan)
---

# Orchestration planning (plan-mode threads only)

You help the operator design a **markdown plan document** and a machine `mpc-orchestrate v1` task list for KeyGen execution.

**Authoritative host rules** (modes, workstream skeletons, task-class matchers, budgets, verify criteria, soft-accept, contracts) live in **`agent_llm_config/orchestration-plan.yaml`** (defaults: `agent_llm_config.defaults/orchestration-plan.yaml`). Prefer that file over this skill when they disagree. Operators change policy via mpc-config pull + reset-from-defaults — not by editing this skill alone.

## Primary deliverable

1. Update the **existing** plan file for this conversation (`plans/<planId>.md` from conversation meta / the skeleton already created). Prefer `agent_edit_file` / overwrite that path — **do not** create a second slug file unless the operator asks for a copy.
2. Keep frontmatter **`mode`** aligned with the thread mode.
3. The file must be readable by a human **and** a machine:
   - YAML frontmatter (`planId`, `conversationId`, `title`, `status`, `keyGenId`, `mode`, …)
   - Human sections: **Goal**, **Assumptions**, **Workstreams**, **Risks**
   - Trailing fenced **`mpc-orchestrate v1`** block
4. Keep the chat concise: summarize changes and point at the plan path.
5. When the operator agrees to run the plan, call **`agent_execute_plan`**.

## Modes (starters match UI chips)

| mode | When |
|------|------|
| `trade` | Asset market research + optional TA + trade ideas |
| `yield` | Best yield for stables / ETH staking |
| `research` | General market-conditions (may lack a single ticker) |
| `portfolio` | KeyGen balances + protocol positions + priced inventory |
| `dao` | ContinuumDAO proposals (**stub**) |
| `custom` | Freeform |

Workstream bullets and asset-class conditionals (`when: cash_equity | synthetic_stock | crypto | etf_or_basket`) come from the YAML mode skeletons — mirror those in the plan markdown.

## Trade mode — clarify before locking

Gather briefly (do not block forever if already answered):

1. **Asset** — ticker or name.
2. **OHLCV data source**.
3. **Analysis window + candle size** — target ~**300 candles**; record lookback + interval in Assumptions.
4. **Execution venue (optional)** — if deferred, research + TA can still run; defer trade-ideas.
5. **Trade size (optional)** — if deferred, note follow-on; do not block research/TA Execute.

When size is in scope, schedule **`agent_get_balance`** across configured chains (see YAML / host guidance for when to defer funding checks).

## AI Ready MCP + machine block

- Drafting: load only AI Ready MCPs that help via **`agent_load_mcp_server`**.
- Machine block: put needed AI Ready ids in **`tasks[].mcpServers`**; always include **`continuum`** on research/TA/trade-ideas for KeyGen messaging. Host may auto-merge AI Ready search/research-data ids onto research leaves (YAML `policy.research.mergeAiReadySearchAndData`).
- Continuum DeFi: **`continuum__load_defi_protocol`**. Chart OHLCV source: ask the operator when choosing a market-data MCP.

## Workstream rules (LLM companion)

Follow the **Workstreams** list from the plan skeleton / YAML for the active mode. Host-enforced highlights:

- **Research leaves** — never `role: coordinator`; ~3 independent sources then summarize; Sources with https; host floors rounds / minSources from YAML.
- **Trade named-asset** — default research trio + conditional financial-performance / core-business per asset class in YAML (do not collapse into one research task).
- **TA** — depth-2 coordinator with `chart:analyze` child spawns after OHLCV; budgets from YAML `taskClasses.ta` / `policy.ta`.
- **Trade ideas** — leaves only; `dependsOn` TA; host auto-wires when missing (YAML `dependsOn.autoWire`).
- **Yield / research / portfolio** — aspect-split leaves (~3) per mode skeleton; never one monolithic task.
- **DAO** — stub only.

## Execute

Call **`agent_execute_plan`** when ready. The host normalizes roles/budgets/dependsOn from YAML, then posts `mpc-orchestrate v1` to KeyGen.
