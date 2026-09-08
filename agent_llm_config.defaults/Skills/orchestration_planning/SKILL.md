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
3. **Analysis window + candle size** — target ~**300 candles**; record lookback + interval in Assumptions. If the operator’s window is below `policy.ta.requiredToolMinBars` plus a conservative pad (`days = ceil(need × intervalHours / 24) + max(3 days, 10%)`), **lock the widened window** (e.g. 30d @ 4h → **37d @ 4h**) and say so. Do not lock a short window or promise shorter MA periods.
4. **Execution venue (optional)** — if deferred, research + TA can still run; defer trade-ideas.
5. **Trade size (optional)** — if deferred, note follow-on; do not block research/TA Execute.

When size is in scope, schedule **`agent_get_balance`** across configured chains (see YAML / host guidance for when to defer funding checks).

## Follow-on plans (any prior TA run)

When the first user message is **`--- prior orchestration rollup ---`**, this thread is a **follow-on**, not a greenfield plan. The recipe is **`followOn`** in **`orchestration-plan.yaml`** (shared by every mode that produced host trade ideas — not only “research market for an asset”).

1. **Store ideas in the plan file** under **`## Prior trade ideas`**: id, side, status, confidence, entry / target / invalidation, `dataSource`, interval, barCount. Host copies the same ideas onto **this** conversation — call **`list_trade_ideas`**. An empty chart-session menu is not “no ideas”.
2. **Inherit** locked inputs (asset, OHLCV source, interval, bars). Do not re-ask. Do not re-run research or TA unless the operator explicitly wants a new analysis.
3. **Trade / “research market for an asset” — live position first** (plan-time, before size or build):
   - Ask: do they have **(or recently had)** a trade on this asset, and **which venue** (e.g. Hyperliquid)? Do not assume the OHLCV source is the live venue.
   - **If they name a venue:** discover tools for **open positions and closed/recent history** (`continuum__search_continuum_tools`, `list_tool_groups`, `load_defi_protocol` + `get_defi_protocol_skill` — look for position, closed, fill, history, or account tools; do not hardcode a fetch name). Pull both for the inherited asset.
   - **If still open:** compare using **whatever `analyze_*` families that orchestration initiated** (`policy.ta.analyzeTools` / the TA task) — not a hardcoded family list. Use every injected Prior trade idea (`analysisType` / `toolName` as stored); the synthesis recommended pick is primary if one was named; other stored ideas from that run are confirmation or contradiction. Families that ran but did not upsert an idea appear only in the TA task summary — use that text. Do not invent families that were not in that run and do not re-run `analyze_*`. For perps: side match, mark vs each stored idea’s entry/target/invalidation, distance-to-target, invalidation already breached. Recommend **hold / close / tighten / add** with reasons that cite those stored signals. Write the comparison into the plan file. Do not invent PnL.
   - **If already closed** (they thought it was live, or history shows a recent close): report what happened — side, size, entry, exit, close time/reason if returned, realized PnL only if returned, and how the exit lines up with the stored idea target/invalidation (hit target, stopped/invalidated, liquidated, manual/unknown). Do not invent a close story. Then **ask what to do next** (open the recommended pick, stay flat, or something else). Only go to funding-size / build if they choose to open.
   - **If they never had a trade** (or tools show neither open nor a relevant close): ask whether they want to **open** one, naming the recommended pick. Only if they say yes: **funding-size** then **trade-ideas** (`build_trade_from_trade_idea`). If they decline, stop.
4. **inherit-trade-ideas** and **live-position-review** are plan-time — do **not** put them in the `mpc-orchestrate` fence.
5. Skip the greenfield questionnaire and the custom-mode starter menu.

## AI Ready MCP + machine block

- Drafting: load only AI Ready MCPs that help via **`agent_load_mcp_server`**.
- Machine block: put needed AI Ready ids in **`tasks[].mcpServers`**; always include **`continuum`** on research/TA/trade-ideas for KeyGen messaging. Host may auto-merge AI Ready search/research-data ids onto research leaves (YAML `policy.research.mergeAiReadySearchAndData`).
- Continuum DeFi: **`continuum__load_defi_protocol`**. Chart OHLCV source: ask the operator when choosing a market-data MCP.

## Workstream rules (LLM companion)

Follow the **Workstreams** list from the plan skeleton / YAML for the active mode. Host-enforced highlights:

- **Research leaves** — never `role: coordinator`; ~3 independent sources then summarize; Sources with https; host floors rounds / minSources from YAML.
- **Trade named-asset** — default research trio + conditional financial-performance / core-business per asset class in YAML (do not collapse into one research task).
- **TA** — coordinator runs each `policy.ta.analyzeTools` `analyze_*` on **this** conversation after **one** load + **one** fetch. Do **not** spawn children (extra MCP sessions have crashed continuum-mcp). If `load_defi_protocol` errors, do not retry it — call fetch next. Never retry identical tool arguments. Isolated `analyze_*` errors are coverage gaps. Post a **slim** `mpc-task-result` immediately (`status: complete` if any family produced evidence). KeyGen `send` timeout is not task failure; retry once with a changed body (`deliveryRetry: 1`).
- **Trade ideas** — leaves only; `dependsOn` TA; host auto-wires when missing (YAML `dependsOn.autoWire`).
- **Yield / research / portfolio** — aspect-split leaves (~3) per mode skeleton; never one monolithic task.
- **DAO** — stub only.

## Execute

Call **`agent_execute_plan`** when ready. The host normalizes roles/budgets/dependsOn from YAML, then posts `mpc-orchestrate v1` to KeyGen.
