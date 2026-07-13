# Scheduled automation (cron & webhooks)

Load this skill when creating or editing **cron jobs**, **inbound webhooks**, or **one-shot scheduled agent turns** — especially when the run must execute **without** an operator present.

Tool reference: continuum MCP **`agent_cron_jobs_docs`** (`agent-cron-jobs.md`), **`agent_webhooks_docs`** (`agent-webhooks.md`). For KeyGen orchestration manifests and synthesis cron, load **`orchestration_planning`** instead.

## Non-interactive runs (required)

Cron jobs, webhook handlers, and scheduled orchestration cron turns:

- **Cannot block on MCP elicitation** or open-ended questions — the turn fails if human input is required.
- Embed **confirmed** parameters in the job **`message`** / webhook **`prompt`**: chain IDs, amounts, addresses, `requestId` targets, fee speed, gas choices, and “broadcast yes/no”.
- Gather preferences in **interactive chat first**, then write the scheduled message with those values frozen.
- Do **not** use open-ended prompts like “ask the operator which chain” inside a cron/webhook body.

## Schedule kinds

| kind | Use when | Notes |
|------|----------|-------|
| **`at`** | One-shot at a specific time (RFC3339 UTC) | Defaults **`deleteAfterRun: true`**. Best for orchestration follow-up and delayed execution. |
| **`every`** | Fixed interval from activation (`everyMs`) | Good for polling/monitoring; avoid tight loops unless the operator asked. |
| **`cron`** | Clock-anchored (5-field expr, optional `tz`) | Prefer structured `{ kind, expr, tz }` over shorthands when editing via API. |

**Test before activate:** **`run_cron_job`** (works even when deactivated), then **`list_cron_job_runs`** to inspect outcome.

## Conversation threading

| Scenario | `conversationId` |
|----------|------------------|
| Standalone scheduled task | Omit or let the node assign a dedicated **`[Cron]`** thread |
| Orchestration synthesis / follow-up | **Same** `[Orchestrator]` conversation — use **`agent_schedule_orchestration_cron`** or set `conversationId` to the orchestrator id when using **`add_cron_job`** |
| Orchestration follow-up via management API | Set **`orchestrationTopLevelMessageId`** so the node resolves the orchestrator thread — **never** leave both empty for orchestration follow-up |

Wrong threading creates a confusing extra `[Cron]` thread disconnected from orchestration context.

## Webhooks

- Activate from catalog (**`add_webhook_from_catalog`**) or custom **`add_webhook`**; set **`WEBHOOK_SECRET_*`** (and **`TELEGRAM_BOT_TOKEN`** for Telegram replies) in Variables **before** enabling.
- Inbound URL is loopback by default — external providers need a relay/tunnel (see node **`AGENT_HOOKS.md`**).
- Webhook **`prompt`** must be self-contained and non-interactive, same as cron **`message`**.

## MultiSign in scheduled turns

When a scheduled turn should propose on-chain actions:

- End with **exactly one `requestId`** when multiple txs belong in one operator round — **`create_compose_multi_sign_request`** or **`create_joined_multi_sign_request`** (see skill **`execution-policy`**).
- Unless the embedded message already includes operator-confirmed broadcast parameters, **stop at proposal** (create + list status) — do not Get Sig/Execute without explicit embedded authorization.

## Trade analysis cron (optional)

Template: **`agent_llm_config.defaults/cron/trade_analysis_cron.example.md`** (mpc-config seed catalog).

- Each **`analyze_*`** step upserts a typed setup into **`conversation.tradeIdeas[]`** on the **`[Cron]`** thread (e.g. **`analyze_trend_structure`** → `trend_structure`, **`analyze_key_levels`** → `key_levels`, **`analyze_key_level_fibonacci`** → `key_level_fibonacci` — separate ideas from the same OHLCV session).
- Optional fenced **`tradeConsensus`** YAML in the job **`message`** gates multi-analysis agreement (node injects a matrix hint). Valid `requiredSources` include `trend_structure`, `key_levels`, `key_level_fibonacci`, `chart_pattern`, `momentum`, …
- Optional fenced **`tradeBuild`** YAML — freeze **`protocolId`** (`hyperliquid` | `gmx` | `uniswap`), chain, sizing, offsets, and optional multisign expiry (**`expiryMinutesFromNow`** relative at build time, or absolute **`expiryDate`** Unix seconds); see template for per-protocol fields.
- **`submitTradeFromConsensus: true`** enables the cron-only **`submit_trade_from_consensus`** step — the agent must pass **`tradeIdeaId`** per prose selection rules in the message (YAML does not auto-pick).
- **Plan / orchestrator** threads use **`build_trade_from_*`** only — never **`submit_trade_from_consensus`**.
- **Uniswap V4** has no protocol OHLCV — cron message must name a separate candle source for analysis; limit-style ideas (trend, levels, fib extension) usually build on **hyperliquid** or **gmx** instead (see **`trade-defaults`**).

## Anti-patterns

- **`every` + short interval** “auto-sign-and-broadcast” loops without embedded confirmation — forbidden for orchestration follow-up; risky elsewhere.
- Copying interactive chat transcripts into cron **`message`** without extracting concrete params.
- Enabling **`initialLoad: true`** on MCP servers in cron that need secrets before Variables are set.

## Operator checklist (edit on your node)

- [ ] Cron/webhook message includes all params needed for a full unattended turn
- [ ] **`run_cron_job`** succeeded once in staging
- [ ] Orchestration follow-ups use orchestrator **`conversationId`**, not a new empty thread
- [ ] Webhook secrets configured in Variables before **activate**
