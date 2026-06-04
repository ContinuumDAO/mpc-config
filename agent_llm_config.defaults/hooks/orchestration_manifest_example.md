# Orchestration manifest example (KeyGen top-level)

Post a top-level KeyGen message whose **body** includes `@agent` and a fenced block like below. The node spawns one sub-agent per `tasks[]` entry (listed `mcpServers` only). Sub-agents post **`mpc-task-result v1`** replies on this thread for the group.

````markdown
@agent Please run the orchestration below.

```mpc-orchestrate v1
version: 1
tasks:
  - id: legal-review
    prompt: "Review clause 4 in the attached context and list risks."
    mcpServers: ["continuum"]
  - id: data-gathering
    prompt: "Gather the metrics described in the operator's plan and summarize sources."
    mcpServers: ["continuum"]
prompts:
  subAgentReply: ""
  externalReply: "A peer replied on the orchestration thread. Review and respond if needed."
  orchestratorOnReply: |
    All tasks are terminal. Synthesize findings from mpc-task-result replies on the KeyGen thread.
    Post synthesis as a REPLY to the top-level orchestration message for the group.
    Present facts and trade-offs; do not assume the operator's preferences or domain.
synthesis:
  at: "2026-06-10T18:00:00Z"
  rescheduleOnReply: true
  cronPrompt: |
    Review synthesis and task results on the KeyGen thread (orchestration state below).
    If proposing multiple on-chain legs for one Accept/Reject round, end with exactly
    one requestId: create_compose_multi_sign_request (all actions[]) or
    create_joined_multi_sign_request (merge two helper payloads; chain for 3+).
    Do not call multiple create_* / ctm_* tools that each return requestId for the same round.
    Quote/simulate first; no broadcast without operator confirmation unless prefs are embedded.
  onPartial: true
```
````

Sub-agents must reply to the top-level message with (**no** `@agent` on the reply):

```mpc-task-result v1
taskId: legal-review
status: complete
summary: |
  Human-readable summary for the KeyGen group.
```

Use MCP **`send_key_gen_message`** with `replyTo` set to the top-level message id. Do **not** use `mpc-orchestrate-task` or post dispatch/progress-only messages.

**Node behavior (summary):**

- Sub-agents run on this node; results belong on KeyGen for the group.
- Same-node replies without `mpc-task-result` do not re-trigger orchestrator hooks.
- When all tasks are terminal (`onPartial` controls failed vs complete-only), the node runs **`orchestratorOnReply`** once in the `[Orchestrator]` conversation (MCP `continuum`, including `send_key_gen_message` for synthesis).
- If **`synthesis.at`** and **`synthesis.cronPrompt`** are both set, a one-shot cron runs that follow-up prompt in `[Orchestrator]` (uses MCP servers with **`initialLoad: true`** — include DeFi MCP ids there if the cron must call `ctm_*` multisign tools).

**Plan mode:** draft manifests in agent chat with `conversationPurpose: "plan"` and the `orchestration_planning` skill. Use **`POST /agent/plan/execute`** (or UI **Execute in KeyGen**) to post to KeyGen.
