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
  at: ""
  rescheduleOnReply: false
  cronPrompt: "Synthesize task results from the orchestration state and KeyGen thread; note missing or failed tasks."
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

**Plan mode:** draft manifests in agent chat with `conversationPurpose: "plan"` and the `orchestration_planning` skill. Use **`POST /agent/plan/execute`** (or UI **Execute in KeyGen**) to post to KeyGen.
