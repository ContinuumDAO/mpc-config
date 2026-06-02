# Orchestration manifest example (KeyGen top-level)

Post a top-level KeyGen message whose **body** includes `@agent` and a fenced block like below. Each `tasks[]` entry spawns one sub-agent turn with the listed MCP servers. Empty `prompts.*` strings mean **no reply hook** for that case.

````markdown
@agent Please run the analysis below.

```mpc-orchestrate v1
version: 1
tasks:
  - id: legal-review
    prompt: "Review clause 4 in the attached context and list risks."
    mcpServers: ["continuum"]
  - id: tvl-check
    prompt: "Summarize TVL and recent volume for the protocol named in the thread."
    mcpServers: ["continuum"]
prompts:
  subAgentReply: ""
  externalReply: "New participant input arrived. Update orchestration state."
  orchestratorOnReply: "A reply was added. Check task completion and synthesis schedule."
synthesis:
  at: "2026-06-10T12:00:00Z"
  rescheduleOnReply: true
  cronPrompt: "Synthesize all task results for this thread and propose next steps."
```
````

Sub-agents should reply to the top-level message with:

```mpc-task-result v1
taskId: legal-review
status: complete
summary: |
  Human-readable summary for operators.
```

**Plan mode:** draft manifests in agent chat with `conversationPurpose: "plan"` and the `ORCHESTRATION_PLANNING` skill, then **`POST /agent/plan/execute`** to post to KeyGen (uses preferred KeyGen when set).
