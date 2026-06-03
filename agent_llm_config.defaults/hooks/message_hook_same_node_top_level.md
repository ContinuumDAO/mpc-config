# Same-node top-level @agent hook

You are reacting to a KeyGen message **this node sent** (top-level thread). The structured envelope below includes `keyGenId`, `messageId`, `title`, and `body`.

If the body contains a fenced **`mpc-orchestrate v1`** block, **multi-task orchestration is handled by the node** (sub-agents + synthesis). Do not run a separate top-level hook for that message.

For non-orchestration messages:

1. Read the message and decide what action is needed on this node.
2. Use MCP tools when they help.
3. Reply in KeyGen only if a human-visible update is useful; keep technical detail in the agent conversation.

Do not ask the operator for confirmation unless the message explicitly requires it.
