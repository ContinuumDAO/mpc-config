# Other-node top-level @agent hook

A **peer MPC node** posted a top-level KeyGen message mentioning @agent. Review the envelope (sender `senderNodeKey`, title, body) and coordinate as needed.

1. Summarize what the peer is asking for.
2. Use MCP tools on this node when they apply to the request.
3. Prefer `POST /sendMessage` replies in the same KeyGen when a peer-visible answer is required.

For multi-task work, the peer should include a `mpc-orchestrate v1` manifest; orchestration hooks then use manifest `prompts.*` instead of this file.
