# Agent LLM config (bundled defaults)

Tracked template files copied into the node’s runtime **`agent_llm_config/`** folder beside `configs.yaml` when you run **`process_config.sh`** (or **`scripts/provision-node.sh`**). Each file is installed **once if missing** — existing runtime copies are never overwritten.

Runtime secrets, mpc-auth–assigned ids, and operator edits live under **`agent_llm_config/`**, which is **gitignored** on deployed nodes so **`git pull`** is not blocked.

| File | Runtime path | Purpose |
|------|--------------|---------|
| **`MCP_default_servers.json`** | Same name | Built-in MCP servers (not removable via API). Ships **continuum** only. |
| **`MCP_servers.json`** | Same name | Bundled optional MCP catalog (removable/editable via UI and `POST /addMcpServer`). See **MCP catalog secrets** below. |
| **`Skills/`** | Same path | Agent skills: **`skills.json`** manifest plus **`.md`** / **`.txt`** bodies. |
| **`cron/jobs.json`** | Same path | Agent cron job manifest. When **`EnableAgentCron`** is true (default), seeds bundled **`auto-sign-and-broadcast`** (every 5 minutes). When cron is disabled, seeds empty **`{"jobs":[]}`**. |
| **`hooks/`** | Same path | KeyGen message hooks + inbound webhooks. mpc-auth assigns webhook **`id`**, **`conversationId`**, and **`WEBHOOK_SECRET_*`** values in Variables on first load. |

See **`runtime-README.md`** (copied to **`agent_llm_config/README.md`** on the node when missing) and **`docs/references/API_IMPLEMENTATION.md`** for API details.

### MCP catalog secrets (`MCP_servers.json`)

When adding another default MCP server entry (keep in sync with continuum-node-sdk `src/core/agent/mcp-servers-catalog.ts`):

- Store **names** only in JSON: `apiKeyEnvVar`, `apiKeyHeader`, `envVars`. Never `apiKey` or other inline secrets.
- Operators set values in **AI Agent → Variables** (`POST /addEnvironmentVariable`). mpc-auth injects them into HTTP headers or the stdio child environment at connect time.
- The **AI agent must not see Variable values** — only names in `GET /listMcpServers` / MCP tool listings (`envConfigured`, masked `apiKeyPresent`). Do not surface `GET /getEnvironmentVariable` values to the agent.
