# Agent LLM config (bundled defaults)

Tracked template files copied into the node’s runtime **`agent_llm_config/`** folder beside `configs.yaml` when you run **`process_config.sh`** (or **`scripts/provision-node.sh`**). Each file is installed **once if missing** — existing runtime copies are never overwritten.

Runtime secrets, mpc-auth–assigned ids, and operator edits live under **`agent_llm_config/`**, which is **gitignored** on deployed nodes so **`git pull`** is not blocked.

| File | Runtime path | Purpose |
|------|--------------|---------|
| **`MCP_default_servers.json`** | Same name (legacy seed) | Built-in **continuum** definition used only when seeding the node database on first run. |
| **`MCP_servers.json`** | Not copied to active storage | **Repository catalog** of optional MCP servers. Use **Add from repository** in the UI or `POST /addMcpServerFromCatalog` to activate on this node. See **MCP catalog secrets** below. |
| **`Skills/`** | Same path | Agent skills: **`skills.json`** manifest plus **`.md`** / **`.txt`** bodies. |
| **`cron/jobs.json`** | Same path | Agent cron job manifest. When **`EnableAgentCron`** is true (default), seeds bundled **`auto-sign-and-broadcast`** (every 5 minutes). When cron is disabled, seeds empty **`{"jobs":[]}`**. |
| **`hooks/message_hook.json`**, **`hooks/message_hook_*.md`** | Same path | KeyGen `@agent` message hooks (copied once if missing). |
| **`hooks/webhooks.json`** | Not copied to runtime | **Repository catalog** of inbound webhook templates. Use **Available from repository** in the UI or `POST /addWebhookFromCatalog`. Active jobs live in MongoDB **`LocalAgentWebhooks`**. |
| **`hooks/runs/`** | Same path | Append-only inbound webhook run logs (`{webhookId}.jsonl`). |

See **`runtime-README.md`** (copied to **`agent_llm_config/README.md`** on the node when missing) and **`docs/references/API_IMPLEMENTATION.md`** for API details.

### Webhook catalog secrets (`hooks/webhooks.json`)

When adding another bundled webhook template (keep in sync with continuum-node-sdk `src/core/agent/webhooks-catalog.ts`):

- Templates define **name**, **type**, **prompt**, and default **enabled** only — no inline secrets.
- On add (catalog or custom), mpc-auth creates **`WEBHOOK_SECRET_<NAME>`** in Variables with a placeholder value; operators replace with provider signing secrets before activating.
- The **AI agent must not see Variable values** — only names and `*Configured` flags in listings.

### MCP catalog secrets (`MCP_servers.json`)

When adding another default MCP server entry (keep in sync with continuum-node-sdk `src/core/agent/mcp-servers-catalog.ts`):

- Store **names** only in JSON: `apiKeyEnvVar`, `apiKeyHeader`, `envVars`. Never `apiKey` or other inline secrets.
- Operators set values in **AI Agent → Variables** (`POST /addEnvironmentVariable`). mpc-auth injects them into HTTP headers or the stdio child environment at connect time.
- The **AI agent must not see Variable values** — only names in `GET /listMcpServers` / MCP tool listings (`envConfigured`, masked `apiKeyPresent`). Do not surface `GET /getEnvironmentVariable` values to the agent.
