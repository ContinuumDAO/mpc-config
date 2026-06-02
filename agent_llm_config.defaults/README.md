# Agent LLM config (bundled defaults)

Tracked template files copied into the node’s runtime **`agent_llm_config/`** folder beside `configs.yaml` when you run **`process_config.sh`** (or **`scripts/provision-node.sh`**). Each file is installed **once if missing** — existing runtime copies are never overwritten.

Runtime secrets, mpc-auth–assigned ids, and operator edits live under **`agent_llm_config/`**, which is **gitignored** on deployed nodes so **`git pull`** is not blocked.

| File | Runtime path | Purpose |
|------|--------------|---------|
| **`MCP_default_servers.json`** | Same name | Built-in MCP servers (not removable via API). Ships **continuum** only. |
| **`MCP_servers.json`** | Same name | Bundled optional MCP catalog (removable/editable via UI and `POST /addMcpServer`). |
| **`Skills/`** | Same path | Agent skills: **`skills.json`** manifest plus **`.md`** / **`.txt`** bodies. |
| **`cron/jobs.json`** | Same path | Agent cron job manifest. When **`EnableAgentCron`** is true (default), seeds bundled **`auto-sign-and-broadcast`** (every 5 minutes). When cron is disabled, seeds empty **`{"jobs":[]}`**. |
| **`hooks/`** | Same path | KeyGen message hooks + inbound webhooks. mpc-auth assigns webhook **`id`**, **`conversationId`**, and **`WEBHOOK_SECRET_*`** values in Variables on first load. |

See **`runtime-README.md`** (copied to **`agent_llm_config/README.md`** on the node when missing) and **`docs/references/API_IMPLEMENTATION.md`** for API details.
