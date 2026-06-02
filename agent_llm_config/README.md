# Agent LLM config (templates)

Tracked files in this directory are copied into the node’s runtime `agent_llm_config/` folder beside `configs.yaml` when you run **`process_config.sh`** (or **`scripts/provision-node.sh`**). Runtime secrets and operator edits stay gitignored.

If you run **`process_config.sh` with `sudo`**, the script creates **`agent_llm_config/`** and **`user_folder/`** as that user’s uid **and primary group** (`chown -R user:group`) so **`git pull`** and local edits are not blocked by root-owned paths.

| File | On the node | Purpose |
|------|-------------|---------|
| **`MCP_default_servers.json`** | Same name | Built-in MCP servers (not removable via API). Ships **continuum** only. |
| **`MCP_servers.json`** | Same name | Bundled optional MCP catalog (removable/editable via UI and `POST /addMcpServer`). Seeded once if missing. |
| **`Skills/`** | Same path | Agent skills: **`skills.json`** manifest plus **`.md`** / **`.txt`** bodies. Seeded once per file if missing (none bundled yet). |
| **`cron/jobs.json`** | Same path | Agent cron job manifest (schedules + instructions). When **`EnableAgentCron`** is true (default), seeded once if missing with bundled default **`auto-sign-and-broadcast`** job (every 5 minutes). When cron is disabled, seeds empty **`{"jobs":[]}`**. Runtime fields (**`id`**, **`conversationId`**, timestamps, **`nextRunAt`**) are assigned by mpc-auth on first load. Run history is written at runtime to **`cron/runs/{jobId}.jsonl`** (gitignored on deployed nodes). |
| **`hooks/`** | Same path | KeyGen message hooks + inbound webhooks: **`message_hook.json`**, four **`MESSAGE_HOOK_*.md`** prompts, **`webhooks.json`** templates, **`ORCHESTRATION_MANIFEST_EXAMPLE.md`**. mpc-auth assigns webhook **`id`**, **`conversationId`**, and **`WEBHOOK_SECRET_*`** values in Variables on first load. Run logs: **`hooks/runs/{webhookId}.jsonl`**. |
| **`Skills/ORCHESTRATION_PLANNING.md`** | **`Skills/`** | Plan-mode skill for drafting **`mpc-orchestrate v1`** manifests (loaded when **`conversationPurpose`** is **`plan`**). |

**Cron jobs:** each job gets a fixed **`conversationId`**; scheduled runs append to that thread. Manage via **`GET/POST /listCronJobs`**, **`/addCronJob`**, **`/activateCronJob`**, **`/deactivateCronJob`**, etc. (see **`docs/references/API_IMPLEMENTATION.md`**). Disable automatic scheduling with **`EnableAgentCron: false`** in **`configs.yaml`** (env **`MPC_AUTH_ENABLE_AGENT_CRON=0`**).

**Agent hooks:** KeyGen **`@agent`** automation, inbound webhooks, Plan mode, and orchestration — see **`docs/AGENT_HOOKS.md`**.

**API keys:** use **`apiKeyEnvVar`** (and optional **`apiKeyHeader`**) in these JSON files, then set values with **AI Agent → Variables** (`POST /addEnvironmentVariable`). Do not commit secrets in `agent-llm-config.json` (created at runtime).

**Initial load:** set `"initialLoad": true` on a server to connect it at agent chat startup (after env vars are configured for STDIO/API-key servers).
