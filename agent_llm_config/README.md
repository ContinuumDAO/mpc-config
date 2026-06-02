# Agent LLM config (runtime)

Runtime directory beside `configs.yaml`, bind-mounted into the mpc-auth container as **`/app/agent_llm_config`**. **Gitignored** on deployed nodes — safe to edit via UI, API, or mpc-auth without blocking **`git pull`**.

Bundled defaults ship in **`agent_llm_config.defaults/`** (tracked in this repo). **`process_config.sh`** copies each default file here **once if missing**; it does not overwrite live data.

If you run **`process_config.sh` with `sudo`**, the script creates **`agent_llm_config/`** and **`user_folder/`** as that user’s uid **and primary group** (`chown -R user:group`) so Docker and editors are not blocked by root-owned paths.

| File / path | Purpose |
|-------------|---------|
| **`agent-llm-config.json`** | LLM provider settings (created at runtime; may contain API key references). |
| **`MCP_default_servers.json`** | Built-in MCP servers (seeded from defaults; not removable via API). |
| **`MCP_servers.json`** | Optional MCP catalog + user edits (**POST /addMcpServer**, etc.). |
| **`Skills/`** | Agent skills manifest (**`skills.json`**) and **`.md`** / **`.txt`** bodies. |
| **`cron/jobs.json`** | Cron job manifest; mpc-auth assigns **`id`**, **`conversationId`**, **`nextRunAt`**. Run logs: **`cron/runs/{jobId}.jsonl`**. |
| **`hooks/`** | KeyGen hooks + inbound webhooks; run logs **`hooks/runs/{webhookId}.jsonl`**. |

**Cron jobs:** manage via **`GET/POST /listCronJobs`**, **`/addCronJob`**, etc. (see **`docs/references/API_IMPLEMENTATION.md`**). Disable automatic scheduling with **`EnableAgentCron: false`** in **`configs.yaml`**.

**Agent hooks:** see **`docs/AGENT_HOOKS.md`**.

**API keys:** use **`apiKeyEnvVar`** in JSON files, then set values with **AI Agent → Variables** (`POST /addEnvironmentVariable`).

**After `git pull`:** run **`./process_config.sh`** to pick up any **new** bundled files (e.g. a new skill **`.md`**) that are not yet present here.

### One-time upgrade (nodes that tracked templates under `agent_llm_config/`)

If **`git pull`** fails on **`agent_llm_config/Skills/skills.json`** or **`cron/jobs.json`**, or removes runtime files when templates move to **`agent_llm_config.defaults/`**, back up and restore:

```bash
cd ~/mpc-config
mkdir -p ~/agent_llm_config-backup
cp -a agent_llm_config/Skills agent_llm_config/cron agent_llm_config/hooks \
  agent_llm_config/MCP_*.json ~/agent_llm_config-backup/ 2>/dev/null || true
sudo chown -R "$(whoami):$(id -gn)" agent_llm_config/

# If pull still complains about local changes to old tracked paths:
git checkout HEAD -- agent_llm_config/Skills/skills.json 2>/dev/null || true
git pull

# Restore live runtime data (process_config.sh will not overwrite existing files)
cp -an ~/agent_llm_config-backup/Skills/. agent_llm_config/Skills/ 2>/dev/null || true
cp -an ~/agent_llm_config-backup/cron/. agent_llm_config/cron/ 2>/dev/null || true
cp -an ~/agent_llm_config-backup/hooks/. agent_llm_config/hooks/ 2>/dev/null || true
cp -an ~/agent_llm_config-backup/MCP_*.json agent_llm_config/ 2>/dev/null || true
./process_config.sh
```

After this, **`agent_llm_config/`** is gitignored and future **`git pull`** calls are clean.
