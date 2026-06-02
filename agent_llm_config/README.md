# Agent LLM config (runtime)

Runtime directory beside `configs.yaml`, bind-mounted into the mpc-auth container as **`/app/agent_llm_config`**. **Gitignored** on deployed nodes — safe to edit via UI, API, or mpc-auth without blocking **`git pull`**.

Bundled defaults ship in **`agent_llm_config.defaults/`** (tracked in this repo). **`process_config.sh`** copies each default file here **once if missing**; it does not overwrite live data.

If you run **`process_config.sh` with `sudo`**, the script creates **`agent_llm_config/`** and **`user_folder/`** as that user’s uid **and primary group** (`chown -R user:group`) so Docker and editors are not blocked by root-owned paths.

**Docker writes bind mounts as root** (default container user). mpc-auth updates **`agent_llm_config/`** through the mount; files may be **`root:root`** on the host. Runtime **`agent_llm_config/`** is **gitignored** after **`fe325e9`**, so **`git pull`** is not blocked; fix ownership for editing with **`sudo ./scripts/fix-bind-mount-ownership.sh`** (or **`sudo chown -R $(whoami):$(id -gn) agent_llm_config/ user_folder/`**). **`process_config.sh`** also **`chown`s `.env`** to your user when run via **`sudo`** so **`docker compose`** can read it.

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

# Stop app so Docker does not recreate root-owned files mid-migration
docker compose stop app

# Fix ownership (or: sudo ./scripts/fix-bind-mount-ownership.sh after you have that script)
sudo chown -R "$(whoami):$(id -gn)" agent_llm_config/ user_folder/ 2>/dev/null || true
mkdir -p ~/agent_llm_config-backup
cp -a agent_llm_config ~/agent_llm_config-backup/runtime

# Move old tracked paths aside (still on pre-fe325e9 checkout)
SID=~/agent_llm_config-pull-stash
mkdir -p "$SID"
mv -f agent_llm_config/MCP_servers.json "$SID/" 2>/dev/null || sudo mv agent_llm_config/MCP_servers.json "$SID/"
mv -f agent_llm_config/Skills/skills.json "$SID/" 2>/dev/null || sudo mv agent_llm_config/Skills/skills.json "$SID/"
mv -f agent_llm_config/MCP_default_servers.json "$SID/" 2>/dev/null || true
mv -f agent_llm_config/cron/jobs.json "$SID/" 2>/dev/null || true
mv -f agent_llm_config/hooks "$SID/hooks" 2>/dev/null || true

git pull

cp -a ~/agent_llm_config-backup/runtime/. agent_llm_config/
sudo chown -R "$(whoami):$(id -gn)" agent_llm_config/ user_folder/
sudo ./process_config.sh --enable-loopback-http --install-mpc-auth-systemd
docker compose up -d --no-deps --force-recreate app
```

After this, **`agent_llm_config/`** is gitignored and future **`git pull`** calls are clean.
