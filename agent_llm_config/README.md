# Agent LLM config (templates)

Tracked files in this directory are copied into the node’s runtime `agent_llm_config/` folder beside `configs.yaml` when you run **`process_config.sh`** (or **`scripts/provision-node.sh`**). Runtime secrets and operator edits stay gitignored.

If you run **`process_config.sh` with `sudo`**, the script creates **`agent_llm_config/`** and **`user_folder/`** as that user’s uid **and primary group** (`chown -R user:group`) so **`git pull`** and local edits are not blocked by root-owned paths.

| File | On the node | Purpose |
|------|-------------|---------|
| **`MCP_default_servers.json`** | Same name | Built-in MCP servers (not removable via API). Ships **continuum** only. |
| **`MCP_servers.json`** | Same name | Bundled optional MCP catalog (removable/editable via UI and `POST /addMcpServer`). Seeded once if missing. |
| **`Skills/`** | Same path | Agent skills: **`skills.json`** manifest plus **`.md`** / **`.txt`** bodies. Seeded once per file if missing (none bundled yet). |

**API keys:** use **`apiKeyEnvVar`** (and optional **`apiKeyHeader`**) in these JSON files, then set values with **AI Agent → Variables** (`POST /addEnvironmentVariable`). Do not commit secrets in `agent-llm-config.json` (created at runtime).

**Initial load:** set `"initialLoad": true` on a server to connect it at agent chat startup (after env vars are configured for STDIO/API-key servers).
