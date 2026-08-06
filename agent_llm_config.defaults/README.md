# Agent LLM config (bundled defaults)

Tracked template files copied into the node’s runtime **`agent_llm_config/`** folder beside `configs.yaml` when you run **`process_config.sh`** (or **`scripts/provision-node.sh`**). Each file is installed **once if missing** — existing runtime copies are never overwritten.

**Docker:** mpc-auth reads this directory at **`/app/agent_llm_config.defaults`** (bind-mounted from **`./agent_llm_config.defaults`** in docker-compose). A host **`git pull`** updates the catalog only when that mount is present — not from files baked into the mpc-auth image alone.

Runtime secrets, mpc-auth–assigned ids, and operator edits live under **`agent_llm_config/`**, which is **gitignored** on deployed nodes so **`git pull`** is not blocked.

| File | Runtime path | Purpose |
|------|--------------|---------|
| **`MCP_default_servers.json`** | Same name (legacy seed) | Default **active** servers seeded on first DB migration: **continuum** (`initialLoad: true`), **coinmarketcap-public** / **coinbase-public** (`initialLoad: false`). |
| **`MCP_servers.json`** | Not copied to active storage | **Repository catalog** of optional MCP servers. Use **Add from repository** in the UI or `POST /addMcpServerFromCatalog` to activate on this node. See **MCP catalog secrets** below. |
| **`trade-desk.yaml`** | Same name | Trade prefill desk defaults (offsets, sizing, LLM fallback). Host-parsed YAML; edit via UI **Host YAML configs** or reset-from-defaults. |
| **`orchestration-plan.yaml`** | Same name | Plan modes, skeletons, task-class matchers, budgets, verify/soft-accept, contracts. Host-parsed YAML — product policy changes without rebuilding mpc-auth after the loader ships. |
| **`agent-intent-rules.yaml`** | Same name | Free-text intent → Continuum pack boost + optional system hint (never short-circuits the LLM). Host-parsed YAML; seeds no-degrade policy affinity pins. |
| **`Skills/`** | Same path | Agent skills: **`skills.json`** manifest plus **`.md`** / **`.txt`** bodies. |

### Host YAML configs (`trade-desk.yaml`, `orchestration-plan.yaml`, `agent-intent-rules.yaml`)

These are **not** agent Skills. mpc-auth loads them at plan/trade/turn time (mtime-aware cache). Ops model:

1. **One-time:** upgrade mpc-auth so the node understands the YAML schema + management APIs.
2. **Ongoing:** edit the file under **`agent_llm_config.defaults/`**, `git pull` on the node, then **reset-from-defaults** in the UI (or `POST /resetOrchestrationPlanFromDefaults` / `/resetTradeDeskFromDefaults` / `/resetAgentIntentRulesFromDefaults`) to overwrite the runtime copy. Or edit runtime YAML via upsert APIs / UI editor.

If YAML is missing or invalid, the node falls back to an embedded last-known-good copy and logs a warning.
| **`cron/jobs.json`** | Not copied to runtime | **Repository catalog** of cron job templates. Use **Available from repository** in the UI or `POST /addCronJobFromCatalog`. Active jobs live in **`agent_llm_config/cron/jobs.json`**. |
| **`hooks/message_hook.json`**, **`hooks/message_hook_*.md`** | Same path | KeyGen `@agent` message hooks (copied once if missing). |
| **`hooks/webhooks.json`** | Not copied to runtime | **Repository catalog** of inbound webhook templates. Use **Available from repository** in the UI or `POST /addWebhookFromCatalog`. Active jobs live in MongoDB **`LocalAgentWebhooks`**. |
| **`hooks/runs/`** | Same path | Append-only inbound webhook run logs (`{webhookId}.jsonl`). |

See **`runtime-README.md`** (copied to **`agent_llm_config/README.md`** on the node when missing) and **`docs/references/API_IMPLEMENTATION.md`** for API details.

### Cron catalog (`cron/jobs.json`)

See **[`CATALOG.md`](CATALOG.md)** — add templates only in **`cron/jobs.json`** here (not in runtime `agent_llm_config/cron/jobs.json`).

- Templates define **name**, **schedule**, **message**, and default **enabled** only.
- **`process_config.sh`** seeds an empty runtime **`{"jobs":[]}`** manifest once; operators activate catalog rows via **Add from repository** or **`POST /addCronJobFromCatalog`**.

### Webhook catalog (`hooks/webhooks.json`)

See **[`CATALOG.md`](CATALOG.md)** — add templates only in **`hooks/webhooks.json`** here (not in continuum-node-sdk or runtime `agent_llm_config/`).

- Templates define **name**, **type**, **prompt**, and default **enabled** only — no inline secrets.
- On add (catalog or custom), mpc-auth creates **`WEBHOOK_SECRET_<NAME>`** in Variables with a placeholder value; operators replace with provider signing secrets before activating.
- The **AI agent must not see Variable values** — only names and `*Configured` flags in listings.

### MCP catalog (`MCP_servers.json`)

See **[`CATALOG.md`](CATALOG.md)** — add servers only in **`MCP_servers.json`** here (not in continuum-node-sdk or runtime `agent_llm_config/`).

Authoritative optional MCP catalog for deployed nodes. mpc-auth reads this file from the bind-mounted **`agent_llm_config.defaults/`** tree:

- **`GET /listMcpServers`** → **`availableCatalog`**: entries not yet active on this node (`source`: `catalog`).
- **`POST /addMcpServerFromCatalog`** → copies the matching catalog row into **`LocalAgentMcpServers`** (active use).

When adding another catalog entry:

- Store **names** only in JSON: `apiKeyEnvVar`, `apiKeyHeader`, `envVars`. Never `apiKey` or other inline secrets.
- Optional **`setupUrl`**: HTTPS setup/documentation link returned in list responses and stored on activate; shown as the **Name** link in the node app (not sent to the MCP child process).
- Operators set values in **AI Agent → Variables** (`POST /addEnvironmentVariable`). mpc-auth injects them into HTTP headers or the stdio child environment at connect time.
- The **AI agent must not see Variable values** — only names in `GET /listMcpServers` / MCP tool listings (`envConfigured`, masked `apiKeyPresent`). Do not surface `GET /getEnvironmentVariable` values to the agent.
