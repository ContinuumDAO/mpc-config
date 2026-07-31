# Repository catalogs (MCP servers, webhooks, and cron jobs)

**Authoritative templates live only in this directory** (`agent_llm_config.defaults/`), bind-mounted on the node as `/app/agent_llm_config.defaults`. After `git pull` on mpc-config, operators see new entries via the API without redeploying mpc-auth.

Do **not** duplicate catalogs in continuum-node-sdk, runtime `agent_llm_config/`, or any other JSON/TypeScript file.

## Add a new MCP server

1. Edit **`MCP_servers.json`** — add one object to the `"servers"` array (`id`, `displayName`, `transport`, …). Optional **`setupUrl`** for setup docs (shown in the node UI Name column).
2. Use **names only** for secrets: `apiKeyEnvVar`, `apiKeyHeader`, `envVars` — never inline `apiKey`.
3. Operators activate on a node: **Add from repository** in the UI or **`POST /addMcpServerFromCatalog`** (`GET /listMcpServers` → `availableCatalog` until active).
4. Document in **`docs/references/API_IMPLEMENTATION.md`** (STDIO/HTTP catalog section) when the server is non-trivial.

Builtin default **active** servers in **`MCP_default_servers.json`** (DB seed on first migration only):

| id | initialLoad | Notes |
|----|-------------|--------|
| **continuum** | `true` | Node MCP; always connected at chat startup |
| **coinmarketcap-public** | `false` | Also in **`MCP_servers.json`**; load per chat via **`agent_load_mcp_server`** only when the operator chooses CoinMarketCap (not auto-loaded for charts) |
| **coinbase-public** | `false` | Also in **`MCP_servers.json`**; load per chat via **`agent_load_mcp_server`** only when the operator chooses Coinbase (not auto-loaded for charts). Optional CDP Variables for authenticated routes — public tools work without secrets |

Other optional servers belong in **`MCP_servers.json`** only — operators activate via catalog unless also added to **`MCP_default_servers.json`** for new-node seed.

## Add a new webhook template

1. Edit **`hooks/webhooks.json`** — add one object to `"webhooks"` (`name`, `type`, `prompt`, default `enabled`: false).
2. Operators activate: **Available from repository** or **`POST /addWebhookFromCatalog`** (`GET /listWebhooks` → `availableCatalog`).
3. See **`docs/AGENT_HOOKS.md`** for provider setup notes in the template `prompt` when helpful.

Active webhooks and MCP servers live in MongoDB on the node after activation, not in copied JSON under `agent_llm_config/`. Active cron jobs live in runtime **`agent_llm_config/cron/jobs.json`** after activation.

## Add a new cron job template

1. Edit **`cron/jobs.json`** — add one object to the `"jobs"` array (`name`, `schedule`, `message`, default `enabled`: false).
2. Operators activate: **Available from repository** in the UI or **`POST /addCronJobFromCatalog`** (`GET /listCronJobs` → `availableCatalog`).
3. Document non-obvious schedule or orchestration behavior in **`docs/references/API_IMPLEMENTATION.md`** (Agent cron jobs section) when helpful.
