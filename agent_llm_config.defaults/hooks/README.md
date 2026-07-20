# Agent hooks (templates)

Copied from **`agent_llm_config.defaults/hooks/`** into the node's runtime **`agent_llm_config/hooks/`** by **`process_config.sh`** (once per file if missing, except **`webhooks.json`** — see below).

| File | Purpose |
|------|---------|
| **`message_hook.json`** | Enable KeyGen `@agent` hooks (`triggerToken`, `markReadAfterRun`, optional `conversationId`). |
| **`message_hook_*.md`** | Prompt templates for same/other node × top-level/reply (reply files often empty; orchestration uses manifest `prompts.*`). |
| **`webhooks.json`** | **Catalog only** (not copied to runtime; do not duplicate in continuum-node-sdk). Activate via Node UI or `POST /addWebhookFromCatalog`. See **[`../CATALOG.md`](../CATALOG.md)**. Active jobs live in MongoDB `LocalAgentWebhooks`. |
| **`TELEGRAM_WEBHOOK_NGROK.md`** | Operator guide: **`telegram_updates`** + free ngrok **Agent Endpoint** (Docker container network). **`GET /getTelegramWebhookNgrokGuide`**. Canonical copy also in **`docs/TELEGRAM_WEBHOOK_NGROK.md`**. |
| **`orchestration_manifest_example.md`** | Reference manifest for multi-task KeyGen orchestration. |

Inbound callback on the node: `http://127.0.0.1:18090/hooks/inbound/{webhookId}` (loopback only by default). Internet providers need a relay, tunnel, or reverse proxy with a CA-trusted cert — not Browser HTTPS `:8443` (self-signed). See **`docs/AGENT_HOOKS.md`**. Telegram + free ngrok: **`docs/TELEGRAM_WEBHOOK_NGROK.md`**.

See **`docs/AGENT_HOOKS.md`** (user guide with setup examples), **`docs/references/API_IMPLEMENTATION.md`** (API reference), and **`docs/references/API_KEYGEN_MESSAGING.md`**.
