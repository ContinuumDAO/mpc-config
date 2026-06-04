# Agent hooks (templates)

Copied from **`agent_llm_config.defaults/hooks/`** into the node's runtime **`agent_llm_config/hooks/`** by **`process_config.sh`** (once per file if missing, except **`webhooks.json`** — see below).

| File | Purpose |
|------|---------|
| **`message_hook.json`** | Enable KeyGen `@agent` hooks (`triggerToken`, `markReadAfterRun`, optional `conversationId`). |
| **`message_hook_*.md`** | Prompt templates for same/other node × top-level/reply (reply files often empty; orchestration uses manifest `prompts.*`). |
| **`webhooks.json`** | **Catalog only** (not copied to runtime). Bundled inbound webhook templates; activate via Node UI or `POST /addWebhookFromCatalog`. Active jobs live in MongoDB `LocalAgentWebhooks`. |
| **`orchestration_manifest_example.md`** | Reference manifest for multi-task KeyGen orchestration. |

Inbound callback on the node: `http://127.0.0.1:18090/hooks/inbound/{webhookId}` (loopback only by default). Internet providers need a relay, tunnel, or reverse proxy with a CA-trusted cert — not Browser HTTPS `:8443` (self-signed). See **`docs/AGENT_HOOKS.md`**.

See **`docs/AGENT_HOOKS.md`** (user guide with setup examples), **`docs/references/API_IMPLEMENTATION.md`** (API reference), and **`docs/references/API_KEYGEN_MESSAGING.md`**.
