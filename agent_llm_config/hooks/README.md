# Agent hooks (templates)

Copied into the node's `agent_llm_config/hooks/` by **`process_config.sh`** (once per file if missing). Runtime secrets and generated ids are assigned by mpc-auth on first load.

| File | Purpose |
|------|---------|
| **`message_hook.json`** | Enable KeyGen `@agent` hooks (`triggerToken`, `markReadAfterRun`, optional `conversationId`). |
| **`MESSAGE_HOOK_*.md`** | Prompt templates for same/other node × top-level/reply (reply files often empty; orchestration uses manifest `prompts.*`). |
| **`webhooks.json`** | Inbound webhook templates (`generic`, `github`, `gmail`, `proton`, `stripe`, `slack`, `telegram`). mpc-auth assigns `id`, `conversationId`, and `WEBHOOK_SECRET_*` in Variables. |
| **`ORCHESTRATION_MANIFEST_EXAMPLE.md`** | Reference manifest for multi-task KeyGen orchestration. |

Inbound callback on the node: `http://127.0.0.1:18090/hooks/inbound/{webhookId}` (loopback only by default). Internet providers need a relay, tunnel, or reverse proxy with a CA-trusted cert — not Browser HTTPS `:8443` (self-signed). See **`docs/AGENT_HOOKS.md`**.

See **`docs/AGENT_HOOKS.md`** (user guide with setup examples), **`docs/references/API_IMPLEMENTATION.md`** (API reference), and **`docs/references/API_KEYGEN_MESSAGING.md`**.
