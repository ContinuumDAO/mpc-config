# Agent skills (templates)

Bundled skill files for the node agent. Copied into the runtime **`agent_llm_config/Skills/`** directory on first provision (see **`process_config.sh`**).

| File | Purpose |
|------|---------|
| **`skills.json`** | Manifest: `name`, `filename`, `initialLoad` per skill |
| **`<name>.md`** / **`<name>.txt`** | Skill body (markdown or plain text) |

Add new defaults here (manifest entry + file), then re-run **`process_config.sh`** on a fresh node or copy files manually. Existing nodes keep their **`skills.json`** until you add skills via the UI or API.

No bundled skills ship yet; operators add skills under **AI Agent → Skills**.
