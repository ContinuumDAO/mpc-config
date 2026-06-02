# Agent skills (templates)

Bundled skill files for the node agent. Copied from **`agent_llm_config.defaults/Skills/`** into runtime **`agent_llm_config/Skills/`** on first provision (see **`process_config.sh`**).

| File | Purpose |
|------|---------|
| **`skills.json`** | Manifest: `name`, `filename`, `initialLoad` per skill |
| **`<name>.md`** / **`<name>.txt`** | Skill body (markdown or plain text) |

Add new defaults here (manifest entry + file), commit, then re-run **`process_config.sh`** on nodes — only **missing** files are installed. Existing nodes keep their runtime **`skills.json`** until you add skills via the UI or API.

No bundled skills ship yet; operators add skills under **AI Agent → Skills**.
