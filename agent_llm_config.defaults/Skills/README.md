# Agent skills (templates)

Bundled skill files for the node agent. Copied from **`agent_llm_config.defaults/Skills/`** into runtime **`agent_llm_config/Skills/`** on first provision (see **`process_config.sh`**).

| File | Purpose |
|------|---------|
| **`skills.json`** | Manifest: `name`, `filename`, `initialLoad` per skill |
| **`orchestration_planning.md`** | Plan-mode orchestration manifest drafting (`conversationPurpose: "plan"`) |
| **`<name>.md`** / **`<name>.txt`** | Additional skill bodies (markdown or plain text) |

Skill **`name`** values must be lowercase (`a-z`, digits, hyphen, underscore) — they match the node API and manifest lookup.

Add new defaults here (manifest entry + file), commit, then re-run **`process_config.sh`** on nodes — only **missing** files are installed. Existing nodes keep their runtime **`skills.json`** until you add skills via the UI or API.
