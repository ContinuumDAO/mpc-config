# Agent skills (templates)

Bundled skill files for the node agent. Copied from **`agent_llm_config.defaults/Skills/`** into runtime **`agent_llm_config/Skills/`** on first provision (see **`process_config.sh`**).

| File | Purpose |
|------|---------|
| **`skills.json`** | Manifest: `name`, `filename`, `initialLoad` per skill |
| **`orchestration_planning.md`** | Plan-mode orchestration manifesto drafting (`toolGroups` / slim sub-loop budgets; `conversationPurpose: "plan"`) |
| **`continuum-mcp-deferred-tools.md`** | Tool bundle discovery; **`load_defi_protocol`** vs **`agent_load_mcp_server`** |
| **`chart-ohlcv-sources.md`** | OHLCV provider choice: DeFi protocols vs catalog MCP servers (`initialLoad: false`; host auto-loads on chart intents) |
| **`chart-periods.md`** | Default lookback by bar interval, newest-first trim, and source-specific fetch notes for **`prepare_chart`** (host auto-loads on chart intents) |
| **`chart-defaults.md`** | Default EMA(50) / RSI(14) / volume behavior, **`technical-indicators`** MCP load, operator override examples (host auto-loads on chart intents) |
| **`chart-analysis-menu.md`** | Analysis menu / picker guidance (host auto-loads on chart intents) |
| **`execution-policy.md`** | MultiSign / on-chain execution policy: gas, one `requestId` per round, confirmation before broadcast |
| **`scheduled-automation.md`** | Cron & webhook behavior: non-interactive runs, schedule kinds, conversation threading |
| **`<name>.md`** / **`<name>.txt`** | Additional skill bodies (markdown or plain text) |

Skill **`name`** values must be lowercase (`a-z`, digits, hyphen, underscore) — they match the node API and manifest lookup.

Add new defaults here (manifest entry + file), commit, then re-run **`process_config.sh`** on nodes — only **missing** files are installed. Existing nodes keep their runtime **`skills.json`** until you add skills via the UI or API.


## Skill file format (required)

Each skill is a directory:

```
Skills/<name>/SKILL.md
```

`SKILL.md` must start with YAML frontmatter:

```md
---
name: skill-name
description: What it does and when to use / skip it (routing signal).
---

# Skill body
```

At chat startup the agent sees **name + description only**; the body loads via `agent_load_skill`.
