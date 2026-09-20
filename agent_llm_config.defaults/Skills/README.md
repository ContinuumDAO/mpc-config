# Agent skills (templates)

Bundled skill files for the node agent. Copied from **`agent_llm_config.defaults/Skills/`** into runtime **`agent_llm_config/Skills/`** on first provision (see **`process_config.sh`**).

| File | Purpose |
|------|---------|
| **`skills.json`** | Manifest: `name`, `filename`, `initialLoad` per skill (must match every `Skills/<name>/SKILL.md` below) |
| **`orchestration_planning`** | Plan-mode markdown plans (`user_folder/plans`); host rules live in **`orchestration-plan.yaml`** |
| **`chart-ohlcv-sources`** | OHLCV provider choice: DeFi protocols vs catalog MCP servers (host auto-loads on chart intents) |
| **`chart-periods`** | Default lookback by bar interval and source-specific fetch notes for **`prepare_chart`** |
| **`chart-defaults`** | Default EMA/RSI/volume overlays; numeric periods come from **`trade-desk.yaml`** |
| **`chart-analysis-menu`** | Analysis menu / picker guidance (host auto-loads on chart intents) |
| **`chart-analysis-trend`** | Trend-structure analysis |
| **`chart-analysis-levels`** | Key-level analysis |
| **`chart-analysis-momentum`** | RSI/MACD momentum analysis |
| **`chart-analysis-liquidity-depth`** | Liquidity depth / volume-profile style analysis |
| **`chart-analysis-divergence`** | Momentum/price divergence analysis |
| **`chart-analysis-range`** | Range / volatility analysis |
| **`chart-analysis-patterns`** | Chart-pattern analysis entry points |
| **`chart-analysis-classic-patterns`** | Classic geometric pattern analysis and drawing |
| **`chart-analysis-time-series`** | Time-series style analysis tools |
| **`chart-analysis-bollinger`** | Bollinger Bands analysis (desk knobs in **`trade-desk.yaml`**) |
| **`chart-analysis-donchian`** | Donchian breakout analysis (desk knobs in **`trade-desk.yaml`**) |
| **`chart-analysis-supertrend`** | Supertrend analysis (desk knobs in **`trade-desk.yaml`**) |
| **`chart-analysis-ichimoku`** | Ichimoku cloud analysis (desk knobs in **`trade-desk.yaml`**) |
| **`chart-analysis-z-score`** | Z-score analysis (desk knobs in **`trade-desk.yaml`**) |
| **`chart-analysis-moving-averages`** | Moving-average analysis (desk knobs in **`trade-desk.yaml`**) |
| **`orchestration-chart-analysis`** | Orchestration chart-analysis task drafting (not a host YAML) |
| **`continuum-mcp-deferred-tools`** | Tool bundle discovery; **`load_defi_protocol`** vs **`agent_load_mcp_server`** (`initialLoad: true`) |
| **`execution-policy`** | MultiSign / on-chain execution: gas, one `requestId` per round, confirm before broadcast |
| **`scheduled-automation`** | Cron & webhook behavior: non-interactive runs, schedule kinds, conversation threading |
| **`trade-defaults`** | Policy-only trade-build guidance; numeric desk defaults live in host YAML **`trade-desk.yaml`** |
| **`workspace-tooling`** | Create / reuse scripts under **`user_folder`** |
| **`continuum-dao-tokenomics`** | Live CTM circulating/escrowed supply, protocol addresses, veCTM locks (catalog MCP, not White Paper) |
| **`continuum-dao-proposals`** | Present live/recent ContinuumDAO proposals and deconstruct multi-action briefs |
| **`continuum-dao-vote-policy`** | Vote + governor Join procedure. Machine defaults live in host YAML **`continuum-dao-vote-policy.yaml`**. Never propose |
| **`continuum-dao-compose-proposal`** | Interactive interview (etherscan ABI + typed params + table + Foundry forge-script simulate) → KeyGen forum/propose or other-address draft. Never reuse `data/proposals/` unless asked. Never from cron |
| **`continuum-dao-proposal-standards`** | Fetch Constitution + **Proposals and Voting** + How to Write; type-fit and format checklist |
| **`continuum-dao-forum-replies`** | Read-only watch for replies to the operator’s Forum posts; cron **`notify-forum-replies`** |
| **`continuum-dao-forum-inbox`** | Interactive: list NodeBB Unread, present posts, mark threads read |
| **`continuum-dao-mpa-wallet-chat`** | MPA Wallet Chat listings, Agent Mail, Technocore discovery. Never ads in Ideas/Governance |

Machine-editable host YAML is **not** under **`Skills/`**. Those files live at **`agent_llm_config.defaults/*.yaml`** (and **`cron/trade-cron.yaml`**) and appear on the Skills / Cron tabs as **Host YAML configs**.

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
