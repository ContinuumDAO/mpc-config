---
name: workspace-tooling
description: Use when creating or reusing scripts under user_folder (skills/<name>/scripts or scripts/). Skip for simple one-off questions that need no persisted automation.
---

# Workspace tooling

## When to write a script
- The same multi-step shell/data transform will be needed again
- You need deterministic, token-efficient execution instead of regenerating code in chat

## When to reuse
1. `agent_glob` / `agent_ls` under `skills/**/scripts` and `scripts/`
2. Read the script and its skill body or `scripts/README.md`
3. Run with `agent_bash`

## Layout
- Prefer `skills/<name>/SKILL.md` + `skills/<name>/scripts/...` and name scripts in the skill body
- Cross-cutting utilities go in `scripts/` with a one-line entry in `scripts/README.md`
- **EVM / Foundry:** `evm/` — place `foundry.toml` there; run `forge` with cwd `evm/`; dry-run imports use `evm/broadcast/<script>/<chainId>/dry-run/run-latest.json`
- **Other chains:** `solana/`, `near/`, `stellar/`, `ton/`, `sui/` — chain-specific contracts and tooling
- Do not write loose files at `user_folder/` root; use a subtree from the root `README.md` index
