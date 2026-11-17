---
name: evm-audit
description: Optional audit of Solidity under evm/. After a Foundry dry-run, offer a QuillShield audit once. A decline still creates the deploy multi-sign request. No key, a declined quote, a short wallet they will not top up, or an API error is a local scan.
---

# EVM audit

Load when the operator asks to audit a contract under `evm/`, or when `evm-foundry` offers an audit after a dry-run.

Ask once. Say that accepting uploads `evm/` to QuillShield before you quote. Skipping does not block deployment. Call `continuum__deploy_built_contract_multi_sign_request` as `evm-foundry` describes. Findings do not block that tool. A missing audit does not block it.

QuillShield is the audit. Catalog server id `quillshield` (`npx -y @quillaudits/mcp`). The operator sets `QUILLSHIELD_API_KEY`. Do not auto-load. If the server is already active, call `agent_load_mcp_server`. If it is only in the catalog, tell the operator to add it and set the key. Read each tool schema before the first call. Do not invent arguments.

When the key is set and they accept:

1. `get_wallet`
2. `submit_audit` with `pay: false`
3. Show the quote. `pay_quote` with `confirm: true` only after they agree to that price.
4. A covered quote (`final_price_cents` is 0) spends the wallet. Do not ask for a top-up.
5. If the tool returns `wallet_topup_required`, stop. Tell them to top up their QuillShield balance. Give the dashboard Billing link from that response. They pay there with card or crypto (Stripe Checkout). Do not start a payment from this node. After the balance covers the quote, they can confirm again.
6. `watch_audit`, then `list_findings` and `get_report`.

The report is an automated QuillShield audit, not a tier-1 manual audit.

If they want an audit and QuillShield cannot run, say why, then run a local scan with cwd `evm/`. That is no key, a declined quote, a short wallet they will not top up, or an API error. This is not a QuillShield audit.

- Run `aderyn .` when that binary is already on `PATH`. Do not install it.
- Walk reachable paths only: an external call before the state write, a function missing a guard its siblings use, spot-price or flash-loan use, an unchecked token return, and upgrade storage layout.

Do not run Slither.
