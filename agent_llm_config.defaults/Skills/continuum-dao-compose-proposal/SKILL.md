---
name: continuum-dao-compose-proposal
description: Interactive only. Interview the operator in plain English, then preview and submit a ContinuumDAO Bravo or Delta proposal. Never load from cron, vote-policy, or proposals presentation.
---

# ContinuumDAO compose proposal (interactive only)

Load when the operator wants to **create** a proposal in chat (“draft a proposal”, “propose that we…”, “put this on-chain”). Always load **`execution-policy`** before any multi-sign submit. Load **`continuum-dao-proposals`** only if they also want a live-list briefing.

**Never load this skill from cron.** Vote cron, governor Join, trade Join, and skills **`continuum-dao-vote-policy`** / **`continuum-dao-proposals`** must not call `agent_load_skill` on this name.

In agent chat, Continuum tools are **`continuum__<name>`**. Load the protocol first: **`continuum__load_defi_protocol({ "protocolId": "continuum-dao" })`**.

This skill **never** votes, executes, cancels, or calls `trigger_sign_result` / `broadcast_sign_result` unless the operator explicitly asks to Get Sig / broadcast after they have confirmed the propose request.

## Proposal threshold (gate first)

`ContinuumDAO.proposalThreshold()` in vectm is **not** a hardcoded `1000`. It is:

```
max(1000 ether, pastTotalSupply(clock-1) * 1000 / 100_000)
```

That is a **floor of 1000e18 ve power** (GovernorSettings, “1000 CTM @ 4 years”) and **1% of current total voting power** (numerator `1000`, denominator `100_000`). The live value moves with ve supply.

1. Identify the proposing KeyGen ETH address (`executorAddress`).
2. `continuum__ctm_continuum_dao_fetch_voting_power` with Linea `chainId` `59144` (Sepolia `59141`), `rpcUrl`, and `account` = that KeyGen. Pass `governor` if the constant is still zero.
3. Compare `votes` to `threshold` as integers (wei / 1e18-scaled ve units). If `votes < threshold`, **stop**. Explain the shortfall in human units (`votes / 1e18` vs `threshold / 1e18`). Do not call `build_propose_*`. Delegation applies at the KeyGen address; attach-to-node is unrelated.
4. Propose builders also enforce this on-chain read and throw if below. Do not try to bypass.

## Interview (ask, do not guess)

Ask one topic at a time until the draft is complete. Plain English is enough; you map it to encoding.

1. **Vote shape → Bravo vs Delta**
   - One yes/no (For / Against / Abstain) → **Bravo** (`configuration: 0`).
   - Several labeled choices → **Delta** (`configuration: 1`). Delta always has a baked-in **NOTA** vote slot; do not add “None of the above” as a user option.
2. **Type tag** (backend only; not on-chain): Admin `0`, Constitution `1`, Decision `2`, Election `3`, Treasury `4`. Default Decision unless they say otherwise.
3. **On-chain effects vs signaling**
   - “No on-chain actions” / signaling → Bravo `actions: []` or each Delta option `actions: []`. The encoder inserts a succeeding no-op (`target = KeyGen ETH`, `value = 0`, `calldata = 0x`). Backend stores `actions: []`.
   - Real effects → collect each action: **network** (Linea or C3 `c3governor` network from `GET /protocol/networks`), **target**, **value** (wei string), **signature**, **inputs** (`name`, `type`, `value`). Flag C3, ETH value, `approve` / `transfer` / owner / upgrade as risks in the preview.
4. **Delta only:** option **labels** (required), `nOptions >= 2`, `nWinners >= 1` and **strictly less than** `nOptions`. Confirm empty vs real actions per option.
5. **Title** ≤ 128 chars (this is the on-chain `description`). **Description** ≤ 1024 chars (backend only).
6. **Forum link (`forumKey`)**
   - Collect an **existing** thread URL, or keep `https://forum.continuumdao.org/` if they have none yet.
   - Do **not** invent a thread, scrape a fake slug, or POST to the forum.
   - Agent-authored forum posts (Express server + **EIP-712** signature from the KeyGen) are **forthcoming**. Until that endpoint exists in the forum codebase, only store the URL the operator gives you.

## Preview (before any write)

Print a briefing in the same shape as `explain_proposal` would: title, type, Bravo vs Delta, each action / option (no-ops labeled **signaling**), C3 called out, forum URL, and **Risks**. Wait for an explicit confirm (“yes, submit”).

## Submit (confirmed only)

1. `continuum__ctm_continuum_dao_build_propose_bravo_multisign` or `…_propose_delta_multisign`. No billing legs. Follow **`execution-policy`** (one `requestId`, confirm before broadcast).
2. After the propose tx is **mined**, `continuum__ctm_continuum_dao_register_proposal` with `onchainId` from `hashProposal` / `ProposalCreated`, plus title, description, proposer (KeyGen ETH), `forumKey`, `type` 0–4, `configuration` 0|1, and user `actions` / `options` (empty arrays for signaling). If the POST fails, retry — do not revert the chain tx.

Do not enable or invent a cron that composes or proposes.
