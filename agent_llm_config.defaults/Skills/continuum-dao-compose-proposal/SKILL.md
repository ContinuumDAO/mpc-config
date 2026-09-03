---
name: continuum-dao-compose-proposal
description: Interactive only. Interview, create a forum thread first (EIP-712 login), then submit a ContinuumDAO Bravo or Delta proposal with that forumKey. Never load from cron, vote-policy, or proposals presentation.
---

# ContinuumDAO compose proposal (interactive only)

Load when the operator wants to **create** a proposal **or** post an Idea/Suggestion in chat (“draft a proposal”, “propose that we…”, “put this on-chain”, “share an idea”). Always load **`continuum-dao-proposal-standards`** and **`execution-policy`** before any multi-sign submit. Load **`continuum-dao-proposals`** only if they also want a live-list briefing. Help the operator draft to the official Proposal Format.

**Classify before writing.** If the operator is seeking feedback, exploring an early thought, or is not ready for a Temperature Check / on-chain vote, that is an **Idea** — `forum_create_idea` only. Do not propose. If they want a formal DAO decision (Temperature Check + vote), that is a **proposal** — Governance section only, never Ideas. Ads, agent discovery, HITL listings, and KeyGen mail are **not** Ideas — load **`continuum-dao-mpa-wallet-chat`**.

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
2. **Type and Forum section** — from **`continuum-dao-proposal-standards`** after fetching Constitution **`continuumdao-proposals-and-voting`**. Pick the type that section defines for this ask (not “whatever the operator named it”). Then set the matching Forum `section` and backend `type`: Admin `0` / `admin`, Constitution `1` / `constitution`, Decision `2` / `decision`, Election `3` / `election`, Treasury `4` / `treasury`. If it does not fit any type, it is an Idea (`forum_create_idea`), not a proposal. Never post a proposal to Ideas. Never default to Decision when Election, Treasury, Constitution, or Admin fits.
3. **On-chain effects vs signaling**
   - “No on-chain actions” / signaling → Bravo `actions: []` or each Delta option `actions: []`. The encoder inserts a succeeding no-op (`target = KeyGen ETH`, `value = 0`, `calldata = 0x`). Backend stores `actions: []`.
   - Real effects → collect each action: **network** (Linea or C3 `c3governor` network from `GET /protocol/networks`), **target**, **value** (wei string), **signature**, **inputs** (`name`, `type`, `value`). Flag C3, ETH value, `approve` / `transfer` / owner / upgrade as risks in the preview.
4. **Delta only:** option **labels** (required), `nOptions >= 2`, `nWinners >= 1` and **strictly less than** `nOptions`. Confirm empty vs real actions per option.
5. **Title** 8–128 chars (on-chain `description` and forum topic title). **Description** ≤ 1024 chars (backend). Forum body: proposal text ≤ **6200** so an 1800-char standards appendix still fits (tool max 8000, English).
6. **Proposal Format** — follow **`continuum-dao-proposal-standards`**. Draft Abstract, Motivation, Overview, Type, Scope, and Treasury extras (Success Criteria, Timeline, Budget). Fetch How to Write a Proposal; do not skip headings.
7. **Vision / Mission and type-fit** — follow **`continuum-dao-proposal-standards`** (required Constitution fetches). If the draft does not further Mission & Vision, or the Type does not match **Proposals and Voting**, **tell the operator** and recommend a rewrite or a different type/section. If they **insist**, continue and append the red/amber appendix from that skill.
8. **Forum thread is required and must be created first in the matching Governance section.** Do not propose with the homepage, an Ideas URL, or an invented URL. `forumKey` must be `/topic/:tid` or `/t/:tid` on forum.continuumdao.org from `forum_create_topic`.

## Forum login / logout / write

Reads do not need a ticket. Writes (`forum_create_topic`, `forum_create_idea`, `forum_reply`, `forum_react`) need a ticket from KeyGen **EIP-712** sign-in (no EVM tx).

1. `continuum__ctm_continuum_dao_forum_sign_in_eligible({ address })` — holder or attach-key veCTM vs `veCtmThresholdPower`. If `eligible` is false, **stop**. Do not start a multi-sign request.
2. If there is no ticket: `continuum__ctm_continuum_dao_build_forum_sign_in_multisign` with `nodeKey` (username = first 16 chars) or `username` on first login. Follow **`execution-policy`**. After Get Sig, the node-app exchanges the signature for a ticket (`/api/continuum/eip712/ticket`). Pass that `ticket` on write tools.
3. `continuum__ctm_continuum_dao_forum_me` to confirm session. `canPostIdea` is enough for Ideas; `canPropose` (`getVotes >= proposalThreshold()`) is required for Governance threads.
4. `continuum__ctm_continuum_dao_forum_sections`. Then:
   - **Idea:** **`continuum__ctm_continuum_dao_forum_create_idea`**. Stop. Do not propose. Do not use the URL as `forumKey`.
   - **Proposal:** **`continuum__ctm_continuum_dao_forum_create_topic`** with the matching `section` from the type table. Title/body must be English. Body = formatted proposal (≤ 6200) **plus** the standards appendix if the operator insisted after a failed check. Keep the returned **`url`**.
5. Optional: `forum_reply` / `forum_react` (`+1` `-1` `heart` `tada` `eyes`) on that thread. To check Unread / mark threads read, load **`continuum-dao-forum-inbox`**.
6. When finished, `continuum__ctm_continuum_dao_forum_sign_out({ ticket })` — no multi-sign.

Never call `build_propose_*` or `register_proposal` until `forum_create_topic` has returned a Governance topic URL. Never pass an Ideas URL as `forumKey`.

## Preview (before any write)

Print a briefing in the same shape as `explain_proposal` would: title, type, Bravo vs Delta, each action / option (no-ops labeled **signaling**), C3 called out, **forum URL (pending create if not yet posted)**, **Vision/Mission + Format review** (from proposal-standards), and **Risks**. Wait for an explicit confirm (“yes, submit”).

## Submit (confirmed only)

1. Forum sign-in (if needed) → `forum_create_topic` (Governance `section`) → keep `url` as `forumKey`.
2. `continuum__ctm_continuum_dao_build_propose_bravo_multisign` or `…_propose_delta_multisign` with that **`forumKey`**. No billing legs. Follow **`execution-policy`**.
3. After the propose tx is **mined**, `continuum__ctm_continuum_dao_register_proposal` with the **same** `forumKey`, plus `onchainId` from `hashProposal` / `ProposalCreated`, title, description, proposer (KeyGen ETH), `type` 0–4, `configuration` 0|1, and user `actions` / `options` (empty arrays for signaling). If the POST fails, retry — do not revert the chain tx.
4. Offer `forum_sign_out`.

Do not enable or invent a cron that composes, creates a forum topic, or proposes.
