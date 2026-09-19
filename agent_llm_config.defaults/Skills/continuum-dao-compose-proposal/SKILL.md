---
name: continuum-dao-compose-proposal
description: Interactive only. Interview a Bravo/Delta proposal (KeyGen submit or other-address draft): load etherscan + foundry, type, per-action contract + function, etherscan ABI, type-check values, table, then Foundry forge-script simulate. Forum + propose only for KeyGen submit. Never load from cron, vote-policy, or proposals presentation.
---

# ContinuumDAO compose proposal (interactive only)

Load when the operator wants to **create** or **draft** a proposal **or** post an Idea/Suggestion in chat (“draft a proposal”, “propose that we…”, “put this on-chain”, “share an idea”). Always load **`continuum-dao-proposal-standards`**. Load **`execution-policy`** only before a KeyGen multi-sign submit. Load **`continuum-dao-proposals`** only if they also want a live-list briefing. Help the operator draft to the official Proposal Format.

**Classify before writing.** If the operator is seeking feedback, exploring an early thought, or is not ready for a Temperature Check / on-chain vote, that is an **Idea** — `forum_create_idea` only. Do not propose. If they want a formal DAO decision (Temperature Check + vote), that is a **proposal** — Governance section only, never Ideas. Ads, agent discovery, HITL listings, and KeyGen mail are **not** Ideas — load **`continuum-dao-mpa-wallet-chat`**.

**Never load this skill from cron.** Vote cron, governor Join, trade Join, and skills **`continuum-dao-vote-policy`** / **`continuum-dao-proposals`** must not call `agent_load_skill` on this name.

In agent chat, Continuum tools are **`continuum__<name>`**. Load the protocol first: **`continuum__load_defi_protocol({ "protocolId": "continuum-dao" })`**.

**Load MCP servers before any ABI lookup or simulate:** `agent_load_mcp_server` **etherscan** (official V2, `https://mcp.etherscan.io/mcp`) then **foundry**. Do not compose or simulate until both are loaded.

This skill **never** votes, executes, cancels, or calls `trigger_sign_result` / `broadcast_sign_result` unless the operator explicitly asks to Get Sig / broadcast after they have confirmed the propose request.

## Path: KeyGen submit vs other-address draft

Ask first (do not assume):

1. **Preferred signer KeyGen** — they intend to submit on-chain from this node’s KeyGen. Full interview below, then optional forge-script simulate, then forum topic + `build_propose_*` (builders **hard-fail** if `getVotes(KeyGen) <` live `proposalThreshold()` or `propose()` reverts).
2. **Other address draft** — committee EOA or any address that is not this KeyGen. Same interview and table. Simulate with `account`. **Do not** call `build_propose_*` or create a forum topic unless they later switch to the KeyGen path.

Both paths use the same compose tool, the same simulate tool, and the same Foundry forge scripts. Do **not** skip ABI lookup, type checks, the input table, or the simulate offer on the KeyGen path.

Do **not** gate the interview on KeyGen voting power. Check power only when they choose to **submit** from the KeyGen (before forum / `build_propose_*`). For another address, `ctm_continuum_dao_simulate_proposal` only **warns**.

A new chat that asks to create or draft a proposal is a **new interview**. Do **not** `agent_grep` / `agent_ls` / `agent_read_file` / `agent_bash` under `data/proposals/` (or any prior `*.md` proposal) unless the operator named that path or said to resume or reuse it. Do not infer type, recipient, amount, or actions from an on-disk file.

On the **other-address draft** path, do **not** call `get_preferred_key_gen`, `fetch_key_gen_result`, or `fetch_voting_power` for this node’s KeyGen. Those are submit-path only. A short KeyGen is not a reason to stop drafting.

## Interview (ask, do not guess)

Ask one topic at a time until the draft is complete.

1. **Vote shape → Bravo vs Delta**
   - One yes/no (For / Against / Abstain) → **Bravo** (`configuration: 0`).
   - Several labeled choices → **Delta** (`configuration: 1`). Delta always has a baked-in **NOTA** vote slot; do not add “None of the above” as a user option.
2. **Type and Forum section** — from **`continuum-dao-proposal-standards`** after fetching Constitution **`continuumdao-proposals-and-voting`**. Pick the type that section defines for this ask (not “whatever the operator named it”). Then set the matching Forum `section` and backend `type`: Admin `0` / `admin`, Constitution `1` / `constitution`, Decision `2` / `decision`, Election `3` / `election`, Treasury `4` / `treasury`. If it does not fit any type, it is an Idea (`forum_create_idea`), not a proposal. Never post a proposal to Ideas. Never default to Decision when Election, Treasury, Constitution, or Admin fits.
3. **On-chain effects vs signaling**
   - “No on-chain actions” / signaling → Bravo `actions: []` or each Delta option `actions: []`. Skip the ABI interview for that option. The encoder inserts a succeeding no-op.
   - Real effects → for **each action**, in order:
     1. Ask the **contract address** (`target`).
     2. Ask the **function name** (plain name is enough; a full signature is also fine).
     3. Call **`etherscan__get_contract_abi`** with `address` = that target and `chainid` `59144` (Sepolia `59141`). Then call **`continuum__ctm_continuum_dao_compose_proposal_action`** with `chainId`, `target`, `functionName`, and that `abi`. Read `parameters` / `overloads` aloud. If there are overloads, ask which `signature` to use and call again with it.
     4. Ask for a value for **each parameter** (one at a time). Arrays/tuples as JSON. Addresses checksummed. Integers as decimal or `0x` hex.
     5. Call the same tool again with `inputs` values (and `value` wei if they send ETH). If `ok` is false, re-ask the fields in `missing` / `error` until types pass. Keep the returned `encoded` action (`target`, `value`, `signature`, `inputs`).
     6. Ask if there is another action (Delta: another action on this option, then the next option).
4. **Delta only:** option **labels** (required), `nOptions >= 2`, `nWinners >= 1` and **strictly less than** `nOptions`. Confirm empty vs real actions per option.
5. **Title** 8–128 chars (on-chain `description` and forum topic title). **Description** ≤ 1024 chars (backend). Forum body: proposal text ≤ **6200** so an 1800-char standards appendix still fits (tool max 8000, English).
6. **Proposal Format** — follow **`continuum-dao-proposal-standards`**. Draft Abstract, Motivation, Overview, Type, Scope, and Treasury extras (Success Criteria, Timeline, Budget). Fetch How to Write a Proposal; do not skip headings.
7. **Vision / Mission and type-fit** — follow **`continuum-dao-proposal-standards`** (required Constitution fetches). If the draft does not further Mission & Vision, or the Type does not match **Proposals and Voting**, **tell the operator** and recommend a rewrite or a different type/section. If they **insist**, continue and append the red/amber appendix from that skill.

## Conclusion table (required)

After every action is collected (or the draft is signaling-only), call **`continuum__ctm_continuum_dao_compose_proposal_action`** with `configuration` and `actions` (Bravo) or `options` + `nWinners` (Delta). Print the returned **`table`** verbatim. If `ok` is false, fix the invalid rows and preview again. Do not simulate or submit until the table is all valid.

## Simulate (offer on both paths)

Ask: “Do you want to simulate this proposal before going further?”

If yes, sequential execute must be a **Foundry forge script** on a Linea fork. Isolated `eth_call` or `cast call` cannot carry state from one action to the next.

1. Confirm **etherscan** and **foundry** are loaded.
2. Call **`continuum__ctm_continuum_dao_simulate_proposal`**:
   - **Other-address draft:** pass `account` = that EOA, plus the same `configuration` / `actions` or `options` + `nWinners`.
   - **KeyGen:** pass `keyGenId` or omit `account` (server fills the KeyGen).
3. Read `warning` aloud if present (Committee is not exempt).
4. For each file in `foundry.files`, call **`foundry__create_solidity_file`** with that `path` and `source`.
5. For each file, call **`foundry__forge_script`** with the Linea (or Linea Sepolia) fork RPC from the chain registry and **no `--broadcast`**. Bravo: one execute script. Delta: one execute script per option. The propose script pranks the proposer; execute scripts prank the governor.
6. If any forge script reverts, stop. Do **not** submit.
7. If `execute.source` is `foundry_required`, that only means the public RPC lacks `eth_simulateV1` — the forge scripts are still the execute sim. Do not fall back to isolated `eth_call`.

`forumKey` is not required on simulate. Never broadcast these scripts.

## KeyGen submit only (after table + optional forge-script simulate)

`ContinuumDAO.proposalThreshold()` is `max(1000 ether, pastTotalSupply(clock-1) * 1000 / 100_000)` — a **floor of 1000e18 ve power** and **1% of current total voting power**. Do not hardcode `1000`.

1. Identify the proposing KeyGen ETH address (`executorAddress`).
2. `continuum__ctm_continuum_dao_fetch_voting_power` with Linea `chainId` `59144` (Sepolia `59141`) and `account` = that KeyGen. If `votes < threshold`, **stop**. Explain the shortfall. Do not call `build_propose_*`.
3. **Forum thread is required and must be created first in the matching Governance section.** Do not propose with the homepage, an Ideas URL, or an invented URL. `forumKey` must be `/topic/:tid` or `/t/:tid` on forum.continuumdao.org from `forum_create_topic`. Citizens should have developed the ask in Ideas first; **Committee** operators may skip that Ideas pre-post for an urgent **Admin** proposal, but the on-chain `forumKey` is still a Governance `admin` topic — never an Ideas URL.

### Forum login / logout / write

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

## Preview briefing (before any write)

Print a briefing in the same shape as `explain_proposal` would: title, type, Bravo vs Delta, the **input table**, each action / option (no-ops labeled **signaling**), C3 called out, **forum URL (pending create if not yet posted)**, **Vision/Mission + Format review** (from proposal-standards), and **Risks**. Wait for an explicit confirm (“yes, submit”).

## Submit (KeyGen, confirmed only)

1. Forum sign-in (if needed) → `forum_create_topic` (Governance `section`) → keep `url` as `forumKey`.
2. `continuum__ctm_continuum_dao_build_propose_bravo_multisign` or `…_propose_delta_multisign` with that **`forumKey`** and the encoded actions from compose. No billing legs. Follow **`execution-policy`**.
3. After the propose tx is **mined**, `continuum__ctm_continuum_dao_register_proposal` with the **same** `forumKey`, plus `onchainId` from `hashProposal` / `ProposalCreated`, title, description, proposer (KeyGen ETH), `type` 0–4, `configuration` 0|1, and user `actions` / `options` (empty arrays for signaling). If the POST fails, retry — do not revert the chain tx.
4. Offer `forum_sign_out`.

Do not enable or invent a cron that composes, creates a forum topic, or proposes.
