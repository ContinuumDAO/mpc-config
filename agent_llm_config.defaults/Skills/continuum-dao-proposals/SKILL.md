---
name: continuum-dao-proposals
description: Present ContinuumDAO proposals (live, pending, ready to execute, recent). Deconstruct multi-action Bravo/Delta briefs and the linked forum thread. Do not vote from this skill.
---

# ContinuumDAO proposals (presentation)

Load when the operator asks what is live, recent, ready to execute, or what a proposal **does**. Also load **`continuum-dao-proposal-standards`**. For “should I vote / how would this node vote?” also load **`continuum-dao-vote-policy`**. Do **not** load **`continuum-dao-compose-proposal`**.

In agent chat, Continuum tools are **`continuum__<name>`**. Load the protocol first: **`continuum__load_defi_protocol({ "protocolId": "continuum-dao" })`**.

## Live / recent list

Do **not** answer from `ctm_continuum_dao_fetch_proposals` or backend `status`.

1. `continuum__ctm_continuum_dao_fetch_live_proposals` with Linea `chainId` `59144` (Sepolia `59141`) and `rpcUrl` from the chain registry. Pass `governor` if the constant is still zero.
2. Read `note`, then print **four short lists** (titles, `#id`, `stateLabel`). Do not dump JSON.

| Bucket | Meaning |
|--------|---------|
| **`live`** | Active — voting now |
| **`pending`** | Not yet voting |
| **`readyToExecute`** | Succeeded. No queue. Offer execute only if the operator asks |
| **`recentlyCompleted`** | Canceled / Defeated / Expired / Executed in this scan |
| **`unknown`** | No on-chain overlay — never call these live |

If `overlay` is `backend-only`, say you could not confirm Governor state.

## Deconstruct one proposal

1. `continuum__ctm_continuum_dao_explain_proposal` with backend `id` or `onchainId`.
2. Read **`briefing` aloud**. Walk every line. Do not collapse to “some transfers.”
3. Encoder no-ops (`value 0`, empty signature, `0x` calldata) are **signaling**, not ETH sent to a KeyGen.
4. If an action has `c3governor`, it runs on **that network via C3**, not on Linea.
5. Header must include proposer as **any EOA or contract** (not “must be a KeyGen”).
6. Delta: one subsection per option, then **None of the above (NOTA)** as a vote slot with no actions.
7. Bravo: “If this passes, the DAO will execute, in order.”
8. Repeat the **Risks** list from the tool. Do not invent extra certainty.
9. If `forumKey` is a topic URL (`/topic/:tid` or `/t/:tid`), `continuum__ctm_continuum_dao_forum_resolve` then `forum_fetch_thread` (index `0` = OP). Note **`section` / `cid`**. Expected: Decision→`decision`, Election→`election`, Treasury→`treasury`, Constitution→`constitution`, Admin→`admin`. If `section` is `ideas` or does not match `typeLabel`, treat as a **mismatch** (amber/red) and say so. Summarize the original post and reply count (`forum_reply_count`). Reads only — no login, reply, `forum_create_topic`, or `forum_create_idea` from this skill.
10. Run **`continuum-dao-proposal-standards`** on the brief + OP (includes fetching Constitution **`continuumdao-proposals-and-voting`**). Highlight Vision/Mission failures, **type-fit** failures, missing Format elements, and Forum section mismatch (do not vote from this skill).

This skill does **not** create a multi-sign request, vote, propose, execute, or call `sign_request_agree`.

## After the briefing

- Operator wants a stance → load **`continuum-dao-vote-policy`**.
- Operator wants to vote in this chat → that skill + **`execution-policy`** (confirm before submit).
- Operator wants to **create** a proposal → load **`continuum-dao-compose-proposal`** (interactive only; never from cron).
- Unattended vote / Join → cron templates; this skill stays presentation-only.
