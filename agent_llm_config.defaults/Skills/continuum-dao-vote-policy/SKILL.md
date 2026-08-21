---
name: continuum-dao-vote-policy
description: How this node votes on ContinuumDAO proposals and how governor Join Accept/Reject works. Read the forum thread; interactive login/reply/react allowed. Never create a proposal or forum topic. Trusted proposers are any EOA or contract.
---

# ContinuumDAO vote policy

Load for “how should I vote?”, policy appraisal, the **appraise-and-vote-proposals** cron, or **conditional-accept-governance-vote**. Always load **`continuum-dao-proposals`** and **`continuum-dao-proposal-standards`** first so the briefing and Constitution/format check exist. For interactive submit, also load **`execution-policy`**. For cron, load **`scheduled-automation`**.

This skill **never** authorizes `ctm_continuum_dao_build_propose_*` or `ctm_continuum_dao_register_proposal`. Do **not** load **`continuum-dao-compose-proposal`**.

## votePolicy (edit on this node)

Marker `votePolicy:` then YAML. Empty allowlists mean “do not filter on that field” except `defaultAction`.

```yaml
votePolicy:
  version: 1
  defaultAction: skip          # skip | nota | against | abstain — never "for"
  keyGenId: ""                 # KeyGen that casts the vote (not a proposer filter)
  trustedProposers: []         # any 0x EOA or contract; empty = do not filter by author
  blockedProposers: []
  types:
    block: [Admin]
    treasury:
      action: against          # against | nota | skip
      maxValueWei: "0"
  signatures:
    allow: []
    deny: ["transfer(", "approve(", "increaseAllowance(", "setOwner(", "upgradeTo"]
  targets:
    deny: []
    treasuryLike: []
  scam:
    rejectValueToEoa: true
    rejectUnknownTarget: true
    rejectEmptyDescriptionWithActions: true
```

**Trusted proposers are not KeyGens.** Any Ethereum address may author a proposal. `keyGenId` is only who **signs the vote**.

## Forum (read always; write when interactive)

A proposal should have a real `forumKey` (`/topic/:tid` or `/t/:tid`). Reads do not need a ticket.

1. `continuum__ctm_continuum_dao_forum_resolve` then `forum_fetch_thread` (index `0` = OP; page replies with `start`/`limit`). Read **`section`**. Expected map: Decision→`decision`, Election→`election`, Treasury→`treasury`, Constitution→`constitution`, Admin→`admin`. `forum_reply_count` for volume. One post: `forum_fetch_post`. A user’s posts: `forum_user_post_ids` then `forum_fetch_post`.
2. Include the OP (and notable replies) in the appraisal. Scam / empty-description rules still apply if the on-chain brief is thin but the thread is not. A thread in **Ideas & Suggestions**, or a section that does not match `typeLabel`, is a **standards failure** (lean `against` / `nota`).

**Interactive write** (operator asked to comment or react — not from cron):

1. `forum_sign_in_eligible` then `build_forum_sign_in_multisign` if there is no ticket (veCTM login gate; no EVM tx). Pass `ticket` on writes.
2. `forum_reply` (English, ≤ 8000) or `forum_react` (`+1` `-1` `heart` `tada` `eyes`). Confirm before posting.
3. `forum_sign_out({ ticket })` when done.

**Cron:** read the thread only. Do **not** `forum_create_topic`, `forum_create_idea`, sign in, reply, or react. Never propose.

## Appraisal (interactive and cron)

1. `explain_proposal` briefing + `fetch_proposal_state` (must be **Active** to vote). Fetch the forum thread as above when `forumKey` is a topic URL.
2. Run **`continuum-dao-proposal-standards`** on the on-chain brief + forum OP (must include the fetched **Proposals and Voting** type-fit). Tell the operator every red (Vision/Mission, type-fit) and amber (missing Format) item.
3. If `proposer` is in `blockedProposers` → `skip` (cron: do nothing).
4. If `trustedProposers` is non-empty and proposer is not on it → `skip`.
5. If type is in `types.block` → `skip` or `against` per YAML.
6. Treasury / value / deny signatures / deny targets / scam flags → `against` or `nota` (Delta) or `skip` if `defaultAction` is skip and the rule says skip.
7. **Standards:** Vision/Mission non-conformance → `against` or `nota` (Constitution: voters should seriously consider rejecting). **Type-fit** failure against fetched Proposals and Voting (wrong type, Constitution without the new text, Treasury with no transfer, Election that is not multi-choice, Admin that is not onlyGov/upgrade/redeploy, or Forum section mismatch / Ideas `forumKey`) → same lean. Missing Format (especially Treasury budget / timeline / success criteria, or no Abstract/Motivation/Scope) → same lean, or `skip` only if `defaultAction` is skip and no other deny rule fired. Cite the failing items in the recommendation.
8. If nothing matches → **`defaultAction`**. Never invent **For**. Good format does not authorize For.
9. Delta “take no action” → put weight on the **last (NOTA)** slot only.

Interactive chat: state the recommendation and **wait for confirmation** before any vote multi-sign. Cron: no questions; if skip/unknown, **do nothing**.

## Creating a vote (interactive or vote cron only)

Allowed tools: `ctm_continuum_dao_build_cast_vote_bravo_multisign` (support 0/1/2) or `…_cast_vote_delta_multisign` (weights length **nOptions + 1**). Forum read tools always; forum login / reply / react only in interactive chat (see above).

Forbidden: propose_*, register_proposal, `forum_create_topic`, `forum_create_idea`, execute, cancel, Compose propose, `trigger_sign_result`, `broadcast_sign_result`.

## Governor Join (`sign_request_agree`) — not the trade job

**`conditional-accept-sign-request` is TRADE only.** Governor requests must use **`conditional-accept-governance-vote`**.

Governor `evm.type` values:

| type | Join cron |
|------|-----------|
| `continuum_dao_cast_vote` | Accept only if votePolicy agrees with the **stance already in the request** |
| `continuum_dao_propose` | **Always Reject** |
| `continuum_dao_execute` | **Reject** |
| `continuum_dao_cancel` | **Reject** |
| anything else | **Skip** (leave for trade job or a human) |

Also match `signatureText` JSON `kind: ContinuumDAO` and `name` `ContinuumDAO.propose` / `castVote` / `execute` / `cancel`.

On a vote request: `explain_proposal` for the `proposalId` in metadata; Accept only if the request’s For/Against/Abstain or Delta weights (incl. NOTA) **match** what votePolicy would cast. If policy is skip or the stance is wrong-way → **Reject**, cite the rule in `thoughts`. Never Accept a propose to clear the queue.

Do not call `trigger_sign_result` or `broadcast_sign_result` from this skill’s cron paths.
