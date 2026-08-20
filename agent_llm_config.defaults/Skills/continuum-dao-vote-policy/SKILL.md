---
name: continuum-dao-vote-policy
description: How this node votes on ContinuumDAO proposals and how governor Join Accept/Reject works. Never create a proposal. Trusted proposers are any EOA or contract.
---

# ContinuumDAO vote policy

Load for “how should I vote?”, policy appraisal, the **appraise-and-vote-proposals** cron, or **conditional-accept-governance-vote**. Always load **`continuum-dao-proposals`** first so the briefing exists. For interactive submit, also load **`execution-policy`**. For cron, load **`scheduled-automation`**.

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

## Appraisal (interactive and cron)

1. `explain_proposal` briefing + `fetch_proposal_state` (must be **Active** to vote).
2. If `proposer` is in `blockedProposers` → `skip` (cron: do nothing).
3. If `trustedProposers` is non-empty and proposer is not on it → `skip`.
4. If type is in `types.block` → `skip` or `against` per YAML.
5. Treasury / value / deny signatures / deny targets / scam flags → `against` or `nota` (Delta) or `skip` if `defaultAction` is skip and the rule says skip.
6. If nothing matches → **`defaultAction`**. Never invent **For**.
7. Delta “take no action” → put weight on the **last (NOTA)** slot only.

Interactive chat: state the recommendation and **wait for confirmation** before any vote multi-sign. Cron: no questions; if skip/unknown, **do nothing**.

## Creating a vote (interactive or vote cron only)

Allowed tools: `ctm_continuum_dao_build_cast_vote_bravo_multisign` (support 0/1/2) or `…_cast_vote_delta_multisign` (weights length **nOptions + 1**).

Forbidden: propose_*, register_proposal, execute, cancel, Compose propose, `trigger_sign_result`, `broadcast_sign_result`.

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
