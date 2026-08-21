---
name: continuum-dao-proposal-standards
description: Fetch official Constitution Vision/Mission and How to Write a Proposal. Check format and alignment. Used by compose, vote, and presentation. Do not copy the docs into other skills.
---

# ContinuumDAO proposal standards

Load with **`continuum-dao-compose-proposal`**, **`continuum-dao-vote-policy`**, or **`continuum-dao-proposals`**. Do **not** paste the Constitution or How-to into this file — fetch them.

## Fetch (once per session)

Docs tools are the **`docs`** bundle. If `get_continuum_doc` is not in the tool list:

`continuum__activate_tool_group({ "groupId": "docs" })`

Then:

1. `continuum__get_continuum_doc({ "path": "ContinuumDAO/Governance/Constitution" })` — read **Mission & Vision** (and Proposal Template / categories if needed). Use `sectionId` from `search_continuum_docs` if the page is long.
2. `continuum__get_continuum_doc({ "path": "ContinuumDAO/Governance/HowToWriteAProposal" })` — read **Proposal Format** and Necessary Elements.

Canonical URLs (for the operator, not as `forumKey`):

- https://docs.continuumdao.org/ContinuumDAO/Governance/Constitution
- https://docs.continuumdao.org/ContinuumDAO/Governance/HowToWriteAProposal

## Checklist (apply to draft or live proposal + forum OP)

**Vision / Mission (red if it fails).** The proposal must further creating public goods that connect web protocols/networks in a decentralized way, and decentralized MPC / trustless coordinated decision-making. If it does not **clearly** do that, it does not conform. Note the specific mismatch (unrelated spend, centralized control, no public-good / MPC / connectivity link).

**Proposal Format (amber if missing).** Required headings / substance:

| Element | Always | Treasury also |
|---------|--------|----------------|
| Abstract (≤ 200 words) | yes | |
| Motivation | yes | |
| Overview (who / background) | yes | |
| Type (Decision / Election / Treasury / Constitution / Admin) | yes | |
| Scope (task list) | yes | |
| Success Criteria / deliverables | | yes |
| Timeline | | yes |
| Budget (amounts vs milestones) | | yes |

Also call out: no clear objectives; no community-discussion mention when the draft is a first post; Constitution-type missing the new Constitution text; re-submission with no material change / no pointer to the prior proposal.

**Help draft (compose only).** Walk the operator through those headings. Suggest wording that states how the work serves Mission & Vision. Do not invent facts.

## Tell the operator first

State **conforms** or **does not conform**, with the red items and amber items in the chat. Do not submit yet.

- Compose: if it fails, recommend fixing the draft. If they **insist**, continue and attach the appendix below.
- Vote / present: highlight the same items. They **contribute to the vote stance** (see vote-policy). Good format never invents **For**.

## Forum body budget

`forum_create_topic` / `forum_reply` body max is **8000** characters, English.

- Keep the proposal text ≤ **6200**.
- Reserve **1800** for the standards appendix. Never drop the appendix to fit more draft; shorten the draft instead.
- Only append the blocks that apply. Omit a block if that list is empty.

Appendix (end of the post, after the proposal text):

```html
---
### Agent standards review
<p style="color:#c0392b"><strong>Does not conform to Constitution Vision / Mission</strong><br>
- …</p>
<p style="color:#d68910"><strong>Missing Proposal Format elements</strong><br>
- …</p>
```

Use those colours (red `#c0392b`, amber `#d68910`). Do not put this block in the on-chain title.
