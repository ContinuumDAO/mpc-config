---
name: continuum-dao-proposal-standards
description: Fetch Constitution Vision/Mission, Proposals and Voting (canonical types), and How to Write a Proposal. Check alignment, type-fit, and format. Used by compose, vote, and presentation.
---

# ContinuumDAO proposal standards

Load with **`continuum-dao-compose-proposal`**, **`continuum-dao-vote-policy`**, or **`continuum-dao-proposals`**. Do **not** paste the Constitution or How-to into this file — fetch them. Apply the fetched **Proposals and Voting** text as the canonical definition of each type.

## Fetch (once per session — all three are required)

Docs tools are the **`docs`** bundle. If `get_continuum_doc` is not in the tool list:

`continuum__activate_tool_group({ "groupId": "docs" })`

Then, in this order:

1. `continuum__get_continuum_doc({ "path": "ContinuumDAO/Governance/Constitution", "sectionId": "mission-amp-vision" })` — **Mission & Vision**.
2. `continuum__get_continuum_doc({ "path": "ContinuumDAO/Governance/Constitution", "sectionId": "continuumdao-proposals-and-voting" })` — **canonical proposal types**. Required before choosing a type, posting to a Forum section, or appraising a live proposal. Do not skip this because the page is long.
3. `continuum__get_continuum_doc({ "path": "ContinuumDAO/Governance/HowToWriteAProposal" })` — **Proposal Format** and Necessary Elements.

If a `sectionId` is not found, `continuum__search_continuum_docs` for that heading and retry with the hit’s `sectionId`. Do not substitute memory or the type table in other skills for the fetched Proposals and Voting text.

Canonical URLs (for the operator, not as `forumKey`):

- https://docs.continuumdao.org/ContinuumDAO/Governance/Constitution?id=mission-amp-vision
- https://docs.continuumdao.org/ContinuumDAO/Governance/Constitution?id=continuumdao-proposals-and-voting
- https://docs.continuumdao.org/ContinuumDAO/Governance/HowToWriteAProposal

## Checklist (apply to draft or live proposal + forum OP)

**Vision / Mission (red if it fails).** The proposal must further creating public goods that connect web protocols/networks in a decentralized way, and decentralized MPC / trustless coordinated decision-making. If it does not **clearly** do that, it does not conform. Note the specific mismatch (unrelated spend, centralized control, no public-good / MPC / connectivity link).

**Type-fit (red if the chosen type does not match the fetched Constitution section).** After reading **ContinuumDAO Proposals and Voting**, the declared Type, Forum section, Bravo/Delta shape, and on-chain actions must match that definition. Use the fetched text as the source of truth. Typical fit (confirm against the fetch):

| Type | Forum `section` | Fits when | Does not fit |
|------|-----------------|-----------|--------------|
| Decision | `decision` | A DAO yes/no (or simple) decision; on-chain action optional | Multi-choice election; treasury transfer; constitution change; onlyGov/upgrade |
| Election | `election` | Multi-choice vote (e.g. Committee); Delta | Single For/Against outcome tagged Election |
| Treasury | `treasury` | Transfer of funds to a wallet (Linea or another chain) | Spend framed as Decision; no transfer when tagged Treasury |
| Constitution | `constitution` | Amends this Constitution / has effect on it; **must include the new Constitution text** | Tagged Constitution with no new document |
| Admin | `admin` | onlyGov contract changes, re-deploys, proxy upgrades on core contracts | Admin tag on a grant, election, or constitution rewrite |

Also red: Constitution-type missing the new Constitution text (and, if it passes, hash + document + hash-check code on [github.com/ContinuumDAO](https://github.com/ContinuumDAO)); Type/section mismatch; formal proposal under Ideas.

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

Also call out: no clear objectives; no community-discussion mention when the draft is a first post; re-submission with no material change / no pointer to the prior proposal.

**Ideas vs proposals.** Ideas & Suggestions is **pre-proposal discussion only** — not a Temperature Check and not a valid `forumKey`. If the operator is not ready for on-chain governance, or the ask does not fit a Constitution type, guide them to post an Idea (`forum_create_idea`) instead of composing a proposal. All formal proposals must appear in a **Governance** category that matches Type.

**Help draft (compose only).** Walk the operator through those headings. Choose Type from the fetched Proposals and Voting section (do not default to Decision when another type fits). Suggest wording that states how the work serves Mission & Vision. Do not invent facts.

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
<p style="color:#c0392b"><strong>Does not fit Constitution proposal type</strong><br>
- …</p>
<p style="color:#d68910"><strong>Missing Proposal Format elements</strong><br>
- …</p>
```

Use those colours (red `#c0392b`, amber `#d68910`). Do not put this block in the on-chain title.
