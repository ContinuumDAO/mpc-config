# ContinuumDAO vote cron and governor Join (policy templates)

Catalog jobs (default **disabled**):

| Job | Role |
|-----|------|
| **`appraise-and-vote-proposals`** | Create **vote** multi-sign requests only. Never propose, execute, cancel, Get Sig, or broadcast. |
| **`conditional-accept-governance-vote`** | Governor **Join** only: Accept/Reject `sign_request_agree`. Always **Reject** propose/execute/cancel. Skip trades. |

Trade Join stays on **`conditional-accept-sign-request`** (`sign_accept_policy.example.md`). That job **skips** ContinuumDAO governor types.

Load skills **`scheduled-automation`**, **`continuum-dao-proposals`**, **`continuum-dao-proposal-standards`**, **`continuum-dao-vote-policy`**. Copy `votePolicy` from the vote-policy skill into the job message if you customize it. **Never** load **`continuum-dao-compose-proposal`**. When `forumKey` is a topic URL, **read** the thread (`forum_resolve` / `forum_fetch_thread`); do not sign in, reply, react, or `forum_create_topic`. Fetch Constitution Vision/Mission and How to Write a Proposal via `get_continuum_doc`; non-conformance and missing format lean **against** / **nota**.

## Governor request types

From `get_sign_request_by_id({ compact: false })`: `evm.type` or `signatureText` JSON (`kind: ContinuumDAO`).

| type / name | Vote-create cron | Governor Join cron |
|-------------|------------------|--------------------|
| `continuum_dao_cast_vote` / `ContinuumDAO.castVote*` | May create (policy) | Accept only if stance matches votePolicy |
| `continuum_dao_propose` / `ContinuumDAO.propose` | **Forbidden** | **Always Reject** |
| `continuum_dao_execute` / `ContinuumDAO.execute` | **Forbidden** | **Reject** |
| `continuum_dao_cancel` / `ContinuumDAO.cancel` | **Forbidden** | **Reject** |
| Trade / escrow / other | Do nothing | **Skip** (no agree) |

Trusted proposers are **any EOA or contract**, not KeyGens. `keyGenId` is only who casts the vote.

## Non-interactive rules (both jobs)

- Do not ask questions or use elicitation.
- Do not call `trigger_sign_result` or `broadcast_sign_result`.
- Process **one** item at a time.
- If votePolicy is `skip` or the briefing is unknown → vote cron does **nothing**; Join **Rejects** a vote that does not match, **Rejects** propose, **Skips** unrelated requests.
- Cite `onchainId`, stance, and the failing/passing rule in Purpose or `thoughts`, plus an ISO 8601 UTC timestamp.

## Operator checklist

- [ ] Edit `votePolicy` on the node (trusted/blocked proposers, treasury, signatures)
- [ ] Set `keyGenId` for the vote-create job
- [ ] **Run now** each job once before enabling
- [ ] Do **not** enable both governor Join auto-Accept and `auto-sign-and-broadcast` unless you intend unattended chain execution
