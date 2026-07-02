# Execution policy (multiSign & on-chain actions)

Load this skill when the operator asks to **propose, sign, or broadcast** on-chain actions (transfers, compose calls, MPA top-ups, etc.) in **interactive agent chat**, KeyGen threads, or orchestrator follow-up — not for plan-mode manifest drafting alone.

Tool reference: continuum MCP **`mpc_docs`** (`mpc.md`), **`management-signer.md`**, and skill **`orchestration_planning`** for orchestration-specific cron/manifest rules.

## Before creating a multiSign request

1. **Resolve KeyGen and executor** — `get_preferred_key_gen` → `fetch_key_gen_result` for the EVM executor address (`ethereumaddress`).
2. **Gas options** — call **`get_multi_sign_gas_options`** with `chainId` (create) and/or `requestId` (Get Sig). Present fee tiers and **`useCustomGas`** choice to the operator when it matters.
3. **Quote / simulate** when the tool or chain supports it — surface amounts, recipients, and gas before submitting a proposal.
4. **One Accept/Reject round → one `requestId`** when multiple legs belong together:
   - Prefer **`create_compose_multi_sign_request`** (all `actions[]` in one call), or
   - **`create_joined_multi_sign_request`** to merge two helper payloads (chain for longer sequences).
   - Do **not** call several `create_*` / `ctm_*` tools that each return a separate `requestId` for the same operator round.

## Before Get Sig and Execute

- **Get Sig** (`trigger_sign_result`): confirm **`feeSpeedTier`** when gas is volatile; use `get_multi_sign_gas_options({ requestId })` if unsure.
- **Execute / broadcast**: require **explicit operator confirmation** in interactive chat unless they already confirmed the exact proposal (chain, amounts, addresses, nonce plan).
- After create, treat returned **`requestId`** as success — verify with **`list_sign_requests`** instead of re-calling the same build tool.

## Operator preferences (edit this section on your node)

| Preference | Default on this node |
|------------|----------------------|
| Confirm before broadcast | **Yes** — always ask unless operator said “broadcast now” with full params |
| Default fee speed (Get Sig) | Ask or use node `defaultGetSigFeeSpeed` from gas options |
| Allowed chains | *(list chain IDs or names your operators use)* |
| Max single transfer without extra confirmation | *(optional wei / USD limit)* |

## Secrets and safety

- **Never** echo Variable values, webhook secrets, API keys, or private key material in chat or KeyGen posts.
- **`list_environment_variables`** / agent Variables UI show **names** and `envConfigured` only — do not invent secret values.
- Prefer management-signed tools with the preferred Ed25519 signer; do not expose manual signing steps to the operator.

## When this skill does not apply

- **Plan chat** (`conversationPurpose: "plan"`) — draft orchestration YAML only; load **`orchestration_planning`** instead of executing txs there.
- **Fully automated cron/webhook turns** — load **`scheduled-automation`**; those runs cannot wait on human input.
