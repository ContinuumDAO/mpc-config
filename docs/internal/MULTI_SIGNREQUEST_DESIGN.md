# Multi SignRequest Design (Internal Evaluation)

**Status:** Draft for evaluation  
**Date:** 2025-03-14  
**Scope:** Design only — no code changes in this document.

---

## 1. Overview

This document describes a proposed **batch SignRequest** feature: a **single** SignRequest carries **N** message hashes (and optional N MessageRaw / metadata). One agree, one trigger, and a **single** SignResult is created. The originator retrieves each signature from the MPC network **individually** (e.g. by message index) and executes transactions in order. Order of execution is **not** enforced by the backend; it is left to the originator, with **consecutive nonces** (n, n+1, n+2, …) as the simple, recommended way to guarantee correct ordering on-chain.

Goals:

- Support “batch” signing for multiple transactions (e.g. approve then transfer, or a series of contract calls from a Forge script).
- Keep the data model simple: one request, one agree, one trigger, one SignResult holding N signatures (or N retrievable signatures).
- Avoid complex backend enforcement of execution order; rely on nonce discipline and optional nonce refresh.
- Optional future: derive the transaction list from a Forge script (e.g. via an AI agent that pushes script to GitHub and creates the batch SignRequest for other nodes to Agree/Reject).

---

## 2. Chosen Approach: Single Batch Request, Single SignResult

### 2.1 One SignRequest with N message hashes

- **Originator** creates **one** SignRequest that carries:
  - **N message hashes** (e.g. `MessageHashes[]` or repeated field), one per transaction.
  - Optionally **N MessageRaw** (or similar) for display/audit.
  - Optionally per-item metadata (e.g. SignatureText, ExtraJSON per index).
  - **Batch flag** so nodes and backend treat it as a batch (e.g. `BatchSignRequest: true`, `BatchSize: N`).
- Same PubKey, KeyList, and group as today. One request id for the whole batch.
- The request is sent to the group once (same mechanism as today: group topic + per-node topics).

### 2.2 One agree, one trigger

- **Other nodes** call **one** `signRequestAgree` on this single request when they are ready to agree to the **entire batch** (all N messages).
- When threshold+1 nodes have agreed, the originator calls **one** `triggerSignRequestById` for that request id.
- No “chain” of requests to receive or validate; no per-request agree. One request, one agree, one trigger.

### 2.3 Single SignResult; signatures retrieved per message

- After trigger, **one** SignResult is created for the batch (one request id, one result id).
- The MPC network produces **N** signatures (one per message hash). How they are stored is TBD: e.g. one SignResult with an array of signature data, or one SignResult that references N “slots.”
- The **originator** gets each signature **individually** from the MPC/backend, e.g.:
  - API such as `getSignResultById` returns the batch result, with a way to obtain the signature for message index `i` (e.g. `Signatures[i]` or `getSignResultSignatureByIndex(requestId, index)`).
  - Originator then: get signature for index 0 → execute tx 0 → get signature for index 1 → execute tx 1 → … in order, without the backend checking that tx i completed before “releasing” signature i+1.

So: **no backend enforcement of execution order**. The originator is responsible for executing in the correct order. Signatures for all N are available after trigger; retrieval by index (or by message hash) is just for convenience and clarity.

### 2.4 Execution order: nonces, not backend checks

- **Why not enforce “tx i must complete before next signature”?**  
  That would require the backend to track on-chain execution (e.g. polling or listening for tx receipt) before allowing the next signature to be used or exposed. That is heavy and chain-dependent; we avoid it.

- **Simpler: consecutive nonces.**  
  For EVM (and similar chains), the batch is built with **consecutive nonces** (e.g. n, n+1, n+2, …, n+N−1). The originator must execute in order so that nonces are consumed in sequence; the chain enforces ordering. No backend logic needed.

- **Updating the start nonce.**  
  The list may have been built with a start nonce that is now stale (e.g. other txs were executed in the meantime). At **trigger time** (or when the originator prepares the final payload), we can allow **updating the start nonce** for the batch so that all N nonces (start, start+1, …) are refreshed in one go. Optionally, the same nonce-refresh behavior can apply to **single-transaction** flow (see §6.4).

### 2.5 Summary of chosen design

| Aspect | Current (single / multi-agree) | Batch SignRequest (chosen) |
|--------|--------------------------------|----------------------------|
| Request shape | One request, one MessageHash | One request, **N** MessageHashes (and optional N MessageRaw) |
| Agree | One agree per request | One agree for the whole batch |
| Trigger | One trigger → one SignResult | One trigger → **one** SignResult (with N signatures) |
| Signatures | One signature per result | Originator gets each of N signatures **individually** (by index or message hash) from the single result |
| Execution order | N/A | **Not** enforced by backend; originator executes in order; **consecutive nonces** recommended |

---

## 3. Data Model / Protocol Concepts (For Evaluation)

These are **conceptual** only; actual field names and storage are TBD.

### 3.1 SignRequest (extended for batch; not a separate type)

We **extend the existing SignRequest** with optional batch fields. There is no separate “BatchSignRequest” message type: the same SignRequest is used; when batch fields are set, it is treated as a batch of N messages.

- **Batch metadata** (optional; when present, this SignRequest is a batch):
  - `BatchSignRequest: true` (flag: this request is a batch)
  - `BatchSize`: N (number of messages in the batch).
- **Repeated / array fields** (when batch):
  - `MessageHashes`: list of N message hashes (replacing single `MessageHash` for batch).
  - `MessageRaw`: optional list of N raw messages (or single blob; TBD).
  - Optionally per-index metadata (e.g. `SignatureText[]`, `ExtraJSON[]`) if needed for UI or audit.
- Existing fields (KeyList, PubKey, DestinationChainID, etc.) stay; for batch, MessageHash/MessageRaw are the array variants above.

### 3.2 Agree semantics

- For a request with `BatchSignRequest == true`:
  - One `signRequestAgree` means “I agree to sign **all** N messages in this batch.”
  - No per-message agree; no chain of requests to receive.

### 3.3 SignResult (single result, N signatures)

- **One** SignResult per batch request (one request id → one result).
- The result holds **N** signatures (e.g. `Signatures[]` or N signature slots keyed by index or message hash).
- Originator retrieves signature for message index `i` via existing or new API (e.g. `getSignResultById` returning batch with `Signatures[i]`, or `getSignResultSignatureByIndex(requestId, index)`).
- No “next” pointer; order is implicit (array index 0 .. N−1).

### 3.4 Trigger

- One `triggerSignRequestById` for the batch request id.
- Backend creates **one** SignResult, runs MPC to produce **N** signatures (one per message hash), and stores them in that single result. No chaining of multiple SignResults.

### 3.5 Batch execution: concurrency and “too many” transactions

- **All N are signed in parallel.** On trigger, the backend starts **N** TSS sign workers at once (one per message hash). There is no staggering or queue: all workers are started in a loop with no delay. Each worker runs a full TSS signing round (multi-round protocol with the other nodes in the group).
- **No batch-size limit today.** The code does not enforce a maximum N. Very large N can lead to:
  - **Resource use:** N concurrent workers each doing CPU-heavy crypto and network I/O; memory and goroutines scale with N.
  - **Channel pressure:** The worker pool uses a shared message channel (capacity scales with pool capacity, not with N). If N is large, many workers can produce a lot of messages; in theory the channel could block or slow down delivery.
  - **Timeouts:** Each sign worker is subject to a timeout (e.g. 5 minutes). If the system is overloaded, more rounds may time out.
- **Presign vs normal sign:** The presign path applies a threshold (e.g. 100 workers) and adds delay when above that; the **batch sign path does not** use that throttling.
- **Recommendation:** Keep batches moderate (e.g. single-digit to low tens of transactions). For very long scripts, split into multiple batch SignRequests (e.g. 10 + 10) or add a configurable batch-size limit / throttling in a future change.

---

## 4. Forge Script → Transaction List: Feasibility

### 4.1 What “Forge” means here

- **Forge** (Foundry) scripts (`forge script`) simulate and/or broadcast a sequence of transactions (deploy, configure, transfer, etc.). The script is Solidity and can call many contracts and emit many txs.
- The idea: get from “a Forge script” to “a list of transactions” that the MPC nodes can agree on, then sign in order.

### 4.2 Can we get a list of transactions from a Forge script?

**Short answer: yes, in principle, but it is tooling-dependent and has caveats.**

- **Dry-run / simulation:**  
  `forge script` can be run in a “dry run” or simulation mode. Foundry records what transactions **would** be broadcast (to, data, value, etc.). So the **ordered list of transaction payloads** can be derived by running the script off-chain (or in CI) and capturing the planned txs.

- **Ways to get the list:**
  1. **Foundry’s JSON output:**  
     Script runs can output JSON (e.g. `--json`) with transaction-like structures. Parsing that and mapping to (to, data, value, chainId, etc.) gives a deterministic list.
  2. **Custom wrapper:**  
     A small tool or script that runs `forge script ...` and parses stdout/JSON to produce a “transaction list” schema (e.g. one entry per tx: messageHash or raw tx fields).
  3. **Re-execution and nonce ordering:**  
     If the script is deterministic (same RPC state, same deployer key), the order of txs is fixed. So “transaction list” = ordered list of (unsigned) tx payloads that the script would emit.

- **Caveats:**
  - **Nonce / state:**  
    The list is valid for a **given** state (nonce, contract addresses). If the MPC wallet’s nonce or on-chain state changes before execution, the list might be stale (e.g. wrong nonce, wrong address).
  - **Dynamic behavior:**  
    Scripts that branch on chain state or time may produce different lists in different runs. For “AI creates script → push to GitHub → derive list,” we’d want deterministic scripts or explicit versioning of “this list corresponds to this script + this commit + this run.”
  - **Gas / fees:**  
    Gas and fee parameters might need to be chosen at **signing** time (or at trigger time), not at “list creation” time, so the exact bytes to sign might be finalized only when the originator triggers.

So: **feasible** to take a Forge script and create a list of transactions from it, with clear boundaries (determinism, state, who runs the script, and when).

### 4.3 AI agent on a node: script → GitHub → transaction list for Agree/Reject

**Idea:** An AI agent on a node drafts a Forge script, pushes it to a GitHub repo the node controls, then derives the transaction list and creates **one batch SignRequest** (N message hashes in a single request) for other nodes to Agree/Reject.

**Feasibility:**

- **Technically feasible:**  
  - Node (or attached service) has Forge + git; runs the script (e.g. in CI or sandbox); parses output to build the ordered list of N transaction payloads (e.g. N message hashes).  
  - Same node (or trusted process) calls the batch SignRequest API once with the N message hashes (and optional N MessageRaw).  
  - Other nodes see one request (the batch); they agree once to the whole batch.

- **What the agent needs:**  
  - Access to run `forge script` (and optionally to clone/push to GitHub).  
  - A defined schema for “transaction list” (e.g. one messageHash per step, optional raw tx fields).  
  - Logic to build one batch SignRequest (BatchSignRequest: true, BatchSize: N, MessageHashes: [h1, h2, …, hN]).  
  - No chain of requests; one request, one agree, one trigger, one SignResult with N signatures.

- **Risks / considerations:**  
  - **Trust:** Other nodes are agreeing to a **batch** produced by the originator (or its agent). They need enough context (e.g. ExtraJSON, Purpose, or KeyGen messaging) to understand what they’re agreeing to.  
  - **Reproducibility:** Linking the batch to “this GitHub repo + this commit + this script path” (e.g. in ExtraJSON) would let nodes (or auditors) re-run the script and verify the list.  
  - **Security:** The node that runs the script and pushes to GitHub must be locked down; the script runs in a controlled environment to avoid supply-chain or dependency attacks.

**Conclusion:** Feasible. Best supported by: (1) a clear “transaction list” schema, (2) optional metadata (repo, commit, script path) in the batch SignRequest, and (3) documentation for the AI agent workflow (create script → push → derive list → create one batch SignRequest).

---

## 5. Alternative Ideas (Not Chosen)

- **Chain of N separate requests (previous design):**  
  N SignRequests (1 of N, 2 of N, …), each referencing the previous. One agree on the first after receiving all N; N SignResults with “next” pointers. More complex (ordering, partial send, chain validation); dropped in favour of one batch request.

- **Agree on each of N requests, but lock order:**  
  Nodes agree to each of 1..N separately; trigger only when all N have threshold+1 and form a valid chain. More flexible (e.g. partial agreement) but more complex and ambiguous (“I agreed to 3 but not 4”).

- **Two-phase: “propose list” then “sign list”:**  
  Phase 1: originator sends a “multi sign proposal” (list of N items); nodes agree. Phase 2: system creates batch SignRequest and SignResult. Clear “approve plan” vs “sign,” but extra message types and flows.

- **Forge integration as optional plugin:**  
  A separate service (or container) that runs Forge script, produces the transaction list, and calls the batch SignRequest API. No change to MPC core; AI agent uses this plugin.

---

## 6. Problems and Potential Fixes

### 6.1 Rejecting one item in the batch

- **Problem:** A node wants to agree to messages 1–4 but reject 5.  
- **Fix:** With one agree for the whole batch, it’s “all or nothing.” Document this. Alternatively allow per-index reject and define threshold semantics (e.g. “agree to full batch only”); all-or-nothing is simpler.

### 6.2 Nonce and EVM ordering (batch)

- **Problem:** For EVM, the batch was built with nonces n, n+1, …, n+N−1. If the wallet has since used nonce n (or more), those signatures would be stale or invalid.  
- **Fix:** (1) **Consecutive nonces:** Require or recommend that the batch use consecutive nonces (n, n+1, …) so execution order is unambiguous and no backend check is needed. (2) **Update start nonce at trigger:** At trigger time, allow the originator (or backend) to refresh the start nonce for the batch (e.g. from chain or from getRemainingNonces), and rebuild the N message hashes with the new nonces before MPC signs. That way the signed payloads match current chain state.

### 6.3 Nonce staleness for single-transaction flow (existing)

- **Problem:** Even for **existing** single-transaction sign requests, the nonce baked into the message hash at creation time can become stale if other txs are executed before trigger.  
- **Fix:** Consider **always** checking whether the nonce is stale at trigger time (or when preparing the sign payload), and allow updating it (e.g. from chain or getRemainingNonces) before the MPC signs. Same idea as batch nonce refresh: apply to both batch and single-tx so behaviour is consistent and users don’t hit “invalid nonce” after agree.

### 6.4 Trigger and single SignResult with N signatures

- **Problem:** Today trigger creates one SignResult with one signature. For batch, one trigger must produce **one** SignResult that holds **N** signatures.  
- **Fix:** Trigger logic for a batch request: (1) Validate batch (BatchSignRequest, BatchSize, MessageHashes length). (2) Optionally refresh nonces and recompute message hashes if supported. (3) Run MPC to produce N signatures (N TSS rounds, one per message). (4) Create **one** SignResult and store the N signatures (e.g. array or keyed by index). (5) Expose API for originator to get signature by index (or by message hash).

### 6.5 Listing and UI

- **Problem:** listSignRequests / listSignRequestsReady should show batch requests clearly (e.g. “Batch of 5”, not “1 of 5”).  
- **Fix:** Add optional fields (BatchSignRequest, BatchSize). Clients show one row per request; for batch, display “Batch of N” and optionally expand to show the N message hashes or metadata.

### 6.6 Backward compatibility

- **Problem:** Existing clients and nodes don’t send or expect batch fields.  
- **Fix:** All new fields optional. If BatchSignRequest is absent or false, request is treated as single-message (existing MessageHash/MessageRaw); one agree, one trigger, one SignResult with one signature. No change to existing signRequest or signRequestAgree contracts.

---

## 7. Suggested Next Steps (If Proceeding)

1. **Define the batch schema** by extending SignRequest (add optional BatchSignRequest, BatchSize, MessageHashes[], optional MessageRaw[] and per-index metadata) and SignResult (add N signatures, e.g. array or keyed by index); add to protob/datatype.proto and DB when moving to implementation.
2. **Design trigger path** for batch: one trigger → one SignResult with N signatures; MPC runs **N rounds** (one TSS signing round per message).
3. **Define API for per-message signature retrieval** (e.g. getSignResultById returning batch with Signatures[], or getSignResultSignatureByIndex(requestId, index)) so the originator can get each signature individually and execute in order.
4. **Nonce refresh:** Design support for updating start nonce (and thus N message hashes) at trigger time for batch; consider **always** checking and allowing nonce refresh at trigger for **single-transaction** flow as well, so nonce staleness is handled consistently.
5. **Define "transaction list" schema** for the Forge → batch use case (and optional AI agent): one canonical format (e.g. ordered list of messageHash + optional raw tx fields) so that any tool (Forge wrapper, agent) can produce the batch payload.
6. **Document the AI + GitHub workflow** in a separate short doc (run Forge, push to GitHub, derive list, create one batch SignRequest, metadata for reproducibility and trust).

---

## 8. Summary

- **Batch SignRequest (chosen):** One SignRequest with N message hashes; one agree, one trigger; **one** SignResult with N signatures. Originator retrieves each signature individually (by index) and executes in order. No backend enforcement of execution order; **consecutive nonces** (n, n+1, …) recommended; optional **start nonce update** at trigger for the batch.
- **Nonce staleness:** Consider **always** checking and allowing nonce refresh at trigger for both batch and **single-transaction** flow, so stale nonces are avoided consistently.
- **Forge script → transaction list** is feasible (dry-run, JSON, wrapper); an **AI agent that pushes script to GitHub and creates one batch SignRequest** for other nodes to Agree/Reject is feasible with a clear schema and security boundaries.
- Main design choices: batch = one request/one result, all-or-nothing agree, no execution-order enforcement by backend, nonce discipline and optional refresh. No code in this doc; next step is to refine schema and trigger/API behaviour, then implement.
