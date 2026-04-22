# Uniswap V4 + MPC: end-to-end swap flow (internal, AI agents)

This note is for **operators and AI agents** wiring Uniswap’s **Trade API** to this repo’s **multiSignRequest** + **executeSignResult** pipeline. Environment variables and management API patterns are documented in `docs/skill/SKILL.md` and `docs/references/API_IMPLEMENTATION.md`.

## Prerequisites (Uniswap Trade API)

Scripts that call Uniswap’s HTTP API need a **Trade API key** (sent as the **`x-api-key`** header):

| Variable | Role |
|----------|------|
| **`UNISWAP_TRADE_API_KEY`** | Required for `uniswap_trade_quote.py` and `uniswap_trade_swap.py`. Alternative: **`--api-key`** on the command line. |
| **`UNISWAP_TRADE_BASE_URL`** | Optional. Default `https://trade-api.gateway.uniswap.org/v1`. Override if Uniswap documents a different base. |
| **`UNISWAP_UR_VERSION`** | Optional. Default `2.0`; sets **`x-universal-router-version`**. Match across quote → swap. |

Obtain or rotate keys in the [Uniswap developer dashboard](https://developers.uniswap.org/dashboard/welcome). Details also appear in each script’s module docstring and `--help`.

**No Uniswap API key:** `permit2_keygen_params.py`, `permit2_approval.py`, and `uniswap_swap_multisign.py` only talk to your **MPC management API** (and optionally **JSON-RPC** for Permit2 allowance reads). They do not call the Trade API.

**Python:** Use the dependencies noted in `docs/skill/SKILL.md` / `scripts/requirements-keygen-agent.txt` where those scripts apply (`eth_account`, etc.).

## What you are building

Two **separate** on-chain concerns:

1. **Permit2 (optional but common):** An **EIP-712** `PermitSingle` message. The MPC signs **`msgHash`** for typed data—**not** an RLP transaction. `scripts/executeSignResult.py` **does not** broadcast that as a raw EVM tx; it prints next steps (see that script’s docstring).
2. **Universal Router swap:** A normal **EVM transaction** (`to`, `data`, `value`). You build a **`multiSignRequest`** whose `bodyForSign` matches that unsigned tx; after TSS you **do** use `executeSignResult.py` to broadcast and wait for receipts.

## Recommended order of operations

### 1. Quote (Trade API)

Run `uniswap_trade_quote.py` with **Uniswap API key**, **MPC wallet** as swapper (`KEYGEN_ID` / `--key-gen-id`), **chain**, **tokens**, **amount**. Save the JSON (or the one-line quote for handoff).

- Script: `uniswap_trade_quote.py` (this folder)
- Output includes fields useful for Permit2 and for `POST /v1/swap`.

### 2. Permit2 path (when the quote uses Permit2)

Use the quote to configure **Permit2** allowance parameters:

- `permit2_keygen_params.py` — derives nonces, deadlines, spender, and kwargs for the approval recipe.
- `permit2_approval.py` — emits **`POST /multiSignRequest`** for the **EIP-712** permit digest (not calldata).

After **multi-agree** completes, use the returned **secp256k1** signature in the flow your stack expects (e.g. bundled with the swap or as input to Trade API—see Uniswap docs for `signature` / `permitData` on **`POST /v1/swap`**).

If your integration uses **`x-permit2-disabled: true`** and classic token **approval** elsewhere, you can skip this block; keep **Universal Router version** headers consistent across quote → swap.

### 3. Create swap calldata (Trade API, no chain tx)

Call **`POST /v1/swap`** via `uniswap_trade_swap.py`: pass the **quote** object, and when required the **signed permit** (`--signature`) and/or **`permitData`** (`--permit-json` / file). This returns JSON with a top-level **`swap`** object (`to`, `data`, `value`, `chainId`, gas fields).

- Script: `uniswap_trade_swap.py` (this folder)

### 4. Turn swap JSON into `multiSignRequest` (MPC)

From the **full create-swap response**, run:

- `uniswap_swap_multisign.py` — builds **`bodyForSign`**, **`messageToSign`**, **`txParams`**, **`triggerTxParams`**, etc., aligned with `generateMultiSignRequestFromCompose.build_compose_multisign`.

Submit **`POST /multiSignRequest`** (plus any **clientSig** / **signedMessage** your node requires). Wait until the sign request reaches **success** (TSS signatures present).

### 5. Execute on chain

Run `scripts/executeSignResult.py` for this **swap** sign request id (with management URL, optional `--sign-request-file` holding `bodyForSign`, RPC as documented). The script triggers if needed, polls sign results, rebuilds the unsigned tx from stored **txParams**, signs with MPC output, **broadcasts**, and **waits for transaction receipts**.

### 6. Close the loop in the management API

After successful broadcast, follow the stderr instructions: **`POST /updateSignResultStatusById`** with **`executed`** and the **transaction hash(es)** so the node and peers record execution.

## Minimal checklist for an AI agent

| Step | Artifact |
|------|-----------|
| Quote | `uniswap_trade_quote.py` → quote JSON |
| Permit2 (if used) | `permit2_keygen_params.py` → `permit2_approval.py` → `POST /multiSignRequest` → TSS success → signature for swap request body |
| Swap calldata | `uniswap_trade_swap.py` → JSON with `swap` |
| EVM sign request | `uniswap_swap_multisign.py` → `POST /multiSignRequest` → TSS success |
| Broadcast | `scripts/executeSignResult.py` |
| Status | `POST /updateSignResultStatusById` (`executed` + tx hash) |

## Purpose and `extraJSON` (Permit2 round vs swap round)

Each **`multiSignRequest`** is its own record: a **separate** `messageToSign` and sign-request id. Nothing in the API **requires** the second request to repeat the first request’s **purpose** text.

- **`purpose` (max 256 chars):** Use **round 1** to describe what other nodes are approving for the **EIP-712 Permit2** sign (the `permit2_approval` defaults tie this to the *intended* trade). Use **round 2** to describe the **on-chain swap** (Universal Router / `multiSignRequest` for the EVM tx). You *may* reuse similar wording for consistency in `listSignRequests`, but a **blind copy** of the permit-only blurb is easy to misread in round 2; prefer a **short, swap-specific** line for the second request (e.g. “Uniswap Universal Router swap — chain 42161”).

- **`extraJSON`:** **Not** needed for a correct **`msgHash`** (the hash is the unsigned tx in round 2, or the typed-data hash in round 1). It is **optional** metadata for operators and peers (see `docs/references/API_IMPLEMENTATION.md`). The **Permit2** recipe often puts **`permit2` audit** and optional **`uniswapTradeQuote`** there so reviewers see quote context. The **swap** recipe can leave **`extraJSON`** minimal; when you do **not** use `--no-custom-gas-params`, `generateMultiSignRequestFromCompose` may still add **`customGasChainDetails`** in `extraJSON` for the same “custom gas” disclosure as other compose flows—that is **not** the same as pasting a full Trade API quote. Duplicating the full quote JSON on the **swap** request is **optional** and only for traceability, not for signing correctness.

## Related files

| File | Role |
|------|------|
| `uniswap_trade_quote.py` | `POST /v1/quote` |
| `uniswap_trade_swap.py` | `POST /v1/swap` |
| `permit2_keygen_params.py` | Permit2 + quote alignment |
| `permit2_approval.py` | Permit2 **multiSignRequest** (EIP-712 hash) |
| `uniswap_swap_multisign.py` | Router **multiSignRequest** (EVM tx hash) |
| `scripts/executeSignResult.py` | Trigger, sign, broadcast **EVM** txs; **skips** raw broadcast for PermitSingle permit-only results |
| `scripts/generateMultiSignRequestFromCompose.py` | Shared compose / `preencodedData` mechanics used by `uniswap_swap_multisign` |

Re-running gas or nonce-changing steps (new quote, new `multiSignRequest` run) changes **`msgHash`**; do not mix outputs from different runs for the same sign request.
