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

**Python:** Use the dependencies noted in `docs/skill/SKILL.md` / `scripts/requirements-keygen-agent.txt` (`eth_account`, `PyNaCl`, etc.).

**`uniswap_mpc_helpers.py`** and **`uniswap_v4_skip_permit2_batch_multisign.py`** only talk to your **MPC management API** and chain **JSON-RPC** (no Uniswap HTTP key required for those steps).

## Flow (aligned with continuumdao-node-app)

Quotes and swap calldata send Uniswap’s **classic ERC-20 allowance** header **`x-permit2-disabled: true`** (required header name from the Trade API). Routing then expects **ERC-20 `approve` + swap** (and, when Trade targets the Universal Router directly, an extra on-chain **allowance-hub `approve` toward the router** in the same batch — see the batch builder).

1. **Dispatcher route** (`swap.to` ≠ inner router in calldata): **2 txs** — `ERC20.approve(swap.to)`, then swap.
2. **Direct router route** (`swap.to` equals inner router): **3 txs** — `ERC20.approve(allowance hub)`, allowance hub **`approve(token, router, amount, expiration)`**, then swap.

### 1. Quote (`POST /v1/quote`)

`uniswap_trade_quote.py` — outputs `uniswapTradeQuote` plus `uniswapBatchRecipe` hints.

### 2. Create swap calldata (`POST /v1/swap`)

`uniswap_trade_swap.py` — same **`x-universal-router-version`** as the quote. No separate permit signature in the request body.

### 3. Build **`POST /multiSignRequest`** (batch)

- **`uniswap_v4_skip_permit2_batch_multisign.py`**, or  
- **`uniswap_swap_multisign.py --batch-approve-and-swap`**

You need: create-swap JSON, quote snapshot with classic **`quote.input.amount`**, and **`--token-in`**. Optional: **`--swap-deadline-unix`**, **`--slippage-percent`** (e.g. EXACT_OUTPUT).

Example:

```bash
python3 recipes/uniswapV4/uniswap_trade_quote.py ... > quote.json
python3 recipes/uniswapV4/uniswap_trade_swap.py --quote-file quote.json > swap.json
python3 recipes/uniswapV4/uniswap_v4_skip_permit2_batch_multisign.py \
  --key-gen-id "$KEYGEN_ID" \
  --swap-file swap.json \
  --quote-file quote.json \
  --token-in 0x... \
  --swap-deadline-unix 1735689600
```

### 4. Execute on chain

`scripts/executeSignResult.py` for this sign request id (batch: multiple txs in order).

### 5. Status

**`POST /updateSignResultStatusById`** with **`executed`** and transaction hash(es).

## Minimal checklist for an AI agent

| Step | Artifact |
|------|-----------|
| Quote | `uniswap_trade_quote.py` → JSON |
| Swap calldata | `uniswap_trade_swap.py` → JSON with `swap` |
| EVM batch sign request | `uniswap_v4_skip_permit2_batch_multisign.py` or `uniswap_swap_multisign.py --batch-approve-and-swap` |
| Broadcast | `scripts/executeSignResult.py` |
| Status | `POST /updateSignResultStatusById` |

## Purpose and `extraJSON`

**`extraJSON`** includes **`batchMeta`** (per-index labels) and optional **`customGasChainDetails`** when using configured gas. The last batch item’s **`uniswapV4`** blob holds audit metadata (quote snapshot, approve path, gas build source).

## Related files

| File | Role |
|------|------|
| `uniswap_mpc_helpers.py` | KeyGen owner resolution; Universal Router address map |
| `uniswap_trade_quote.py` | `POST /v1/quote` |
| `uniswap_trade_swap.py` | `POST /v1/swap` |
| `uniswap_v4_skip_permit2_batch_multisign.py` | Batch `multiSignRequest` |
| `uniswap_swap_multisign.py` | `--batch-approve-and-swap` or legacy single-tx calldata compose |
| `scripts/executeSignResult.py` | Trigger, sign, broadcast |
| `scripts/generateMultiSignRequestFromCompose.py` | Shared compose / signing-hash helpers |

Re-running gas or nonce-changing steps changes **`msgHash`** / **`messageHashes`**; do not mix outputs from different runs for the same sign request.
