# AI Agent Guide: Creating `POST /multiSignRequest` payloads

This is the **home doc** for anything that produces a **`POST /multiSignRequest`** body (multi-agree keys only). **POST /signRequest** is for **tx-check / relayer** keys only.

## How you may build `multiSignRequest` payloads (strict)

Valid **EVM unsigned-transaction** payloads must include correct **`msgHash`** / **`messageHashes`**, **`messageRawBatch`**, **`txParams`** alignment for trigger/execute, and **`extraJSON`** / batch metadata where required. Agent automation in this repo assumes **broadcastable EVM transactions** only; **`./API_IMPLEMENTATION.md`** § **`POST /triggerSignRequestById`** describes **`txParams`** / **`messageHash`** / **`txParamsBatch`**. **`bodyForSign` / `messageToSign` must include a `purpose` string** (use `""` when unused); mpc-auth always treats **`purpose`** as part of the signed JSON (see **`./API_IMPLEMENTATION.md`** § **`POST /multiSignRequest`**). **Do not** invent or hand-edit **`multiSignRequest`** JSON from scratch: the message must reflect **TxParams**, signing hashes, and app parity rules documented in **`./API_IMPLEMENTATION.md`** and the helper scripts.

**Agents are expected to `POST /multiSignRequest`** with bodies produced **only** by the supported paths below (helpers and recipes). The mistake to avoid is fabricating JSON without those tools—not avoiding the endpoint.

The **only** supported ways to obtain a new **`multiSignRequest`** body are:

1. **Recipes** — run the supplied scripts under **`$MPA_PATH/recipes/`** (see [Recipes table](#recipes-table) below). They call **`generateMultiSignRequestFromCompose.py`** with the right **`GET /getKeyGenResultById`** / **`GET /getChainDetails`** behavior.
2. **Compose helper** — **`$MPA_PATH/scripts/generateMultiSignRequestFromCompose.py`** when you have (or build) **compose JSON** (function signature, parameters, chain id), matching the **Compose** flow in **`continuumdao-node-app`**. See [Compose JSON](#compose-json-schema) below.
3. **Foundry helper** — **`$MPA_PATH/scripts/generateSignRequestWithFoundryScript.py`** with **`forge script`** output (**`run-latest.json`**), together with Foundry as described in **`./AI_AGENT_FORGE_SIGNREQUEST.md`**.

For **two** helper outputs merged into **one** batch proposal, use **`$MPA_PATH/scripts/multiSignJoin.py`** (see **`../skill/SKILL.md`** and **`multiSignJoin.py --help`**).

**Output is a first-class payload:** stdout has the same **`bodyForSign`** / **`messageToSign`** envelope as the other helpers. Add **`clientSig`** / **`signedMessage`**, then **`POST /multiSignRequest`**—**never** edit the merged JSON by hand except via this tool.

**Chaining (complicated sequences):** each run only joins **two** files. To build longer ordered sequences on the **same chain**, run **`multiSignJoin.py`** again: use the **previous run’s saved stdout** as **`--a`** or **`--b`**, and the next recipe/helper JSON as the other input. **`--first-nonce`** must be the MPC **`cast nonce`** (or equivalent) for the **first** transaction in the **combined** result after that merge. You can repeat this as many times as needed (e.g. approve → swap → bridge steps), still **only** through helper outputs and **`multiSignJoin`**—not hand-built JSON.

**Management signing** (**clientSig**, nonces, **signedMessage**) is documented in **`./ED25519_MANAGEMENT_KEY_SIGNING.md`** (Ed25519) and **`./AI_AGENT_FORGE_SIGNREQUEST.md`** (shared **messageToSign** rules).

---

## Compose JSON → helper (manual compose)

This section is for agents that build **compose JSON** (function signature, Solidity parameters, chain id)—the same conceptual input as the **Compose** panel in **`continuumdao-node-app`** (manual mode, not Foundry import). Run **`$MPA_PATH/scripts/generateMultiSignRequestFromCompose.py`**.

**Foundry path:** For transactions produced by **`forge script`** and **`run-latest.json`**, use **`generateSignRequestWithFoundryScript.py`** and **`./AI_AGENT_FORGE_SIGNREQUEST.md`** instead of compose JSON.

### Checklist (multiSignRequest)

1. **Resolve** **`keyGenId`**, the MPC wallet **`from`** address, and the **management API base URL** for the node you call (e.g. **`GET /getKeyGenResultById`**, environment such as **`KEYGEN_ID`** / **`AUTH_KEY_PATH`**, port from **`configs.yaml`** or the operator).
2. **Build** the unsigned **`POST /multiSignRequest`** body with a repo helper: **`$MPA_PATH/scripts/generateSignRequestWithFoundryScript.py`** (Foundry) or **`$MPA_PATH/scripts/generateMultiSignRequestFromCompose.py`** (compose JSON), following **`./AI_AGENT_FORGE_SIGNREQUEST.md`** or **this document**.
3. **Review** **`Purpose`** (≤256 characters) and transaction fields (chain id, calldata, gas, nonces) against group intent and messages.
4. **Sign for HTTP:** add **management** **`clientSig`** (and any other fields **`./API_IMPLEMENTATION.md`** requires for your deployment).
5. **Submit and complete the lifecycle:** **`POST /multiSignRequest`** → peers **`POST /signRequestAgree`** → when ready, **AI agents** use **only** **`$MPA_PATH/scripts/executeSignResult.py`**: it **`POST`**s **`/triggerSignRequestById`** with **`txParams`** and **`messageHash`** (or **`txParamsBatch`** for batch), polls **`getSignResultById`**, and broadcasts (see **`../skill/SKILL.md`**). Do **not** call **`POST /triggerSignRequestById`** or broadcast **directly** from the agent. Then **`POST /updateSignResultStatusById`** (when applicable). Human operators: **`./instructions.md`** and **`./API_IMPLEMENTATION.md`** § **`POST /triggerSignRequestById`**.

---

## Management API URL

Point **`--mpc-auth-url`** at the node’s **management HTTP API** as **`$MPC_AUTH_URL:$MANAGEMENT_PORT`**. `MPC_AUTH_URL` should be host-only (for example `http://127.0.0.1` or `http://<IP>`), and `MANAGEMENT_PORT` should be the numeric `ManagementAPIsPort` in `configs.yaml`. Load these from **`$MPA_PATH/.env`** when present (**`../skill/SKILL.md`** **Environment**).

The script calls:

- **`GET /getKeyGenResultById?id=<keyGenId>`** — `keyList`, `pubKey`, MPC `ethereumaddress`, optional **`ClientKeys`** → **`clientId`**
- **`GET /getChainDetails?chain_id=<n>`** — when **`rpcGateway`** is omitted from compose JSON (to read the node’s stored RPC and gas settings, matching the app’s **OK** submit path)

It also performs **JSON-RPC** against that RPC (`eth_getTransactionCount`, `eth_estimateGas`, `eth_gasPrice`, latest block / EIP-1559 fields).

---

## Goal

1. Build (or receive) one **compose JSON** object describing one or more contract calls (signature + args + destination contract), plus **destination chain** and optional gas behavior.
2. Run **`$MPA_PATH/scripts/generateMultiSignRequestFromCompose.py`** to obtain **`bodyForSign`** and **`messageToSign`** (same convention as the web app before management signing).
3. Add **`clientSig`** (and **`signedMessage`** for MetaMask-style management keys), then **POST /multiSignRequest**.

The script fills **`keyList`** and **`pubKey`** from the node. It computes **EVM tx signing hashes** using the same helpers as the Foundry script so **`msgHash`** / **`messageHashes`** match **unsigned EIP-1559 / legacy** serialization. The numbered **Checklist** at the top of this file is the same sequence as **`./instructions.md`**.

---

## Install dependencies (required)

**Both** packages are **mandatory** (the script imports **PyNaCl** at startup). Use the venv at **`$MPA_PATH/.venv`** (create with **`python3 -m venv "$MPA_PATH/.venv"`** if missing). Full bootstrap and verification: **`../skill/SKILL.md`** **Python dependencies**.

```bash
"$MPA_PATH/.venv/bin/pip" install eth-account PyNaCl
```

- **`eth_account`** brings **`eth_abi`** / **`eth_utils`** for ABI encoding and optional EIP-191 signing.
- **`PyNaCl`** is required even if you only print **`bodyForSign`** and sign elsewhere; the module fails immediately if it is missing.

---

## Compose JSON schema

Top-level fields (the script also accepts common **snake_case** aliases where noted):

| Field | Required | Description |
|-------|----------|-------------|
| **`keyGenId`** | Yes | Key generation request id (`key_gen_id` alias). |
| **`destinationChainId`** | Yes | Decimal string, e.g. `"11155111"` (`destination_chain_id`). |
| **`composeActions`** | Yes | Non-empty array of actions (`compose_actions`). |
| **`rpcGateway`** | No | If set, used as the JSON-RPC URL for nonce, estimateGas, and fee discovery. If omitted, the script loads RPC from **`GET /getChainDetails`** (`rpc_gateway` alias). |
| **`purpose`** | No | Short text (app limit 256 chars for display on agree). |
| **`noCustomGasParams`** | No | When **true**, ignores **`getChainDetails`** gas fields and estimates gas limit and fees only from the RPC. When **false** or omitted (default), uses each gas-related field from chain config when set, and RPC estimates for missing fields. |
| **`clientId`** | No | Override; otherwise first non-empty value from **`getKeyGenResultById`** → **`ClientKeys`** / **`clientkeys`**. |

Each **compose action** object:

| Field | Required | Description |
|-------|----------|-------------|
| **`signature`** | Yes | Function signature text, e.g. **`transfer(address,uint256)`** (same as app / `encodeActionCalldata`). |
| **`destinationContract`** | Yes | Called contract address (`destination_contract`). |
| **`inputs`** | Yes | Array of **`{ "name", "type", "value" }`** in parameter order. Types follow Solidity ABI strings (`address`, `uint256`, `uint256[]`, etc.). |
| **`paramUnits`** | No | Map **index as string** → **`Wei`** \| **`Ether`** \| **`Gwei`** \| **`USD`**. Applies only to **`uint256`** and **`uint256[]`**, same as the app (`param_units`). |
| **`estimatedGas`** | No | If set and &gt; 0, used as gas limit. Otherwise, when **`noCustomGasParams`** is false and chain **gasLimit** is set, the limit is **`max(chain gasLimit, eth_estimateGas)`** so a low chain default (e.g. 21000) cannot underfund a contract call. When chain **gasLimit** is empty, **`eth_estimateGas`** is used. |
| **`gasPriceWei`** | No | Legacy: if set, used as gas price (wei); else RPC (`gas_price_wei`). |
| **`maxFeePerGas`** / **`maxPriorityFeePerGas`** | No | EIP-1559: if **both** set and &gt; 0, used; else computed from RPC + chain multipliers (`max_fee_per_gas`, `max_priority_fee_per_gas`). |

**Nonces:** The script uses **`eth_getTransactionCount(..., "pending")`** for the MPC address and assigns **consecutive nonces** for each action in order (batch = same behavior as the app).

---

## CLI usage

```bash
# From file
"$MPA_PATH/.venv/bin/python" "$MPA_PATH/scripts/generateMultiSignRequestFromCompose.py" --file compose.json --mpc-auth-url "$MPC_AUTH_URL:$MANAGEMENT_PORT"

# Stdin
cat compose.json | "$MPA_PATH/.venv/bin/python" "$MPA_PATH/scripts/generateMultiSignRequestFromCompose.py" --mpc-auth-url "$MPC_AUTH_URL:$MANAGEMENT_PORT"

# Override key gen id without editing JSON
"$MPA_PATH/.venv/bin/python" "$MPA_PATH/scripts/generateMultiSignRequestFromCompose.py" --file compose.json \
  --key-gen-id KeyGen20260111003720999cf104d0f \
  --mpc-auth-url "$MPC_AUTH_URL:$MANAGEMENT_PORT"
```

**Optional signing (writes `postBody` into stdout JSON):**

| Flag | Effect |
|------|--------|
| **`--ed25519-seed-hex HEX`** | Signs **`messageToSign`** with Ed25519 (**64 hex** = 32-byte seed, or **128 hex** uses first 32 bytes as seed). Sets **`clientSig`** to **128 hex** (no `0x`) and **`signedMessage`** = **`messageToSign`** (required by mpc-auth for **`POST /multiSignRequest`**). |
| **`--eip191-private-key-hex HEX`** | Signs with secp256k1 **personal_sign** (EIP-191). Sets **`clientSig`** with **`0x`** prefix and **`signedMessage`** = exact **`messageToSign`**. |

Use **one** of these if the agent holds the management private material; otherwise compute **`clientSig`** yourself from **`messageToSign`** (see next section).

---

## Script output (stdout JSON)

The table below describes **`generateMultiSignRequestFromCompose.py`**. **`generateSignRequestWithFoundryScript.py`** emits the **same top-level keys** (**`endpoint`**, **`bodyForSign`**, **`messageToSign`**, **`chainId`**, **`count`**, **`triggerTxParams`**, **`triggerMessageHash`**); it does **not** support **`--ed25519-seed-hex`** / **`postBody`** (see **`./AI_AGENT_FORGE_SIGNREQUEST.md`**).

| Key | Meaning |
|-----|---------|
| **`endpoint`** | Always **`"multiSignRequest"`**. |
| **`bodyForSign`** | Object to sign: includes **`keyList`**, **`pubKey`**, hashes/raw fields, **`destinationChainID`**, optional **`purpose`**, **`clientId`**, **`txNonce`** / **`txGasLimit`** / fee fields for the first tx, **`txParams`** (single) or **`proposalTxParams`** (batch), etc. **No** **`clientSig`** / **`signedMessage`** here. |
| **`messageToSign`** | **Exact string** to sign for management auth: compact JSON (**no spaces** after `:` or `,`), same as the app’s **`JSON.stringify(bodyForSign)`**. |
| **`chainId`** | Destination chain id string. |
| **`count`** | Number of compose actions (1 = single, ≥2 = batch). |
| **`triggerTxParams`** | Convenience: first-index **`txParams`** for **`POST /triggerSignRequestById`** (also emitted by the Foundry helper). |
| **`triggerMessageHash`** | Hash paired with **`triggerTxParams`** (first **`msgHash`** when batch). |
| **`postBody`** | **Compose only:** present if **`--ed25519-seed-hex`** or **`--eip191-private-key-hex`** was passed: ready-to-POST body including **`clientSig`** and **`signedMessage`** (= **`messageToSign`**). |

### `signedMessage` vs what you sign (avoid confusion)

- You **always** sign the **`messageToSign`** string (UTF-8). That string is the compact JSON form of **`bodyForSign`** only — **before** **`clientSig`** and **`signedMessage`** exist as separate fields.
- The **HTTP** body is **`bodyForSign`** **plus** **`clientSig`** **plus** **`signedMessage`**. You **do not** compute a signature over that merged JSON; **`clientSig`** is over **`messageToSign`** only.
- **`signedMessage`** must be the **exact** string that was signed — the same **`messageToSign`** from stdout — for both **Ed25519** and **EIP-191** on **`POST /multiSignRequest`** (mpc-auth rejects empty **`signedMessage`**). Helpers set **`signedMessage`** = **`messageToSign`** automatically.
- If **`postBody`** is present (signing flags), **`POST`** it as-is; no **`jq`** step is required to “re-canonicalize” what was signed.

---

## Management `clientSig` (not the MPC key)

Same rules as **`./AI_AGENT_FORGE_SIGNREQUEST.md`** § “How to get keyList, pubKey, and clientSig”. **Ed25519**, **`getPublicMgtKeyNonce`**, and **`sign-clipboard --inline` / `--inline-file`**: **`./ED25519_MANAGEMENT_KEY_SIGNING.md`**.

---

## Recipes table

Thin CLI wrappers under **`$MPA_PATH/recipes/`**. Each calls **`generateMultiSignRequestFromCompose.py`** internally (needs **`eth-account`** + **`PyNaCl`** in **`$MPA_PATH/.venv`** — **`../skill/SKILL.md`** **Python dependencies**).

| Script | What it builds |
|--------|------------------|
| **`linea_register.py`** | **`register()`** on the Linea fee contract (chain **`59144`**); RPC from **`getChainDetails`** unless overridden. |
| **`linea_fee_deposit.py`** | **`deposit(address,uint256)`** on the Linea fee contract; **`--amount-wei`**; MPC must have **approved** the fee token first. |
| **`erc20_transfer.py`** | ERC-20 **`transfer(address,uint256)`** on **`--token`** toward **`--to`**. |
| **`native_transfer.py`** | Native gas token transfer (**`nativeTransfer`** compose). |
| **`ctmerc20_transfer.py`** | CTMERC20 **`c3transfer`** (cross-chain third arg **`--to-chain-id`**). |
| **`ctmrwa1_transfer_whole.py`** | CTMRWA1 **`transferWholeTokenX`**. |
| **`ctmrwa1_transfer_partial.py`** | CTMRWA1 **`transferPartialTokenX`**. |

**Examples** (paths and flags): **`../skill/SKILL.md`** **Recipes** (short examples) or run **`--help`** on each script.

---

## Lifecycle after you have a payload

Once **`POST /multiSignRequest`** succeeds, other nodes **`POST /signRequestAgree`**, then the originator runs the trigger / execute / broadcast step. **AI agents:** **only** **`executeSignResult.py`** for automation (same as **`../skill/SKILL.md`** **Default operational loop**). Trigger bodies (inside the script) carry **`txParams`** and **`messageHash`**, or **`txParamsBatch`** for batch — Get Sig / Execute parity. See **`recipes/uniswapV4/README.md`** and **`./API_IMPLEMENTATION.md`**.

---

## Single vs batch body shape (critical)

The script matches **`continuumdao-node-app`** **`handleComposeOK`** behavior:

| `count` | Primary fields | Notes |
|---------|----------------|--------|
| **1** | **`msgHash`**, **`msgRaw`** | **`msgRaw`** is **calldata only**, **without** leading **`0x`** (not the full RLP unsigned tx). |
| **≥ 2** | **`messageHashes`**, **`messageRawBatch`** | Full **serialized unsigned tx** hex per item (with **`0x`**). Also sets first-item **`msgHash`** / **`msgRaw`** (first calldata, no `0x`) for app compatibility. **`extraJSON`** contains **`{"batchMeta":[...]}`** with per-tx **`destinationAddress`** and **`signatureText`**. When **`noCustomGasParams`** is false or omitted (default), **`generateMultiSignRequestFromCompose.py`** also adds **`customGasChainDetails`** (gas-related fields from **`GET /getChainDetails`**, not **`rpcGateway`**, which may embed API keys) in the same object for Join/Execute disclosure. |
| **Foundry helper (`generateSignRequestWithFoundryScript.py`)** | Same batch/hashing rules for **`messageHashes`** / **`messageRawBatch`** | Single-tx **`msgRaw`** is the **full** serialized unsigned transaction (with **`0x`**), not calldata-only—see **`./AI_AGENT_FORGE_SIGNREQUEST.md`**. |

**MPC signing** still uses the **transaction signing hash** in **`msgHash`** / **`messageHashes`**; do not replace those with `keccak256(calldata)` only.

---

## When to prefer Compose vs Foundry

| Situation | Tool |
|-----------|------|
| Agent or user specifies **function + arguments** (like a dApp compose form), no Foundry project | **`$MPA_PATH/scripts/generateMultiSignRequestFromCompose.py`** |
| Agent runs **Solidity / forge script** and has **broadcast JSON** | **`$MPA_PATH/scripts/generateSignRequestWithFoundryScript.py`** |

---

## Checklist for the agent

- [ ] Install deps in **`$MPA_PATH/.venv`**: **`"$MPA_PATH/.venv/bin/pip" install eth-account PyNaCl`** (see **`../skill/SKILL.md`** **Python dependencies**).
- [ ] Compose JSON includes **`keyGenId`**, **`destinationChainId`**, and at least one **`composeActions`** entry with valid **`signature`**, **`destinationContract`**, and **`inputs`**.
- [ ] Either set **`rpcGateway`** in JSON or ensure the chain exists on the node with an RPC in **Configure blockchains** (for **`getChainDetails`**).
- [ ] Run the script with **`--mpc-auth-url`** pointing at **ManagementAPIsPort**.
- [ ] Parse stdout JSON; use **`messageToSign`** to produce **`clientSig`** (or use **`postBody`** if you passed a signing flag).
- [ ] **POST** the final JSON body to **`POST /multiSignRequest`** (not **`/signRequest`** for multi-agree keys).
- [ ] Use the returned request id for **`/signRequestAgree`**, then **`executeSignResult.py`** (not raw **`/triggerSignRequestById`** from the agent). **`txParams`** / **`messageHash`** (or batch **`txParamsBatch`**) per **`./API_IMPLEMENTATION.md`** and **`../skill/SKILL.md`**.

---

## References

- **Script:** `$MPA_PATH/scripts/generateMultiSignRequestFromCompose.py` (module docstring + argparse help).
- **Forge path:** `./AI_AGENT_FORGE_SIGNREQUEST.md`.
- **Ed25519 management signing:** `./ED25519_MANAGEMENT_KEY_SIGNING.md`.
- **API:** `./API_IMPLEMENTATION.md` (§ **POST /multiSignRequest**).
- **Batch behavior:** see **Single vs batch body shape** in this doc and **`./API_IMPLEMENTATION.md`**.
- **UI parity:** `continuumdao-node-app` — Compose manual flow: `app/multi-sign/page.tsx` (`handleComposeOK`), calldata: `app/utils/continuumDAO.ts` (`encodeActionCalldata`), fees: `app/utils/chainFees.ts` (`fetchChainFeeParams`).
