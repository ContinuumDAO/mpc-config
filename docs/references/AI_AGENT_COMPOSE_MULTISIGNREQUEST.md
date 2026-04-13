# AI Agent Guide: Compose JSON → multiSignRequest

This document is for **AI agents** that build **POST /multiSignRequest** payloads from **human-style compose data** (function signature, Solidity parameters, chain id)—the same conceptual input as the **Compose** panel in **`continuumdao-node-app`** (manual mode, not Foundry import). Use **`$MPA_PATH/scripts/generateMultiSignRequestFromCompose.py`**.

**Do not confuse with Foundry:** For transactions produced by **`forge script`** and **`run-latest.json`**, use **`$MPA_PATH/scripts/generateSignRequestWithFoundryScript.py`** and **[AI_AGENT_FORGE_SIGNREQUEST.md](./AI_AGENT_FORGE_SIGNREQUEST.md)** instead.

**Endpoint discipline:** **POST /multiSignRequest** is for **multi-agree** MPC keys only. **POST /signRequest** is for **tx-check / relayer** keys only.

### Checklist (multiSignRequest)

1. **Resolve** **`keyGenId`**, the MPC wallet **`from`** address, and the **management API base URL** for the node you call (e.g. **`GET /getKeyGenResultById`**, environment such as **`KEYGEN_ID`** / **`AUTH_KEY_PATH`**, port from **`configs.yaml`** or the operator).
2. **Build** the unsigned **`POST /multiSignRequest`** body with a repo helper: **`$MPA_PATH/scripts/generateSignRequestWithFoundryScript.py`** (Foundry) or **`$MPA_PATH/scripts/generateMultiSignRequestFromCompose.py`** (compose JSON), following **[AI_AGENT_FORGE_SIGNREQUEST.md](./AI_AGENT_FORGE_SIGNREQUEST.md)** or **this document**.
3. **Review** **`Purpose`** (≤256 characters) and transaction fields (chain id, calldata, gas, nonces) against group intent and messages.
4. **Sign for HTTP:** add **management** **`clientSig`** (and any other fields **[API_IMPLEMENTATION.md](./API_IMPLEMENTATION.md)** requires for your deployment).
5. **Submit and complete the lifecycle:** **`POST /multiSignRequest`** → track peer responses → **`POST /triggerSignRequestById`** when ready → broadcast raw transactions → **`POST /updateSignResultStatusById`**. **EVM:** **`POST /triggerSignRequestById`** must include **`txParams`** and **`messageHash`** so the node stores them (see **[API_IMPLEMENTATION.md](./API_IMPLEMENTATION.md)** § **`POST /triggerSignRequestById`**). Narrative flow: **[instructions.md](./instructions.md)**.

---

## Management API URL

Point **`--mpc-auth-url`** at the node’s **management HTTP API** as **`$MPC_AUTH_URL:$MANAGEMENT_PORT`**. `MPC_AUTH_URL` should be host-only (for example `http://127.0.0.1` or `http://<IP>`), and `MANAGEMENT_PORT` should be the numeric `ManagementAPIsPort` in `configs.yaml`. See **[AGENT_ED25519_SETUP.md](./AGENT_ED25519_SETUP.md)** §8.2 if you use a non-default port or remote access.

The script calls:

- **`GET /getKeyGenResultById?id=<keyGenId>`** — `keyList`, `pubKey`, MPC `ethereumaddress`, optional **`ClientKeys`** → **`clientId`**
- **`GET /getChainDetails?chain_id=<n>`** — when **`rpcGateway`** is omitted from compose JSON (to read the node’s stored RPC and gas settings, matching the app’s **OK** submit path)

It also performs **JSON-RPC** against that RPC (`eth_getTransactionCount`, `eth_estimateGas`, `eth_gasPrice`, latest block / EIP-1559 fields).

---

## Goal

1. Build (or receive) one **compose JSON** object describing one or more contract calls (signature + args + destination contract), plus **destination chain** and optional gas behavior.
2. Run **`$MPA_PATH/scripts/generateMultiSignRequestFromCompose.py`** to obtain **`bodyForSign`** and **`messageToSign`** (same convention as the web app before management signing).
3. Add **`clientSig`** (and **`signedMessage`** for MetaMask-style management keys), then **POST /multiSignRequest**.

The script fills **`keyList`** and **`pubKey`** from the node. It computes **EVM tx signing hashes** using the same helpers as the Foundry script so **`msgHash`** / **`messageHashes`** match **unsigned EIP-1559 / legacy** serialization. The numbered **Checklist** at the top of this file is the same sequence as **[instructions.md](./instructions.md)**.

---

## Install dependencies (required)

**Both** packages are **mandatory** (the script imports **PyNaCl** at startup). Use the venv at **`$MPA_PATH/.venv`** (create with **`python3 -m venv "$MPA_PATH/.venv"`** if missing). Full bootstrap and verification: **[SKILL.md](../skill/SKILL.md)** **Python dependencies**.

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
| **`--ed25519-seed-hex HEX`** | Signs **`messageToSign`** with Ed25519 (**64 hex** = 32-byte seed, or **128 hex** uses first 32 bytes as seed). Sets **`clientSig`** to **128 hex** (no `0x`) and **`signedMessage`** to **`""`**. |
| **`--eip191-private-key-hex HEX`** | Signs with secp256k1 **personal_sign** (EIP-191). Sets **`clientSig`** with **`0x`** prefix and **`signedMessage`** = exact **`messageToSign`**. |

Use **one** of these if the agent holds the management private material; otherwise compute **`clientSig`** yourself from **`messageToSign`** (see next section).

---

## Script output (stdout JSON)

| Key | Meaning |
|-----|---------|
| **`endpoint`** | Always **`"multiSignRequest"`**. |
| **`bodyForSign`** | Object to sign: includes **`keyList`**, **`pubKey`**, hashes/raw fields, **`destinationChainID`**, optional **`purpose`**, **`clientId`**, **`txNonce`** / **`txGasLimit`** / fee fields for the first tx, etc. **No** **`clientSig`** / **`signedMessage`** here. |
| **`messageToSign`** | **Exact string** to sign for management auth: compact JSON (**no spaces** after `:` or `,`), same as the app’s **`JSON.stringify(bodyForSign)`**. |
| **`chainId`** | Destination chain id string. |
| **`count`** | Number of compose actions (1 = single, ≥2 = batch). |
| **`postBody`** | Present only if **`--ed25519-seed-hex`** or **`--eip191-private-key-hex`** was passed: ready-to-POST body including **`clientSig`** (and **`signedMessage`** for EIP-191). |

### `signedMessage` vs what you sign (avoid confusion)

- You **always** sign the **`messageToSign`** string (UTF-8). That string is the compact JSON form of **`bodyForSign`** only — **before** **`clientSig`** exists.
- The **HTTP** body is **`bodyForSign`** **plus** **`clientSig`** **plus** **`signedMessage`**. You **do not** compute a signature over that merged JSON for this endpoint.
- **`signedMessage`** is not “the entire POST body as a string”. For **Ed25519**, send **`signedMessage`: `""`**. For **EIP-191**, **`signedMessage`** must be the **exact** string you signed — use the **`messageToSign`** value from stdout verbatim — not a serialization of the request including the signature.
- If **`postBody`** is present (signing flags), **`POST`** it as-is; no **`jq`** step is required to “re-canonicalize” what was signed.

---

## Management `clientSig` (not the MPC key)

Same rules as **[AI_AGENT_FORGE_SIGNREQUEST.md](./AI_AGENT_FORGE_SIGNREQUEST.md)** § “How to get keyList, pubKey, and clientSig”:

- **`clientSig`** authenticates the **management** key (Ed25519 or Ethereum), **not** the MPC wallet.
- **Ed25519:** Sign the **`messageToSign`** string with the management secret key; **`clientSig`** = **128 hex**; **`signedMessage`** may be empty (backend can canonicalize).
- **MetaMask / NodeMgtKey:** EIP-191 sign **`messageToSign`**; **`clientSig`** = **`0x` + signature**; **`signedMessage`** must equal the **exact** string that was signed.

**Management API nonces** (`GET /getPublicMgtKeyNonce`, etc.) apply to **other** management POSTs where documented; **`multiSignRequest`** in the standard flow is signed via **`messageToSign`** as above.

---

## Single vs batch body shape (critical)

The script matches **`continuumdao-node-app`** **`handleComposeOK`** behavior:

| `count` | Primary fields | Notes |
|---------|----------------|--------|
| **1** | **`msgHash`**, **`msgRaw`** | **`msgRaw`** is **calldata only**, **without** leading **`0x`** (not the full RLP unsigned tx). |
| **≥ 2** | **`messageHashes`**, **`messageRawBatch`** | Full **serialized unsigned tx** hex per item (with **`0x`**). Also sets first-item **`msgHash`** / **`msgRaw`** (first calldata, no `0x`) for app compatibility. **`extraJSON`** contains **`{"batchMeta":[...]}`** with per-tx **`destinationAddress`** and **`signatureText`**. |

**MPC signing** still uses the **transaction signing hash** in **`msgHash`** / **`messageHashes`**; do not replace those with `keccak256(calldata)` only.

---

## When to prefer Compose vs Foundry

| Situation | Tool |
|-----------|------|
| Agent or user specifies **function + arguments** (like a dApp compose form), no Foundry project | **`$MPA_PATH/scripts/generateMultiSignRequestFromCompose.py`** |
| Agent runs **Solidity / forge script** and has **broadcast JSON** | **`$MPA_PATH/scripts/generateSignRequestWithFoundryScript.py`** |

---

## Checklist for the agent

- [ ] Install deps in **`$MPA_PATH/.venv`**: **`"$MPA_PATH/.venv/bin/pip" install eth-account PyNaCl`** (see **[SKILL.md](../skill/SKILL.md)** **Python dependencies**).
- [ ] Compose JSON includes **`keyGenId`**, **`destinationChainId`**, and at least one **`composeActions`** entry with valid **`signature`**, **`destinationContract`**, and **`inputs`**.
- [ ] Either set **`rpcGateway`** in JSON or ensure the chain exists on the node with an RPC in **Configure blockchains** (for **`getChainDetails`**).
- [ ] Run the script with **`--mpc-auth-url`** pointing at **ManagementAPIsPort**.
- [ ] Parse stdout JSON; use **`messageToSign`** to produce **`clientSig`** (or use **`postBody`** if you passed a signing flag).
- [ ] **POST** the final JSON body to **`POST /multiSignRequest`** (not **`/signRequest`** for multi-agree keys).
- [ ] Use the returned request id for **`/signRequestAgree`**, **`/triggerSignRequestById`** (EVM: include **`txParams`** + **`messageHash`** on trigger—see API doc), **`/getSignResultById`** as in the forge guide.

---

## References

- **Script:** `$MPA_PATH/scripts/generateMultiSignRequestFromCompose.py` (module docstring + argparse help).
- **Forge path:** [AI_AGENT_FORGE_SIGNREQUEST.md](./AI_AGENT_FORGE_SIGNREQUEST.md).
- **API:** [API_IMPLEMENTATION.md](./API_IMPLEMENTATION.md) (§ **POST /multiSignRequest**).
- **Batch behavior:** see **Single vs batch body shape** in this doc and **[API_IMPLEMENTATION.md](./API_IMPLEMENTATION.md)**.
- **UI parity:** `continuumdao-node-app` — Compose manual flow: `app/multi-sign/page.tsx` (`handleComposeOK`), calldata: `app/utils/continuumDAO.ts` (`encodeActionCalldata`), fees: `app/utils/chainFees.ts` (`fetchChainFeeParams`).
