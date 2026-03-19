# AI Agent Guide: Forge Script → multiSignRequest

This document is for **AI agents** (e.g. Open Claw, Cursor, or other automation) that turn a Foundry script’s transaction list into a payload for **POST /multiSignRequest** (multi-agree MPC keys). **POST /signRequest** is **only** for **tx-check / relayer** keys—not for multi-agree forge flows; do not use it here.

### Management API URL (co-located agents)

When the agent runs on the **same machine as one of the MPC nodes**, point **`--mpc-auth-url`** at the node’s management HTTP API: **`http://localhost:<port>`**, where **`<port>`** is **`ManagementAPIsPort`** in the node’s **`configs.yaml`** (often `8080` in sample configs). See **`mpc-config/docs/AGENT_ED25519_SETUP.md`** §8.2. If you changed the port in config, pass that port to the script (e.g. `--mpc-auth-url=http://localhost:9000`).

---

## Goal

1. Run (or read output from) **`forge script`** so you have a list of transactions.
2. Convert that into **one** JSON body for **POST /multiSignRequest** only (one tx → `msgHash` / `msgRaw`; two or more → `messageHashes` / `messageRawBatch`). The server rejects **multiSignRequest** for non–multi-agree keys and **signRequest** for this key type.

The Python utility **fills `keyList` and `pubKey`** via **GET /getKeyGenResultById** (`--key-gen-id`, `--mpc-auth-url` must match **ManagementAPIsPort** in `configs.yaml`). Your agent must still add **`clientSig`** (and optionally adjust `purpose`, etc.) before calling the API.

---

## How to get keyList, pubKey, and clientSig

### keyList and pubKey: from key generation result

Use the **key generation request ID** of the multi-agree MPC key you want to sign with (the same key that was created via `POST /keyGenRequest` and agreed by nodes).

1. **GET /getKeyGenResultById**
   - **Query:** `id=<keyGenRequestId>` (e.g. the keygen ID you used when creating the key, or from your app’s state).
   - **Response (when ready):** `data.keylist`, `data.pubkeyhex`, plus `requestid`, `ethereumaddress`, etc.

2. **Use in the sign request body:**
   - **keyList** = `data.keylist` (array of node public keys, 128 hex each).
   - **pubKey** = `data.pubkeyhex` (128 hex; the MPC public key for this keygen).

If the keygen is not ready yet, the API returns `code: 1` ("not ready"); wait for keygen to complete (threshold+1 parties agreed and TSS finished) then call again.

### clientSig: management key signature (same as keyGenRequest)

`clientSig` is **not** from the MPC key. It is the **management key** of the node (the key that is allowed to create sign requests and trigger them). The node accepts either **MetaMask (NodeMgtKey)** or **Ed25519 (PublicMgtKey)**. Use the same key type and key that the node has configured (and that was used when creating the keygen, if applicable).

#### Option 1: Ed25519 management key (recommended for agents)

Use when the node has an Ed25519 management key configured (`GET /hasPublicMgtKey` returns `true`). No nonce is required for multiSignRequest.

1. **Build the full request body** with all fields from the script output (e.g. `messageHashes`, `messageRawBatch`, `destinationChainID`, `keyList`, `pubKey`, `purpose`, etc.). Set **`clientSig`** and **`signedMessage`** to empty strings.
2. **Canonical message to sign:** The backend expects the **canonical JSON** of that body (same field order as Go’s `json.Marshal`; `clientSig` and `signedMessage` must be empty). You can either:
   - Replicate the backend order and omit `clientSig`/`signedMessage`, or  
   - Omit `signedMessage` in the request and let the backend recompute the canonical JSON when verifying (backend does this when `signedMessage` is empty and the client key is Ed25519).
3. **Sign** that exact JSON string with the **Ed25519 private key** that matches one of the node’s allowed management keys (config `PublicMgtKey` or a key added via `POST /addManagementKey`). Signature must be **64 bytes**, encoded as **128 hex characters**.
4. **Send** the same body with **`clientSig`** set to that 128-hex signature. You can leave **`signedMessage`** empty; the backend will use canonical JSON for verification.

**Note:** The Ed25519 keypair is the **management** keypair (e.g. from config or from the key you added). It is not the MPC key from keygen.

#### Option 2: MetaMask (NodeMgtKey)

Use when the node uses an Ethereum address as the management key (e.g. MetaMask).

1. **Build the full request body** with `clientSig` and `signedMessage` empty.
2. **Build the exact message string** that will be signed (canonical JSON of the body with `clientSig` and `signedMessage` empty).
3. **Sign** that string with **Ethereum `personal_sign`** (EIP-191) from the **NodeMgtKey** address (same as in node config).
4. **Send** the body with **`clientSig`** = the 0x-prefixed signature and **`signedMessage`** = the exact string you signed (required for MetaMask).

**Summary:** `keyList` and `pubKey` come from **GET /getKeyGenResultById**. `clientSig` is produced by signing the (canonical) request body with the node’s **management key** (Ed25519 or MetaMask), not with the MPC key.

---

## Option A: Python script (recommended for agents)

**Location:** `scripts/generateSignRequestWithFoundryScript.py` in this repo (mpc-auth).

**Dependency:**  
```bash
pip install eth_account
# or from repo:
pip install -r scripts/requirements-forge-sign.txt
```

**Input:** Foundry broadcast JSON (see “Where does the JSON come from?” below).

**Required:** `--key-gen-id=<KeyGenRequestId>`. The script calls `GET {mpc-auth-url}/getKeyGenResultById?id=...`. Set **`--mpc-auth-url`** to `http://localhost:<ManagementAPIsPort>` from the node’s **`configs.yaml`**.

**Read from stdin:**
```bash
cat broadcast/MyScript.s.sol/11155111/run-latest.json | \
  python3 scripts/generateSignRequestWithFoundryScript.py --key-gen-id=KeyGen20260111003720999cf104d0f
```

**Read from file:**
```bash
python3 scripts/generateSignRequestWithFoundryScript.py \
  --key-gen-id=KeyGen20260111003720999cf104d0f \
  --file=broadcast/MyScript.s.sol/11155111/run-latest.json
```

**Optional overrides:**
```bash
python3 scripts/generateSignRequestWithFoundryScript.py --key-gen-id=KeyGen... --file=... \
  --destination-chain-id=11155111 \
  --purpose="Deploy and configure contract" \
  --mpc-auth-url=http://localhost:8080   # replace 8080 with ManagementAPIsPort from configs.yaml
```

**Output:** One JSON object to stdout, for example:

```json
{
  "endpoint": "multiSignRequest",
  "body": {
    "messageHashes": ["abc123...", "def456..."],
    "messageRawBatch": ["0x02f8...", "0x02f8..."],
    "destinationChainID": "11155111"
  },
  "chainId": "11155111",
  "count": 2
}
```

- **`endpoint`:** Always `"multiSignRequest"` for this flow (Python/TS utilities below). Ignore **signRequest** unless you are on a separate tx-check / relayer integration.
- **`body`:** Already includes `keyList` and `pubKey` from the node. Add **`clientSig`** (management key), then **POST /multiSignRequest**.
- **`count`:** Number of transactions in the broadcast (1 still uses **multiSignRequest** with `msgHash` / `msgRaw`).

---

## Option B: TypeScript (frontend / Node)

**Location (utility):** `app/utils/generateSignRequestWithFoundryScript.ts` in **continuumdao-node-app** (sibling repo).

**CLI (if you have Node/ts-node in that repo):**
```bash
cd ../continuumdao-node-app
npx ts-node scripts/generateSignRequestFromForge.ts < path/to/run-latest.json
# or
npx ts-node scripts/generateSignRequestFromForge.ts --file=path/to/run-latest.json
```

**From code:**  
Import `generateSignRequestWithFoundryScriptFromJson` or `generateSignRequestWithFoundryScript`, pass the broadcast JSON (object or string) and optional overrides; you get the same shape as above (`endpoint`, `body`, `chainId`, `count`).

---

## Where does the JSON come from?

The script expects **Foundry broadcast JSON** with a `transactions` array. Typical sources:

1. **Broadcast file (recommended)**  
   After:
   ```bash
   forge script script/MyScript.s.sol --broadcast
   ```
   Foundry writes e.g.:
   ```text
   broadcast/MyScript.s.sol/<chain_id>/run-latest.json
   ```
   Use that file path with `--file=...` or pipe its contents to the script.

2. **Forge script with JSON output**  
   If your Foundry version writes broadcast-style JSON to stdout when using `--json`, you can pipe it:
   ```bash
   forge script script/MyScript.s.sol --broadcast --json 2>/dev/null | python3 scripts/generateSignRequestWithFoundryScript.py
   ```
   (Adjust flags if your Foundry version uses a different way to emit JSON.)

3. **Any JSON with the same shape**  
   The script accepts any object with a top-level `transactions` array. Each element can have either:
   - `transaction`: { from, gas, value, input/data, nonce, chainId, to?, type?, maxFeePerGas?, maxPriorityFeePerGas?, gasPrice? }, or  
   - `tx`: same fields (e.g. `type`, `data`, `to`, etc.).

So you can also generate or edit such JSON in your agent and pass it to the script.

---

## What to do with the output

1. **Parse** the script’s stdout as JSON.
2. **Read** `body` (and confirm `endpoint` is **`multiSignRequest`**).
3. **Add** to `body`:
   - **keyList** / **pubKey**: already set by the Python script (same as `GET /getKeyGenResultById`). If not using the script, fetch manually; see [How to get keyList, pubKey, and clientSig](#how-to-get-keylist-pubkey-and-clientsig).
   - **clientSig**: management key signature (Ed25519 or MetaMask) over the canonical request body; see the same section for step-by-step.
   - Optionally, but purpose is strongly recommended (including link to github if applicable): `purpose`, `destinationAddress`, `extraJSON`, `signatureText`.
4. **POST** the final body to **POST /multiSignRequest** only (not **/signRequest**—that path is for tx-check / relayer keys).
5. **Use** the returned `requestId` for:
   - **signRequestAgree** (multi-agree),
   - **triggerSignRequestById** (after enough agreements),
   - **getSignResultById** to get signature(s). For batch, use `data.batchSignatures[i]` for the i-th transaction.

---

## Single vs batch (both use multiSignRequest)

| Count | Body fields (always **POST /multiSignRequest**) |
|-------|--------------------------------------------------|
| 1     | `msgHash`, `msgRaw`                              |
| ≥2    | `messageHashes[]`, `messageRawBatch[]`           |

**signRequest** is unrelated to this table (tx-check / relayer only). The script sets the correct **multiSignRequest** body shape from the number of transactions.

---

## Checklist for the agent

- [ ] Obtain or generate Foundry broadcast JSON (e.g. `run-latest.json` or forge script JSON output).
- [ ] Run the Python script (or TypeScript) with that JSON as input.
- [ ] Parse the JSON output; use `body` for **POST /multiSignRequest**.
- [ ] Add `clientSig` to `body` (`keyList`/`pubKey` already filled if using the Python script with `--key-gen-id`).
- [ ] POST the complete body to **POST /multiSignRequest** (not `/signRequest` for multi-agree keys).
- [ ] Use the returned `requestId` for agree/trigger and then get sign result(s).

---

## References

- **API:** `API_IMPLEMENTATION.md` in this repo (§ POST /multiSignRequest, GET /getSignResultById). **signRequest** is documented there for tx-check / relayer flows only.
- **Batch design:** `docs-internal/MULTI_SIGNREQUEST_DESIGN.md`.