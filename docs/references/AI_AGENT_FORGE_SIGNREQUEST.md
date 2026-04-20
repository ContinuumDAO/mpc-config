# AI Agent Guide: Forge Script → multiSignRequest

This document is for **AI agents** and **other programmatic automation** that turn a Foundry script’s transaction list into a payload for **POST /multiSignRequest** (multi-agree MPC keys). **POST /signRequest** is **only** for **tx-check / relayer** keys—not for multi-agree forge flows; do not use it here.

### Checklist (multiSignRequest)

1. **Resolve** **`keyGenId`**, the MPC wallet **`from`** address, and the **management API base URL** for the node you call (e.g. **`GET /getKeyGenResultById`**, environment such as **`KEYGEN_ID`** / **`AUTH_KEY_PATH`**, port from **`configs.yaml`** or the operator).
2. **Build** the unsigned **`POST /multiSignRequest`** body with a repo helper: **`$MPA_PATH/scripts/generateSignRequestWithFoundryScript.py`** (Foundry) or **`$MPA_PATH/scripts/generateMultiSignRequestFromCompose.py`** (compose JSON), following **this document** or **`./AI_AGENT_COMPOSE_MULTISIGNREQUEST.md`**.
3. **Review** **`Purpose`** (≤256 characters) and transaction fields (chain id, calldata, gas, nonces) against group intent and messages.
4. **Sign for HTTP:** add **management** **`clientSig`** (and any other fields **`./API_IMPLEMENTATION.md`** requires for your deployment).
5. **Submit and complete the lifecycle:** **`POST /multiSignRequest`** → peers agree → when ready, **AI agents** run **only** **`$MPA_PATH/scripts/executeSignResult.py`** for EVM trigger + broadcast (see **`../skill/SKILL.md`**—do **not** call **`POST /triggerSignRequestById`** directly). **`updateSignResultStatusById`** after execution. **`./instructions.md`** and **`./API_IMPLEMENTATION.md`** describe the full protocol including manual **`curl`** / web **Execute**.

### Management API URL

Point **`--mpc-auth-url`** at the node’s **management HTTP API** as **`$MPC_AUTH_URL:$MANAGEMENT_PORT`**. `MPC_AUTH_URL` should be host-only (for example `http://127.0.0.1` or `http://<IP>`), and `MANAGEMENT_PORT` should be numeric (`ManagementAPIsPort` in `configs.yaml`). Load from **`$MPA_PATH/.env`** when present (**`../skill/SKILL.md`** **Environment**).

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

Use when the node has an Ed25519 management key configured (`GET /hasPublicMgtKey` returns `true`). No separate **management nonce** is required for **`multiSignRequest`** (signing uses **`messageToSign`** only). For **other** management endpoints that include **`nonce`** in the body (**`sendMessage`**, **`triggerSignRequestById`**, **`addManagementKey`**, …), use **`GET /getPublicMgtKeyNonce`** for Ed25519 — not **`GET /getNodeMgtKeyNonce`** (Ethereum **`NodeMgtKey`** only). See **`../skill/SKILL.md`** § Management API nonce and **`./API_IMPLEMENTATION.md`**.

1. **Canonical message to sign:** The helper’s **`messageToSign`** string — compact JSON of **`bodyForSign`** only (no **`clientSig`** / **`signedMessage`** in the signed bytes).
2. **Sign** that exact UTF-8 string with the **Ed25519 private key** that matches one of the node’s allowed management keys (config `PublicMgtKey` or a key added via `POST /addManagementKey`). **`clientSig`** must be **64 bytes**, encoded as **128 hex characters** (optional `0x` stripped).
3. **POST** the full body: all fields from **`bodyForSign`** plus **`clientSig`** plus **`signedMessage`**, where **`signedMessage`** is the **same** string as **`messageToSign`** (mpc-auth **`POST /multiSignRequest`** requires non-empty **`signedMessage`** so the verifier can check **`Ed25519`** over that exact string). Repo helpers (`**generateMultiSignRequestFromCompose.py**`, **`generateSignRequestWithFoundryScript.py**`, **`recipes/*.py`**) set this automatically.

**Note:** The Ed25519 keypair is the **management** keypair (e.g. from config or from the key you added). It is not the MPC key from keygen.

#### Option 2: MetaMask (NodeMgtKey)

Use when the node uses an Ethereum address as the management key (e.g. MetaMask).

1. **Build the full request body** with `clientSig` and `signedMessage` empty.
2. **Build the exact message string** that will be signed (canonical JSON of the body with `clientSig` and `signedMessage` empty).
3. **Sign** that string with **Ethereum `personal_sign`** (EIP-191) from the **NodeMgtKey** address (same as in node config).
4. **Send** the body with **`clientSig`** = the 0x-prefixed signature and **`signedMessage`** = the exact string you signed (required for MetaMask).

**Summary:** `keyList` and `pubKey` come from **GET /getKeyGenResultById**. `clientSig` is produced by signing the (canonical) request body with the node’s **management key** (Ed25519 or MetaMask), not with the MPC key.

---

## Python script

**Location:** `$MPA_PATH/scripts/generateSignRequestWithFoundryScript.py`.

**Dependency:** Install **`eth-account`** into **`$MPA_PATH/.venv`** and run the helper with **`$MPA_PATH/.venv/bin/python`** (bootstrap: **`python3 -m venv "$MPA_PATH/.venv"`** if the directory does not exist). Full package list and verification: **`../skill/SKILL.md`** **Python dependencies**.

```bash
"$MPA_PATH/.venv/bin/pip" install eth-account
```

**Input:** Foundry broadcast JSON (see “Where does the JSON come from?” below).

**Required:** `--key-gen-id=<KeyGenRequestId>`. The script calls `GET {mpc-auth-url}/getKeyGenResultById?id=...`. Set **`--mpc-auth-url`** to **`$MPC_AUTH_URL:$MANAGEMENT_PORT`** from your environment / node config.

**Read from stdin:**
```bash
cat broadcast/MyScript.s.sol/11155111/run-latest.json | \
  "$MPA_PATH/.venv/bin/python" "$MPA_PATH/scripts/generateSignRequestWithFoundryScript.py" --key-gen-id=KeyGen20260111003720999cf104d0f
```

**Read from file:**
```bash
"$MPA_PATH/.venv/bin/python" "$MPA_PATH/scripts/generateSignRequestWithFoundryScript.py" \
  --key-gen-id=KeyGen20260111003720999cf104d0f \
  --file=broadcast/MyScript.s.sol/11155111/run-latest.json
```

**Common overrides (chain, purpose, API):**
```bash
"$MPA_PATH/.venv/bin/python" "$MPA_PATH/scripts/generateSignRequestWithFoundryScript.py" --key-gen-id=KeyGen... --file=... \
  --destination-chain-id=11155111 \
  --purpose="Deploy and configure contract" \
  --mpc-auth-url="$MPC_AUTH_URL:$MANAGEMENT_PORT"
```

**Destination and display (optional):** `--destination-address` (single tx), `--destination-addresses` (batch: JSON array), `--signature-text`, `--signature-texts` (batch: JSON array), `--extra-json` (merged with batch `batchMeta` when batching).

**Nonce and sender (optional):** If the broadcast used a different `from` (e.g. Anvil default) but you will execute with the MPC key’s address, override the sender and assign sequential nonces without re-running Foundry:

- **`--override-sender=ADDR`** — use this address as `from` for every transaction.
- **`--first-nonce=N`** — set nonces to `N`, `N+1`, `N+2`, … (defaults to `0` when combined with `--override-sender` if omitted).

Example: broadcast from another key, sign with the KeyGen address and current nonce `5`:

```bash
"$MPA_PATH/.venv/bin/python" "$MPA_PATH/scripts/generateSignRequestWithFoundryScript.py" --key-gen-id=KeyGen... \
  --override-sender=0xYourKeyGenAddress --first-nonce=5 \
  < broadcast/.../run-latest.json
```

**Gas and fees (optional):** By default the script keeps gas and fee fields from the broadcast. If you pass **any** of the flags below, it augments the broadcast (e.g. dry-run output with missing fees). EIP-1559 is the default when augmenting unless you pass **`--legacy`**.

| Area | Flags |
|------|--------|
| Mode | `--legacy` (gas price), or `--is-eip1559` (EIP-1559; default when augmenting if not `--legacy`) |
| EIP-1559 | `--base-fee-gwei`, `--priority-fee-gwei`, `--base-fee-multiplier` (percent, ≥100, default 100) |
| Legacy | `--gas-price-gwei`, `--gas-price` (minimum gwei; max with `--gas-price-gwei`), `--gas-multiplier` (extra % on gas price) |
| Both | `--gas-limit` (per-tx when augmenting) |

When any of these augment flags is used, **`generateSignRequestWithFoundryScript.py`** also sets **`extraJSON.customGasChainDetails`** to a gas-hints snapshot from **`GET /getChainDetails`** for the destination chain (same convention as the Multi-Sign app and **`generateMultiSignRequestFromCompose.py`**; **`rpcGateway` is omitted**), with a fallback to the CLI-derived augment hints if the node lookup fails.

Example: dry-run JSON with no fees, EIP-1559 and fresh sender/nonce:

```bash
"$MPA_PATH/.venv/bin/python" "$MPA_PATH/scripts/generateSignRequestWithFoundryScript.py" --key-gen-id=KeyGen... \
  --is-eip1559 --base-fee-gwei=30 --priority-fee-gwei=2 \
  --first-nonce=0 --override-sender=0xYourKeyGen \
  < broadcast/.../run-latest.json
```

**Output:** One JSON object to stdout with the **same envelope** as **`generateMultiSignRequestFromCompose.py`**: **`bodyForSign`**, **`messageToSign`**, **`chainId`**, **`count`**, plus **`triggerTxParams`** and **`triggerMessageHash`** (convenience for **`POST /triggerSignRequestById`**; **`executeSignResult.py`** still applies). Example (batch):

```json
{
  "endpoint": "multiSignRequest",
  "bodyForSign": {
    "keyList": ["…"],
    "pubKey": "…",
    "msgHash": "abc123…",
    "msgRaw": "a9059cbb…",
    "messageHashes": ["abc123…", "def456…"],
    "messageRawBatch": ["0x02f8…", "0x02f8…"],
    "destinationChainID": "11155111",
    "extraJSON": "{\"batchMeta\":[{\"destinationAddress\":\"0x…\",\"signatureText\":\"\"},…]}",
    "txNonce": 12,
    "txGasLimit": "21000",
    "txMaxFeePerGas": "…",
    "txMaxPriorityFeePerGas": "…",
    "proposalTxParams": [
      { "nonce": 12, "gasLimit": "…", "txType": "eip1559", "maxFeePerGas": "…", "maxPriorityFeePerGas": "…" },
      { "nonce": 13, "gasLimit": "…", "txType": "eip1559", "maxFeePerGas": "…", "maxPriorityFeePerGas": "…" }
    ]
  },
  "messageToSign": "{\"keyList\":…,\"pubKey\":…}",
  "chainId": "11155111",
  "count": 2,
  "triggerTxParams": { "nonce": 12, "gasLimit": "…", "txType": "eip1559", "maxFeePerGas": "…", "maxPriorityFeePerGas": "…" },
  "triggerMessageHash": "abc123…"
}
```

- **`endpoint`:** Always `"multiSignRequest"` for this flow. Ignore **signRequest** unless you are on a separate tx-check / relayer integration.
- **`bodyForSign`:** Includes **`keyList`** and **`pubKey`** from the node, hashes and serialized unsigned txs, **`destinationChainID`**, first-tx fee snapshot (**`txNonce`** / **`txGasLimit`** / fee fields), and **`txParams`** (one tx) or **`proposalTxParams`** (batch)—aligned with **`GET /getSignRequestById?tx_params=1`**. Add **`clientSig`** and **`signedMessage`**, then **POST /multiSignRequest**. Do **not** use the removed legacy top-level key **`body`**.
- **`messageToSign`:** Compact JSON of **`bodyForSign`** only (what management signs for **`clientSig`**).
- **`triggerTxParams` / `triggerMessageHash`:** First index for trigger; batch proposals use **`proposalTxParams`** inside **`bodyForSign`**.
- **`count`:** Number of transactions in the broadcast (1 still uses **multiSignRequest** with **`msgHash`** / **`msgRaw`** and **`txParams`**).

---

## Where does the JSON come from?

The script expects **Foundry broadcast JSON** with a `transactions` array. Typical sources:

1. **Broadcast file (recommended)**  
   Do **not** pass **`--broadcast`**. You **must** pass **`--sender`** (the address that will execute the txs on-chain—often overridden later via the Python script’s `--override-sender` when the broadcast used a stand-in key). Use **`--rpc-url`** for the chain you simulate against. Example:
   ```bash
   forge script script/MyScript.s.sol --rpc-url https://... --sender 0x...
   ```
   Foundry writes e.g.:
   ```text
   broadcast/MyScript.s.sol/<chain_id>/run-latest.json
   ```
   Use that file path with `--file=...` or pipe its contents to the script.

2. **Forge script with JSON output**  
   If your Foundry version writes broadcast-style JSON to stdout when using `--json`, you can pipe it (still **without** `--broadcast`, **with** `--sender` and **`--rpc-url`** as needed):
   ```bash
   forge script script/MyScript.s.sol --rpc-url https://... --sender 0x... --json 2>/dev/null | "$MPA_PATH/.venv/bin/python" "$MPA_PATH/scripts/generateSignRequestWithFoundryScript.py"
   ```
   (Adjust flags if your Foundry version uses a different way to emit JSON.)

3. **Any JSON with the same shape**  
   The script accepts any object with a top-level `transactions` array. Each element can have either:
   - `transaction`: { from, gas, value, input/data, nonce, chainId, to?, type?, maxFeePerGas?, maxPriorityFeePerGas?, gasPrice? }, or  
   - `tx`: same fields (e.g. `type`, `data`, `to`, etc.).

So you can also generate or edit such JSON in your agent and pass it to the script.

---

## Linea fee: approve + deposit (batch)

The Linea **MultiSignFeeRegistry** at **`0x55aD6Df6d8f8824486C3fd3373f1CF29eCecF0A3`** (chain id **59144**) pulls the fee ERC20 from the MPC wallet via **`transferFrom`** in **`deposit(address,uint256)`**, so the MPC must **`approve`** that contract **before** **`deposit`**. This repo includes a Foundry script that records **both** calls in one broadcast (approve on the fee token, then **`deposit`** on the registry).

**Script:** `forge/script/LineaFeeApproveDeposit.s.sol` (run from the `forge/` directory).

**Environment:**

| Variable | Meaning |
|----------|---------|
| `DEPOSIT_AMOUNT_WEI` | Deposit amount in fee-token smallest units (must be ≥ this KeyGen’s **`minimumDeposit`** from **`keyGenFeeConfig`**). |
| `MPC_ADDRESS` | KeyGen **Ethereum** address (same as **`--sender`** and first arg to **`deposit`**). |
| `FORGE_LINEA_FEE_SIMULATE` | Optional **`true`**: uses **`deal`** so a fork simulation can succeed **without** real fee-token balance (only for building **`run-latest.json`**; cheats do not exist on mainnet). |

**1. Generate broadcast JSON** (from repo root `mpc-config/`):

```bash
cd forge
export DEPOSIT_AMOUNT_WEI=5000000          # example; use your amount and respect minimumDeposit
export MPC_ADDRESS=0xYourKeyGenAddress
export FORGE_LINEA_FEE_SIMULATE=true       # omit if the MPC already holds enough fee token on the fork
forge script script/LineaFeeApproveDeposit.s.sol:LineaFeeApproveDeposit \
  --rpc-url "https://rpc.linea.build" \
  --sender "$MPC_ADDRESS" \
  --skip-simulation
```

Foundry writes **`broadcast/LineaFeeApproveDeposit.s.sol/59144/dry-run/run-latest.json`** (when using **`--skip-simulation`**). If you run **without** **`--skip-simulation`** and the MPC has enough fee token on the RPC you use, the file may be under **`broadcast/.../59144/run-latest.json`** instead.

**2. Build `multiSignRequest` JSON** (repo root; **`--key-gen-id`** and **`--mpc-auth-url`** as elsewhere in this doc):

```bash
"$MPA_PATH/.venv/bin/python" "$MPA_PATH/scripts/generateSignRequestWithFoundryScript.py" \
  --key-gen-id=KeyGen... \
  --mpc-auth-url="$MPC_AUTH_URL:$MANAGEMENT_PORT" \
  --file=forge/broadcast/LineaFeeApproveDeposit.s.sol/59144/dry-run/run-latest.json \
  --destination-chain-id=59144 \
  --purpose="Linea fee token approve and deposit" \
  --override-sender=0xYourKeyGenAddress \
  --first-nonce="$(cast nonce 0xYourKeyGenAddress --rpc-url https://rpc.linea.build)" \
  --is-eip1559 --base-fee-gwei=30 --priority-fee-gwei=2 --gas-limit=200000 \
  --signature-texts='["ERC20 approve fee contract","Linea fee deposit"]'
```

Use **`--override-sender`** / **`--first-nonce`** when the broadcast **`from`** or nonces must match the live MPC account (see **Nonce and sender** under **Python script** above). Dry-run broadcast segments often omit **`gas`** and EIP-1559 fields; **use `--gas-limit` (e.g. 200000)** and fee flags so each transaction is encodable as type-2 txs. The Python output uses **`messageHashes`** / **`messageRawBatch`** for **two** transactions.

---

## What to do with the output

1. **Parse** the script’s stdout as JSON.
2. **Read** **`bodyForSign`** and **`messageToSign`** (and confirm **`endpoint`** is **`multiSignRequest`**).
3. **Add** to **`bodyForSign`** (or build the HTTP body as **`bodyForSign`** plus signing fields):
   - **keyList** / **pubKey**: already set by the Python script (same as `GET /getKeyGenResultById`). If not using the script, fetch manually; see [How to get keyList, pubKey, and clientSig](#how-to-get-keylist-pubkey-and-clientsig).
   - **clientSig** / **signedMessage**: management key (Ed25519 or MetaMask); sign **`messageToSign`** exactly—see the same section for step-by-step.
   - Optionally, but purpose is strongly recommended (including link to github if applicable): **`purpose`**, **`destinationAddress`**, **`extraJSON`**, **`signatureText`**.
4. **POST** the final **`POST /multiSignRequest`** body (**`bodyForSign`** fields + **`clientSig`** + **`signedMessage`**) only (not **/signRequest**—that path is for tx-check / relayer keys).
5. **Use** the returned `requestId` for:
   - **signRequestAgree** (multi-agree),
   - **EVM (AI agent):** **`executeSignResult.py`** only—it performs **triggerSignRequestById** (with **`txParams`** or **`txParamsBatch`** / **`messageHash`**) and **`getSignResultById`** as in **API_IMPLEMENTATION.md** / **`../skill/SKILL.md`**. Save the same helper stdout as **`--sign-request-file`** so **`bodyForSign`** (nonce, gas, **`proposalTxParams`**) is available if **GET** omits fields. For batch signatures, the script consumes `data.batchSignatures[i]` the same way as the web flow.

---

## Single vs batch (both use multiSignRequest)

| Count | Body fields (inside **`bodyForSign`**; always **POST /multiSignRequest**) |
|-------|---------------------------------------------------------------------------|
| 1     | **`msgHash`**, **`msgRaw`** (full serialized unsigned tx hex with **`0x`**), **`txParams`**, first-tx **`txNonce`** / **`txGasLimit`** / fee fields |
| ≥2    | **`messageHashes[]`**, **`messageRawBatch[]`**, top-level **`msgHash`** / **`msgRaw`** (first item), **`proposalTxParams[]`**, first-tx fee snapshot |

**Note:** Compose’s single-tx **`msgRaw`** is **calldata only** (no `0x`); this Foundry helper uses the **full RLP unsigned tx** in **`msgRaw`** for a single transaction—both are valid **`multiSignRequest`** shapes for the node; **`txParams`** matches the preimage.

**signRequest** is unrelated to this table (tx-check / relayer only). The script sets the correct **multiSignRequest** **`bodyForSign`** shape from the number of transactions.

---

## Checklist for the agent

- [ ] Obtain or generate Foundry broadcast JSON (e.g. `run-latest.json` or forge script JSON output).
- [ ] Run the Python script with that JSON as input.
- [ ] Parse the JSON output; use **`bodyForSign`** for **POST /multiSignRequest** (and **`messageToSign`** for management signing).
- [ ] Add **`clientSig`** / **`signedMessage`** to the POST body (`keyList`/`pubKey` already filled if using the Python script with `--key-gen-id`).
- [ ] POST the complete body to **POST /multiSignRequest** (not `/signRequest` for multi-agree keys).
- [ ] Use the returned `requestId` for agree, then **`executeSignResult.py`** for trigger + signatures + broadcast (**EVM** **`txParams`** / **`messageHash`** handled inside the script—see **API_IMPLEMENTATION.md** and **`../skill/SKILL.md`**).

---

## References

- **API:** `./API_IMPLEMENTATION.md` in this folder (§ POST /multiSignRequest, GET /getSignResultById). **signRequest** is documented there for tx-check / relayer flows only.
- **Batch behavior:** See **Single vs batch** in this document and **`./API_IMPLEMENTATION.md`** (`POST /multiSignRequest`).
