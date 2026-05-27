# Ed25519 management signing (operational guide)

This document is for an **AI agent** or script that already has access to an **Ed25519 management private key** and calls the **management API** on an mpc-auth node. It does **not** cover generating keys, **`PublicMgtKey`** in config, or operator onboarding—see **`../CONFIGURING_ED25519_KEYS.md`** and **`./API_IMPLEMENTATION.md`**.

---

## 1. Check whether the node accepts Ed25519 management auth

| Goal | Endpoint | Success |
|------|----------|---------|
| Boolean: is any Ed25519 key configured? | **`GET /hasPublicMgtKey`** | `data: true` |
| List allowed keys (with labels) | **`GET /getAllowedEd25519MgtKeys`** | `data`: array of `{ "publicKey": "<64 hex>", "label": "…" }` |
| Same keys, plain array only | **`GET /getPublicMgtKey`** | `data`: array of 64-hex strings |

If **`hasPublicMgtKey`** is false, the node is not using Ed25519 management keys (it may use Ethereum **`NodeMgtKey`** only). See **`./API_IMPLEMENTATION.md`** (`GET /hasPublicMgtKey`, `GET /getAllowedEd25519MgtKeys`, `GET /getPublicMgtKey`).

---

## 2. Which private keys can you sign with?

The node stores **only public keys**. You must know which **private** keys you can use locally.

1. **Fetch the allow-list** with **`GET /getAllowedEd25519MgtKeys`** (or **`GET /getPublicMgtKey`**).
2. For each candidate private key file (e.g. **`$AUTH_KEY_PATH/$AUTH_KEY_FILENAME`** or **`~/.ssh/mpc_auth_ed25519`** per **`../skill/SKILL.md`** **Environment**), derive the **64-hex public key**:

   ```bash
   "$MPA_PATH/.venv/bin/python" "$MPA_PATH/tools/ed25519_private_to_pubkey_hex.py" /path/to/private_key
   ```

   (`cryptography` in **`$MPA_PATH/.venv`** — see **`../skill/SKILL.md`** **Python dependencies**.)

3. **Match** that hex string against the **`publicKey`** values from **`getAllowedEd25519MgtKeys`**. Only keys that appear in the list can authenticate **`POST`** requests.

If none of your keys match, you cannot sign management **`POST`**s on this node until the operator adds your public key (out of scope here).

---

## 3. Every `POST` needs a management signature

**Every** **`POST`** to the management API requires **management** authentication: **Ed25519** (this doc) or **Ethereum** **`NodeMgtKey`** / **`personal_sign`** (EIP-191), depending on what the node accepts (see **`./API_IMPLEMENTATION.md`** § *Using an Ethereum wallet or Ed25519 for Management API Authentication*).

- **`clientSig`** on **`POST /multiSignRequest`** and **`POST /signRequestAgree`** signs the canonical JSON body (with **`clientSig`** cleared) using the **management** key, together with **`nonce`** and **`nodeKey`**. Details: **`./AI_AGENT_COMPOSE_MULTISIGNREQUEST.md`** and **`./API_IMPLEMENTATION.md`**.

Do **not** confuse **management signatures** (per-node HTTP auth) with **MPC signatures** (threshold signing for the shared wallet).

---

## 4. Nonces: `GET /getPublicMgtKeyNonce` (Ed25519)

Replay protection uses **separate** nonce sequences in **`NodeMgtKeyHistory`** for **Ethereum** vs **Ed25519** signers. Using one **does not** advance the other.

Among **Ed25519** management keys, **each distinct keypair** (each **64-hex public key** in the allow-list—bootstrap **`PublicMgtKey`** plus every key added via **`POST /addManagementKey`**) has **its own** nonce counter. Signing a request with key **A** only advances **A**’s sequence; key **B**’s next nonce is unchanged.

| Signer | Next nonce |
|--------|------------|
| **Ed25519** management key (bootstrap **`PublicMgtKey`** or keys from **`POST /addManagementKey`**) | **`GET /getPublicMgtKeyNonce`** — add **`?publicKey=<64_hex>`** when the signer is an **added** key, not the config default |
| **Ethereum** **`NodeMgtKey`** (`personal_sign`) | **`GET /getNodeMgtKeyNonce`** |

**`GET /getPublicMgtKeyNonce`** and **`GET /getNodeMgtKeyNonce`** return **`Data`** shaped as **`{ "key": "<…>", "nonce": <int> }`** (`key` is either the **64-hex Ed25519** public key or the **`0x…`** NodeMgtKey, matching the endpoint).

**Do not** use **`getNodeMgtKeyNonce`** to track Ed25519 activity. If you only ever sign with Ed25519, **`getNodeMgtKeyNonce`** can stay at **`nonce: 0`** indefinitely.

**`nonce: 0`** means “the next successful request for this key should use nonce **0**” (no prior use for that signer in the DB).

### Where the nonce appears

- **Endpoints that use `nonce` + `clientSig` (management signature)** — e.g. **`POST /keyGenRequest`**, **`POST /keyGenRequestAgree`**, **`POST /multiSignRequest`**, **`POST /signRequestAgree`**, **`POST /keyGenEjectAgree`**, **`POST /triggerSignRequestById`**, **`POST /updateSignResultStatusById`**, **`POST /shelveSignRequest`**, **`POST /sendMessage`**, **`POST /markMessageRead`**, and other KeyGen messaging **`POST`**s per **`./API_KEYGEN_MESSAGING.md`** — you **must** fetch the current value from **`GET /getPublicMgtKeyNonce`** (Ed25519) immediately before building the body, embed that integer in the JSON together with **`nodeKey`** (128 hex from **`GET /getNodeKey`**), then produce **`clientSig`** over the canonical JSON with that field left empty (exact layout per **`./API_IMPLEMENTATION.md`** for that route).

### Do not confuse management nonces with **`globalNonce`**

**`globalNonce`** (from **`GET /getGlobalNonceByKeyGenId`**, also surfaced on **`GET /getKeyGenResultById`**) is a **per–KeyGen** counter tied to **MPC signing activity** on that wallet (for **secp256k1** / EVM-style keys it reflects completed MPC sign operations; other key types may report **`0`**). It is **unrelated** to HTTP replay protection.

**Management** nonces (**`GET /getPublicMgtKeyNonce`** / **`GET /getNodeMgtKeyNonce`**) are **per signing identity** on **this node’s management API** (each Ed25519 public key or the Ethereum **`NodeMgtKey`**). They only govern **`POST`** authentication to the management port.

The two systems do not advance each other: changing **`globalNonce`** does not change **`getPublicMgtKeyNonce`**, and vice versa.

---

## 5. KeyGen `ClientKeys`, `clientId`, and which key to use

A **KeyGen result** includes **`ClientKeys`**: a map from **node public key** (128 hex) → **client key** for that node (e.g. **Ethereum `0x…`** for browser-wallet management, or **Ed25519 64 hex** for agent-style signing). See **`GET /getKeyGenResultById`** in **`./API_IMPLEMENTATION.md`**.

### `clientId` on `multiSignRequest` payloads

Helpers such as **`generateMultiSignRequestFromCompose.py`** add an optional **`clientId`** field to the **`multiSignRequest`** body. They take it from **`ClientKeys`** (first non-empty value) or from compose JSON **`clientId`** / **`client_id`** override — see **`generateMultiSignRequestFromCompose.py`** (loads **`clientId`** from **`getKeyGenResultById`**). That value is **MPC / request metadata** for the proposal, not the same field as the HTTP **management** signature.

### Same identity for KeyGen-scoped actions

For **KeyGen messaging** (`POST /sendMessage`, `POST /markMessageRead`, …), the server chooses **Ethereum `personal_sign` vs Ed25519** verification based on **your** entry in **`ClientKeys`** for that KeyGen (**`./API_KEYGEN_MESSAGING.md`** § *Management key signature*). In practice:

- Use the **Ed25519 private key** whose **64-hex public key** matches **your** **`ClientKeys`** value for this KeyGen **and** appears in **`getAllowedEd25519MgtKeys`** for management **`POST`**s.
- Keep **management** signing **consistent** for that KeyGen across **`sendMessage`**, **`multiSignRequest`** (as **`clientSig`**), **`signRequestAgree`**, **`triggerSignRequestById`**, etc., per the **API** rules for each route.

### KeyGen actions (management-signed vs read-only)

| Action | Endpoint | Management signature |
|--------|----------|----------------------|
| Create KeyGen | **`POST /keyGenRequest`** | Yes — **`nonce`**, **`sig`** (see API_IMPLEMENTATION) |
| Agree to KeyGen | **`POST /keyGenRequestAgree`** | Yes — **`nonce`**, **`sig`** |
| Send a message | **`POST /sendMessage`** | Yes — **`Nonce`**, **`Sig`** (see API_KEYGEN_MESSAGING) |
| Mark read | **`POST /markMessageRead`**, **`POST /multiMarkMessagesRead`** | Yes |
| Delete | **`POST /deleteMessage`**, **`POST /multiDeleteMessages`** | Yes (originator rules apply) |
| List / read | **`GET /listMessages`**, **`GET /getMessageById`**, **`GET /getMessageThread`** | No (must be in KeyList) |

---

## 6. Tools (`$MPA_PATH/tools/`)

| Tool | Path | Use |
|------|------|-----|
| **`sign-clipboard`** | **`$MPA_PATH/tools/sign-clipboard`** (see **`README.md`** there) | Sign the **exact** UTF-8 string the API expects. For automation, use **`--inline`** or **`--inline-file`** (not clipboard) so the signed bytes match the **`POST`** body or **`messageToSign`**. |
| **`ed25519_private_to_pubkey_hex.py`** | **`$MPA_PATH/tools/ed25519_private_to_pubkey_hex.py`** | Derive **64-hex** public key from a private key file to **match** **`getAllowedEd25519MgtKeys`**. |
| **`check_ed25519_mgt_keygen.py`** | **`$MPA_PATH/tools/check_ed25519_mgt_keygen.py`** | Given **`--seed-hex`** or **`--key-file`**, derive the Ed25519 **64-hex** pubkey and check **`GET /getAllowedEd25519MgtKeys`** and **`GET /getKeyGenResultById` → `ClientKeys`** (exit **0** only if the key appears in **both**). Use when debugging **`client sig is not valid`** on **`POST /multiSignRequest`** (see **§8**). Requires **PyNaCl**; **`--key-file`** needs **cryptography**. |

**Example (`sign-clipboard`):**

```bash
SIG=$(sign-clipboard --inline-file /path/to/unsigned_body.json)
curl -sS -X POST "$MPC_AUTH_URL:$MANAGEMENT_PORT/..." \
  -H 'Content-Type: application/json' \
  -d "$(jq --arg s "$SIG" '. + {sig: $s}' unsigned_body.json)"
```

(Adjust field names **`sig`** / **`Sig`** / **`clientSig`** per **`./API_IMPLEMENTATION.md`** for each endpoint.)

---

## 7. Raw 32-byte seed vs key file (avoid PKCS#8 / base64 confusion)

Some flows expose the **private key** as **PKCS#8 DER** (often shown as a **Base64** line) or as an **OpenSSH** / **PEM** file. Those are **not** the same thing as the **raw Ed25519 seed** used by helpers that take **`--ed25519-seed-hex`** or the env var **`MPC_MGT_ED25519_SEED_HEX`** in **`../skill/SKILL.md`** / **`scripts/mpc_mgt_helpers.py`**.

| What you have | What to do |
|-----------------|------------|
| **64 hex characters** (32 bytes), lowercase/uppercase hex | Valid **`MPC_MGT_ED25519_SEED_HEX`** / **`--ed25519-seed-hex`**. |
| **OpenSSH** (`-----BEGIN OPENSSH PRIVATE KEY-----`) or **PEM** file on disk | Use **`--ed25519-key-file`** on recipes (e.g. **`recipes/linea_register.py`**) or rely on **`AUTH_KEY_PATH`** + **`AUTH_KEY_FILENAME`** so **`mpc_mgt_helpers.load_ed25519_private_key()`** loads the file—**do not** `cat` the file into **`MPC_MGT_ED25519_SEED_HEX`**. |
| **Base64** blob starting with **`MC`** (or similar) — PKCS#8 **DER** for Ed25519 | **Not** valid hex seed. Either save the key as a proper **`.pem`** / OpenSSH file and use **`--ed25519-key-file`**, or derive the **32-byte seed** with **`cryptography`** (same as loading that DER) and then use the **64-hex** seed only if you must use env-based signing. |

If a recipe or script fails before printing JSON (e.g. empty **`curl -d`** and **`Error":"EOF"`** on **`POST /multiSignRequest`**), the usual cause is **invalid seed hex** (wrong length or wrong encoding), not the MPC logic.

---

## 8. Troubleshooting: `client sig is not valid` on `POST /multiSignRequest`

The management **`clientSig`** must be an **Ed25519** signature (128 hex) over **`signedMessage`** (same bytes as **`messageToSign`** from the helper). If the node rejects the signature, check **in order**:

1. **KeyGen `ClientKeys` vs your key** — For multi-agree KeyGens, mpc-auth expects the signer’s **64-hex Ed25519 public key** to appear as **a value** in **`GET /getKeyGenResultById` → `ClientKeys`** for the KeyGen you are using (the client identity your **node** registered for that wallet). If **`getAllowedEd25519MgtKeys`** lists an **added** key but **`ClientKeys`** still has only the **bootstrap** public key (or an **Ethereum `0x…`** client address), signing with the **added** key will fail until **`ClientKeys`** matches that identity for your node (same onboarding as the web app).

2. **Allow-list** — **`GET /getAllowedEd25519MgtKeys`** must include your public key.

3. **Run the checker** — From the repo root:

   ```bash
   python3 tools/check_ed25519_mgt_keygen.py \
     --mpc-base "http://127.0.0.1:8080" \
     --key-gen-id "KeyGen2026..." \
     --seed-hex "$ED25519_SEED_HEX"
   ```

   Or **`--key-file ~/.ssh/mpc_auth_ed25519`**. Exit code **0** only if the derived pubkey appears in **both** the allow-list and **`ClientKeys`**.

4. **Fresh payload** — Re-run the recipe **once** and **`POST`** immediately; **`msgHash`** / fees tie to RPC state—do not mix an old **`clientSig`** with a new body.

---

## 9. Further reading

| Topic | Document |
|--------|----------|
| Bootstrap **`PublicMgtKey`**, add keys, private key file layout | **`../CONFIGURING_ED25519_KEYS.md`** |
| **`multiSignRequest`** creation (recipes, helpers, **never** hand-roll tx payloads) | **`./AI_AGENT_COMPOSE_MULTISIGNREQUEST.md`** |
| Foundry → **`multiSignRequest`** | **`./AI_AGENT_FORGE_SIGNREQUEST.md`** |
| KeyGen messaging bodies | **`./API_KEYGEN_MESSAGING.md`** |
| Full REST spec | **`./API_IMPLEMENTATION.md`** |
| Agent env defaults (`$MPA_PATH/.env`, **`AUTH_KEY_PATH`**, **`MPC_MGT_ED25519_SEED_HEX`**) | **`../skill/SKILL.md`** **Environment** |
