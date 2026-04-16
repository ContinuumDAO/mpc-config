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

**Every** **`POST`** to the management API requires **management** authentication: **Ed25519** (this doc) or **Ethereum** **`NodeMgtKey`** / MetaMask (`personal_sign`), depending on what the node accepts (see **`./API_IMPLEMENTATION.md`** § *Using MetaMask or Ed25519 for Management API Authentication*).

- **`clientSig`** on **`POST /multiSignRequest`** signs the **canonical `messageToSign`** string with the **management** key (not the MPC key). Details and **`signedMessage`** rules: **`./AI_AGENT_COMPOSE_MULTISIGNREQUEST.md`** and **`./AI_AGENT_FORGE_SIGNREQUEST.md`**.

Do **not** confuse **management signatures** (per-node HTTP auth) with **MPC signatures** (threshold signing for the shared wallet).

---

## 4. Nonces: `GET /getPublicMgtKeyNonce` (Ed25519)

Replay protection uses **separate** nonce sequences in **`NodeMgtKeyHistory`** for **Ethereum** vs **Ed25519** signers. Using one **does not** advance the other.

Among **Ed25519** management keys, **each distinct keypair** (each **64-hex public key** in the allow-list—bootstrap **`PublicMgtKey`** plus every key added via **`POST /addManagementKey`**) has **its own** nonce counter. Signing a request with key **A** only advances **A**’s sequence; key **B**’s next nonce is unchanged.

| Signer | Next nonce |
|--------|------------|
| **Ed25519** management key (bootstrap **`PublicMgtKey`** or keys from **`POST /addManagementKey`**) | **`GET /getPublicMgtKeyNonce`** — add **`?publicKey=<64_hex>`** when the signer is an **added** key, not the config default |
| **Ethereum** **`NodeMgtKey`** (MetaMask / `personal_sign`) | **`GET /getNodeMgtKeyNonce`** |

**`GET /getPublicMgtKeyNonce`** and **`GET /getNodeMgtKeyNonce`** return **`Data`** shaped as **`{ "key": "<…>", "nonce": <int> }`** (`key` is either the **64-hex Ed25519** public key or the **`0x…`** NodeMgtKey, matching the endpoint).

**Do not** use **`getNodeMgtKeyNonce`** to track Ed25519 activity. If you only ever sign with Ed25519, **`getNodeMgtKeyNonce`** can stay at **`nonce: 0`** indefinitely.

**`nonce: 0`** means “the next successful request for this key should use nonce **0**” (no prior use for that signer in the DB).

### Where the nonce appears

- **Endpoints that use `nonce` + `sig` (or `Nonce` + `Sig`)** — e.g. **`POST /keyGenRequest`**, **`POST /keyGenRequestAgree`**, **`POST /triggerSignRequestById`**, **`POST /updateSignResultStatusById`**, **`POST /shelveSignRequest`**, **`POST /sendMessage`**, **`POST /markMessageRead`**, and other KeyGen messaging **`POST`**s per **`./API_KEYGEN_MESSAGING.md`** — you **must** fetch the current value from **`GET /getPublicMgtKeyNonce`** (Ed25519) immediately before building the body, embed that integer in the JSON, then produce **`sig`/`Sig`** over the canonical JSON with that field left empty (exact layout per **`./API_IMPLEMENTATION.md`** for that route).
- **`POST /multiSignRequest`** and **`POST /signRequestAgree`** — use **`clientSig`** over the **documented** JSON body ( **`messageToSign`** / compact JSON without **`clientSig`** for **`multiSignRequest`**). They do **not** use the same **`nonce`** field as **`getPublicMgtKeyNonce`** in the body; replay protection is via the signed payload. Still use **`getPublicMgtKeyNonce`** for **`triggerSignRequestById`**, **`sendMessage`**, etc.

### Do not confuse management nonces with **`globalNonce`**

**`globalNonce`** (from **`GET /getGlobalNonceByKeyGenId`**, also surfaced on **`GET /getKeyGenResultById`**) is a **per–KeyGen** counter tied to **MPC signing activity** on that wallet (for **secp256k1** / EVM-style keys it reflects completed MPC sign operations; other key types may report **`0`**). It is **unrelated** to HTTP replay protection.

**Management** nonces (**`GET /getPublicMgtKeyNonce`** / **`GET /getNodeMgtKeyNonce`**) are **per signing identity** on **this node’s management API** (each Ed25519 public key or the Ethereum **`NodeMgtKey`**). They only govern **`POST`** authentication to the management port.

The two systems do not advance each other: changing **`globalNonce`** does not change **`getPublicMgtKeyNonce`**, and vice versa.

---

## 5. KeyGen `ClientKeys`, `clientId`, and which key to use

A **KeyGen result** includes **`ClientKeys`**: a map from **node public key** (128 hex) → **client key** for that node (e.g. **Ethereum `0x…`** for MetaMask, or **Ed25519 64 hex** for agent-style signing). See **`GET /getKeyGenResultById`** in **`./API_IMPLEMENTATION.md`**.

### `clientId` on `multiSignRequest` payloads

Helpers such as **`generateMultiSignRequestFromCompose.py`** add an optional **`clientId`** field to the **`multiSignRequest`** body. They take it from **`ClientKeys`** (first non-empty value) or from compose JSON **`clientId`** / **`client_id`** override — see **`generateMultiSignRequestFromCompose.py`** (loads **`clientId`** from **`getKeyGenResultById`**). That value is **MPC / request metadata** for the proposal, not the same field as the HTTP **management** signature.

### Same identity for KeyGen-scoped actions

For **KeyGen messaging** (`POST /sendMessage`, `POST /markMessageRead`, …), the server chooses **MetaMask vs Ed25519** verification based on **your** entry in **`ClientKeys`** for that KeyGen (**`./API_KEYGEN_MESSAGING.md`** § *Management key signature*). In practice:

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

## 6. Tools: `sign-clipboard` and `ed25519_private_to_pubkey_hex.py`

| Tool | Path | Use |
|------|------|-----|
| **`sign-clipboard`** | **`$MPA_PATH/tools/sign-clipboard`** (see **`README.md`** there) | Sign the **exact** UTF-8 string the API expects. For automation, use **`--inline`** or **`--inline-file`** (not clipboard) so the signed bytes match the **`POST`** body or **`messageToSign`**. |
| **`ed25519_private_to_pubkey_hex.py`** | **`$MPA_PATH/tools/ed25519_private_to_pubkey_hex.py`** | Derive **64-hex** public key from a private key file to **match** **`getAllowedEd25519MgtKeys`**. |

**Example (`sign-clipboard`):**

```bash
SIG=$(sign-clipboard --inline-file /path/to/unsigned_body.json)
curl -sS -X POST "$MPC_AUTH_URL:$MANAGEMENT_PORT/..." \
  -H 'Content-Type: application/json' \
  -d "$(jq --arg s "$SIG" '. + {sig: $s}' unsigned_body.json)"
```

(Adjust field names **`sig`** / **`Sig`** / **`clientSig`** per **`./API_IMPLEMENTATION.md`** for each endpoint.)

---

## 7. Further reading

| Topic | Document |
|--------|----------|
| Bootstrap **`PublicMgtKey`**, add keys, private key file layout | **`../CONFIGURING_ED25519_KEYS.md`** |
| **`multiSignRequest`** creation (recipes, helpers, **never** hand-roll tx payloads) | **`./AI_AGENT_COMPOSE_MULTISIGNREQUEST.md`** |
| Foundry → **`multiSignRequest`** | **`./AI_AGENT_FORGE_SIGNREQUEST.md`** |
| KeyGen messaging bodies | **`./API_KEYGEN_MESSAGING.md`** |
| Full REST spec | **`./API_IMPLEMENTATION.md`** |
| Agent env defaults (`$MPA_PATH/.env`, **`AUTH_KEY_PATH`**) | **`../skill/SKILL.md`** **Environment** |
