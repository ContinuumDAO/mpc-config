# Configuring Ed25519 management keys (node owner guide)

This guide is for **operators and node owners** who want mpc-auth to accept **Ed25519** management authentication (so agents or scripts can call the management API **without an Ethereum wallet / EIP-191 signing**). It covers **creating keys**, **putting the public key on the node**, **adding more allowed keys**, and **where to store private key material**.

**Day-to-day API signing** (nonces, `clientSig`, `messageToSign`, `getAllowedEd25519MgtKeys`, tools): use **[references/ED25519_MANAGEMENT_KEY_SIGNING.md](./references/ED25519_MANAGEMENT_KEY_SIGNING.md)** — not this document.

**Full REST details** (exact bodies, `POST /addManagementKey`, etc.): **[references/API_IMPLEMENTATION.md](./references/API_IMPLEMENTATION.md)**.

**Agent environment** (`AUTH_KEY_PATH`, `$MPA_PATH/.env`): **[skill/SKILL.md](./skill/SKILL.md)** **Environment**.

---

## What the node stores vs what you keep secret

- The node configuration holds **only Ed25519 public keys** (e.g. bootstrap **`PublicMgtKey`** as **64 lowercase hex** = 32-byte public key, no `0x` prefix).
- **Private keys never go on the node.** You keep the private key where signing happens (your workstation, or the agent host’s **`~/.ssh/mpc_auth_ed25519`** / **`AUTH_KEY_PATH`**).
- After bootstrap, you can add more public keys with **`POST /addManagementKey`** (each request signed by an already-allowed Ed25519 key). See **API_IMPLEMENTATION.md** (`POST /addManagementKey`, `GET /getAllowedEd25519MgtKeys`).

---

## 1. Create or obtain an Ed25519 keypair

You may use any tool that produces a standard **Ed25519** private key and lets you derive the **raw 32-byte public key** as **64 hex** for **`PublicMgtKey`**.

Common options:

- **`ssh-keygen -t ed25519`** — produces OpenSSH public/private files. The **`.pub` line is not** the hex mpc-auth stores; convert with **`$MPA_PATH/tools/openssh_ed25519_to_hex.py`** (stdlib-only) on the `.pub` file or pasted line.
- **`openssl genpkey -algorithm ED25519`** — PEM private key; derive **64 hex** with **`$MPA_PATH/tools/ed25519_private_to_pubkey_hex.py`** (needs **`cryptography`** in **`$MPA_PATH/.venv`** — see **SKILL.md** **Python dependencies**).
- **continuumdao-node-app → Info** — if the app offers **Create new key pair**, you can copy the **public key (64 hex)** into config and save the **private** PEM to a secure path (the node never sees the private key).

**OpenSSH `.pub` → 64 hex:**

```bash
python3 "$MPA_PATH/tools/openssh_ed25519_to_hex.py" ~/.ssh/id_ed25519.pub
```

---

## 2. Configure the node (mpc-auth)

Set **`PublicMgtKey`** in **`configs.yaml`** or via environment:

```yaml
PublicMgtKey: "<64-hex-public-key>"
```

```bash
export PublicMgtKey="<64-hex-public-key>"
```

Restart mpc-auth. Confirm Ed25519 is active:

```bash
curl "http://<host>:<ManagementAPIsPort>/hasPublicMgtKey"
# Expect data: true (envelope may use Code/Data or code/data per build)
```

**List allowed keys:** The value you set as **`PublicMgtKey`** is the **bootstrap** management key—the first Ed25519 public key the node trusts from config. Keys added later via **`POST /addManagementKey`** are separate entries. To see every allowed **64-hex** public key with a short **label**, call **`GET /getAllowedEd25519MgtKeys`**. The API marks the bootstrap key explicitly (typically **`label`** such as **`Bootstrap (config)`**), so you can tell which **`publicKey`** came from **`PublicMgtKey`** versus **Added key …** for keys registered through the API.

```bash
curl "http://<host>:<ManagementAPIsPort>/getAllowedEd25519MgtKeys"
```

Interactive installs may use **`process_config.sh`** in this repo to normalize **`PublicMgtKey`** from OpenSSH or base64 when prompted.

---

## 3. Add another public key (e.g. dedicated agent key)

After **`PublicMgtKey`** is set, you can register additional **64-hex** public keys with **`POST /addManagementKey`**. The request must be **signed with an already-allowed** Ed25519 private key (the bootstrap key or a previously added key). Exact JSON, nonce, and signature layout: **API_IMPLEMENTATION.md** (`POST /addManagementKey`, `GET /getPublicMgtKeyNonce`).

This lets you rotate or separate **human** vs **automation** keys without editing node config again.

---

## 4. Where to put the private key for an agent

Agents read a **management** private key from disk (OpenSSH or PEM):

- Default path: **`~/.ssh/mpc_auth_ed25519`** if **`AUTH_KEY_PATH`** is unset.
- Or set **`AUTH_KEY_PATH`** to a **directory** and **`AUTH_KEY_FILENAME`** (default **`mpc_auth_ed25519`**) — see **SKILL.md** **Environment**.
- Prefer **`chmod 600`** on the key file and a dedicated user or service account if you run the agent as a service.

Load **`MPC_AUTH_URL`**, **`MANAGEMENT_PORT`**, and optionally **`MPA_PATH`** from **`$MPA_PATH/.env`** (or your process manager) so the same **`mpc-config`** tree can live anywhere on disk.

**Verify** the file matches an allowed public key: **`ed25519_private_to_pubkey_hex.py`** vs **`getAllowedEd25519MgtKeys`** — summarized in **ED25519_MANAGEMENT_KEY_SIGNING.md** §2.

---

## 5. Key management practices

- **Backup** the private key in an offline or secure store; loss means you cannot sign management **`POST`**s until another allowed key or operator recovery path exists.
- **Do not** commit private keys, put them in the frontend, or paste them into node config.
- **Restrict** who can reach **`ManagementAPIsPort`** (firewall, TLS reverse proxy, bind to loopback when only local agents should connect).
- **Rotation:** add a new public key with **`POST /addManagementKey`**, switch automation to the new private key, then plan deprecation of the old key with your security policy.

---

## 6. Relationship to MPC / KeyGen (short)

**Management** Ed25519 keys authenticate **this node’s HTTP API**. They are **not** the MPC wallet key. For **KeyGen**, you may register a **client** public key (`clientPk` / **`ClientKeys`**) as required by the app — that is separate from **`PublicMgtKey`**, though operators often use the **same** Ed25519 identity for simplicity. Operational details: **ED25519_MANAGEMENT_KEY_SIGNING.md** §5 and **API_KEYGEN_MESSAGING.md**.

For **groups, KeyGen, threshold signing, and workflows**, see **[references/instructions.md](./references/instructions.md)** and **[skill/SKILL.md](./skill/SKILL.md)**.
