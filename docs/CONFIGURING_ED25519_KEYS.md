# Ed25519 management keys (technical lifecycle)

Lifecycle of **Ed25519 management keys** on an mpc-auth node used by the built-in AI agent (continuum-mcp) and other management-signed clients.

**User guides (docs.continuumdao.org):**

- [Default Ed25519 signer](https://docs.continuumdao.org/ContinuumDAO/MPAWallet/DefaultEd25519Signer)
- [Configure the AI harness](https://docs.continuumdao.org/ContinuumDAO/MPAWallet/AIHarness/Configure)
- [AI harness overview](https://docs.continuumdao.org/ContinuumDAO/MPAWallet/AIHarness/Overview)

**Not this document:**

- Per-request signing recipes (nonces, `clientSig`, `messageToSign`) → [references/ED25519_MANAGEMENT_KEY_SIGNING.md](./references/ED25519_MANAGEMENT_KEY_SIGNING.md)
- Full REST bodies → [references/API_IMPLEMENTATION.md](./references/API_IMPLEMENTATION.md)

---

## Concepts

| Concept | What it is |
|---------|------------|
| **Bootstrap key** | First allowed Ed25519 management public key in `configs.yaml` as **`PublicMgtKey`** (64 hex). Private seed on disk: `bootstrap_key/ed25519_private.hex`. |
| **Added (extra) keys** | Additional allow-list keys from **`POST /addManagementKey`**. Public rows in Mongo **`ExtraPublicMgtKeys`**; private PEM under `added_keys/added_key_<N>`. |
| **Preferred / default signer** | One active public key pointer (Mongo) that automation should use first: **`GET /getPreferredSigner`**, **`POST /setPreferredSigner`**. |
| **Management vs MPC** | Management Ed25519 authenticates this node’s HTTP API and **may** live on disk for the built-in agent. The **MPC / KeyGen wallet** never exists as a full on-chain private key on the node (threshold shares only). |

List allowed keys: **`GET /getAllowedEd25519MgtKeys`**, **`GET /getPublicMgtKey`**, **`GET /hasPublicMgtKey`**.

---

## Bootstrap key

### Created when

- **`process_config.sh`** always runs **`tools/bootstrap_key_provision.py`**.
- If **`PublicMgtKey`** is empty → write seed, set **`PublicMgtKey`**, set **`DeterministicNodeKey: true`**.
- If **`PublicMgtKey`** is already set (reinstall / restore) → verify `bootstrap_key/ed25519_private.hex` matches and set **`DeterministicNodeKey: true`** when valid.

### Stored

| Item | Location |
|------|----------|
| Private seed (32-byte hex, `0600`) | Host: `./bootstrap_key/ed25519_private.hex` next to `configs.yaml` · Container: `/app/bootstrap_key/ed25519_private.hex` |
| Public key | `configs.yaml` → **`PublicMgtKey`** (64 lowercase hex) |
| Deterministic node identity | **`DeterministicNodeKey: true`** (with matching seed + public key → stable P-256 **`nodeKey`** on fresh Mongo) |

**Docker mounts (mpc-config compose):** `./bootstrap_key` → `/app/bootstrap_key` (writable on `app`; typically read-only on `continuum-mcp`).

### API (see API_IMPLEMENTATION)

- **`POST /postBootstrapKey`** — write seed file when absent (management-signed)
- **`POST /fetchBootstrapKey`** — return seed for offline backup (HTTPS or loopback; eligibility gates apply)
- **`POST /removeBootstrapKey`** — delete seed file (management-signed)

### Used for

- Management allow-list auth (label typically **Bootstrap (config)**)
- Deterministic **`nodeKey`** and encrypted DB backup eligibility
- Agent / continuum-mcp signing when preferred signer points here or fallback resolves to bootstrap

---

## Extra (added) keys

### Created when

**`POST /addManagementKey`** — the node **generates** the keypair. Clients do **not** supply `newPublicKey`. Authorize with an already-allowed Ed25519 key or Ethereum **`NodeMgtKey`** (EIP-191). Exact body: **API_IMPLEMENTATION.md**.

### Stored

| Item | Location |
|------|----------|
| Public key + label | Mongo **`ExtraPublicMgtKeys`** (“Added key N”) |
| Private key (PKCS#8 PEM, `0600`) | Host: `./added_keys/added_key_<N>` · Container: `/app/added_keys/added_key_<N>` |
| Public hex file | `added_key_<N>.pub` |

**Docker:** `./added_keys` bind-mounted for `app` and `continuum-mcp`.

### Removed when

**`POST /removeManagementKey`** — soft-removes the Mongo row and deletes local files. **Cannot** remove the bootstrap **`PublicMgtKey`**.

### Used for

- Same management auth as bootstrap (per-key nonces via **`GET /getPublicMgtKeyNonce?publicKey=`**)
- Preferred signer may point at an added key

---

## How keys are selected for agent signing

Built-in harness (continuum-mcp) resolution order:

1. **`GET /getPreferredSigner`** — if `publicKeyHex` is set, that key is still in the active allow-list, and a matching local private key is readable under `/app/bootstrap_key` or `/app/added_keys` → use it.
2. Else → first allowed key with usable local private material.
3. Else → fail.

Operators set preferred via **`POST /setPreferredSigner`** or the node app (**Node → Ed25519 Management Keys**, Agent chat). User-facing steps: [Default Ed25519 signer](https://docs.continuumdao.org/ContinuumDAO/MPAWallet/DefaultEd25519Signer).

---

## Operator tools

| Tool | Purpose |
|------|---------|
| `$MPA_PATH/tools/openssh_ed25519_to_hex.py` | OpenSSH `.pub` / line → 64 hex public key |
| `$MPA_PATH/tools/ed25519_private_to_pubkey_hex.py` | Private PEM / OpenSSH / seed hex → 64 hex public (`cryptography` in `$MPA_PATH/.venv`) |
| `$MPA_PATH/tools/sign-clipboard` | Human clipboard signing helper |
| `$MPA_PATH/tools/check_ed25519_mgt_keygen.py` | Match private key against allow-list and KeyGen `ClientKeys` |

See [ED25519_MANAGEMENT_KEY_SIGNING.md](./references/ED25519_MANAGEMENT_KEY_SIGNING.md) § Tools.

---

## Security notes

- Protect on-disk **management** material (`bootstrap_key/`, `added_keys/`); do not commit seeds; restrict who can reach **`ManagementAPIsPort`**.
- Protecting management keys is separate from MPC: the node still never reconstructs or stores a full on-chain wallet private key.
- **External / script agents** that keep private keys off-node (e.g. `AUTH_KEY_PATH` / `~/.ssh/mpc_auth_ed25519`) still authenticate only if the matching public key is on the allow-list — see [ED25519_MANAGEMENT_KEY_SIGNING.md](./references/ED25519_MANAGEMENT_KEY_SIGNING.md) and [skill/SKILL.md](./skill/SKILL.md).
