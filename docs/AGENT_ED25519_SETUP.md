# Agent Ed25519 setup for node management

This doc describes how a **node owner** can set up their node so that an **AI agent** (e.g. Open Claw or any automated process) can perform management signing using an Ed25519 keypair—without MetaMask. The agent can then call the node APIs for signRequestAgree, triggerSignRequestById, updateSignResultStatusById, shelveSignRequest, and keyGen (create/join) using Ed25519 signatures.

## Summary

1. **Node** stores only the **public** key in config (`PublicMgtKey`). It verifies signatures over the port; it never holds the private key.
2. **You (the node owner)** bootstrap the node with one Ed25519 key in config (`PublicMgtKey`) and then add additional allowed Ed25519 management keys via **`POST /addManagementKey`** (signed by an already-allowed Ed25519 key), as documented in `API_IMPLEMENTATION.md`.
3. **Agent key onboarding** is done by adding the agent’s **public** key to the allowed set via **`POST /addManagementKey`**. The agent keeps its **private** key (e.g. at `~/.ssh/mpc_auth_ed25519`) and uses it to sign management requests; the node never holds private keys.
4. **Signing** is done by you (via a local helper or by pasting the 128-hex signature in the frontend) or by the agent (using its key and then calling the node API over the port with the signature). Access to the node is over the port and is secure.
5. No new node endpoints are required; the app uses **hasPublicMgtKey** and the existing management APIs.

## 1. Node setup (one-time, by the node owner)

### 1.1 Bootstrap the node with an Ed25519 management key (PublicMgtKey)

The node needs **at least one** allowed Ed25519 management key to start with (the “bootstrap key”). This is provided via config as **`PublicMgtKey`**: the raw **32-byte Ed25519 public key** written as **64 lowercase hex characters** (no `0x` prefix). After that, you can add more keys (e.g. an agent key) via **`POST /addManagementKey`** without editing config again.

**OpenSSH `.pub` format is not what mpc-auth stores**—if you only have a line like `ssh-ed25519 AAAA… comment` (or the **base64 middle field** alone), convert it first. In this bundle, **`$MPA_PATH/tools/openssh_ed25519_to_hex.py`** (stdlib only) accepts the full line or the base64 blob and prints **64 hex** on stdout.

```bash
python3 "$MPA_PATH/tools/openssh_ed25519_to_hex.py" ~/.ssh/id_ed25519.pub
# or: echo 'ssh-ed25519 AAAA…' | python3 "$MPA_PATH/tools/openssh_ed25519_to_hex.py"
```

**`process_config.sh`** (same repo) can also prompt for or normalize **`PublicMgtKey`** from OpenSSH / base64 when you run it interactively or when the value is already in **`configs.yaml`**. For a **private** key file (PEM / OpenSSH), use **`$MPA_PATH/tools/ed25519_private_to_pubkey_hex.py`**: it needs **`cryptography`** in **`$MPA_PATH/.venv`** — e.g. **`$MPA_PATH/.venv/bin/pip install cryptography`**, then **`$MPA_PATH/.venv/bin/python "$MPA_PATH/tools/ed25519_private_to_pubkey_hex.py" …`** (see **[SKILL.md](../skill/SKILL.md)** **Python dependencies**).

How you generate the bootstrap keypair is otherwise up to you. The important part is: **you end up with a 64-hex Ed25519 public key** for `PublicMgtKey`, and you keep the corresponding private key somewhere safe for signing (human helper or the agent).

### 1.2 Configure the node (mpc-auth) with the public key

In the mpc-auth repo, set **PublicMgtKey** in `configs.yaml` or via environment:

```yaml
# configs.yaml
PublicMgtKey: "<64-hex-public-key>"
```

Or:

```bash
export PublicMgtKey="<64-hex-public-key>"
```

Restart the mpc-auth node. Verify:

```bash
curl http://<node-host>:<port>/hasPublicMgtKey
# Expect: {"code":0,"data":true,...}
```

### 1.3 Add the agent’s Ed25519 public key via `POST /addManagementKey` (recommended)

Once the node is bootstrapped with `PublicMgtKey`, add the agent’s public key to the allowed set using the API described in `API_IMPLEMENTATION.md`.

- **Goal**: allow the agent to sign management API requests with its own Ed25519 key, without changing node config.
- **Auth**: the `POST /addManagementKey` request **must be signed by an already-allowed Ed25519 key** (the bootstrap `PublicMgtKey`, or a key previously added).

**Request body (canonical message to sign):**

- Fetch nonce for the signer key (response is `{ "Code":0, "Data": { "key":"<64 hex or 0x…>", "nonce":<int> } }` — use **`Data.nonce`**):

```bash
curl "http://<node-host>:<port>/getPublicMgtKeyNonce"
# or, if you have multiple allowed keys and need the signer’s nonce explicitly:
# curl "http://<node-host>:<port>/getPublicMgtKeyNonce?publicKey=<64-hex-signer-public-key>"
```

- Build the exact JSON string and sign it with the signer’s Ed25519 private key (signature must be **128 hex**). The canonical string is the JSON body **with `sig` set to empty string**:

```json
{"newPublicKey":"<64-hex-agent-public-key>","nonce":<nonce_from_getPublicMgtKeyNonce>,"sig":""}
```

- Then POST the same body with `sig` filled in:

```bash
curl -X POST "http://<node-host>:<port>/addManagementKey" \
  -H "Content-Type: application/json" \
  -d '{"newPublicKey":"<64-hex-agent-public-key>","nonce":<n>,"sig":"<128-hex-ed25519-signature>"}'
```

Optional: list allowed keys (bootstrap + added) so you can confirm it’s present:

```bash
curl "http://<node-host>:<port>/getAllowedEd25519MgtKeys"
```

### 1.4 Frontend: connect the node

From the app, attach the node by its URL (e.g. `https://your-node.example.com`). You can connect MetaMask for your own use; the agent will use Ed25519.

## 2. KeyGen: use Ed25519 for this key (optional but recommended for agent-only flows)

When **creating** or **joining** a multi-agree key (Keys page):

- Choose **"Ed25519 keypair"** as the multi-sign client auth.
- For **join**, provide this node's **Ed25519 public key** (same 64 hex as `PublicMgtKey`) as the client key so the node is identified by that key for that keyGen.

Then for that keyGen, the frontend will use the Ed25519 flow for Compose and for **Accept/Reject** (signRequestAgree): it shows the message to sign; you sign with your private key (local helper or CLI) and paste the 128-hex signature, or the agent signs with its key and POSTs to the node.

## 3. What the agent can do with Ed25519

Once PublicMgtKey is set on the node, the backend will accept Ed25519 signatures for:

| Action              | Endpoint                     | Notes |
|---------------------|-----------------------------|-------|
| Create sign request | `POST /multiSignRequest`     | Build body (keyList, pubKey, msgHash, msgRaw, destinationChainID, etc.); sign with Ed25519; send as clientSig (128 hex) + signedMessage. Agent can initiate new multi-sign requests with their key. |
| Agree/Reject        | `POST /signRequestAgree`     | Message = JSON body (requestId, clientSig: "", accept, thoughts?, nonce). Sign with Ed25519; send as clientSig (128 hex) + signedMessage. |
| Trigger sign        | `POST /triggerSignRequestById` | Same pattern: get nonce, build body, sign, send **`Sig`** (management). **EVM multi-agree:** the body **must** also include **`txParams`** and **`messageHash`** so the node stores them—see **[API_IMPLEMENTATION.md](./API_IMPLEMENTATION.md)** § **`POST /triggerSignRequestById`**. |
| Update result status| `POST /updateSignResultStatusById` | Same pattern. |
| Shelve request      | `POST /shelveSignRequest`    | Body shape: Nonce, RequestId, Sig. Sign the JSON string; send Sig (Ed25519 128 hex). |
| KeyGen create/join  | `POST /keyGenRequest`, `POST /keyGenRequestAgree` | Use clientPk = 64-hex Ed25519 public key; sign payload with Ed25519. |

| KeyGen Actions                | Endpoint                      | Notes |
| ------------------------------|-------------------------------|-------|
| Send a message                | `POST /sendMessage`           | Send a message (top-level or reply) in a keyGen channel (mgt key required) |
| List messages                 | `GET /listMessages`           | List messages (with unread, time range, top_level, pagination) |
| Get a single message by id    | `GET /getMessageById`         | Get message thread |
| Get a top-level message       | `GET /getMessageThread`       | Get a top-level message and its reply tree (nested, max depth 3) |
| Mark a message as read        | `POST /markMessageRead`       | Mark a message as read (add read receipt) (mgt key required) |
| Mark multiple messages as read| `POST /multiMarkMessagesRead` | Mark multiple messages as read (list of message ids) (mgt key required) |
| Delete a message              | `POST /deleteMessage`         | Delete a message and all its replies (originator only) (mgt key required) |
| Delete multiple messages      | `POST /multiDeleteMessages`   | Delete multiple messages (and their reply trees); originator-only per message; mgt key required |

The agent should communicate its actions and intentions using the message channel to all nodes in the group of the KeyGen.

The agent needs to:

1. **Fetch the next nonce for the Ed25519 key you sign with:** `GET /getPublicMgtKeyNonce` (uses config `PublicMgtKey` when the query param is omitted) or `GET /getPublicMgtKeyNonce?publicKey=<64-hex>` when signing with an **added** key. **Do not** use `GET /getNodeMgtKeyNonce` for Ed25519—that endpoint returns the nonce sequence for the Ethereum **`NodeMgtKey`** only (`Data.key` is a `0x…` address). If you only ever sign with Ed25519, `getNodeMgtKeyNonce` can stay at `nonce: 0` while `getPublicMgtKeyNonce` increases—see **[API_IMPLEMENTATION.md](./API_IMPLEMENTATION.md)** (`GET /getNodeMgtKeyNonce`, `GET /getPublicMgtKeyNonce`). Both nonce endpoints return `Data` as `{ "key": "…", "nonce": <int> }`.
2. Build the exact JSON body expected by the endpoint (with `clientSig` or `Sig` empty).
3. Sign that JSON string with the Ed25519 **private** key; produce 128 hex characters.
4. POST the body with `clientSig` (or `Sig`) set to that signature and `signedMessage` set to the same JSON string when the API requires it.

## 4. Using the frontend with Ed25519 (user on PC)

If the keyGen uses Ed25519 client auth:

- **Compose:** After you click OK, the app shows the message to sign and a field to paste the 128-hex Ed25519 signature (from your CLI or script), then Submit.
- **Accept/Reject:** Click Accept or Reject; the app fetches the nonce and shows the same "Sign with Ed25519" panel (message + signature field). Paste the signature and Submit.

So you can use the frontend without MetaMask for that key by signing elsewhere and pasting the signature.

## 5. Info page: create key pair and instructions

On the **Info** page, once the wallet is connected and the node URL matches:

- The app uses **`GET /hasPublicMgtKey`** (mpc-auth API) to see if the node allows Ed25519 management keys (bootstrap `PublicMgtKey` or keys added via `POST /addManagementKey`).
- If configured, it can show "Ed25519 management key is configured" and you can use Ed25519 for management operations. At this point, the recommended way to onboard an **agent key** is to add the agent’s **public** key via **`POST /addManagementKey`** (see section 1.3 and `API_IMPLEMENTATION.md`) rather than editing node config.
- If not configured, a **Create new key pair** button is shown. Clicking it generates an Ed25519 keypair in the browser. You are shown:
  - **Public key (64 hex)** with a copy button. Use this as the **bootstrap key** by putting it into the `PublicMgtKey` field of `configs.yaml` on the node (or set the `PublicMgtKey` environment variable), then restart the node.
  - **Private key** (PEM) with a copy button and a warning that you will not be shown it again. Save it to `~/.ssh/mpc_auth_ed25519` on **your PC** (or the machine that will do signing); set permissions to 600. The node never holds private keys.
- After creation, the option to create again is hidden unless you click **"I've removed the key and config, create a new key pair"**.
- For an AI agent on the same machine: put the agent’s private key in `~/.ssh/mpc_auth_ed25519` (chmod 600). The agent signs locally and calls the node over the port with the signature.

No new node endpoints are required; see `MPC_AUTH_ED25519_NODE_API.md` (in the node-app repo if applicable).

## 6. Agent on the same machine: reading the private key from disk

If the AI agent (or a signing helper) runs **on the same machine as the node**, it can read the Ed25519 private key from disk instead of receiving signatures from elsewhere.

- **Path:** Use only **`~/.ssh/mpc_auth_ed25519`** for the private key (on your PC or the agent's machine). Configure the agent (or your helper) to read that path and sign the exact message string the backend expects.
- **Key format:** The file at `~/.ssh/mpc_auth_ed25519` can be OpenSSH or PEM format. Sign the **exact** JSON message string (no EIP-191 wrapper) and output the signature as **128 hex characters**. The public key for `PublicMgtKey` is the same key, expressed as 64 hex.
- **Human users (no copy-paste of key):** Use the **sign-clipboard** helper in `$MPA_PATH/tools/sign-clipboard`: copy the message from the app, run the binary, then paste the 128-hex signature back into the app. See `$MPA_PATH/tools/sign-clipboard/README.md`.

## 8. Deploying the agent on the node VPS (e.g. Open Claw)

To run the agent (e.g. Open Claw) on the **same VPS as the node**, use a dedicated OS user and access the node API via its port. This keeps the agent isolated and makes key placement consistent.

### 8.1 Create a dedicated user (recommended: `ai-agent`)

On the node VPS, create a user that will run only the agent (not the node itself):

```bash
# Create user (no login shell if the agent is a service)
sudo adduser --disabled-password --gecos "AI agent for MPC node" ai-agent

# Or with login shell if you need to SSH in or run interactive commands:
# sudo adduser ai-agent
```

The node continues to run as its own user (e.g. the user that runs Docker or the mpc-auth process). The agent runs as `ai-agent` and only needs to call the node API over the network.

### 8.2 Node API URL and port

The node exposes its management API on `ManagementAPIsPort` in `configs.yaml`. Build the API base URL as **`$MPC_AUTH_URL:$MANAGEMENT_PORT`** where `MPC_AUTH_URL` is host-only (`http://127.0.0.1` or `http://<IP>`) and `MANAGEMENT_PORT` is numeric.

- **Base URL:** `"$MPC_AUTH_URL:$MANAGEMENT_PORT"`
- Typical co-located setting: `MPC_AUTH_URL=http://127.0.0.1`, `MANAGEMENT_PORT=<management_api_port>`.

Examples:

- Health: `GET $MPC_AUTH_URL:$MANAGEMENT_PORT/health`
- Check Ed25519: `GET $MPC_AUTH_URL:$MANAGEMENT_PORT/hasPublicMgtKey`
- Nonce: `GET $MPC_AUTH_URL:$MANAGEMENT_PORT/getPublicMgtKeyNonce`

So the agent (e.g. Open Claw) should be configured with **node URL = `$MPC_AUTH_URL:$MANAGEMENT_PORT`** when it runs on the node VPS.

### 8.3 Install and run the agent as `ai-agent`

1. **Switch to the agent user** (or deploy your agent process under that user):
   ```bash
   sudo su - ai-agent
   ```

2. **Create SSH directory and put the Ed25519 key** (same key whose public key is in the node’s `PublicMgtKey`):
   ```bash
   mkdir -p ~/.ssh
   chmod 700 ~/.ssh
   # Copy or generate the key at ~/.ssh/mpc_auth_ed25519
   chmod 600 ~/.ssh/mpc_auth_ed25519
   ```

3. **Configure the agent** to use:
   - **Node URL:** `$MPC_AUTH_URL:$MANAGEMENT_PORT`
   - **Private key path:** `~/.ssh/mpc_auth_ed25519` (i.e. `/home/ai-agent/.ssh/mpc_auth_ed25519`)

4. Run the agent as `ai-agent`. It will read the key from disk and call the node API over the loopback port.

### 8.4 Security (optional)

- **Restrict who can reach the node API:** If only the agent on the same host should talk to the node, bind the management API to `127.0.0.1` (if supported by the node config) or use a firewall so that `MANAGEMENT_PORT` is only reachable from loopback.
- **Key permissions:** Ensure only `ai-agent` can read `~/.ssh/mpc_auth_ed25519` (e.g. `chmod 600` and correct ownership).

### 8.5 Open Claw: isolated cron + KeyGen message poll

To react when someone `@mentions` the agent in the KeyGen channel, use **Open Claw’s Gateway cron** ([Scheduled Tasks / Cron](https://docs.openclaw.ai/cron)) with an **isolated** job whose prompt tells the agent to **run a small script** on the host, then **reply** with `POST /sendMessage` (management-signed) per [API_KEYGEN_MESSAGING.md](./API_KEYGEN_MESSAGING.md).

**Poll helper in this repo:** `$MPA_PATH/scripts/keygen_messaging_agent_poll.py`

1. Install deps once: create **`$MPA_PATH/.venv`** if needed (`python3 -m venv "$MPA_PATH/.venv"`), then `"$MPA_PATH/.venv/bin/pip" install eth-account cryptography` (or `"$MPA_PATH/.venv/bin/pip" install -r "$MPA_PATH/scripts/requirements-keygen-agent.txt"`). See **[SKILL.md](../skill/SKILL.md)** **Python dependencies**.
2. Export at least **`KEYGEN_ID`**, **`MPC_AUTH_URL`** (host-only, e.g. `http://127.0.0.1`), and **`MANAGEMENT_PORT`** so the API base URL is always `$MPC_AUTH_URL:$MANAGEMENT_PORT`. The script loads the Ed25519 management key from **`AUTH_KEY_PATH` / `AUTH_KEY_FILENAME`** (default filename **`mpc_auth_ed25519`**; if **`AUTH_KEY_PATH`** is unset, the file **`~/.ssh/mpc_auth_ed25519`** is used). **`AUTH_KEY_PATH`** must be a **directory**, not the key file path. Alternatively use optional **`MPC_MGT_ED25519_SEED_HEX`**.
3. The script prints one JSON line: `matches` (unread messages whose title/body match `@agent` by default), then calls `POST /multiMarkMessagesRead` so the next poll skips handled items. Use `--dry-run` to inspect without marking read. **Interpreting** those messages (read `title`/`body`, infer intent, call tools or other management endpoints) is **always the agent’s job**, not this script—document that in **SKILL.md** and in the cron **`--message`** below.

**Poll period (select one):** Run **`$MPA_PATH/scripts/mpc_cron_schedules.py`** to print the allowed intervals, or **`--interactive`** to pick by number. The fixed choices are **every 1, 5, 10, 30, 60 minutes** and **every 2, 4, 6, 8, 10, 12, 24 hours**. Each row gives an Open Claw **`--every`** string (e.g. **`1m`**, **`5m`**, **`1h`**, **`2h`**) and a standard **crontab** five-field line for non–Open Claw timers.

**Example cron** (adjust paths). The schedule is **not** fixed: run **`$MPA_PATH/.venv/bin/python $MPA_PATH/scripts/mpc_cron_schedules.py`** (or **`--interactive`**) and copy the **Open Claw `--every`** value you want (see **Poll period** above). Set shell variable **`EVERY`** to that string, then:

```bash
EVERY="5m"  # replace with your choice from mpc_cron_schedules.py (e.g. 1m, 30m, 1h, 12h, 24h)
openclaw cron add --name "keygen-agent-inbox" --every "$EVERY" --session isolated \
  --message "Run: $MPA_PATH/.venv/bin/python $MPA_PATH/scripts/keygen_messaging_agent_poll.py. Parse the JSON on stdout. If match_count > 0: for each match read title and body (and getMessageThread if needed), figure out what the user wants, then do it—tools, management POSTs as appropriate, and/or reply via POST /sendMessage (Nonce, Sig, keyGenId, title or replyTo+body; see API_KEYGEN_MESSAGING.md). Body max 512 chars." \
  --tools "exec,read"
```

Ensure the job may run `exec`. Keep `--message` on one line so the shell parses it reliably.

The isolated job should inherit the same env as the agent service (**`KEYGEN_ID`**, **`AUTH_KEY_PATH`**, **`MPC_AUTH_URL`**, etc.). The poll script only **lists, filters, and marks read**. **Acting on message content** (reasoning, **`POST /sendMessage`**, other APIs) is always done by the agent per **`--message`** / **SKILL.md**—not by the Python script.

## 7. Security notes

- Keep the Ed25519 **private** key only where the agent (or you) can use it; never put it in the frontend or in the node config.
- Only the **public** half of an **Ed25519** keypair goes in mpc-auth (`PublicMgtKey`) and, for keyGen, as the node's client key (**64 hex** = 32-byte public key). mpc-auth does not generate it: you create the keypair outside the node (any Ed25519 tool or library), then configure that public value. Practical paths in this doc: **§1.1** (bootstrap), **§5** (node app **Info** → **Create new key pair** → copy **Public key (64 hex)**), **§6** (private key in `~/.ssh/mpc_auth_ed25519`; the matching public key is the same identity as 64 hex).
- Restrict access to the node API (TLS, firewall, auth) as you would for any management interface.
- Protect `~/.ssh/mpc_auth_ed25519` (permissions, deploy keys only for the agent user) so only the intended process can use the key.
