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

**OpenSSH `.pub` format is not what mpc-auth stores**—if you only have a line like `ssh-ed25519 AAAA… comment` (or the **base64 middle field** alone), convert it first. In the **mpc-config** repo, **`tools/openssh_ed25519_to_hex.py`** (stdlib only) accepts the full line or the base64 blob and prints **64 hex** on stdout. Example (adjust path if you keep a symlink or copy of **`tools/`** next to the agent, e.g. under the agent’s home directory):

```bash
python3 /path/to/mpc-config/tools/openssh_ed25519_to_hex.py ~/.ssh/id_ed25519.pub
# or: echo 'ssh-ed25519 AAAA…' | python3 …/openssh_ed25519_to_hex.py
```

**`process_config.sh`** (same repo) can also prompt for or normalize **`PublicMgtKey`** from OpenSSH / base64 when you run it interactively or when the value is already in **`configs.yaml`**. For a **private** key file (PEM / OpenSSH), use **`tools/ed25519_private_to_pubkey_hex.py`** (`pip install cryptography`).

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

- Fetch nonce for the signer key:

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
| Trigger sign        | `POST /triggerSignRequestById` | Same pattern: get nonce, build body, sign, send clientSig + signedMessage. |
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

1. Call `GET /getNodeMgtKeyNonce` (or equivalent) where a nonce is required.
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
- **Human users (no copy-paste of key):** Use the **sign-clipboard** helper in `tools/sign-clipboard`: copy the message from the app, run the binary, then paste the 128-hex signature back into the app. See `tools/sign-clipboard/README.md`.

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

The node exposes its management API on **port 8080** by default (configurable via `ManagementAPIsPort` in `~mpcnode/mpc-config/configs.yaml`). When the agent runs on the same VPS:

- **Base URL:** `http://localhost:8080` or `http://127.0.0.1:8080`
- If you changed the port in config, use that port instead.

Examples:

- Health: `GET http://localhost:8080/health`
- Check Ed25519: `GET http://localhost:8080/hasPublicMgtKey`
- Nonce: `GET http://localhost:8080/getPublicMgtKeyNonce`

So the agent (e.g. Open Claw) should be configured with **node URL = `http://localhost:8080`** when it runs on the node VPS.

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
   - **Node URL:** `http://localhost:8080` (or `http://127.0.0.1:8080`)
   - **Private key path:** `~/.ssh/mpc_auth_ed25519` (i.e. `/home/ai-agent/.ssh/mpc_auth_ed25519`)

4. Run the agent as `ai-agent`. It will read the key from disk and call the node API over the loopback port.

### 8.4 Security (optional)

- **Restrict who can reach the node API:** If only the agent on the same host should talk to the node, bind the management API to `127.0.0.1` (if supported by the node config) or use a firewall so that port 8080 is only reachable from localhost.
- **Key permissions:** Ensure only `ai-agent` can read `~/.ssh/mpc_auth_ed25519` (e.g. `chmod 600` and correct ownership).

### 8.5 Open Claw: isolated cron + KeyGen message poll

To react when someone `@mentions` the agent in the KeyGen channel, use **Open Claw’s Gateway cron** ([Scheduled Tasks / Cron](https://docs.openclaw.ai/cron)) with an **isolated** job whose prompt tells the agent to **run a small script** on the host, then **reply** with `POST /sendMessage` (management-signed) per [API_KEYGEN_MESSAGING.md](./API_KEYGEN_MESSAGING.md).

**Poll helper in this repo:** `scripts/keygen_messaging_agent_poll.py`

1. Install deps once: `pip install -r scripts/requirements-keygen-agent.txt`
2. Export at least **`KEYGEN_ID`** (same as [SKILL.md](../skill/SKILL.md) / Open Claw skill) and, if needed, **`MPC_AUTH_URL`** for the management API (default `http://127.0.0.1:8080`). The script loads the Ed25519 management key from **`AUTH_KEY_PATH`** (default `~/.ssh/mpc_auth_ed25519`) or optional **`MPC_MGT_ED25519_SEED_HEX`**.
3. The script prints one JSON line: `matches` (unread messages whose title/body match `@agent` by default), then calls `POST /multiMarkMessagesRead` so the next poll skips handled items. Use `--dry-run` to inspect without marking read.

**Example cron** (adjust paths and schedule; ensure the job may run `exec`). Keep `--message` on one line so the shell parses it reliably:

```bash
openclaw cron add --name "keygen-agent-inbox" --every "3m" --session isolated \
  --message "Run: python3 /home/ai-agent/mpc-config/scripts/keygen_messaging_agent_poll.py. Parse the one JSON line on stdout. If match_count > 0, reply via POST /sendMessage (Nonce, Sig, keyGenId, title or replyTo+body; see API_KEYGEN_MESSAGING.md). Body max 512 chars." \
  --tools "exec,read"
```

The isolated job should inherit the same env as the agent service (**`KEYGEN_ID`**, **`AUTH_KEY_PATH`**, **`MPC_AUTH_URL`**, etc.). **Sending** messages remains an explicit agent step (sign with the same Ed25519 management key as other mgt endpoints); the poll script only **lists, filters, and marks read**.

## 7. Security notes

- Keep the Ed25519 **private** key only where the agent (or you) can use it; never put it in the frontend or in the node config.
- Only the **public** half of an **Ed25519** keypair goes in mpc-auth (`PublicMgtKey`) and, for keyGen, as the node's client key (**64 hex** = 32-byte public key). mpc-auth does not generate it: you create the keypair outside the node (any Ed25519 tool or library), then configure that public value. Practical paths in this doc: **§1.1** (bootstrap), **§5** (node app **Info** → **Create new key pair** → copy **Public key (64 hex)**), **§6** (private key in `~/.ssh/mpc_auth_ed25519`; the matching public key is the same identity as 64 hex).
- Restrict access to the node API (TLS, firewall, auth) as you would for any management interface.
- Protect `~/.ssh/mpc_auth_ed25519` (permissions, deploy keys only for the agent user) so only the intended process can use the key.
