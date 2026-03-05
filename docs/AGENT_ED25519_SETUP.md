# Agent Ed25519 setup for node management

This doc describes how a **node owner** can set up their node so that an **AI agent** (or any automated process) can perform management signing using an Ed25519 keypair—without MetaMask. The agent can then call the node APIs for signRequestAgree, triggerSignRequestById, updateSignResultStatusById, shelveSignRequest, and keyGen (create/join) using Ed25519 signatures.

## Summary

1. **Node** stores only the **public** key in config (`PublicMgtKey`). It verifies signatures over the port; it never holds the private key.
2. **You (the node owner)** generate an Ed25519 keypair and put the **public** key in the node config. You keep the **private** key at `~/.ssh/mpc_auth_ed25519` on your PC, or on the agent's machine at the same path.
3. **Signing** is done by you (via a local helper or by pasting the 128-hex signature in the frontend) or by the agent (using its key and then calling the node API over the port with the signature). Access to the node is over the port and is secure.
4. No new node endpoints are required; the app uses **hasPublicMgtKey** and the existing management APIs.

## 1. Node setup (one-time, by the node owner)

### 1.1 Generate Ed25519 keypair

On your PC (or the machine where the agent will run), create the key and save it as **`~/.ssh/mpc_auth_ed25519`** (this path only; it keeps things consistent):

```bash
mkdir -p ~/.ssh
openssl genpkey -algorithm Ed25519 -out ~/.ssh/mpc_auth_ed25519
chmod 600 ~/.ssh/mpc_auth_ed25519
```

Get the public key as 64 hex characters (for mpc-auth config):

```bash
openssl pkey -in ~/.ssh/mpc_auth_ed25519 -pubout -outform DER 2>/dev/null | tail -c 32 | xxd -p -c 32
```

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

### 1.3 Frontend: connect the node

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

- The app uses **`GET /hasPublicMgtKey`** (existing mpc-auth API) to see if the node has Ed25519 configured. If so, it shows "Ed25519 management key is configured" and instructions.
- If not configured, a **Create new key pair** button is shown. Clicking it generates an Ed25519 keypair in the browser. You are shown:
  - **Public key (64 hex)** with a copy button. Copy this into the `PublicMgtKey` field of `configs.yaml` on the node (or set the `PublicMgtKey` environment variable), then restart the node.
  - **Private key** (PEM) with a copy button, and a warning that you will not be shown it again. Save it to `~/.ssh/mpc_auth_ed25519` on **your PC** or the machine where the agent runs; set permissions to 600. The node never holds the private key.
- After creation, the option to create again is hidden unless you click **"I've removed the key and config, create a new key pair"**.
- For an AI agent on the same machine: put the private key in the agent's `~/.ssh/mpc_auth_ed25519` (chmod 600). The agent signs locally and calls the node over the port with the signature.

No new node endpoints are required; see `MPC_AUTH_ED25519_NODE_API.md` (in the node-app repo if applicable).

## 6. Agent on the same machine: reading the private key from disk

If the AI agent (or a signing helper) runs **on the same machine as the node**, it can read the Ed25519 private key from disk instead of receiving signatures from elsewhere.

- **Path:** Use only **`~/.ssh/mpc_auth_ed25519`** for the private key (on your PC or the agent's machine). Configure the agent (or your helper) to read that path and sign the exact message string the backend expects.
- **Key format:** The file at `~/.ssh/mpc_auth_ed25519` can be OpenSSH or PEM format. Sign the **exact** JSON message string (no EIP-191 wrapper) and output the signature as **128 hex characters**. The public key for `PublicMgtKey` is the same key, expressed as 64 hex.
- **Human users (no copy-paste of key):** Use the **sign-clipboard** helper in `tools/sign-clipboard`: copy the message from the app, run the binary, then paste the 128-hex signature back into the app. See `tools/sign-clipboard/README.md`.

## 7. Security notes

- Keep the Ed25519 **private** key only where the agent (or you) can use it; never put it in the frontend or in the node config.
- Only the **public** key goes in mpc-auth (`PublicMgtKey`) and, for keyGen, as the node's client key (64 hex).
- Restrict access to the node API (TLS, firewall, auth) as you would for any management interface.
- Protect `~/.ssh/mpc_auth_ed25519` (permissions, deploy keys only for the agent user) so only the intended process can use the key.
