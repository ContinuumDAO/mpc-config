---
name: mpa-wallet
description: Operate and automate threshold multisignature workflows for MPC/MPA wallets on an isolated, dedicated host that contains no unrelated sensitive data or private keys.
version: 1.0.7
metadata:
  openclaw:
    requires:
      env:
        - KEYGEN_ID
        - AUTH_KEY_PATH
        - MPA_PATH
        - MPC_CONFIG_PATH
        - MPC_AUTH_URL
        - MANAGEMENT_PORT
      bins:
        - curl
        - jq
        - forge
        - cast
        - python3
        - pipx
      config:
        - "$AUTH_KEY_PATH/mpc_auth_ed25519"
        - "$MPC_CONFIG_PATH"
    primaryEnv: MPC_AUTH_URL
    os:
      - linux
    homepage: https://clawhub.ai/patrickcure/mpa-wallet
---

# Skill: MPA / MPC wallet agent (Open Claw / Clawhub)

Use this skill when operating an **AI agent** (e.g. **Open Claw**) that manages an **mpc-auth** node participating in a **Multi-Party Agent (MPA) wallet**: a single on-chain address (EVM today) whose **MPC signature** requires cooperation of **at least threshold+1** nodes in a **Group**. No single node holds the full private key.

## Prerequisites

This skill assumes the **operator has already provisioned an MPA wallet environment** in ContinuumDAO terms—not a single standalone node:

- **At least two mpc-auth nodes** must exist: one run by a **human** and one run for the **AI agent**. Threshold signing requires multiple parties; a minimal useful setup pairs a human-controlled node with an agent-controlled node.
- The **agent’s node** must use **Ed25519 management signing** (`PublicMgtKey` / `POST /addManagementKey` flow) so automated `POST` calls to the management API are authenticated without MetaMask. See **[AGENT_ED25519_SETUP.md]($MPA_PATH/references/AGENT_ED25519_SETUP.md)** in this repo for technical steps.

## Host security requirements (mandatory)

- Run this skill only on a **dedicated, isolated machine** used for MPC node operations.
- Do **not** run this skill on hosts that contain unrelated secrets, wallets, SSH keys, cloud credentials, or developer tokens.
- The only private key material available to the agent should be the **dedicated management key** used for management API authentication.
- Restrict filesystem and network permissions to only what is required for the local mpc-auth node and expected RPC/API endpoints.
- Prefer a dedicated key path (outside your normal user SSH key set) and ensure this key is not reused for other systems.

## Scope and egress guardrails (mandatory)

- This skill is limited to **local MPA operations**: management API calls on **`$MPC_AUTH_URL:$MANAGEMENT_PORT`**, chain RPC calls configured by the node, and local files under **`$MPA_PATH`** plus the dedicated management key path.
- Do **not** send data to external messaging platforms or third-party web APIs unless the operator explicitly enables that behavior outside this skill.
- Do **not** read unrelated files, shell history, home-directory secrets, cloud credentials, wallet files, or SSH keys other than the dedicated management key.
- Treat **`AUTH_KEY_PATH`** material as high-privilege signing input only: never print or transmit private key contents.
- If a task would require leaving this scope, stop and ask for explicit operator approval first.

**ContinuumDAO documentation** (end-user setup, before this skill applies):

| Topic | Link |
|--------|------|
| **Running a node** (install, configure, operate an mpc-auth node) | [Node running instructions](https://docs.continuumdao.org/ContinuumDAO/RunningInstructions/NodeRunningInstruction) |
| **Creating an MPC signer** (forming a **Group**, running **KeyGen**, obtaining the shared MPC wallet / address) | [Create MPC signer](https://docs.continuumdao.org/ContinuumDAO/MPCSigner/CreateMPCSigner) |
| **Interact using Foundry** (create forge scripts, read on-chain data using cast) | [Foundry skill](https://docs.continuumdao.org/ContinuumDAO/OpenClaw/FoundryInstructionSkill) |

Complete those guides first; then use this skill for **day-to-day agent behavior** (messaging, `multiSignRequest`, agree/trigger/execute, and API discipline).

---

## Overview (read this first)

This section restates the ideas in **[`instructions.md`]($MPA_PATH/references/instructions.md)** in a form suited for **users and agents** who do not yet see why **Group**, **KeyGen**, **threshold**, and **two signature types** matter.

### What you are operating

A **Multi-Party Agent (MPA) wallet** is **one** shared wallet address (EVM today: one Ethereum address) whose **private key never exists whole on any server**. It is created and used via **Multi-Party Computation (MPC)** across a **Group** of **nodes** (often VPSs). **No single node can sign alone:** producing a valid **MPC signature** requires cooperation of at least **threshold+1** nodes. The integer **threshold** is set when the **KeyGen** is created. That is how the address stays protected if one machine is compromised.

The MPC address works on **any EVM network**; it is **not** locked to one smart contract.

**Humans and AI agents are symmetric.** Some nodes are operated by people, others by an agent (e.g. Open Claw). All use the same REST ideas: **message** the group, **propose** txs via **`/multiSignRequest`**, **agree** or **reject** with **`/signRequestAgree`**, optionally add **`Thoughts`**, then **trigger** MPC signing and **broadcast**. The agent’s job is to take **intent** from the KeyGen messaging flow, produce **Foundry** scripts ([Foundry](https://www.getfoundry.sh/introduction/getting-started)), and turn outputs into **`multiSignRequest`** payloads—always subject to **threshold+1** agreement before **`triggerSignRequestById`**.

### The two signatures (critical distinction)

1. **Management signature** — **Per-node API authentication.** Each client has its **own** key material; public keys are in config (e.g. **`mpc-config/configs.yaml`**). Every **`POST`** to the management API must be signed by **that** client’s management key (Ed25519 for agents, often MetaMask for interactive users). This proves **who is calling the API**, not what the MPC wallet authorizes on-chain.

2. **MPC signature** — **On-chain authorization** by the **shared** wallet. There is **no** single MPC private key file. Nodes run a protocol so that, only after enough **agreements**, a signature valid for the **MPC public address** is produced.

### Groups, KeyGen, signing (short)

- **Group:** Peers configure each other, one node proposes a group, invitees accept → **Group ID**. See **Groups** / **KeyGen** / **Signing** in [`instructions.md`]($MPA_PATH/references/instructions.md).
- **KeyGen:** Started inside a group; all participants must accept; yields **pubKey** / (secp256k1) an **Ethereum address** and fixes **threshold**.
- **Signing:** A member proposes a sign request; each node **accepts or rejects**; optional **`Thoughts`** guide whether to **shelve** and revise. With **threshold+1** accepts, **`triggerSignRequestById`** runs MPC signing; then **broadcast** txs and **`updateSignResultStatusById`**.

### Persistent context (why messages and Purpose matter)

Each node stores the same logical data over time: **KeyGen messages** (`listMessages`, `getMessageThread`, …) and **sign-request / sign-result metadata** (**`Purpose`**, **`Thoughts`**). That **shared history** is what future decisions should use—regardless of which LLM or agent version is connected.

---

## When this skill applies

- Proposing or evaluating **multi-sign requests** (`POST /multiSignRequest`, `POST /signRequestAgree`, `POST /triggerSignRequestById`).
- Using **KeyGen messaging** (`POST /sendMessage`, `GET /getMessageThread`) for group coordination.
- Generating **Foundry** scripts and turning **`forge script`** output into API payloads.
- **Combining** two **`multiSignRequest`**-style JSON outputs (from recipes or **`generateSignRequestWithFoundryScript`**) into **one** batch with **`multiSignJoin.py`** before **`POST /multiSignRequest`**.
- Configuring **Ed25519 management** authentication for automated `POST` calls to the node API.
- Explaining **threshold**, **Purpose**, **Thoughts**, **shelve**, and **execute** flows.

Do **not** confuse **management signatures** (per-node API auth) with **MPC signatures** (threshold signing over a message).

---

## Core concepts

| Term | Meaning |
|------|--------|
| **Group** | Set of nodes that mutually trust each other for relay/config; identified by **Group ID**. Formed after configured nodes accept a group request. |
| **KeyGen** | MPC key generation for a wallet; yields **pubKey** / (for secp256k1) an **Ethereum address**. Requires all invited nodes to accept. **Threshold** is fixed at KeyGen creation. |
| **Threshold** | Minimum cooperating parties minus one in the usual t-of-n wording: signing needs **threshold+1** agreeing nodes. |
| **Management signature** | Authenticates **this node’s** HTTP **POST**s to its management API. Keys come from `mpc-config/configs.yaml` (e.g. **PublicMgtKey** / **NodeMgtKey**). |
| **MPC signature** | Produced only when enough nodes accept the **same** sign request and the network runs the TSS signing protocol—not a single machine’s private key. |
| **multi-agree** | Policy where nodes explicitly agree (`signRequestAgree`) before `triggerSignRequestById`; use **`/multiSignRequest`**, not `/signRequest` (relayer/tx-check only). |

---

## Environment (agent)

| Variable | Purpose | Default |
|----------|---------|---------|
| **`KEYGEN_ID`** | If set, prefer this KeyGen for signing when unambiguous. If unset or ambiguous, ask the user via the configured channel (e.g. gateway **port 18789**). | Unset |
| **`AUTH_KEY_PATH`** | Ed25519 **management** private key used to sign API bodies. | `~/.ssh/mpc_auth_ed25519` |
| **`MPA_PATH`** | If set, points to the directory containing references, scripts, recipes, and tools. | `~/.mpa` |
| **`MPC_CONFIG_PATH`** | Absolute path to the node `configs.yaml` for this deployment (operator-defined, no hardcoded user/home assumption). | `/path/to/mpc-config/configs.yaml` |
| **`MPC_AUTH_URL`** | Points to the base URL of the management API. | `http://127.0.0.1` |
| **`MANAGEMENT_PORT`** | The port of the management API. | `8080` |

Base URL for a co-located node: **`$MPC_AUTH_URL:$MANAGEMENT_PORT`** (see `configs.yaml`, often **8080**).

`MPA_PATH` is a filesystem location, not a credential. `primaryEnv` is set to `MPC_AUTH_URL` because the management API endpoint is the primary operational target for this skill.

**`scripts/keygen_messaging_agent_poll.py`** uses **`KEYGEN_ID`**, **`AUTH_KEY_PATH`**, and **`MPC_AUTH_URL`**.

### Python dependencies

Use **[pipx](https://github.com/pypa/pipx)** for installing these packages (not **`pip`** / **`pip3`** on the system interpreter). Install **`pipx`** once per host if needed (see the pipx docs). PyPI names use hyphens where applicable (**`eth-account`** installs the **`eth_account`** import).

1. **Base (all signing scripts in `$MPA_PATH/scripts`):** `pipx install eth-account` — pulls **`rlp`**, **`eth_utils`**, **`hexbytes`**, etc., needed by **`generateSignRequestWithFoundryScript.py`**, **`generateMultiSignRequestFromCompose.py`**, **`multiSignJoin.py`**, and **`executeSignResult.py`**.
2. **Compose + recipes:** `pipx inject eth-account PyNaCl` — only **`generateMultiSignRequestFromCompose.py`** and **`recipes/*.py`** need **`PyNaCl`** (optional Ed25519 fields on payloads). Skip this inject if you use **only** the Forge helper, **`multiSignJoin`**, or **`executeSignResult`**.
3. **KeyGen inbox poll:** `pipx inject eth-account cryptography` — satisfies **`keygen_messaging_agent_poll.py`** (same minimum as **`$MPA_PATH/scripts/requirements-keygen-agent.txt`**). Alternatively, if your **`pipx`** supports it: `pipx inject eth-account -r $MPA_PATH/scripts/requirements-keygen-agent.txt`.

**Run scripts** with the Python interpreter from the pipx venv for **`eth-account`** (paths vary by OS; **`pipx list`** shows each app’s venv). Example on many Linux installs: **`~/.local/pipx/venvs/eth-account/bin/python $MPA_PATH/scripts/generateSignRequestWithFoundryScript.py ...`**. Plain **`python3 ...`** only works if that environment is the one on your **`PATH`**.

### KeyGen inbox poll (`@agent`)

To **notice unread channel messages directed at the agent** without manual **`GET /listMessages`** each time, run **`$MPA_PATH/scripts/keygen_messaging_agent_poll.py`** on a timer (recommended: **Open Claw Gateway isolated cron**; see **`$MPA_PATH/references/AGENT_ED25519_SETUP.md`** §8.5 and [Open Claw cron](https://docs.openclaw.ai/cron)).

1. **Once:** install **`cryptography`** into the pipx **`eth-account`** environment (**`pipx inject eth-account cryptography`** — see **[Python dependencies](#python-dependencies)**).
2. **Run:** the venv **`python`** for **`eth-account`** with **`$MPA_PATH/scripts/keygen_messaging_agent_poll.py`** (and **`KEYGEN_ID`** set; **`AUTH_KEY_PATH`** / **`MPC_AUTH_URL`** if not defaults). **`--dry-run`** lists matching unread messages without calling **`multiMarkMessagesRead`**.
3. **Output:** one JSON line: **`matches`**, **`match_count`**, **`marked_ids`**. The script marks matched messages read so the next poll does not repeat them.
4. **After a non-empty `matches`:** interpret the thread, decide what to do, and reply with **`POST /sendMessage`** (management-signed; **`$MPA_PATH/references/API_KEYGEN_MESSAGING.md`**). Humans can **`@agent`** in title or body to target the agent.

---

## Default operational loop (high level)

1. **Discuss** in KeyGen messaging: human or other nodes **`POST /sendMessage`**; everyone reads **`GET /getMessageThread`** (and related list/get APIs). Optionally use the **KeyGen inbox poll** above when the agent should wake on **`@agent`** mentions.
2. **Plan**: use KeyGen message context plus local/on-chain state to produce **Foundry** scripts and a concise rationale.
3. **Build tx intent**: for common flows, prefer **[recipes](#recipes-thin-cli-wrappers)** (**`linea_register.py`**, **`linea_fee_deposit.py`**, **`erc20_transfer.py`**, **`native_transfer.py`**, **`ctmerc20_transfer.py`**, **`ctmrwa1_transfer_whole.py`**, **`ctmrwa1_transfer_partial.py`**) which wrap **`generateMultiSignRequestFromCompose`** and use **`GET /getChainDetails`** when **`rpcGateway`** is omitted. Otherwise: run **`forge script … --sender <MPC address>`** → `broadcast/.../run-latest.json` and feed **`$MPA_PATH/scripts/generateSignRequestWithFoundryScript.py`** to build JSON for **`POST /multiSignRequest`** (see **`$MPA_PATH/references/AI_AGENT_FORGE_SIGNREQUEST.md`**), **or** build **Compose-style** JSON (function signature + parameters) and run **`$MPA_PATH/scripts/generateMultiSignRequestFromCompose.py`** (see **`$MPA_PATH/references/AI_AGENT_COMPOSE_MULTISIGNREQUEST.md`**). When you need **two** such payloads (e.g. ERC-20 transfer then a second call) as **one** proposal with **one** agree/trigger cycle, run **`$MPA_PATH/scripts/multiSignJoin.py`** with **`--a`**, **`--b`**, and **`--first-nonce`** set to the MPC wallet’s **EVM** nonce on that chain (**`cast nonce <MPC> --rpc-url $RPC`**)—see [multiSignJoin](#multisignjoin-merge-two-multisignrequest-json-files). Include a concise **`Purpose`** (≤256 chars).
4. **Agree**: each node **`POST /signRequestAgree`** (accept/reject); optional **`Thoughts`** per node to guide the agent (e.g. to **`POST /shelveSignRequest`** and revise).
5. **Approval gate (recommended default):** require explicit human approval in KeyGen messaging before `POST /triggerSignRequestById`.
6. **Trigger & sign**: after approval, when **`/isSignRequestReadyById`** is true, **`POST /triggerSignRequestById`**; poll **`GET /getSignResultById`** until signatures exist.
7. **Execute**: require explicit human approval before broadcast, then send tx(s) with sufficient gas/credit. Prefer **`$MPA_PATH/scripts/executeSignResult.py`**: it loads **`GET /getSignResultById`** (and **`GET /getSignRequestById`** for **`msgRaw` / `messageRawBatch`**), resolves RPC from **`--rpc-url`** or **`GET /getChainDetails`**, submits **`eth_sendRawTransaction`**, and by default sends each tx **sequentially** and waits for receipts; pass **`--fast`** to confirm batched txs **concurrently**. Then **`POST /updateSignResultStatusById`** with **`executed`** and **`transactionHash`** (or batch hashes).
8. **Report**: **`POST /sendMessage`** summarizing what was done and what to expect.
9. **Context**: for future spends, use **messages** plus **`Purpose` / `Thoughts`** on sign results (**`GET /listSignResults`**, **`GET /getSignRequestById`** / **`getSignResultById`**).

---

## Other API capabilities (agent)

Per **`$MPA_PATH/references/instructions.md`**, the agent may also: **`/keyGenRequest`**, **`/keyGenRequestAgree`**, **`/addKnownAddress`**, **`/postChainDetails`**, **`/addToken`**, health/version discovery, and **fee/credit** checks via **`GET /getGlobalNonceByKeyGenId`** (and top-up gas as needed). For **on-chain** fee state on **Linea mainnet**, use the subsection below.

---

## Fee payment (Linea mainnet, chainId 59144)

ContinuumDAO’s **fee / registration** contract on **Linea** is deployed at a fixed address. Agents should use **Foundry `cast`** against that contract with an RPC URL taken from the node’s chain config (same pattern as other on-chain checks).

**Fee contract (Linea mainnet):** `0x55aD6Df6d8f8824486C3fd3373f1CF29eCecF0A3`

**On-chain `register()` from the MPC wallet (multiSignRequest):** use the **[`linea_register.py`](#recipes-thin-cli-wrappers)** recipe (Linea **`59144`**, **`register()`**, RPC from **`getChainDetails`**). **Fee-token top-up (`deposit`)** from the MPC wallet: **[`linea_fee_deposit.py`](#recipes-thin-cli-wrappers)** with **`--amount-wei`** (smallest fee-token units); the MPC must **approve** the fee contract for the ERC20 fee token before **`deposit`** succeeds. For **approve + deposit** in a **single** batch **multiSignRequest**, use **`forge/script/LineaFeeApproveDeposit.s.sol`** → **`generateSignRequestWithFoundryScript.py`** (see **`$MPA_PATH/references/AI_AGENT_FORGE_SIGNREQUEST.md`** § Linea fee). For read-only **`cast`** checks below, any RPC URL from the node’s chain config is fine.

**Variables:** Set **`KEYGEN_ID`** to your KeyGen result id (see **Environment**). Set **`WALLET_ADDRESS`** to the MPC wallet **Ethereum address** for that KeyGen (from **`GET /getKeyGenResultById`** / **`ethereumaddress`**). Use your co-located management API base URL ($MPC_AUTH_URL) instead of `localhost` if needed.

**RPC URL from the node** (Linea `chain_id` **59144**):

```bash
RPC=$(curl -s "$MPC_AUTH_URL:$MANAGEMENT_PORT/getChainDetails?chain_id=59144" | jq -r '.Data.rpcGateway')
```

**Registration and fee state** (`cast` reads only):

```bash
# Is the KeyGen registered?
cast call 0x55aD6Df6d8f8824486C3fd3373f1CF29eCecF0A3 \
  "isRegistered(address)(bool)" $WALLET_ADDRESS --rpc-url $RPC

# Fee config for this KeyGen
cast call 0x55aD6Df6d8f8824486C3fd3373f1CF29eCecF0A3 \
  "keyGenFeeConfig(address)(address,uint256,uint256,uint256,bytes32)" \
  $WALLET_ADDRESS --rpc-url $RPC

# Global nonce (for getRemainingNonces) — from the management API, not cast nonce
GNONCE=$(curl -s "$MPC_AUTH_URL:$MANAGEMENT_PORT/getGlobalNonceByKeyGenId?id=$KEYGEN_ID" | jq -r '.Data.globalnonce')

# Remaining signatures before top-up
cast call 0x55aD6Df6d8f8824486C3fd3373f1CF29eCecF0A3 \
  "getRemainingNonces(address,uint256)(uint256)" $WALLET_ADDRESS $GNONCE --rpc-url $RPC
```

**Note:** **`globalnonce`** here is the KeyGen’s MPC signing counter from the API. It is **not** the EVM account nonce from **`cast nonce`**. **Fee payment / top-up** can be sent as ordinary EVM transactions **from any funded wallet**—they do **not** require the **`multiSignRequest`** / threshold flow. Paying from a separate hot wallet or custodian is often more convenient than routing top-ups through the MPC wallet. If you do spend **from the MPC address** itself, those txs still go through **`multiSignRequest`** as usual. For ABI-level details of the fee contract, see **[$MPA_PATH/references/API_IMPLEMENTATION.md]($MPA_PATH/references/API_IMPLEMENTATION.md)** and on-chain docs your deployment publishes.

---

## Incoming MPC sign requests (policy)

When another member requests a signature, default decision inputs:

- Group **messages** and the request **`Purpose`**.
- Independent analysis from available node messages, API state, and on-chain data.
- Owner instructions left for the agent.
- If uncertain, **message the owner** on the dedicated messaging API **`POST /sendMessage`** awaiting guidance.

Remember: **threshold+1** accepts are required to generate the MPC signature.

---

## Authentication discipline

- Every **`POST`** to the management API requires a **management** signature (Ed25519 or MetaMask flow per node config).
- **`clientSig`** on **`multiSignRequest`** signs the **canonical request body** with the **management** key—not the MPC key.
- Setup details: **[references/AGENT_ED25519_SETUP.md]($MPA_PATH/references/AGENT_ED25519_SETUP.md)**.

### `sign-clipboard`, **`--inline`**, and **`--inline-file`** (Ed25519 POST signing)

The **`sign-clipboard`** helper (**[`tools/sign-clipboard`]($MPA_PATH/tools/sign-clipboard)** in this repo; see **`$MPA_PATH/tools/sign-clipboard/README.md`**) signs the **exact UTF-8 string** that the management API expects with the node’s **Ed25519 management key**.

**For any `POST` whose body must be signed** (including **`POST /multiSignRequest`**, **`POST /signRequestAgree`**, **`POST /sendMessage`**, **`POST /triggerSignRequestById`**, and other management **`POST`** routes), agents **must** use **`--inline`** or **`--inline-file`** (not the clipboard path):

```bash
sign-clipboard --inline '<canonical JSON string>'
# or, for large bodies (same bytes as the HTTP body—avoids shell quoting limits):
sign-clipboard --inline-file /path/to/body.json
```

**Why `--inline` / `--inline-file`:** These pass the **message to sign** without reading the clipboard—either as a **literal argument** or as the **exact file contents**. That matches automation and scripts: the signed bytes must match what you **`POST`** (or the **`messageToSign`** / canonical JSON the API documents). Clipboard-based signing is fine for humans in the GUI; **`--inline`** / **`--inline-file`** avoid clipboard races, accidental whitespace or BOM changes, and missed copies when the agent is driving **`curl`** or Python **`urllib`**.

**Behavior:**

- **`--inline`** signs the argument **byte-for-byte** (after normal shell quoting—ensure the JSON matches the real request body, including key order if the API requires a canonical form).
- **`--inline-file`** reads the message from the given path (**`~`** is expanded); file contents are signed **byte-for-byte** (a leading UTF-8 BOM is stripped, same as other modes). Use this when the JSON is **large** or awkward to quote.
- The **128-hex Ed25519 signature** is written to **standard output** (one line). Use it as **`clientSig`** on the JSON body. If the endpoint also expects **`signedMessage`**, set it to the **same string** you signed when the API specifies that field (see **[$MPA_PATH/references/API_IMPLEMENTATION.md]($MPA_PATH/references/API_IMPLEMENTATION.md)** per route).
- Combine with **`--bootstrap`**, **`--primary`**, or **`--key-file`** when multiple management keys exist (same rules as the README).
- **Do not** combine **`--inline`**, **`--inline-file`**, or **`--stdin`** with each other; use one input mode.

**Example (pattern only; body must match your generated payload):**

```bash
SIG=$(sign-clipboard --inline "$(jq -c . < body.json)" )
curl -sS -X POST "$MPC_AUTH_URL/multiSignRequest" \
  -H 'Content-Type: application/json' \
  -d "$(jq --arg s "$SIG" '. + {clientSig: $s}' body.json)"
```

**Large body (sign the same file you send):**

```bash
jq -c . body.json > body.compact.json   # optional: one canonical line
SIG=$(sign-clipboard --inline-file body.compact.json)
curl -sS -X POST "$MPC_AUTH_URL/multiSignRequest" \
  -H 'Content-Type: application/json' \
  -d "$(jq --arg s "$SIG" '. + {clientSig: $s}' body.compact.json)"
```

(Adjust **`jq`** usage so the signed string equals the server’s canonical JSON; many flows sign **`messageToSign`** from script output, then merge **`clientSig`** into **`postBody`**.)

---

## Creating transactions (`multiSignRequest`)

Skim-level recipe for agents (e.g. Open Claw). **Foundry path:** **[AI_AGENT_FORGE_SIGNREQUEST.md]($MPA_PATH/references/AI_AGENT_FORGE_SIGNREQUEST.md)**. **Compose-style JSON (no Foundry broadcast):** **[AI_AGENT_COMPOSE_MULTISIGNREQUEST.md]($MPA_PATH/references/AI_AGENT_COMPOSE_MULTISIGNREQUEST.md)**. **Shortcut:** see **[Recipes](#recipes-thin-cli-wrappers)** (**`linea_register`**, **`linea_fee_deposit`**, **`erc20_transfer`**, **`native_transfer`**, **`ctmerc20_transfer`**, **`ctmrwa1_transfer_whole`**, **`ctmrwa1_transfer_partial`**, …) before hand-writing compose JSON.

1. **Simulate with Foundry** — Run **`forge script`** with **`--rpc-url`** and **`--sender <MPC address>`**. **Do not** use **`--broadcast`** (the MPC key is not on disk). Consume the artifact **`broadcast/<Script>.s.sol/<chain_id>/run-latest.json`**.
2. **Build the request JSON** — Run **`cast nonce <MPC address> --rpc-url $RPC`** and pass that value as **`--first-nonce`** to **`$MPA_PATH/scripts/generateSignRequestWithFoundryScript.py`** (see **Scripts** below), together with **`--key-gen-id`**, **`--file`** pointing at **`run-latest.json`**, **`--purpose`**, and **`--mpc-auth-url`**. The helper needs **`eth_account`** (see **[Python dependencies](#python-dependencies)** and **`$MPA_PATH/references/AI_AGENT_FORGE_SIGNREQUEST.md`**).
3. **Sign and submit** — Clear **`clientSig`** / **`signedMessage`**, build **canonical JSON**, sign with the **management** key, set **`clientSig`**, then **`POST /multiSignRequest`**.
4. **Notify the group** — **`POST /sendMessage`** on the KeyGen channel with a short title/body and the **request id** returned from **`multiSignRequest`** so peers can review.

### multiSignJoin: merge two multiSignRequest JSON files

Use **`$MPA_PATH/scripts/multiSignJoin.py`** when you already have **two** JSON blobs in the same shape as **`generateMultiSignRequestFromCompose.py`** or **`generateSignRequestWithFoundryScript.py`** stdout (wrapper with **`bodyForSign`** / **`messageToSign`** or a raw body) and you want **one** **`POST /multiSignRequest`** that batches both transactions.

- **Inputs:** **`--a`** and **`--b`** paths (or stdin patterns from recipes saved to files).
- **Chain:** both payloads must use the same **`destinationChainID`**; the script errors if they differ.
- **Nonces:** the script rewrites serialized unsigned txs so nonces are **consecutive** starting at **`--first-nonce`**. Set that to the MPC address’s **current EVM pending nonce** on that chain (**`cast nonce <address> --rpc-url …`**), not **`globalnonce`** from **`getGlobalNonceByKeyGenId`**.
- **Gas / fees:** values are **preserved** from each input’s unsigned tx (whatever the recipe or Foundry helper embedded). **`multiSignJoin`** only adjusts nonces and recomputes signing hashes; it does **not** re-estimate gas or fees.
- **Output:** a **batch-shaped** body (**`messageHashes`**, **`messageRawBatch`**, **`extraJSON.batchMeta`**) when the merged count is at least two (or when either input was already a batch). Add **`clientSig`** to the merged JSON, then **`POST /multiSignRequest`** as usual.

**Example:** The commands below use **`python3`**; that only works if the **`eth-account`** pipx venv is the **`python3`** on your **`PATH`**. Otherwise use that venv’s **`python`** path (see **`pipx list`** and **[Python dependencies](#python-dependencies)**).

```bash
python3 "$RECIPES/erc20_transfer.py" ... > /tmp/a.json
python3 "$RECIPES/ctmerc20_transfer.py" ... > /tmp/b.json
NONCE=$(cast nonce "$WALLET_ADDRESS" --rpc-url "$RPC")
python3 "$MPA_PATH/scripts/multiSignJoin.py" --a /tmp/a.json --b /tmp/b.json --first-nonce "$NONCE"
```

**Common mistakes**

- Using **`forge script … --broadcast`** — wrong; simulation only until MPC signing completes.
- Confusing **`globalnonce`** (KeyGen MPC counter from **`getGlobalNonceByKeyGenId`**) with **`cast nonce`** — for **`--first-nonce`**, use **EVM** **`cast nonce`** on the MPC address for **that chain**.
- Forgetting **`sendMessage`** after submit — coordination and audit depend on it.

---

## Scripts

**Location:** These are python scripts for API automation that live in **`$MPA_PATH/scripts/`**.
**Dependencies:** (**[Python dependencies](#python-dependencies)** — **`pipx install eth-account`** then **`pipx inject eth-account PyNaCl`**). **`eth_account`** is required for all scripts.

| Location | Use |
|----------|-----|
| `generateSignRequestWithFoundryScript.py` | Forge broadcast JSON → **`multiSignRequest`** JSON helper. |
| `generateMultiSignRequestFromCompose.py` | Compose-style JSON (function + args) → **`multiSignRequest`** body / **`messageToSign`**. Requires **`PyNaCl`**. |
| `multiSignJoin.py` | Two recipe/helper JSON outputs → **one** batch **`multiSignRequest`**; **`--first-nonce`** = EVM **`cast nonce`**; same chain only; preserves gas/fees from inputs. See [multiSignJoin](#multisignjoin-merge-two-multisignrequest-json-files). |
| `executeSignResult.py` | After **`getSignResultById`**: build signed raw txs and broadcast (sequential by default; **`--fast`** for parallel confirm). |
| `keygen_messaging_agent_poll.py` | Poll KeyGen messaging for unread items that mention the agent, then mark them read. |

## Recipes

**Location:** These are thin CLI wrappers that live in **`$MPA_PATH/recipes/`**. They call **`generateMultiSignRequestFromCompose`** internally: **`GET /getKeyGenResultById`**, **`GET /getChainDetails`** (when **`rpcGateway`** is not overridden), then JSON-RPC for nonce / gas / fees.
**Dependencies:** same as **`generateMultiSignRequestFromCompose.py`** (**[Python dependencies](#python-dependencies)** — **`pipx install eth-account`** then **`pipx inject eth-account PyNaCl`**).
**Output:** JSON with **`bodyForSign`**, **`messageToSign`**; add **`clientSig`** (management key) before **`POST /multiSignRequest`**; optional **`--ed25519-seed-hex`** / **`--eip191-private-key-hex`** to embed **`postBody`**.

| Script | Use |
|--------|-----|
| **`linea_register.py`** | **`register()`** on the Linea fee contract (**`59144`**); stored chain RPC; optional **`--no-custom-gas-params`** (ignore ChainDetails gas; RPC-only estimates). |
| **`linea_fee_deposit.py`** | **`deposit(address,uint256)`** on the Linea fee contract; **`--amount-wei`** (fee token smallest units); MPC **`ethereumaddress`** from **`getKeyGenResultById`**; **ERC20 approve** required before submit. |
| **`erc20_transfer.py`** | **`transfer(address,uint256)`** on the token **`--token`**; **`--chain-id`**, **`--to`**, **`--amount`** / **`--amount-unit`**; optional **`--no-custom-gas-params`**, **`--rpc-gateway`**. |
| **`native_transfer.py`** | Native gas token send to **`--to`** (compose **`nativeTransfer`**); same flags pattern as ERC-20. |
| **`ctmerc20_transfer.py`** | CTMERC20 **`c3transfer(string,uint256,string)`** (same sig as **Add Asset** / **`GET /getTokens`** defaults in **`TOKEN_STORAGE_SCHEMA.md`**); **`--to-chain-id`** for the third arg (cross-chain); defaults to **`--chain-id`** when omitted. |
| **`ctmrwa1_transfer_whole.py`** | CTMRWA1 **`transferWholeTokenX`** (whole **`fromTokenId`**); **`--from`**, **`--to`**, **`--from-token-id`**, **`--id`**, **`--version`**, **`--fee-token-str`**, optional **`--to-chain-id`**. |
| **`ctmrwa1_transfer_partial.py`** | CTMRWA1 **`transferPartialTokenX`** (partial fungible **`value`**); **`--from-token-id`**, **`--to`**, **`--value`** / **`--value-unit`**, **`--id`**, **`--version`**, **`--fee-token-str`**, optional **`--to-chain-id`**. |

**Example:** Same **`python3`** note as in the [multiSignJoin](#multisignjoin-merge-two-multisignrequest-json-files) example: **`python3`** must resolve to the **`eth-account`** pipx environment (see **[Python dependencies](#python-dependencies)**). Otherwise use the venv **`python`** from **`pipx list`**.

```bash
python3 "$MPA_PATH/recipes/linea_register.py" --key-gen-id "$KEYGEN_ID" --mpc-auth-url "$MPC_AUTH_URL"
python3 "$MPA_PATH/recipes/linea_fee_deposit.py" --key-gen-id "$KEYGEN_ID" --amount-wei 1000000000000000000 --mpc-auth-url "$MPC_AUTH_URL"
python3 "$MPA_PATH/recipes/erc20_transfer.py" --key-gen-id "$KEYGEN_ID" --chain-id 59144 --token 0x... --to 0x... --amount 1 --amount-unit Ether
python3 "$MPA_PATH/recipes/native_transfer.py" --key-gen-id "$KEYGEN_ID" --chain-id 59144 --to 0x... --amount 0.01 --amount-unit Ether
python3 "$MPA_PATH/recipes/ctmerc20_transfer.py" --key-gen-id "$KEYGEN_ID" --chain-id 59144 --token 0x... --to 0x... --amount 100 --amount-unit Wei --to-chain-id 1
python3 "$MPA_PATH/recipes/ctmrwa1_transfer_whole.py" --key-gen-id "$KEYGEN_ID" --chain-id 59144 --token 0x... --from 0x... --to 0x... --from-token-id 1 --id 42 --version 1 --fee-token-str 0x...
python3 "$MPA_PATH/recipes/ctmrwa1_transfer_partial.py" --key-gen-id "$KEYGEN_ID" --chain-id 59144 --token 0x... --from-token-id 1 --to 0x... --value 1 --value-unit Ether --id 42 --version 1 --fee-token-str 0x...
```

## References (bundled snapshots)

**Location:** References directory containing API specification and agent instructions that live in **`$MPA_PATH/references`**.

| Document | Description |
|----------|-------------|
| [AGENT_BASICS.md]($MPA_PATH/references/AGENT_BASICS.md) | Overview of how an agent interacts with an MPA wallet. |
| [instructions.md]($MPA_PATH/references/instructions.md) | Human-oriented full workflow; same story as above with more narrative. |
| [AGENT_ED25519_SETUP.md]($MPA_PATH/references/AGENT_ED25519_SETUP.md) | Agent Ed25519 onboarding, `PublicMgtKey`, `addManagementKey`. |
| [AI_AGENT_FORGE_SIGNREQUEST.md]($MPA_PATH/references/AI_AGENT_FORGE_SIGNREQUEST.md) | End-to-end: Foundry → Python helper → `multiSignRequest`; **`clientSig`** rules. |
| [AI_AGENT_COMPOSE_MULTISIGNREQUEST.md]($MPA_PATH/references/AI_AGENT_COMPOSE_MULTISIGNREQUEST.md) | Compose JSON → `multiSignRequest`; `generateMultiSignRequestFromCompose.py`. |
| [API_IMPLEMENTATION.md]($MPA_PATH/references/API_IMPLEMENTATION.md) | Canonical REST API specification (endpoints, auth, bodies). |
| [swagger.yaml]($MPA_PATH/references/swagger.yaml) | OpenAPI/Swagger for tooling and codegen. |
| [TOKEN_STORAGE_SCHEMA.md]($MPA_PATH/references/TOKEN_STORAGE_SCHEMA.md) | Local token config (**ERC20**, **CTMERC20** `c3transfer` sig, **CTMRWA1**, etc.). |
| [API_KEYGEN_MESSAGING.md]($MPA_PATH/references/API_KEYGEN_MESSAGING.md) | API specification for the inter-node messaging system. |
| [KNOWN_ADDRESSES_SCHEMA.md]($MPA_PATH/references/KNOWN_ADDRESSES_SCHEMA.md) | Address book for commonly used addresses (both EOA and contract), managed and stored locally by the node only. |
| [README.md]($MPA_PATH/references/README.md) | |

## Tools

**Location:** Directory containing tools including sign-clipboard for signing all POST requests, that live in **`$MPA_PATH/tools`**.

---

## Style notes for agents

- Prefer **exact** JSON bodies and canonical signing strings as described in **API_IMPLEMENTATION**.
- Use **`Thoughts`** and **`Purpose`** as durable audit and coordination context across nodes.
