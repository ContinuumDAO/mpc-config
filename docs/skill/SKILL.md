---
name: mpa-wallet
description: Operate and automate threshold multisignature workflows for MPC/MPA wallets on an isolated, dedicated host that contains no unrelated sensitive data or private keys.
version: 1.0.1
metadata:
  openclaw:
    requires:
      env:
        - KEYGEN_ID
        - AUTH_KEY_PATH
        - REFS_PATH
        - SCRIPTS_PATH
      bins:
        - curl
        - jq
        - forge
        - cast
        - python3
      config:
        - "~/.ssh/mpc_auth_ed25519"
        - "~mpcnode/mpc-config/configs.yaml"
        - "~mpcnode/mpc-config/scripts"
        - "~mpcnode/mpc-config/docs/references"
    primaryEnv: AUTH_KEY_PATH
    os:
      - linux
    homepage: https://clawhub.ai/patrickcure/mpa-wallet
---

# Skill: MPA / MPC wallet agent (Open Claw / Clawhub)

Use this skill when operating an **AI agent** (e.g. **Open Claw**) that manages an **mpc-auth** node participating in a **Multi-Party Agent (MPA) wallet**: a single on-chain address (EVM today) whose **MPC signature** requires cooperation of **at least threshold+1** nodes in a **Group**. No single node holds the full private key.

## Prerequisites

This skill assumes the **operator has already provisioned an MPA wallet environment** in ContinuumDAO terms—not a single standalone node:

- **At least two mpc-auth nodes** must exist: one run by a **human** and one run for the **AI agent**. Threshold signing requires multiple parties; a minimal useful setup pairs a human-controlled node with an agent-controlled node.
- The **agent’s node** must use **Ed25519 management signing** (`PublicMgtKey` / `POST /addManagementKey` flow) so automated `POST` calls to the management API are authenticated without MetaMask. See **[$REFS_PATH/AGENT_ED25519_SETUP.md]($REFS_PATH/AGENT_ED25519_SETUP.md)** in this repo for technical steps.
- A link from `~mpcnode/mpc-config/scripts` and `~mpcnode/mpc-config/docs/references` is made using `ln -s ~mpcnode/mpc-config/scripts ~/. && ln -s ~mpcnode/mpc-config/docs/references ~/.` (target other directories if using a custom $REFS_PATH or $SCRIPTS_PATH, see [environment](#environment-agent) below).

## Host security requirements (mandatory)

- Run this skill only on a **dedicated, isolated machine** used for MPC node operations.
- Do **not** run this skill on hosts that contain unrelated secrets, wallets, SSH keys, cloud credentials, or developer tokens.
- The only private key material available to the agent should be the **dedicated management key** used for management API authentication.
- Restrict filesystem and network permissions to only what is required for the local mpc-auth node and expected RPC/API endpoints.
- Prefer a dedicated key path (outside your normal user SSH key set) and ensure this key is not reused for other systems.

**ContinuumDAO documentation** (end-user setup, before this skill applies):

| Topic | Link |
|--------|------|
| **Running a node** (install, configure, operate an mpc-auth node) | [Node running instructions](https://docs.continuumdao.org/ContinuumDAO/RunningInstructions/NodeRunningInstruction) |
| **Creating an MPC signer** (forming a **Group**, running **KeyGen**, obtaining the shared MPC wallet / address) | [Create MPC signer](https://docs.continuumdao.org/ContinuumDAO/MPCSigner/CreateMPCSigner) |
| **Interact using Foundry** (create forge scripts, read on-chain data using cast) | [Foundry skill](https://docs.continuumdao.org/ContinuumDAO/OpenClaw/FoundryInstructionSkill) |

Complete those guides first; then use this skill for **day-to-day agent behavior** (messaging, `multiSignRequest`, agree/trigger/execute, and API discipline).

---

## Overview (read this first)

This section restates the ideas in **[`$REFS_PATH/instructions.md`]($REFS_PATH/instructions.md)** in a form suited for **users and agents** who do not yet see why **Group**, **KeyGen**, **threshold**, and **two signature types** matter.

### What you are operating

A **Multi-Party Agent (MPA) wallet** is **one** shared wallet address (EVM today: one Ethereum address) whose **private key never exists whole on any server**. It is created and used via **Multi-Party Computation (MPC)** across a **Group** of **nodes** (often VPSs). **No single node can sign alone:** producing a valid **MPC signature** requires cooperation of at least **threshold+1** nodes. The integer **threshold** is set when the **KeyGen** is created. That is how the address stays protected if one machine is compromised.

The MPC address works on **any EVM network**; it is **not** locked to one smart contract.

**Humans and AI agents are symmetric.** Some nodes are operated by people, others by an agent (e.g. Open Claw). All use the same REST ideas: **message** the group, **propose** txs via **`/multiSignRequest`**, **agree** or **reject** with **`/signRequestAgree`**, optionally add **`Thoughts`**, then **trigger** MPC signing and **broadcast**. The agent’s job is to take **intent** from discussion (KeyGen messaging preferred, or e.g. Telegram), optionally **research**, produce **Foundry** scripts ([Foundry](https://www.getfoundry.sh/introduction/getting-started)), and turn outputs into **`multiSignRequest`** payloads—always subject to **threshold+1** agreement before **`triggerSignRequestById`**.

### The two signatures (critical distinction)

1. **Management signature** — **Per-node API authentication.** Each client has its **own** key material; public keys are in config (e.g. **`mpc-config/configs.yaml`**). Every **`POST`** to the management API must be signed by **that** client’s management key (Ed25519 for agents, often MetaMask for interactive users). This proves **who is calling the API**, not what the MPC wallet authorizes on-chain.

2. **MPC signature** — **On-chain authorization** by the **shared** wallet. There is **no** single MPC private key file. Nodes run a protocol so that, only after enough **agreements**, a signature valid for the **MPC public address** is produced.

### Groups, KeyGen, signing (short)

- **Group:** Peers configure each other, one node proposes a group, invitees accept → **Group ID**. See **Groups** / **KeyGen** / **Signing** in [`instructions.md`]($REFS_PATH/instructions.md).
- **KeyGen:** Started inside a group; all participants must accept; yields **pubKey** / (secp256k1) an **Ethereum address** and fixes **threshold**.
- **Signing:** A member proposes a sign request; each node **accepts or rejects**; optional **`Thoughts`** guide whether to **shelve** and revise. With **threshold+1** accepts, **`triggerSignRequestById`** runs MPC signing; then **broadcast** txs and **`updateSignResultStatusById`**.

### Persistent context (why messages and Purpose matter)

Each node stores the same logical data over time: **KeyGen messages** (`listMessages`, `getMessageThread`, …) and **sign-request / sign-result metadata** (**`Purpose`**, **`Thoughts`**). That **shared history** is what future decisions should use—regardless of which LLM or agent version is connected.

---

## When this skill applies

- Proposing or evaluating **multi-sign requests** (`POST /multiSignRequest`, `POST /signRequestAgree`, `POST /triggerSignRequestById`).
- Using **KeyGen messaging** (`POST /sendMessage`, `GET /getMessageThread`) for group coordination.
- Generating **Foundry** scripts and turning **`forge script`** output into API payloads.
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
| **`REFS_PATH`** | If set, points to the references directory containing API specification and agent instructions. | ~/references |
| **`SCRIPTS_PATH`** | If set, points to the scripts directory containing python scripts for API automation. | ~/scripts |

Base URL for a co-located node: **`http://127.0.0.1:<ManagementAPIsPort>`** (see `configs.yaml`, often **8080**). For HTTP calls from scripts, set **`MPC_AUTH_URL`** to that base URL if it is not the default `http://127.0.0.1:8080`.

**`scripts/keygen_messaging_agent_poll.py`** uses **`KEYGEN_ID`**, **`AUTH_KEY_PATH`**, and optional **`MPC_AUTH_URL`** (see the script docstring for poll-specific env vars).

### KeyGen inbox poll (`@agent`)

To **notice unread channel messages directed at the agent** without manual **`GET /listMessages`** each time, run **`$SCRIPTS_PATH/keygen_messaging_agent_poll.py`** on a timer (recommended: **Open Claw Gateway isolated cron**; see **`$REFS_PATH/AGENT_ED25519_SETUP.md`** §8.5 and [Open Claw cron](https://docs.openclaw.ai/cron)).

1. **Once:** `pip install -r $SCRIPTS_PATH/requirements-keygen-agent.txt` (needs **`cryptography`**).
2. **Run:** `python3 $SCRIPTS_PATH/keygen_messaging_agent_poll.py` with **`KEYGEN_ID`** set (and **`AUTH_KEY_PATH`** / **`MPC_AUTH_URL`** if not defaults). **`--dry-run`** lists matching unread messages without calling **`multiMarkMessagesRead`**.
3. **Output:** one JSON line: **`matches`**, **`match_count`**, **`marked_ids`**. The script marks matched messages read so the next poll does not repeat them.
4. **After a non-empty `matches`:** interpret the thread, decide what to do, and reply with **`POST /sendMessage`** (management-signed; **`$REFS_PATH/API_KEYGEN_MESSAGING.md`**). Humans can **`@agent`** in title or body to target the agent.

---

## Default operational loop (high level)

1. **Discuss** in KeyGen messaging: human or other nodes **`POST /sendMessage`**; everyone reads **`GET /getMessageThread`** (and related list/get APIs). Optionally use the **KeyGen inbox poll** above when the agent should wake on **`@agent`** mentions.
2. **Plan**: agent may research on the web; produce **Foundry** scripts and a **rationale**; optionally push to a shared Git repo.
3. **Build tx intent**: run **`forge script … --sender <MPC address>`** → `broadcast/.../run-latest.json`; feed to **`$SCRIPTS_PATH/generateSignRequestWithFoundryScript.py`** (see references) to build JSON for **`POST /multiSignRequest`**. Include a concise **`Purpose`** (≤256 chars).
4. **Agree**: each node **`POST /signRequestAgree`** (accept/reject); optional **`Thoughts`** per node to guide the agent (e.g. to **`POST /shelveSignRequest`** and revise).
5. **Trigger & sign**: when **`/isSignRequestReadyById`** is true and the agent should proceed, **`POST /triggerSignRequestById`**; poll **`GET /getSignResultById`** until signatures exist.
6. **Execute**: broadcast tx(s) with sufficient gas/credit; **`POST /updateSignResultStatusById`** with **`executed`** and **`transactionHash`** (or batch hashes).
7. **Report**: **`POST /sendMessage`** summarizing what was done and what to expect.
8. **Context**: for future spends, use **messages** plus **`Purpose` / `Thoughts`** on sign results (**`GET /listSignResults`**, **`GET /getSignRequestById`** / **`getSignResultById`**).

---

## Other API capabilities (agent)

Per **`$REFS_PATH/instructions.md`**, the agent may also: **`/keyGenRequest`**, **`/keyGenRequestAgree`**, **`/addKnownAddress`**, **`/postChainDetails`**, **`/addToken`**, health/version discovery, and **fee/credit** checks via **`GET /getGlobalNonceByKeyGenId`** (and top-up gas as needed). For **on-chain** fee state on **Linea mainnet**, use the subsection below.

---

## Fee payment (Linea mainnet, chainId 59144)

ContinuumDAO’s **fee / registration** contract on **Linea** is deployed at a fixed address. Agents should use **Foundry `cast`** against that contract with an RPC URL taken from the node’s chain config (same pattern as other on-chain checks).

**Fee contract (Linea mainnet):** `0x55aD6Df6d8f8824486C3fd3373f1CF29eCecF0A3`

**Variables:** Set **`KEYGEN_ID`** to your KeyGen result id (see **Environment**). Set **`WALLET_ADDRESS`** to the MPC wallet **Ethereum address** for that KeyGen (from **`GET /getKeyGenResultById`** / **`ethereumaddress`**). Use your co-located management API base URL instead of `localhost` if needed.

**RPC URL from the node** (Linea `chain_id` **59144**):

```bash
RPC=$(curl -s "http://localhost:8080/getChainDetails?chain_id=59144" | jq -r '.Data.rpcGateway')
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
GNONCE=$(curl -s "http://localhost:8080/getGlobalNonceByKeyGenId?id=$KEYGEN_ID" | jq -r '.Data.globalnonce')

# Remaining signatures before top-up
cast call 0x55aD6Df6d8f8824486C3fd3373f1CF29eCecF0A3 \
  "getRemainingNonces(address,uint256)(uint256)" $WALLET_ADDRESS $GNONCE --rpc-url $RPC
```

**Note:** **`globalnonce`** here is the KeyGen’s MPC signing counter from the API. It is **not** the EVM account nonce from **`cast nonce`**. **Fee payment / top-up** can be sent as ordinary EVM transactions **from any funded wallet**—they do **not** require the **`multiSignRequest`** / threshold flow. Paying from a separate hot wallet or custodian is often more convenient than routing top-ups through the MPC wallet. If you do spend **from the MPC address** itself, those txs still go through **`multiSignRequest`** as usual. For ABI-level details of the fee contract, see **[$REFS_PATH/API_IMPLEMENTATION.md]($REFS_PATH/API_IMPLEMENTATION.md)** and on-chain docs your deployment publishes.

---

## Incoming MPC sign requests (policy)

When another member requests a signature, default decision inputs:

- Group **messages** and the request **`Purpose`**.
- Independent research on whether signing is appropriate.
- Owner instructions left for the agent.
- If uncertain, **message the owner** on the dedicated messaging API **`POST /sendMessage`** awaiting guidance.

Remember: **threshold+1** accepts are required to generate the MPC signature.

---

## Authentication discipline

- Every **`POST`** to the management API requires a **management** signature (Ed25519 or MetaMask flow per node config).
- **`clientSig`** on **`multiSignRequest`** signs the **canonical request body** with the **management** key—not the MPC key.
- Setup details: **[references/AGENT_ED25519_SETUP.md]($REFS_PATH/AGENT_ED25519_SETUP.md)**.

---

## Creating transactions (`multiSignRequest`)

Skim-level recipe for agents (e.g. Open Claw). **Full commands, flags, and signing details:** **[$REFS_PATH/AI_AGENT_FORGE_SIGNREQUEST.md]($REFS_PATH/AI_AGENT_FORGE_SIGNREQUEST.md)**.

1. **Simulate with Foundry** — Run **`forge script`** with **`--rpc-url`** and **`--sender <MPC address>`**. **Do not** use **`--broadcast`** (the MPC key is not on disk). Consume the artifact **`broadcast/<Script>.s.sol/<chain_id>/run-latest.json`**.
2. **Build the request JSON** — Run **`cast nonce <MPC address> --rpc-url $RPC`** and pass that value as **`--first-nonce`** to **`$SCRIPTS_PATH/generateSignRequestWithFoundryScript.py`** (see **Scripts** below), together with **`--key-gen-id`**, **`--file`** pointing at **`run-latest.json`**, **`--purpose`**, and **`--mpc-auth-url`**. The helper needs Python **`eth_account`** (see the reference doc).
3. **Sign and submit** — Clear **`clientSig`** / **`signedMessage`**, build **canonical JSON**, sign with the **management** key, set **`clientSig`**, then **`POST /multiSignRequest`**.
4. **Notify the group** — **`POST /sendMessage`** on the KeyGen channel with a short title/body and the **request id** returned from **`multiSignRequest`** so peers can review.

**Common mistakes**

- Using **`forge script … --broadcast`** — wrong; simulation only until MPC signing completes.
- Confusing **`globalnonce`** (KeyGen MPC counter from **`getGlobalNonceByKeyGenId`**) with **`cast nonce`** — for **`--first-nonce`**, use **EVM** **`cast nonce`** on the MPC address for **that chain**.
- Forgetting **`sendMessage`** after submit — coordination and audit depend on it.

---

## Scripts (linked in $SCRIPTS_PATH)

| Location | Use |
|----------|-----|
| `$SCRIPTS_PATH/generateSignRequestWithFoundryScript.py` | Forge broadcast JSON → **`multiSignRequest`** JSON helper. |

---

## References (bundled snapshots)

| Document | Description |
|----------|-------------|
| [references/AGENT_BASICS.md]($REFS_PATH/AGENT_BASICS.md) | Overview of how an agent interacts with an MPA wallet. |
| [references/instructions.md]($REFS_PATH/instructions.md) | Human-oriented full workflow; same story as above with more narrative. |
| [references/AGENT_ED25519_SETUP.md]($REFS_PATH/AGENT_ED25519_SETUP.md) | Agent Ed25519 onboarding, `PublicMgtKey`, `addManagementKey`, localhost API port. |
| [references/AI_AGENT_FORGE_SIGNREQUEST.md]($REFS_PATH/AI_AGENT_FORGE_SIGNREQUEST.md) | End-to-end: Foundry → Python helper → `multiSignRequest`; **`clientSig`** rules. |
| [references/API_IMPLEMENTATION.md]($REFS_PATH/API_IMPLEMENTATION.md) | Canonical REST API specification (endpoints, auth, bodies). |
| [references/swagger.yaml]($REFS_PATH/swagger.yaml) | OpenAPI/Swagger for tooling and codegen. |

---

## Style notes for agents

- Prefer **exact** JSON bodies and canonical signing strings as described in **API_IMPLEMENTATION**.
- Use **`Thoughts`** and **`Purpose`** as durable audit and coordination context across nodes.
