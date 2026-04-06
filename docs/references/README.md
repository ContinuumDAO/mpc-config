# Reference documents (snapshot)

This folder contains a **snapshot** of documents from the sibling repository **`mpc-config/docs`** (path: `../mpc-config/docs` relative to the `mpc-auth` repo root). They are copied here so **SKILLS.md** and tooling (e.g. Open Claw / Clawhub) can cite stable paths inside this repo.

For the **full narrative** workflow (same source as the skill), see also **[`./instructions.md`](./instructions.md)** in this repo.

---

## Overview (why these docs exist)

A **Multi-Party Agent (MPA) wallet** is a **single** on-chain address (EVM today: one Ethereum address) that has a **public** key, but **no single machine ever holds the full private key**. The key material exists only as a distributed **Multi-Party Computation (MPC)** secret split across a **Group** of nodes (often on VPSs). To produce a valid **MPC signature**, at least **threshold+1** nodes must cooperate. The **threshold** is chosen when the **KeyGen** (MPC wallet creation) is set up. That design protects the address: one compromised laptop cannot drain the wallet alone.

The same MPC address can be used on **any EVM chain**; it is **not** tied to a specific smart contract.

**Humans and agents are peers.** Typically some nodes are run by people and one or more by an **AI agent** (e.g. Open Claw). Each node uses the **same class of APIs**; the agent is not a “special” signer—it participates in messaging, agrees or rejects sign requests, and may originate transactions like anyone else in the KeyGen.

**What the agent is for (in product terms):** ingest intent via the **KeyGen group messaging** API (preferred)—or another channel such as Telegram—then reason, optionally research online, produce **[Foundry](https://www.getfoundry.sh/introduction/getting-started)** scripts, and drive **joint** signing so that **`threshold+1`** nodes accept a **`/multiSignRequest`** before **`/triggerSignRequestById`** runs the MPC signing protocol.

### Two completely different “signatures” (do not confuse them)

| Kind | What it is | Used for |
|------|------------|----------|
| **Management signature** | Each **client** (human or agent) has its **own** keypair. Public keys live in node config (e.g. `mpc-config/configs.yaml`). | Authenticating **HTTP POST** calls to **this node’s** management API (`clientSig`, message `Sig`, etc.). |
| **MPC signature** | Produced only when enough nodes agree on the **same** sign request and run TSS together. **There is no exportable MPC private key on any disk.** | Authorizing a **transaction** or message as the **shared MPC wallet** address. |

Agents using Ed25519 use **`PublicMgtKey`** / **`POST /addManagementKey`** for **management** signing; that key is **not** the MPC key from KeyGen.

### Groups, KeyGen, and signing (minimal mental model)

- **Group:** Nodes add each other in config, one node starts a group request, everyone invited accepts → a **Group ID** exists. Messaging and trust are scoped to that group.
- **KeyGen:** A member starts a KeyGen with nodes in the group; all invited must accept → after distributed computation you get a **pubKey** (and for secp256k1, an Ethereum address). **Threshold** is fixed here.
- **Signing:** Any KeyGen member can propose a **sign request**. Others evaluate it (`Purpose`, **messages**, **`Thoughts`**). If **threshold+1** accept, an originator can **trigger** MPC signing, then broadcast on-chain and **update** sign result status.

The files below spell out **exact** HTTP paths, bodies, and signing rules.

---

| File | Role |
|------|------|
| [AGENT_ED25519_SETUP.md](./AGENT_ED25519_SETUP.md) | Ed25519 management key setup for agents; API base URL and auth patterns |
| [AI_AGENT_FORGE_SIGNREQUEST.md](./AI_AGENT_FORGE_SIGNREQUEST.md) | Foundry `forge script` → `POST /multiSignRequest`; Python helper and `clientSig` |
| [API_KEYGEN_MESSAGING.md](./API_KEYGEN_MESSAGING.md) | KeyGen messaging: `sendMessage`, `getMessageThread`, management signatures |
| [API_IMPLEMENTATION.md](./API_IMPLEMENTATION.md) | Full REST API behavior, auth, and endpoint details |
| [swagger.yaml](./swagger.yaml) | OpenAPI / Swagger specification for the management API |

Cross-links inside these files may still mention `mpc-config/docs/...`; resolve them against the copies in this folder when working only inside `mpc-auth`.
