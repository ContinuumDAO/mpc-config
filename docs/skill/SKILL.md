---

name: mpa-wallet
description: >
  Operate and automate threshold multisignature workflows for MPC/MPA wallets
  on an isolated, dedicated host that contains no unrelated sensitive data or
  private keys.
version: 1.0.12
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
        - pip3
      config:
        - "$AUTH_KEY_PATH/mpc_auth_ed25519"
        - "$MPC_CONFIG_PATH/configs.yaml"
        - "$MPA_PATH/.env"
    primaryEnv: MPC_AUTH_URL
    os:
      - linux
homepage: https://clawhub.ai/patrickcure/mpa-wallet

---

# Skill: MPA / MPC wallet agent (OpenClaw / Clawhub)

Use this skill when operating an **AI agent** (e.g. **OpenClaw**) that manages an
**mpc-auth** node participating in a **Multi-Party Agent (MPA) wallet**: a single
on-chain address (EVM today) whose **MPC signature** requires cooperation of **at
least threshold+1** nodes in a **Group**. No single node holds the full private
key.

## Examples of usage

Here are some examples of what a user can say to their AI agent

- Create a new KeyGen using the Group with all the nodes and tell me its Ethereum address. 
  Use this KeyGen from now on.
- I have added a little ETH to the new Ethereum address on Linea. Please register it.
- Add the chain Linea mainnet to my node.
- I added some ETH and USDC to my new Ethereum address on Arbitrum mainnet. Please add 
  the ERC20 Asset USDC contract 0xaf88d065e77c8cC2239327C5EDb3A432268e5831 with decimals 6 on Arbitrum.
- Add Arbitrum mainnet to my chain config
- Add a new contact Fred with address 0xf33c74Ee25061966efC645BF2244F6EB0a492511
- Send Fred 100 USDC on Arbitrum
- Send Fred 1 ETH


## Prerequisites

This skill assumes the **operator has already provisioned an MPA wallet
environment** in ContinuumDAO terms—not a single standalone node:

- **At least two mpc-auth nodes** must exist: one run by a **human** and one run
for the **AI agent**. Threshold signing requires multiple parties; a minimal
useful setup pairs a human-controlled node with an agent-controlled node.
- The **agent’s node** must use **Ed25519 management signing** so automated
`POST` calls to the management API are authenticated without MetaMask (operator
provisions `**PublicMgtKey`** / allow-list). Operational signing details:
`**$MPA_PATH/references/ED25519_MANAGEMENT_KEY_SIGNING.md**`.

## Host security requirements (mandatory)

- Run this skill only on a **dedicated, isolated machine** used for MPC node
  operations.
- Do **not** run this skill on hosts that contain unrelated secrets, wallets,
  SSH keys, cloud credentials, or developer tokens.
- The only private key material available to the agent should be the **dedicated
  management key** used for management API authentication.
- Restrict filesystem and network permissions to only what is required for the
  local mpc-auth node and expected RPC/API endpoints.
- Prefer a dedicated key path (outside your normal user SSH key set) and ensure
  this key is not reused for other systems.
- Ensure that there is at least one human-controlled node in the **threshold+1**
  required by the MPC algorithm, so the group cannot be taken over solely via
  prompt injection against an automated management-signing client.

## Scope and egress guardrails (mandatory)

- This skill is limited to **local MPA operations**: management API calls on
`**$MPC_AUTH_URL:$MANAGEMENT_PORT**`, chain RPC calls configured by the node,
and local files under `**$MPA_PATH**` plus the dedicated management key path.
- Do **not** send data to external messaging platforms or third-party web APIs
unless the operator explicitly enables that behavior outside this skill.
- Do **not** read unrelated files, shell history, home-directory secrets, cloud
credentials, wallet files, or SSH keys other than the dedicated management key.
- Treat `**AUTH_KEY_PATH**` material as high-privilege signing input only: never
print or transmit private key contents.
- If a task would require leaving this scope, stop and ask for explicit operator
approval first.

**ContinuumDAO documentation** (end-user setup, before this skill applies):

- **Running a node** — install, configure, operate an mpc-auth node.  
  https://docs.continuumdao.org/ContinuumDAO/RunningInstructions/NodeRunningInstruction
- **Creating an MPC signer** — Group, KeyGen, shared MPC wallet / address.  
  https://docs.continuumdao.org/ContinuumDAO/MPCSigner/CreateMPCSigner
- **Interact using Foundry** — forge scripts, `cast` for on-chain reads.  
  https://docs.continuumdao.org/ContinuumDAO/OpenClaw/FoundryInstructionSkill  
(Building **`multiSignRequest`** bodies for **`POST /multiSignRequest`** is **only**
via the repo helpers listed under **When this skill applies**—not arbitrary forge
projects or hand-written JSON.)

Complete those guides first; then use this skill for **day-to-day agent
behavior** (messaging, `multiSignRequest`, agree/trigger/execute, and API
discipline).

## New session and environment bootstrap

On **session start**, follow **`$MPA_PATH/references/AI_AGENT_NEW_SESSION.md`**:
load **`$MPA_PATH/.env`**, confirm **`MPA_PATH`**, **`MPC_AUTH_URL`**,
**`MANAGEMENT_PORT`**, **`AUTH_KEY_PATH`**, and **`MPC_CONFIG_PATH`**; ensure
**`$MPA_PATH/{recipes,references,scripts,tools}`** symlink to the clone under
**`MPC_CONFIG_PATH`** when the repo dirs exist; verify **`GET /health`**; then
set or obtain **`KEYGEN_ID`** (existing id or **`POST /keyGenRequest`** / agree
flow per **`$MPA_PATH/references/API_IMPLEMENTATION.md`**). That doc also restates
what the **mpa-wallet** skill is for.

---

## Overview (read this first)

This section restates the ideas in **`$MPA_PATH/references/instructions.md`**
in a form suited for **users and agents** who do not yet see why **Group**,
**KeyGen**, **threshold**, and **two signature types** matter.

### What you are operating

A **Multi-Party Agent (MPA) wallet** is **one** shared wallet address (EVM today:
one Ethereum address) whose **private key never exists whole on any server**. It
is created and used via **Multi-Party Computation (MPC)** across a **Group** of
**nodes** (often VPSs). **No single node can sign alone:** producing a valid **MPC
signature** requires cooperation of at least **threshold+1** nodes. The integer
**threshold** is set when the **KeyGen** is created. That is how the address stays
protected if one machine is compromised.

The MPC address works on **any EVM network**; it is **not** locked to one smart
contract.

**Humans and AI agents are symmetric.** Some nodes are operated by people, others
by an agent (e.g. Open Claw). All use the same REST ideas: **message** the group
to **propose** and refine **intent**; **build** **`multiSignRequest`** bodies
**only** with **`$MPA_PATH/scripts/generateMultiSignRequestFromCompose.py`**,
**`$MPA_PATH/scripts/generateSignRequestWithFoundryScript.py`**, or
**`$MPA_PATH/recipes/`** scripts (see **`$MPA_PATH/references/AI_AGENT_COMPOSE_MULTISIGNREQUEST.md`**
and **`$MPA_PATH/references/AI_AGENT_FORGE_SIGNREQUEST.md`**). **Never** invent or
hand-edit **`multiSignRequest`** JSON from scratch. **Submit**
**`POST /multiSignRequest`** with that helper output plus management **`clientSig`**
/ **`signedMessage`** (see **`$MPA_PATH/references/ED25519_MANAGEMENT_KEY_SIGNING.md`**).
**Other** nodes **agree** or **reject** with **`/signRequestAgree`** (the
**originator** does not need to agree), optionally add **`Thoughts`**, then **EVM
execution** is **only** **`$MPA_PATH/scripts/executeSignResult.py`**: that script
**`POST`**s **`/triggerSignRequestById`** (management-signed, with **`txParams`**
/ **`messageHash`** when required), **polls** **`GET /getSignResultById`** until
MPC signatures exist, then **`eth_sendRawTransaction`**—do **not** call
**`POST /triggerSignRequestById`** **directly** or bypass the script. The agent’s
job is to take **intent** from the KeyGen messaging flow, run **only** those
helpers. Use **`multiSignJoin.py`** to merge **two** helper-sized JSON files into
**one** batch; **save stdout** and run **`multiSignJoin.py`** again (previous output
as **`--a`** or **`--b`**, plus another helper file) to extend ordered sequences on
the same chain—**repeatedly** for multi-step flows. Then **`POST /multiSignRequest`**
with management signing and later **`executeSignResult.py`** as required—**never**
fabricate **`multiSignRequest`** JSON except via the approved helpers (compose,
Forge, recipes, or **`multiSignJoin`** when merging two outputs).

https://www.getfoundry.sh/introduction/getting-started

### The two signatures (critical distinction)

1. **Management signature** — **Per-node API authentication.** Each client has its
  **own** key material; public keys are in config (e.g. `**mpc-config/configs.yaml**`).
   Every `**POST**` to the management API must be signed by **that** client’s
   management key (Ed25519 for agents, often MetaMask for interactive users). This
   proves **who is calling the API**, not what the MPC wallet authorizes on-chain.
2. **MPC signature** — **On-chain authorization** by the **shared** wallet. There
  is **no** single MPC private key file. Nodes run a protocol so that, only after
   enough **agreements**, a signature valid for the **MPC public address** is
   produced.

### Groups, KeyGen, signing (short)

- **Group:** Peers configure each other, one node proposes a group, invitees accept
→ **Group ID**. See **Groups** / **KeyGen** / **Signing** in
`**$MPA_PATH/references/instructions.md**`.
- **KeyGen:** Started inside a group; all participants must accept; yields **pubKey**
/ (secp256k1) an **Ethereum address** and fixes **threshold**. When all nodes have agreed,
the KeyGen is automatically generated after a delay of up to 2 minutes.
- **Signing:** A member proposes a sign request; each node **accepts or rejects**;
optional `**Thoughts**` guide whether to **shelve** and revise. With **threshold+1**
accepts, `**executeSignResult.py**` `**POST`**s `**/triggerSignRequestById`** (MPC
signing), then **broadcast** txs and `**updateSignResultStatusById`**.

### Persistent context (why messages and Purpose matter)

Each node stores the same logical data over time: **KeyGen messages**
(`listMessages`, `getMessageThread`, …) and **sign-request / sign-result metadata**
(`**Purpose`**, `**Thoughts**`). That **shared history** is what future decisions
should use—regardless of which LLM or agent version is connected.

---

## When this skill applies

- Generating **single or batched** transaction proposals and **`POST /multiSignRequest`**:
  **only** use helper output from **`$MPA_PATH/scripts/generateMultiSignRequestFromCompose.py`**,
  **`$MPA_PATH/scripts/generateSignRequestWithFoundryScript.py`**,
  **`$MPA_PATH/scripts/multiSignJoin.py`** (including **chained** runs whose inputs are
  prior helper or **`multiSignJoin`** output), or a script under **`$MPA_PATH/recipes/`**—see
  **`$MPA_PATH/references/AI_AGENT_COMPOSE_MULTISIGNREQUEST.md`**. **Never** hand-write or
  invent **`multiSignRequest`** JSON; add **`clientSig`** / **`signedMessage`** per
  **`$MPA_PATH/references/ED25519_MANAGEMENT_KEY_SIGNING.md`**, then **`POST /multiSignRequest`**.
  For the Foundry helper, feed **`forge script`** **`run-latest.json`** per
  **`$MPA_PATH/references/AI_AGENT_FORGE_SIGNREQUEST.md`**. Common intents include **token
  transfers**, **cross-chain** calls, and other **DeFi** protocol interactions.
  **Evaluating** the multi-sign lifecycle (**`POST /signRequestAgree`**, etc.) when helping
  operators interpret state. **EVM trigger + broadcast:** **only**
  **`$MPA_PATH/scripts/executeSignResult.py`** (it **`POST`**s **`/triggerSignRequestById`**—do
  not call that endpoint **directly**).
- Using **KeyGen messaging** (`POST /sendMessage`, `GET /getMessageThread`) for
group coordination.
- **Combining** with **`multiSignJoin.py`:** merge **two** JSON outputs (recipes,
  compose/Foundry helpers, or **a previous `multiSignJoin` stdout** saved to a file)
  into **one** batch. **Chain merges** by running **`multiSignJoin.py`** again on
  (merged file + next helper) to build longer same-chain sequences; then **`POST /multiSignRequest`**
  with **only** that tool output plus management signing (see **`AI_AGENT_COMPOSE_MULTISIGNREQUEST.md`**).
- Configuring **Ed25519 management** authentication for automated `POST` calls to
the node API.
- Explaining **threshold**, **Purpose**, **Thoughts**, **shelve**, and **execute**
flows.

Do **not** confuse **management signatures** (per-node API auth) with **MPC
signatures** (threshold signing over a message).

---

## Core concepts

- **Group:** Set of nodes that mutually trust each other for relay/config;
  identified by **Group ID**. Formed after configured nodes accept a group
  request.

- **KeyGen:** MPC key generation for a wallet; yields **pubKey** / (for
  secp256k1) an **Ethereum address**. Requires all invited nodes to accept.
  **Threshold** is fixed at KeyGen creation.

- **Threshold:** Minimum cooperating parties minus one in the usual t-of-n
  wording: signing needs **threshold+1** agreeing nodes.

- **Management signature:** Authenticates **this node’s** HTTP **POST**s to its
  management API. Keys come from `mpc-config/configs.yaml` (e.g.
  **PublicMgtKey** / **NodeMgtKey**).

- **MPC signature:** Produced only when enough nodes accept the **same** sign
  request and the network runs the TSS signing protocol—not a single machine’s
  private key.

- **multi-agree:** Policy where nodes explicitly agree (`signRequestAgree`)
  before `triggerSignRequestById`; use **`POST /multiSignRequest`**, not
  `/signRequest` (relayer/tx-check only).

---

## Environment (agent)

Default env file: `**$MPA_PATH/.env**`. Load this file first (if present) before
prompting for missing variables.

- **`KEYGEN_ID`** — If set, prefer this KeyGen for signing when unambiguous. If
  unset or ambiguous, ask the user via the configured channel (e.g. gateway
  **port 18789**), or ask if they want a new KeyGen. **Default:** Unset.

- **`AUTH_KEY_PATH`** — Directory containing the Ed25519 **management** private
  key (see **`AUTH_KEY_FILENAME`**). If **unset**, scripts resolve
  **`~/.ssh/mpc_auth_ed25519`** (equivalent to `~/.ssh` + default basename).
  **Default:** Unset (→ `~/.ssh/mpc_auth_ed25519`).

- **`AUTH_KEY_FILENAME`** — Basename of the key file inside **`AUTH_KEY_PATH`**
  (when set). **Default:** `mpc_auth_ed25519`.

- **`MPC_MGT_ED25519_SEED_HEX`** — Optional override: **exactly 64 hex characters**
  (32-byte raw Ed25519 seed), **not** a PEM/OpenSSH file contents and **not** a
  PKCS#8 Base64 line—see **`$MPA_PATH/references/ED25519_MANAGEMENT_KEY_SIGNING.md`**
  § *Raw 32-byte seed vs key file*. If unset, scripts load **`AUTH_KEY_PATH`**
  / **`AUTH_KEY_FILENAME`** as a key **file**.

- **`MPA_PATH`** — Directory containing references, scripts, recipes, and tools.
  **Default:** `~/.mpa`.

- **`MPC_CONFIG_PATH`** — Absolute path to the **mpc-config** repo root (clone
  with **`configs.yaml`**, **`scripts/`**, **`recipes/`**, **`references/`**,
  **`tools/`**, **`docs/`**). Used for symlinks into **`$MPA_PATH`** and owner
  docs. **Default:** `/path/to/mpc-config`.

- **`MPC_AUTH_URL`** — Base URL of the management API (host only).
  **Default:** `http://127.0.0.1`.

- **`MANAGEMENT_PORT`** — Management API port (see `ManagementAPIsPort` in
  `configs.yaml`). **Default:** `<management_api_port>` (often **8080**).

Base URL for a co-located node: `**$MPC_AUTH_URL:$MANAGEMENT_PORT**` (see
`configs.yaml` for `ManagementAPIsPort`).

`MPA_PATH` is a filesystem location, not a credential. `primaryEnv` is set to
`MPC_AUTH_URL` because the management API endpoint is the primary operational
target for this skill.

Schedule **`$MPA_PATH/scripts/mpc_event_listener.py`** (see **KeyGen inbox poll**
below)—not **`keygen_messaging_agent_poll.py`** alone. **`--keygen-messages`**
runs the same poll as **`keygen_messaging_agent_poll.py`**; **`KEYGEN_ID`**,
**`AUTH_KEY_PATH`**, and **`MPC_AUTH_URL`** apply. **`--sign-ready`** runs
**`executeSignResult.py`** per ready id (which **`POST`**s **`/triggerSignRequestById`**).
**`KEYGEN_ID`** is not required for **`--sign-ready`** alone (that path still needs
**`AUTH_KEY_PATH`** / **`MPC_MGT_ED25519_SEED_HEX`** for management **`POST`**s inside
**`executeSignResult.py`**). If **`KEYGEN_ID`** is not set for the keygen handler,
ask the user what to do, including stopping **`--keygen-messages`** polling with
cron.

### Python dependencies

Use a **dedicated virtual environment** under `**$MPA_PATH/.venv`** (with the
default `**MPA_PATH**`, that is `**~/.mpa/.venv**`). Install packages **into that
venv** with `**pip`** from the venv (e.g. `**$MPA_PATH/.venv/bin/pip install …**`)
or after `**source $MPA_PATH/.venv/bin/activate**` — **not** with bare `**pip3`**
on the system interpreter. PyPI names use hyphens where applicable (`**eth-account**`
installs the `**eth_account**` import).

**Bootstrap once** (if `**$MPA_PATH/.venv`** does not exist):

```bash
python3 -m venv "$MPA_PATH/.venv"
```

Then install into the venv:

1. **Base (all signing scripts in `$MPA_PATH/scripts`):**
  `**$MPA_PATH/.venv/bin/pip install eth-account`** — pulls `**rlp**`, `**eth_utils**`,
   `**hexbytes**`, etc., needed by `**generateSignRequestWithFoundryScript.py**`,
   `**generateMultiSignRequestFromCompose.py**`, `**multiSignJoin.py**`, and
   `**executeSignResult.py**`.
2. **Compose + recipes:** `**$MPA_PATH/.venv/bin/pip install PyNaCl`** — only
  `**generateMultiSignRequestFromCompose.py**` and `**recipes/*.py**` need `**PyNaCl**`
   (optional Ed25519 fields on payloads). Skip if you use **only** the Forge helper,
   `**multiSignJoin`**, or `**executeSignResult**`.
3. **KeyGen inbox poll + event listener:** `**$MPA_PATH/.venv/bin/pip install cryptography`**
  — satisfies `**keygen_messaging_agent_poll.py**` and `**mpc_event_listener.py**`
   (same minimum as `**$MPA_PATH/scripts/requirements-keygen-agent.txt**`).
   Alternatively:
   `**$MPA_PATH/.venv/bin/pip install -r $MPA_PATH/scripts/requirements-keygen-agent.txt**`.

**Verify packages** before running helpers (agents should check the venv, not the
system `**python3`**):

```bash
"$MPA_PATH/.venv/bin/pip" show eth-account PyNaCl cryptography 2>/dev/null | grep -E '^Name:|^Version:'
"$MPA_PATH/.venv/bin/python" -c "import eth_account; import nacl; import cryptography"
```

(Adjust the `**import**` line if optional packages were skipped — e.g. omit `**nacl**`
/ `**cryptography**` when not installed.)

**Run scripts** with `**$MPA_PATH/.venv/bin/python**` — for example
`**$MPA_PATH/.venv/bin/python $MPA_PATH/scripts/generateSignRequestWithFoundryScript.py ...**`.
Plain `**python3 ...**` only works if your shell’s `**PATH**` puts that venv first
(prefer the explicit venv `**python**` path in automation).

### KeyGen inbox poll (`@agent`)

To **notice unread channel messages directed at the agent** without manual
**`GET /listMessages`** each time, schedule **`$MPA_PATH/scripts/mpc_event_listener.py`**
**`--keygen-messages`** (recommended: **OpenClaw Gateway** isolated cron; see
**`$MPC_CONFIG_PATH/docs/AGENT_ED25519_SETUP.md`** §8.5; OpenClaw cron:
https://docs.openclaw.ai/cron). That handler runs the same logic
as **`keygen_messaging_agent_poll.py`**; use the poll script **only** for one-off
debugging, not as the primary scheduled entry point.

If polling may already be configured, report whether it is active, the last run
time (if known), which handlers are enabled, and the period—then ask whether the
operator wants to change it. **Ask the operator once** whether they want scheduled
polling (and where: e.g. OpenClaw cron) **before** you add or change a timer. **If
they want a schedule, ask which period** from the fixed set: **every 1, 5, 10,
30, 60 minutes** or **every 2, 4, 6, 8, 10, 12, 24 hours**. Use
**`$MPA_PATH/scripts/mpc_cron_schedules.py`** (**`--interactive`** on a TTY, or
plain output for the table) to map the choice to OpenClaw **`--every`** and
crontab. Do **not** assume background polling: some setups only use ad-hoc
**`GET /listMessages`** / **`getMessageThread`**, and the handler **marks matched
messages read**. If they already declined, a cron entry already exists, or they
explicitly asked you to wire the poll, skip re-asking.

1. **Once:** install **`cryptography`** into **`$MPA_PATH/.venv`** (see **Python
   dependencies** below).
2. **Run:** **`$MPA_PATH/.venv/bin/python`**
   **`$MPA_PATH/scripts/mpc_event_listener.py`** **`--keygen-messages`** (and
   **`KEYGEN_ID`** set; **`AUTH_KEY_PATH`** / **`MPC_AUTH_URL`** if not defaults).
   **`--dry-run`** applies to the keygen handler only: list matches without
   **`multiMarkMessagesRead`**.
3. **Output:** one JSON line: **`handlers.keygen_messages`** contains **`matches`**,
   **`match_count`**, **`marked_ids`** (same shape as **`keygen_messaging_agent_poll.py`**
   stdout). If **`KEYGEN_ID`** is missing, the **`keygen_messages`** handler fails
   (set **`KEYGEN_ID`**). For a JSON **`error`** line on stdout instead, run
   **`keygen_messaging_agent_poll.py`** directly (debug only).
4. **After `handlers.keygen_messages.match_count` > 0:** the handler only marks
   messages read; **you** must **read each match’s `title` and `body`** (and pull
   thread context with **`GET /getMessageThread`** / related APIs if needed),
   **infer intent**, then **act**—invoke tools, management **`POST`** routes (e.g.
   **`/sendMessage`**), or build **`multiSignRequest`** bodies with the approved
   helpers and **`POST /multiSignRequest`** per
   **`$MPA_PATH/references/AI_AGENT_COMPOSE_MULTISIGNREQUEST.md`** (never invent the
   JSON), or both. Reply in-channel with **`POST /sendMessage`** when a text
   response is appropriate (management-signed;
   **`$MPA_PATH/references/API_KEYGEN_MESSAGING.md`**). Encode the same “parse → act”
   expectation in any **Open Claw cron `--message`** that runs this script. Humans
   can **`@agent`** in title or body to target the agent.

### Event listener (`mpc_event_listener.py`) — optional extra handlers

Use the **same** **`mpc_event_listener.py`** when one cron should also run
**`sign_ready`** (**`GET /listSignRequestsReady`** → **`executeSignResult.py`** per
id, which **`POST`**s **`/triggerSignRequestById`**, polls **`getSignResultById`**,
then broadcasts—optional **`--fast`** / **`--execute-fast`**). **AI agents** run
**only** **`executeSignResult.py`** for EVM execution. **Ask the operator** which
handlers to turn on: use **`--interactive`** (TTY) or explicit **`--keygen-messages`**
/ **`--sign-ready`** (or both). For **`sign_ready`**, **`--execute-fast`** selects
the **`executeSignResult --fast`** path (parallel receipt confirmation for batch
txs); omit it for sequential execution. **`--sign-ready-dry-run`** only lists ready
request ids (no **`executeSignResult`**). **Before** you add or change a timer for
this script, **ask the operator once** if they want scheduled polling (and where:
e.g. Open Claw cron); **if yes, ask which period** from the fixed set (**every 1, 5,
10, 30, 60 minutes** or **every 2, 4, 6, 8, 10, 12, 24 hours**) and map it with
**`mpc_cron_schedules.py`** to Open Claw **`--every`** and crontab. Apply the same
**ask once** / **skip re-asking** rules as the **KeyGen inbox poll** above. More
handlers can be added to the same script over time.

---

## Default operational loop (high level)

1. **Discuss** in KeyGen messaging: human or other nodes `**POST /sendMessage**`;
  everyone reads `**GET /getMessageThread**` (and related list/get APIs). Optionally
   use **`mpc_event_listener.py`** **`--keygen-messages`** (KeyGen inbox poll above)
   when the agent should wake on **`@agent`** mentions.
2. **Plan**: use KeyGen message context plus local/on-chain state to pick a concise
  rationale based on the user's wishes and **which** path applies: **`generateMultiSignRequestFromCompose.py`**,
   **`generateSignRequestWithFoundryScript.py`**, **`$MPA_PATH/recipes/`**, and—**only when**
   merging two separate helper outputs—**`multiSignJoin.py`** (including **chained** joins
   for longer same-chain sequences).
3. **Build and propose:** follow **`$MPA_PATH/references/AI_AGENT_COMPOSE_MULTISIGNREQUEST.md`**
  — **only** those tools; Foundry broadcast JSON for **`generateSignRequestWithFoundryScript.py`**
   per **`$MPA_PATH/references/AI_AGENT_FORGE_SIGNREQUEST.md`**. **Most proposals:** run **one**
   compose/Forge/recipe helper and **`POST /multiSignRequest`** with that stdout (add **`clientSig`** /
   **`signedMessage`** per **`ED25519_MANAGEMENT_KEY_SIGNING.md`**)—**no** **`multiSignJoin`** needed.
   **When you need two helper outputs in one batch:** merge with **`multiSignJoin.py`**
   (**`--first-nonce`** = MPC **`cast nonce`** for the **first** tx in that merge); **repeat**
   with saved stdout plus another helper file to grow the batch. Include a concise **`Purpose`**
   (≤256 chars). **`POST /multiSignRequest`** with **only** tool-produced JSON (**never** ad hoc).
4. **Agree**: **other** nodes (everyone except the **originator** of the sign
  request) `**POST /signRequestAgree**`
   (accept/reject) until **threshold+1** agreements exist. The originator does
   **not** need to agree—creating the request already records their intent. Optional
   `**Thoughts**` per node to guide the agent (e.g. to `**POST /shelveSignRequest**`
   and revise).
5. **Approval gate (recommended default):** require explicit human approval in
  KeyGen messaging before `**executeSignResult.py**` (see step 6).
6. **Trigger, MPC sign, and broadcast (AI agent):** **only**
  `**$MPA_PATH/scripts/executeSignResult.py**`. It `**POST`**s **`/triggerSignRequestById`**
   only when `**getSignResultById**` does not yet have MPC signatures. **EVM
   (required):** pass **`--sign-request-file PATH`** to the **saved JSON from the same
   compose/recipe run** (stdout that includes **`bodyForSign`** with **`txNonce`** /
   **`txGasLimit`** / fee fields), plus **`--sign-request-id`**. The management API does
   not return those fields on **`GET /getSignRequestById`**; the file is what lets the
   script build **`txParams`** and **`messageHash`** for trigger (same as web **Get Sig**).
   See `**$MPA_PATH/references/API_IMPLEMENTATION.md**` § **`POST /triggerSignRequestById`**.
   After trigger, **`GET /getSignRequestById?tx_params=1`** can return the stored snapshot.
   The script **polls** `**GET /getSignResultById`** until signatures exist, then rebuilds and
   **`eth_sendRawTransaction`**. **Single-tx:** same reconstruction as
   **continuumdao-node-app** Execute — **`GET /getSignRequestById?tx_params=1`** (or merged file),
   **`GET /getChainDetails`**, RPC **`estimateGas`** / fee discovery, then **`r,s,v`**.
   **Batch:** **`messageRawBatch[i]`** + **`batchsignatures[i]`**. By default
   **sequential** receipt waits; **`--fast`** for concurrent confirms.
   **Readiness:** **`GET /isSignRequestReadyById`** (see
   **`$MPA_PATH/references/API_IMPLEMENTATION.md`**). Then
   **`POST /updateSignResultStatusById`** with **`executed`** and **`transactionHash`**
   (or batch hashes).
7. **Report**: `**POST /sendMessage`** summarizing what was done and what to expect.
8. **Context**: for future spends, use **messages** plus `**Purpose` / `Thoughts`**
  on sign results (`**GET /listSignResults**`, `**GET /getSignRequestById**` /
   `**getSignResultById**`).

---

## Other API capabilities (agent)

Per **`$MPA_PATH/references/instructions.md`**, the agent may also: **`/keyGenRequest`**,
**`/keyGenRequestAgree`**, **`/addKnownAddress`**, **`/postChainDetails`**, **`/addToken`**,
health/version discovery, and **fee/credit** checks via **`GET /getGlobalNonceByKeyGenId`**
(and top-up gas as needed). For **on-chain** fee state on **Linea mainnet**, use the
subsection below.

---

## Fee payment (Linea mainnet, chainId 59144)

ContinuumDAO’s **fee / registration** contract on **Linea** is deployed at a fixed
address. Agents should use **Foundry `cast`** against that contract with an RPC URL
taken from the node’s chain config (same pattern as other on-chain checks).

**Fee contract (Linea mainnet):** `0x55aD6Df6d8f8824486C3fd3373f1CF29eCecF0A3`

**On-chain `register()` from the MPC wallet (multiSignRequest):** use the
`**linea_register.py`** recipe in
`**$MPA_PATH/references/AI_AGENT_COMPOSE_MULTISIGNREQUEST.md**` (recipes table)
(Linea `**59144**`, `**register()**`, RPC from `**getChainDetails**`). **Fee-token
top-up (`deposit`)** from the MPC wallet: `**linea_fee_deposit.py`** in the same
table; the MPC must **approve** the fee contract for the ERC20 fee token before
`**deposit`** succeeds. For **approve + deposit** in a **single** batch
`**multiSignRequest`**, use `**forge/script/LineaFeeApproveDeposit.s.sol**` →
`**generateSignRequestWithFoundryScript.py**` (see
`**$MPA_PATH/references/AI_AGENT_FORGE_SIGNREQUEST.md**` § Linea fee). For read-only
`**cast**` checks below, any RPC URL from the node’s chain config is fine.

**Variables:** Set `**KEYGEN_ID`** to your KeyGen result id (see **Environment**).
Set `**WALLET_ADDRESS`** to the MPC wallet **Ethereum address** for that KeyGen
(from `**GET /getKeyGenResultById`** / `**ethereumaddress**`). Use your management
API base URL as `**$MPC_AUTH_URL:$MANAGEMENT_PORT**`.

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

**Note:** `**globalnonce`** here is the KeyGen’s MPC signing counter from the API. It
is **not** the EVM account nonce from `**cast nonce`**. **Fee payment / top-up** can
be sent as ordinary EVM transactions **from any funded wallet**—they do **not**
require the `**multiSignRequest`** / threshold flow. Paying from a separate hot
wallet or custodian is often more convenient than routing top-ups through the MPC
wallet. If you do spend **from the MPC address** itself, those txs still go through
`**multiSignRequest`** as usual. For ABI-level details of the fee contract, see
`**$MPA_PATH/references/API_IMPLEMENTATION.md**`
and on-chain docs your deployment publishes.

---

## Incoming MPC sign requests (policy)

When another member requests a signature, default decision inputs:

- Group **messages** and the request `**Purpose**`.
- Independent analysis from available node messages, API state, and on-chain data.
- Owner instructions left for the agent.
- If uncertain, **message the owner** on the dedicated messaging API
`**POST /sendMessage**` awaiting guidance.

Remember: **threshold+1** accepts are required to generate the MPC signature.

---

## Management API authentication (Ed25519)

- Every `**POST**` to the management API requires a **management** signature
(Ed25519 or Ethereum `**NodeMgtKey**` per node config).
- `**clientSig**` on `**multiSignRequest**` signs `**messageToSign**` with the
**management** key—not the MPC key.
- `**GET /getPublicMgtKeyNonce**` vs `**GET /getNodeMgtKeyNonce**`,
`**GET /getAllowedEd25519MgtKeys**`, `**sign-clipboard**` (`**--inline**` /
`**--inline-file**`), and `**tools/ed25519_private_to_pubkey_hex.py**`:
`**$MPA_PATH/references/ED25519_MANAGEMENT_KEY_SIGNING.md`** (see **§7** *Raw 32-byte
seed vs key file* for **`MPC_MGT_ED25519_SEED_HEX`** / recipe **`--ed25519-seed-hex`**
vs **`--ed25519-key-file`**).

---

## Creating `multiSignRequest` payloads

**Skim:** **Foundry** → **`$MPA_PATH/references/AI_AGENT_FORGE_SIGNREQUEST.md`**.
**Compose JSON** → **`$MPA_PATH/references/AI_AGENT_COMPOSE_MULTISIGNREQUEST.md`**.
Prefer **Recipes** below (`linea_register`, `linea_fee_deposit`, `erc20_transfer`,
…) before hand-writing compose JSON.

**Do not** invent or hand-edit **`multiSignRequest`** JSON from scratch. **Only** use
**`$MPA_PATH/scripts/generateMultiSignRequestFromCompose.py`**,
**`$MPA_PATH/scripts/generateSignRequestWithFoundryScript.py`**, or a script under
**`$MPA_PATH/recipes/`** (see **`$MPA_PATH/references/AI_AGENT_COMPOSE_MULTISIGNREQUEST.md`**
and **`$MPA_PATH/references/AI_AGENT_FORGE_SIGNREQUEST.md`** for **`forge script`**
inputs to the Foundry helper). **Typical flow:** one helper run → add **`clientSig`**
/ **`signedMessage`** → **`POST /multiSignRequest`** (no **`multiSignJoin`**). **When**
you need **two** helper outputs in **one** proposal, merge with **`multiSignJoin.py`**;
**repeat** **`multiSignJoin.py`** using prior stdout as an input file to build longer
sequences (same chain, **`--first-nonce`** = first tx nonce in the final
batch—typically **`cast nonce`** on the MPC address). **After** any helper or
**`multiSignJoin`** run prints **`bodyForSign`** / **`messageToSign`**, add
**`clientSig`** (and **`signedMessage`** if required) per
**`ED25519_MANAGEMENT_KEY_SIGNING.md`**, then **`POST /multiSignRequest`** with **that**
JSON—the agent **may** call this endpoint; the restriction is **never** submitting a
payload the tools did not produce.

That reference doc has **`messageToSign`** / **`signedMessage`** / **`postBody`**
rules, **`multiSignJoin`** usage, and the **recipes** table.

---

## Scripts

**Location:** Python scripts for API automation under **`$MPA_PATH/scripts/`**.
**Dependencies:** (**Python dependencies** above —
**`$MPA_PATH/.venv/bin/pip install eth-account`**, then **`PyNaCl`** for
compose/recipes). **`eth_account`** is required for all of the following.

- **`generateSignRequestWithFoundryScript.py`** — Forge broadcast JSON →
  **`multiSignRequest`** JSON. Use when the user needs Foundry script logic for
  complex flows.

- **`generateMultiSignRequestFromCompose.py`** — Compose JSON (one or batch calls)
  → **`multiSignRequest`** body / **`messageToSign`**. Requires **`PyNaCl`**.

- **`multiSignJoin.py`** — Join **two** helper JSON files → **one** batch
  **`multiSignRequest`** output. **Chaining:** reuse stdout as **`--a`** or **`--b`**
  with another helper. **`--first-nonce`** = nonce of the **first** tx in the merge.
  Valid after **`clientSig`**. See **`$MPA_PATH/references/AI_AGENT_COMPOSE_MULTISIGNREQUEST.md`**.

- **`executeSignResult.py`** — **Only** EVM path for **AI agents**: **`POST`**s
  **`/triggerSignRequestById`** when needed, polls **`getSignResultById`**, then
  broadcasts like web **Execute**. **Single-tx:** **`getSignRequestById?tx_params=1`**
  + chain/RPC; **batch:** **`messageRawBatch`** + **`batchsignatures`**. Sequential
  by default; **`--fast`** for parallel confirm.

- **`keygen_messaging_agent_poll.py`** — Underlying KeyGen **`@agent`** poll (debug
  or tests). Prefer **`mpc_event_listener.py`** **`--keygen-messages`** for
  scheduled runs.

- **`mpc_event_listener.py`** — **Preferred** cron entry: **`--keygen-messages`**
  (inbox), optional **`--sign-ready`** → **`executeSignResult.py`** per ready id.

- **`mpc_cron_schedules.py`** — Maps poll periods (1–60 min, 2–24 h) to Open Claw
  **`--every`** and crontab.

## Recipes

**Location:** **`$MPA_PATH/recipes/`** — thin CLIs around
**`generateMultiSignRequestFromCompose.py`** (same venv deps as compose). Check
here before hand-writing compose JSON; common operations are covered.

**Per-script behavior, the recipes table, and examples:**
**`$MPA_PATH/references/AI_AGENT_COMPOSE_MULTISIGNREQUEST.md`**.

## References (bundled snapshots)

**Location:** API specs and agent notes under **`$MPA_PATH/references`**.

- **`$MPC_CONFIG_PATH/docs/CONFIGURING_ED25519_KEYS.md`** (or **`$MPA_PATH/docs/...`**
  if **`docs/`** is symlinked) — Node owner: **`PublicMgtKey`**, add keys, store
  agent private keys.

- **`$MPA_PATH/references/instructions.md`** — Human-oriented full workflow.

- **`$MPA_PATH/references/ED25519_MANAGEMENT_KEY_SIGNING.md`** — Ed25519 management
  signing: allow-list, nonces, tools, KeyGen **`ClientKeys`**.

- **`$MPA_PATH/references/AI_AGENT_FORGE_SIGNREQUEST.md`** — Foundry → helper →
  **`multiSignRequest`**; **`clientSig`** rules.

- **`$MPA_PATH/references/AI_AGENT_COMPOSE_MULTISIGNREQUEST.md`** — Compose JSON →
  **`multiSignRequest`**; **`generateMultiSignRequestFromCompose.py`**.

- **`$MPA_PATH/references/AI_AGENT_NEW_SESSION.md`** — `.env`, symlinks,
  **`GET /health`**, **`KEYGEN_ID`** / KeyGen creation.

- **`$MPA_PATH/references/API_IMPLEMENTATION.md`** — Canonical REST API (endpoints,
  auth, bodies).

- **`$MPA_PATH/references/swagger.yaml`** — OpenAPI/Swagger for tooling.

- **`$MPA_PATH/references/TOKEN_STORAGE_SCHEMA.md`** — Local token config (**ERC20**,
  **CTMERC20** **`c3transfer`**, **CTMRWA1**, etc.).

- **`$MPA_PATH/references/API_KEYGEN_MESSAGING.md`** — Inter-node messaging API.

- **`$MPA_PATH/references/KNOWN_ADDRESSES_SCHEMA.md`** — Local address book (EOA and
  contract).

- **`$MPA_PATH/references/README.md`** — Index of references.


## Tools

**Location:** `**$MPA_PATH/tools`** — includes `**sign-clipboard**` (management
`**POST**` signing), `**ed25519_private_to_pubkey_hex.py**`, and
`**check_ed25519_mgt_keygen.py**` (debug allow-list + **`ClientKeys`** vs a seed or key file).
Usage and `**--inline**` / `**--inline-file**`:
`**$MPA_PATH/references/ED25519_MANAGEMENT_KEY_SIGNING.md**`
§ Tools; `**sign-clipboard/README.md**` for flags.

---

## Style notes for agents

- **`POST /multiSignRequest`:** use **only** JSON from
  **`generateMultiSignRequestFromCompose.py`**, **`generateSignRequestWithFoundryScript.py`**,
  **`recipes/`**, or **`multiSignJoin.py`** (including **chained** **`multiSignJoin`**
  runs whose inputs are prior helper or join output files)—never improvise the payload.
- Prefer **exact** JSON bodies and canonical signing strings as described in
  **API_IMPLEMENTATION**.
- Lookup REST API endpoints in **`swagger.yaml`** first; use **API_IMPLEMENTATION**
  only when you need more detail.
- Use **`Thoughts`** and **`Purpose`** as durable audit and coordination context
  across nodes.
- Use **API_KEYGEN_MESSAGING** so group members stay informed.

