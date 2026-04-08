# Overview

This document contains instructions for an agent such as OpenClaw to manage an MPA wallet client on a node.

A Multi-Party Agent wallet is a single wallet address (Ethereum address only for now) that has a public key but whose private key can only be generated collectively by a Group of nodes (usually run on VPSs) using Multi Party Computation (MPC). Together the nodes can generate an MPC signature using some of the nodes (in fact at least threshold+1 nodes). The "threshold" is a parameter defined when the MPC address (or KeyGen) was created. No single node can ever sign a transaction message, This can only be accomplished via cooperation between nodes. In this way the wallet address is protected. Typically some of the nodes will be run by humans and one or more will be run by an AI Agent, such as Open Claw.

The MPC Ethereum address can be used on any EVM blockchain. It is not limited by any smart contract.

The purpose of the AI Agent is to take input instructions via a discussion using the MPA wallets group messaging system (preferred), or its attached communication channel (e.g. Telegram) from its nodes and to generate strategies and ultimately suggest forge scripts (https://www.getfoundry.sh/introduction/getting-started) that when run, produce one or more transactions to be jointly signed by threshold+1 nodes.

### What **`POST /multiSignRequest`** is (read this first)

A **multiSignRequest** is a **formal proposal** stored on every node in the KeyGen: it describes **one or more EVM transactions** the shared MPC wallet would execute (calldata, chain id, nonces, fee fields, etc.). It is **not** an MPC signature yet—nodes must **agree** first. After enough nodes accept (**threshold+1**), an authorized node can **`POST /triggerSignRequestById`** to run the MPC signing protocol and obtain signatures to broadcast on-chain.

- **`Purpose`** (string, **max 256 characters**): A short, human-readable summary for **other nodes** (and future you) explaining *why* this proposal exists—e.g. “Swap 1 ETH to USDC on Uniswap v3 then approve router.” Empty or vague Purposes make review harder; treat it as required discipline.
- **Batch:** More than one transaction in the **same** proposal is a **batch** sign request; each tx gets its own MPC signature when triggered.
- **Management vs MPC:** Submitting **`/multiSignRequest`** uses the **management** key (`clientSig`, etc.) to authenticate **your node’s HTTP API**. The **MPC** signature is produced only **after** agreement and **`/triggerSignRequestById`**. Do not confuse the two (see note under “Functions of the Open Claw run AI Agent nodes” below).

**Deep references (this repo):** step-by-step payloads, CLI, and signing—**[AI_AGENT_COMPOSE_MULTISIGNREQUEST.md](./AI_AGENT_COMPOSE_MULTISIGNREQUEST.md)** (compose JSON → script → POST), **[AI_AGENT_FORGE_SIGNREQUEST.md](./AI_AGENT_FORGE_SIGNREQUEST.md)** (Foundry `run-latest.json` → POST), **[API_IMPLEMENTATION.md](./API_IMPLEMENTATION.md)** (all endpoints). Co-located agents: management API is usually **`http://localhost:8080`** (or **`ManagementAPIsPort`** in `configs.yaml`); scripts need **`KEYGEN_ID`**, **`AUTH_KEY_PATH`**, and Python deps as described in those guides.

This is a typical sequence of actions that the nodes go through —

(1) A human run node sends a message to the Group using the API method POST /sendMessage asking for something to be done, which will require some transactions from the MPC wallet.

(2) The other nodes read the messages using /getMessageThread and respond with their considered opinions replying to the original message. This can include the AI agent run node(s) opinions, which may access the internet in its research.

(3) The AI Agent prepares **one** multiSignRequest proposal using **either** path below (not both for the same proposal). It must set **`Purpose`** in the API body (or pass **`purpose`** into the compose script so it lands in the body).

    - **Path A — Foundry:** Write or obtain a Foundry script; run **`forge script … --sender <MPC Ethereum address>`** so **`broadcast/.../run-latest.json`** exists; run **`scripts/generateSignRequestWithFoundryScript.py`** on that file to build the **`POST /multiSignRequest`** body. **Guide:** [AI_AGENT_FORGE_SIGNREQUEST.md](./AI_AGENT_FORGE_SIGNREQUEST.md).
    - **Path B — Compose JSON (no Foundry run on the agent machine):** Build a compose JSON object (function **`signature`**, **`destinationContract`**, **`inputs`**, **`keyGenId`**, **`destinationChainId`**, optional **`rpcGateway`** or rely on **`GET /getChainDetails?chain_id=…`**); run **`scripts/generateMultiSignRequestFromCompose.py`**; add management signing; **POST /multiSignRequest**. **Guide:** [AI_AGENT_COMPOSE_MULTISIGNREQUEST.md](./AI_AGENT_COMPOSE_MULTISIGNREQUEST.md).

(4) For Path A, the Solidity script would ideally live in a **Git repository** the other nodes can review. The AI Agent may run another **`/sendMessage`** round for approval, or proceed if group context is already clear. **`forge script <Contract>.s.sol:<Function> --rpc-url <RPC_URL> --sender <MPC address>`** produces **`run-latest.json`** under **`broadcast/`**; feed that path into **`generateSignRequestWithFoundryScript.py`**.

(5) For Path B, the compose JSON may include **one or more** actions in **`composeActions`** (batch). Omit **`rpcGateway`** to pull RPC and gas hints from **`GET /getChainDetails`** for that chain; or supply explicit RPC and gas fields per the guide. The script outputs JSON ready to complete with **`clientSig`** (and related management-auth fields) before **POST /multiSignRequest**.

(6) **POST /multiSignRequest** (authenticated with the **management** key) registers the proposal on the network. Every node in the KeyGen can list and inspect it. **Batch** = multiple transactions in one proposal. **`Purpose`** (≤256 chars) must summarize intent for reviewers. **Note:** **`POST /signRequest`** is a **different** flow (relayer / tx-check keys); for standard multi-agree MPC wallets use **`/multiSignRequest`** only.

(7) Each node can now see the multiSignRequest and decide if it wishes to accept or reject the sign request. Each one may POST /signRequestAgree, accepting or rejecting the proposal. In each node's responses, they may add a text message called 'Thoughts' that can be used to guide the AI Agent, so that even if enough nodes accept the multiSignRequest, the AI Agent may decide to Shelve the current proposal (POST /shelveSignRequest) and re-issue it, or abandon it. If the multiSignRequest has at least threshold+1 responses that Accept the proposal (/isSignRequestReadyById is read to trigger) and the AI Agent wishes to proceed, then it can POST /triggerSignRequestById which initiates the MPC node network to collectively create the MPC signatures (one per transaction). Once the signatures have been generated (/getSignResultById has a signature), then the AI Agent should, having checked that it has enough gas to do so, broadcast the transaction(s) to the blockchain and update the status of the sign request (POST /updateSignResultStatusById).

(8) The AI Agent should then post a message to the Group updating the nodes about what it has done, what to expect, or what the outcome was. This may require on-going messages as the situation evolves.

(9) Whenever the AI Agent is asked to generate an idea to spend funds from the MPC wallet, it should examine the stored context information on its node (identical to the information on all the nodes in the Group). This information is stored in the messages (GET /listMessages and GET /getMessageThread or GET /getMessageById), as well as the 'Purpose' and 'Thoughts' messages stored in each sign result (GET /listSignResults and GET /getSignRequestById). 

The nodes' context increases with time, being added to their databases and supplemented with the AI Agents research and the human responses to it and this permananent storage should evolve over time to allow better decisions to result. This will occur no matter which AI Agents are used, or what LLMs are connected to the Open Claw.



## Functions of the Open Claw run AI Agent nodes

The primary purpose of the Open Claw run node in the MPA wallet Group is to control a single blockchain account (such as an EVM address, but on all blockchains), and sign MPC (Multi Party Computation) transactions with that account. In this regard, it is no different from any other node, which could be run by humans or other AI Agents.

There is a rich Restful API that is at the disposal of the AI Agent run node. Here is a list of other things that the AI Agent may do

(1) Generate new MPC Ethereum addresses (a KeyGen) with their own Group of nodes and their own threshold (/keyGenRequest)

(2) Agree to join a new KeyGen, which is a new MPC controlled wallet address (/keyGenRequestAgree)

(3) Send messages to the KeyGen Group whenever it wants to (/sendMessage)

(4) Manage a list of Known Addresses that are significant to itself, being Externally Owned Addresses, or contract addresses and which are stored only on its own node (POST /addKnownAddress, GET /getKnownAddresses)

(5) Manage the way it interacts with each EVM blockchain. This allows the preferred RPC gateway to be stored in the node database, whether this chain is an EIP 1559 chain or legacy, the gas parameters to be used (or left to be determined at run time). The API commands are POST /postChainDetails and GET /getChainDetails

(6) Store a list of assets on each blockchain that are important for the MPC wallet of the KeyGen (POST /addToken and GET /getTokens). The result of /getTokens includes some commonly used function descriptions such as transfer that can be used when creating the multiSignRequest described above.

(7) Discover information about the node hardware and software environment and that of the other nodes in the Group. This includes health and connectivity, capability (e.g. disk space, RAM, CPU cores) and MPA wallet software version.

(8) Ensure that the KeyGen MPC wallet address it is part of has sufficient credit to pay for signatures and top up as required. The AI Agent can discover how many signatures it has left at any time by doing GET /getGlobalNonceByKeyGenId which returns the number of signatures left on all blockchains. Also the agent can top up the MPC wallet address with gas on the chain ID that it wishes to operate on. The AI Agent should always make sure that it has enough credit and gas to cover its actions.


Note: there are two types of signature referenced in this document, not to be confused with one another:

- Management Signature: This is a signature made by each client using (a) private key(s) unique to them. The public key(s) are stored in the `mpc-config/configs.yaml` file, and there must be at least one. The management signature is used by each client (be it an agent managed node or a user managed node) to authenticate communications and configuration changes made by/to the individual client. It is also required by the client to interact with its API using all POST requests.
- MPC Signature: This is a signature formed by a threshold number of nodes in a Group for a given KeyGen. There is no private key, and client nodes must accept the MPC signature request according to the threshold in order for the signature to be performed.


All of the controls specified hereof are accessible via an API on each client. All actions are authenticated by a management key that each client has stored on their node, unique to them. For agents running on a node, this is a locally stored ed25519 keypair (PublicMgtKey - see environment below for the location of the key). For users who manage their node via the frontend application, this is usually a MetaMask signature (NodeMgtKey in the config file) - this is out of scope for the following instructions, which are for agents that users have deployed on their nodes to manage the client for them.

## Environment

The agent is run in an environment with the following variables configured:

### KEYGEN_ID

If the user's node is already a part of a Group which has already created a KeyGen that should be used for signing, then the user may specify that KeyGen ID in this environment variable. This is the KeyGen that should be used for signing and nullifies the requirement to request another KeyGen ID, unless instructed to do so by the node owner. In the case that this environmental variable is undefined, or if there is ambiguity as to which KeyGen ID to use, then ask the user via their established communications channel on gateway port 18789.

### AUTH_KEY_PATH

The agent uses an ed25519 key to authenticate API interactions. This key is stored somewhere on the node (local to the agent). By default, it is `~/.ssh/mpc_auth_ed25519`, but may also be specified by the node owner via this environmental variable.

## Groups

A Group can be created collectively by any individual nodes. It is created when:

1. Each of the nodes add each others' hosts (IP address) to their configuration (Configured Nodes).
2. One of the nodes initiates a Group request with all OR a subset of the nodes in its configuration.
3. All of the nodes who were requested accept the Group request.

At this point, a Group is formed with a unique Group ID. After a Group is created, KeyGen requests can be made up of all or a subset of the nodes in that particular Group.

## KeyGen

A KeyGen can be created by individual nodes that are in a common Group. It is created when:

1. A member of a given Group (can be anyone in the Group) initiates a KeyGen request with all nodes in that Group.
2. All of the nodes in the Group accept the KeyGen request.

At this point, a KeyGen is generated. This allows either EVM or non-EVM key generation. Once all nodes that were requested to form the key accept, a calculation is performed between the nodes and after some time the key is generated. This yields a public key. In the case of secp256k1, this would be an Ethereum 20-byte address. In the case of ed25519, this would be a non-EVM address such as NEAR or Solana - the same key works on multiple blockchains. At this point, the generated wallet/public key can be used to sign transactions that can be broadcast on chain.

## Signing

Once generated, the KeyGen can be funded for its intended blockchain by one of the users, or anyone who has the KeyGen's address. At this point it is ready to request MPC signatures that, if successful, may be broadcast as transactions on its intended blockchain. Any of the nodes that are members of that KeyGen can propose transactions by making a sign request. This request is communicated to other nodes in that KeyGen and they can then evaluate the sign request, and subsequently accept or reject the MPC signature. Individual nodes may accept or reject the MPC signature request - this is up to them. If threshold is reached (threshold + 1 nodes agree to the request), then an MPC signature can be generated by the originator node, and following this, the originator of the MPC signature request may also broadcast it on chain.

## Incoming Requests

If a node whose client is managed by an agent is a part of a Group with an established KeyGen, and another Group member requests an MPC signature for some data, then the agent must decide what to do. This depends on what the individual who set up the agent to manage their node has instructed them to do, but by default the agent should make their choice based on:

- What the other Group members have stated in the messages channel; including the 'Purpose' field specified by the originator of the MPC signature request,
- Independently conducted research online as to whether the MPC signature is a 'good idea',
- Examine the context or other inputs left to the agent by the node owner, who may have instructed the agent what to do when an MPC signature is requested by a Group,
- If uncertain, the agent should message the node owner over an established channel on the gateway (Telegram, WhatsApp, whatever the owner has configured on OpenClaw's port 18789).
Once a decision is made, the agent may decide to accept or reject the MPC signature request. Keep in mind that in order for the MPC signature to be generated, it must reach threshold plus one. That means that one more node must accept than the number configured for the 'threshold' of that particular KeyGen. This number was determined by the Group member who initially proposed the creation of the KeyGen to the rest of the Group.


