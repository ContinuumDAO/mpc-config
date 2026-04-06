# Overview

This document contains instructions for an agent such as OpenClaw to manage an MPA wallet client on a node.

Note: there are two types of signature referenced in this document, not to be confused with one another:

- Management Signature: This is a signature made by each client using (a) private key(s) unique to them. The public key(s) are stored in the `mpc-config/configs.yaml` file, and there must be at least one. The management signature is used by each client (be it an agent managed node or a user managed node) to authenticate communications and configuration changes made by/to the individual client. It is also required by the client to interact with its API.
- MPC Signature: This is a signature formed by a threshold number of nodes in a Group for a given KeyGen. There is no private key, and client nodes must accept the MPC signature request according to the threshold in order for the signature to be performed.

The purpose of the client is to join Groups with other nodes, generate keys (KeyGen) that control a single blockchain account (such as an EVM address), and sign MPC (Multi-Party Control) transactions with that account. MPC signatures for this account can only be controlled by a threshold number of the nodes that control that KeyGen to accept the MPC signature, at which point it may be broadcast on-chain. The basis for the MPC signature generation is Multi Party Computation (MPC), which means there is no private key for the controlled account.

All of the controls specified hereof are accessible via an API on each client. All actions are authenticated by a management key that each client has stored on their node, unique to them. For agents running on a node, this is a locally stored ed25519 keypair (see environment below for the location of the key). For users who manage their node via the frontend application, this is usually a MetaMask signature - this is out of scope for the following instructions, which are for agents that users have deployed on their nodes to manage the client for them.

## Environment

The agent is run in an environment with the following variables configured:

### KEYGEN_ID

If the user's node is already a part of a Group which has already created a KeyGen that should be used for signing, then the user may specify that KeyGen ID in this environment variable. This is the KeyGen that should be used for signing and nullifies the requirement to request another KeyGen ID, unless instructed to do so by the node owner. In the case that this environmental variable is undefined, or if there is ambiguity as to which KeyGen ID to use, then ask the user via their established communications channel on gateway port 18789.

### AUTH_KEY_PATH

The agent uses an ed25519 key to authenticate API interactions. This key is stored somewhere on the node (local to the agent). By default, it is `~/.ssh/mpc_auth_ed25519`, but may also be specified by the node owner via this environmental variable.

## Groups

A Group can be created by and of individual nodes. It is created when:

1. Each of the nodes add each others' hosts (IP address) to their configuration.
2. One of the nodes initiates a Group request with all OR a subset of the nodes in its configuration.
3. All of the nodes who were requested accept the Group request.

At this point, a Group is formed with a unique Group ID. After a Group is created, KeyGen requests can be made up of all or a subset of the nodes in that particular Group.

## KeyGen

A KeyGen can be created by individual nodes that are in a common Group. It is created when:

1. A member of a given Group (can be anyone in the Group) initiates a KeyGen request with all nodes in that Group.
2. All of the nodes in the Group accept the KeyGen request.

At this point, a KeyGen is generated. This allows either EVM or non-EVM key generation. Once all nodes that were requested to form the key accept, a calculation is performed between the nodes and after some time the key is generated. This yields a public key. In the case of secp256k1, this would be an Ethereum 20-byte address. In the case of ed25519, this would be a non-EVM address such as NEAR or Solana - the same key works on multiple blockchains. At this point, the generated wallet/public key can be used to sign transactions that can be broadcast on chain.

## Signing

Once generated, the KeyGen can be funded for its intended blockchain by one of the users, or anyone who has the KeyGen's address. At this point it is ready to request MPC signatures that, if successful, may be broadcast as transactions on its intended blockchain. Any of the nodes that are members of that KeyGen can propose transactions by making a sign request. This request is communicated to other nodes in that KeyGen and they can then evaluate the sign request, and subsequently accept or reject the MPC signature. Individual nodes may accept or reject the MPC signature request - this is up to them. If threshold is reached (threshold + 1 nodes agree to the request), then an MPC signature can be generated, and following this, the originator of the MPC signature request may broadcast it on chain.

## Incoming Requests

If a node whose client is managed by an agent is a part of a Group with an established KeyGen, and another Group member requests an MPC signature for some data, then the agent must decide what to do. This depends on what the individual who set up the agent to manage their node has instructed them to do, but by default the agent should make their choice based on:

- What the other Group members have stated in the messages channel; including the 'reason' field specified by the originator of the MPC signature request,
- Independently conducted research online as to whether the MPC signature is a 'good idea',
- Examine the context or other inputs left to the agent by the node owner, who may have instructed the agent what to do when an MPC signature is requested by a Group,
- If uncertain, the agent should message the node owner over an established channel on the gateway (Telegram, WhatsApp, whatever the owner has configured on OpenClaw's port 18789).
Once a decision is made, the agent may decide to accept or reject the MPC signature request. Keep in mind that in order for the MPC signature to be generated, it must reach threshold plus one. That means that one more node must accept than the number configured for the 'threshold' of that particular KeyGen. This number was determined by the Group member who initially proposed the creation of the KeyGen to the rest of the Group.

## Agent Key Management

To perform any of the actions listed in this document, including API interaction or node configuration, the agent must prove that it has the right to make decisions on behalf of the node. This is done by a management signature for each of these actions. Agents can sign actions (API calls) using a validated ed25519 key. This key was originally created by the node owner and stored somewhere local to the agent (see environment: AUTH_KEY_PATH above). This private key is accessible by the agent and can be used for signing API requests that require a management signature.
