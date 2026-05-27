# API Implementation Documentation

## Overview

The Distributed Auth Management API provides a RESTful interface for managing MPC (Multi-Party Computation) nodes, key generation, signing operations, and system monitoring. The API is implemented using the Gin web framework and follows a consistent response format.

**CGGMP24 / FROST (givre) / Rust:** For **`ecdsaMpcProtocol`** on **`POST /keyGenRequest`**, **`GET /version`** (`cggmp24UpstreamGitRev`, **`givreUpstreamGitRev`**), FROST **ed25519** / **bitcoin-taproot** keygen/sign/presign, **`POST /keyGenEjectRequest`** (secp256k1 CGGMP24, FROST **ed25519**, FROST **bitcoin-taproot**), and export routes **`POST /getEthereumPrivateKey`**, **`POST /getBitcoinPrivateKey`**, **`POST /getEd25519PrivateKey`**, **`POST /getTaprootPrivateKey`**, and optional **`-tags rust`** builds, see **[`CGGMP24_AND_RUST_BUILD.md`](./CGGMP24_AND_RUST_BUILD.md)** and sibling repo **mpc-auth** `docs-internal/FROST_ROADMAP.md`.

## Architecture

### Base URL
- Management port: `ManagementAPIsPort` in `configs.yaml` (export as `MANAGEMENT_PORT`)
- Base path: `/`
- Swagger UI: `/swagger/index.html` (if docs are enabled)
- Environment form for automation: `"$MPC_AUTH_URL:$MANAGEMENT_PORT"` where `MPC_AUTH_URL` is host-only (for example `http://127.0.0.1` or `http://<IP>`) and `MANAGEMENT_PORT` is numeric.
- Many curl examples below use `$MPC_AUTH_URL:$MANAGEMENT_PORT` as a placeholder; replace with `"$MPC_AUTH_URL:$MANAGEMENT_PORT"` in real deployments.

<a id="public-discovery-http"></a>
### Public discovery HTTP
If **`PublicDiscoveryPort`** is set in `configs.yaml` (env `PublicDiscoveryPort`) **and** it differs from **`ManagementAPIsPort`**, the node starts an additional HTTP listener on that port with a **minimal** surface (no full management API): **`GET /getNodeMgtKey`**, **`GET /getPublicMgtKey`**, **`GET /getAllowedEd25519MgtKeys`**, **`GET /getPreferredSigner`**, **`GET /getPreferredKeyGen`**, **`GET /health`** (no JWT on this listener). This lets operators expose only discovery to the internet (e.g. port **18080**) while keeping **`$MANAGEMENT_PORT`** private. When **`PublicDiscoveryPort`** equals **`ManagementAPIsPort`**, a single listener serves the full API; **`GET /getPublicMgtKey`** is still available on that port.

**`GET /getNodeMgtKey`** returns the configured **`NodeMgtKey`** (Ethereum management address from `configs.yaml` / env) as a JSON string in **`data`**. No authentication on this listener; use it with **`GET /getNodeMgtKeyNonce`** for Ethereum wallet management signing (`personal_sign`).

**`GET /getPublicMgtKey`** returns the same Ed25519 public keys as the allow-list for management auth (config **`PublicMgtKey`** plus keys from **`POST /addManagementKey`**), as a JSON array of 64-hex strings (no labels). Issuers and apps can learn the public keys without reading `configs.yaml` or static Railway env maps.

### Response Format

All endpoints return a standardized `APIResponse` structure:

```json
{
  "code": 0,        // 0 = success, 1 = error
  "error": "",      // Error message (empty if success)
  "data": {}        // Response data (varies by endpoint)
}
```

<a id="effective-ecdsa-mpc-protocol"></a>
### `effectiveEcdsaMpcProtocol` (read-only)

Keygen and sign **GET** responses include **`effectiveEcdsaMpcProtocol`** when the implementation can classify the key’s secp256k1 MPC stack:

- **`"cggmp24"`** for **secp256k1** (default for new keys; omit `ecdsaMpcProtocol` or set `"cggmp24"` at keygen).
- **`"gg18"`** only for **legacy Mongo rows** created before GG18 removal — new keygen rejects `"gg18"`; signing/presign on legacy keys fail closed (mandatory re-key).

**Omitted or empty** for **ed25519**, **bitcoin-taproot**, and other non-ECDSA key types.

Schnorr keys also expose **`effectiveSchnorrMpcProtocol`**: **`"givre"`** for **ed25519** and **bitcoin-taproot** (Lockness FROST). Empty for secp256k1.

This field is **computed for JSON only** (not stored as its own MongoDB column). The keygen request body may still carry **`ecdsaMpcProtocol`** as sent at **`POST /keyGenRequest`**; use **`effectiveEcdsaMpcProtocol`** / **`effectiveSchnorrMpcProtocol`** in clients when branching on which MPC runtime applies.

**Where it appears:** [`GET /listKeyGenRequests`](#get-listkeygenrequests), [`GET /getKeyGenRequestById`](#get-getkeygenrequestbyid), [`GET /getKeyGenResultById`](#get-getkeygenresultbyid), **`GET /getGlobalNonceByKeyGenId`** (inside **`data`**), **`GET /listSignRequests`**, **`GET /getSignRequestById`**, **`GET /listSignRequestsReady`**, **`GET /getSignResultById`**, **`GET /listSignResults`**.

<a id="key-eject-export-endpoints"></a>
For **ejected** keys ([`POST /keyGenEjectRequest`](#post-keygenejectrequest)), [`GET /getKeyGenResultById`](#get-getkeygenresultbyid) still returns public metadata, **`status`**: **`ejected`**, persisted **`keygenresultstatus`**: **`ejected`**, and **`ejectedat`** when present; MPC share material (**`savedata`**, and for secp256k1 **`cggmp24aux`**) is cleared on nodes that finalized. The raw scalar is not returned on this GET — use the key-type-specific export POST for a node that stored the export blob:

| Key type | Export endpoint |
|----------|-----------------|
| **`secp256k1`** (CGGMP24) | [`POST /getEthereumPrivateKey`](#post-getethereumprivatekey), [`POST /getBitcoinPrivateKey`](#post-getbitcoinprivatekey) |
| **`ed25519`** (FROST/givre) | [`POST /getEd25519PrivateKey`](#post-geted25519privatekey) |
| **`bitcoin-taproot`** (FROST/givre) | [`POST /getTaprootPrivateKey`](#post-gettaprootprivatekey) |

On [`GET /listKeyGenRequests`](#get-listkeygenrequests) / [`GET /getKeyGenRequestById`](#get-getkeygenrequestbyid), the request row’s effective **`status`** is also **`ejected`** when the result row is tombstoned; use **`filter=ejected`** to list those requests.

<a id="bitcoin-p2wpkh-mainnet-address"></a>
### Bitcoin P2WPKH derived addresses (`bitcoinp2wpkhmainnet`, `bitcoinp2wpkhtestnet`, `bitcoinp2wpkhsignet`) (read-only)

For **secp256k1** keygen results whose **`pubkeyhex`** is present, [`GET /getKeyGenResultById`](#get-getkeygenresultbyid) and each **`keyGens[]`** element from **`GET /getAllGroupIds`** include these fields when derivable. All three are native **SegWit v0** (**P2WPKH**) **Bech32** encodings computed from the same uncompressed **x‖y `pubkeyhex`** as **`ethereumaddress`**, using **`chaincfg`** from **btcd** (mainnet, **TestNet3**, **SigNet**). They are persisted on the keygen result document when pubkey material is saved; [`GET /getKeyGenResultById`](#get-getkeygenresultbyid) and **`GET /getAllGroupIds`** **recompute** them so legacy rows without these columns still return consistent values.

| JSON field | Network | Typical prefix |
|-----------|---------|----------------|
| **`bitcoinp2wpkhmainnet`** | Bitcoin mainnet | **`bc1q…`** |
| **`bitcoinp2wpkhtestnet`** | Bitcoin TestNet3 | **`tb1…`** |
| **`bitcoinp2wpkhsignet`** | Bitcoin Signet | **`tb1…`** in this stack (SigNet witness HRP **`tb`** in **btcd** — for a given pubkey the string often **matches** **`bitcoinp2wpkhtestnet`** exactly; discriminate by context / params, not by Bech32 HRP alone) |

Regtest is **not** exposed as a dedicated API field. **Low-`s`** normalization for ECDSA completions follows the node’s Bitcoin compatibility layer so encodings remain spendable where low-`s` is required.

<a id="ed25519-derived-addresses"></a>
### ed25519 derived addresses (`solanaaddress`, `sorobanaddress`, `nearaddress`, `tonaddress`, `suiaddress`) (read-only)

For **`ed25519`** FROST keygen results, [`GET /getKeyGenResultById`](#get-getkeygenresultbyid) and **`GET /getAllGroupIds`** `keyGens[]` may include:

| JSON field | Chain | Format |
|-----------|--------|--------|
| **`solanaaddress`** | Solana | Base58-encoded 32-byte ed25519 pubkey |
| **`sorobanaddress`** | Stellar / Soroban | Stellar strkey account (`G…`) |
| **`nearaddress`** | NEAR | Implicit account — lowercase 64-hex pubkey |
| **`tonaddress`** | TON | Wallet v4-style base64url address |
| **`suiaddress`** | Sui | `0x` + 64 hex — BLAKE2b-256 of `0x00 \|\| pubkey` (Ed25519 scheme flag) |

All are derived from **`pubkeyhex`** (64 hex) at keygen save and backfilled on GET when missing. Omitted or empty for **secp256k1** and **bitcoin-taproot** keys.

<a id="bitcoin-p2tr-mainnet-address"></a>
### Bitcoin Taproot derived addresses (`bitcoinp2trmainnet`, `taprootinternalpubkeyhex`) (read-only)

For **`bitcoin-taproot`** FROST keygen results, [`GET /getKeyGenResultById`](#get-getkeygenresultbyid) and **`GET /getAllGroupIds`** may include:

| JSON field | Meaning |
|-----------|---------|
| **`taprootinternalpubkeyhex`** | x-only internal key *P* (64 hex) from DKG |
| **`bitcoinp2trmainnet`** | Pay-to-Taproot output key *Q* (x-only, 64 hex) after BIP-341 tap tweak with empty script tree; mainnet **`bc1p…`** address when derivable |

Signing uses the **BIP-340** digest of the spend (32-byte message hash). Requires mpc-auth built with **`-tags rust`** and givre FFI.

### Logging

All API requests are logged using the node's logger with the format:
```
Client: <IP> Called API: <package>.<function>
```

<a id="management-signatures-nodekey"></a>
### Management signatures (`nonce`, `clientSig`, `nodeKey`)

Authenticated management **POST** bodies that embed **`NodeMgtKeySig`** use this JSON envelope (field names are **lowercase**):

```json
{
  "nonce": 0,
  "clientSig": "",
  "nodeKey": "<128-hex from GET /getNodeKey>"
}
```

- **`nonce`**: anti-replay counter from **`GET /getNodeMgtKeyNonce`** (Ethereum **NodeMgtKey**) or **`GET /getPublicMgtKeyNonce`** (Ed25519; add **`?publicKey=`** for added keys).
- **`clientSig`**: management proof. For verification the server marshals the **same JSON with `clientSig` cleared** (`""`), then checks the signature you send in **`clientSig`**. **Ed25519:** 128 hex from an allowed management key. **Ethereum:** EIP‑191 **`personal_sign`** on **`signedMessage`** when the endpoint supports that dual mode (e.g. **`POST /addManagementKey`**).
- **`nodeKey`**: **required** on JSON payloads. Must equal this node's MPC public key from **`GET /getNodeKey`** (128 hex, no **`0x`**). Binds the signature to this node so it cannot be replayed on another node that shares the same management key.

**Legacy `Nonce` / `Sig` / `sig` field names are no longer accepted** on **`NodeMgtKeySig`** routes.

**Non-JSON signed payloads:** Some endpoints sign an opaque string (e.g. **`POST /configUpdateImplement`** prefixed line, **`caCertPem`** for **`POST /postMSQTTKey`**). Include **`nodeKey`** in the JSON request body (validated separately); the signed bytes are not JSON.

**Swagger:** **`node.NodeMgtKeySig`** and endpoint schemas in **`swagger.yaml`** / **`docs/swagger.json`** (mpc-auth and mpc-config).

<a id="browser-https-and-loopback-http-jwt"></a>
### Browser HTTPS and loopback HTTP (JWT)

When **`BrowserHTTPS`** is enabled, the TLS listener requires **`Authorization: Bearer <JWT>`** (**RS256**, **`JWKSURL`**) on **`GET`** requests. **`POST`** is not JWT-gated on that listener; use management-key signatures where documented. The optional **`BrowserLoopbackReadHTTP`** listener follows the same **`GET`** rules when Browser HTTPS is configured.

## Quick Reference: All Endpoints

Jump to detailed descriptions in [Endpoint Categories](#endpoint-categories) below. Maintenance and host apply helpers: [Restart quiescence](#restart-quiescence-maintenance-detail).

### Node Information
- [`GET /version`](#get-version) - Get node version
- [`GET /getMachineInfo`](#get-getmachineinfo) - Get machine information (CPU, memory, disk)
- [`GET /getNodeKey`](#get-getnodekey) - Get node public key (node ID)
- [`GET /getNodeMgtKey`](#get-getnodemgtkey) - Get node management key
- [`GET /getNodeMgtKeyNonce`](#get-getnodemgtkeynonce) - Next nonce for Ethereum **NodeMgtKey** only (`Data`: `{key, nonce}`)
- [`GET /hasPublicMgtKey`](#get-haspublicmgtkey) - Returns true if any Ed25519 management key is allowed (config or added via addManagementKey)
- [`GET /getAllowedEd25519MgtKeys`](#get-getalloweded25519mgtkeys) - List allowed Ed25519 management keys with labels (bootstrap + added) so the app can show "Which key?" **Also on `PublicDiscoveryPort`** (see [Public discovery HTTP](#public-discovery-http)).
- [`GET /getPublicMgtKey`](#get-getpublicmgtkey) - List allowed Ed25519 public keys (plain `[]string`, 64 hex); same allow-list as above. **Also served on `PublicDiscoveryPort`** (see [Public discovery HTTP](#public-discovery-http)) alongside `GET /getNodeMgtKey`.
- [`GET /getPublicMgtKeyNonce`](#get-getpublicmgtkeynonce) - Get current nonce for an Ed25519 key (optional `?publicKey=` for added keys)
- [`POST /verifyMgtKey`](#post-verifymgtkey) - Verify Ed25519 management key (attach-time proof; no other side effects)
- [`POST /addManagementKey`](#post-addmanagementkey) - Generate a new Ed25519 management key pair on the node, register its public key, and write local key files (`added_key_<N>` + `.pub`; continuum-mcp-server layout). Authorize with Ed25519 **`clientSig`** or EIP‑191 **NodeMgtKey** (`signedMessage` + **`clientSig`**).
- [`POST /removeManagementKey`](#post-removemanagementkey) - Soft-remove an added Ed25519 key and delete its local `added_key_<N>` files (**same dual auth**; Ed25519 signer must be allowed and ≠ key removed)
- [`GET /getAllowedKeyTypes`](#get-getallowedkeytypes) - Get allowed key types
- [`GET /getAllowedMsgCheckTypes`](#get-getallowedmsgchecktypes) - Get allowed message check types
- [`GET /getSuccessRate`](#get-getsuccessrate) - Get success rate statistics
- [`GET /getPreSigningVerificationStatus`](#get-getpresigningverificationstatus) - Get presigning verification status
- [`GET /getClientSigStatus`](#get-getclientsigstatus) - Get client signature check status (IgnoreClientSigCheck)
- [`GET /getSubscriptions`](#get-getsubscriptions) - Get MQTT subscriptions
- [`GET /getMSQTTKey`](#get-getmqttkey) - Get MQTT broker TLS CA PEM (`path`, `caCertPem`)
- [`GET /getWebTLSKey`](#get-getwebtlskey) - Get Browser HTTPS TLS certificate PEM (`path`, `certPem`)
- [`POST /postMSQTTKey`](#post-postmqttkey) - Write MQTT broker TLS CA PEM (management key signed)
- [`POST /configUpdatePlan`](#post-configupdateplan) - Plan staged `configs.yaml` update
- [`POST /configUpdateImplement`](#post-configupdateimplement) - Apply planned `configs.yaml` (management key signed)
- [`GET /health`](#get-health) - Get comprehensive health status
- [`GET /connectivityHealth`](#get-connectivityhealth) - Get connectivity health for nodes
- [`GET /getLogs`](#get-getlogs) - Get log entries
- [`GET /getConfiguredNodeKeys`](#get-getconfigurednodekeys) - Get node keys for configured addresses

### Node Registration
- [`POST /nodeRegister`](#post-noderegister) - Register node (one-time)
- [`GET /fetchNodeData`](#get-fetchnodedata) - Fetch node data by node ID
- `GET /fetchNodeDataByPublicKey` - Fetch node data by public key

### Local Chain Config
- [`POST /postChainDetails`](#post-postchaindetails) - Store EVM chain config on this node only (requires mgt key)
- [`GET /getChainDetails`](#get-getchaindetails) - Get EVM chain config(s); optional `chain_id` query for single chain
- [`POST /removeChainDetails`](#post-removechaindetails) - Remove EVM chain config for one chain (requires mgt key)

### Local Non-EVM Chain Config
- [`POST /postNonEvmChainDetails`](#post-postnonevmchaindetails) - Store non-EVM chain config (Solana, NEAR, Sui, TON, Stellar) on this node only (requires mgt key)
- [`GET /getNonEvmChainDetails`](#get-getnonevmchaindetails) - Get non-EVM chain config(s); optional `chain_type` and `chain_id` query filters
- [`POST /removeNonEvmChainDetails`](#post-removenonevmchaindetails) - Remove non-EVM chain config for one `(chainType, chainId)` (requires mgt key)

### Local Token Config
- [`POST /addToken`](#post-addtoken) - Add a token contract for a chain (this node only; requires mgt key)
- [`POST /removeToken`](#post-removetoken) - Remove a token contract (requires mgt key)
- [`GET /getTokens`](#get-gettokens) - Get all token configs grouped by chain type; optional `chainType`, `chain_id` filter

### Known Addresses (local node only)
- [`POST /addKnownAddress`](#post-addknownaddress) - Add or update a known address for a chain type (requires mgt key)
- [`POST /removeKnownAddress`](#post-removeknownaddress) - Remove a known address (requires mgt key)
- [`GET /getKnownAddresses`](#get-getknownaddresses) - Get all known addresses grouped by chain type; optional `chain_type`, `chain_id`, `is_contract` (0 or 1) filters

### Agent preferred signer (local node only)
- [`GET /getPreferredSigner`](#get-getpreferredsigner) - Get the default Ed25519 public key for agent signing if still an active management key. **Also on `PublicDiscoveryPort`** when split from **`ManagementAPIsPort`** (see [Public discovery HTTP](#public-discovery-http)).
- [`POST /setPreferredSigner`](#post-setpreferredsigner) - Store an **active** allowed Ed25519 management key as default for agents (requires mgt key)

### Agent preferred KeyGen (local node only)
- [`GET /getPreferredKeyGen`](#get-getpreferredkeygen) - Get the default multi-agree KeyGen for agent **`POST /multiSignRequest`** if still eligible. **Also on `PublicDiscoveryPort`** when split from **`ManagementAPIsPort`** (see [Public discovery HTTP](#public-discovery-http)).
- [`POST /postPreferredKeyGen`](#post-postpreferredkeygen) - Store a multi-agree KeyGen request id as the agent default for composing multiSignRequest payloads (requires mgt key)

### Agent LLM config (local filesystem)
- [`GET /agentLlmConfigStatus`](#get-agentllmconfigstatus) - Read agent LLM settings for the node agent (masked API key; **read JWT** on Browser HTTPS / loopback)
- [`POST /agentLlmConfig`](#post-agentllmconfig) - Update provider, model, and optional base URL (**management signature**; does not change `apiKey`)
- [`POST /agentLlmApiKey`](#post-agentllmapikey) - Set, rotate, or clear the cloud LLM API key only (**management signature**; `apiKey: ""` clears)
- [`POST /agent/chat`](#post-agentchat) - Stream one assistant turn (LLM + MCP **tools/call** loop; **read JWT** on Browser HTTPS / loopback)
- [`GET /agent/chat`](#get-agentchat) - Load persisted conversation history by `conversationId` (**read JWT** when JWT applies)
- [`POST /agent/chat/cancel`](#post-agentchatcancel) - Cancel in-flight turn for `conversationId` (**read JWT**)
- [`POST /agent/chat/elicitation`](#post-agentchatelicitation) - Complete pending MCP elicitation during a stream (**read JWT**)
- [`GET /agent/conversations`](#get-agentconversations) - List thread metadata for multi-tab UI (**read JWT**)
- [`GET /agent/conversations/:id`](#get-agentconversationsid) - Load one thread by id (**read JWT**)
- [`DELETE /agent/conversations/:id`](#delete-agentconversationsid) - Delete a thread (**read JWT**)
- [`GET /agent/mcp/tools`](#get-agentmcptools) - **tools/list** from **continuum-mcp** (Streamable HTTP; **read JWT** when JWT applies)

### Node Ping & Connectivity
- [`GET /pingNodesRequest`](#get-pingnodesrequest) - Ping nodes to test connectivity
- [`GET /getPingNodesResultById`](#get-getpingnodesresultbyid) - Get ping results by ID
- [`GET /listPingResults`](#get-listpingresults) - List all ping results
- [`GET /getInactiveNodes`](#get-getinactivenodes) - Get inactive nodes

### Group Management
- [`POST /newGroupRequest`](#post-newgrouprequest) - Create new group request (requires mgt key)
- [`GET /listNewGroupRequests`](#get-listnewgrouprequests) - List new group requests
- [`GET /getNewGroupRequestById`](#get-getnewgrouprequestbyid) - Get new group request by ID
- [`POST /newGroupRequestRetry`](#post-newgrouprequestretry) - Retry `NEWGROUPREQUEST` MQTT to one peer (originator only; requires mgt key)
- [`POST /newGroupRequestAgree`](#post-newgrouprequestagree) - Agree to new group request (requires mgt key)
- [`GET /getGroupResultById`](#get-getgroupresultbyid) - Get group result by request ID or group_id
- [`GET /getNewGroupResultById`](#get-getnewgroupresultbyid) - **Deprecated** — same as `GET /getGroupResultById`

### Key Generation
- [`POST /keyGenRequest`](#post-keygenrequest) - Create key generation request (requires mgt key)
- [`GET /listKeyGenRequests`](#get-listkeygenrequests) - List key generation requests
- [`GET /getKeyGenRequestById`](#get-getkeygenrequestbyid) - Get key generation request by ID
- [`POST /keyGenRequestRetry`](#post-keygenrequestretry) - Retry `KEYGENREQUEST` MQTT to one peer (originator only; requires mgt key)
- [`POST /keyGenRequestAgree`](#post-keygenrequestagree) - Agree to key generation request (requires mgt key)
- [`GET /getKeyGenResultById`](#get-getkeygenresultbyid) - Get key generation result by ID
- [`POST /keyGenEjectRequest`](#post-keygenejectrequest) - Start **multi-agree key eject** (CGGMP24 **secp256k1**, FROST **ed25519**, FROST **bitcoin-taproot**; requires mgt key)
- [`POST /keyGenEjectAgree`](#post-keygenejectagree) - Vote accept/reject on key eject (requires mgt key; same pattern as `signRequestAgree`)
- [`GET /listKeyGenEjectRequests`](#get-listkeygenejectrequests) - List in-progress or completed key eject flows for this node
- [`GET /getKeyGenEjectRequestById`](#get-getkeygenejectrequestbyid) - Get one key eject flow by eject request id
- [`POST /getEthereumPrivateKey`](#post-getethereumprivatekey) - After eject: read exported **64-hex** secp256k1 scalar (**secp256k1** only; also returns Bitcoin mainnet WIF when derivable)
- [`POST /getBitcoinPrivateKey`](#post-getbitcoinprivatekey) - After eject: read exported **Bitcoin mainnet compressed WIF** for the same ejected secp256k1 scalar
- [`POST /getEd25519PrivateKey`](#post-geted25519privatekey) - After eject: read exported **Ed25519 seed** and chain wallet import formats (**ed25519** only)
- [`POST /getTaprootPrivateKey`](#post-gettaprootprivatekey) - After eject: read exported **Taproot internal key scalar** and P2TR metadata (**bitcoin-taproot** only)
- [`GET /getGlobalNonceByKeyGenId`](#get-getglobalnoncebykeygenid) - Get globalNonce by keyGen result id
- [`GET /getKeyGenGroupId`](#get-getkeygengroupid) - Get key generation result and GroupId by keyGen ID
- [`GET /getAllGroupIds`](#get-getallgroupids) - Get all GroupIds with their keyGens
- [`GET /listGroupResults`](#get-listgroupresults) - List configured groups and member node keys (`nodeKeys`); optional filters `node_key`, `exclude_node_key`

### KeyGen Messaging
KeyGen messaging is documented in `./API_KEYGEN_MESSAGING.md`. Response format and conventions follow this document (`./API_IMPLEMENTATION.md`). **sendMessage, markMessageRead, multiMarkMessagesRead, deleteMessage, and multiDeleteMessages require a management key signature** (Ethereum wallet / NodeMgtKey or Ed25519, depending on the client key in the keyGen); see API_KEYGEN_MESSAGING.md for **`nonce` / `clientSig` / `nodeKey`** and getMessageToSign / getNodeMgtKeyNonce / getAllowedEd25519MgtKeys. For **Open Claw** (or similar), a poll-and-mark-read helper that uses `listMessages` + `multiMarkMessagesRead` is `$MPA_PATH/scripts/keygen_messaging_agent_poll.py`; scheduling and env are described in `../skill/SKILL.md` (**KeyGen inbox poll**). Ed25519 management signing: `./ED25519_MANAGEMENT_KEY_SIGNING.md`.
- [`POST /sendMessage`](#post-sendmessage) - Send a message (top-level or reply) in a keyGen channel (mgt key required)
- [`GET /listMessages`](#get-listmessages) - List messages (with unread, time range, top_level, pagination)
- [`GET /getMessageById`](#get-getmessagebyid) - Get a single message by id
- [`GET /getMessageThread`](#get-getmessagethread) - Get a top-level message and its reply tree (nested, max depth 3)
- [`POST /markMessageRead`](#post-markmessageread) - Mark a message as read (add read receipt) (mgt key required)
- [`POST /multiMarkMessagesRead`](#post-multimarkmessagesread) - Mark multiple messages as read (list of message ids) (mgt key required)
- [`POST /deleteMessage`](#post-deletemessage) - Delete a message and all its replies (originator only) (mgt key required)
- [`POST /multiDeleteMessages`](#post-multideletemessages) - Delete multiple messages (and their reply trees); originator-only per message; mgt key required

### Maintenance (restart quiescence)
Use these on the **same** `ManagementAPIsPort` listener as the rest of the management API (SSH tunnel forwards that port; **no separate listener**). `POST /maintenance/requestRestartPrep` requires a normal **management key** signature (`VerifyMgtKeySig`, same pattern as `POST /configUpdatePlan`). **`GET /maintenance/restartGate`** is read-only and exempt from JWT on the browser HTTPS / loopback listeners (for polling from scripts). MQTT-driven protocol continuation is **not** covered by the HTTP in-flight counter — see [Restart quiescence (maintenance)](#restart-quiescence-maintenance-detail).
- [`POST /maintenance/requestRestartPrep`](#post-maintenance-requestrestartprep) — enter draining mode so new tracked mutations return `503` until `GET /maintenance/restartGate` reports `readyForProcessExit` (then restart the process from the host/docker).
- [`GET /maintenance/restartGate`](#get-maintenance-restartgate) — returns `draining`, `inFlight`, `readyForProcessExit`, and a hint list of tracked POST paths.
- [`POST /reboot`](#post-reboot) — while **draining**, signed `{"nonce", "sig"}`; writes **`pending-reboot.json`** for **`mpc-auth-docker-pending-reboot.path`** when **`MPC_AUTH_PENDING_REBOOT_FILE`** / **`MpcAuthPendingRebootPath`** is set (same bind mount as pending Docker updates); host runs **`systemctl reboot`**. See **`systemd/README.md`**.
- [`POST /updateMpcAuth`](#post-updatempcauth) — while **draining**, signed request with target **tag** (e.g. `latest`, `v1.1`, or another published tag); node queries **Docker Hub** for **`registryDigest`** (`sha256:…`) for **`MpcAuthDockerRepo`**. Response includes **`previousVersion`** / **`previousVersionDate`** and **`newVersionRequested`**. The API does **not** run Docker on the host; apply the digest with **`mpc-auth-docker-update.sh TAG digest`** (no `/etc/default` edit required for one shot)—see [Host apply (digest)—not the same process as the HTTP API](#post-updatempc-auth-host) and **`systemd/README.md`**.
- [`POST /backupDatabase`](#post-backupdatabase) — encrypted MongoDB backup file under `database_backups/` (**deterministic** `nodeKey` + `bootstrap_key` only; management-signed). Requires **`mongodump`** on the node host.
- [`GET /listDatabaseBackups`](#get-listdatabasebackups) — lists backups for this node (`backupId`, `backupUtc`, `notes`); read-only; **no** management signature (like [`GET /checkDatabase`](#get-checkdatabase)).
- [`POST /fetchDatabaseBackup`](#post-fetchdatabasebackup) — **streams** the encrypted backup file to the client (**HTTPS** or **loopback** only, same transport rule as **`fetchBootstrapKey`**); management-signed; supports **HTTP Range** for resumable downloads.
- [`POST /postDatabaseBackup`](#post-postdatabasebackup) — **upload** encrypted backup JSON from an operator workstation into **`database_backups/`** (**`multipart/form-data`**: signed JSON field **`meta`** + raw file **`file`**); **`contentSha256`** in **`meta`** must match **`file`**; server validates envelope and proves decrypt with **bootstrap**; same eligibility and **maintenance quiescence** as **`POST /backupDatabase`** / **`POST /restoreDatabase`**.
- [`POST /restoreDatabase`](#post-restoredatabase) — destructive **`mongorestore --drop`** from an encrypted backup produced by this node (same eligibility as backup). Caller supplies **`backupId`** (filename) or **`backupPath`** (see below).
- [`POST /fetchBootstrapKey`](#post-fetchbootstrapkey) — returns **`ed25519PrivateSeedHex`** for offline backup decryption (**HTTPS** or **loopback** only); same eligibility as backup.
- [`POST /postBootstrapKey`](#post-postbootstrapkey) — write **`bootstrap_key/ed25519_private.hex`** from **`ed25519PrivateSeedHex`** in the signed body when the file is absent; management-signed; **not** subject to maintenance quiescence (no **503** while draining).
- [`POST /removeBootstrapKey`](#post-removebootstrapkey) — delete **`bootstrap_key/ed25519_private.hex`** if present; management-signed; **not** subject to maintenance quiescence.

### Database integrity
- [`GET /checkDatabase`](#get-checkdatabase) — MongoDB integrity report for configured group shards and local collections (**no** management signature; **no** deterministic-node / backup eligibility gate). See [MongoDB integrity](#mongodb-integrity-report-read-only).
- [`POST /fixDatabase`](#post-fixdatabase) — Apply **automated** Mongo repairs from the integrity scan (**management-signed**; same deterministic-node eligibility as backup; **maintenance quiescence** until **`GET /maintenance/restartGate`** reports **`readyForProcessExit`**). See [MongoDB integrity](#mongodb-integrity-report-read-only).

### Pre-Signing
- [`POST /presignRequest`](#post-presignrequest) - Create presign request (requires mgt key)
- [`GET /listPresignRequests`](#get-listpresignrequests) - List presign requests
- [`GET /getPresignRequestById`](#get-getpresignrequestbyid) - Get presign request by ID
- [`POST /presignRequestAgree`](#post-presignrequestagree) - Agree to presign request (requires mgt key)
- [`GET /listPresignResults`](#get-listpresignresults) - List presign results
- [`GET /getPresignResultById`](#get-getpresignresultbyid) - Get presign result by ID
- [`GET /getPresigningStatus`](#get-getpresigningstatus) - Get presigning status

### Signing
- [`POST /signRequest`](#post-signrequest) - Create sign request (requires relayer auth)
- [`POST /multiSignRequest`](#post-multisignrequest) - Create multi-agree sign request (no relayer)
- [`GET /listSignRequests`](#get-listsignrequests) - List sign requests
- [`GET /getSignRequestById`](#get-getsignrequestbyid) - Get sign request by ID
- [`POST /signRequestAgree`](#post-signrequestagree) - Agree to sign request (requires mgt key for multi-agree)
- [`GET /isSignRequestReadyById`](#get-issignrequestreadybyid) - Check if multi-agree sign request is ready to trigger
- [`GET /listSignRequestsReady`](#get-listsignrequestsready) - List multi-agree sign requests ready to trigger (with pagenum/pagesize)
- [`POST /triggerSignRequestById`](#post-triggersignrequestbyid) - Trigger signature generation for multi-agree (requires mgt key)
- [`POST /updateSignResultStatusById`](#post-updatesignresultstatusbyid) - Update sign result status: executed / failed / shelved; batch hashes; single-tx retry failed→executed (originator, mgt key)
- [`POST /shelveSignRequest`](#post-shelvesignrequest) - Set sign request status to shelved (originator only, requires mgt key)
- [`GET /listSignResults`](#get-listsignresults) - List sign results (filter + pagination)
- [`GET /getSignResultById`](#get-getsignresultbyid) - Get sign result by ID

### Relayer Management
- [`POST /admin/registerRelayer`](#post-admin-registerrelayer) - Register relayer (one-time per node)
- [`GET /admin/listRelayers`](#get-admin-listrelayers) - List all relayers
- [`GET /admin/getRelayer`](#get-admin-getrelayer) - Get relayer by public key
- [`POST /updateRelayer`](#post-updaterelayer) - Update relayer public keys (self-managed)

### Sub-Group (Deprecated)
- `POST /newSubGroupRequest` - Create sub-group request (deprecated)
- `GET /listNewSubGroupRequests` - List sub-group requests (deprecated)
- `POST /newSubGroupRequestAgree` - Agree to sub-group request (deprecated)

---

<a id="restart-quiescence-maintenance-detail"></a>
## Restart quiescence (maintenance)

**Purpose:** Operators can request **draining** before restarting the mpc-auth container so that **HTTP-coordinated** MPC, signing, messaging, and config-update mutations are not started mid-flight. The node does **not** execute `docker compose restart` itself — you stop or restart the process from the host (or orchestration) once the gate says it is safe.

**Same port as management API:** Maintenance routes are registered on **`Gin`** for **`ManagementAPIsPort`** (`configs.yaml` **`ManagementAPIsPort`**). An SSH tunnel forwards that port (e.g. `ssh -L 8080:127.0.0.1:8080 ...`). You do **not** need a second port or a second process unless you choose to split listeners for policy reasons (this implementation does not add one).

<a id="post-maintenance-requestrestartprep"></a>
#### `POST /maintenance/requestRestartPrep`

**Signing:** `POST /maintenance/requestRestartPrep` accepts JSON `{"nonce": <int>, "clientSig": "<hex>", "nodeKey": "<128-hex from GET /getNodeKey>"}`. The server verifies **`VerifyMgtKeySig`** over canonical JSON with **`clientSig` cleared** (same semantics as other management-signed POSTs); see [Management signatures (`nonce`, `clientSig`, `nodeKey`)](#management-signatures-nodekey).

<a id="get-maintenance-restartgate"></a>
#### `GET /maintenance/restartGate`

Returns **`draining`**, **`inFlight`**, **`readyForProcessExit`**, and a hint list of tracked POST paths. Read-only; exempt from JWT on the browser HTTPS / loopback listeners where configured (for polling from scripts).

**Flow:** (1) Sign and `POST /maintenance/requestRestartPrep`. (2) Poll `GET /maintenance/restartGate` until **`readyForProcessExit`** is `true` (`draining` is `true` and **`inFlight`** is `0`). (3) Restart the container or process on the host. Tracked paths include group/subgroup agree flows, keyGen, presign, sign/multiSign and related agrees/triggers/status/shelve, **KeyGen messaging** (`sendMessage`, read/delete variants), **`configUpdatePlan` / `configUpdateImplement`**, database backup routes **`POST /backupDatabase`**, **`POST /postDatabaseBackup`**, **`POST /restoreDatabase`**, **`POST /fetchDatabaseBackup`**, **`POST /fetchBootstrapKey`**, and **`POST /fixDatabase`** (automated integrity repairs under quiescence). **`POST /postBootstrapKey`** and **`POST /removeBootstrapKey`** are **not** tracked — they stay available while **`draining`** and do not increment **`inFlight`**.

**MQTT caveat:** In-flight work that continues only over **MQTT** (without a matching management POST on this node) is **not** included in the HTTP ref-count. Pause clients or wait briefly if needed.

<a id="post-reboot"></a>
#### `POST /reboot`

**Host reboot trigger:** Management-signed JSON `{"nonce": <int>, "sig": "<hex>"}` (canonical body with **`sig`** cleared for verification), **only while draining** (same precondition as **`POST /updateMpcAuth`**). The API does not reboot the machine itself. When **`MpcAuthPendingRebootPath`** in **`configs.yaml`** or **`MPC_AUTH_PENDING_REBOOT_FILE`** in the environment points at a host path bind-mounted read-write (same directory as **`pending-update.json`** is typical), mpc-auth writes **`pending-reboot.json`** atomically; **`mpc-config`** **`mpc-auth-docker-pending-reboot.path`** starts **`mpc-auth-apply-pending-reboot.sh`**, which archives the request and runs **`systemctl reboot`** on systemd hosts only (no legacy **`shutdown`** path; see **`systemd/README.md`** for inhibitors and non-interactive behavior).

<a id="post-updatempcauth"></a>
#### `POST /updateMpcAuth`

**Docker image upgrade (tag digest):** `POST /updateMpcAuth` (management-signed JSON `{ nonce, sig, tag }`) may be called **only while draining** (`requestRestartPrep` already applied). The node resolves the image via **Docker Hub** (`registry-1.docker.io`) and returns **`registryDigest`** aligned with **`MpcAuthDockerRepo`** (optional in `configs.yaml`, default **`continuumdao/mpc-auth`**), plus **`previousVersion`** / **`previousVersionDate`** (matches **`GET /version`** for the **current** process) and **`newVersionRequested`** (= requested **image tag**). The running container image is **not** changed by the API itself—see [Host apply (digest)—not the same process as the HTTP API](#post-updatempc-auth-host).

<a id="post-updatempc-auth-host"></a>
##### Host apply (digest) — why SSH or a host helper is still involved

The management API runs **inside** the mpc-auth container (or equivalent) and **cannot** invoke **`docker pull`** / **`docker compose`** on the Docker host unless you deliberately grant the container privileged access (e.g. mount **`/var/run/docker.sock`**) and accept the security implications. Typical deployments keep Docker on the host and expose only HTTP for management signatures.

So **`registryDigest`** is returned **for verification** when **something with Docker access** runs the bundled update script. **You do not have to edit `/etc/default/mpc-auth-docker` for each upgrade.**

**One-shot (recommended for copy-paste from the DAO app):**

```bash
sudo /usr/local/libexec/mpc-auth/mpc-auth-docker-update.sh "$TAG" "$REGISTRY_DIGEST"
# Example: mpc-auth-docker-update.sh v1.1 sha256:216dbe264b1f9b8528dff053cb333958952251d3002a544e9261da06efa43aac
```

The script uses the **second argument** as **`MPC_AUTH_EXPECTED_DIGEST`** for that process (see **`systemd/mpc-auth-docker-update.sh`**).

**Recommended automation (no Docker socket in the app container):** install **`mpc-config`** **`systemd/mpc-auth-docker-pending-update.path`** + bind-mount **`/var/lib/mpc-auth-docker`** into the container (**`docker-compose*.yml`** in mpc-config). Implement in **mpc-auth**, after **`POST /updateMpcAuth`** succeeds and returns **`registryDigest`**, write **`/var/lib/mpc-auth-docker/pending-update.json`** atomically (**write temp → `rename`**). **`systemd.path`** invokes **`mpc-auth-apply-pending-update.sh`**, which runs **`mpc-auth-docker-update.sh`** on the host. See **`mpc-config/systemd/README.md`** → *Fully automated upgrades*.

**Alternatively — Docker socket (`/var/run/docker.sock`) in the container:** **`docker`** CLI/API from mpc-auth avoids the trigger file but gives the container **full Docker API access** vs the host — usually worse for security than **systemd.path**.

<a id="mongodb-integrity-report-read-only"></a>
## MongoDB integrity report and automated repair

Read-only diagnostics (**`GET /checkDatabase`**) and optional **automated corrections** (**`POST /fixDatabase`**) share the same scanning logic on the server. Repairs run only under [**restart quiescence**](#restart-quiescence-maintenance-detail): while **`draining`** is **`true`**, **`POST /fixDatabase`** returns **`503`** until **`GET /maintenance/restartGate`** reports **`readyForProcessExit`** (`draining` **and** **`inFlight`** **`0`**), matching **`POST /backupDatabase`** / **`POST /restoreDatabase`** behavior.

These checks from **`GET /checkDatabase`** are **reports only** — that handler performs **no writes**. The scan is bounded by a **server-side timeout** (on the order of minutes on large databases).

**Authentication / eligibility:** **`GET /checkDatabase`** does **not** require **`VerifyMgtKeySig`** and does **not** use the same **deterministic nodeKey + bootstrap_key** gate as [`POST /backupDatabase`](#post-backupdatabase) and related backup routes. Treat it like other unsigned diagnostic **GET** routes on **`ManagementAPIsPort`**: restrict access with **firewall / VPN / SSH tunnel** as you would for the full management API.

**`POST /fixDatabase`** requires **`VerifyMgtKeySig`** and the **same deterministic-node eligibility** as **[MongoDB backup routes](#database-backup-maintenance)** (`403` when ineligible).

<a id="get-checkdatabase"></a>
#### `GET /checkDatabase`

**Success `data`:** a **`CheckDatabaseReport`** object (JSON), including:

- **`checkedAtUtc`**, **`baseDb`**
- **`summary`:** counts of **`error`** / **`warning`** / **`info`** issues, **`configuredGroupCount`**, **`groupDatabaseScanned`**
- **`issues`:** array of findings; each item has **`severity`**, **`scope`**, **`code`**, **`detail`**, optional **`hint`**, optional **`ref`** (e.g. `groupId`, `requestId`, collection name)
- **`baseCollectionSampleCounts`:** document counts for principal **base** database collections (Group, NewGroup, local chain/token/known-addresses, node key, etc.)
- **`perGroup`:** for each configured **GroupId**, counts and cross-checks for that shard’s **`KeyGen`**, **`KeyGenRequest`**, **`SignRequest`**, **`Sign`**, presign collections, **`KeyGenMessage`**, plus a map of **`pubkeyhex` → keygen `requestid`** and sign requests that reference a missing keygen
- **`orphanGroupDatabases`**, **`otherMongoDatabasesMatchingBasePrefix`:** Mongo database names that look like per-group shards (`{DBName}_…`) but do not match any configured group’s resolved DB name (stale shard, truncation, or restore mismatch)

**What it validates (high level):**

- **`Group`** rows: **`GroupId`**, node keys in **`KeyList`**
- **Per-group `KeyGen` / `KeyGenRequest`:** embedded **`KeyGenRequestDataPb`** (including BSON field-name fallbacks), **`GroupId` matches the shard**, **`KeyType` / `MsgCheck`** vs node allowlists, **`pubkeyhex`** shape for **secp256k1** / **ed25519**, **`globalnonce` / `val`** for secp256k1 fee nonce integrity
- **`SignRequest` / `Sign`:** embedded **`SignRequestDataPb`**, **`PubKey` ↔ KeyGen` in that group**, **`KeyGenRequestId`** vs the keygen’s **`requestid`**, batch vs single message-hash consistency
- **Local-only docs:** **`LocalChainConfig`**, **`LocalTokenConfig`**, **`LocalKnownAddresses`**, plus light checks on **`ExtraPublicMgtKeys`**
- **KeyGen messaging:** **`keyGenId`** references a known keygen **`requestid`** in the shard

**Errors:** **`503`**-class if database services are unavailable; **`500`** if the scan fails (e.g. Mongo error). **`200`** with **`code: 0`** when the report is produced, even when the report lists many **`severity: "error"`** findings (those describe data issues, not HTTP failure).

<a id="post-fixdatabase"></a>
#### `POST /fixDatabase`

**When to use:** After **`GET /checkDatabase`** shows repairable issue codes and you have entered [**maintenance draining**](#restart-quiescence-maintenance-detail) (`POST /maintenance/requestRestartPrep`, poll **`GET /maintenance/restartGate`** until **`readyForProcessExit`**).

**Signing:** Canonical JSON with **`clientSig`** cleared for **`VerifyMgtKeySig`** — same **`nonce` / `clientSig` / `nodeKey`** pattern as **`POST /backupDatabase`** ([management signatures](#management-signatures-nodekey)).

**Body:**

- **`instruction`** (required): **`"error"`** — apply fixes only for issues with **`severity`** **`error`**; **`"error_and_warning"`** — **`error`** and **`warning`**; **`"all"`** — **`error`**, **`warning`**, and **`info`** (only codes that have an implementation are changed; most findings have no auto-fix).
- **`report`** (required): the **`data`** object from **`GET /checkDatabase`** (must include **`checkedAtUtc`**). The signature **binds the operator request** to that snapshot. The server **always re-runs the full integrity scan** before applying fixes; repairs are driven by **current** MongoDB state and the **`instruction`** filter, **not** by stale entries in the submitted report alone.

**Automated fixes (current implementation):**

| Issue `code` | Action |
|--------------|--------|
| **`keygen_globalnonce_val_mismatch`** | **`$set`** **`val`** **`= hash(globalnonce)`** on the **`KeyGen`** row (secp256k1) when it still mismatches |
| **`sign_request_keygen_id_mismatch`** | Set embedded **`SignRequestDataPb.KeyGenRequestId`** to **`expectedKeyGenRequestId`** from the scan (**`SignRequest`** collection) |
| **`sign_result_keygen_id_mismatch`** | Same for **`Sign`** / **`SignResult`** |

Other finding codes are **skipped** until a repair is implemented. Failed repair attempts appear in **`fixesFailed`** with an error message.

**Success `data`:** **`instruction`**, **`inputReportCheckedAtUtc`**, **`fixesApplied`**, **`fixesFailed`**, **`summaryBefore`**, **`summaryAfter`**, **`issueCountBefore`**, **`issueCountAfter`**, **`reportAfter`** (full second **`GET /checkDatabase`**-shaped report).

**HTTP errors:** **`400`** validation; **`401`** / **`403`** signature or backup eligibility; **`503`** while **`draining`** and not yet **`readyForProcessExit`**; **`500`** scan or internal error.

<a id="database-backup-maintenance"></a>
## MongoDB backup, restore, and bootstrap key (maintenance)

These routes require **`VerifyMgtKeySig`** (Ethereum **`NodeMgtKey`** and/or allowed **Ed25519** keys). **Additional gate:** the node’s stored **`nodeKey`** must match the **P-256 public key** derived from **`configs.yaml` `PublicMgtKey`** and the on-disk **`bootstrap_key/ed25519_private.hex`** (see **`DeterministicNodeKey`** in **`mpc-auth`** and **`docs-internal/DATABASE_BACKUP_RESTORE_PLAN.md`**). Legacy **random** `nodeKey` nodes receive **403** on **`POST /backupDatabase`**, **`POST /fetchDatabaseBackup`**, **`POST /postDatabaseBackup`**, **`POST /restoreDatabase`**, **`POST /fetchBootstrapKey`**, and **`POST /fixDatabase`**. **`GET /listDatabaseBackups`** is read-only metadata only and does **not** require a management signature or this eligibility gate.

**Bootstrap file install/remove (separate):** **`POST /postBootstrapKey`** and **`POST /removeBootstrapKey`** are management-signed writes/deletes of **`bootstrap_key/ed25519_private.hex`** (see below). They use **`VerifyMgtKeySig`** but **not** the same deterministic-node / backup eligibility gate as the routes in the preceding paragraph, and they are **excluded** from [restart draining](#restart-quiescence-maintenance-detail) (no **503** while **`draining`**).

**Config / layout (defaults):** beside **`configs.yaml`** — directory **`bootstrap_key/`** (private seed file **`ed25519_private.hex`**, `0600`) and **`database_backups/`** (encrypted JSON envelopes). Override with **`BootstrapKeyDir`** / **`DatabaseBackupsDir`** in **`configs.yaml`** (absolute or relative to the configs.yaml parent directory). In **mpc-config** Docker Compose, **`./database_backups`** is bind-mounted to **`/app/database_backups`** so the default **`DatabaseBackupsDir: database_backups`** persists on the host next to the compose project. If **`bootstrap_key`** is bind-mounted **read-only** into the container, **`POST /postBootstrapKey`** / **`POST /removeBootstrapKey`** cannot change the file from inside the container — use a read-write mount (or change the file on the host) for API-driven provisioning.

**Provisioning:** **`process_config.sh`** always runs **`tools/bootstrap_key_provision.py`**. If **`PublicMgtKey`** is still empty after the management-key step, it writes **`bootstrap_key/ed25519_private.hex`**, sets **`PublicMgtKey`**, and sets **`DeterministicNodeKey: true`**. If **`PublicMgtKey`** is **already set** but **`DeterministicNodeKey`** was never written (common with **`provision-node.sh --public-mgt-key`**), the same script **verifies **`bootstrap_key/ed25519_private.hex`** matches **`configs.yaml`** and sets **`DeterministicNodeKey: true`**. Operators must archive **`bootstrap_key/`** securely (or call **`POST /fetchBootstrapKey`** over TLS after the node is up). For reinstallations, **`bootstrap_key/`** must exist **before** provisioning finishes so mpc-auth initializes Mongo with deterministic **`nodeKey`** (or wipe Mongo after **`DeterministicNodeKey`** plus seed are correct).

<a id="post-backupdatabase"></a>
#### `POST /backupDatabase`

**Body (signed JSON, `sig` cleared for verification; include `nonce`, optional `nodeKey` binding):**  
- **`includeGroupIds`** / **`excludeGroupIds`:** mutually exclusive; omit both to back up all **configured** group DBs plus the main **`DBName`** database.  
- **`mongoRootUsername`** / **`mongoRootPassword`:** optional; merged into **`MongodbUri`** when MongoDB uses auth (**`mongodump`**).
- **`notes`** (optional): Operator comment, **at most 256 Unicode code points**; stored in plaintext in the backup JSON envelope and echoed in the API **`data`**; must be part of the signed payload if sent.

**Process:** **`mongodump`** to an in-memory archive → **AES-256-GCM** encrypt (key from HKDF on bootstrap seed) → write JSON envelope under **`database_backups/`** (`ciphertextSha256`, `backupGroupFilter`, etc.).

**Success `data`:** includes **`backupId`** (backup filename), **`path`** (full path written), `backupUtc`, `ciphertextSha256`, `ciphertextByteLength`, `backupFileSizeBytes`, plus identifying fields (`notes`, filter, etc.).

<a id="get-listdatabasebackups"></a>
#### `GET /listDatabaseBackups`

**Auth:** none (read-only metadata; same class as [`GET /checkDatabase`](#get-checkdatabase)). Returns only **`backupId`**, **`backupUtc`**, and operator **`notes`** from envelope headers — not ciphertext or bootstrap material.

**Success `data`:** `{ "backups": [ { "backupId", "backupUtc", "notes" }, ... ] }` sorted **newest first** (by envelope `backupUtc`, with filename tie-break). Only files named `{first 20 chars of nodeKeyPublic}.backup.*.json` under **`database_backups/`** are listed (legacy `{full nodeKeyPublic}.backup.*.json` still recognized). Malformed files are skipped.

<a id="post-fetchdatabasebackup"></a>
#### `POST /fetchDatabaseBackup`

**Transport:** **`403`** unless the request is **TLS** or **loopback** (same rule as **`POST /fetchBootstrapKey`**). The file is ciphertext, but transport should still be protected.

**Body:** management-signed JSON with **exactly one** of **`backupId`** or **`backupPath`** (same rules as **`POST /restoreDatabase`**; no Mongo fields).

**Success response (not `APIResponse` JSON):** raw bytes of the backup file. The server sets **`Accept-Ranges: bytes`** and uses Go’s **`http.ServeContent`** so clients can resume with an HTTP **`Range`** header (e.g. `bytes=1048576-` for the tail after the first megabyte).

**Notification headers (inspect before/during download):**

- **`X-Mpc-Auth-Database-Backup-Total-Bytes`** — full file size on disk (for progress UI).
- **`X-Mpc-Auth-Database-Backup-Id`** — backup filename.
- **`X-Mpc-Auth-Database-Backup-Resume-Hint`** — reminder to repeat the **same signed POST** and send **`Range`** to continue.

**Stopping:** Close the HTTP client (Ctrl-C in **`curl`**); the server stops reading once the client disconnects. There is **no** configured upper size limit on the stream.

**Example (resume with curl):** use **`curl -C -`** against this POST so **`curl`** sends **`Range`** based on the partially written local file. **Each** request needs a **fresh management nonce/signature** (same as any other POST). Build a **new** signed JSON body for every attempt, including retries after a partial download.

<a id="post-postdatabasebackup"></a>
#### `POST /postDatabaseBackup`

**Purpose:** Copy an encrypted backup JSON from an operator machine onto the node’s **`database_backups/`** directory (same on-disk format as **`POST /backupDatabase`**).

**Quiescence:** Same as **`POST /backupDatabase`** — use **`POST /maintenance/requestRestartPrep`** and poll **`GET /maintenance/restartGate`** until **`readyForProcessExit`** before calling this endpoint while the node is busy.

**Request:** **`multipart/form-data`** with:

- **`meta`:** string holding management-signed JSON (**`PostDatabaseBackupPost`**): **`nonce`**, **`clientSig`**, **`nodeKey`**, **`contentSha256`** (hex **SHA-256** of the raw bytes sent in **`file`**).
- **`file`:** the backup **`.json`** file (UTF-8), unchanged from download or from another node that shares the same **`PublicMgtKey`** / **`bootstrap_key`** identity.

**Validation:** The server checks **`contentSha256`** matches **`file`**, verifies **`VerifyMgtKeySig`** on **`meta`**, then parses the envelope and applies the same logical checks as **`POST /restoreDatabase`** through successful **AES-GCM decrypt** with this node’s **bootstrap** seed (without writing to Mongo yet). **`publicMgtKey`** / **`nodeKeyPublic`** in the envelope must match this node.

**Filename:** Same rule as **`POST /backupDatabase`**, but the timestamp segment is taken from the envelope’s **`backupUtc`** (when the snapshot was created), **not** the upload time — so downloading a backup and **`POST /postDatabaseBackup`** it back yields the **same** `backupId` whenever the envelope is unchanged. The stem is the first **20** characters of **`nodeKeyPublic`** (or this node’s key if the field was omitted in older envelopes). If a file at that path **already exists**, the server returns **`code: 0`** with **`data.message`** `"Database backup was already present"` and **`data.alreadyPresent: true`** (no write; existing file unchanged).

**Success `data`:** **`backupId`**, **`path`**, **`backupFileSizeBytes`**, **`contentSha256`** (hash of uploaded bytes). **`alreadyPresent`** is **`false`** when a new file was written. When **`alreadyPresent`** is **`true`**, **`message`** is **`Database backup was already present`**, **`backupFileSizeBytes`** is the **existing** file on disk, and the file was not modified (**`contentSha256`** is still the uploaded payload hash).

**Errors:** **`400`** for multipart/sha/envelope/decrypt issues; **`401`** for signature failure; **`503`** while draining and not yet **`readyForProcessExit`** (same as other tracked backup POSTs).

**Size:** The server accepts large backup files via **`multipart/form-data`** (parsed with a generous in-memory buffer, then spillover to disk — suitable for typical encrypted snapshots).

<a id="post-restoredatabase"></a>
#### `POST /restoreDatabase`

**Body:** management-signed JSON with **exactly one** of **`backupId`** or **`backupPath`**, plus optional Mongo credentials as above.

- **`backupId`:** the backup **filename only** (no `/` or `..`), e.g. the **`backupId`** from **`POST /backupDatabase`** or **`GET /listDatabaseBackups`**.
- **`backupPath`:** legacy form — relative to **`database_backups/`** or absolute path still constrained to that directory.

**Semantics:** **`mongorestore --archive --drop`** from decrypted payload — **destructive** for databases present in the backup. **`publicMgtKey`** / **`nodeKeyPublic`** in the envelope must match this node.

**Success `data`:** `restoredFrom` (absolute path) and **`backupId`** (basename).

<a id="post-fetchbootstrapkey"></a>
#### `POST /fetchBootstrapKey`

**Body:** management-signed JSON (e.g. `{ "nonce", "sig" }`).

**Transport:** **`403`** when the request is **not** TLS and **not** to **loopback** (`127.0.0.1` / `localhost` / `::1`).

**Success `data`:** `publicMgtKey`, `ed25519PrivateSeedHex` (32-byte seed as 64 hex), `format` discriminator. **Never log** the private material.

<a id="post-postbootstrapkey"></a>
#### `POST /postBootstrapKey`

**Purpose:** Create **`ed25519_private.hex`** under **`EffectiveBootstrapKeyDir`** (default **`bootstrap_key/`** next to **`configs.yaml`**) when it does **not** already exist.

**Quiescence:** **None** — this route is **not** in **`maintenancePathsCritical`**; it is **not** refused with **503** while **`draining`**.

**Body:** management-signed JSON (**`PostBootstrapKeyPost`**): **`nonce`**, **`clientSig`**, **`nodeKey`**, **`ed25519PrivateSeedHex`** (64 hex chars, 32-byte seed). Canonical JSON for verification uses **`clientSig` cleared.

**Success when absent:** writes the file with mode **`0600`** (and creates the directory **`0700`** if needed). **`data`:** **`path`**, **`wrote: true`**, **`alreadyPresent: false`**.

**Success when already present:** **`code: 0`**, **`data.message`** **`Bootstrap key already in place`**, **`alreadyPresent: true`**, **`wrote: false`** — existing file is **not** overwritten.

**Errors:** **`400`** validation/signature payload issues; **`401`** signature verification failure.

<a id="post-removebootstrapkey"></a>
#### `POST /removeBootstrapKey`

**Purpose:** Delete **`ed25519_private.hex`** under **`EffectiveBootstrapKeyDir`** if it exists.

**Quiescence:** **None** — same as **`POST /postBootstrapKey`** (not tracked for restart draining).

**Body:** management-signed JSON (**`RemoveBootstrapKeyPost`**): **`nonce`**, **`clientSig`**, **`nodeKey`**.

**Success when file existed:** **`data`:** **`path`**, **`removed: true`**, **`message`** **`Bootstrap key file removed`**.

**Success when file missing:** **`code: 0`**, **`removed: false`**, **`message`** **`Bootstrap key file was not present`**.

**Errors:** **`401`** signature failure; **`500`** if **`stat`**/**`remove`** fails unexpectedly.

<a id="endpoint-categories"></a>
## Endpoint Categories

### 1. Node Information Endpoints

<a id="get-version"></a>
#### `GET /version`
Returns the current **application release** version (semver string) and the date it was set for that release.

**Docker tag vs. `data.version`:** Your compose file may pull **`continuumdao/mpc-auth:latest`** (default in mpc-config templates) or any other registry tag you set via **`MPC_AUTH_COMPOSE_APP_IMAGE`**. That tag only selects **which image** to run. The **`version`** field here is **not** the Docker tag: it is the **mpc-auth build version** compiled into the binary when that image was produced (e.g. **`v1.1`**). So after **`docker compose pull`** and **`docker compose up -d`**, use **`GET /version`** on the management or public discovery port (per your deployment) to read the **semver of the running app**. Official **`latest`** builds should still embed a normal semver in the binary (so operators see **`v1.1`** in **`data.version`** even though the image reference is **`…:latest`**).

Also served on **PublicDiscoveryPort** (e.g. **18080**) when that listener is split from **ManagementAPIsPort**. **Not** registered on **Browser HTTPS** (**8443**); use discovery or management URL (no JWT for this route).

**Diagnostics:** `data.cggmp24UpstreamGitRev` and **`data.givreUpstreamGitRev`** are git revisions of the Lockness **cggmp21** and **givre** crates pinned in the build (via CGO FFI). Each is **non-empty** only when the binary was built with **`-tags rust`** and the corresponding FFI library is linked; default builds omit them (empty string). Use them to confirm which upstream revision an image was compiled against.

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": {
    "version": "v1.1",
    "versionDate": "2024-01-15",
    "cggmp24UpstreamGitRev": "",
    "givreUpstreamGitRev": ""
  }
}
```

**Field Descriptions:**
- `version`: The current node **application** version string (e.g. **`v1.12`**) — from the running binary, not necessarily the Docker image tag (`latest`, `v1.0`, etc.).
- `versionDate`: The date when this version was set/changed (ISO 8601 date format, e.g., "2024-01-15")
- `cggmp24UpstreamGitRev`: Pinned upstream git revision for the CGGMP24 Rust stack when built with **`-tags rust`**; otherwise `""` (see **Diagnostics** above).
- `givreUpstreamGitRev`: Pinned upstream git revision for the FROST/givre Rust stack when built with **`-tags rust`**; otherwise `""`.

<a id="get-getmachineinfo"></a>
#### `GET /getMachineInfo`
Returns machine information (CPU, memory, disk, etc.). By default, returns cached data from MongoDB. Automatically refreshes if data doesn't exist or is older than 1 month.

**Query Parameters:**
- `refresh` (optional): If `true`, forces a fresh fetch and updates MongoDB. If `false` (default), returns cached data from MongoDB, but automatically refreshes if:
  - No cached data exists, or
  - Last refresh was more than 1 month ago

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": {
    "cpu": {
      "cores": 8,
      "usagePercent": 0.0
    },
    "memory": {
      "totalGB": "16.00 GB",
      "usedGB": "8.50 GB",
      "availableGB": "7.50 GB"
    },
    "disk": {
      "totalGB": "500.00 GB",
      "usedGB": "250.00 GB",
      "availableGB": "250.00 GB"
    },
    "os": {
      "version": "linux 6.5.0"
    },
    "cpuInfo": {
      "version": "Intel Core i7-9700K",
      "physicalCores": 4,
      "logicalCores": 8
    },
    "vps": {
      "isVPS": true,
      "provider": "AWS EC2"
    },
    "countryCode": "US"
  }
}
```

**Field Descriptions:**
- `cpu.cores`: Number of logical CPU cores
- `cpu.usagePercent`: CPU usage percentage (currently always 0.0, requires periodic sampling)
- `memory.totalGB`: Total system memory (formatted as string with "GB" suffix)
- `memory.usedGB`: Used system memory (formatted as string with "GB" suffix)
- `memory.availableGB`: Available system memory (formatted as string with "GB" suffix)
- `disk.totalGB`: Total disk space (formatted as string with "GB" suffix)
- `disk.usedGB`: Used disk space (formatted as string with "GB" suffix)
- `disk.availableGB`: Available disk space (formatted as string with "GB" suffix)
- `os.version`: Operating system version
- `cpuInfo.version`: CPU model name/version
- `cpuInfo.physicalCores`: Number of physical CPU cores
- `cpuInfo.logicalCores`: Number of logical CPU cores
- `vps.isVPS`: Boolean indicating if the machine is detected as a VPS
- `vps.provider`: VPS provider name (e.g., "AWS EC2", "Google Cloud", "Contabo", "DigitalOcean", etc.) or empty string if not a VPS or provider cannot be detected
- `countryCode`: ISO 3166-1 alpha-2 country code (e.g., "US", "DE", "GB") detected from the machine's public IP address, or empty string if detection fails

**Field Descriptions:**
- `cpu.cores`: Number of logical CPU cores
- `cpu.usagePercent`: CPU usage percentage (currently always 0.0, requires periodic sampling)
- `memory.totalGB`: Total system memory (formatted as string with "GB" suffix)
- `memory.usedGB`: Used system memory (formatted as string with "GB" suffix)
- `memory.availableGB`: Available system memory (formatted as string with "GB" suffix)
- `disk.totalGB`: Total disk space (formatted as string with "GB" suffix)
- `disk.usedGB`: Used disk space (formatted as string with "GB" suffix)
- `disk.availableGB`: Available disk space (formatted as string with "GB" suffix)
- `os.version`: Operating system version
- `cpuInfo.version`: CPU model name/version
- `cpuInfo.physicalCores`: Number of physical CPU cores
- `cpuInfo.logicalCores`: Number of logical CPU cores
- `vps.isVPS`: Boolean indicating if the machine is detected as a VPS
- `vps.provider`: VPS provider name (e.g., "AWS EC2", "Google Cloud", "Contabo", "DigitalOcean", etc.) or empty string if not a VPS or provider cannot be detected

**Examples:**
```bash
# Get cached machine info from MongoDB (default)
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getMachineInfo"

# Refresh and fetch fresh machine info
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getMachineInfo?refresh=true"
```

**Notes:**
- Machine info is stored in MongoDB keyed by node's public key
- Automatic refresh occurs if:
  - No cached data exists (first call), or
  - Last refresh was more than 1 month ago
- Use `refresh=true` to force a fresh fetch regardless of cache age
- Fresh data includes VPS detection and country code lookup (may take a few seconds)
- Cached data is returned immediately for fast responses

<a id="get-getnodekey"></a>
#### `GET /getNodeKey`
Returns the node's unique public key (node ID). This is the 128-character hex string that identifies the node in MPC operations.

Also served on **PublicDiscoveryPort** (e.g. **18080**) when that listener is split from **ManagementAPIsPort** — see [Public discovery HTTP](#public-discovery-http). **Not** registered on **Browser HTTPS** (**8443**); use discovery or management URL (no JWT for this route).

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": "1711c3077fc974b538fe6a786aae141f35f07e0ae7a91e89ebd1aed67f16846fea83a3d3b51a0c30d1d908dbf3f5ddfe71e0c03a0a0afa200a1e4cacfe223c3e"
}
```

**Example:**
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getNodeKey"
curl "http://localhost:18080/getNodeKey"   # when PublicDiscoveryPort is split (e.g. 18080)
```

<a id="get-getnodemgtkey"></a>
#### `GET /getNodeMgtKey`
Returns the **`NodeMgtKey`** configured for this node (Ethereum address: `0x` plus 40 hex from `configs.yaml` / `NodeMgtKey` env). **`data`** is that string. **No authentication** on the management HTTP port or on **PublicDiscoveryPort** (see [Public discovery HTTP](#public-discovery-http)). On **Browser HTTPS** / **BrowserLoopbackReadHTTP**, **GET** requests require **JWT** like other routes on those listeners—use the management or discovery base URL when you need this value without JWT.

Use this address with [`GET /getNodeMgtKeyNonce`](#get-getnodemgtkeynonce) and Ethereum wallet **`personal_sign`** for management API requests signed by the Ethereum key.

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb5"
}
```

**Example:**
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getNodeMgtKey"
curl "http://localhost:18080/getNodeMgtKey"   # when PublicDiscoveryPort is split (e.g. 18080)
```

<a id="get-getnodeuptime"></a>
#### `GET /getNodeUptime`
Returns node uptime statistics including first start date, last restart date, total uptime hours, and current session uptime hours.

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": {
    "firstStartDate": "2024-01-15",
    "lastRestartDate": "2024-01-20T10:30:00Z",
    "totalUptimeHours": "120.50",
    "currentSessionUptimeHours": "48.25"
  }
}
```

**Field Descriptions:**
- `firstStartDate`: Date when the node was first started (ISO 8601 date format, e.g., "2024-01-15"). This value is set once and never updated, even if the code is upgraded.
- `lastRestartDate`: Date and time of the last restart (ISO 8601 timestamp format, e.g., "2024-01-20T10:30:00Z"). Updated every time the node starts.
- `totalUptimeHours`: Total cumulative uptime in hours since the node was first started (formatted as string with 2 decimal places). This is calculated as the time elapsed since `firstStartDate` and does not account for downtime periods.
- `currentSessionUptimeHours`: Hours since the last restart (formatted as string with 2 decimal places). This is calculated as the time elapsed since `lastRestartDate`.

**Example:**
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getNodeUptime"
```

**Notes:**
- Uptime tracking is automatically initialized when the node starts (in `StartManagementAPIs`).
- If the node has never been started before, `firstStartDate` and `lastRestartDate` will be set to the current date/time.
- `totalUptimeHours` represents the total time elapsed since first start, not actual running time (it doesn't subtract downtime periods).
- `currentSessionUptimeHours` is calculated in real-time on each API call.

<a id="get-getnodemgtkeynonce"></a>
#### `GET /getNodeMgtKeyNonce`
Returns the **next nonce to use** for the **Ethereum NodeMgtKey** from config (the same address as [`GET /getNodeMgtKey`](#get-getnodemgtkey)). The server stores one monotonic nonce sequence **per signer key** in `NodeMgtKeyHistory`; this endpoint only reports the sequence for the configured `NodeMgtKey` address, not for Ed25519 keys.

**Response (success):**
```json
{
  "code": 0,
  "error": "",
  "data": {
    "key": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb5",
    "nonce": 0
  }
}
```

(Live JSON may use capitalized `Code`, `Error`, `Data`; `data` is always an object with `key` and `nonce`.)

**Field descriptions (`data`):**
- `key`: The node’s **NodeMgtKey** (Ethereum address, `0x`-prefixed). Same value as `GET /getNodeMgtKey`. Confirms which key this nonce applies to.
- `nonce`: The **expected next nonce** for that Ethereum key in signed management requests. If there is **no** history yet for this address in the DB, this is **`0`** (first signature uses nonce `0`). After each successful authenticated request, the next call returns the previous value plus one.

**Ed25519 vs Ethereum (`NodeMgtKey`):** If you authenticate with an **Ed25519** management key (config `PublicMgtKey` or keys from `addManagementKey`), nonce consumption is tracked under that **64-hex public key**, not under the Ethereum `NodeMgtKey`. In that case **`GET /getNodeMgtKeyNonce` can stay at `0`** even after many Ed25519-signed operations. Use [`GET /getPublicMgtKeyNonce`](#get-getpublicmgtkeynonce) (and `?publicKey=<64_hex>` for added keys) for the nonce that matches your signing key.

**Example:**
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getNodeMgtKeyNonce"
```

**Note:** Always fetch the latest nonce immediately before building the payload to sign; do not manually increment—use the value returned by this endpoint (Ethereum) or by `getPublicMgtKeyNonce` (Ed25519).

<a id="get-haspublicmgtkey"></a>
#### `GET /hasPublicMgtKey`
Returns whether at least one Ed25519 management key is allowed. This is true if `PublicMgtKey` is set in config with valid structure, or any keys have been added via `POST /addManagementKey`. When true, node runners can use an Ed25519 key pair for direct API management without a frontend (in addition to Ethereum wallet / NodeMgtKey).

**Validation:** The config key (if set) must be exactly 64 hex characters (32-byte Ed25519 public key). When no key is configured and none have been added, `data` is `false`.

**Response (valid key configured):**
```json
{
  "code": 0,
  "error": "",
  "data": true
}
```

**Response (no key or invalid key):**
```json
{
  "code": 0,
  "error": "PublicMgtKey not configured",
  "data": false
}
```
or when a value is set but invalid:
```json
{
  "code": 0,
  "error": "PublicMgtKey invalid: must be 64 hex characters (32-byte Ed25519 public key)",
  "data": false
}
```
`data` is `true` if at least one Ed25519 management key is allowed (config or added via addManagementKey). When `data` is `false`, `error` describes why.

**Example:**
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/hasPublicMgtKey"
```

<a id="get-getalloweded25519mgtkeys"></a>
#### `GET /getAllowedEd25519MgtKeys`
Returns the list of Ed25519 public keys allowed for management API auth (config `PublicMgtKey` plus keys added via `POST /addManagementKey`), each with a short label so the app can show "Which key are you using?" without the user needing to know the hex. Keys removed with [`POST /removeManagementKey`](#post-removemanagementkey) still occupy their **Added key N** slot: those entries have **`"deleted": true`**, empty **`publicKey`**, and **`removedPublicKey`** set to the retired 64-hex value. Used by continuumdao-node-app when the user clicks "Attach with Ed25519".

**Response (success):**
```json
{
  "code": 0,
  "error": "",
  "data": [
    { "publicKey": "64hex...", "label": "Bootstrap (config)" },
    { "publicKey": "64hex...", "label": "Added key 1" },
    { "publicKey": "", "label": "Added key 2", "deleted": true, "removedPublicKey": "64hex..." }
  ]
}
```

**Example:**
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getAllowedEd25519MgtKeys"
curl "http://localhost:18080/getAllowedEd25519MgtKeys"   # when PublicDiscoveryPort is split (e.g. 18080)
```

<a id="get-getpublicmgtkey"></a>
#### `GET /getPublicMgtKey`
Returns every allowed Ed25519 public key for management API auth as a **plain array of strings** (each 64 hex characters, no `0x` prefix): config **`PublicMgtKey`** (if valid) plus keys added via **`POST /addManagementKey`**. Same keys as **`GET /getAllowedEd25519MgtKeys`**, but without labels.

**Use cases:** discovery for JWKS issuers, DAO apps, or scripts that need the public key(s) to verify Ed25519 challenges or to populate **`NODE_PUBLIC_MGT_KEYS_JSON`**, without reading the node config file.

**Response (success):**
```json
{
  "code": 0,
  "error": "",
  "data": ["a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"]
}
```

When no Ed25519 key is configured, `data` is `[]`.

**Examples:**
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getPublicMgtKey"
curl "http://localhost:18080/getPublicMgtKey"
```

<a id="get-getpublicmgtkeynonce"></a>
#### `GET /getPublicMgtKeyNonce`
Returns the current nonce for an Ed25519 management key. Optional query param `publicKey` (64 hex) selects which key; if omitted, uses config `PublicMgtKey`. Use when authenticating management API requests with an Ed25519 key pair. Returns `400` if no key is specified or the key is not in the allowed set (config or added via `addManagementKey`).

**Response (success):**
```json
{
  "code": 0,
  "error": "",
  "data": {
    "key": "a1b2c3...",
    "nonce": 1
  }
}
```

**Examples:**
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getPublicMgtKeyNonce"
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getPublicMgtKeyNonce?publicKey=YOUR_64_HEX_KEY"
```

<a id="post-verifymgtkey"></a>
#### `POST /verifyMgtKey`
Verify-only endpoint for Ed25519 management key ownership. Accepts **`nonce`**, **`clientSig`**, and **`nodeKey`** (128-hex Ed25519 signature over the exact JSON `{"nonce":<n>,"clientSig":"","nodeKey":"<128-hex>"}`). The node verifies the signature with one of the allowed Ed25519 keys (config `PublicMgtKey` or keys added via `addManagementKey`), consumes the nonce (same semantics as other management endpoints), and returns `code: 0` on success. No other state is changed. Used by the continuumdao-node-app when the user clicks "Attach with Ed25519" to prove key ownership at attach time without performing any other action.

**Request body:**
- `nonce` (required): Current nonce from `GET /getPublicMgtKeyNonce` (or `?publicKey=<your_key>`).
- `clientSig` (required): Ed25519 signature, 128 hex characters, over the exact message with `clientSig` cleared (same nonce and `nodeKey` as in the body).
- `nodeKey` (required): This node's MPC public key from `GET /getNodeKey` (128 hex).

**Response (success):** `{ "code": 0, "error": "", "data": null }`

**Response (failure):** `code` non-zero, `error` describes the reason (e.g. invalid signature, nonce mismatch, nonce already used, missing/wrong `nodeKey`, or no Ed25519 key configured).

**Example flow:** 1) `GET /getNodeKey` and `GET /getPublicMgtKeyNonce` → get `nodeKey` and nonce. 2) Build message `{"nonce":<n>,"clientSig":"","nodeKey":"<128-hex>"}` and sign with your Ed25519 private key. 3) `POST /verifyMgtKey` with body including `clientSig`.

<a id="post-addmanagementkey"></a>
#### `POST /addManagementKey`
Generates a **new Ed25519 key pair on the node**, adds its public key to the allowed set used for Ed25519 management signatures (alongside bootstrap **`PublicMgtKey`** in `configs.yaml` and keys already added via this endpoint), and writes local key material for automation (**continuum-mcp-server** layout):

| File | Content | Mode |
|------|---------|------|
| `KEY_ROOT/management_keys/added_key_<N>` | PKCS#8 PEM private key | `0600` |
| `KEY_ROOT/management_keys/added_key_<N>.pub` | 64-hex public key + newline | `0644` |

`<N>` is the **Added key N** slot (1-based index among Mongo **`ExtraPublicMgtKeys`** rows, including soft-removed slots). **`KEY_ROOT`** resolves from env **`MPA_PATH`** or **`KEY_ROOT`**, default **`~/.mpa`**. In **Docker** (mpc-config compose), keys are bind-mounted at **`./.mpa/management_keys`** in the repo with **`MPA_PATH=/app/.mpa`** (app) and **`KEY_ROOT=/app/.mpa`** (continuum-mcp).

The client **does not** supply `newPublicKey` or a private key. Any **currently allowed** signer may authorize — **either** an allowed **Ed25519** management key **or** the configured **`NodeMgtKey`** (EIP‑191), as below.

At least **one** Ed25519 allowance must exist on the node (bootstrap **`PublicMgtKey`** and/or previously added keys).

##### Canonical payload (same bytes for Ed25519 and EIP‑191 modes)

Compute the canonical UTF‑8 JSON string (**field order**, **`clientSig`** exactly **`""`**, **`nodeKey`** required):

```json
{"nonce":N,"clientSig":"","nodeKey":"<128-hex>"}
```

##### Mode A — Ed25519 signer

1. Obtain **`nonce`** from [`GET /getPublicMgtKeyNonce`](#get-getpublicmgtkeynonce); add **`?publicKey=<your_64_hex_signer>`** when the signer is an **Added key** rather than the default config key.

2. Set **`clientSig`** to the raw Ed25519 signature (**128 hex**, optional **`0x`** stripped).

3. **Do not** set **`signedMessage`**.

Example POST shape:

```json
{
  "nonce": 7,
  "clientSig": "<128_hex>",
  "nodeKey": "<128-hex>"
}
```

##### Mode B — Ethereum `NodeMgtKey`

1. Requires non-empty **`NodeMgtKey`** in `configs.yaml`.

2. Obtain **`nonce`** from [`GET /getNodeMgtKeyNonce`](#get-getnodemgtkeynonce).

3. Set **`signedMessage`** to the **exact** canonical UTF‑8 string (must byte‑match mpc-auth — i.e. the same UTF‑8 as Go `encoding/json.Marshal` would emit for **`{nonce, clientSig: "", nodeKey}`**).

4. Set **`clientSig`** to EIP‑191 **`personal_sign(signedMessage)`** (`0x` prefix allowed).

Example POST shape:

```json
{
  "nonce": 3,
  "nodeKey": "<128-hex>",
  "signedMessage": "{\"nonce\":3,\"clientSig\":\"\",\"nodeKey\":\"...\"}",
  "clientSig": "0x..."
}
```

**Swagger:** **`#/definitions/node.AddManagementKeyPost`**

**Response (success):** [`APIResponse`](#response-format) **`code`** `0`; **`data`** includes:

| Field | Description |
|-------|-------------|
| `addedPublicKey` | 64-hex lowercase public key (server-generated) |
| `keySlot` | Added key N slot (`N` in `added_key_<N>`) |
| `fileName` | Base name (e.g. `added_key_1`) |
| `privateKeyPath` | Absolute path to PKCS#8 PEM file |
| `publicKeyPath` | Absolute path to `.pub` file |
| `privateKeyPem` | PKCS#8 PEM of the new private key (returned once in the API response so the operator can save a local backup; also written to `privateKeyPath`) |

Confirm via [`GET /getAllowedEd25519MgtKeys`](#get-getalloweded25519mgtkeys) / [`GET /getPublicMgtKey`](#get-getpublicmgtkey).

**Response (failure):** invalid body, **`signedMessage`** not equal canonical JSON (EIP‑191 mode), wrong nonce bucket, **`NodeMgtKey`** missing while using EIP‑191, ambiguous **`sig`**+**`clientSig`**, signer not authorized, or filesystem error writing key files.

<a id="post-removemanagementkey"></a>
#### `POST /removeManagementKey`
Soft-removes an Ed25519 public key **only among keys previously added via** [`POST /addManagementKey`](#post-addmanagementkey). The Mongo row keeps its **Added key N** label: **`publicKey`** clears, **`removedPublicKey`** retains the retired 64‑hex. The bootstrap **`PublicMgtKey`** from `configs.yaml` **cannot** be removed here.

Also deletes **`KEY_ROOT/management_keys/added_key_<N>`** and **`added_key_<N>.pub`** when present (same `<N>` as the slot; no error if files are already missing).

**Auth:** Dual pattern **identical conceptually** to [`POST /addManagementKey`](#post-addmanagementkey):

##### Canonical UTF‑8 string

```json
{"publicKey":"<64_hex_lowercase_of_key_being_removed>","nonce":N,"clientSig":"","nodeKey":"<128-hex>"}
```

##### Mode A — Ed25519

The **signer must be allowed** AND **≠** **`publicKey`** (you cannot authorize removal by signing **as** the key you are retiring). Nonce comes from **`GET /getPublicMgtKeyNonce?publicKey=<signer_hex>`**.

Post `{ publicKey, nonce, clientSig, nodeKey }` (omit **`signedMessage`**).

##### Mode B — Ethereum `NodeMgtKey`

Use **`GET /getNodeMgtKeyNonce`**; **`signedMessage`** canonical string must match server encoding; **`clientSig`** EIP‑191; include **`nodeKey`**.

**Swagger:** **`#/definitions/node.RemoveManagementKeyPost`**

**Response (success):** **`data`** includes **`removedPublicKey`** (64‑hex lowercase) and, when the slot was resolved:

| Field | Description |
|-------|-------------|
| `keySlot` | Added key N slot |
| `fileName` | Base name (e.g. `added_key_1`) |
| `privateKeyPath` | Path to PEM file that was removed (or expected path) |
| `publicKeyPath` | Path to `.pub` file |
| `privateKeyRemoved` | `true` if at least one local file was deleted |

**Errors:** **`404`** — target hex not currently present as an active added key (`PublicMgtKey` / wrong hex / soft-already‑removed races); **`401`** — signing rules failed (wrong signer pairing in Ed25519 mode, mismatching **`signedMessage`**, etc.).

#### `POST /getMessageToSign` **NEW**
Returns the exact message format that needs to be signed with your Ethereum wallet (`personal_sign`, EIP-191) for management API requests. The signature must be from the NodeMgtKey address.

**Request Body:**
Send the request body (without the `sig` field) that you want to sign. For example, for a `keyGenRequest`:
```json
{
  "nonce": 1,
  "clientPk": "08caf50811eb4c2bed7b3f8dc9c292b5cf521ba3774ea49dcd949e8235a48b22e8c1f16b356710aae4095e498bfff8385eada1e53a47dbdd984d32ae4d20a5de",
  "threshold": 2,
  "groupId": "566633a647306335d3ad6ab49829dcfad9abe1f4d1275e4ea3c3f8c292e20ee9",
  "msgCheck": "multi-agree",
  "keyType": "secp256k1"
}
```

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": {
    "messageToSign": "{\"nonce\":1,\"clientPk\":\"08caf50811eb4c2bed7b3f8dc9c292b5cf521ba3774ea49dcd949e8235a48b22e8c1f16b356710aae4095e498bfff8385eada1e53a47dbdd984d32ae4d20a5de\",\"threshold\":2,\"groupId\":\"566633a647306335d3ad6ab49829dcfad9abe1f4d1275e4ea3c3f8c292e20ee9\",\"msgCheck\":\"multi-agree\",\"keyType\":\"secp256k1\"}",
    "nodeMgtKey": "0x1234567890ABCDEF1234567890ABCDEF12345678",
    "currentNonce": 1,
    "signingInstructions": "Sign this message using personal_sign (EIP-191) from your Ethereum wallet. The signature must be from the NodeMgtKey address. You may use eth_signTypedData or personal_sign, depending on your wallet.",
    "example": {
      "javascript": "const message = '...'; const signature = await ethereum.request({ method: 'personal_sign', params: [message, account] });",
      "web3js": "const signature = await web3.eth.personal.sign(message, account);"
    }
  }
}
```

**Example:**
```bash
curl -X POST $MPC_AUTH_URL:$MANAGEMENT_PORT/getMessageToSign \
  -H "Content-Type: application/json" \
  -d '{
    "nonce": 1,
    "clientPk": "08caf50811eb4c2bed7b3f8dc9c292b5cf521ba3774ea49dcd949e8235a48b22e8c1f16b356710aae4095e498bfff8385eada1e53a47dbdd984d32ae4d20a5de",
    "threshold": 2,
    "groupId": "566633a647306335d3ad6ab49829dcfad9abe1f4d1275e4ea3c3f8c292e20ee9",
    "msgCheck": "multi-agree",
    "keyType": "secp256k1"
  }'
```

### Using an Ethereum wallet or Ed25519 for Management API Authentication

Management API endpoints (like `/keyGenRequest`, `/keyGenRequestRetry`, `/newGroupRequest`, `/newGroupRequestRetry`, `/presignRequest`, etc.) require authentication. The node accepts **either** of the following:

- **NodeMgtKey (Ethereum wallet)**: Ethereum address in config; sign with `personal_sign` (EIP-191).
- **PublicMgtKey (Ed25519)**: Bootstrap **`PublicMgtKey`** in config plus keys added via **`POST /addManagementKey`** (and soft-removed via **`POST /removeManagementKey`** for **Added key N** rows only — see headings). Typical management POST bodies use **`sig`**; **add**/ **remove extra Ed25519 management keys** also accept **`signedMessage` + `clientSig`** (**EIP‑191** from **`NodeMgtKey`**) alongside the **`sig`** (Ed25519) path — canonical JSON documented under each endpoint (**Swagger**: **`#/definitions/node.AddManagementKeyPost`**, **`RemoveManagementKeyPost`**).

You only need one. If both are configured, either signature type is accepted.

---

#### Using NodeMgtKey (Ethereum wallet)

**How it works:**
1. The request body (excluding the `sig` field) is JSON-marshaled to create a message string
2. This message is signed using Ethereum's personal_sign format (EIP-191): `"\x19Ethereum Signed Message:\n<length><message>"`
3. The signature is verified by recovering the address from the signature and comparing it to `NodeMgtKey`
4. The signature must be from the same address as `NodeMgtKey`

**Steps to sign with your Ethereum wallet:**

1. **Get the NodeMgtKey and current nonce:**
   ```bash
   curl $MPC_AUTH_URL:$MANAGEMENT_PORT/getNodeMgtKey
   curl $MPC_AUTH_URL:$MANAGEMENT_PORT/getNodeMgtKeyNonce
   ```

2. **Get the message to sign** (optional, but helpful):
   ```bash
   curl -X POST $MPC_AUTH_URL:$MANAGEMENT_PORT/getMessageToSign \
     -H "Content-Type: application/json" \
     -d '{...your request body without "sig"...}'
   ```

3. **Sign with Ethereum wallet `personal_sign`:**
   ```javascript
   // In your dApp/frontend
   const message = '{"nonce":1,"clientPk":"...","threshold":2,...}';
   const account = '0x1234567890ABCDEF1234567890ABCDEF12345678'; // Must match NodeMgtKey
   
   // Browser wallet (e.g. EIP-1193 provider)
   const signature = await ethereum.request({
     method: 'personal_sign',
     params: [message, account]
   });
   
   // Or using web3.js
   const signature = await web3.eth.personal.sign(message, account);
   ```

4. **Include the signature in your API request:**
   ```bash
   curl -X POST $MPC_AUTH_URL:$MANAGEMENT_PORT/keyGenRequest \
     -H "Content-Type: application/json" \
     -d '{
       "nonce": 1,
       "sig": "0x...",  # Signature from your Ethereum wallet
       "clientPk": "...",
       ...
     }'
   ```

**Important Notes:**
- The signature must be from the **same address** as `NodeMgtKey` (configured in `configs.yaml`)
- The message to sign is the **JSON string** of the request body (without the `sig` field)
- The signature format is Ethereum's `personal_sign` (EIP-191), as implemented by typical Ethereum wallets
- Each request requires a unique nonce (obtained from `/getNodeMgtKeyNonce`)
- The nonce increments automatically after each successful request

---

#### Using Ed25519 (PublicMgtKey)

When the node has `PublicMgtKey` configured (check with `GET /hasPublicMgtKey`), you can authenticate management API requests with an Ed25519 key pair instead of an Ethereum wallet. This allows scripts and backends to manage the node without a browser.

**How it works:**
1. The request body (excluding the `sig` field) is JSON-marshaled to produce the **exact message string** to sign. **Do not** add the EIP-191 prefix; sign the raw JSON string.
2. Sign that string with your Ed25519 private key. Signature must be 64 bytes (128 hex characters).
3. Put the signature in the `sig` field (hex string, optional `0x` prefix). The node detects Ed25519 by signature length (128 hex chars) and verifies with one of the allowed Ed25519 keys (config `PublicMgtKey` or keys added via `addManagementKey`).
4. Use the nonce from `GET /getPublicMgtKeyNonce` or `GET /getPublicMgtKeyNonce?publicKey=<your_key>` (each key has its own nonce sequence).

**Steps:**

1. **Check that the node accepts Ed25519 and get nonce:**
   ```bash
   curl $MPC_AUTH_URL:$MANAGEMENT_PORT/hasPublicMgtKey    # must be true
   curl $MPC_AUTH_URL:$MANAGEMENT_PORT/getPublicMgtKeyNonce
   ```

2. **Build the request body** (include `nonce`, omit `sig`), then produce the **exact** JSON string (byte-for-byte, e.g. no extra spaces). Sign that string with Ed25519.

3. **Example (Go):**
   ```go
   // message = exact JSON string of request body without "sig"
   message := `{"nonce":1,"clientPk":"...","threshold":2,"groupId":"...","msgCheck":"multi-agree","keyType":"secp256k1"}`
   sigBytes := ed25519.Sign(privKey, []byte(message))
   sigHex := hex.EncodeToString(sigBytes) // 128 hex chars
   // POST body: same JSON with "sig": "<sigHex>"
   ```

4. **Example (curl):**
   ```bash
   curl -X POST $MPC_AUTH_URL:$MANAGEMENT_PORT/keyGenRequest \
     -H "Content-Type: application/json" \
     -d '{"nonce":1,"sig":"<128-hex-char-ed25519-sig>","clientPk":"...",...}'
   ```

**Important Notes:**
- Message to sign is the **raw** request body JSON string (no `\x19Ethereum Signed Message:\n` prefix).
- Signature must be **64 bytes**, encoded as **128 hex characters** (optional `0x` prefix).
- Allowed Ed25519 keys are the config `PublicMgtKey` (64 hex) plus any added via `POST /addManagementKey`.
- Nonce is from `/getPublicMgtKeyNonce` (or `?publicKey=<key>` for added keys); each key has its own nonce sequence, separate from NodeMgtKey.

<a id="get-getallowedkeytypes"></a>
#### `GET /getAllowedKeyTypes`
Returns list of allowed key types supported by the node.

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": ["secp256k1", "ed25519", "bitcoin-taproot"]
}
```

**Example:**
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getAllowedKeyTypes"
```

**Key Types:**
- `secp256k1`: EVM ECDSA (CGGMP24 MPC); also yields Bitcoin P2WPKH derived addresses
- `ed25519`: FROST Schnorr (givre) — Solana, Stellar/Soroban, NEAR, TON, Sui, etc.
- `bitcoin-taproot`: FROST BIP-340 Taproot key-path (givre); **`bc1p…`** P2TR when derivable

Nodes only accept key types listed in **`AllowedKeyTypeList`** in `configs.yaml`. FROST types require a **`-tags rust`** mpc-auth image with givre FFI linked.

**Example `configs.yaml` (all three types enabled):**
```yaml
AllowedKeyTypeList:
  - "secp256k1"
  - "ed25519"
  - "bitcoin-taproot"
```

After changing `AllowedKeyTypeList`, restart the node so `GET /getAllowedKeyTypes` and `POST /keyGenRequest` pick up the new list. To use Bitcoin Taproot in Multi-Sign Compose, create a **multi-agree** KeyGen with `keyType: "bitcoin-taproot"` (separate from `ed25519`, which targets Solana/Sui/NEAR-style chains).

<a id="get-getallowedmsgchecktypes"></a>
#### `GET /getAllowedMsgCheckTypes`
Returns list of allowed message check types for key generation and signing operations.

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": ["multi-agree", "single-agree"]
}
```

**Example:**
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getAllowedMsgCheckTypes"
```

**Message Check Types:**
- `multi-agree`: Requires agreement from multiple nodes (default)
- `single-agree`: Requires agreement from a single node

<a id="get-getsuccessrate"></a>
#### `GET /getSuccessRate`
Returns node success rate statistics for keygen and signing operations. Counts total requests and successful results across all groups this node participates in.

**Query Parameters:**
- `hours` (optional, integer): Time window in hours to filter statistics. If provided, only counts requests and results within the specified time window. If omitted or set to 0, returns statistics for all time.

**Examples:**
- `GET /getSuccessRate` - Returns statistics for all time
- `GET /getSuccessRate?hours=24` - Returns statistics for the last 24 hours
- `GET /getSuccessRate?hours=168` - Returns statistics for the last week (168 hours)

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": {
    "keygen": {
      "total": 100,
      "success": 95,
      "failed": 5,
      "successRate": 0.95
    },
    "signing": {
      "total": 500,
      "success": 490,
      "failed": 10,
      "successRate": 0.98
    }
  }
}
```

**Field Descriptions:**
- `keygen.total`: Total number of keygen requests across all groups
- `keygen.success`: Number of successful keygen operations (KeyGenResult with savedata and pubkeyhex)
- `keygen.failed`: Number of failed keygen operations (total - success)
- `keygen.successRate`: Success rate as a decimal (0.0 to 1.0)
- `signing.total`: Total number of signing requests across all groups (excludes test transactions)
- `signing.success`: Number of successful signing operations (SignResult with sigdata or sigr/sigs, excludes test transactions)
- `signing.failed`: Number of failed signing operations (total - success)
- `signing.successRate`: Success rate as a decimal (0.0 to 1.0)

**Note:** Test transactions (identified by `IsTestTransaction = true`, which occurs when `SourceTxHash` or `SourceChainID` is empty) are excluded from all signing statistics to provide accurate production transaction success rates. For backwards compatibility, records without the `IsTestTransaction` field are treated as real transactions (not test transactions).

**Note:** Test transactions (identified by empty `SourceTxHash`) are excluded from all signing statistics to provide accurate production transaction success rates.

**Example:**
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getSuccessRate"
```

**Notes:**
- Statistics are aggregated across all groups this node participates in
- Success is determined by the presence of a result with valid data (savedata for keygen, sigdata/sigr/sigs for signing)
- Failed operations are calculated as: `total - success`
- If no requests exist, success rate will be 0.0

**Example:**
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getSuccessRate"
```

<a id="get-getpresigningverificationstatus"></a>
#### `GET /getPreSigningVerificationStatus`
Returns the status and configuration of pre-signing verification.

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": {
    "enabled": true,
    "relayerAPIURL": "http://82.208.20.136:8080",
    "verificationMode": "strict"
  }
}
```

**Example:**
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getPreSigningVerificationStatus"
```

<a id="get-getclientsigstatus"></a>
#### `GET /getClientSigStatus`
Returns whether client signature verification is ignored (`IgnoreClientSigCheck`). When `true`, client signatures during MPC coordination are not verified; should be `false` in production.

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": {
    "ignoreClientSigCheck": true
  }
}
```

**Example:**
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getClientSigStatus"
```

<a id="get-getsubscriptions"></a>
#### `GET /getSubscriptions`
Returns information about all current MQTT topic subscriptions.

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": [
    {
      "groupId": "566633a647306335d3ad6ab49829dcfad9abe1f4d1275e4ea3c3f8c292e20ee9",
      "brokers": ["ssl://82.180.145.77:8883"],
      "topics": ["566633a647306335d3ad6ab49829dcfad9abe1f4d1275e4ea3c3f8c292e20ee9", "1711c3077fc974b538fe6a786aae141f35f07e0ae7a91e89ebd1aed67f16846f..."],
      "clientId": "1711c3077fc974b538fe6a786aae141f35f07e0ae7a91e89ebd1aed67f16846f...",
      "isConnected": true
    }
  ]
}
```

**Example:**
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getSubscriptions"
```

<a id="get-getmqttkey"></a>
#### `GET /getMSQTTKey`

Returns the MQTT broker TLS CA certificate as PEM text.

**`data`:** `{ "path", "caCertPem" }`. **Error** if the file is missing.

**Resolved `path` (in order):** env **`MQTT_BROKER_CA_HOST_PATH`**; **`MQTTTLS.CAFile`** from merged config (including **`MQTT_TLS_CA_FILE`**); else **`mosquitto/config/certs/ca.crt`** relative to the process working directory.

**JWT:** On Browser HTTPS / loopback read listeners, **`GET`** requires a bearer token—see [Browser HTTPS and loopback HTTP (JWT)](#browser-https-and-loopback-http-jwt). Plain **`ManagementAPIsPort`** does not apply JWT to this route.

**Response (`code === 0`):**
```json
{
  "code": 0,
  "error": "",
  "data": {
    "path": "/mosquitto/config/certs/ca.crt",
    "caCertPem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"
  }
}
```

**Examples:**
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getMSQTTKey"
curl -H "Authorization: Bearer <JWT>" "https://localhost:8443/getMSQTTKey"
```

<a id="get-getwebtlskey"></a>
#### `GET /getWebTLSKey`

Returns the Browser HTTPS server certificate as PEM text (the public certificate used for TLS on the browser-facing HTTPS listener, typically **`browser.crt`**).

**`data`:** `{ "path", "certPem" }`. **Error** if the file is missing.

**Resolved `path` (in order):** env **`WEB_TLS_BROWSER_CRT_HOST_PATH`**; **`BrowserHTTPS.CertFile`** from merged `configs.yaml` when non-empty (e.g. **`/webTLS/config/certs/browser.crt`** in Docker); else **`webTLS/config/certs/browser.crt`** relative to the process working directory.

**JWT:** On Browser HTTPS / loopback read listeners, **`GET`** requires a bearer token—see [Browser HTTPS and loopback HTTP (JWT)](#browser-https-and-loopback-http-jwt). Plain **`ManagementAPIsPort`** does not apply JWT to this route.

**Response (`code === 0`):**
```json
{
  "code": 0,
  "error": "",
  "data": {
    "path": "/path/to/webTLS/config/certs/browser.crt",
    "certPem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"
  }
}
```

**Examples:**
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getWebTLSKey"
curl -H "Authorization: Bearer <JWT>" "https://localhost:8443/getWebTLSKey"
```

<a id="post-postmqttkey"></a>
#### `POST /postMSQTTKey`

**Auth:** Management key (`clientSig`), same family as **`POST /postChainDetails`**. Sign the **`caCertPem`** bytes (opaque PEM, not JSON). Include **`nonce`**, **`clientSig`**, and **`nodeKey`** (128 hex from `GET /getNodeKey`) in the JSON body. **`caCertPem`:** valid X.509 **CERTIFICATE** PEM, max **512 KiB**.

**`data` on success:** `{ "path", "message" }` (e.g. `"MQTT broker CA PEM written"`). Write is atomic; parent directories may be created. Service reload is **not** automatic.

**Example JSON body:**

```json
{
  "nonce": 0,
  "clientSig": "0x... or 128-hex Ed25519",
  "nodeKey": "<128-hex from GET /getNodeKey>",
  "caCertPem": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n"
}
```

**Example:**
```bash
curl -X POST "$MPC_AUTH_URL:$MANAGEMENT_PORT/postMSQTTKey" \
  -H "Content-Type: application/json" \
  -d '{"nonce":0,"clientSig":"...","nodeKey":"<128-hex>","caCertPem":"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"}'
```

**Why `configUpdatePlan` and `configUpdateImplement`?** mpc-auth uses two steps on purpose:

1. **Preview before write** — The plan returns **`plannedYaml`** and **`preview`** but does **not** merge into **`configs.yaml`**. Review derived **`mqttBroker`**, peer URLs, and **`implementSignSteps`**; abandon if incorrect.
2. **Sign a short binding** — Implement signs **`plannedShaMessage`** (`configUpdateImplement|` + SHA-256 of **`plannedYaml`**), binding the approval to exact bytes without signing a large YAML file in a wallet.
3. **Current keys vs. extra proofs** — **Implement** verifies **`clientSig`** against **on-disk** **`NodeMgtKey`** / allowed Ed25519 keys. When the plan adds the **first** **`PublicMgtKey`**, **`rotationPublicMgtKeyClientSig`** is required (Ed25519 from that new key). **`rotationNodeMgtKeyClientSig`** is **optional**: if supplied when **`NodeMgtKey`** changes, it must verify as **`personal_sign(signedMessage)`** from the **new** Ethereum address (callers may omit it when **`clientSig`** already proves control, e.g. Ed25519-only tooling).
4. **Apply boundary** — Backup, merge, and optional compose run only on successful **implement**.

<a id="post-configupdateplan"></a>
#### `POST /configUpdatePlan`

**Auth:** `VerifyMgtKeySig` over the **canonical JSON** of the request body with **`sig` set to the empty string** (then compare to **`sig`** in the body)—same pattern as **`POST /newGroupRequest`**. Uses **`configs.yaml` on disk** for **`NodeMgtKey`** / allowed Ed25519 keys when **`IgnoreMgtKeySigCheck`** is false.

**Body (mpc-auth `ConfigUpdatePlanPost`):**

| Field | Role |
|-------|------|
| `nonce`, `sig` | Required for signed requests (unless sig check ignored). |
| `nodeMgtKey` | Optional. New Ethereum **`NodeMgtKey`** (checksum address). |
| `publicMgtKey` | Optional **only if** `PublicMgtKey` is **currently empty** in `configs.yaml` (first bootstrap). Otherwise use **`POST /addManagementKey`**. Value: 64-hex Ed25519 public key or `ssh-ed25519` line. |
| `MSQTTRelayIP` | Required when **`nodeAddresses`** is non-empty. Must be the **relay** host (same as the **first** entry in `nodeAddresses` after ordering). |
| `nodeAddresses` | Optional string array of peer **public** hostnames/IPs (order: relay first). Forbidden: doc-example IPs **203.0.113.10–12**, loopback/private per server validation. |
| `managementHttpPort` | Optional; default = current **`ManagementAPIsPort`** (or 8080). Used in generated `http://host:port` management URLs. |

**Validation:** At least one of `nodeMgtKey`, `publicMgtKey`, `MSQTTRelayIP`, `nodeAddresses`, or `managementHttpPort` must be set. **`MSQTTRelayIP` is required whenever `nodeAddresses` is non-empty.**

**What the plan changes in YAML:**

- **`nodeMgtKey`** → top-level `NodeMgtKey`.
- **`publicMgtKey`** → top-level `PublicMgtKey` (bootstrap only).
- **`MSQTTRelayIP` + `nodeAddresses`** → **`MPCGroups[0].nodeAddresses`**: map `node001_key` … `node00N_key` → `http://<host>:<managementHttpPort>` (relay = first host), and **`MPCGroups[0].mqttBroker`** → `ssl://<first-host>:8883` (TLS MQTT to relay). This is the **configured peers** list; **`GET /getConfiguredNodeKeys`** probes those URLs (plus **`getNodeKey`** on discovery/management ports)—it does **not** have its own POST; change peers via this plan.

**Response `data`:** `configsPath`, `planTempPath`, **`plannedYaml`** (full YAML text), **`plannedShaMessage`** = `configUpdateImplement\|<sha256-hex-of-plannedYaml>`, **`preview`** (human-readable diff hints, `mqttBrokerRelay`, `nodeAddressUrlsOrdered`, **`implementSignSteps`**, etc.).

**Examples (plan body only—fill `sig` with your wallet/tool):**

**Example 1 — Change `NodeMgtKey`:** implement requires only a valid **`clientSig`** over **`plannedShaMessage`** from an authorized management key (existing **`NodeMgtKey`** or allowed Ed25519). **`rotationNodeMgtKeyClientSig`** is optional extra proof from the new Ethereum address if you choose to send it.

```json
{
  "nonce": 1,
  "sig": "0x…",
  "nodeMgtKey": "0xYourNewManagementAddress…"
}
```

**Example 2 — Set bootstrap `PublicMgtKey`** (only when it is still empty in `configs.yaml`); implement requires **`rotationPublicMgtKeyClientSig`** from that Ed25519 key.

```json
{
  "nonce": 2,
  "sig": "0x…",
  "publicMgtKey": "<64-hex-ed25519-public>"
}
```

**Example 3 — Relay, peer management URLs, and MQTT broker:** there is no separate `mqttBroker` field in the POST; the server sets **`MPCGroups[0].mqttBroker`** to `ssl://<first-host>:8883` when you pass **`MSQTTRelayIP`** and **`nodeAddresses`** (relay first).

```json
{
  "nonce": 3,
  "sig": "0x…",
  "MSQTTRelayIP": "198.51.100.10",
  "nodeAddresses": [
    "198.51.100.10",
    "198.51.100.11",
    "198.51.100.12"
  ],
  "managementHttpPort": 8080
}
```

**Example 4 — Combined:** one plan can include **`nodeMgtKey`** and topology fields; call **`configUpdateImplement`** once, supplying **`clientSig`** and any extra signatures listed in **`preview.implementSignSteps`** (e.g. first-time **`PublicMgtKey`** needs **`rotationPublicMgtKeyClientSig`**).

```json
{
  "nonce": 4,
  "sig": "0x…",
  "nodeMgtKey": "0x…",
  "MSQTTRelayIP": "198.51.100.10",
  "nodeAddresses": ["198.51.100.10", "198.51.100.11"],
  "managementHttpPort": 8080
}
```

**Note:** If `configs.yaml` is missing or empty, the server may seed it from a relay/client template **before** verifying the plan signature, then merge your fields.

<a id="post-configupdateimplement"></a>
#### `POST /configUpdateImplement`

**Auth:** **`clientSig`** is a management signature over **`signedMessage`**, where **`signedMessage` must exactly equal `data.plannedShaMessage`** from the plan response (i.e. prefix **`configUpdateImplement|`** + **64-hex SHA-256** of the **`plannedYaml`** bytes). Verification uses **on-disk** **`NodeMgtKey`** / Ed25519 allow list **before** apply.

**Rotation fields:** **`rotationPublicMgtKeyClientSig`** is **required** when the plan introduces the **first** **`PublicMgtKey`** (was empty in `configs.yaml`). **`rotationNodeMgtKeyClientSig`** is **optional** when **`NodeMgtKey`** changes: if present, it must be **`personal_sign(signedMessage)`** from the **new** Ethereum address; if omitted, **`clientSig`** alone (e.g. Ed25519 from an allowed key) is sufficient. See **`preview.implementSignSteps`** for bootstrap **`PublicMgtKey`** and the primary **`clientSig`** step.

**Body:** `plannedYaml` (**exact** string from **`configUpdatePlan`**), `nonce`, `clientSig`, `nodeKey`, `signedMessage` (opaque `configUpdateImplement|<sha256>` line); **`rotationPublicMgtKeyClientSig`** when bootstrapping Ed25519; **`rotationNodeMgtKeyClientSig`** only if you supply the optional extra proof.

**Example:**

```json
{
  "plannedYaml": "NodeMgtKey: …\nMPCGroups:\n  - …\n",
  "nonce": 10,
  "clientSig": "0x… or 128-hex-ed25519",
  "nodeKey": "<128-hex from GET /getNodeKey>",
  "signedMessage": "configUpdateImplement|<copy data.plannedShaMessage from plan response>",
  "rotationPublicMgtKeyClientSig": "128-hex-ed25519 (only when first PublicMgtKey in plan)",
  "rotationNodeMgtKeyClientSig": "0x… (optional when NodeMgtKey changes)"
}
```

(Omit unused `rotation*` fields. Replace `signedMessage` with the real **`plannedShaMessage`** from your plan response.)

**Response:** Successful merge; **`composeWarning`** may be present. **Restart** the process so in-memory config matches the file.

<a id="get-health"></a>
#### `GET /health` **NEW**
Returns comprehensive health status including MQTT connection, subscriptions, and MongoDB connection.

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": {
    "status": "healthy",
    "timestamp": 1704110400,
    "mqtt": {
      "connected": true,
      "channels": 2,
      "errors": [],
      "warnings": []
    },
    "mongodb": {
      "connected": true,
      "error": ""
    },
    "subscriptions": [
      {
        "groupId": "566633a647306335d3ad6ab49829dcfad9abe1f4d1275e4ea3c3f8c292e20ee9",
        "brokers": ["ssl://82.180.145.77:8883"],
        "topics": ["566633a647306335d3ad6ab49829dcfad9abe1f4d1275e4ea3c3f8c292e20ee9", "1711c3077fc974b538fe6a786aae141f35f07e0ae7a91e89ebd1aed67f16846f..."],
        "clientId": "1711c3077fc974b538fe6a786aae141f35f07e0ae7a91e89ebd1aed67f16846f...",
        "isConnected": true
      }
    ]
  }
}
```

**Health Status Values:**
- `status`: `"healthy"` or `"unhealthy"`
- `mqtt.connected`: `true` if at least one MQTT channel is connected
- `mqtt.channels`: Number of active MQTT channels
- `mqtt.errors`: Array of error messages (if any)
- `mqtt.warnings`: Array of warning messages (if any)
- `mongodb.connected`: `true` if MongoDB connection is healthy
- `mongodb.error`: Error message if MongoDB connection failed

**HTTP status:** Always **`200 OK`** with a JSON body. When the node is unhealthy, **`code`** is **`1`**, **`error`** is non-empty, and **`data.status`** is **`"unhealthy"`** (do not rely on HTTP 503 — browsers and proxies often return a non-JSON body for 503, which breaks JSON consumers).

**Example Usage:**
```bash
# Check node health
curl $MPC_AUTH_URL:$MANAGEMENT_PORT/health

# Response when healthy
{
  "code": 0,
  "error": "",
  "data": {
    "status": "healthy",
    ...
  }
}

# Response when unhealthy
{
  "code": 1,
  "error": "one or more health checks failed",
  "data": {
    "status": "unhealthy",
    "mqtt": {
      "connected": false,
      "errors": ["no MQTT channels connected"]
    },
    ...
  }
}
```

<a id="get-connectivityhealth"></a>
<a id="get-connectivityhealth"></a>
#### `GET /connectivityHealth` **NEW**
Pings all nodes in a group (or all groups if groupId not provided) and reports connectivity status and latency with speed categorization.

**Query Parameters:**
- `groupId` (optional): Specific group ID to check. If not provided, checks all groups this node is part of.
- `timeout` (optional): Timeout in seconds for each ping (default: 5)

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": [
    {
      "groupId": "566633a647306335d3ad6ab49829dcfad9abe1f4d1275e4ea3c3f8c292e20ee9",
      "nodeCount": 3,
      "results": [
        {
          "nodeKey": "1711c3077fc974b538fe6a786aae141f35f07e0ae7a91e89ebd1aed67f16846fea83a3d3b51a0c30d1d908dbf3f5ddfe71e0c03a0a0afa200a1e4cacfe223c3e",
          "responded": true,
          "latencyMs": 45.2,
          "speed": "very_good",
          "error": ""
        },
        {
          "nodeKey": "167b2b7a21bd62d87ad9237f0f103f131469bb9849b238f003e508570f89aa122b64262248c94da97e7f5ddf2a26b3f8a66b810b7d1a81d708d0ed803cee295a",
          "responded": true,
          "latencyMs": 350.8,
          "speed": "good",
          "error": ""
        },
        {
          "nodeKey": "a14ed80f88e0ce9cca05e3e11fe5475430d0908536dfc9584bb4544f5029a271a74b743f3865ce4f5c6e6f0ea3079ed040404bdb366eedd2bac7f460f2db2e1a",
          "responded": false,
          "speed": "",
          "error": "timeout waiting for reply"
        }
      ],
      "summary": {
        "very_good": 1,
        "good": 1,
        "medium": 0,
        "slow": 0,
        "very_slow": 0,
        "no_response": 1
      }
    }
  ]
}
```

**Speed Categories:**
- `very_good`: < 100ms
- `good`: 100-500ms
- `medium`: 500ms-1s
- `slow`: 1-2s
- `very_slow`: > 2s
- `no_response`: No reply within timeout

**Example Usage:**
```bash
# Check connectivity for all groups
curl $MPC_AUTH_URL:$MANAGEMENT_PORT/connectivityHealth

# Check specific group
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/connectivityHealth?groupId=566633a647306335d3ad6ab49829dcfad9abe1f4d1275e4ea3c3f8c292e20ee9"

# Check with custom timeout (10 seconds)
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/connectivityHealth?timeout=10"

# Check specific group with custom timeout
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/connectivityHealth?groupId=566633a647306335d3ad6ab49829dcfad9abe1f4d1275e4ea3c3f8c292e20ee9&timeout=10"
```

**Response Fields:**
- `groupId`: The group ID that was checked
- `nodeCount`: Total number of nodes in the group
- `results`: Array of connectivity results for each node
  - `nodeKey`: The node's public key (128 hex characters)
  - `responded`: `true` if the node responded within timeout
  - `latencyMs`: Response latency in milliseconds (only present if `responded` is `true`)
  - `speed`: Speed category (only present if `responded` is `true`)
  - `error`: Error message if the node didn't respond or ping failed
- `summary`: Count of nodes by speed category

**Notes:**
- The endpoint pings nodes individually to measure per-node latency
- Self-ping (current node) always returns `very_good` with 0ms latency
- Nodes that don't respond within the timeout are marked with `responded: false` and included in `no_response` count
- If no groups are found, returns an error response

<a id="get-getlogs"></a>
#### `GET /getLogs` **NEW**
Retrieves log entries from the node's log files for a specified time period.

**Query Parameters:**
- `hours` (optional, number): Number of hours to look back. Default: `12`

**Examples:**
- `GET /getLogs` - Returns logs from last 12 hours
- `GET /getLogs?hours=24` - Returns logs from last 24 hours
- `GET /getLogs?hours=0.5` - Returns logs from last 30 minutes

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": {
    "hours": 12,
    "cutoffTime": "2024-01-01T12:00:00Z",
    "count": 150,
    "logs": [
      {
        "time": "2024-01-01T23:59:59Z",
        "level": "error",
        "msg": "error message",
        ... // All other log fields from logrus
      },
      ...
    ]
  }
}
```

**Implementation Details:**
- Reads current log file and rotated backup files (up to 100 backups)
- Log files are parsed as JSON (logrus JSONFormatter)
- Filters entries by timestamp (only returns entries after cutoff time)
- Results are sorted by time (newest first)
- Supports both RFC3339 and RFC3339Nano time formats
- Handles missing log files gracefully
- Skips invalid JSON lines

**Error Responses:**
- `400 Bad Request`: Invalid `hours` parameter (must be positive number)
- `500 Internal Server Error`: Failed to read log files

### 2. Node Registration

<a id="post-noderegister"></a>
#### `POST /nodeRegister`
One-time registration of the node. Requires a `NodeMgtKey` signature; rejected if the node is already registered. Relayer authorization is handled separately via the RelayerWhitelist (e.g. auto-registration from RelayerAPIURL at management startup or `POST /admin/registerRelayer`).

**Note:** This endpoint automatically calls `getMachineInfo` with `refresh=true` to populate `vpsProvider`, `ramGB`, and `cpuCores` from the machine's actual hardware/VPS information. User-provided values for these fields will be ignored if machine info is successfully retrieved.

Request body (NodeRegisterRequest):
```json
{
  "nodeName": "my-node-name",
  "forumHandle": "telegram_or_x_handle",
  "forumType": "Telegram|X",
  "email": "operator@example.com",
  "vpsProvider": "aws|gcp|azure|self-hosted|...",
  "ramGB": 16,
  "cpuCores": 8,
  "didType": "optional",
  "did": "optional",
  "nodeMgtKeySig": "<signature over request payload>",
  "nonce": 1
}
```

**Field Descriptions:**
- `nodeName` (required): Node name, at least 6 characters
- `forumHandle` (required): Telegram or X handle
- `forumType` (required): "Telegram" or "X"
- `email` (required): Email address
- `vpsProvider` (required, but auto-populated): VPS provider (e.g., "AWS EC2", "Google Cloud", "Contabo", "self-hosted", etc.). **Automatically populated from machine info if available.**
- `ramGB` (required, but auto-populated): RAM in GB. **Automatically populated from machine info if available.**
- `cpuCores` (required, but auto-populated): CPU core count. **Automatically populated from machine info if available.**
- `didType` (optional): DID type
- `did` (optional): DID identifier
- `nodeMgtKeySig` (required): Signature from NodeMgtKey over the request payload (excluding `nodeMgtKeySig` field)
- `nonce` (required): Current nonce from `/getNodeMgtKeyNonce`

**Field Requirements:**
- `nodeName` (required): String with at least 6 characters

Response:
```json
{ "code": 0, "error": "", "data": "Node registered successfully" }
```

Notes:
- Enforced once; subsequent attempts return "node registration is disabled: node has already been registered."
- No update endpoint is implemented yet (docs mention `updateNodeData`, but it is not present).
- `/getMachineInfo` returns live host stats (CPU/memory/disk) without needing stored metadata.

<a id="get-fetchnodedata"></a>
#### `GET /fetchNodeData`
Fetches node registration data for the current node.

**Query Parameters:**
None. Returns the stored registration data for the current node.

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": {
    "nodeName": "my-node-name",
    "nodeId": "http://192.168.1.10:8080",
    "nodePublicKey": "<128-hex>",
    "nodeMgtKey": "0x...",
    "relayerPublicKey": "",
    "forumHandle": "telegram_or_x_handle",
    "forumType": "Telegram",
    "email": "operator@example.com",
    "vpsProvider": "aws",
    "ramGB": 16,
    "cpuCores": 8,
    "countryCode": "US",
    "didType": "optional",
    "did": "optional",
    "mpcGroups": [...],
    "createdAt": "2024-01-01T00:00:00Z"
  }
}
```

- `relayerPublicKey` in the response is legacy: it may be empty for nodes registered after relayerPublicKey was removed from `POST /nodeRegister`. Relayer authorization is via RelayerWhitelist only.

### Local Chain Config

Chain config details are stored on the local node only (not propagated to other nodes). Used by apps (e.g. continuumdao-node-app) to add custom chain RPC and gas settings per node.

<a id="post-postchaindetails"></a>
#### `POST /postChainDetails`
Stores or updates chain config for one chain on this node. Requires management key signature ([Management signatures (`nonce`, `clientSig`, `nodeKey`)](#management-signatures-nodekey)): marshal the **full request JSON with `clientSig` cleared** and sign that string (Ed25519 128 hex or Ethereum `personal_sign`). Both **Ethereum (`NodeMgtKey`)** and **Ed25519** management keys are supported.

**Request Body (PostChainDetailsPost):**
```json
{
  "nonce": 1,
  "clientSig": "0x... or 128-hex Ed25519",
  "nodeKey": "<128-hex from GET /getNodeKey>",
  "chainName": "Ethereum Mainnet",
  "chainId": "1",
  "rpcGateway": "https://eth.llamarpc.com",
  "explorer": "https://etherscan.io",
  "legacy": false,
  "testnet": false,
  "gasName": "ETH",
  "gasLimit": 21000,
  "baseFee": 30,
  "priorityFee": 2,
  "baseFeeMultiplier": 200,
  "gasPrice": 25,
  "defaultGetSigFeeSpeed": "normal"
}
```

**Field Descriptions:**
- `nonce` (required): Current nonce from `/getNodeMgtKeyNonce` (or `/getPublicMgtKeyNonce` for Ed25519).
- `clientSig` (required): Management signature over canonical JSON with `clientSig` cleared (see [Management signatures](#management-signatures-nodekey)).
- `nodeKey` (required): This node's MPC public key (128 hex from `GET /getNodeKey`); binds the signature to this node.
- `chainName` (required): Human-readable chain name.
- `chainId` (required): Chain ID (number or string in JSON; stored as string).
- `rpcGateway` (required): RPC URL (e.g. HTTPS).
- `explorer` (optional): Blockchain explorer URL (e.g. https://etherscan.io). Must be a valid http or https URL if provided.
- `legacy` (optional): If true, legacy gas model (gas multiplier, optional gasPrice); if false, EIP-1559 (baseFee/priorityFee).
- `testnet` (optional): If true, chain is a testnet; if false, mainnet. Defaults to false when omitted.
- `gasName` (optional): Native gas token symbol (e.g. "ETH", "BNB").
- `gasLimit` (optional): Default gas limit.
- `baseFee` (optional): Default base fee in gwei (EIP-1559). Omit or send `null` to leave unset so the client can refetch (e.g. "Use custom gas config").
- `priorityFee` (optional): Default priority fee in gwei (EIP-1559). Omit or send `null` to leave unset so the client can refetch.
- `baseFeeMultiplier` (optional): EIP-1559 only. Percentage applied to base fee for the base component of `maxFeePerGas` (e.g. 200 = 2× base). Must be ≥ 100 so that `maxFeePerGas ≥ baseFee + maxPriorityFeePerGas`. Omitted or 200 preserves previous default behaviour.
- `gasMultiplier` (optional): Gas multiplier for legacy chains.
- `gasPrice` (optional): Gas price in gwei for legacy chains.
- `defaultGetSigFeeSpeed` (optional): Default fee tier for the Execute tab **Get Sig / Get Sigs** step on this chain: `slow`, `normal`, or `fast` (RPC `eth_feeHistory`–based). Omit on older nodes; clients should treat missing as `normal`. Not used for `advanced` (user-edited gwei).

**Response:**
```json
{ "code": 0, "error": "", "data": "Chain config stored" }
```

**Error Responses:**
- `400 Bad Request`: Missing required fields (chainName, rpcGateway, chainId, nodeKey).
- `401 Unauthorized`: Invalid or missing management key signature / nonce.
- `500 Internal Server Error`: Database error.

**Example (Ethereum wallet flow):**
```bash
# 1. Get nonce and nodeKey
curl -s "$MPC_AUTH_URL:$MANAGEMENT_PORT/getNodeMgtKeyNonce" | jq .data
curl -s "$MPC_AUTH_URL:$MANAGEMENT_PORT/getNodeKey" | jq .data

# 2. Build JSON body (clientSig ""), personal_sign the canonical string, then POST full body with clientSig filled in:
curl -X POST $MPC_AUTH_URL:$MANAGEMENT_PORT/postChainDetails \
  -H "Content-Type: application/json" \
  -d '{
    "nonce": 1,
    "clientSig": "0x...",
    "nodeKey": "<128-hex>",
    "chainName": "Ethereum Mainnet",
    "chainId": "1",
    "rpcGateway": "https://eth.llamarpc.com",
    "legacy": false,
    "testnet": false,
    "gasName": "ETH"
  }'
```

<a id="get-getchaindetails"></a>
#### `GET /getChainDetails`
Returns chain config details stored on this node. Optional query parameter selects a single chain or all chains. Response `data` is either a single object (when `chain_id` is provided) or an array of objects (when omitted). Each object has the following optional fields.

**Response data fields (per chain):**
- `chainId` (string): Chain ID.
- `chainName` (string): Human-readable chain name.
- `rpcGateway` (string): RPC URL (e.g. HTTPS).
- `explorer` (string, optional): Blockchain explorer URL (e.g. https://etherscan.io).
- `legacy` (boolean): If true, legacy gas model; if false, EIP-1559.
- `testnet` (boolean): If true, chain is a testnet; if false, mainnet.
- `gasName` (string, optional): Native gas token symbol (e.g. "ETH", "BNB").
- `gasLimit` (number, optional): Default gas limit.
- `baseFee` (number or null, optional): Default base fee in gwei (EIP-1559). Omitted or `null` when not stored so the client can refetch.
- `priorityFee` (number or null, optional): Default priority fee in gwei (EIP-1559). Omitted or `null` when not stored so the client can refetch.
- `baseFeeMultiplier` (number, optional): EIP-1559 only. Percentage for base component of maxFeePerGas (e.g. 200 = 2× base); must be ≥ 100.
- `gasMultiplier` (number, optional): Gas multiplier for legacy chains (%).
- `gasPrice` (number, optional): Gas price in gwei for legacy chains.
- `defaultGetSigFeeSpeed` (string, optional): `slow` | `normal` | `fast` — default Get Sig(s) fee tier for this chain in continuumdao-node-app. Omitted on legacy stored configs; clients default to `normal`.
- `updatedAt` (string): Last update time (RFC3339).

**Query Parameters:**
- `chain_id` (optional): If set, returns the config for that chain only. If omitted, returns all stored chain configs.

**Response (single chain, when `chain_id` is provided):**
```json
{
  "code": 0,
  "error": "",
  "data": {
    "chainId": "1",
    "chainName": "Ethereum Mainnet",
    "rpcGateway": "https://eth.llamarpc.com",
    "explorer": "https://etherscan.io",
    "legacy": false,
    "testnet": false,
    "gasName": "ETH",
    "gasLimit": 21000,
    "baseFee": 30,
    "priorityFee": 2,
    "baseFeeMultiplier": 200,
    "gasMultiplier": 0,
    "gasPrice": 0,
    "defaultGetSigFeeSpeed": "normal",
    "updatedAt": "2026-02-25T12:00:00Z"
  }
}
```

**Response (all chains, when `chain_id` is omitted):**
```json
{
  "code": 0,
  "error": "",
  "data": [
    {
      "chainId": "1",
      "chainName": "Ethereum Mainnet",
      "rpcGateway": "https://eth.llamarpc.com",
      "explorer": "https://etherscan.io",
      "legacy": false,
      "testnet": false,
      "gasName": "ETH",
      "gasLimit": 21000,
      "baseFee": 30,
      "priorityFee": 2,
      "baseFeeMultiplier": 200,
      "gasMultiplier": 0,
      "gasPrice": 0,
      "defaultGetSigFeeSpeed": "normal",
      "updatedAt": "2026-02-25T12:00:00Z"
    },
    {
      "chainId": "11155111",
      "chainName": "Sepolia",
      "rpcGateway": "https://rpc.sepolia.org",
      "legacy": false,
      "testnet": true,
      "gasName": "ETH",
      "updatedAt": "2026-02-25T12:05:00Z"
    }
  ]
}
```

**Error Responses:**
- `404 Not Found`: When `chain_id` is provided but no config exists for that chain.
- `500 Internal Server Error`: Database error.

**Examples:**
```bash
# Get all chain configs
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getChainDetails"

# Get config for a specific chain
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getChainDetails?chain_id=1"
```

<a id="post-removechaindetails"></a>
#### `POST /removeChainDetails`
Removes the stored chain config for one chain on this node. Requires management key signature (same [`nonce`, `clientSig`, `nodeKey`](#management-signatures-nodekey) pattern as `POST /postChainDetails`).

**Request Body (RemoveChainDetailsPost):**
```json
{
  "nonce": 2,
  "clientSig": "0x... or 128-hex Ed25519",
  "nodeKey": "<128-hex from GET /getNodeKey>",
  "chainId": "1"
}
```

**Field Descriptions:**
- `nonce`, `clientSig`, `nodeKey` (required): Management signature envelope (sign full JSON with `clientSig` cleared).
- `chainId` (required): Chain ID to remove (number or string in JSON).

**Response:**
```json
{ "code": 0, "error": "", "data": "Chain config removed" }
```

**Error Responses:**
- `400 Bad Request`: Missing required fields (e.g. chainId, nodeKey).
- `401 Unauthorized`: Invalid or missing management key signature / nonce.
- `404 Not Found`: No chain config exists for the given chainId.
- `500 Internal Server Error`: Database error.

**Example:**
```bash
curl -X POST $MPC_AUTH_URL:$MANAGEMENT_PORT/removeChainDetails \
  -H "Content-Type: application/json" \
  -d '{
    "nonce": 2,
    "clientSig": "0x...",
    "nodeKey": "<128-hex>",
    "chainId": "1"
  }'
```

### Local Non-EVM Chain Config

Non-EVM chain config is stored on the local node only (not propagated). Used for Solana, NEAR, Sui, TON, and Stellar networks. Identity is **`(chainType, chainId)`** — the same model as [`getTokens`](#get-gettokens) and [`getKnownAddresses`](#get-getknownaddresses). `chainId` is a string network id (e.g. `mainnet-beta` for Solana mainnet, `public` for Stellar).

<a id="post-postnonevmchaindetails"></a>
#### `POST /postNonEvmChainDetails`
Stores or updates non-EVM chain config for one network on this node. Requires management key signature ([`nonce`, `clientSig`, `nodeKey`](#management-signatures-nodekey) — sign full JSON with `clientSig` cleared).

**Request Body (PostNonEvmChainDetailsPost):**
```json
{
  "nonce": 1,
  "clientSig": "0x... or 128-hex Ed25519",
  "nodeKey": "<128-hex from GET /getNodeKey>",
  "chainType": "solana",
  "chainId": "mainnet-beta",
  "chainName": "Solana",
  "rpcGateway": "https://api.mainnet-beta.solana.com",
  "endpointKind": "json-rpc",
  "explorer": "https://solscan.io",
  "testnet": false,
  "nativeSymbol": "SOL",
  "nativeDecimals": 9,
  "signingDefaults": { "commitment": "confirmed" }
}
```

**Field Descriptions:**
- `nonce`, `clientSig`, `nodeKey` (required): Management signature envelope.
- `chainType` (required): One of `solana`, `near`, `sui`, `ton`, `stellar` (stored lowercase).
- `chainId` (required): Network id within `chainType` (string, e.g. `mainnet-beta`, `testnet`, `devnet`, `public`).
- `chainName` (required): Human-readable name (e.g. "Solana", "Solana testnet").
- `rpcGateway` (required): Primary HTTPS endpoint (JSON-RPC, Horizon REST, or TON HTTP depending on `endpointKind`).
- `endpointKind` (required): `json-rpc` | `horizon` | `ton-http`.
- `explorer` (optional): Block explorer base URL.
- `testnet` (optional): `true` for test/dev networks; defaults to `false`.
- `nativeSymbol` (required): Native gas token symbol (e.g. `SOL`, `NEAR`, `XLM`).
- `nativeDecimals` (required): Native token decimals for balance display (e.g. `9` for SOL, `24` for NEAR, `7` for XLM).
- `wsGateway` (optional): WebSocket URL (e.g. Solana subscriptions).
- `tonVendor` (optional): For TON HTTP endpoints: `toncenter` | `tonapi` | `custom`.
- `signingDefaults` (optional): Chain-specific fee/priority defaults for compose/sign (object). Examples: Solana `{ "commitment": "confirmed", "computeUnitLimit": 200000, "priorityFeeMicroLamports": 1000 }`; Stellar `{ "baseFeeStroops": 100 }`.

**Response:**
```json
{ "code": 0, "error": "", "data": "Non-EVM chain config stored" }
```

<a id="get-getnonevmchaindetails"></a>
#### `GET /getNonEvmChainDetails`
Returns non-EVM chain configs stored on this node.

**Query Parameters:**
- `chain_type` (optional): Filter by chain family (e.g. `solana`).
- `chain_id` (optional): Filter by network id within the chain type.

When **both** `chain_type` and `chain_id` are set, returns a single object or **404**. When omitted, returns all matching configs (array).

**Response data fields (per chain):**
- `chainType`, `chainId`, `chainName`, `rpcGateway`, `endpointKind`, `explorer`, `testnet`, `nativeSymbol`, `nativeDecimals`, `wsGateway`, `tonVendor`, `signingDefaults`, `updatedAt`.

**Examples:**
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getNonEvmChainDetails"
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getNonEvmChainDetails?chain_type=solana"
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getNonEvmChainDetails?chain_type=solana&chain_id=mainnet-beta"
```

<a id="post-removenonevmchaindetails"></a>
#### `POST /removeNonEvmChainDetails`
Removes stored non-EVM chain config for one `(chainType, chainId)`. Requires management key signature ([`nonce`, `clientSig`, `nodeKey`](#management-signatures-nodekey)).

**Request Body (RemoveNonEvmChainDetailsPost):**
```json
{
  "nonce": 2,
  "clientSig": "0x... or 128-hex Ed25519",
  "nodeKey": "<128-hex from GET /getNodeKey>",
  "chainType": "solana",
  "chainId": "mainnet-beta"
}
```

**Response:**
```json
{ "code": 0, "error": "", "data": "Non-EVM chain config removed" }
```

### Local Token Config

Token contracts are stored on the local node only (not propagated). Used so the frontend wallet can display and interact with tokens per chain. Supports multiple `chainType` values (e.g. `ethereum`, `solana`, `NEAR`, `stellar`, `TON`) and per-chain `chainId` (integer for Ethereum, string for others; stored as string). Token types for Ethereum include `ERC20`, `ERC721`, `CTMERC20`, `CTMRWA1`; new chain and token types can be added later.

<a id="post-addtoken"></a>
#### `POST /addToken`
Adds a token contract for the given `chainType`, `chainId` and `tokenType`. Requires management key signature ([`nonce`, `clientSig`, `nodeKey`](#management-signatures-nodekey) — sign full JSON with `clientSig` cleared).

**Request Body (AddTokenPost):**
```json
{
  "nonce": 1,
  "clientSig": "0x... or 128-hex Ed25519",
  "nodeKey": "<128-hex from GET /getNodeKey>",
  "chainType": "ethereum",
  "chainId": 1234,
  "tokenType": "ERC20",
  "contract": {
    "contractAddress": "0x1234567890123456789012345678901234567890",
    "name": "My Token",
    "symbol": "MTK",
    "symbolURL": "https://example.com/icon.png"
  }
}
```

**Field Descriptions:**
- `nonce`, `clientSig`, `nodeKey` (required): Management signature envelope.
- `chainType` (required): e.g. `ethereum`, `solana`, `NEAR`, `stellar`, `TON` (stored lowercase for lookup).
- `chainId` (required): Number (Ethereum) or string; normalized to string when stored.
- `tokenType` (required): e.g. `ERC20`, `ERC721`, `CTMERC20`, `CTMRWA1`.
- `contract` (required): Object with at least `contractAddress`. Other fields by token type:
  - **ERC20 / CTMERC20**: `name`, `symbol`, `symbolURL` (optional, can be empty string). Optional `decimals` (number, e.g. 18) for display/formatting; stored and returned by `GET /getTokens`.
  - **ERC721**: `name`, `symbol`, `tokenURI`, and `tokenId` (required; identifies the specific NFT). If the same (contractAddress, tokenId) already exists for that chain/token type, that entry is updated; otherwise a new contract entry is appended.
  - **CTMRWA1**: same as ERC20/ERC721 plus any RWA-specific fields (transfer sigs are set by server).
- `transferSig`, `transferNames` (optional): Used when creating a new token-type entry; omitted for known types (server uses defaults).

**Response:** `{ "code": 0, "error": "", "data": "Token added" }`

**Errors:** `400` missing/invalid fields; `401` invalid signature; `500` database error.

<a id="post-removetoken"></a>
#### `POST /removeToken`
Removes the token contract with the given `contractAddress` for `chainType`, `chainId` and `tokenType`. For **ERC721**, `tokenId` is required so that only the specific (contractAddress, tokenId) entry is removed. Requires management key signature ([`nonce`, `clientSig`, `nodeKey`](#management-signatures-nodekey)).

**Request Body (RemoveTokenPost):**
- `nonce`, `clientSig`, `nodeKey`, `chainType`, `chainId`, `tokenType`, `contractAddress` (all required).
- **`tokenId`** (required for ERC721): The token ID of the NFT to remove. Omit or leave empty for ERC20 and other token types.

Example (ERC20):
```json
{
  "nonce": 2,
  "clientSig": "0x... or 128-hex Ed25519",
  "nodeKey": "<128-hex from GET /getNodeKey>",
  "chainType": "ethereum",
  "chainId": "1234",
  "tokenType": "ERC20",
  "contractAddress": "0x1234567890123456789012345678901234567890"
}
```

Example (ERC721):
```json
{
  "nonce": 2,
  "clientSig": "0x...",
  "nodeKey": "<128-hex>",
  "chainType": "ethereum",
  "chainId": "1234",
  "tokenType": "ERC721",
  "contractAddress": "0x221EC90B3B083A8501A37bdeb7035CeaedF3C31f",
  "tokenId": "18"
}
```

**Response:** `{ "code": 0, "error": "", "data": "Token removed" }`  
**Errors:** `400` missing fields (including `tokenId` for ERC721); `401` invalid signature; `404` token contract not found; `500` database error.

<a id="get-gettokens"></a>
#### `GET /getTokens`
Returns all token configs stored on this node, grouped by `chainType`. Response shape: `{ "ethereum": [ { "chainId": "...", "ERC20": { "transferSig": "...", "transferNames": [...], "contracts": [ { "contractAddress", "name", "symbol", "symbolURL", "decimals"?, ... } ] }, ... }, ... ], "solana": [], ... }`. Each contract in `contracts` includes whatever fields were stored (e.g. `decimals` if provided on addToken).

**Query Parameters:**
- `chainType` (optional): Filter by chain type (e.g. `ethereum`, `solana`).
- `chain_id` (optional): Filter by chain ID.

**Response:** `{ "code": 0, "error": "", "data": { "ethereum": [ ... ], "solana": [ ... ], ... } }`

See `./TOKEN_STORAGE_SCHEMA.md` for the full JSON structure and CTMRWA1 transfer signatures.

### Known Addresses (local node only)

Known addresses are stored on the local node only (not propagated). Each entry is scoped by chain type (e.g. `ethereum`, `solana`) and includes an address, optional `name`, optional `chainIds` (empty = valid on all chains of that type), and `isContract` (false = EOA). See `./KNOWN_ADDRESSES_SCHEMA.md`.

<a id="post-addknownaddress"></a>
#### `POST /addKnownAddress`
Adds or updates a known address for the given `chainType`. Requires management key signature ([`nonce`, `clientSig`, `nodeKey`](#management-signatures-nodekey)).

**Request Body (AddKnownAddressPost):**
```json
{
  "nonce": 1,
  "clientSig": "0x... or 128-hex Ed25519",
  "nodeKey": "<128-hex from GET /getNodeKey>",
  "chainType": "ethereum",
  "address": "0x1234567890123456789012345678901234567890",
  "name": "My Wallet",
  "chainIds": ["1", "137"],
  "isContract": false
}
```

**Field Descriptions:**
- `nonce`, `clientSig`, `nodeKey` (required): Management signature envelope.
- `chainType` (required): e.g. `ethereum`, `solana` (stored lowercase).
- `address` (required): The address; normalized server-side (e.g. lowercase for 0x-prefixed).
- `name` (optional): Display name for the address.
- `chainIds` (optional): Array of chain IDs this address is valid on. **Omit or empty = no restrictions** (valid on all chains of that type).
- `isContract` (optional, default false): `true` = contract address, `false` = EOA.

**Response:** `{ "code": 0, "error": "", "data": "Known address added" }`

**Errors:** `400` missing/invalid fields; `401` invalid signature; `500` database error.

<a id="post-removeknownaddress"></a>
#### `POST /removeKnownAddress`
Removes the known address for the given `chainType` and `address`. Requires management key signature ([`nonce`, `clientSig`, `nodeKey`](#management-signatures-nodekey)).

**Request Body (RemoveKnownAddressPost):**
- `nonce`, `clientSig`, `nodeKey`, `chainType`, `address` (all required).

Example:
```json
{
  "nonce": 2,
  "clientSig": "0x...",
  "nodeKey": "<128-hex>",
  "chainType": "ethereum",
  "address": "0x1234567890123456789012345678901234567890"
}
```

**Response:** `{ "code": 0, "error": "", "data": "Known address removed" }`

**Errors:** `400` missing fields; `401` invalid signature; `404` known address not found; `500` database error.

<a id="get-getknownaddresses"></a>
#### `GET /getKnownAddresses`
Returns all known addresses stored on this node, grouped by chain type. Each entry includes `address`, `name`, `chainIds`, `isContract`, and `updatedAt`. Optional query parameters filter the result set.

**Query Parameters:**
- `chain_type` (optional): Filter by chain type (e.g. `ethereum`, `solana`).
- `chain_id` (optional): Filter by chain ID — only addresses that are valid on this chain are returned (i.e. documents where `chainIds` is empty or contains `chain_id`).
- `is_contract` (optional): Filter by contract flag — `1` = contract addresses only, `0` = EOAs only. Omit to return both.

**Response:** `{ "code": 0, "error": "", "data": { "ethereum": [ { "address": "0x...", "name": "My Wallet", "chainIds": ["1", "137"], "isContract": false, "updatedAt": "..." }, ... ], "solana": [ ... ], ... } }`

See `./KNOWN_ADDRESSES_SCHEMA.md` for the full document shape.

### Agent preferred signer (local node only)

Operators can persist a single **Ed25519 public key** (64 hex) per MPC node process that automation (for example AI agents calling the management API) should treat as the default key when obtaining nonces and signing **management POST** requests. The value is stored in MongoDB on this node only; it is **not** propagated to peers. **`publicKey` must always be an active allowed management key:** the bootstrap **`PublicMgtKey`** from `configs.yaml` or a key added via **`POST /addManagementKey`** that has **not** been soft-removed with **`POST /removeManagementKey`**. **`GET /getPreferredSigner`** (served on **`ManagementAPIsPort`** and **`PublicDiscoveryPort`** when split — see below) returns **`publicKeyHex` only while that stored key is still in the active allow-list** (same definition); if the key was removed or is otherwise no longer allowed, the response uses an empty string.

<a id="get-getpreferredsigner"></a>
#### `GET /getPreferredSigner`

**Where served:** **`ManagementAPIsPort`** and, when **`PublicDiscoveryPort`** is split from it, the same handler on **`PublicDiscoveryPort`** (e.g. **18080**) — see [Public discovery HTTP](#public-discovery-http). **Not** a substitute for `POST /setPreferredSigner` (that remains management-only with signed auth).

**Auth:** None (same class as `GET /getChainDetails`).

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": {
    "publicKeyHex": ""
  }
}
```

- `publicKeyHex`: Lowercase 64-hex Ed25519 public key when a value is stored **and** that key is still an active allowed Ed25519 management key (bootstrap or non-removed added key). **Empty string** when nothing is stored, or when the stored key is no longer allowed (e.g. after `removeManagementKey`).

**Example:**
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getPreferredSigner"
curl "http://localhost:18080/getPreferredSigner"   # when PublicDiscoveryPort is split (e.g. 18080)
```

<a id="post-setpreferredsigner"></a>
#### `POST /setPreferredSigner`

**Auth:** Management key ([`nonce`, `clientSig`, `nodeKey`](#management-signatures-nodekey) — sign full JSON with `clientSig` cleared).

**Request body (SetPreferredSignerPost):**
```json
{
  "nonce": 1,
  "clientSig": "0x... or 128-hex Ed25519",
  "nodeKey": "<128-hex from GET /getNodeKey>",
  "publicKey": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
```

**Validation:**
- `publicKey` (required): **64 hexadecimal characters** (32-byte Ed25519 public key); optional `0x` prefix (stripped server-side). Must pass **`IsValidEd25519PublicKeyHex`** and must be **currently present** in the active Ed25519 management allow-list: **`PublicMgtKey`** from config and/or keys from **`addManagementKey`** that have **not** been removed with **`removeManagementKey`** (see **`GET /getPublicMgtKey`** / **`GET /getAllowedEd25519MgtKeys`** for active keys).
- Invalid length, non-hex, malformed keys, or key not in the allow-list → **`400`**.

**Response:** `{ "code": 0, "error": "", "data": "Preferred signer stored" }`

**Errors:** `400` invalid body, invalid `publicKey`, or `publicKey` not an active allowed Ed25519 management key; `401` invalid management signature; `500` database error.

**Example:**
```bash
curl -X POST "$MPC_AUTH_URL:$MANAGEMENT_PORT/setPreferredSigner" \
  -H "Content-Type: application/json" \
  -d '{"nonce":1,"publicKey":"<64-hex>","clientSig":"...","nodeKey":"<128-hex>"}'
```

### Agent preferred KeyGen (local node only)

Operators can persist a single **multi-agree KeyGen request id** (`requestid`, same value as **`GET /getKeyGenResultById?id=`**) per MPC node process that automation (for example AI agents composing **`POST /multiSignRequest`**) should treat as the default key. The value is stored in MongoDB on this node only; it is **not** propagated to peers. **`keyGenId` must refer to a KeyGen that is eligible for multiSignRequest:** the keygen request must exist with **`MsgCheck`** **`multi-agree`**, the keygen **result** must exist with a non-empty **`pubkeyhex`**, and the result must **not** be **ejected**. **`GET /getPreferredKeyGen`** (served on **`ManagementAPIsPort`** and **`PublicDiscoveryPort`** when split — see below) returns **`keyGenId`**, **`pubKey`**, and **`keyType` only while the stored KeyGen is still eligible**; if the key was ejected, deleted, or is otherwise invalid, the response uses empty strings.

<a id="get-getpreferredkeygen"></a>
#### `GET /getPreferredKeyGen`

**Where served:** **`ManagementAPIsPort`** and, when **`PublicDiscoveryPort`** is split from it, the same handler on **`PublicDiscoveryPort`** (e.g. **18080**) — see [Public discovery HTTP](#public-discovery-http). **Not** a substitute for **`POST /postPreferredKeyGen`** (that remains management-only with signed auth).

**Auth:** None (same class as `GET /getPreferredSigner`).

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": {
    "keyGenId": "",
    "pubKey": "",
    "keyType": ""
  }
}
```

| Field | Notes |
|-------|--------|
| `keyGenId` | KeyGen request id when stored **and** still eligible (multi-agree, non-ejected, public key present). Empty when nothing is stored or the stored id is no longer valid. |
| `pubKey` | **`pubkeyhex`** from the keygen result when eligible; empty otherwise. Agents can pass this as **`pubKey`** on **`POST /multiSignRequest`**. |
| `keyType` | Key type from the keygen request/result (e.g. `secp256k1`, `ed25519`, `bitcoin-taproot`) when eligible; empty otherwise. |

**Example:**
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getPreferredKeyGen"
curl "http://localhost:18080/getPreferredKeyGen"   # when PublicDiscoveryPort is split (e.g. 18080)
```

<a id="post-postpreferredkeygen"></a>
#### `POST /postPreferredKeyGen`

**Auth:** Management key ([`nonce`, `clientSig`, `nodeKey`](#management-signatures-nodekey) — sign full JSON with `clientSig` cleared).

**Request body (PostPreferredKeyGenPost):**
```json
{
  "nonce": 1,
  "clientSig": "0x... or 128-hex Ed25519",
  "nodeKey": "<128-hex from GET /getNodeKey>",
  "keyGenId": "KeyGen20260111003720999cf104d0f"
}
```

**Validation:**
- `keyGenId` (required): KeyGen **request id** (same as [`GET /getKeyGenResultById`](#get-getkeygenresultbyid) `id` query parameter).
- The keygen request must exist with **`MsgCheck`** **`multi-agree`**.
- The keygen **result** must exist on this node with a non-empty public key (**`pubkeyhex`**).
- **Ejected** keys are rejected → **`400`**.

**Response:** `{ "code": 0, "error": "", "data": "Preferred KeyGen stored" }`

**Errors:** `400` invalid body or KeyGen not eligible; `401` invalid management signature; `500` database error.

**Example:**
```bash
curl -X POST "$MPC_AUTH_URL:$MANAGEMENT_PORT/postPreferredKeyGen" \
  -H "Content-Type: application/json" \
  -d '{"nonce":1,"keyGenId":"KeyGen20260111003720999cf104d0f","clientSig":"...","nodeKey":"<128-hex>"}'
```

### Agent LLM config (local filesystem)

Cloud LLM settings for the **node agent** (MCP chat / in-app agent) are stored in a **bind-mounted JSON file** on the host, not in MongoDB. The browser and automation never receive the full API key on read; only the node agent runtime loads the file when calling the model.

| Piece | Value |
|-------|--------|
| **Default host path** | `<compose-project>/agent_llm_config/agent-llm-config.json` (beside **`configs.yaml`**, same layout as **`database_backups/`**) |
| **Container path** | `/app/agent_llm_config/agent-llm-config.json` |
| **Config key** | **`AgentLlmConfigDir`** in **`configs.yaml`** (default **`agent_llm_config`**; relative paths resolve next to **`configs.yaml`**) |
| **Env override** | **`MPC_AUTH_AGENT_LLM_CONFIG_FILE`** (wins over YAML dir resolution) |
| **Docker** | **`./agent_llm_config`** bind-mounted to **`/app/agent_llm_config`** (same pattern as **`database_backups/`**) |
| **Provisioning** | **`process_config.sh`** and **`scripts/provision-node.sh`** set **`AgentLlmConfigDir`**, create **`./agent_llm_config/`**, and set compose env by default; use **`--no-agent-llm-config-path`** or **`PROCESS_CONFIG_SKIP_AGENT_LLM_CONFIG_PATH=1`** to skip |
| **Write** | Atomic temp file + `rename`; file mode **0640**; parent dirs **0755** |
| **Listeners** | **ManagementAPIsPort**, **Browser HTTPS** (`:8443`), **BrowserLoopbackReadHTTP** (SSH tunnel), and plain co-located attach — same route registration as other management APIs |

**Where served:** All three routes are on the attach URL family the wallet UI already uses (`https` / loopback / plain). **`GET /agentLlmConfigStatus`** follows [Browser HTTPS and loopback HTTP (JWT)](#browser-https-and-loopback-http-jwt) on those listeners. **`POST`** routes are **not** JWT-gated; use **management-key signature** like `POST /postChainDetails`.

<a id="get-agentllmconfigstatus"></a>
#### `GET /agentLlmConfigStatus`

**Auth:** On **Browser HTTPS** and **BrowserLoopbackReadHTTP**, **`Authorization: Bearer <read JWT>`** (same RS256 read JWT as other GETs on those listeners). On plain **ManagementAPIsPort** / co-located attach, same rules as other GETs on that listener (no JWT when the port is not JWT-enabled).

**Response `data`:**
```json
{
  "configured": true,
  "provider": "openai",
  "model": "gpt-4.1",
  "baseUrl": null,
  "apiKeyPresent": true,
  "apiKeyMasked": "…4f2a",
  "updatedAt": "2026-05-19T12:00:00.000000000Z"
}
```

| Field | Notes |
|-------|--------|
| `configured` | `true` when `provider` and `model` are non-empty in the file |
| `provider`, `model`, `baseUrl` | Current non-secret fields (`baseUrl` may be `null`) |
| `apiKey` | **Never** returned in full |
| `apiKeyPresent` | `true` when a non-empty key is stored |
| `apiKeyMasked` | Last four characters only, prefixed with `…` (e.g. `…4f2a`) |
| `updatedAt` | RFC3339Nano timestamp from last write |

**Example:**
```bash
curl -H "Authorization: Bearer <JWT>" "https://localhost:8443/agentLlmConfigStatus"
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/agentLlmConfigStatus"   # plain management when no JWT
```

<a id="post-agentllmconfig"></a>
#### `POST /agentLlmConfig`

**Does not include `apiKey`.** Use **`POST /agentLlmApiKey`** to set or clear the secret.

**Auth:** Management key ([`nonce`, `clientSig`, `nodeKey`](#management-signatures-nodekey)). Sign canonical JSON (see below) with `clientSig` cleared.

**Request body (AgentLlmConfigPost):**
```json
{
  "nonce": 42,
  "clientSig": "0x... or 128-hex Ed25519",
  "nodeKey": "<128-hex from GET /getNodeKey>",
  "provider": "openai",
  "model": "gpt-4.1",
  "baseUrl": null
}
```

**Canonical signed bytes:** Server verifies signature over exactly:
```json
{"action":"agentLlmConfig","baseUrl":<string|null>,"clientSig":"","model":"<model>","nonce":<int>,"nodeKey":"<128-hex>","provider":"<provider>"}
```
Field order must match (as produced by the Go marshaller / continuumdao-node-app). `baseUrl` is `null` when omitted or empty.

**Behavior:** Read-merge-write `agent-llm-config.json`; updates `provider`, `model`, `baseUrl` only; **preserves** existing `apiKey` unless **`POST /agentLlmApiKey`** runs.

**Response:** `{ "code": 0, "error": "", "data": { ...same shape as GET /agentLlmConfigStatus... } }`

**Errors:** `400` invalid body or nodeKey mismatch; `401` invalid management signature; `500` filesystem error.

<a id="post-agentllmapikey"></a>
#### `POST /agentLlmApiKey`

**Auth:** Management signature (same as **`POST /agentLlmConfig`** — [`nonce`, `clientSig`, `nodeKey`](#management-signatures-nodekey)).

**Request body (AgentLlmApiKeyPost):**
```json
{
  "nonce": 43,
  "clientSig": "0x... or 128-hex Ed25519",
  "nodeKey": "<128-hex from GET /getNodeKey>",
  "apiKey": "sk-…"
}
```

**Clear key:** Same route with **`"apiKey": ""`** (exact empty string). Whitespace-only values are rejected. There is **no** `DELETE` route.

**Canonical signed bytes:**
```json
{"action":"agentLlmApiKey","apiKey":"<string>","clientSig":"","nonce":<int>,"nodeKey":"<128-hex>"}
```
For clear, `apiKey` in both body and signed JSON is `""`.

**Behavior:** Updates only `apiKey` in the file (merge-write). Agent must not call the LLM until a new key is set after clear.

**Response:** `{ "code": 0, "error": "", "data": { ...status object... } }`

**Example (clear):**
```bash
curl -X POST "$MPC_AUTH_URL:$MANAGEMENT_PORT/agentLlmApiKey" \
  -H "Content-Type: application/json" \
  -d '{"nonce":44,"apiKey":"","clientSig":"...","nodeKey":"<128-hex>"}'
```

<a id="post-agentchat"></a>
#### `POST /agent/chat`

**Auth:** **Read JWT** on Browser HTTPS and loopback read HTTP (same as **`GET /agentLlmConfigStatus`**). Plain **management** port (`ManagementAPIsPort`) has no JWT — trusted co-located / LAN attach only.

**Request body:**
```json
{ "conversationId": "<uuid or empty for new>", "message": "user text" }
```

**Response:** `Content-Type: text/event-stream` — SSE events:

| Event | Data |
|-------|------|
| `meta` | `{ "conversationId", "provider", "model" }` |
| `tools` | `{ "mcpServerUrl", "toolCount", "tools", "error"? }` |
| `tool_call` | `{ "name", "id"?, "arguments"?, "error"? }` |
| `tool_result` | `{ "name", "id"?, "content", "isError"? }` |
| `elicitation` | `{ "conversationId", "elicitationId", "mode", "message", "url"?, "requestedSchema"? }` — browser must **`POST /agent/chat/elicitation`** |
| `token` | `{ "delta": "<text chunk>" }` |
| `done` | `{ "conversationId" }` |
| `cancelled` | `{ "conversationId" }` |
| `error` | `{ "message": "..." }` |

**Feature flag:** When **`EnableMcpChat: false`** in `configs.yaml` (or env **`MPC_AUTH_ENABLE_MCP_CHAT=0`**), chat routes return **403**. **`GET /agentLlmConfigStatus`** includes **`enableMcpChat`**.

**Behavior:** Reads **`agent-llm-config.json`**, streams one assistant turn with optional MCP tool loop. Provider routing:

| `provider` | Default base (if `baseUrl` empty) | HTTP path |
|------------|-----------------------------------|-----------|
| `openai` | `https://api.openai.com/v1` | `{base}/chat/completions` (OpenAI-compatible SSE) |
| `ollama` | `https://ollama.com/api` | `{base}/chat` (Ollama native NDJSON stream) |

Other providers require **`baseUrl`**. If `baseUrl` ends with `/chat`, Ollama native is used; if it ends with `/chat/completions`, OpenAI-compatible is used. Conversation history is persisted under **`{AgentLlmConfigDir}/conversations/`** on the bind mount (survives mpc-auth restarts).

<a id="get-agentchat"></a>
#### `GET /agent/chat`

**Query:** `conversationId` (required)

**Auth:** Read JWT when applicable (see **`POST /agent/chat`**).

**Response:** `{ "code": 0, "data": { "conversationId", "messages": [ { "role", "content", "createdAt" } ] } }`

<a id="post-agentchatcancel"></a>
#### `POST /agent/chat/cancel`

**Auth:** Read JWT when applicable.

**Request body:** `{ "conversationId": "<uuid>" }`

**Response `data`:** `{ "conversationId", "cancelled": true|false }`

<a id="post-agentchatelicitation"></a>
#### `POST /agent/chat/elicitation`

**Auth:** Read JWT when applicable.

**Request body:** `{ "conversationId", "elicitationId", "action": "accept"|"decline"|"cancel", "content"?: { ... } }`

**Behavior:** Unblocks the in-flight **`POST /agent/chat`** stream waiting on MCP **`elicitation/create`**.

<a id="get-agentconversations"></a>
#### `GET /agent/conversations`

**Auth:** Read JWT when applicable.

**Response `data`:** `{ "conversations": [ { "conversationId", "title", "updatedAt", "createdAt" } ] }`

<a id="get-agentconversationsid"></a>
#### `GET /agent/conversations/:id`

Same payload as **`GET /agent/chat?conversationId=`** for the given id.

<a id="delete-agentconversationsid"></a>
#### `DELETE /agent/conversations/:id`

Removes the persisted thread file and index entry.

<a id="get-agentmcptools"></a>
#### `GET /agent/mcp/tools`

**Auth:** Read JWT when applicable (same as **`GET /agentLlmConfigStatus`**).

**Behavior:** mpc-auth connects to the MCP server as an MCP client (`@modelcontextprotocol/go-sdk`), runs **`tools/list`**, and returns summaries. Default server URL from env **`MPC_AGENT_MCP_SERVER_URL`** (`http://continuum-mcp:8446/mcp` in compose). MCP client advertises **elicitation**; **`tools/call`** may trigger **`elicitation/create`** during **`POST /agent/chat`**.

**Response `data`:** `{ "mcpServerUrl", "toolCount", "tools": [ { "name", "title", "description" } ] }`

### 3. Node Tools

<a id="get-getconfigurednodekeys"></a>
#### `GET /getConfiguredNodeKeys`
Returns node public keys for all configured node addresses in `configs.yaml`. Queries each node's `/getNodeKey` endpoint to retrieve their actual public keys.

**Where served:** Registered on the **management** port and **Browser HTTPS** (GET requires JWT on **8443**). **`GET /getNodeKey`** (used to build this response) is on **PublicDiscoveryPort** / management only — see [Public discovery HTTP](#public-discovery-http).

<a id="peer-getnodekey-probes"></a>
**Peer probe transport:** Each peer is queried over **HTTP** in order: **`PublicDiscoveryPort`**, then **`ManagementAPIsPort`** (see [Peer `getNodeKey` probes](#peer-getnodekey-probes)).

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": {
    "nodes": [
      {
        "address": "http://82.180.145.77:8081",
        "available": true,
        "publicKey": "1711c3077fc974b538fe6a786aae141f35f07e0ae7a91e89ebd1aed67f16846fea83a3d3b51a0c30d1d908dbf3f5ddfe71e0c03a0a0afa200a1e4cacfe223c3e"
      },
      {
        "address": "http://82.180.145.78:8081",
        "available": true,
        "publicKey": "167b2b7a21bd62d87ad9237f0f103f131469bb9849b238f003e508570f89aa122b64262248c94da97e7f5ddf2a26b3f8a66b810b7d1a81d708d0ed803cee295a"
      }
    ],
    "nodesMap": {
      "http://82.180.145.77:8081": {
        "address": "http://82.180.145.77:8081",
        "available": true,
        "publicKey": "1711c3077fc974b538fe6a786aae141f35f07e0ae7a91e89ebd1aed67f16846fea83a3d3b51a0c30d1d908dbf3f5ddfe71e0c03a0a0afa200a1e4cacfe223c3e"
      }
    },
    "total": 2,
    "available": 2,
    "unavailable": 0
  }
}
```

**Response Fields:**
- `nodes`: Array of node information, **preserving order from config** (node1_key, node2_key, etc.)
- `nodesMap`: Map of address → node info (for backward compatibility, may be sorted by JSON/jq)
- `publicKey`: The node's actual public key (128 hex characters) - this is the node's unique identifier
- `address`: The node address from `NodeAddresses` in config
- `available`: Whether the node responded successfully

**Important Notes:**
- The `publicKey` values are the **actual node public keys** (128 hex characters), not placeholder keys like "node1_key"
- These `publicKey` values are **NOT the keyList** - they are individual node identifiers
- To create a `keyList` for group creation, extract the `publicKey` values from the `nodes` array in order
- The `nodes` array preserves the order from your config file (sorted by node keys: node1_key, node2_key, etc.)

**Example:**
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getConfiguredNodeKeys"
# Browser HTTPS (JWT required on GET):
curl -H "Authorization: Bearer <JWT>" "https://localhost:8443/getConfiguredNodeKeys"
```

**Use Cases:**
- Get actual node public keys for group creation (extract `publicKey` values to form `keyList`)
- Verify node keys match configuration
- Check which nodes are online and available
- Debug node key mismatches

### 3. Node Ping & Connectivity

<a id="get-connectivityhealth-ping"></a>
#### `GET /connectivityHealth`
See [Node Information Endpoints](#1-node-information-endpoints) section above for detailed documentation.

<a id="get-pingnodesrequest"></a>
#### `GET /pingNodesRequest`
Sends a ping request to specified nodes to test connectivity and measure latency.

**Query Parameters:**
- `nodekey` (array, required): Node keys to ping (128 hex characters each)

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": "Ping20260111003720999cf104d0f"
}
```

**Example:**
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/pingNodesRequest?nodekey=1711c3077fc974b538fe6a786aae141f35f07e0ae7a91e89ebd1aed67f16846fea83a3d3b51a0c30d1d908dbf3f5ddfe71e0c03a0a0afa200a1e4cacfe223c3e&nodekey=167b2b7a21bd62d87ad9237f0f103f131469bb9849b238f003e508570f89aa122b64262248c94da97e7f5ddf2a26b3f8a66b810b7d1a81d708d0ed803cee295a"
```

<a id="get-getpingnodesresultbyid"></a>
#### `GET /getPingNodesResultById`
Retrieves ping results by request ID. Shows which nodes responded and their latency.

**Query Parameters:**
- `id` (required): Ping request ID

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": {
    "requestId": "Ping20260111003720999cf104d0f",
    "results": [
      {
        "nodeKey": "1711c3077fc974b538fe6a786aae141f35f07e0ae7a91e89ebd1aed67f16846fea83a3d3b51a0c30d1d908dbf3f5ddfe71e0c03a0a0afa200a1e4cacfe223c3e",
        "responded": true,
        "latencyMs": 45.2,
        "error": ""
      },
      {
        "nodeKey": "167b2b7a21bd62d87ad9237f0f103f131469bb9849b238f003e508570f89aa122b64262248c94da97e7f5ddf2a26b3f8a66b810b7d1a81d708d0ed803cee295a",
        "responded": false,
        "error": "timeout"
      }
    ]
  }
}
```

**Example:**
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getPingNodesResultById?id=Ping20260111003720999cf104d0f"
```

<a id="get-listpingresults"></a>
#### `GET /listPingResults`
Lists all ping results with filtering and pagination.

**Query Parameters:**
- `filter` (optional): `all`, `pending`, `success` (default: `all`)
- `pagenum` (optional, default: 0): Page number (0-indexed)
- `pagesize` (optional, default: 10): Number of items per page

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": [
    {
      "RequestId": "Ping20260111003720999cf104d0f",
      "Timepoint": "2026-01-11T00:37:20Z",
      "Status": "success"
    }
  ]
}
```

**Example:**
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/listPingResults?filter=all&pagenum=0&pagesize=10"
```

<a id="get-getinactivenodes"></a>
#### `GET /getInactiveNodes`
Gets a list of inactive nodes (nodes that haven't responded to pings recently).

**Query Parameters:**
- `groupId` (optional): Specific group ID to check. If not provided, checks all groups.

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": [
    {
      "nodeKey": "167b2b7a21bd62d87ad9237f0f103f131469bb9849b238f003e508570f89aa122b64262248c94da97e7f5ddf2a26b3f8a66b810b7d1a81d708d0ed803cee295a",
      "groupId": "566633a647306335d3ad6ab49829dcfad9abe1f4d1275e4ea3c3f8c292e20ee9",
      "lastSeen": "2026-01-10T12:00:00Z",
      "inactiveDuration": "24h"
    }
  ]
}
```

**Example:**
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getInactiveNodes"
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getInactiveNodes?groupId=566633a647306335d3ad6ab49829dcfad9abe1f4d1275e4ea3c3f8c292e20ee9"
```

### 5. Group Management

Groups can be created in two ways:
1. **Pre-configured** in `configs.yaml` (automatically created on node startup)
2. **Via API** using `POST /newGroupRequest` (dynamic creation)

<a id="post-newgrouprequest"></a>
#### `POST /newGroupRequest`
Creates a new MPC group request. **Requires management key authentication.**

**Request Body:**
```json
{
  "keyList": ["node1_pubkey", "node2_pubkey", "node3_pubkey"],
  "BrokerArray": ["ssl://82.180.145.77:8883"],  // Optional - see auto-derivation below
  "nonce": 1,
  "sig": "..."
}
```

**Field Descriptions:**
- `keyList` (required): Array of node public keys (128 hex characters each) that will form the group
- `BrokerArray` (optional): Array of MQTT broker addresses for the group. If omitted, will be auto-derived from `configs.yaml` (see below)
- `nonce` (required): Current nonce from `/getNodeMgtKeyNonce`
- `sig` (required): Management key signature over the request body (excluding `sig` field)

**BrokerArray Auto-Derivation:**
If `BrokerArray` is omitted or empty, the system will attempt to derive it from `configs.yaml`:
1. Searches for a matching `MPCGroupConfig` with the same `keyList`
2. Uses `mqttBroker` if explicitly set in the config
3. Otherwise derives from `nodeAddresses` (first node's IP with `ssl://<ip>:8883`)
4. If no match is found, returns an error requiring explicit `BrokerArray`

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": "NewGroup20241228123456789abc123"
}
```

The `data` field contains the `requestId` which can be used to track the group creation.

**Workflow:**
1. Initiator calls `POST /newGroupRequest` with `keyList` and optional `BrokerArray`
2. System registers relay channels and sends `NEWGROUPREQUEST` messages to all nodes
3. Other nodes can see the request via `GET /listNewGroupRequests`
4. **Optional recovery:** If a peer never received the MQTT `NEWGROUPREQUEST` (e.g. transient broker loss after pings succeeded), the **initiator** may call [`POST /newGroupRequestRetry`](#post-newgrouprequestretry) with that peer’s public key to republish the same `requestId` (see guards in that section).
5. Each node calls `POST /newGroupRequestAgree` to agree
6. When all nodes agree, group is created and nodes subscribe to the broker
7. Check results via `GET /getGroupResultById` (deprecated alias: `GET /getNewGroupResultById`)

**Persistence:** Each node stores at most one `NewGroup` document per `requestid` (upsert on save, plus a unique index on `requestid` when the database allows it). Duplicate MQTT deliveries of the same `NEWGROUPREQUEST` do not create duplicate rows; the node **merges** `SigList` on re-delivery so locally recorded peer signatures are not dropped. The initiator is stored as **`MsgPb.From`** on that document; list/get new-group request APIs return it as **`originator`**.

<a id="newgroup-request-status-values"></a>
**New group request `status` (stored on `MsgPb` in the `NewGroup` collection):**

| Value | Meaning |
|--------|---------|
| **`pending`** | Waiting for more nodes to sign the key list. Set on initial save and while replies are merged but the request is not yet in a terminal success state. Empty/missing status in legacy data is treated as **`pending`** in APIs. |
| **`agree`** | Agreement succeeded: all keys in `KeyList` have signatures recorded, or **`NewGroupRequestConfirmSuccess`** was processed. **`GET /listNewGroupRequests?filter=success`** lists rows where **`status` is `agree`** (the query parameter is named `success`, not a stored value `"success"`). |
| **`failed`** | Terminal failure (e.g. worker timeout, expiry, insufficient **`NewGroupResultConfirmSuccess`** within the window). |

**`GET /listNewGroupRequests` `filter` vs JSON `status`:** `filter=success` → **`status === "agree"`**; `filter=pending` → **`status` is not `agree` and not `failed`**; `filter=failed` → **`status === "failed"`**.

**Error Responses:**
- `400 Bad Request`: Missing required fields, invalid `keyList`, or `BrokerArray` cannot be derived
- `500 Internal Server Error`: Failed to send messages, group already exists, or other internal errors

<a id="get-listnewgrouprequests"></a>
#### `GET /listNewGroupRequests`
Lists all new group requests with filtering and pagination.

**Query Parameters:**
- `filter` (optional): `all`, `pending`, `success`, `failed` (default: `all`). **`success`** matches documents whose stored **`status` is `agree`**; **`pending`** matches non-terminal requests (`status` not `agree` and not `failed`); **`failed`** matches `status === "failed"`. See [New group request `status`](#newgroup-request-status-values).
- `pagenum` (optional, default: 0)
- `pagesize` (optional, default: 10)

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": [
    {
      "RequestId": "NewGroup20241228123456789abc123",
      "NewGroupDataPb": {
        "GroupId": "...",
        "KeyList": ["key1", "key2", "key3"],
        "Addresses": ["http://203.0.113.10:8080", "http://203.0.113.11:8080", "http://203.0.113.12:8080"],
        "SigList": {...},
        "BrokerArray": ["ssl://82.180.145.77:8883"]
      },
      "Timepoint": "2024-12-28T12:34:56Z",
      "status": "pending",
      "originator": "033d741c45434993c6b994eb0b28debe18234188505425f827680a5d2ce82cb7509ea0bec0b652ba4a533d331631c5165e3e1415e378a39c942f0975c8e7d0bf"
    }
  ]
}
```

**Note:** The `Addresses` field contains HTTP API addresses for each node, where `Addresses[i]` corresponds to `KeyList[i]`. Each item includes **`status`** (see [New group request `status`](#newgroup-request-status-values)).

**`originator`:** Node public key (128 hex characters) of the node that initiated the new-group flow—the same value as **`MsgPb.From`** on the stored **`NEWGROUPREQUEST`** document. Omitted when empty (legacy rows). Not to be confused with the `filter` query parameter value **`originator`** on keygen list (see [`GET /listKeyGenRequests`](#get-listkeygenrequests)).

<a id="get-getnewgrouprequestbyid"></a>
#### `GET /getNewGroupRequestById`
Gets a specific group request by ID.

**Query Parameters:**
- `id` (required): Request ID from `newGroupRequest` response

**Response:** Same shape as one element of `GET /listNewGroupRequests` `data`, including **`status`** ([reference](#newgroup-request-status-values)) and **`originator`** (initiator node key; see note under [`GET /listNewGroupRequests`](#get-listnewgrouprequests)).

<a id="post-newgrouprequestretry"></a>
#### `POST /newGroupRequestRetry`
Republishes the same MQTT **`NEWGROUPREQUEST`** (same `requestId`, same key-list payload shape as the initial send) to **one** peer’s topic. **Requires management key authentication.** Intended for recovery when a ping passed but a peer never applied the first message.

**Caller:** Only the **originator** of the request (the node whose key equals **`MsgPb.From`** / **`originator`** for that `requestId`) may call this; use the **`$MPC_AUTH_URL:$MANAGEMENT_PORT`** of that node.

**Request Body:**
```json
{
  "requestId": "NewGroup20241228123456789abc123",
  "targetNodeKey": "128_hex_node_public_key_of_peer",
  "nonce": 1,
  "sig": "..."
}
```

**Field Descriptions:**
- `requestId` (required): Existing new-group request id returned from `POST /newGroupRequest`.
- `targetNodeKey` (required): Public key (128 hex) of the peer that must receive the retry; must appear in the stored request’s `KeyList`, and must **not** be the originator (the originator does not consume `NEWGROUPREQUEST` over MQTT).
- `nonce` / `sig` (required unless `IgnoreMgtKeySigCheck`): Same management signing pattern as other group endpoints (canonical JSON of the body with `sig` cleared).

**Guards (error if violated):**
- Stored request **`status`** is **`failed`**, or the group already exists in **`GROUPDB`** for that `groupId`.
- The originator’s stored `SigList` already contains a non-empty entry for **`targetNodeKey`** (that peer has already replied on the host; use [`POST /newGroupRequestAgree`](#post-newgrouprequestagree) on the peer instead if they still need to proceed locally).

**Response (success):**
```json
{
  "code": 0,
  "error": "",
  "data": "retried newGroupRequest NewGroup... to <targetNodeKey>"
}
```

**Peer behavior:** If the peer receives a duplicate `NEWGROUPREQUEST`, their node **merges** signatures into the existing `NewGroup` row (same `requestId`, same `From`) and does not drop signatures already saved—so retries and at-least-once delivery are safe without a second `requestId`.

**Error Responses:** `400` / `500` with `code: 1` and an `error` string (e.g. not originator, invalid target, group exists, target already responded).

<a id="post-newgrouprequestagree"></a>
#### `POST /newGroupRequestAgree`
Agrees to a new group request. **Requires management key authentication.**

**Request Body:**
```json
{
  "requestId": "NewGroup20241228123456789abc123",
  "nonce": 1,
  "sig": "..."
}
```

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": "success to aggree newgrouprequest with requestid NewGroup20241228123456789abc123"
}
```

**Note:** When a node agrees, it registers relay channels for the broker and sends a reply message back to the initiator.

<a id="get-getgroupresultbyid"></a>
#### `GET /getGroupResultById`
Gets a specific group result by ID (requestId) or by group_id (after the group is successfully created). This is the preferred path; `GET /getNewGroupResultById` is an identical deprecated alias and may be removed in a future release.

**Query Parameters:**
- `id` (optional): Request ID from `newGroupRequest` response
- `group_id` (optional): Group ID (deterministic hash of sorted keyList)

**Note:** Either `id` or `group_id` must be provided, but not both.

**Response (success):** `data` is a **flat** object (no nested protobuf wrapper). Field names may use `Code`/`Data` or `code`/`data` at the top level depending on serialization; clients should accept both.

```json
{
  "code": 0,
  "error": "",
  "data": {
    "requestid": "NewGroup20241228123456789abc123",
    "GroupId": "566633a647306335d3ad6ab49829dcfad9abe1f4d1275e4ea3c3f8c292e20ee9",
    "KeyList": ["node1_key", "node2_key", "node3_key"],
    "Addresses": ["http://203.0.113.10:8080", "http://203.0.113.11:8080", "http://203.0.113.12:8080"],
    "SigList": {
      "node1_key": "signature_hex",
      "node2_key": "signature_hex",
      "node3_key": "signature_hex"
    },
    "BrokerArray": ["ssl://82.180.145.77:8883"],
    "timepoint": "2024-12-28T12:34:56.000",
    "originator": "033d741c45434993c6b994eb0b28debe18234188505425f827680a5d2ce82cb7509ea0bec0b652ba4a533d331631c5165e3e1415e378a39c942f0975c8e7d0bf"
  }
}
```

**`data` field descriptions:**
- `requestid`: The new-group request ID (same as the `id` query parameter when querying by request id).
- `GroupId`: Unique identifier for the group (deterministic hash of the sorted key list).
- `KeyList`: Array of node public keys (128 hex characters each) that form the group.
- `Addresses`: Array of HTTP API addresses corresponding to each node in `KeyList`. Index `i` matches `KeyList[i]`. Format: `http://ip:port` or `https://hostname:port`.
- `SigList`: Map of node key → signature (hex) for nodes that agreed to the group creation.
- `BrokerArray`: MQTT broker addresses for the group (typically one entry, e.g. `["ssl://host:8883"]`).
- `timepoint`: When this result was recorded (node-local string).
- `originator`: Node public key of the initiator of the original new-group **request** (persisted when the group result is saved). May be empty on older documents that were written before this field existed.

**Examples:**

Query by requestId:
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getGroupResultById?id=NewGroup20241228123456789abc123"
```

Query by group_id:
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getGroupResultById?group_id=566633a647306335d3ad6ab49829dcfad9abe1f4d1275e4ea3c3f8c292e20ee9"
```

**Note:** Groups can also be pre-configured in `configs.yaml` and will be automatically created on node startup. API-based creation is recommended for new groups to avoid the chicken-and-egg problem.

<a id="get-getnewgroupresultbyid"></a>
#### `GET /getNewGroupResultById` (deprecated)
Same behavior, query parameters, and response as [`GET /getGroupResultById`](#get-getgroupresultbyid). Prefer `GET /getGroupResultById` for new integrations; this path may be removed in a future release.

### 6. Key Generation

<a id="keygen-request-status-values"></a>
**KeyGen request `status` field (stored values):** Each node persists a keygen request document per request id. The JSON field **`status`** on that document can be one of:

| Value | Meaning |
|--------|---------|
| **`pending`** | Waiting for more nodes to complete the agreement: the request exists, but **not every** key in the group’s **`KeyList`** has a non-empty signature in **`SigList`** yet (peers still need to call `keyGenRequestAgree`, or the initiator is still merging partial `KEYGENREQUESTREPLY` updates). New requests are saved with this status. |
| **`agree`** | **All** group nodes have signed the keygen request off-chain. Set when **`KEYGENREQUESTREPLY`** / **`KEYGENREQUESTCONFIRMSUCCESS`** / **`POST /keyGenRequestAgree`** reflects a full **`SigList`**. The keygen **request** row can remain **`agree`** until TSS finishes; **`success`** is written when encrypted **`SaveData`** is stored on the keygen result. |
| **`success`** | TSS completed on this node: the keygen **result** document has non-nil **`savedata`** (encrypted share). The server sets **`status`** to **`success`** on the keygen request when **`UpdateKeyGenResultSaveDataFull`** / **`UpdateEDKeyGenResultSaveDataFull`** completes. |
| **`failed`** | Terminal failure: e.g. TSS/worker error or timeout, expiry of a long-pending request, or fewer than **MPC quorum** KEYGENRESULT confirmations within the configured window (**CGGMP24 / FROST:** *t* parties; see **`threshold`** on keygen)—the keygen **result** may be removed; the **request** row can remain with this status. |
| **`ejected`** | **Effective** status only (derived from the keygen **result** row, not the request document): [`GET /getKeyGenResultById`](#get-getkeygenresultbyid) returns **`status`** **`ejected`** when **`keygenresultstatus`** is **`ejected`**; [`GET /listKeyGenRequests`](#get-listkeygenrequests) / [`GET /getKeyGenRequestById`](#get-getkeygenrequestbyid) surface the same effective **`status`** for the request list/detail. MPC shares are cleared; see [Key eject](#post-keygenejectrequest). |

**Initiator (`originator`):** The node that created the keygen request is stored as **`MsgPb.From`** on the keygen request document; [`GET /listKeyGenRequests`](#get-listkeygenrequests) and [`GET /getKeyGenRequestById`](#get-getkeygenrequestbyid) return it as the JSON field **`originator`**.

**API “effective” status** (for [`GET /getKeyGenRequestById`](#get-getkeygenrequestbyid), [`GET /listKeyGenRequests`](#get-listkeygenrequests)): if the keygen **result** row has **`keygenresultstatus`** **`ejected`**, responses return **`status`** **`ejected`**. Otherwise, if the stored request status is **`agree`** but this node’s keygen **result** row already has **`savedata`**, responses return **`status`** **`success`** (so clients see completion even if the request document was not yet updated to **`success`**). The keygen **result** endpoint [`GET /getKeyGenResultById`](#get-getkeygenresultbyid) uses the same **`ejected`** / **`success`** semantics on its JSON **`status`** field (see that section).

**`GET /listKeyGenRequests` `filter` vs stored / effective status:** `filter=pending` → effective status is not **`agree`**, **`success`**, **`failed`**, or **`ejected`**; `filter=success` → effective status is **`success`** (TSS complete / **`SaveData`** present); `filter=ejected` → effective status is **`ejected`** (key export tombstone); `filter=agree` → **stored** status is **`agree`**, this node’s keygen result has **no** **`savedata`** yet, and the result is **not** **ejected** (off-chain agreement done, TSS still in progress); `filter=failed` → stored **`status === "failed"`**.

<a id="post-keygenrequest"></a>
#### `POST /keyGenRequest`
Creates a new key generation request. **Requires management key authentication.**

**Request Body:**
```json
{
  "nonce": 1,
  "sig": "<NodeMgtKey signature over request body>",
  "clientPk": "<client public key>",
  "threshold": 2,
  "groupId": "566633a647306335d3ad6ab49829dcfad9abe1f4d1275e4ea3c3f8c292e20ee9",
  "msgCheck": "multi-agree",
  "keyType": "secp256k1",
  "ecdsaMpcProtocol": "cggmp24"
}
```

**Field Descriptions:**
- `nonce` (required): Current nonce from `/getNodeMgtKeyNonce`
- `sig` (required): Management key signature over the request body (excluding `sig` field)
- `clientPk` (required): Client public key (128 hex characters)
- `threshold` (required): Signing quorum **t** — **stored as-is** on the keygen payload. For **secp256k1** (CGGMP24), **ed25519**, and **bitcoin-taproot** (FROST/givre): validate **2 ≤ t ≤ n** (*n* = group size). Multi-agree, signing, and keygen confirmation flows use **MPC quorum = t**.
- `groupId` (required): Group ID where key generation will occur
- `msgCheck` (optional): Message check type, default is "multi-agree". Must be in allowed types from `/getAllowedMsgCheckTypes`
- `keyType` (required): `"secp256k1"` (EVM / CGGMP24 ECDSA), `"ed25519"` (FROST Schnorr), or `"bitcoin-taproot"` (FROST BIP-340 Taproot key-path)
- `ecdsaMpcProtocol` (optional): **secp256k1 only.** Omit or **`"cggmp24"`** for the default **CGGMP24** ECDSA DKG (Lockness, requires **`-tags rust`** build). Explicit **`"gg18"`** is **rejected** on new keygen (legacy Mongo keys fail closed). **Ignored for `ed25519` and `bitcoin-taproot`**. Invalid values return **400**. Include in the signed JSON when sent.

**Protocol note:** The choice is persisted on the **`KEYGENREQUEST`** payload (`KeyGenRequestDataPb`) and flows with MQTT/relay so all parties run the same mode. **ed25519** and **bitcoin-taproot** use **FROST via givre** (Lockness); **`ecdsaMpcProtocol`** does not apply.

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": "KeyGen20260111003720999cf104d0f"
}
```

**Example:**
```bash
curl -X POST $MPC_AUTH_URL:$MANAGEMENT_PORT/keyGenRequest \
  -H "Content-Type: application/json" \
  -d '{
    "nonce": 1,
    "sig": "0x...",
    "clientPk": "08caf50811eb4c2bed7b3f8dc9c292b5cf521ba3774ea49dcd949e8235a48b22e8c1f16b356710aae4095e498bfff8385eada1e53a47dbdd984d32ae4d20a5de",
    "threshold": 2,
    "groupId": "566633a647306335d3ad6ab49829dcfad9abe1f4d1275e4ea3c3f8c292e20ee9",
    "msgCheck": "multi-agree",
    "keyType": "secp256k1"
  }'
```

**Deduplication:** Nodes treat duplicate `KEYGENREQUEST` MQTT deliveries for the same `requestId` within a short window as a single processed message for throughput; a later delivery (e.g. operator [`POST /keyGenRequestRetry`](#post-keygenrequestretry)) still **merges** into the same DB row without wiping `SigList` / `ClientKeys` entries peers already stored.

**CGGMP24 secp256k1:** Default for new keys. Signing requires a completed distributed **KeyShare** (aux_info_gen + merge). **Presign is not supported** for CGGMP24 ECDSA keys.

**FROST (ed25519 / bitcoin-taproot):** Requires mpc-auth built with **`-tags rust`**. Supports interactive sign, batch sign (via `multiSignRequest`), and **presign** (see [Pre-Signing](#7-pre-signing)).

**Optional recovery:** If a peer never received **`KEYGENREQUEST`** after [`POST /keyGenRequest`](#post-keygenrequest), the initiator may call [`POST /keyGenRequestRetry`](#post-keygenrequestretry) for that peer’s public key (see that section for guards). If the first delivery was processed very recently, MQTT dedupe may drop a duplicate until a later retry or until the short window passes.

<a id="get-listkeygenrequests"></a>
#### `GET /listKeyGenRequests`
Lists all key generation requests with filtering and pagination.

**Query Parameters:**
- `filter` (optional): `all`, `pending`, `success`, `failed`, `agree`, `originator`, **`ejected`** (default: `all`). For keygen: **`success`** = TSS complete (effective **`SaveData`**); **`ejected`** = key export tombstone (**`keygenresultstatus`** on the result row; see [`GET /getKeyGenResultById`](#get-getkeygenresultbyid)); **`agree`** = stored **`agree`** with no **`savedata`** yet and not **ejected**; **`pending`** excludes **`agree`**, **`success`**, **`failed`**, and **`ejected`**; **`failed`** = failed keygen.
- `pagenum` (optional, default: 0)
- `pagesize` (optional, default: 10)

**Response:**
```json
{
  "Code": 0,
  "Error": "",
  "Data": [
    {
      "requestid": "KeyGen20260217130529999704c2304",
      "ClientKeys": {
        "033d741c45434993c6b994eb0b28debe18234188505425f827680a5d2ce82cb7509ea0bec0b652ba4a533d331631c5165e3e1415e378a39c942f0975c8e7d0bf": "0x1234",
        "7a5781dc05f06ad0e5c192a6762598ab5db53b6339b3faa63180cc5a68ea9f2eccd34e9b9c004c3fe855f0a81561db85fc4cd9149bbd321dc64ee2b5de54c742": "0x1234"
      },
      "GroupId": "f2f594b92389c386cac08f0b26e42e79faf09f1a8735785cce0b5f54cc5aa72a",
      "KeyType": "secp256k1",
      "MsgCheck": "tx-check",
      "SigList": {
        "033d741c45434993c6b994eb0b28debe18234188505425f827680a5d2ce82cb7509ea0bec0b652ba4a533d331631c5165e3e1415e378a39c942f0975c8e7d0bf": "80485a105bbdefc74c3e08e51c39f2bbcac037679bde0956c02e6709b996e9f38d0f4724e2b397714fc633b88e49ce3dace9044b0828d8f1f2dd939591b989b7",
        "7a5781dc05f06ad0e5c192a6762598ab5db53b6339b3faa63180cc5a68ea9f2eccd34e9b9c004c3fe855f0a81561db85fc4cd9149bbd321dc64ee2b5de54c742": "04073ed1c4c54b8a3fc186fe1af42303ae814d436be51c9f144b2706c68d2537a61136c00c5f0fa2975c323171c9293d63cdd6b79ad9d21c7abf55cab71abe2a"
      },
      "Threshold": 1,
      "timepoint": "2026-02-17 13:05:29.157",
      "status": "agree",
      "originator": "033d741c45434993c6b994eb0b28debe18234188505425f827680a5d2ce82cb7509ea0bec0b652ba4a533d331631c5165e3e1415e378a39c942f0975c8e7d0bf"
    }
  ]
}
```

**Response field descriptions (each item in `Data`):**
- `requestid`: Key generation request ID
- `status`: Lifecycle status from the keygen request document in the database. **All possible values and meanings:** see [KeyGen request `status` field (stored values)](#keygen-request-status-values). Omitted when unset.
- `ClientKeys`: Map of node public key (128 hex) to client key / placeholder (e.g. `"0x1234"` or `""`)
- `GroupId`: Group identifier (hash of sorted keyList)
- `KeyType`: Key type, e.g. `"secp256k1"` or `"ed25519"`
- `MsgCheck`: Message check type, e.g. `"tx-check"` or `"multi-agree"`
- `EcdsaMpcProtocol` (when present): For **secp256k1** keygen requests, the stored ECDSA MPC mode (`cggmp24`; legacy rows may show `gg18`). Omitted or empty means **CGGMP24** (default). **ed25519** / **bitcoin-taproot** requests omit this field.
- `SigList`: Map of node public key (128 hex) to signature (hex) for nodes that agreed
- `Threshold`: Stored signing quorum **t** from keygen (MPC quorum = **t** for CGGMP24 and FROST). See [`POST /keyGenRequest`](#post-keygenrequest) `threshold`.
- `timepoint`: Timestamp when the request was recorded (with optional fractional seconds)
- `originator`: Node public key (128 hex characters) of the node that created the keygen **request**—the same value as **`MsgPb.From`** on the stored **`KEYGENREQUEST`** document. Omitted when empty.

**Example:**
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/listKeyGenRequests?filter=ejected"
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/listKeyGenRequests?filter=success"
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/listKeyGenRequests?filter=all&pagenum=0&pagesize=10"
```

<a id="get-getkeygenrequestbyid"></a>
#### `GET /getKeyGenRequestById`
Gets a specific key generation request by ID.

**Query Parameters:**
- `id` (required): Key generation request ID

**Response:** Same shape as one element of `GET /listKeyGenRequests` `Data`, including `requestid`, embedded keygen request fields (`GroupId`, `KeyType`, `SigList`, etc.), `timepoint`, **`status`** (see [KeyGen request `status` field (stored values)](#keygen-request-status-values)), and **`originator`** (initiator node key; see field list under [`GET /listKeyGenRequests`](#get-listkeygenrequests)).

**Example:**
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getKeyGenRequestById?id=KeyGen20260111003720999cf104d0f"
```

<a id="post-keygenrequestretry"></a>
#### `POST /keyGenRequestRetry`
Republishes the same MQTT **`KEYGENREQUEST`** (same `requestId`, same **`SigList` / `ClientKeys` shape as the initial send**: only the initiator’s slots populated) to **one** peer’s topic. **Requires management key authentication.** Use when pings passed but a peer never persisted the first message.

**Caller:** Only the **originator** (`MsgPb.From` / **`originator`** for that `requestId`) may call; use that node’s **`$MPC_AUTH_URL:$MANAGEMENT_PORT`**.

**Request Body:**
```json
{
  "requestId": "KeyGen20260111003720999cf104d0f",
  "targetNodeKey": "128_hex_node_public_key_of_peer",
  "nonce": 1,
  "sig": "..."
}
```

**Guards (error if violated):** target is in the group’s `KeyList` and is not the originator; stored request **`status`** is not **`failed`**; originator’s stored **`SigList[targetNodeKey]`** is still empty (that peer already replied on the initiator); keygen **result** for this `requestId` is not already complete (**`pubkeyhex`** present on this node). Refuses if the stored request is missing the initiator’s **`ClientKeys`** entry.

**Receiver behavior:** Duplicate **`KEYGENREQUEST`** processing **merges** `SigList` and `ClientKeys` with the existing row (same `requestId`, same `From`) so local peer progress is not overwritten. Conflicting non-empty values for the same key return an error.

**Response (success):** `data` string confirms retry, e.g. `retried keyGenRequest <id> to <targetNodeKey>`.

<a id="post-keygenrequestagree"></a>
#### `POST /keyGenRequestAgree`
Agrees to a key generation request. **Requires management key authentication.**

**Request Body:**
```json
{
  "requestId": "KeyGen20260111003720999cf104d0f",
  "nonce": 1,
  "sig": "<NodeMgtKey signature>"
}
```

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": "success to aggree keygenrequest with requestid KeyGen20260111003720999cf104d0f"
}
```

<a id="post-keygenejectrequest"></a>
#### `POST /keyGenEjectRequest`
Starts a **multi-agree key eject** so the committee can export the **full private key** for that keygen, verify it against stored public metadata, then **tombstone** MPC for that key (**`keygenresultstatus`** → **`ejected`**, **`savedata`** cleared on nodes that finalize; secp256k1 also clears **`cggmp24aux`**). **Requires management key authentication** (same **`Nonce` / `Sig`** pattern as other signed POST bodies; optional **`nodeKey`** binding per [Management signatures](#management-signatures-nodekey)).

**Supported key types (server-enforced):**

| Key type | MPC stack | Exported secret |
|----------|-----------|-----------------|
| **`secp256k1`** | **CGGMP24** (`effectiveEcdsaMpcProtocol`: **`cggmp24`**) | 64-hex secp256k1 scalar (same as **`ethereumaddress`** / **`bitcoinp2wpkhmainnet`**) |
| **`ed25519`** | **FROST/givre** (`effectiveSchnorrMpcProtocol`: **`givre`**) | 32-byte Ed25519 seed (64 hex) |
| **`bitcoin-taproot`** | **FROST/givre** (`effectiveSchnorrMpcProtocol`: **`givre`**) | Taproot internal key scalar (64 hex; verified against **`taprootinternalpubkeyhex`**) |

**Eligibility (all types):** **`msgCheck`** on the keygen must be **`multi-agree`**. **Not eligible:** **`tx-check`** keygens; **legacy GG18** secp256k1 keys; keygens already **`ejected`**.

**Governance:** **M-of-N accepts** use the **same quorum semantics as signing** for that key (**`KeyGenMpcSigningQuorumFromStored`** / stored threshold vs **`KeyList`**). **Reject** votes (**`POST /keyGenEjectAgree`** with **`accept`:** **`false`**) are **audit-only** and do **not** block completion once enough parties have accepted.

**Request body (canonical JSON is what you sign with `Sig` emptied):**
```json
{
  "Nonce": 42,
  "Sig": "<management signature>",
  "nodeKey": "<optional 128-hex GET /getNodeKey>",
  "keyGenId": "KeyGen20260111003720999cf104d0f",
  "purpose": "Optional operator rationale"
}
```

**Success response:**
```json
{
  "code": 0,
  "error": "",
  "data": {
    "ejectRequestId": "<id used for agrees and status>"
  }
}
```

The node propagates eject protocol traffic over MQTT (`KEYGENEJECT*` message types). Finalization requires mpc-auth built with **`-tags rust`** (CGGMP24 and FROST/givre share reconstruction FFI). After finalize, fetch export material with the key-type-specific POST in the [ejected key export endpoints](#key-eject-export-endpoints) table. Product-level notes: sibling repo **mpc-auth** [`docs-internal/ETHEREUM_KEY_EJECT_EVALUATION.md`](../../mpc-auth/docs-internal/ETHEREUM_KEY_EJECT_EVALUATION.md) (clone layout: **mpc-config** and **mpc-auth** as sibling directories).

<a id="post-keygenejectagree"></a>
#### `POST /keyGenEjectAgree`
Records a committee member **accept** or **reject** for an eject started with [`POST /keyGenEjectRequest`](#post-keygenejectrequest). **Requires management key authentication** (same pattern as **`signRequestAgree`**, **`triggerSignRequestById`**, etc.): fetch nonce from **`GET /getPublicMgtKeyNonce`** (Ed25519) or **`GET /getNodeMgtKeyNonce`** (Ethereum **`NodeMgtKey`**), build JSON with **`nonce`**, **`nodeKey`** (128 hex from **`GET /getNodeKey`**), and other fields, sign with **`clientSig` cleared**, send as **`clientSig`**. Optional **`thoughts`** (max 256 characters).

**Request body:**
```json
{
  "ejectRequestId": "<from keyGenEjectRequest data>",
  "nonce": 1,
  "nodeKey": "<128-hex MPC node key from GET /getNodeKey>",
  "clientSig": "<management signature>",
  "accept": true,
  "thoughts": "optional"
}
```

Use **`accept`:** **`false`** for a logged reject (does not veto quorum). Omit **`accept`** or set **`true`** for the accept path.

**Success:** `data` is the string **`ok`**.

<a id="get-listkeygenejectrequests"></a>
#### `GET /listKeyGenEjectRequests`
Lists **key eject** flows visible to **this node** (the caller’s **`GET /getNodeKey`** must appear in the eject **`KeyList`**). Applies to **secp256k1**, **ed25519**, and **bitcoin-taproot** multi-agree keygens. Use this to drive Pending Keys UI rows while an eject is in progress and to inspect completed flows.

**Query Parameters:**
- `filter` (optional, default: **`pending`**): **`all`**, **`pending`**, or **`done`**
  - **`pending`**: lifecycle status is not **`done`** and the target keygen result is **not** yet **ejected** on this node
  - **`done`**: lifecycle status is **`done`** **or** the keygen result is **ejected** (tombstone)
  - **`all`**: no status filter (still scoped to ejects where this node is in **`KeyList`**)
- `pagenum` (optional, default: 0)
- `pagesize` (optional, default: 10)

**Response:** `Data` is an array of eject request objects (newest **`timepoint`** first). Each item has the same shape as [`GET /getKeyGenEjectRequestById`](#get-getkeygenejectrequestbyid) **`data`**.

```json
{
  "code": 0,
  "error": "",
  "data": [
    {
      "requestid": "KeyGenEject20260519143000abc123",
      "KeyGenId": "KeyGen20260111003720999cf104d0f",
      "KeyList": ["node1_key", "node2_key", "node3_key"],
      "SigList": {
        "node1_key": "80485a105bbdefc74c3e08e51c39f2bbcac037679bde0956c02e6709b996e9f38d0f4724e2b397714fc633b88e49ce3dace9044b0828d8f1f2dd939591b989b7",
        "node2_key": "",
        "node3_key": ""
      },
      "ClientSigs": {},
      "Purpose": { "node1_key": "Operator export" },
      "Thoughts": {},
      "RejectedBy": [],
      "timepoint": "2026-05-19 14:30:00.123",
      "status": "live",
      "originator": "node1_key"
    }
  ]
}
```

**Response field descriptions (each item in `Data`):**
- `requestid`: Eject request id (same value as **`ejectRequestId`** from [`POST /keyGenEjectRequest`](#post-keygenejectrequest))
- `KeyGenId`: Target keygen request id
- `KeyList`: Committee node public keys (128 hex) participating in the eject
- `SigList`: Map of node public key → management signature hex for nodes that accepted (empty string when not yet agreed)
- `ClientSigs`, `Purpose`, `Thoughts`: Optional per-node maps merged during propagation (same merge semantics as keygen agrees)
- `RejectedBy`: Node keys that logged a reject via [`POST /keyGenEjectAgree`](#post-keygenejectagree) with **`accept`:** **`false`** (audit-only; does not block quorum)
- `timepoint`: When this eject request was recorded on this node
- `status`: Eject lifecycle on this node (e.g. **`live`**, **`eject_share_phase`**, **`done`**). **`done`** means the eject protocol finished on this node; the keygen may already show **`ejected`** on [`GET /getKeyGenResultById`](#get-getkeygenresultbyid)
- `originator`: Node public key that started the eject (**`MsgPb.From`** on the stored **`KEYGENEJECTREQUEST`**)

**Client UI note:** The continuumdao-node-app Keys page may hide **pending** eject rows whose **`timepoint`** is older than **7 days** (same client-side stale window as pending keygens). The API still returns those rows when **`filter=pending`**.

**Example:**
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/listKeyGenEjectRequests?filter=pending"
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/listKeyGenEjectRequests?filter=all&pagenum=0&pagesize=10"
```

<a id="get-getkeygenejectrequestbyid"></a>
#### `GET /getKeyGenEjectRequestById`
Returns one key eject flow by **`requestid`**.

**Query Parameters:**
- `id` (required): Eject request id (from [`POST /keyGenEjectRequest`](#post-keygenejectrequest) **`data.ejectRequestId`**)

**Response:** Same shape as one element of [`GET /listKeyGenEjectRequests`](#get-listkeygenejectrequests) **`Data`** (single object in **`data`**, not an array).

**Example:**
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getKeyGenEjectRequestById?id=KeyGenEject20260519143000abc123"
```

<a id="post-getethereumprivatekey"></a>
#### `POST /getEthereumPrivateKey`
Returns the **exported private key** as **64 hex characters** (no `0x` prefix) after eject, plus **Bitcoin mainnet** export fields derived from the same secp256k1 scalar when available. **Requires management key authentication** over **`Nonce`**, **`Sig`** (with **`Sig`** cleared for verification), **`keyGenId`**, and optional **`nodeKey`**.

**Preconditions:** This node must appear in the keygen **`keylist`**; the stored result must have **`keygenresultstatus`** **`ejected`**; this node must have persisted the encrypted export blob (each **KeyList** participant stores ciphertext locally after finalize; nodes that did not run finalize may return an error).

**Request body:**
```json
{
  "Nonce": 43,
  "Sig": "<management signature>",
  "nodeKey": "<optional 128-hex>",
  "keyGenId": "KeyGen20260111003720999cf104d0f"
}
```

**Success response:**
```json
{
  "code": 0,
  "error": "",
  "data": {
    "privateKeyHex": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "bitcoinPrivateKeyWif": "Kyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "privateKeyWif": "Kyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "bitcoinP2WPKHMainnet": "bc1qm8kh3fp58gs593p6y7wfduznjchlajmrkl78p8"
  }
}
```

| Field | Description |
|-------|-------------|
| **`privateKeyHex`** | Ethereum / raw secp256k1 scalar (**64 hex**, no `0x`) |
| **`bitcoinPrivateKeyWif`** / **`privateKeyWif`** | Bitcoin **mainnet compressed WIF** for the same scalar (P2WPKH-compatible) |
| **`bitcoinP2WPKHMainnet`** | Native SegWit v0 **bc1…** address for this key when derivable; see [bitcoinp2wpkh fields](#bitcoin-p2wpkh-mainnet-address) |

Typical errors: **`400`** if the key is not **`ejected`**; **`403`** if this node is not in **`KeyList`**; **`404`** if there is no export material on this node.

**Example:**
```bash
curl -X POST "$MPC_AUTH_URL:$MANAGEMENT_PORT/getEthereumPrivateKey" \
  -H "Content-Type: application/json" \
  -d '{"Nonce":43,"Sig":"<management signature>","keyGenId":"KeyGen20260111003720999cf104d0f"}'
```

<a id="post-getbitcoinprivatekey"></a>
#### `POST /getBitcoinPrivateKey`
Returns the **Bitcoin mainnet compressed private key (WIF)** for the ejected secp256k1 scalar—the same underlying key as [`POST /getEthereumPrivateKey`](#post-getethereumprivatekey), encoded for Bitcoin wallet import. **Requires management key authentication** over **`Nonce`**, **`Sig`** (with **`Sig`** cleared for verification), **`keyGenId`**, and optional **`nodeKey`**.

**Preconditions:** Same as [`POST /getEthereumPrivateKey`](#post-getethereumprivatekey).

**Request body:** Same shape as [`POST /getEthereumPrivateKey`](#post-getethereumprivatekey) (`keyGenId` identifies the keygen request).

**Success response:**
```json
{
  "code": 0,
  "error": "",
  "data": {
    "privateKeyWif": "Kyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "bitcoinPrivateKeyWif": "Kyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "privateKeyHex": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "bitcoinP2WPKHMainnet": "bc1qm8kh3fp58gs593p6y7wfduznjchlajmrkl78p8"
  }
}
```

Typical errors: same as [`POST /getEthereumPrivateKey`](#post-getethereumprivatekey).

**Example:**
```bash
curl -X POST "$MPC_AUTH_URL:$MANAGEMENT_PORT/getBitcoinPrivateKey" \
  -H "Content-Type: application/json" \
  -d '{"Nonce":43,"Sig":"<management signature>","keyGenId":"KeyGen20260111003720999cf104d0f"}'
```

<a id="post-geted25519privatekey"></a>
#### `POST /getEd25519PrivateKey`
Returns the **exported Ed25519 seed** and chain-specific wallet import formats after a successful **FROST ed25519** eject. **Requires management key authentication** over **`Nonce`**, **`Sig`** (with **`Sig`** cleared for verification), **`keyGenId`**, and optional **`nodeKey`**.

**Preconditions:** Target keygen **`keytype`** is **`ed25519`**; this node must appear in the keygen **`keylist`**; stored result must have **`keygenresultstatus`** **`ejected`**; this node must have persisted the encrypted export blob after finalize.

**Request body:** Same shape as [`POST /getEthereumPrivateKey`](#post-getethereumprivatekey) (`keyGenId` identifies the keygen request).

**Success response (`data` fields):**

| Field | Description |
|-------|-------------|
| **`privateKeyHex`** / **`ed25519SeedHex`** | 32-byte Ed25519 seed (**64 hex**, no `0x`) |
| **`publicKeyHex`** | Stored **`pubkeyhex`** |
| **`solanaPrivateKeyBase58`** | Base58-encoded 64-byte keypair (seed‖pub) |
| **`nearPrivateKey`**, **`nearPrivateKeyBase58`** | NEAR import formats |
| **`stellarSecretKey`**, **`sorobanPrivateKey`** | Stellar/Soroban **S…** strkey |
| **`tonPrivateKeyHex`**, **`suiPrivateKeyHex`** | TON seed hex; Sui **`0x` + seed** |
| **`solanaaddress`**, **`sorobanaddress`**, etc. | Derived addresses when present on the keygen result |

Typical errors: **`400`** if the key is not **`ejected`** or wrong **`keytype`**; **`403`** if this node is not in **`KeyList`**; **`404`** if there is no export material on this node.

**Example:**
```bash
curl -X POST "$MPC_AUTH_URL:$MANAGEMENT_PORT/getEd25519PrivateKey" \
  -H "Content-Type: application/json" \
  -d '{"Nonce":43,"Sig":"<management signature>","keyGenId":"KeyGen20260111003720999cf104d0f"}'
```

<a id="post-gettaprootprivatekey"></a>
#### `POST /getTaprootPrivateKey`
Returns the **exported Taproot internal key scalar** and P2TR metadata after a successful **FROST bitcoin-taproot** eject. **Requires management key authentication** over **`Nonce`**, **`Sig`** (with **`Sig`** cleared for verification), **`keyGenId`**, and optional **`nodeKey`**.

**Preconditions:** Target keygen **`keytype`** is **`bitcoin-taproot`**; this node must appear in the keygen **`keylist`**; stored result must have **`keygenresultstatus`** **`ejected`**; this node must have persisted the encrypted export blob after finalize.

**Request body:** Same shape as [`POST /getEthereumPrivateKey`](#post-getethereumprivatekey) (`keyGenId` identifies the keygen request).

**Success response (`data` fields):**

| Field | Description |
|-------|-------------|
| **`privateKeyHex`** | Taproot **internal key** scalar (**64 hex**, no `0x`) |
| **`taprootInternalPubKeyHex`** | x-only internal key *P* (**64 hex**) |
| **`outputPubKeyHex`** | On-chain Taproot output key *Q* (**64 hex**; same as **`pubkeyhex`**) |
| **`bitcoinp2trmainnet`**, **`bitcoinp2trtestnet`**, **`bitcoinp2trsignet`** | **bc1p…** / testnet / signet P2TR addresses when derivable |
| **`bitcoinPrivateKeyWif`** | Bitcoin mainnet compressed WIF for the internal scalar (when derivable) |

Typical errors: same as [`POST /getEd25519PrivateKey`](#post-geted25519privatekey).

**Example:**
```bash
curl -X POST "$MPC_AUTH_URL:$MANAGEMENT_PORT/getTaprootPrivateKey" \
  -H "Content-Type: application/json" \
  -d '{"Nonce":43,"Sig":"<management signature>","keyGenId":"KeyGen20260111003720999cf104d0f"}'
```

<a id="get-getkeygenresultbyid"></a>
#### `GET /getKeyGenResultById`

Returns the **keygen result** for one **`requestid`** (same id as the keygen request): public key, derived addresses, **`keylist`**, and lifecycle fields such as **`status`** (including **`ejected`** after key export). There is **no** `filter` query parameter—only **`id`**. To **list** all ejected keygens, use [`GET /listKeyGenRequests`](#get-listkeygenrequests) with **`filter=ejected`**; each item’s effective **`status`** matches this endpoint’s semantics for that request.

A result is returned (Code 0) when either **(a)** this node completed the TSS and still has a local share (**`savedata`** present), **or (b)** the key was **ejected** on this node (**`keygenresultstatus`** **`ejected`**) so **`savedata`** / **`cggmp24aux`** were cleared but public metadata and tombstone state remain. In the usual case, **(a)** also requires at least the **MPC quorum** (*t* parties for CGGMP24 and FROST) to have sent KEYGENRESULTCONFIRMSUCCESS within 7 days. If fewer parties completed by then, the keygen is useless for signing (cannot produce a signature); the result is then deleted and the keygen request is marked failed. If this node did not complete (e.g. worker timed out) and the key is not **ejected**, it returns Code 1 "not ready". If one node returns "not ready" and another had completed, the client may need to call `getKeyGenResultById` on another node—but if fewer than the quorum completed overall, no node will keep the result (all will delete it after the 7-day timeout).

**Query Parameters:**
- `id` (required): Key generation request ID

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": {
    "requestid": "KeyGen20260111003720999cf104d0f",
    "keylist": ["node1_key", "node2_key", "node3_key"],
    "pubkeyhex": "08caf50811eb4c2bed7b3f8dc9c292b5cf521ba3774ea49dcd949e8235a48b22e8c1f16b356710aae4095e498bfff8385eada1e53a47dbdd984d32ae4d20a5de",
    "ethereumaddress": "0x85E554a6Da9c12839561Db76a6F56323e8582e83",
    "bitcoinp2wpkhmainnet": "bc1qm8kh3fp58gs593p6y7wfduznjchlajmrkl78p8",
    "bitcoinp2wpkhtestnet": "tb1qm8kh3fp58gs593p6y7wfduznjchlajmrue9565",
    "bitcoinp2wpkhsignet": "tb1qm8kh3fp58gs593p6y7wfduznjchlajmrue9565",
    "solanaaddress": "",
    "sorobanaddress": "",
    "nearaddress": "",
    "tonaddress": "",
    "suiaddress": "",
    "savedata": "HIDE ENCRYPTED DATA",
    "timepoint": "2026-01-11T00:37:20.999Z",
    "globalnonce": 0,
    "status": "agree",
    "effectiveEcdsaMpcProtocol": "cggmp24"
  }
}
```

**Note:** The `keylist` field contains all node keys that participated in key generation. **globalnonce** is the number of sign results created for this keyGen (secp256k1); it is also available via `GET /getGlobalNonceByKeyGenId`. If it's `null` in the database, the endpoint will attempt to populate it from the group configuration. **`effectiveEcdsaMpcProtocol`** summarizes the secp256k1 MPC runtime for this key (`cggmp24`; legacy rows may show `gg18`); see [effectiveEcdsaMpcProtocol](#effective-ecdsa-mpc-protocol). **`effectiveSchnorrMpcProtocol`** is **`givre`** for ed25519 / bitcoin-taproot. For secp256k1 keys, **Bitcoin SegWit v0 P2WPKH** fields (**`bitcoinp2wpkhmainnet`**, **`bitcoinp2wpkhtestnet`**, **`bitcoinp2wpkhsignet`**) are returned when derivable; see [bitcoinp2wpkh fields](#bitcoin-p2wpkh-mainnet-address). For **ed25519**, see [ed25519 derived addresses](#ed25519-derived-addresses). For **bitcoin-taproot**, see [Bitcoin Taproot derived addresses](#bitcoin-p2tr-mainnet-address). After **eject**, **`savedata`** / **`cggmp24aux`** are absent; responses may include **`keygenresultstatus`**, **`ejectedat`**, and redacted **`ejectedprivatekey`**; use [`POST /getEthereumPrivateKey`](#post-getethereumprivatekey) or [`POST /getBitcoinPrivateKey`](#post-getbitcoinprivatekey) for export on nodes that stored the ciphertext.

**`status`:** Same **effective** lifecycle as the keygen request (see [KeyGen request `status` field (stored values)](#keygen-request-status-values)): not stored on the keygen result row; if **`keygenresultstatus`** is **`ejected`**, responses force **`status`** **`ejected`**. Otherwise, if the request is still **`agree`** but this node has **`savedata`**, responses return **`success`**. Omitted if the request record cannot be loaded.

**Example:**
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getKeyGenResultById?id=KeyGen20260111003720999cf104d0f"
```

<a id="get-getglobalnoncebykeygenid"></a>
#### `GET /getGlobalNonceByKeyGenId`
Returns the **globalNonce** for a keyGen result. The `id` is the keyGen result id (same as the keyGen requestId).

**Query Parameters:**
- `id` (required): KeyGen result id (requestId)

**Response (secp256k1):**
```json
{
  "code": 0,
  "error": "",
  "data": {
    "globalnonce": 5,
    "effectiveEcdsaMpcProtocol": "cggmp24"
  }
}
```

For keyGen results that are not secp256k1 (e.g. ed25519, bitcoin-taproot), the endpoint returns `globalnonce: 0`, **`keytype`**, empty **`effectiveEcdsaMpcProtocol`**, and **`effectiveSchnorrMpcProtocol`: `"givre"`** when applicable.

**Example:**
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getGlobalNonceByKeyGenId?id=KeyGen20260111003720999cf104d0f"
```

<a id="get-getkeygengroupid"></a>
#### `GET /getKeyGenGroupId` **NEW**
Gets the GroupId for a given keyGen request ID.

**Query Parameters:**
- `id` (required): Key generation request ID

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": {
    "requestid": "KeyGen20260111003720999cf104d0f",
    "groupid": "566633a647306335d3ad6ab49829dcfad9abe1f4d1275e4ea3c3f8c292e20ee9"
  }
}
```

**Example:**
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getKeyGenGroupId?id=KeyGen20260111003720999cf104d0f"
```

**Use Cases:**
- Determine which group a keyGen belongs to
- Debug keyGen issues by identifying the group
- Query group-specific information

<a id="get-getallgroupids"></a>
#### `GET /getAllGroupIds` **NEW**
Gets all configured GroupIds and their associated keyGen results.

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": {
    "groups": [
      {
        "groupId": "566633a647306335d3ad6ab49829dcfad9abe1f4d1275e4ea3c3f8c292e20ee9",
        "keyGens": [
          {
            "requestid": "KeyGen20260111003720999cf104d0f",
            "pubkeyhex": "08caf50811eb4c2bed7b3f8dc9c292b5cf521ba3774ea49dcd949e8235a48b22e8c1f16b356710aae4095e498bfff8385eada1e53a47dbdd984d32ae4d20a5de",
            "keylist": ["node1_key", "node2_key", "node3_key"],
            "timepoint": "2026-01-11T00:37:20.999Z",
            "ethereumaddress": "0x85E554a6Da9c12839561Db76a6F56323e8582e83",
            "bitcoinp2wpkhmainnet": "bc1qm8kh3fp58gs593p6y7wfduznjchlajmrkl78p8",
            "bitcoinp2wpkhtestnet": "tb1qm8kh3fp58gs593p6y7wfduznjchlajmrue9565",
            "bitcoinp2wpkhsignet": "tb1qm8kh3fp58gs593p6y7wfduznjchlajmrue9565",
            "groupid": "566633a647306335d3ad6ab49829dcfad9abe1f4d1275e4ea3c3f8c292e20ee9",
            "threshold": 2,
            "keytype": "secp256k1"
          }
        ]
      },
      {
        "groupId": "another_group_id",
        "keyGens": []
      }
    ]
  }
}
```

**Response Fields:**
- `groups`: Array of group data
  - `groupId`: The group identifier
  - `keyGens`: Array of key generation results for this group
    - `requestid`: Key generation request ID
    - `pubkeyhex`: Generated public key (128 hex characters)
    - `keylist`: Array of node keys that participated (may be empty if not saved)
    - `timepoint`: When the key was generated
    - `ethereumaddress`: Ethereum address (for secp256k1 keys)
    - `bitcoinp2wpkhmainnet`: Bitcoin mainnet P2WPKH / `bc1q…` (for secp256k1 keys; see [Bitcoin P2WPKH derived addresses](#bitcoin-p2wpkh-mainnet-address))
    - `bitcoinp2wpkhtestnet`: Bitcoin TestNet3 P2WPKH / `tb1…`
    - `bitcoinp2wpkhsignet`: Bitcoin Signet P2WPKH (often same `tb1…` string as testnet under **btcd** SigNet params)
    - `solanaaddress`: Solana address (for ed25519 keys)
    - `sorobanaddress`: Soroban/Stellar address (for ed25519 keys)
    - `nearaddress`: NEAR address (for ed25519 keys)
    - `tonaddress`: TON address (for ed25519 keys)
    - `suiaddress`: Sui account address (for ed25519 keys; see [ed25519 derived addresses](#ed25519-derived-addresses))
    - `groupid`: Group ID (redundant but included for convenience)
    - `threshold`: Signing threshold
    - `keytype`: Key type (`"secp256k1"` or `"ed25519"`)

**Note:** 
- `savedata` is excluded for security
- Groups with errors still appear with empty `keyGens` array
- Results are sorted by `timepoint` (newest first)

**Example:**
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getAllGroupIds"
```

**Use Cases:**
- Get overview of all groups and their keyGens
- Verify that `keylist` is populated for all keyGens
- Debug missing keyList issues
- Monitor key generation across all groups

<a id="get-listgroupresults"></a>
#### `GET /listGroupResults`
Lists every **configured** MPC group and the **member node public keys** for each group (the new-group **`KeyList`**, exposed as `nodeKeys`). This is lighter than [`GET /getAllGroupIds`](#get-getallgroupids), which also loads all keyGen documents per group.

**Query parameters (all optional):**

| Parameter | Semantics |
|-----------|-----------|
| `node_key` | **Repeatable** (`?node_key=a&node_key=b`). If any non-empty values are sent, only groups whose `nodeKeys` contain **every** listed key (**AND**, exact string match after trim) are returned. |
| `exclude_node_key` | **Repeatable**. Omit any group whose `nodeKeys` contain **at least one** of the listed keys. |

Filters apply after resolving each group’s `nodeKeys` (empty if the group record is missing or has no `KeyList`).

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": {
    "groups": [
      {
        "groupId": "566633a647306335d3ad6ab49829dcfad9abe1f4d1275e4ea3c3f8c292e20ee9",
        "nodeKeys": ["node1_key_hex", "node2_key_hex", "node3_key_hex"]
      }
    ]
  }
}
```

**Examples:**
```bash
# All configured groups with member node keys
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/listGroupResults"

# Only groups that include this node (single value)
curl -G "$MPC_AUTH_URL:$MANAGEMENT_PORT/listGroupResults" --data-urlencode "node_key=NODE_PUBKEY_HEX"

# Only groups that include both keys (AND)
curl -G "$MPC_AUTH_URL:$MANAGEMENT_PORT/listGroupResults" \
  --data-urlencode "node_key=KEY_A" \
  --data-urlencode "node_key=KEY_B"

# Exclude groups that contain a given member
curl -G "$MPC_AUTH_URL:$MANAGEMENT_PORT/listGroupResults" --data-urlencode "exclude_node_key=NODE_PUBKEY_HEX"
```

**Use Cases:**
- Enumerate group membership without scanning keyGen collections
- Find which groups include a specific node (or a set of nodes)
- Exclude groups that still contain retired or unwanted node keys

### 6a. KeyGen Messaging

Per-keyGen channels for nodes in that key’s **`KeyList`**. Full request bodies, query parameters, and error codes: [`API_KEYGEN_MESSAGING.md`](./API_KEYGEN_MESSAGING.md).

<a id="post-sendmessage"></a>
#### `POST /sendMessage`
Creates a message (top-level or reply). **Requires management key signature.** See [`API_KEYGEN_MESSAGING.md` → `POST /sendMessage`](./API_KEYGEN_MESSAGING.md#post-sendmessage).

<a id="get-listmessages"></a>
#### `GET /listMessages`
Lists messages with filters and pagination. See [`API_KEYGEN_MESSAGING.md` → `GET /listMessages`](./API_KEYGEN_MESSAGING.md#get-listmessages).

<a id="get-getmessagebyid"></a>
#### `GET /getMessageById`
Returns one message by id. See [`API_KEYGEN_MESSAGING.md` → `GET /getMessageById`](./API_KEYGEN_MESSAGING.md#get-getmessagebyid).

<a id="get-getmessagethread"></a>
#### `GET /getMessageThread`
Returns a top-level message and nested replies (max depth 3). See [`API_KEYGEN_MESSAGING.md` → `GET /getMessageThread`](./API_KEYGEN_MESSAGING.md#get-getmessagethread).

<a id="post-markmessageread"></a>
#### `POST /markMessageRead`
Adds a read receipt for the calling node. **Requires management key signature.** See [`API_KEYGEN_MESSAGING.md` → `POST /markMessageRead`](./API_KEYGEN_MESSAGING.md#post-markmessageread).

<a id="post-multimarkmessagesread"></a>
#### `POST /multiMarkMessagesRead`
Marks multiple messages read in one request. **Requires management key signature.** See [`API_KEYGEN_MESSAGING.md` → `POST /multiMarkMessagesRead`](./API_KEYGEN_MESSAGING.md#post-multimarkmessagesread).

<a id="post-deletemessage"></a>
#### `POST /deleteMessage`
Deletes a message and its reply tree; originator only. **Requires management key signature.** See [`API_KEYGEN_MESSAGING.md` → `POST /deleteMessage`](./API_KEYGEN_MESSAGING.md#post-deletemessage).

<a id="post-multideletemessages"></a>
#### `POST /multiDeleteMessages`
Deletes multiple messages (and trees); originator-only per message. **Requires management key signature.** See [`API_KEYGEN_MESSAGING.md` → `POST /multiDeleteMessages`](./API_KEYGEN_MESSAGING.md#post-multideletemessages).

### 7. Pre-Signing

Presign accelerates **FROST** signing for **`ed25519`** and **`bitcoin-taproot`** keys (givre). Each presignature stores a **round-1 nonce commitment** locally at generation time; at sign time the node runs a **presign-finish** worker (commitments + partial signatures + aggregate) instead of a full interactive FROST sign.

**Not supported:** **CGGMP24 secp256k1** keys (`presign is not implemented for CGGMP24 (ecdsa) keys`). **Legacy GG18** keys fail closed.

When **`InitiatePreSigning: true`** in `configs.yaml`, the background worker auto-creates presign requests only for eligible FROST key groups.

<a id="post-presignrequest"></a>
#### `POST /presignRequest`
Creates a new pre-signing request. **Requires management key authentication.** **FROST keys only** (`ed25519`, `bitcoin-taproot`).

**Request Body:**
```json
{
  "nonce": 1,
  "sig": "<NodeMgtKey signature over request body>",
  "pubKey": "08caf50811eb4c2bed7b3f8dc9c292b5cf521ba3774ea49dcd949e8235a48b22e8c1f16b356710aae4095e498bfff8385eada1e53a47dbdd984d32ae4d20a5de",
  "keyList": ["node1_key", "node2_key", "node3_key"],
  "presignAmt": 5
}
```

**Field Descriptions:**
- `nonce` (required): Current nonce from `/getNodeMgtKeyNonce`
- `sig` (required): Management key signature over the request body (excluding `sig` field)
- `pubKey` (required): Public key from key generation (128 hex characters)
- `keyList` (required): Array of node keys that will participate in presigning
- `presignAmt` (required): Number of presignatures to generate

**CGGMP24 secp256k1 keys:** **`POST /presignRequest`** returns an error. Use FROST keys for presign, or sign interactively without `presignId`.

**Sign with presign:** Pass the presign result id as **`presignId`** on **`POST /signRequest`** or **`POST /multiSignRequest`** (single-message only). **`keyList`** must be **`null`**. Batch **`multiSignRequest`** does **not** use presign — each batch leg runs a full interactive sign in parallel.

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": "Presign20260111003720999cf104d0f"
}
```

**Example:**
```bash
curl -X POST $MPC_AUTH_URL:$MANAGEMENT_PORT/presignRequest \
  -H "Content-Type: application/json" \
  -d '{
    "nonce": 1,
    "sig": "0x...",
    "pubKey": "08caf50811eb4c2bed7b3f8dc9c292b5cf521ba3774ea49dcd949e8235a48b22e8c1f16b356710aae4095e498bfff8385eada1e53a47dbdd984d32ae4d20a5de",
    "keyList": ["node1_key", "node2_key", "node3_key"],
    "presignAmt": 5
  }'
```

<a id="get-listpresignrequests"></a>
#### `GET /listPresignRequests`
Lists all pre-signing requests with filtering and pagination.

**Query Parameters:**
- `filter` (optional): `all`, `pending`, `success`, `failed` (default: `all`)
- `pagenum` (optional, default: 0)
- `pagesize` (optional, default: 10)

**Example:**
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/listPresignRequests?filter=all&pagenum=0&pagesize=10"
```

<a id="get-getpresignrequestbyid"></a>
#### `GET /getPresignRequestById`
Gets a specific pre-signing request by ID.

**Query Parameters:**
- `id` (required): Presign request ID

**Example:**
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getPresignRequestById?id=Presign20260111003720999cf104d0f"
```

<a id="post-presignrequestagree"></a>
#### `POST /presignRequestAgree`
Agrees to a pre-signing request. **Requires management key authentication.**

**Request Body:**
```json
{
  "requestId": "Presign20260111003720999cf104d0f",
  "nonce": 1,
  "sig": "<NodeMgtKey signature>"
}
```

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": "success to aggree presignrequest with requestid Presign20260111003720999cf104d0f"
}
```

<a id="get-listpresignresults"></a>
#### `GET /listPresignResults`
Lists all pre-signing results with pagination.

**Query Parameters:**
- `pagenum` (optional, default: 0)
- `pagesize` (optional, default: 10)
- `afterId` (optional): Get results after this ID (for pagination)

**Example:**
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/listPresignResults?pagenum=0&pagesize=10"
```

<a id="get-getpresignresultbyid"></a>
#### `GET /getPresignResultById`
Gets a specific pre-signing result by ID.

**Query Parameters:**
- `id` (required): Presign request ID

**Example:**
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getPresignResultById?id=Presign20260111003720999cf104d0f"
```

<a id="get-getpresigningstatus"></a>
#### `GET /getPresigningStatus`
Returns presigning status including configuration and cache levels for all key groups.

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": {
    "enabled": true,
    "targetCacheSize": 100,
    "minCacheSize": 50,
    "keyGroups": [
      {
        "pubKey": "08caf50811eb4c2bed7b3f8dc9c292b5cf521ba3774ea49dcd949e8235a48b22e8c1f16b356710aae4095e498bfff8385eada1e53a47dbdd984d32ae4d20a5de",
        "currentCache": 75,
        "targetCache": 100,
        "status": "healthy"
      }
    ]
  }
}
```

**Example:**
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getPresigningStatus"
```

### 8. Signing

<a id="post-signrequest"></a>
#### `POST /signRequest`
Creates a new signing request. **Requires relayer authentication.**

**Request Body:**
```json
{
  "clientSig": "<client signature over message>",
  "keyList": ["node1_key", "node2_key", "node3_key"],
  "presignId": "",
  "pubKey": "08caf50811eb4c2bed7b3f8dc9c292b5cf521ba3774ea49dcd949e8235a48b22e8c1f16b356710aae4095e498bfff8385eada1e53a47dbdd984d32ae4d20a5de",
  "msgHash": "751f68b43977269a16128143fa15e0e7ab3c15ba52484fe8278796561505698b",
  "msgRaw": "<raw message bytes>",
  "relayerPublicKey": "ed8639ee02b0e0cb8caade8ea24c71b1c60c55fa241032767e67c4da6e691f5fd08a36b005a2c1fd68c9b5a04137c406d458ba73b562aa269f52ceb6a285e41a",
  "relayerSignature": "<relayer signature over request>",
  "chainID": "11155111",
  "sourceTxHash": "",
  "sourceChainID": "",
  "destinationChainID": "11155111",
  "destinationAddress": "0x...",
  "extraJSON": "{}"
}
```

**Field Descriptions:**
- `clientSig` (required): Client signature over the message
- `keyList` (required for normal signing): Array of node keys. For normal signing, can be empty array `[]` (mpc-auth will use the keyList from KeyGenResult). For presign mode, must be `null`.
- `presignId` (optional): Presign ID for faster signing. If provided, `keyList` must be `null`.
- `pubKey` (required): Public key (128 hex characters) from key generation
- `msgHash` (required): Keccak256 hash of the message to sign
- `msgRaw` (optional): Raw message bytes (hex encoded)
- `relayerPublicKey` (required): Relayer's public key (128 hex characters, no `0x` prefix)
- `relayerSignature` (required): Relayer's signature over the request (excluding `relayerSignature` field)
- `chainID` (optional): Chain ID for chain-specific access control
- `sourceTxHash` (optional): Source transaction hash for cross-chain operations
- `sourceChainID` (optional): Source chain ID for cross-chain operations
- `destinationChainID` (optional): Destination chain ID (EVM signatures only; stored and returned in `listSignRequests` / `getSignRequestById`)
- `destinationAddress` (optional): Destination address (EVM signatures only; stored and returned in `listSignRequests` / `getSignRequestById`)
- `extraJSON` (optional): Arbitrary JSON string for node context; used for **Ed25519** key types (not secp256k1). Stored and returned in `listSignRequests` / `getSignRequestById`.
- `signatureText` (optional): For EVM/secp256k1, a JSON string with structure `{"signature": "<function signature>", "names": ["<name1>", "<name2>", ...]}` where `signature` is the function selector text (e.g. `transfer(address,uint256)`) and `names` is an array of parameter names in order (one per argument). Example: `{"signature": "transfer(address,uint256)", "names": ["to", "amount"]}`. Other chains: program name or custom text. Stored and returned in `listSignRequests` / `getSignRequestById`.
- `purpose` (optional): Free text from the creator, max 256 characters; visible to nodes when they list or get the sign request so they can read it before calling `signRequestAgree`

**Important Notes:**
- **KeyList Handling:**
  - For **normal signing** (`presignId` empty): `keyList` should be `[]` (empty array) or a specific node key list
  - For **presign signing** (`presignId` provided): `keyList` must be `null` (not `[]`)
- **Relayer Authentication:**
  - Relayer must be whitelisted and active
  - Signature verification uses exact JSON structure matching mpc-auth's `SignRequestPost`
  - Case-sensitive: `relayerPublicKey` must match exactly what's stored in the database
- **Key type:** SignRequest only accepts keys with MsgCheck type `tx-check`. For keys with MsgCheck `multi-agree`, use `POST /multiSignRequest` instead.
- **CGGMP24 secp256k1 keys:** Signing requires a completed distributed **KeyShare**. If aux merge is incomplete, sign creation returns an error (see **`docs-internal/CGGMP24_ROADMAP.md`** in mpc-auth). **Presign is not available** for CGGMP24 ECDSA.
- **FROST presign:** When **`presignId`** is set, signing uses presign-finish (see [Pre-Signing](#7-pre-signing)).
- **Client sig for tx-check:** For `tx-check` (relayer) keys, `clientSig` is **not** verified. Relayer authentication (relayerPublicKey + relayerSignature) is sufficient. Tx-check keys are often created with a placeholder client key at keygen; the relayer is the authorized party. You may send an empty or placeholder `clientSig` for SignRequest. For `multi-agree` keys (multiSignRequest), client sig is still verified.

**Relayer-facing endpoints (no client-sig failure for tx-check flow):**

| Endpoint | Auth | Notes |
|----------|------|--------|
| `GET /version` | None | Health/version check. **"Connection refused"** here means the MPC node is not reachable (not running, wrong port, or firewall), not a signature error. |
| `POST /signRequest` | Relayer only | Requires `relayerPublicKey` + `relayerSignature`. Client sig is **not** verified for tx-check keys. |
| `GET /getSignRequestById` | None | Query by request id. |
| `GET /getSignResultById` | None | Query by request id. |
| `GET /listSignRequests` | None | List with filter/pagination. |
| `GET /getPresignRequestById`, `GET /getPresignResultById`, `GET /listPresignRequests` | None | No signature required. |

Management-key endpoints (`keyGenRequest`, `keyGenRequestRetry`, `presignRequest`, `newGroupRequest`, `newGroupRequestRetry`, etc.) are used by the node operator/frontend, not by the relayer; they require NodeMgtKey or PublicMgtKey signature.

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": "Sign20260111003720999cf104d0f"
}
```

**Example:**
```bash
curl -X POST $MPC_AUTH_URL:$MANAGEMENT_PORT/signRequest \
  -H "Content-Type: application/json" \
  -d '{
    "clientSig": "0x...",
    "keyList": [],
    "presignId": "",
    "pubKey": "08caf50811eb4c2bed7b3f8dc9c292b5cf521ba3774ea49dcd949e8235a48b22e8c1f16b356710aae4095e498bfff8385eada1e53a47dbdd984d32ae4d20a5de",
    "msgHash": "751f68b43977269a16128143fa15e0e7ab3c15ba52484fe8278796561505698b",
    "msgRaw": "",
    "relayerPublicKey": "ed8639ee02b0e0cb8caade8ea24c71b1c60c55fa241032767e67c4da6e691f5fd08a36b005a2c1fd68c9b5a04137c406d458ba73b562aa269f52ceb6a285e41a",
    "relayerSignature": "0x...",
    "chainID": "11155111",
    "sourceTxHash": "",
    "sourceChainID": ""
  }'
```

**Error Responses:**
- `400 Bad Request`: Invalid parameters (e.g., `presignId` and `keyList` combination), or key is not tx-check type
- `401 Unauthorized`: Relayer not whitelisted or invalid signature
- `403 Forbidden`: Relayer inactive or chain access denied
- `500 Internal Server Error`: Internal processing error

<a id="post-multisignrequest"></a>
#### `POST /multiSignRequest`
Creates a new signing request for **multi-agree keys only**. No relayer authentication; uses the same internal sign flow as `signRequest`. Nodes in the same GroupId must agree via `POST /signRequestAgree`; when enough nodes have agreed, the message(s) are signed. Supports **single** (one message) and **batch** (N messages in one request: one agree, one trigger, one SignResult with N signatures). Supports **gas token (native transfer) requests**: use optional `sendGas` and `value` for "Send gas" flows; they are part of the signed payload and stored in `ExtraJSON` so all nodes see them in `getSignRequestById` and `listSignRequests`.

**CGGMP24 secp256k1:** Same KeyShare completion requirement as `POST /signRequest`. **Presign is not used** for batch requests — N parallel full-sign workers run (one per batch index).

**Single vs batch:** For a **single** message, send `msgHash` (required) and optional `msgRaw`. For a **batch** of N messages (e.g. a sequence of transactions), send `messageHashes` (array of N hex strings, length ≥ 2) and optionally `messageRawBatch` (length 0 or N); do not send `msgHash`/`msgRaw` for batch. One agree and one trigger then produce one SignResult whose `batchSignatures` array holds the N signatures (see `GET /getSignResultById`). Optional **`presignId`** applies to **single-message** requests only.

**Management signature (`nonce`, `nodeKey`, `clientSig`), and `purpose` in the signed payload:**

Requires **management key authentication** (Ethereum **`NodeMgtKey`** / **`personal_sign`** or Ed25519 **`PublicMgtKey`** / added keys). Fetch the current nonce from **`GET /getPublicMgtKeyNonce`** (Ed25519) or **`GET /getNodeMgtKeyNonce`** (Ethereum) immediately before building the body. The signed message is **`json.Marshal`** of the full POST body with **`clientSig`** and **`signedMessage`** cleared (same pattern as **`POST /triggerSignRequestById`**). **`nodeKey`** (128 hex from **`GET /getNodeKey`**) is **required** and binds the signature to this MPC node.

- **`purpose` in JSON:** The `purpose` field is **always present** in the Go request struct’s JSON encoding: `encoding/json` emits **`"purpose"`** even when the value is `""`. The signed payload **must include the `purpose` key** (string, possibly empty). This aligns with the stored **Purpose** map (creator node key → text, including empty text).
- **Ethereum (`NodeMgtKey`):** `personal_sign` over the canonical JSON string (with `clientSig` cleared).
- **Ed25519 (`PublicMgtKey` or added key):** Sign the same canonical JSON string (128-hex signature).

**Request Body (single):**
```json
{
  "nonce": 1,
  "nodeKey": "<128-hex MPC node key from GET /getNodeKey>",
  "clientSig": "<management signature over JSON with clientSig cleared>",
  "keyList": ["node1_key", "node2_key", "node3_key"],
  "pubKey": "08caf50811eb4c2bed7b3f8dc9c292b5cf521ba3774ea49dcd949e8235a48b22e8c1f16b356710aae4095e498bfff8385eada1e53a47dbdd984d32ae4d20a5de",
  "msgHash": "751f68b43977269a16128143fa15e0e7ab3c15ba52484fe8278796561505698b",
  "msgRaw": "<raw message bytes, hex encoded>",
  "destinationChainID": "11155111",
  "destinationAddress": "0x...",
  "extraJSON": "{}",
  "purpose": "",
  "sendGas": true,
  "value": "1000000000000000000"
}
```

**Request Body (batch):** Same as above but use `messageHashes` and optional `messageRawBatch` instead of `msgHash`/`msgRaw`:
```json
{
  "nonce": 1,
  "nodeKey": "<128-hex MPC node key>",
  "clientSig": "...",
  "keyList": ["node1_key", "node2_key", "node3_key"],
  "pubKey": "08caf...",
  "messageHashes": ["hash1_hex", "hash2_hex", "hash3_hex"],
  "messageRawBatch": ["raw1_hex", "raw2_hex", "raw3_hex"],
  "destinationChainID": "11155111",
  ...
}
```

**Field Descriptions:**
- `nonce` (required): Anti-replay nonce from **`GET /getPublicMgtKeyNonce`** or **`GET /getNodeMgtKeyNonce`** (must match the signing key).
- `nodeKey` (required): This node's MPC public key (128 hex from **`GET /getNodeKey`**); binds the management signature to this node.
- `clientSig` (required): Management signature over the canonical JSON body with **`clientSig`** and **`signedMessage`** cleared; see **Management signature** above.
- `keyList` (required): Array of node keys in the same GroupId that may participate; can be empty array `[]` to use keyList from KeyGenResult
- `pubKey` (required): Public key (128 hex characters) from key generation (must be multi-agree key)
- `msgHash` (required for **single**): Keccak256 hash of the message to sign. Omit when using `messageHashes` (batch). **EVM broadcast:** For secp256k1 keys, if the client will build a signed tx and call `eth_sendRawTransaction`, the recovered signer must match the keyGen's `ethereumaddress`. That only holds when the signature is over the **transaction signing hash** (hash of the serialized unsigned EIP-1559/legacy tx). If the client sends a different hash (e.g. only `keccak256(msgRaw)`), the MPC signs it correctly, but using that (r,s,v) on the full tx yields a different recovered address; send the tx signing hash as `msgHash` and use the same nonce/gas when building the signed tx.
- `msgRaw` (optional, **single**): Raw message bytes (hex encoded). Omit for batch.
- `messageHashes` (optional, **batch**): Array of N message hashes (hex strings), in order. When length ≥ 2, creates a batch request; `msgHash`/`msgRaw` are ignored. Each element must be valid hex.
- `messageRawBatch` (optional, **batch**): Array of N raw messages (hex encoded) for display/audit. Length must be 0 or equal to `messageHashes` length.
- `destinationChainID` (required): Destination chain ID for the signed message (EVM signatures only; stored and returned in `listSignRequests` / `getSignRequestById` so the node key knows which chain the signature is destined for)
- `destinationAddress` (optional): Destination address (EVM signatures only; stored and returned in `listSignRequests` / `getSignRequestById`)
- `extraJSON` (optional): Arbitrary JSON string for node context; used for **Ed25519** key types (not secp256k1). Stored and returned in `listSignRequests` / `getSignRequestById`. For send-gas requests, the backend merges `sendGas` and `value` into this object before storing.
- `signatureText` (optional): For EVM/secp256k1, a JSON string with structure `{"signature": "<function signature>", "names": ["<name1>", "<name2>", ...]}` where `signature` is the function selector text (e.g. `transfer(address,uint256)`) and `names` is an array of parameter names in order. Example: `{"signature": "transfer(address,uint256)", "names": ["to", "amount"]}`. Other chains: program name or custom text. Stored and returned in `listSignRequests` / `getSignRequestById`.
- `purpose` (optional text, **required JSON key for signing**): Free text from the creator, max 256 characters; use `""` when there is no description. Visible to nodes considering `signRequestAgree` (stored and returned in list/get endpoints and `getSignResultById`). Stored as a map in `Purpose`: the creator node key (128 hex) is the key and the purpose text is the value, so the originator is identifiable even when the text is empty. The signed JSON / **`messageToSign`** **always** includes `"purpose"` (see signing rules above). Example response: `"Purpose": { "04a1b2c3...128hex": "Bridge transfer to L2" }`.
- `sendGas` (optional, **multi-agree gas token only**): Set to `true` for native transfer requests created from the Assets "Send gas" dialog. Included in the signed payload when present. Stored in `ExtraJSON` and propagated; returned in `getSignRequestById` and `listSignRequests` via `ExtraJSON`.
- `value` (optional, **multi-agree gas token only**): Amount in wei for the native transfer. Included in the signed payload when present. Stored in `ExtraJSON` and propagated; returned in `getSignRequestById` and `listSignRequests` via `ExtraJSON`. Also available in sign result metadata for Execute.
- **`txParams`** (optional, **EVM**): Proposal-time gas/nonce snapshot for **single-tx** requests — same shape as trigger/GET `txParams` (`nonce`, `gasLimit`, `txType`, EIP-1559 or legacy fee fields). Stored on **`proposal_tx_params`** (one entry) and **propagated**. **Mutually exclusive** with **`proposalTxParams`** on the same POST.
- **`proposalTxParams`** (optional, **EVM**): For **batch**, array of length **N** = **`len(messageHashes)`**, one **`txParams`‑shaped** object per index. For **single-tx**, at most **one** element (equivalent to **`txParams`**). Propagated. **Mutually exclusive** with **`txParams`**.
- **`skipMessageHashVerification`** (optional): Boolean; stored and propagated. Reserved for server-side hash recomputation policy (strict vs skip); does not change **`msgHash`** / **`messageHashes`** on the wire.

**Response (success):** Standard **`APIResponse`**. **`data`** is an object:

```json
{
  "code": 0,
  "error": "",
  "data": {
    "requestId": "Sign20260111003720999cf104d0f",
    "warnings": [
      { "code": 0, "detail": "…" }
    ]
  }
}
```

- **`requestId`:** Signing request id (same value older builds returned as a plain string in **`data`**).
- **`warnings`:** Optional array of **`{ code, detail }`** (`code` **0** = informational config/membership drift when the request still proceeds). Omitted or empty when none.

**Example:**
```bash
curl -X POST $MPC_AUTH_URL:$MANAGEMENT_PORT/multiSignRequest \
  -H "Content-Type: application/json" \
  -d '{
    "clientSig": "0x...",
    "keyList": [],
    "pubKey": "08caf50811eb4c2bed7b3f8dc9c292b5cf521ba3774ea49dcd949e8235a48b22e8c1f16b356710aae4095e498bfff8385eada1e53a47dbdd984d32ae4d20a5de",
    "msgHash": "751f68b43977269a16128143fa15e0e7ab3c15ba52484fe8278796561505698b",
    "msgRaw": "",
    "destinationChainID": "11155111",
    "destinationAddress": "0x...",
    "extraJSON": "{}",
    "purpose": ""
  }'
```

**Error Responses:**
- `400 Bad Request`: Key not found or key is not multi-agree type; for single, missing `msgHash`; for batch, invalid `messageHashes` (e.g. non-hex or `messageRawBatch` length not 0 or N); Ethereum wallet / NodeMgtKey path with empty `signedMessage`
- `401 Unauthorized`: Client signature invalid
- `500 Internal Server Error`: Internal processing error

<a id="get-listsignrequests"></a>
#### `GET /listSignRequests`
Lists all signing requests with filtering and pagination. Use this (and `getSignRequestById`) to see which node keys have already agreed: **SigList** contains node key → signature for each node that has agreed; any node in **KeyList** that is missing from SigList or has an empty signature can still call `POST /signRequestAgree`.


**Query Parameters:**
- `filter` (optional): `all`, `live`, `pending`, `success`, `blocked`, `shelved` (default: `all`). Values align with sign request lifecycle status.
  - `all`: All sign requests (any status, including `live`)
  - `live`: Sign requests with status `live` (active requests not yet agreed by this node, success, blocked, or shelved)
  - `pending`: Sign requests with status `pending` (this node has called signRequestAgree; not propagated to other nodes)
  - `success`: Sign requests with status `success` (a sign result was created for the request)
  - `blocked`: Sign requests with status `blocked` (MPC quorum agreements can no longer be reached among remaining participants)
  - `shelved`: Sign requests with status `shelved` (originator shelved the request)
- `pagenum` (optional, default: 0)
- `pagesize` (optional, default: 10)
- `fromTime` (optional): Only include requests with `timepoint` ≥ this value (Unix timestamp in seconds).
- `toTime` (optional): Only include requests with `timepoint` ≤ this value (Unix timestamp in seconds). If both `fromTime` and `toTime` are set, `fromTime` must be ≤ `toTime`.

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": [
    {
      "requestid": "Sign20260111003720999cf104d0f",
      "PubKey": "08caf50811eb4c2bed7b3f8dc9c292b5cf521ba3774ea49dcd949e8235a48b22...",
      "MessageHash": "751f68b43977269a16128143fa15e0e7ab3c15ba52484fe8278796561505698b",
      "MessageRaw": "",
      "KeyList": ["node1_key", "node2_key", "node3_key"],
      "PresignId": "",
      "ClientSigs": {
        "node1_key": "0x...",
        "node2_key": ""
      },
      "SigList": {
        "node1_key": "80485a105bbdefc74c3e08e51c39f2bbcac037679bde0956c02e6709b996e9f3...",
        "node2_key": ""
      },
      "IsTestTransaction": true,
      "DestinationChainID": "11155111",
      "DestinationAddress": "0x...",
      "ExtraJSON": "{}",
      "SignatureText": "{\"signature\": \"transfer(address,uint256)\", \"names\": [\"to\", \"amount\"]}",
      "RejectedBy": [],
      "Purpose": { "04a1b2c3d4e5f6...128hex": "Bridge transfer to L2" },
      "Thoughts": {},
      "KeyGenRequestId": "KeyGen20260217130529999704c2304",
      "timepoint": "2026-01-11T00:37:20Z"
    }
  ]
}
```

**Note:** `Purpose` is a key/value map: node key (128 hex) → purpose text. For **multiSignRequest** the creator node key is the key and the purpose text they sent is the value; for **signRequest** (tx-check) the node that received the request is the key and the purpose text is the value.

**Response field descriptions (each item in `data`):**
- `requestid`: Sign request ID (use with `POST /signRequestAgree` and `GET /getSignResultById`)
- `PubKey`: MPC public key (128 hex) for this sign request
- `MessageHash`, `MessageRaw`: For **single** requests, the message to sign (Keccak256 hash and optional raw bytes). For **batch** requests, `MessageHash`/`MessageRaw` are the first element; use `MessageHashes`/`MessageRawBatch` for the full list.
- `BatchSignRequest` (optional): When `true`, this is a batch request; use `MessageHashes` and optionally `MessageRawBatch`.
- `BatchSize` (optional): Number of messages in the batch (N); present when `BatchSignRequest` is true.
- `MessageHashes` (optional): When batch, array of N message hashes (hex), in order.
- `MessageRawBatch` (optional): When batch, array of N raw messages (hex) for display/audit; may be empty.
- `KeyList`: Node keys that may participate in signing (same GroupId as the key)
- `PresignId`: If set, this request uses a presign; otherwise normal signing
- `ClientSigs`: Map of node key → client signature (from the node when agreeing); empty or missing means that node has not agreed yet
- `SigList`: Map of node key → agreement signature for nodes that have agreed. **If a node is in KeyList but missing from SigList or has an empty value, that node can call `POST /signRequestAgree`.**
- `IsTestTransaction`: Whether the request was created without source tx verification
- `DestinationChainID`: Chain ID the signature is destined for (EVM signatures only). Set for requests created via `multiSignRequest` or passed in `signRequest`; empty if not provided.
- `DestinationAddress`: Destination address when provided at request creation (EVM signatures only); empty if not provided.
- `ExtraJSON`: Arbitrary JSON string passed at request creation (e.g. for node context); stored and returned in listSignRequests; empty if not provided. For **multi-agree send-gas** requests, the backend merges `sendGas` and `value` into this object, so the app can read them for Join/Execute UI and for building the native transfer at Get Sig/Execute.
- `SignatureText`: For EVM/secp256k1, JSON string `{"signature": "<function signature>", "names": ["<name1>", ...]}` (signature = selector text, names = parameter names in order). Other chains: program name or custom text. Stored and returned in listSignRequests; empty if not provided.
- `RejectedBy`: (multi-agree only) List of node keys that declined to sign.
- `Purpose`: Key/value map: node key (128 hex) → purpose text (max 256 chars per entry). Visible to nodes considering agree/reject. The key identifies which node created or submitted the request (multiSignRequest: creator node; signRequest/tx-check: node that received the request).
- `Thoughts`: Map of node key → optional comment (max 256 chars each) from each node when they called `signRequestAgree` (accept or reject).
- `KeyGenRequestId`: Key generation request ID (keyGenId) for the MPC key used by this sign request (same as the keygen request that produced `PubKey`). Included in listSignRequests, getSignRequestById, getSignResultById, and listSignRequestsReady.
- `status`: Sign request lifecycle status: `"live"` (default after creation), `"pending"` (set locally when this node has called `POST /signRequestAgree`; not propagated), `"shelved"` (set by the originator via `POST /shelveSignRequest`), `"blocked"` (set automatically when the **MPC quorum** can no longer be reached), or `"success"` (set when a sign result is created). Omitted or `"live"` until set.
- `timepoint`: When the request was recorded

**Example:**
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/listSignRequests?filter=all&pagenum=0&pagesize=10"
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/listSignRequests?filter=live&pagenum=0&pagesize=10"
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/listSignRequests?filter=pending&pagenum=0&pagesize=10"
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/listSignRequests?filter=success&pagenum=0&pagesize=10"
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/listSignRequests?filter=blocked&pagenum=0&pagesize=10"
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/listSignRequests?filter=shelved&pagenum=0&pagesize=10"
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/listSignRequests?filter=all&pagenum=0&pagesize=10&fromTime=1704067200&toTime=1704153600"
```

<a id="get-getsignrequestbyid"></a>
#### `GET /getSignRequestById`
Gets a specific signing request by ID. Returns the same structure as each item in `listSignRequests` (including `KeyGenRequestId`, `DestinationChainID`, `Purpose`, **`proposalTxParams`** / **`proposal_tx_params`** when set at **`multiSignRequest`**, **`TxParams`** / **`executeTxParams`** for **local** execute snapshots after trigger — field names match the JSON your **mpc-auth** build emits). Optional fields only appear if this node is running a build that includes them (see note under `listSignRequests`).

**Query Parameters:**
- `id` (required): Sign request ID
- `tx_params` (optional): If `1`, response **`data`** is **only** the TxParams payload for **Execute**, not the full sign request:
  - **Single-tx:** one JSON **object** (`nonce`, `gasLimit`, `txType`, EIP-1559 or legacy fee fields).
  - **Batch** (multiple `messageHashes`): JSON **array** of **N** objects — one per batch index — in order. **Precedence per slot:** if the originator ran **`POST /triggerSignRequestById`** on **this** node, the merged **execute** snapshot (**`execute_tx_params`**) is returned when present; otherwise **`proposal_tx_params`** for that index; if neither exists for that index, the slot may be `null` or missing depending on stored data.

Without **`tx_params=1`**, full sign request JSON includes propagated **`proposal_tx_params`** (and on the originator after trigger, local **`execute_tx_params`** / **`TxParams`** for execute snapshots — not propagated to peers). On the **originator**, **`messageHashes`** / **`messageRawBatch`** on the sign request may be **updated** when trigger included optional **`messageHashes`** / **`messageRawBatch`** (fee bump or dropping a leg — see [triggerSignRequestById](#post-triggersignrequestbyid)); other nodes’ **`SIGNREQUEST`** documents may still show **proposal** digests — use **`GET /getSignResultById`** for the **SignResult** snapshot all signers used after confirm.

**EVM Execute:** Callers should prefer **`?tx_params=1`** so automation gets the same nonce/gas/fees used for the signing digest (**`MessageHash`** or batch **`messageHashes`**). If **`data`** is **`null`**, proposal fields were not sent at **`multiSignRequest`** and trigger did not persist a merged snapshot — use **`--sign-request-file`** / compose output or trigger with **`txParams`** / **`txParamsBatch`** as documented under [triggerSignRequestById](#post-triggersignrequestbyid).

**Example:**
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getSignRequestById?id=Sign20260111003720999cf104d0f"
```

**Example (TxParams only):**
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getSignRequestById?id=Sign20260111003720999cf104d0f&tx_params=1"
```

<a id="post-signrequestagree"></a>
#### `POST /signRequestAgree`
Agrees to or rejects a signing request. **Requires management key authentication** for **multi-agree** keys (same **`nonce` + `nodeKey` + `clientSig`** pattern as **`POST /triggerSignRequestById`**, **`POST /presignRequestAgree`**, etc.). **tx-check (relayer)** keys are unchanged: request body may be `requestId` only; no management signature is verified.

- **tx-check (relayer):** Unchanged. Request body is `requestId` (+ optional `clientSig`); no `accept` or `thoughts` field. Relayer flow is not affected.
- **multi-agree:** Optional `accept` (boolean). Omitted or `true` = agree to sign (same as before). `false` = reject: this node is recorded as having declined in **RejectedBy**. The client must sign the canonical JSON body (including `requestId`, `nonce`, `nodeKey`, `clientSig` empty, `accept`, and `thoughts` when present). Other nodes may still agree; rejection is per-node.

**Request Body:**
- `requestId` (required): Sign request ID
- `nonce` (required for multi-agree when management sig check enabled): From **`GET /getPublicMgtKeyNonce`** (Ed25519) or **`GET /getNodeMgtKeyNonce`** (Ethereum **`NodeMgtKey`**)
- `nodeKey` (required for multi-agree): This node's MPC public key (128 hex from **`GET /getNodeKey`**); binds the signature to this node
- `clientSig` (required for multi-agree when management sig check enabled): Management signature over **`json.Marshal`** of the body with **`clientSig`** and **`signedMessage`** cleared (includes `requestId`, `nonce`, `nodeKey`, `accept`, `thoughts` when present)
- `accept` (optional, **multi-agree only**): `true` or omitted = agree to sign; `false` = reject (drops from this node's pending list). Ignored for tx-check.
- `thoughts` (optional): Comment from this node when agreeing or rejecting, max 256 characters; stored per node key and returned in list/get and `getSignResultById`.

**Example (multi-agree agree):**
```json
{ "requestId": "Sign20260111003720999cf104d0f", "nonce": 1, "nodeKey": "<128-hex>", "clientSig": "0x...", "accept": true }
```

**Example (multi-agree agree with thoughts):**
```json
{ "requestId": "Sign20260111003720999cf104d0f", "nonce": 1, "nodeKey": "<128-hex>", "clientSig": "0x...", "accept": true, "thoughts": "Verified on explorer" }
```

**Example (multi-agree reject):**
```json
{ "requestId": "Sign20260111003720999cf104d0f", "nonce": 1, "nodeKey": "<128-hex>", "clientSig": "0x...", "accept": false }
```

**Example (multi-agree reject with thoughts):**
```json
{ "requestId": "Sign20260111003720999cf104d0f", "nonce": 1, "nodeKey": "<128-hex>", "clientSig": "0x...", "accept": false, "thoughts": "Risk too high" }
```

**Response:**
- On agree: `"data": "success to agree signrequest with requestid ..."`
- On reject (multi-agree only): `"data": "success to reject signrequest with requestid ..."`

<a id="get-listsignresults"></a>
#### `GET /listSignResults`
Lists sign results with optional filter and pagination. Each item in the response has the **same fields** as a single `GET /getSignResultById` result (requestid, messagehash, sigdata, sigr, sigs, sigrecover, timepoint, keylist, participatingkeys, signaturehex, keytype, signatureformat, DestinationChainID, DestinationAddress, ExtraJSON, RejectedBy, Purpose, Thoughts, KeyGenRequestId, status, transactionhash, shelved, and ethereumSignature when applicable). For **batch** sign results, each item also includes `batchSignResult`, `batchSize`, and `batchSignatures` (array of N signature entries); see `GET /getSignResultById` for the batch response shape.

**Query Parameters:**
- `filter` (optional, default `"all"`): `"all"` — all sign results (including **`failed`** for History); `"active"` — status is not `"executed"` and not `"shelved"` (includes never-updated, **`failed`** single-tx awaiting retry, and batch **`failed`**); `"originator"` — only results where this node's key is the key in the **Purpose** map.
- `pagenum` (optional): Page number (0-based). Used only when `pagesize` > 0.
- `pagesize` (optional): Page size. Use `0` to return all results for the filter (no pagination).
- `fromTime` (optional): Unix timestamp in seconds (Linux time). Only include sign results whose stored **timepoint** is greater than or equal to this time. Ignored if omitted.
- `toTime` (optional): Unix timestamp in seconds (Linux time). Only include sign results whose stored **timepoint** is less than or equal to this time. Ignored if omitted. If both `fromTime` and `toTime` are set, `fromTime` must be ≤ `toTime`.

**Response:** When pagination is used (`pagesize` > 0), the response includes a top-level `total` field with the total number of items matching the filter (so clients can show "Page X of Y" and compute total pages).
```json
{
  "code": 0,
  "error": "",
  "data": [
    {
      "requestid": "Sign20260111003720999cf104d0f",
      "messagehash": "...",
      "sigdata": { "R": "...", "S": "..." },
      "sigr": "...",
      "sigs": "...",
      "sigrecover": "...",
      "timepoint": "2026-01-11T00:37:25.123Z",
      "keylist": ["..."],
      "participatingkeys": ["..."],
      "signaturehex": "...",
      "keytype": "ed25519",
      "signatureformat": "ed25519",
      "DestinationChainID": "11155111",
      "DestinationAddress": "0x...",
      "ExtraJSON": "{}",
      "RejectedBy": [],
      "Purpose": { "04a1b2...128hex": "Bridge transfer to L2" },
      "Thoughts": {},
      "KeyGenRequestId": "KeyGen20260217130529999704c2304",
      "status": "executed",
      "transactionhash": "0xabc123...",
      "shelved": false
    }
  ],
  "total": 42
}
```

- `data`: Array of sign result objects for the requested page.
- `total`: Total number of sign results matching the filter (all pages). Always returned so clients can show "Page X of Y" when using pagination.

Results are sorted by **timepoint** descending. Field meanings are the same as in `GET /getSignResultById`.

**Example:**
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/listSignResults?filter=active&pagenum=0&pagesize=10"
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/listSignResults?filter=originator&pagesize=0"
# Date filter: only results between two Unix timestamps (e.g. 1704931200 = 2024-01-11 00:00:00 UTC and 1705017600 = 2024-01-12 00:00:00 UTC)
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/listSignResults?filter=all&fromTime=1704931200&toTime=1705017600&pagenum=0&pagesize=10"
```

<a id="get-getsignresultbyid"></a>
#### `GET /getSignResultById`
Gets a specific signing result by ID. Returns the signature data. For **single** requests the result has one signature in the top-level fields; for **batch** requests the result has `batchSignResult: true`, `batchSize`, and `batchSignatures` (array of N signature entries).

**Query Parameters:**
- `id` (required): Sign request ID

**Not ready:** Until the signature(s) are ready, the API returns `code: 1` with error message `signresults with id ... is not ready, pls query again after 5 seconds` (single) or `signresults with id ... is not ready (batch), pls query again after a few seconds` (batch). For batch, "ready" means all N slots in `batchSignatures` have been filled.

**Response (single):**
```json
{
  "code": 0,
  "error": "",
  "data": {
    "requestid": "Sign20260111003720999cf104d0f",
    "messagehash": "751f68b43977269a16128143fa15e0e7ab3c15ba52484fe8278796561505698b",
    "sigdata": {
      "R": "...",
      "S": "..."
    },
    "sigr": "...",
    "sigs": "...",
    "sigrecover": "...",
    "timepoint": "2026-01-11T00:37:25.123Z",
    "keylist": ["node1_key", "node2_key", "node3_key"],
    "participatingkeys": ["1711c3077fc974b538fe6a786aae141f35f07e0ae7a91e89ebd1aed67f16846fea83a3d3b51a0c30d1d908dbf3f5ddfe71e0c03a0a0afa200a1e4cacfe223c3e", "a14ed80f88e0ce9cca05e3e11fe5475430d0908536dfc9584bb4544f5029a271a74b743f3865ce4f5c6e6f0ea3079ed040404bdb366eedd2bac7f460f2db2e1a"],
    "signaturehex": "...",
    "keytype": "ed25519",
    "signatureformat": "ed25519",
    "DestinationChainID": "11155111",
    "DestinationAddress": "0x...",
    "ExtraJSON": "{}",
    "RejectedBy": [],
    "Purpose": { "04a1b2c3d4e5f6...128hex": "Bridge transfer to L2" },
    "Thoughts": {},
    "KeyGenRequestId": "KeyGen20260217130529999704c2304",
    "status": "executed",
    "transactionhash": "0xabc123...",
    "shelved": false
  }
}
```

**Response (batch):** Same as above, plus:
- `batchSignResult`: `true`
- `batchSize`: N (number of messages in the batch)
- `batchSignatures`: Array of N objects, one per message, in order. Each object has:
  - `messagehash`: The message hash that was signed
  - `sigr`, `sigs`, `sigrecover`: Signature components (same as top-level for single)
  - `signaturehex`: Full signature as hex (convenience)
  - `ethereumsignature`: Ethereum r\|s\|v format when key type is secp256k1

Use `data.batchSignatures[i]` to get the signature for the i-th message (index 0 to N−1). Execute transactions in order: get signature for index 0, broadcast tx 0, then index 1, etc.

**Note:** `Purpose` in the result is a key/value map (node key → purpose text). `KeyGenRequestId` is the keygen id for the MPC key. **Status** is set via `POST /updateSignResultStatusById`: `"executed"` (with `transactionHash` or `batchTransactionHashes`), `"failed"` (single-tx or partial batch), or `"shelved"`. **`batchTransactionHashes`** (array) is stored for batch **executed** and partial **failed**; list/get return it when the node persists it. Single-tx **`failed`** can later become **`executed`** on retry.

**Field Descriptions:**
- `keylist`: Array of node keys that were selected to participate in signing (filtered to only online nodes)
- `participatingkeys`: Array of node keys that actually participated in signing (derived from `SigList`, sorted alphabetically). This is the definitive list of nodes that contributed to the signature.
- `signaturehex` (single): Full signature as hex string (64 bytes = 128 hex chars for both secp256k1 and ed25519)
- `keytype`: Key type used ("secp256k1" or "ed25519")
- `signatureformat`: Signature format ("ieee-p1363" for secp256k1, "ed25519" for ed25519)
- `DestinationChainID`, `DestinationAddress`, `ExtraJSON`, `RejectedBy`, `Purpose`, `Thoughts`, `KeyGenRequestId`: Same as in the sign request; merged from the latest sign request so the result includes this metadata. For **send-gas** (multi-agree native transfer) requests, `ExtraJSON` contains `sendGas` and `value` (wei) so the app can build the native transfer at Execute. `Purpose` is a key/value map (node key → purpose text); see note above and listSignRequests field descriptions. `KeyGenRequestId` is the key generation request ID (keyGenId) for the MPC key.
- `status`: `"executed"` | `"failed"` | `"shelved"` (originator via `updateSignResultStatusById`). Omitted until set.
- `transactionhash` / `transactionHash`: Single-tx hash when executed; often last hash for display when batch executed server-side stores per-hash in `batchTransactionHashes`.
- `batchtransactionhashes` / `batchTransactionHashes`: Batch only; all hashes when executed; partial list when failed mid-batch.
- `shelved`: Boolean; `true` when the originator marked the result as shelved (not to be broadcast). Set when `status` is `"shelved"`. Omitted or false until set.

**When `status` is `"shelved"`:** The API does not return the signature. The fields `sigdata`, `sigr`, `sigs`, `sigrecover`, `signaturehex`, and `ethereumsignature` are omitted from the response for both `GET /getSignResultById` and each item in `GET /listSignResults`. For batch, each entry in `batchSignatures` is also redacted (signature fields cleared).

**Example:**
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getSignResultById?id=Sign20260111003720999cf104d0f"
```

<a id="get-issignrequestreadybyid"></a>
#### `GET /isSignRequestReadyById`
Returns whether a sign request is **ready to trigger** (multi-agree only). Ready means **SigList** has at least the **MPC quorum** (see keygen **`threshold`** semantics). For tx-check or non–multi-agree keys, returns `ready: false`. Use this before calling `POST /triggerSignRequestById`.

**Query Parameters:**
- `id` (required): Sign request ID.

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": {
    "ready": true,
    "requestId": "Sign20260111003720999cf104d0f"
  }
}
```

**Example:**
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/isSignRequestReadyById?id=Sign20260111003720999cf104d0f"
```

<a id="get-listsignrequestsready"></a>
#### `GET /listSignRequestsReady`
Lists **multi-agree** sign requests that are **ready to trigger**: this node is in the agreeing set (**SigList**), at least **MPC quorum** have agreed (see keygen **`threshold`**), and the request has **not** yet been triggered (no sign result). Use `GET /getSignResultById` to see when the signature is ready after triggering. Supports pagination.

**Query Parameters:**
- `pagenum` (optional): Page number (default `0`).
- `pagesize` (optional): Page size (default `10`). Use `0` to return all.

**Response:** Same structure as `GET /listSignRequests` (array of sign request objects, including `KeyGenRequestId`). Only includes requests that are ready and where this node is in **SigList**.

**Rejections and keyGen:** Rejecting a sign request (`POST /signRequestAgree` with `accept: false`) only adds this node to **RejectedBy**; it does **not** remove or alter the keyGen request or keyGen result. "Ready" is based solely on **SigList** (agreeing nodes): if **SigList** reaches the **MPC quorum** for this key (**t** parties for CGGMP24 and FROST), the request is ready regardless of **RejectedBy** (unless blocked by remaining-participant logic). If a quorum-ready agreement does **not** appear in `listSignRequestsReady` or `triggerSignRequestById` fails with "keygen result for pubkey ... not found", the **keyGen result** is missing on this node. The keyGen result is only deleted when **keygen** failed: fewer than **MPC quorum** parties sent KEYGENRESULTCONFIRMSUCCESS within 7 days; then the result is deleted and the keyGen **request** is marked `"failed"` (the request document is not deleted). In that case the key is unusable for signing. The keyGen request remains in the DB with status `"failed"`; only the keyGen **result** (the actual key material) is removed.

**Example:**
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/listSignRequestsReady?pagenum=0&pagesize=10"
```

<a id="post-triggersignrequestbyid"></a>
#### `POST /triggerSignRequestById`
**Multi-agree only.** When at least the **MPC quorum** for this key have accepted in **SigList** (and rejections are excluded), triggers signature generation: sends **SIGNREQUESTCONFIRMSUCCESS** and starts the sign worker(s). For **single** requests, one signature is produced; for **batch** requests, one trigger produces one SignResult with N signatures (retrieved via `GET /getSignResultById` as the `batchSignatures` array). **Only the originator may call this:** the request’s **Purpose** map must have this node’s key as the (originator) key; otherwise the server returns an error. **If the sign request status is `"shelved"`** (set via `POST /shelveSignRequest`), the server returns an error and does not trigger. **Idempotent:** if the request was already triggered, returns success with data `"Already triggered"`. Does not affect tx-check flow. Requires management key signature (Ethereum wallet / NodeMgtKey or Ed25519).

**EVM unsigned transaction (typical `executeSignResult` / broadcast):** The originator should include **`messageHash`** (single-tx: the **RLP/unsigned-tx** signing hash the MPC will sign; if present, the backend updates the sign request’s **MessageHash** on this node before the worker runs). For gas/nonce/fees stored on **this node only** (not propagated), send:
- **`txParams`**: one object — used for **single-tx**, or for **batch** merged **only at index 0** with **`proposal_tx_params[0]`** unless **`txParamsBatch`** is set (see below).
- **`txParamsBatch`** (optional, **batch only**): array of length **N** = **`len(messageHashes)`**; each element merges with **`proposal_tx_params[i]`** into **`execute_tx_params[i]`** on this node. Do not send both **`txParams`** and **`txParamsBatch`** in the same request.

**Batch digests (fee bump / raw refresh / skip a leg):** Optional **`messageHashes`** and **`messageRawBatch`** (each length **N**, same as the batch agreed at **`multiSignRequest`**) update the per-leg signing digests and optional raw tx bytes on the **originator** only. **`SIGNREQUESTCONFIRMSUCCESS`** carries the new list so all participating nodes run MPC against the same hashes. Use this when EIP-1559 / legacy fee fields change the unsigned tx (new **keccak** per leg). **Skipping a leg:** set **`messageHashes[i]`** to **`""`** (empty string); that index gets **no** signature slot (at least one index must remain non-empty). **`messageRawBatch`** must be sent with the **same length** as **`messageHashes`** when both are present. **`messageHashes`** / **`messageRawBatch`** are invalid on **single-tx** triggers.

**Automation note (this repo):** **`executeSignResult.py`**, **`mpc_event_listener.py`**, and the **continuumdao-node-app** agent guides assume **`POST /multiSignRequest`** carries **unsigned EVM transaction** material (**`msgRaw`** / **`messageRawBatch`** + **`txParams`** alignment). **`POST /triggerSignRequestById`** therefore includes **`txParams`** / **`txParamsBatch`** and **`messageHash`** (and for batch, optionally **`messageHashes`** / **`messageRawBatch`**) as below. mpc-auth may still accept a **minimal** trigger body (management **`requestId`**, **`nonce`**, **`sig`** only) for **legacy** proposals that are not standard unsigned txs; that path is **not** used by the supported Python automation.

After trigger, **`GET /getSignRequestById?tx_params=1`** returns the **merged** execute snapshot(s) when present; if the client already sent full **`proposalTxParams`** at **`multiSignRequest`**, **`?tx_params=1`** can still return usable params **before** trigger (proposal only).

**Request Body:**
```json
{
  "requestId": "Sign20260111003720999cf104d0f",
  "nonce": 1,
  "sig": "0x..."
}
```

Minimal body above is structurally valid. **For supported automation,** add `messageHash` and `txParams` and/or `txParamsBatch` as below (see **`executeSignResult.py`** and **`./instructions.md`**).

- `requestId` (required): Sign request ID.
- `nonce`, `sig`: Management key signature over the JSON body with `sig` set to empty (same as other mgt-key endpoints).
- `txParams` (**EVM**): Object with `nonce` (number), `gasLimit` (string), `txType` (`"eip1559"` or `"legacy"`), and for EIP-1559: `maxFeePerGas`, `maxPriorityFeePerGas` (strings); for legacy: `gasPrice` (string). **Local only** (not propagated). Merged with **`proposal_tx_params[0]`** into the Execute snapshot (**`TxParams`** for single-tx; index **0** for batch when **`txParamsBatch`** is omitted). Returned via **`GET ...?tx_params=1`** (single object or array index 0) after merge.
- `txParamsBatch` (optional, **EVM**, **batch**): Array of **N** objects (same shape as `txParams`); merges per index with **`proposal_tx_params`** into **`execute_tx_params`**. Mutually exclusive with **`txParams`**.
- `messageHash` (optional, **EVM** single-tx when the preimage is an **unsigned transaction**): The **transaction signing hash** (hex, typically 64 hex chars without `0x`) for the unsigned RLP-style tx. The backend updates the sign request's **`MessageHash`** on **this node only** before starting the sign worker. Not propagated. For **batch**, do not use this field for per-leg hashes — use **`messageHashes`** instead.
- `messageHashes` (optional, **batch only**): Array of length **N** = agreed batch size. Replaces the **`messageHashes`** on the originator’s sign request and is embedded in **`SIGNREQUESTCONFIRMSUCCESS`** so every node signs the same digests. Each element is hex (same rules as at **`multiSignRequest`**) or **`""`** to **skip** MPC for that index. At least one element must be non-empty.
- `messageRawBatch` (optional, **batch only**): Array of length **N**; must match **`messageHashes`** length when both are sent. Updates stored per-leg raw material (e.g. serialized unsigned txs) on the originator. If you only send **`messageHashes`**, stale **`messageRawBatch`** may be cleared when its length no longer matches (backend behavior); prefer sending both when execution tooling needs updated raws.

**Response (triggered):**
```json
{
  "code": 0,
  "error": "",
  "data": "Triggered"
}
```

**Response (already triggered):**
```json
{
  "code": 0,
  "error": "",
  "data": "Already triggered"
}
```

**Errors:** If the node posting is not the originator (this node’s key is not the key in the Purpose map), the server returns `500` with error message like: `only the originator (node key in Purpose) can trigger this sign request`. If the sign request status is `"shelved"`, the server returns `500` with error: `sign request ... is shelved; cannot trigger signature generation`.

**Example (management + request id only — minimal trigger; may apply to legacy proposals outside supported automation):**
```bash
curl -X POST $MPC_AUTH_URL:$MANAGEMENT_PORT/triggerSignRequestById \
  -H "Content-Type: application/json" \
  -d '{
    "requestId": "Sign20260111003720999cf104d0f",
    "nonce": 1,
    "sig": "0x..."
  }'
```

**Example (EVM unsigned tx):** include **`txParams`** and **`messageHash`** in the JSON body (values must match the unsigned tx you intend to broadcast). Shape matches **`continuumdao-node-app`** Get Sig / **`docs/SIGN_REQUEST_TX_PARAMS.md`** in the **continuumdao-node-app** repo.

<a id="post-updatesignresultstatusbyid"></a>
#### `POST /updateSignResultStatusById`
**Originator only.** Updates the sign result status so that nodes see it in `GET /getSignResultById` and `GET /listSignResults`. Only the node that created the sign request (originator: node key in **Purpose**) may call. Requires management key signature (Ethereum wallet / NodeMgtKey or Ed25519).

**Final vs retryable:**
- **`executed`** and **`shelved`** are terminal for a sign result (no further status updates except as below).
- **`failed`**: Broadcast did not complete as intended. **Single-tx only**—after `failed`, the originator may call again with **`executed`** and `transactionHash` when a retry broadcast succeeds (**failed → executed**). **Batch** results cannot be retried via status; use `failed` with `batchTransactionHashes` listing only the txs that did broadcast before the failure.
- For **`executed`**, at most one successful update applies unless the current status is **`failed`** (single tx retry).

**Status values:**
- **`executed`**: Success. **Single tx:** send `transactionHash`. **Batch:** send `batchTransactionHashes` (array length = batch size; one hash per broadcast tx in order). For batch indices **skipped** at trigger (**`messageHashes[i]`** was empty — no signature), **`batchTransactionHashes[i]`** may be **`""`**; every **signed** leg must have a non-empty tx hash. Do not send a redundant `transactionHash` for batch when all hashes are in `batchTransactionHashes`.
- **`failed`**: **Single tx:** broadcast failed (or not attempted); omit `transactionHash` and `batchTransactionHashes`. **Batch partial:** send `batchTransactionHashes` with only the hashes that were broadcast successfully before stopping (length ≤ batch size).
- **`shelved`**: Will not broadcast. Set `shelved: true` (or omit; backend sets true). No `transactionHash` / `batchTransactionHashes`.

**Request Body (single tx executed):**
```json
{
  "requestId": "Sign20260111003720999cf104d0f",
  "status": "executed",
  "transactionHash": "0xabc123...",
  "nonce": 1,
  "sig": "0x..."
}
```

**Request Body (batch executed — all txs broadcast):**
```json
{
  "requestId": "Sign20260111003720999cf104d0f",
  "status": "executed",
  "batchTransactionHashes": ["0xaaa...", "0xbbb..."],
  "nonce": 1,
  "sig": "0x..."
}
```

**Request Body (single tx failed, e.g. after RPC error):**
```json
{
  "requestId": "Sign20260111003720999cf104d0f",
  "status": "failed",
  "nonce": 1,
  "sig": "0x..."
}
```

**Request Body (batch partial failure):**
```json
{
  "requestId": "Sign20260111003720999cf104d0f",
  "status": "failed",
  "batchTransactionHashes": ["0xaaa..."],
  "nonce": 1,
  "sig": "0x..."
}
```

For shelved:
```json
{
  "requestId": "Sign20260111003720999cf104d0f",
  "status": "shelved",
  "shelved": true,
  "nonce": 1,
  "sig": "0x..."
}
```

- `requestId` (required): Sign request ID (must already have a sign result).
- `status` (required): `"executed"`, `"failed"`, or `"shelved"`.
- `transactionHash`: Required when `status` is `"executed"` **for a single-tx** sign result (or use one element in `batchTransactionHashes` only for batch).
- `batchTransactionHashes`: Required when `status` is `"executed"` **for a batch** (length = batch size). Required when `status` is `"failed"` **for a batch** (partial list of successful tx hashes). Omit for single-tx `failed`.
- `shelved`: Optional when `status` is `"shelved"`.
- `nonce`, `sig`: Management key signature over the JSON body with `sig` set to empty (canonical JSON of the struct fields the server unmarshals).

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": "Updated"
}
```

**Errors:** Non-originator or missing Purpose returns 500. Sign result not found returns 500. Status already **`executed`** or **`shelved`** returns 500. From **`failed`** (single tx), only **`executed`** is accepted next.

**Examples:**
```bash
curl -X POST $MPC_AUTH_URL:$MANAGEMENT_PORT/updateSignResultStatusById \
  -H "Content-Type: application/json" \
  -d '{"requestId":"...","status":"executed","transactionHash":"0x...","nonce":1,"sig":"0x..."}'
```

<a id="post-shelvesignrequest"></a>
#### `POST /shelveSignRequest`
**Originator only.** Sets the sign request lifecycle status to `"shelved"`. Only the node that created the sign request (originator: node key in **Purpose**) may call. The update is propagated to other nodes so all nodes see the status in `GET /getSignRequestById` and `GET /listSignRequests`. **The update can only happen once:** if the sign request is already shelved or blocked, a second call returns an error. Requires management key signature (Ethereum wallet / NodeMgtKey or Ed25519). **Note:** When a node rejects via `POST /signRequestAgree` with `accept: false`, if the number of remaining nodes that could still agree falls below the **MPC quorum** for this key, the backend automatically sets the sign request status to `"blocked"` and propagates it to other nodes; `GET /getSignRequestById` then returns `"status": "blocked"`.

**Request Body:**
- `requestId` (required): Sign request ID.
- `nonce`, `sig`: Management key signature over the JSON body with `sig` set to empty.

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": "Shelved"
}
```

**Errors:** Non-originator or missing Purpose returns 500. Sign request not found or already shelved returns 500.

**Example:**
```bash
curl -X POST $MPC_AUTH_URL:$MANAGEMENT_PORT/shelveSignRequest \
  -H "Content-Type: application/json" \
  -d '{
    "requestId": "Sign20260111003720999cf104d0f",
    "nonce": 1,
    "sig": "0x..."
  }'
```

### 9. Relayer Management

All relayer management endpoints are under the `/admin/` prefix.

<a id="post-admin-registerrelayer"></a>
#### `POST /admin/registerRelayer`
Registers a new relayer in the whitelist. **Can only be called once per node** - subsequent attempts will be rejected.

**Request Body:**
```json
{
  "relayerPublicKey": "ed8639ee02b0e0cb8caade8ea24c71b1c60c55fa241032767e67c4da6e691f5fd08a36b005a2c1fd68c9b5a04137c406d458ba73b562aa269f52ceb6a285e41a",
  "relayerName": "my-relayer",
  "allowedChains": ["11155111", "1", "421614"],
  "registeredBy": "node-operator",
  "metadata": {
    "relayerAPIURL": "http://82.208.20.136:8080",
    "source": "manual-registration"
  }
}
```

**Field Descriptions:**
- `relayerPublicKey` (optional if `RelayerAPIURL` configured): Relayer public key (128 hex characters, no `0x` prefix). If omitted, will be fetched from `RelayerAPIURL` in config.
- `relayerName` (required): Human-readable name for the relayer
- `allowedChains` (optional): Array of chain IDs the relayer can access. Empty array means access to all chains.
- `registeredBy` (optional): Who registered the relayer
- `metadata` (optional): Additional metadata (e.g., `relayerAPIURL`, `source`)

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": "Relayer my-relayer registered successfully with public key"
}
```

**Error Responses:**
- `400 Bad Request`: Invalid public key format or missing required fields
- `403 Forbidden`: Relayer already registered (only one registration allowed per node)
- `500 Internal Server Error`: Failed to register relayer

**Example:**
```bash
curl -X POST $MPC_AUTH_URL:$MANAGEMENT_PORT/admin/registerRelayer \
  -H "Content-Type: application/json" \
  -d '{
    "relayerPublicKey": "ed8639ee02b0e0cb8caade8ea24c71b1c60c55fa241032767e67c4da6e691f5fd08a36b005a2c1fd68c9b5a04137c406d458ba73b562aa269f52ceb6a285e41a",
    "relayerName": "my-relayer",
    "allowedChains": ["11155111"],
    "registeredBy": "operator",
    "metadata": {}
  }'
```

<a id="get-admin-listrelayers"></a>
#### `GET /admin/listRelayers`
Lists all whitelisted relayers.

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": [
    {
      "publicKeys": ["ed8639ee02b0e0cb8caade8ea24c71b1c60c55fa241032767e67c4da6e691f5fd08a36b005a2c1fd68c9b5a04137c406d458ba73b562aa269f52ceb6a285e41a"],
      "relayerName": "my-relayer",
      "allowedChains": ["11155111"],
      "registeredAt": "2025-12-30 01:37:29.217",
      "registeredBy": "operator",
      "isActive": true,
      "metadata": {
        "relayerAPIURL": "http://82.208.20.136:8080",
        "source": "manual-registration"
      },
      "lastSeen": "",
      "requestCount": 0
    }
  ]
}
```

**Example:**
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/admin/listRelayers"
```

<a id="get-admin-getrelayer"></a>
#### `GET /admin/getRelayer`
Gets a specific relayer by public key.

**Query Parameters:**
- `publicKey` (required): Relayer public key (128 hex characters, no `0x` prefix)

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": {
    "publicKeys": ["ed8639ee02b0e0cb8caade8ea24c71b1c60c55fa241032767e67c4da6e691f5fd08a36b005a2c1fd68c9b5a04137c406d458ba73b562aa269f52ceb6a285e41a"],
    "relayerName": "my-relayer",
    "allowedChains": ["11155111"],
    "registeredAt": "2025-12-30 01:37:29.217",
    "registeredBy": "operator",
    "isActive": true,
    "metadata": {},
    "lastSeen": "",
    "requestCount": 0
  }
}
```

**Error Responses:**
- `404 Not Found`: Relayer not found

**Example:**
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/admin/getRelayer?publicKey=ed8639ee02b0e0cb8caade8ea24c71b1c60c55fa241032767e67c4da6e691f5fd08a36b005a2c1fd68c9b5a04137c406d458ba73b562aa269f52ceb6a285e41a"
```

**Note:** The `publicKey` parameter is case-sensitive and must match exactly what's stored in the database (MongoDB field is `publicKeys` with camelCase).

<a id="post-updaterelayer"></a>
#### `POST /updateRelayer`
Updates relayer public keys. **Self-managed by relayers** - requires signature from an existing public key.

**Request Body:**
```json
{
  "relayerPublicKey": "<existing public key>",
  "newPublicKeys": ["<new_key1>", "<new_key2>"],
  "signature": "<signature from existing key>"
}
```

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": "Relayer public keys updated successfully"
}
```

**Example:**
```bash
curl -X POST $MPC_AUTH_URL:$MANAGEMENT_PORT/updateRelayer \
  -H "Content-Type: application/json" \
  -d '{
    "relayerPublicKey": "ed8639ee02b0e0cb8caade8ea24c71b1c60c55fa241032767e67c4da6e691f5fd08a36b005a2c1fd68c9b5a04137c406d458ba73b562aa269f52ceb6a285e41a",
    "newPublicKeys": ["new_key1", "new_key2"],
    "signature": "0x..."
  }'
```

## Authentication

### Management Key Authentication

Endpoints marked with "**Requires management key authentication**" require:
1. A valid `NodeMgtKey` signature
2. A valid nonce (obtained via `/getNodeMgtKeyNonce`)
3. The signature must be over the request body (excluding the `sig` field)

**Note:** Can be disabled for testing via `IgnoreMgtKeySigCheck: true` in config (NOT recommended for production).

### Relayer Authentication

Signing requests require:
1. `relayerPublicKey` and `relayerSignature` in the request
2. Relayer must be registered and active
3. Signature verification over the request data
4. Chain access control (if `chainID` is provided)

### Client Signature Authentication

For MPC operations (keygen, signing), client signatures are verified using the client key saved during key generation.

## Error Handling

### HTTP Status Codes
- `200 OK`: Successful request
- `400 Bad Request`: Invalid parameters
- `401 Unauthorized`: Authentication failed
- `403 Forbidden`: Access denied (e.g., inactive relayer)
- `404 Not Found`: Resource not found
- `500 Internal Server Error`: Server error

### Error Response Format
```json
{
  "code": 1,
  "error": "Error message describing what went wrong",
  "data": null
}
```

## Logging Implementation

### Log File Structure
- **Format:** JSON (logrus JSONFormatter)
- **Location:** Configurable via `LogPath` in `configs.yaml` (default: `logs/MPCAuth.log`)
- **Rotation:** Managed by lumberjack
  - Max size: 10 MB per file
  - Max backups: 100 files
  - Max age: 90 days
  - Compression: Disabled by default

### Log Entry Structure
Each log entry is a JSON object with fields such as:
- `time`: RFC3339 timestamp
- `level`: Log level (panic, fatal, error, warn, info, debug, trace)
- `msg`: Log message
- Additional context fields as needed

### Log Retrieval Implementation

The `/getLogs` endpoint implementation:

1. **File Reading:**
   - Reads current log file: `logs/MPCAuth.log`
   - Reads rotated files: `logs/MPCAuth.log.1`, `logs/MPCAuth.log.2`, etc.
   - Stops when a rotated file doesn't exist (up to 100 backups)

2. **Parsing:**
   - Each line is parsed as a JSON object
   - Invalid JSON lines are skipped
   - Timestamp is extracted and parsed (supports RFC3339 and RFC3339Nano)

3. **Filtering:**
   - Only entries with timestamp >= (current time - hours) are included
   - Entries are sorted by time (newest first)

4. **Performance Considerations:**
   - Reads entire log files (no early termination for efficiency)
   - Processes all files sequentially
   - Suitable for reasonable log file sizes (10MB per file)

## Configuration

API behavior is controlled via `configs.yaml`:

```yaml
# Management API port
ManagementAPIsPort: 8080

# Logging
LogLevel: 6  # 0: Panic, 1: Fatal, 2: Error, 3: Warn, 4: Info, 5: Debug, 6: Trace, 7: All
LogPath: "logs/MPCAuth.log"

# Authentication
NodeMgtKey: "0x..."
IgnoreMgtKeySigCheck: false  # WARNING: Set to false in production

# Swagger documentation
DisableDocs: false
```

## Swagger Documentation

Interactive API documentation is available at:
- **URL:** `$MPC_AUTH_URL:$MANAGEMENT_PORT/swagger/index.html`
- **Format:** OpenAPI 3.0 (Swagger)
- **Files:**
  - `docs/swagger.yaml` - YAML format
  - `docs/swagger.json` - JSON format

The Swagger documentation is automatically generated from code annotations and includes:
- All endpoint definitions
- Request/response schemas
- Parameter descriptions
- Example values

## Best Practices

1. **Error Handling:**
   - Always check the `code` field in responses
   - Handle `400` and `500` errors appropriately
   - Log errors for debugging

2. **Authentication:**
   - Never disable `IgnoreMgtKeySigCheck` in production
   - Always verify relayer signatures
   - Use proper nonce management for management key operations

3. **Log Retrieval:**
   - Use reasonable `hours` values (avoid very large values that may return too much data)
   - Consider pagination for large log sets (future enhancement)
   - Monitor log file sizes to prevent disk space issues

4. **Rate Limiting:**
   - Consider implementing rate limiting for production deployments
   - Monitor API usage patterns

## Future Enhancements

Potential improvements to the API:

1. **Log Retrieval:**
   - Add pagination support
   - Add filtering by log level
   - Add filtering by specific fields
   - Add streaming support for large log sets

2. **Performance:**
   - Implement caching for frequently accessed data
   - Add response compression
   - Optimize log file reading (reverse reading, indexing)

3. **Monitoring:**
   - ✅ Health check endpoint (`/health`) - **IMPLEMENTED**
   - ✅ Connectivity health endpoint (`/connectivityHealth`) - **IMPLEMENTED**
   - Add metrics endpoint
   - Add performance monitoring

4. **Security:**
   - Add rate limiting
   - Add request size limits
   - Add IP whitelisting options

## Common Workflows

### 1. Creating a Group and Generating a Key

```bash
# Step 1: Get node keys
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getConfiguredNodeKeys"

# Step 2: Create group
curl -X POST $MPC_AUTH_URL:$MANAGEMENT_PORT/newGroupRequest \
  -H "Content-Type: application/json" \
  -d '{
    "keyList": ["node1_key", "node2_key", "node3_key"],
    "BrokerArray": ["ssl://82.180.145.77:8883"],
    "nonce": 1,
    "sig": "0x..."
  }'

# Step 2b (optional): Initiator only — retry NEWGROUPREQUEST to one peer that missed MQTT delivery
curl -X POST $MPC_AUTH_URL:$MANAGEMENT_PORT/newGroupRequestRetry \
  -H "Content-Type: application/json" \
  -d '{
    "requestId": "NewGroup20241228123456789abc123",
    "targetNodeKey": "128_hex_pubkey_of_peer",
    "nonce": 1,
    "sig": "0x..."
  }'

# Step 3: Each node agrees
curl -X POST $MPC_AUTH_URL:$MANAGEMENT_PORT/newGroupRequestAgree \
  -H "Content-Type: application/json" \
  -d '{
    "requestId": "NewGroup20241228123456789abc123",
    "nonce": 1,
    "sig": "0x..."
  }'

# Step 4: Request key generation
# Note: clientPk should be generated by the client/dApp (not by the node)
curl -X POST $MPC_AUTH_URL:$MANAGEMENT_PORT/keyGenRequest \
  -H "Content-Type: application/json" \
  -d '{
    "nonce": 2,
    "sig": "0x...",
    "clientPk": "<client_public_key>",
    "threshold": 2,
    "groupId": "<group_id_from_step_2>",
    "msgCheck": "multi-agree",
    "keyType": "secp256k1"
  }'

# Step 4b (optional): Initiator only — retry KEYGENREQUEST to one peer that missed MQTT delivery
curl -X POST $MPC_AUTH_URL:$MANAGEMENT_PORT/keyGenRequestRetry \
  -H "Content-Type: application/json" \
  -d '{
    "requestId": "KeyGen20260111003720999cf104d0f",
    "targetNodeKey": "128_hex_pubkey_of_peer",
    "nonce": 2,
    "sig": "0x..."
  }'

# Step 5: Each node agrees to keygen
curl -X POST $MPC_AUTH_URL:$MANAGEMENT_PORT/keyGenRequestAgree \
  -H "Content-Type: application/json" \
  -d '{
    "requestId": "KeyGen20260111003720999cf104d0f",
    "nonce": 2,
    "sig": "0x..."
  }'

# Step 6: Get key generation result
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getKeyGenResultById?id=KeyGen20260111003720999cf104d0f"
```

### 2. Signing a Transaction

```bash
# Step 1: Register relayer (one-time per node)
curl -X POST $MPC_AUTH_URL:$MANAGEMENT_PORT/admin/registerRelayer \
  -H "Content-Type: application/json" \
  -d '{
    "relayerPublicKey": "ed8639ee02b0e0cb8caade8ea24c71b1c60c55fa241032767e67c4da6e691f5fd08a36b005a2c1fd68c9b5a04137c406d458ba73b562aa269f52ceb6a285e41a",
    "relayerName": "my-relayer",
    "allowedChains": ["11155111"],
    "registeredBy": "operator"
  }'

# Step 2: Create sign request (from relayer)
curl -X POST $MPC_AUTH_URL:$MANAGEMENT_PORT/signRequest \
  -H "Content-Type: application/json" \
  -d '{
    "clientSig": "0x...",
    "keyList": [],
    "presignId": "",
    "pubKey": "08caf50811eb4c2bed7b3f8dc9c292b5cf521ba3774ea49dcd949e8235a48b22e8c1f16b356710aae4095e498bfff8385eada1e53a47dbdd984d32ae4d20a5de",
    "msgHash": "751f68b43977269a16128143fa15e0e7ab3c15ba52484fe8278796561505698b",
    "relayerPublicKey": "ed8639ee02b0e0cb8caade8ea24c71b1c60c55fa241032767e67c4da6e691f5fd08a36b005a2c1fd68c9b5a04137c406d458ba73b562aa269f52ceb6a285e41a",
    "relayerSignature": "0x...",
    "chainID": "11155111"
  }'

# Step 3: Each node agrees
curl -X POST $MPC_AUTH_URL:$MANAGEMENT_PORT/signRequestAgree \
  -H "Content-Type: application/json" \
  -d '{
    "requestId": "Sign20260111003720999cf104d0f"
  }'

# Step 4: Get signature result
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getSignResultById?id=Sign20260111003720999cf104d0f"
```

### 3. Multi-Agree Signing (Ready / Trigger Flow)

For **multi-agree** keys, nodes agree via `POST /signRequestAgree`. Once **SigList** reaches the **MPC quorum** for this key (**t** parties for CGGMP24 and FROST), **only the originator** (the node whose key is the key in the Purpose map, i.e. the one that created the request via multiSignRequest) may call `POST /triggerSignRequestById` to trigger signature generation. Use `GET /getSignResultById` to poll for the signature. The originator can then call `POST /updateSignResultStatusById` to set status to `"executed"` (with transaction hash) or `"shelved"` (transaction will not be broadcast); these fields appear in `getSignResultById`. The originator can also call `POST /shelveSignRequest` to set the **sign request** status to `"shelved"` (e.g. to cancel or defer the request before triggering); this status appears in `getSignRequestById` and `listSignRequests` and is propagated to all nodes.

**Batch sign request:** To request N signatures in one go (e.g. a sequence of transactions), call `POST /multiSignRequest` with `messageHashes` (array of N hex hashes) and optionally `messageRawBatch`. One `POST /signRequestAgree` agrees to the entire batch. After trigger, `GET /getSignResultById` returns one result with `batchSignResult: true`, `batchSize: N`, and `batchSignatures` (array of N entries: `messagehash`, `sigr`, `sigs`, `sigrecover`, `signaturehex`, `ethereumsignature`). Use `data.batchSignatures[i]` for the i-th signature and execute transactions in order (e.g. consecutive nonces on EVM). Batch signing does **not** use presign; each message runs a full interactive sign worker in parallel.

```bash
# Step 1: Create multi-agree sign request (e.g. from dApp)
curl -X POST $MPC_AUTH_URL:$MANAGEMENT_PORT/multiSignRequest \
  -H "Content-Type: application/json" \
  -d '{
    "pubKey": "<mpc_public_key>",
    "msgHash": "<message_hash_hex>",
    "clientSig": "0x...",
    "keyList": ["node1_key", "node2_key", "node3_key"],
    ...
  }'
# Returns requestId, e.g. "Sign20260111003720999cf104d0f"

# Step 2: Each node agrees (or rejects) via signRequestAgree
curl -X POST $MPC_AUTH_URL:$MANAGEMENT_PORT/signRequestAgree \
  -H "Content-Type: application/json" \
  -d '{"requestId": "Sign20260111003720999cf104d0f", "nonce": 1, "nodeKey": "<128-hex from GET /getNodeKey>", "clientSig": "0x...", "accept": true}'

# Step 3: Check if ready, then trigger (any node)
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/isSignRequestReadyById?id=Sign20260111003720999cf104d0f"
# When data.ready is true:
curl -X POST $MPC_AUTH_URL:$MANAGEMENT_PORT/triggerSignRequestById \
  -H "Content-Type: application/json" \
  -d '{"requestId": "Sign20260111003720999cf104d0f", "nonce": 1, "sig": "0x..."}'

# Step 4: Get signature result (poll until available)
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getSignResultById?id=Sign20260111003720999cf104d0f"

# Optional: list all sign requests ready to trigger (for this node)
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/listSignRequestsReady?pagenum=0&pagesize=10"
```

### 4. Checking System Health

```bash
# Check overall health
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/health"

# Check connectivity
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/connectivityHealth"

# Check specific group connectivity
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/connectivityHealth?groupId=566633a647306335d3ad6ab49829dcfad9abe1f4d1275e4ea3c3f8c292e20ee9"

# Get logs
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getLogs?hours=24"
```

### 5. Querying Key Generation Information

```bash
# Get keyGen result (response includes status from the keygen request: pending, agree, or failed)
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getKeyGenResultById?id=KeyGen20260111003720999cf104d0f"

# Get keyGen request by id (includes status)
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getKeyGenRequestById?id=KeyGen20260111003720999cf104d0f"

# List keyGen requests (each item includes status)
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/listKeyGenRequests?filter=all&pagenum=0&pagesize=10"

# Get GroupId for a keyGen
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getKeyGenGroupId?id=KeyGen20260111003720999cf104d0f"

# Get all groups and their keyGens
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getAllGroupIds"
```

## See Also

- `API_docs.md` - Usage examples and workflows
- `README.md` - General project documentation
- `docs/swagger.yaml` - Complete API specification
- `node/managementapi.go` - API implementation source code

