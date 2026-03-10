# API Implementation Documentation

## Overview

The Distributed Auth Management API provides a RESTful interface for managing MPC (Multi-Party Computation) nodes, key generation, signing operations, and system monitoring. The API is implemented using the Gin web framework and follows a consistent response format.

## Architecture

### Base URL
- Default port: `8080` (configurable via `ManagementAPIsPort` in `configs.yaml`)
- Base path: `/`
- Swagger UI: `/swagger/index.html` (if docs are enabled)

### Response Format

All endpoints return a standardized `APIResponse` structure:

```json
{
  "code": 0,        // 0 = success, 1 = error
  "error": "",      // Error message (empty if success)
  "data": {}        // Response data (varies by endpoint)
}
```

### Logging

All API requests are logged using the node's logger with the format:
```
Client: <IP> Called API: <package>.<function>
```

## Quick Reference: All Endpoints

Jump to detailed descriptions in [Endpoint Categories](#endpoint-categories) below. Use the links to go to a specific endpoint.

### Node Information
- [`GET /version`](#get-version) - Get node version
- [`GET /getMachineInfo`](#get-getmachineinfo) - Get machine information (CPU, memory, disk)
- [`GET /getNodeKey`](#get-getnodekey) - Get node public key (node ID)
- [`GET /getNodeMgtKey`](#get-getnodemgtkey) - Get node management key
- [`GET /getNodeMgtKeyNonce`](#get-getnodemgtkeynonce) - Get current management key nonce
- [`GET /hasPublicMgtKey`](#get-haspublicmgtkey) - Returns true if any Ed25519 management key is allowed (config or added via addManagementKey)
- [`GET /getAllowedEd25519MgtKeys`](#get-getalloweded25519mgtkeys) - List allowed Ed25519 management keys with labels (bootstrap + added) so the app can show "Which key?"
- [`GET /getPublicMgtKeyNonce`](#get-getpublicmgtkeynonce) - Get current nonce for an Ed25519 key (optional `?publicKey=` for added keys)
- [`POST /verifyMgtKey`](#post-verifymgtkey) - Verify Ed25519 management key (attach-time proof; no other side effects)
- [`POST /addManagementKey`](#post-addmanagementkey) - Add another Ed25519 public key (request must be signed by an existing Ed25519 management key)
- [`GET /getAllowedKeyTypes`](#get-getallowedkeytypes) - Get allowed key types
- [`GET /getAllowedMsgCheckTypes`](#get-getallowedmsgchecktypes) - Get allowed message check types
- [`GET /getSuccessRate`](#get-getsuccessrate) - Get success rate statistics
- [`GET /getPreSigningVerificationStatus`](#get-getpresigningverificationstatus) - Get presigning verification status
- [`GET /getClientSigStatus`](#get-getclientsigstatus) - Get client signature check status (IgnoreClientSigCheck)
- [`GET /getSubscriptions`](#get-getsubscriptions) - Get MQTT subscriptions
- [`GET /health`](#get-health) - Get comprehensive health status
- [`GET /connectivityHealth`](#get-connectivityhealth) - Get connectivity health for nodes
- [`GET /getLogs`](#get-getlogs) - Get log entries
- [`GET /getConfiguredNodeKeys`](#get-getconfigurednodekeys) - Get node keys for configured addresses

### Node Registration
- [`POST /nodeRegister`](#post-noderegister) - Register node (one-time)
- [`GET /fetchNodeData`](#get-fetchnodedata) - Fetch node data by node ID
- `GET /fetchNodeDataByPublicKey` - Fetch node data by public key

### Local Chain Config
- [`POST /postChainDetails`](#post-postchaindetails) - Store chain config on this node only (requires mgt key)
- [`GET /getChainDetails`](#get-getchaindetails) - Get chain config(s); optional `chain_id` query for single chain
- [`POST /removeChainDetails`](#post-removechaindetails) - Remove chain config for one chain (requires mgt key)

### Local Token Config
- [`POST /addToken`](#post-addtoken) - Add a token contract for a chain (this node only; requires mgt key)
- [`POST /removeToken`](#post-removetoken) - Remove a token contract (requires mgt key)
- [`GET /getTokens`](#get-gettokens) - Get all token configs grouped by chain type; optional `chainType`, `chain_id` filter

### Known Addresses (local node only)
- [`POST /addKnownAddress`](#post-addknownaddress) - Add or update a known address for a chain type (requires mgt key)
- [`POST /removeKnownAddress`](#post-removeknownaddress) - Remove a known address (requires mgt key)
- [`GET /getKnownAddresses`](#get-getknownaddresses) - Get all known addresses grouped by chain type; optional `chain_type`, `chain_id`, `is_contract` (0 or 1) filters

### Node Ping & Connectivity
- [`GET /pingNodesRequest`](#get-pingnodesrequest) - Ping nodes to test connectivity
- [`GET /getPingNodesResultById`](#get-getpingnodesresultbyid) - Get ping results by ID
- [`GET /listPingResults`](#get-listpingresults) - List all ping results
- [`GET /getInactiveNodes`](#get-getinactivenodes) - Get inactive nodes

### Group Management
- [`POST /newGroupRequest`](#post-newgrouprequest) - Create new group request (requires mgt key)
- [`GET /listNewGroupRequests`](#get-listnewgrouprequests) - List new group requests
- [`GET /getNewGroupRequestById`](#get-getnewgrouprequestbyid) - Get new group request by ID
- [`POST /newGroupRequestAgree`](#post-newgrouprequestagree) - Agree to new group request (requires mgt key)
- [`GET /getNewGroupResultById`](#get-getnewgroupresultbyid) - Get new group result by ID

### Key Generation
- [`POST /keyGenRequest`](#post-keygenrequest) - Create key generation request (requires mgt key)
- [`GET /listKeyGenRequests`](#get-listkeygenrequests) - List key generation requests
- [`GET /getKeyGenRequestById`](#get-getkeygenrequestbyid) - Get key generation request by ID
- [`POST /keyGenRequestAgree`](#post-keygenrequestagree) - Agree to key generation request (requires mgt key)
- [`GET /getKeyGenResultById`](#get-getkeygenresultbyid) - Get key generation result by ID
- [`GET /getKeyGenGroupId`](#get-getkeygengrouesultbyid) - Get key generation result by ID
- [`GET /getKeyGenGroupId`](#get-getkeygengroupid) - Get GroupId for a keyGen request
- [`GET /getAllGroupIds`](#get-getallgroupids) - Get all GroupIds with their keyGens

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
- [`POST /signRequestAgree`](#post-signrequestagree) - Agree to sign request
- [`GET /isSignRequestReadyById`](#get-issignrequestreadybyid) - Check if multi-agree sign request is ready to trigger
- [`GET /listSignRequestsReady`](#get-listsignrequestsready) - List multi-agree sign requests ready to trigger (with pagenum/pagesize)
- [`POST /triggerSignRequestById`](#post-triggersignrequestbyid) - Trigger signature generation for multi-agree (requires mgt key)
- [`POST /updateSignResultStatusById`](#post-updatesignresultstatusbyid) - Update sign result status: executed (with tx hash) or shelved (originator only, requires mgt key)
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

<a id="endpoint-categories"></a>
## Endpoint Categories

### 1. Node Information Endpoints

<a id="get-version"></a>
#### `GET /version`
Returns the current node version and the date it was changed.

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": {
    "version": "v1.12",
    "versionDate": "2024-01-15"
  }
}
```

**Field Descriptions:**
- `version`: The current node version string (e.g., "v1.12")
- `versionDate`: The date when this version was set/changed (ISO 8601 date format, e.g., "2024-01-15")
```

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
curl "http://localhost:8080/getMachineInfo"

# Refresh and fetch fresh machine info
curl "http://localhost:8080/getMachineInfo?refresh=true"
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
curl "http://localhost:8080/getNodeKey"
```

<a id="get-getnodemgtkey"></a>
#### `GET /getNodeMgtKey`
Returns the node management key (Ethereum address format). This key is used for authenticating management operations.

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
curl "http://localhost:8080/getNodeUptime"
```

**Notes:**
- Uptime tracking is automatically initialized when the node starts (in `StartManagementAPIs`).
- If the node has never been started before, `firstStartDate` and `lastRestartDate` will be set to the current date/time.
- `totalUptimeHours` represents the total time elapsed since first start, not actual running time (it doesn't subtract downtime periods).
- `currentSessionUptimeHours` is calculated in real-time on each API call.

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
curl "http://localhost:8080/getNodeMgtKey"
```

<a id="get-getnodemgtkeynonce"></a>
#### `GET /getNodeMgtKeyNonce`
Returns the current nonce for the node management key. This nonce must be used (and incremented) for each management key signature.

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": 1
}
```

**Example:**
```bash
curl "http://localhost:8080/getNodeMgtKeyNonce"
```

**Note:** After using a nonce, it will be incremented. Always fetch the current nonce before creating a signature.

<a id="get-haspublicmgtkey"></a>
#### `GET /hasPublicMgtKey`
Returns whether at least one Ed25519 management key is allowed. This is true if `PublicMgtKey` is set in config with valid structure, or any keys have been added via `POST /addManagementKey`. When true, node runners can use an Ed25519 key pair for direct API management without a frontend (in addition to MetaMask/NodeMgtKey).

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
curl "http://localhost:8080/hasPublicMgtKey"
```

<a id="get-getalloweded25519mgtkeys"></a>
#### `GET /getAllowedEd25519MgtKeys`
Returns the list of Ed25519 public keys allowed for management API auth (config `PublicMgtKey` plus keys added via `POST /addManagementKey`), each with a short label so the app can show "Which key are you using?" without the user needing to know the hex. Used by continuumdao-node-app when the user clicks "Attach with Ed25519".

**Response (success):**
```json
{
  "code": 0,
  "error": "",
  "data": [
    { "publicKey": "64hex...", "label": "Bootstrap (config)" },
    { "publicKey": "64hex...", "label": "Added key 1" }
  ]
}
```

**Example:**
```bash
curl "http://localhost:8080/getAllowedEd25519MgtKeys"
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
curl "http://localhost:8080/getPublicMgtKeyNonce"
curl "http://localhost:8080/getPublicMgtKeyNonce?publicKey=YOUR_64_HEX_KEY"
```

<a id="post-verifymgtkey"></a>
#### `POST /verifyMgtKey`
Verify-only endpoint for Ed25519 management key ownership. Accepts `Nonce` and `Sig` (128-hex Ed25519 signature over the exact JSON `{"Nonce":<nonce>,"Sig":""}`). The node verifies the signature with one of the allowed Ed25519 keys (config `PublicMgtKey` or keys added via `addManagementKey`), consumes the nonce (same semantics as other management endpoints), and returns `code: 0` on success. No other state is changed. Used by the continuumdao-node-app when the user clicks "Attach with Ed25519" to prove key ownership at attach time without performing any other action.

**Request body:**
- `Nonce` (required): Current nonce from `GET /getPublicMgtKeyNonce` (or `?publicKey=<your_key>`).
- `Sig` (required): Ed25519 signature, 128 hex characters, over the exact message `{"Nonce":<that_nonce>,"Sig":""}` (same nonce as in the body). Sign with the private key that matches an allowed Ed25519 management key.

**Response (success):** `{ "code": 0, "error": "", "data": null }`

**Response (failure):** `code` non-zero, `error` describes the reason (e.g. invalid signature, nonce mismatch, nonce already used, or no Ed25519 key configured).

**Example flow:** 1) `GET /getPublicMgtKeyNonce` → get nonce. 2) Build message `{"Nonce":<nonce>,"Sig":""}` and sign with your Ed25519 private key. 3) `POST /verifyMgtKey` with body `{"Nonce":<nonce>,"Sig":"<128_hex_signature>"}`.

<a id="post-addmanagementkey"></a>
#### `POST /addManagementKey`
Adds a new Ed25519 public key to the allowed set for management API auth. The request **must be signed with an existing Ed25519 management key** (config `PublicMgtKey` or a key previously added). Only a permitted machine can add another key. Use the first `PublicMgtKey` from config to add the next key.

**Request body:** `newPublicKey` (64 hex), `nonce` (current nonce for the signer key from `GET /getPublicMgtKeyNonce` or `GET /getPublicMgtKeyNonce?publicKey=<signer_key>`), `sig` (Ed25519 signature, 128 hex, over the canonical JSON of the request body with `sig` set to empty string).

**Example flow:** 1) Set `PublicMgtKey` in config (bootstrap key). 2) Get nonce: `GET /getPublicMgtKeyNonce`. 3) Build body `{"newPublicKey":"<64 hex>","nonce":<n>,"sig":""}`, sign the JSON string with your Ed25519 private key, set `sig` to the signature. 4) `POST /addManagementKey` with that body. The new key can then sign management requests and add further keys.

#### `POST /getMessageToSign` ⭐ **NEW**
Returns the exact message format that needs to be signed with MetaMask (or any Ethereum wallet) for management API requests. The signature must be from the NodeMgtKey address.

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
    "signingInstructions": "Sign this message using MetaMask's personal_sign method. The signature must be from the NodeMgtKey address. Use eth_signTypedData or personal_sign in your wallet.",
    "example": {
      "javascript": "const message = '...'; const signature = await ethereum.request({ method: 'personal_sign', params: [message, account] });",
      "web3js": "const signature = await web3.eth.personal.sign(message, account);"
    }
  }
}
```

**Example:**
```bash
curl -X POST http://localhost:8080/getMessageToSign \
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

### Using MetaMask or Ed25519 for Management API Authentication

Management API endpoints (like `/keyGenRequest`, `/newGroupRequest`, `/presignRequest`, etc.) require authentication. The node accepts **either** of the following:

- **NodeMgtKey (MetaMask)**: Ethereum address in config; sign with MetaMask/personal_sign (EIP-191).
- **PublicMgtKey (Ed25519)**: Optional Ed25519 public key in config (bootstrap key); additional keys can be added via `POST /addManagementKey` (signed by an existing Ed25519 key). Sign the raw request body with your Ed25519 private key. Use for direct API access without a frontend.

You only need one. If both are configured, either signature type is accepted.

---

#### Using MetaMask (NodeMgtKey)

**How it works:**
1. The request body (excluding the `sig` field) is JSON-marshaled to create a message string
2. This message is signed using Ethereum's personal_sign format (EIP-191): `"\x19Ethereum Signed Message:\n<length><message>"`
3. The signature is verified by recovering the address from the signature and comparing it to `NodeMgtKey`
4. The signature must be from the same address as `NodeMgtKey`

**Steps to sign with MetaMask:**

1. **Get the NodeMgtKey and current nonce:**
   ```bash
   curl http://localhost:8080/getNodeMgtKey
   curl http://localhost:8080/getNodeMgtKeyNonce
   ```

2. **Get the message to sign** (optional, but helpful):
   ```bash
   curl -X POST http://localhost:8080/getMessageToSign \
     -H "Content-Type: application/json" \
     -d '{...your request body without "sig"...}'
   ```

3. **Sign the message with MetaMask:**
   ```javascript
   // In your dApp/frontend
   const message = '{"nonce":1,"clientPk":"...","threshold":2,...}';
   const account = '0x1234567890ABCDEF1234567890ABCDEF12345678'; // Must match NodeMgtKey
   
   // Using MetaMask
   const signature = await ethereum.request({
     method: 'personal_sign',
     params: [message, account]
   });
   
   // Or using web3.js
   const signature = await web3.eth.personal.sign(message, account);
   ```

4. **Include the signature in your API request:**
   ```bash
   curl -X POST http://localhost:8080/keyGenRequest \
     -H "Content-Type: application/json" \
     -d '{
       "nonce": 1,
       "sig": "0x...",  # The signature from MetaMask
       "clientPk": "...",
       ...
     }'
   ```

**Important Notes:**
- The signature must be from the **same address** as `NodeMgtKey` (configured in `configs.yaml`)
- The message to sign is the **JSON string** of the request body (without the `sig` field)
- The signature format is Ethereum's `personal_sign` (EIP-191), which MetaMask uses by default
- Each request requires a unique nonce (obtained from `/getNodeMgtKeyNonce`)
- The nonce increments automatically after each successful request

---

#### Using Ed25519 (PublicMgtKey)

When the node has `PublicMgtKey` configured (check with `GET /hasPublicMgtKey`), you can authenticate management API requests with an Ed25519 key pair instead of MetaMask. This allows scripts and backends to manage the node without a browser.

**How it works:**
1. The request body (excluding the `sig` field) is JSON-marshaled to produce the **exact message string** to sign. **Do not** add the EIP-191 prefix; sign the raw JSON string.
2. Sign that string with your Ed25519 private key. Signature must be 64 bytes (128 hex characters).
3. Put the signature in the `sig` field (hex string, optional `0x` prefix). The node detects Ed25519 by signature length (128 hex chars) and verifies with one of the allowed Ed25519 keys (config `PublicMgtKey` or keys added via `addManagementKey`).
4. Use the nonce from `GET /getPublicMgtKeyNonce` or `GET /getPublicMgtKeyNonce?publicKey=<your_key>` (each key has its own nonce sequence).

**Steps:**

1. **Check that the node accepts Ed25519 and get nonce:**
   ```bash
   curl http://localhost:8080/hasPublicMgtKey    # must be true
   curl http://localhost:8080/getPublicMgtKeyNonce
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
   curl -X POST http://localhost:8080/keyGenRequest \
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
  "data": ["secp256k1", "ed25519"]
}
```

**Example:**
```bash
curl "http://localhost:8080/getAllowedKeyTypes"
```

**Key Types:**
- `secp256k1`: Used for EVM chains (Ethereum, BSC, Polygon, etc.)
- `ed25519`: Used for Solana, Stellar, NEAR, TON

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
curl "http://localhost:8080/getAllowedMsgCheckTypes"
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
curl "http://localhost:8080/getSuccessRate"
```

**Notes:**
- Statistics are aggregated across all groups this node participates in
- Success is determined by the presence of a result with valid data (savedata for keygen, sigdata/sigr/sigs for signing)
- Failed operations are calculated as: `total - success`
- If no requests exist, success rate will be 0.0

**Example:**
```bash
curl "http://localhost:8080/getSuccessRate"
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
curl "http://localhost:8080/getPreSigningVerificationStatus"
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
curl "http://localhost:8080/getClientSigStatus"
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

<a id="get-health"></a>
#### `GET /health` ⭐ **NEW**
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

**HTTP Status Codes:**
- `200 OK`: Node is healthy
- `503 Service Unavailable`: Node is unhealthy (one or more checks failed)

**Example Usage:**
```bash
# Check node health
curl http://localhost:8080/health

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
#### `GET /connectivityHealth` ⭐ **NEW**
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
curl http://localhost:8080/connectivityHealth

# Check specific group
curl "http://localhost:8080/connectivityHealth?groupId=566633a647306335d3ad6ab49829dcfad9abe1f4d1275e4ea3c3f8c292e20ee9"

# Check with custom timeout (10 seconds)
curl "http://localhost:8080/connectivityHealth?timeout=10"

# Check specific group with custom timeout
curl "http://localhost:8080/connectivityHealth?groupId=566633a647306335d3ad6ab49829dcfad9abe1f4d1275e4ea3c3f8c292e20ee9&timeout=10"
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
#### `GET /getLogs` ⭐ **NEW**
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
Stores or updates chain config for one chain on this node. Requires management key signature over the message. Both **MetaMask (Ethereum)** and **Ed25519** management keys are supported.

**Request Body (PostChainDetailsPost):**
```json
{
  "nonce": 1,
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
  "gasPrice": 25,
  "signedMessage": "{\"nonce\":1,\"chainName\":\"Ethereum Mainnet\",\"chainId\":\"1\",\"rpcGateway\":\"https://eth.llamarpc.com\",\"legacy\":false,\"testnet\":false,\"gasName\":\"ETH\"}",
  "clientSig": "0x..."
}
```

**Field Descriptions:**
- `nonce` (required): Current nonce from `/getNodeMgtKeyNonce` (or `/getPublicMgtKeyNonce` for Ed25519).
- `chainName` (required): Human-readable chain name.
- `chainId` (required): Chain ID (number or string in JSON; stored as string).
- `rpcGateway` (required): RPC URL (e.g. HTTPS).
- `explorer` (optional): Blockchain explorer URL (e.g. https://etherscan.io). Must be a valid http or https URL if provided.
- `legacy` (optional): If true, legacy gas model (gas multiplier, optional gasPrice); if false, EIP-1559 (baseFee/priorityFee).
- `testnet` (optional): If true, chain is a testnet; if false, mainnet. Defaults to false when omitted.
- `gasName` (optional): Native gas token symbol (e.g. "ETH", "BNB").
- `gasLimit` (optional): Default gas limit.
- `baseFee` (optional): Default base fee (EIP-1559).
- `priorityFee` (optional): Default priority fee (EIP-1559).
- `gasMultiplier` (optional): Gas multiplier for legacy chains.
- `gasPrice` (optional): Gas price in gwei for legacy chains.
- `signedMessage` (required): The exact string that was signed (e.g. JSON of nonce, chainName, chainId, rpcGateway, explorer, legacy, testnet, gasName, and optional gas fields).
- `clientSig` (required): Signature from management key. **MetaMask:** sign `signedMessage` with `personal_sign` (NodeMgtKey address), send 0x-prefixed signature. **Ed25519:** sign the same `signedMessage` with an allowed Ed25519 key (config PublicMgtKey or added via addManagementKey), send 128-hex signature.

**Response:**
```json
{ "code": 0, "error": "", "data": "Chain config stored" }
```

**Error Responses:**
- `400 Bad Request`: Missing required fields (chainName, rpcGateway, chainId).
- `401 Unauthorized`: Invalid or missing management key signature / nonce.
- `500 Internal Server Error`: Database error.

**Example (MetaMask flow):**
```bash
# 1. Get nonce
curl -s "http://localhost:8080/getNodeMgtKeyNonce" | jq .data

# 2. Build message (same as signedMessage), sign with MetaMask personal_sign, then:
curl -X POST http://localhost:8080/postChainDetails \
  -H "Content-Type: application/json" \
  -d '{
    "nonce": 1,
    "chainName": "Ethereum Mainnet",
    "chainId": "1",
    "rpcGateway": "https://eth.llamarpc.com",
    "legacy": false,
    "testnet": false,
    "gasName": "ETH",
    "signedMessage": "{\"nonce\":1,\"chainName\":\"Ethereum Mainnet\",\"chainId\":\"1\",\"rpcGateway\":\"https://eth.llamarpc.com\",\"legacy\":false,\"testnet\":false,\"gasName\":\"ETH\"}",
    "clientSig": "0x..."
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
- `baseFee` (number, optional): Default base fee in gwei (EIP-1559).
- `priorityFee` (number, optional): Default priority fee in gwei (EIP-1559).
- `gasMultiplier` (number, optional): Gas multiplier for legacy chains (%).
- `gasPrice` (number, optional): Gas price in gwei for legacy chains.
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
    "gasMultiplier": 0,
    "gasPrice": 0,
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
      "gasMultiplier": 0,
      "gasPrice": 0,
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
curl "http://localhost:8080/getChainDetails"

# Get config for a specific chain
curl "http://localhost:8080/getChainDetails?chain_id=1"
```

<a id="post-removechaindetails"></a>
#### `POST /removeChainDetails`
Removes the stored chain config for one chain on this node. Requires management key signature over the message. Same signature types as `POST /postChainDetails` (MetaMask `personal_sign` or Ed25519).

**Request Body (RemoveChainDetailsPost):**
```json
{
  "nonce": 2,
  "chainId": "1",
  "signedMessage": "{\"nonce\":2,\"chainId\":\"1\",\"action\":\"removeChainDetails\"}",
  "clientSig": "0x..."
}
```

**Field Descriptions:**
- `nonce` (required): Current nonce from `/getNodeMgtKeyNonce` (or `/getPublicMgtKeyNonce` for Ed25519).
- `chainId` (required): Chain ID to remove (number or string in JSON).
- `signedMessage` (required): The exact string that was signed (e.g. JSON with nonce, chainId, and optionally action `"removeChainDetails"`).
- `clientSig` (required): Signature from management key (same as postChainDetails).

**Response:**
```json
{ "code": 0, "error": "", "data": "Chain config removed" }
```

**Error Responses:**
- `400 Bad Request`: Missing required fields (e.g. chainId).
- `401 Unauthorized`: Invalid or missing management key signature / nonce.
- `404 Not Found`: No chain config exists for the given chainId.
- `500 Internal Server Error`: Database error.

**Example:**
```bash
# 1. Get nonce
curl -s "http://localhost:8080/getNodeMgtKeyNonce" | jq .data

# 2. Build message, sign with MetaMask personal_sign (or Ed25519), then:
curl -X POST http://localhost:8080/removeChainDetails \
  -H "Content-Type: application/json" \
  -d '{
    "nonce": 2,
    "chainId": "1",
    "signedMessage": "{\"nonce\":2,\"chainId\":\"1\",\"action\":\"removeChainDetails\"}",
    "clientSig": "0x..."
  }'
```

### Local Token Config

Token contracts are stored on the local node only (not propagated). Used so the frontend wallet can display and interact with tokens per chain. Supports multiple `chainType` values (e.g. `ethereum`, `solana`, `NEAR`, `stellar`, `TON`) and per-chain `chainId` (integer for Ethereum, string for others; stored as string). Token types for Ethereum include `ERC20`, `ERC721`, `CTMERC20`, `CTMRWA1`; new chain and token types can be added later.

<a id="post-addtoken"></a>
#### `POST /addToken`
Adds a token contract for the given `chainType`, `chainId` and `tokenType`. Requires management key signature (MetaMask or Ed25519, same as postChainDetails).

**Request Body (AddTokenPost):**
```json
{
  "nonce": 1,
  "chainType": "ethereum",
  "chainId": 1234,
  "tokenType": "ERC20",
  "contract": {
    "contractAddress": "0x1234567890123456789012345678901234567890",
    "name": "My Token",
    "symbol": "MTK",
    "symbolURL": "https://example.com/icon.png"
  },
  "signedMessage": "{\"nonce\":1,\"chainType\":\"ethereum\",\"chainId\":\"1234\",\"tokenType\":\"ERC20\",\"action\":\"addToken\"}",
  "clientSig": "0x..."
}
```

**Field Descriptions:**
- `nonce` (required): From `/getNodeMgtKeyNonce` or `/getPublicMgtKeyNonce`.
- `chainType` (required): e.g. `ethereum`, `solana`, `NEAR`, `stellar`, `TON` (stored lowercase for lookup).
- `chainId` (required): Number (Ethereum) or string; normalized to string when stored.
- `tokenType` (required): e.g. `ERC20`, `ERC721`, `CTMERC20`, `CTMRWA1`.
- `contract` (required): Object with at least `contractAddress`. Other fields by token type:
  - **ERC20 / CTMERC20**: `name`, `symbol`, `symbolURL` (optional, can be empty string). Optional `decimals` (number, e.g. 18) for display/formatting; stored and returned by `GET /getTokens`.
  - **ERC721**: `name`, `symbol`, `tokenURI`, and `tokenId` (required; identifies the specific NFT). If the same (contractAddress, tokenId) already exists for that chain/token type, that entry is updated; otherwise a new contract entry is appended.
  - **CTMRWA1**: same as ERC20/ERC721 plus any RWA-specific fields (transfer sigs are set by server).
- `transferSig`, `transferNames` (optional): Used when creating a new token-type entry; omitted for known types (server uses defaults).
- `signedMessage` (required): Exact string signed by management key.
- `clientSig` (required): MetaMask (0x-prefixed) or Ed25519 (128 hex) signature.

**Response:** `{ "code": 0, "error": "", "data": "Token added" }`

**Errors:** `400` missing/invalid fields; `401` invalid signature; `500` database error.

<a id="post-removetoken"></a>
#### `POST /removeToken`
Removes the token contract with the given `contractAddress` for `chainType`, `chainId` and `tokenType`. For **ERC721**, `tokenId` is required so that only the specific (contractAddress, tokenId) entry is removed. Requires management key signature.

**Request Body (RemoveTokenPost):**
- `nonce`, `chainType`, `chainId`, `tokenType`, `contractAddress`, `signedMessage`, `clientSig` (all required).
- **`tokenId`** (required for ERC721): The token ID of the NFT to remove. Omit or leave empty for ERC20 and other token types.

Example (ERC20):
```json
{
  "nonce": 2,
  "chainType": "ethereum",
  "chainId": "1234",
  "tokenType": "ERC20",
  "contractAddress": "0x1234567890123456789012345678901234567890",
  "signedMessage": "{\"nonce\":2,\"chainType\":\"ethereum\",\"chainId\":\"1234\",\"tokenType\":\"ERC20\",\"contractAddress\":\"0x1234...\",\"action\":\"removeToken\"}",
  "clientSig": "0x..."
}
```

Example (ERC721; `tokenId` must appear in both the body and the signed message):
```json
{
  "nonce": 2,
  "chainType": "ethereum",
  "chainId": "1234",
  "tokenType": "ERC721",
  "contractAddress": "0x221EC90B3B083A8501A37bdeb7035CeaedF3C31f",
  "tokenId": "18",
  "signedMessage": "{\"nonce\":2,\"chainType\":\"ethereum\",\"chainId\":\"1234\",\"tokenType\":\"ERC721\",\"contractAddress\":\"0x221EC90B3B083A8501A37bdeb7035CeaedF3C31f\",\"tokenId\":\"18\",\"action\":\"removeToken\"}",
  "clientSig": "0x..."
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

See [Token storage schema](docs/TOKEN_STORAGE_SCHEMA.md) for the full JSON structure and CTMRWA1 transfer signatures.

### Known Addresses (local node only)

Known addresses are stored on the local node only (not propagated). Each entry is scoped by chain type (e.g. `ethereum`, `solana`) and includes an address, optional `name`, optional `chainIds` (empty = valid on all chains of that type), and `isContract` (false = EOA). See [Known Addresses schema](docs/KNOWN_ADDRESSES_SCHEMA.md).

<a id="post-addknownaddress"></a>
#### `POST /addKnownAddress`
Adds or updates a known address for the given `chainType`. Requires management key signature (MetaMask or Ed25519, same as postChainDetails).

**Request Body (AddKnownAddressPost):**
```json
{
  "nonce": 1,
  "chainType": "ethereum",
  "address": "0x1234567890123456789012345678901234567890",
  "name": "My Wallet",
  "chainIds": ["1", "137"],
  "isContract": false,
  "signedMessage": "{\"nonce\":1,\"chainType\":\"ethereum\",\"address\":\"0x1234...\",\"action\":\"addKnownAddress\"}",
  "clientSig": "0x..."
}
```

**Field Descriptions:**
- `nonce` (required): From `/getNodeMgtKeyNonce` or `/getPublicMgtKeyNonce`.
- `chainType` (required): e.g. `ethereum`, `solana` (stored lowercase).
- `address` (required): The address; normalized server-side (e.g. lowercase for 0x-prefixed).
- `name` (optional): Display name for the address.
- `chainIds` (optional): Array of chain IDs this address is valid on. **Omit or empty = no restrictions** (valid on all chains of that type).
- `isContract` (optional, default false): `true` = contract address, `false` = EOA.
- `signedMessage` (required): Exact string signed by management key.
- `clientSig` (required): MetaMask (0x-prefixed) or Ed25519 (128 hex) signature.

**Response:** `{ "code": 0, "error": "", "data": "Known address added" }`

**Errors:** `400` missing/invalid fields; `401` invalid signature; `500` database error.

<a id="post-removeknownaddress"></a>
#### `POST /removeKnownAddress`
Removes the known address for the given `chainType` and `address`. Requires management key signature.

**Request Body (RemoveKnownAddressPost):**
- `nonce`, `chainType`, `address`, `signedMessage`, `clientSig` (all required).

Example:
```json
{
  "nonce": 2,
  "chainType": "ethereum",
  "address": "0x1234567890123456789012345678901234567890",
  "signedMessage": "{\"nonce\":2,\"chainType\":\"ethereum\",\"address\":\"0x1234...\",\"action\":\"removeKnownAddress\"}",
  "clientSig": "0x..."
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

See [Known Addresses schema](docs/KNOWN_ADDRESSES_SCHEMA.md) for the full document shape.

### 3. Node Tools

<a id="get-getconfigurednodekeys"></a>
#### `GET /getConfiguredNodeKeys`
Returns node public keys for all configured node addresses in `configs.yaml`. Queries each node's `/getNodeKey` endpoint to retrieve their actual public keys.

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
curl "http://localhost:8080/getConfiguredNodeKeys"
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
curl "http://localhost:8080/pingNodesRequest?nodekey=1711c3077fc974b538fe6a786aae141f35f07e0ae7a91e89ebd1aed67f16846fea83a3d3b51a0c30d1d908dbf3f5ddfe71e0c03a0a0afa200a1e4cacfe223c3e&nodekey=167b2b7a21bd62d87ad9237f0f103f131469bb9849b238f003e508570f89aa122b64262248c94da97e7f5ddf2a26b3f8a66b810b7d1a81d708d0ed803cee295a"
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
curl "http://localhost:8080/getPingNodesResultById?id=Ping20260111003720999cf104d0f"
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
curl "http://localhost:8080/listPingResults?filter=all&pagenum=0&pagesize=10"
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
curl "http://localhost:8080/getInactiveNodes"
curl "http://localhost:8080/getInactiveNodes?groupId=566633a647306335d3ad6ab49829dcfad9abe1f4d1275e4ea3c3f8c292e20ee9"
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
4. Each node calls `POST /newGroupRequestAgree` to agree
5. When all nodes agree, group is created and nodes subscribe to the broker
6. Check results via `GET /getNewGroupResultById`

**Error Responses:**
- `400 Bad Request`: Missing required fields, invalid `keyList`, or `BrokerArray` cannot be derived
- `500 Internal Server Error`: Failed to send messages, group already exists, or other internal errors

<a id="get-listnewgrouprequests"></a>
#### `GET /listNewGroupRequests`
Lists all new group requests with filtering and pagination.

**Query Parameters:**
- `filter` (optional): `all`, `pending`, `success`, `failed` (default: `all`). Use `failed` to list group requests that were marked as failed.
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
      "Timepoint": "2024-12-28T12:34:56Z"
    }
  ]
}
```

**Note:** The `Addresses` field contains HTTP API addresses for each node, where `Addresses[i]` corresponds to `KeyList[i]`.

<a id="get-getnewgrouprequestbyid"></a>
#### `GET /getNewGroupRequestById`
Gets a specific group request by ID.

**Query Parameters:**
- `id` (required): Request ID from `newGroupRequest` response

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

<a id="get-getnewgroupresultbyid"></a>
#### `GET /getNewGroupResultById`
Gets a specific group result by ID (requestId) or by group_id (after group is successfully created).

**Query Parameters:**
- `id` (optional): Request ID from `newGroupRequest` response
- `group_id` (optional): Group ID (deterministic hash of sorted keyList)

**Note:** Either `id` or `group_id` must be provided, but not both.

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": {
    "RequestId": "NewGroup20241228123456789abc123",
    "NewGroupDataPb": {
      "GroupId": "566633a647306335d3ad6ab49829dcfad9abe1f4d1275e4ea3c3f8c292e20ee9",
      "KeyList": ["node1_key", "node2_key", "node3_key"],
      "Addresses": ["http://203.0.113.10:8080", "http://203.0.113.11:8080", "http://203.0.113.12:8080"],
      "SigList": {...},
      "BrokerArray": ["ssl://82.180.145.77:8883"]
    },
    "Timepoint": "2024-12-28T12:34:56Z"
  }
}
```

**Response Field Descriptions:**
- `GroupId`: Unique identifier for the group (deterministic hash)
- `KeyList`: Array of node public keys (128 hex characters each) that form the group
- `Addresses`: Array of HTTP API addresses corresponding to each node in `KeyList`. Each address at index `i` corresponds to the node key at `KeyList[i]`. Format: `http://ip:port` or `https://hostname:port`
- `SigList`: Map of node signatures agreeing to the group creation (nodeKey → signature)
- `BrokerArray`: Array of MQTT broker addresses for the group (typically one broker, e.g., `["ssl://82.180.145.77:8883"]`)

**Examples:**

Query by requestId:
```bash
curl "http://localhost:8080/getNewGroupResultById?id=NewGroup20241228123456789abc123"
```

Query by group_id:
```bash
curl "http://localhost:8080/getNewGroupResultById?group_id=566633a647306335d3ad6ab49829dcfad9abe1f4d1275e4ea3c3f8c292e20ee9"
```

**Note:** Groups can also be pre-configured in `configs.yaml` and will be automatically created on node startup. API-based creation is recommended for new groups to avoid the chicken-and-egg problem.

### 6. Key Generation

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
  "keyType": "secp256k1"
}
```

**Field Descriptions:**
- `nonce` (required): Current nonce from `/getNodeMgtKeyNonce`
- `sig` (required): Management key signature over the request body (excluding `sig` field)
- `clientPk` (required): Client public key (128 hex characters)
- `threshold` (required): Minimum number of nodes required to sign (must be less than keyList length)
- `groupId` (required): Group ID where key generation will occur
- `msgCheck` (optional): Message check type, default is "multi-agree". Must be in allowed types from `/getAllowedMsgCheckTypes`
- `keyType` (required): Key type - `"secp256k1"` for EVM chains or `"ed25519"` for Solana/Stellar/NEAR/TON

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
curl -X POST http://localhost:8080/keyGenRequest \
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

<a id="get-listkeygenrequests"></a>
#### `GET /listKeyGenRequests`
Lists all key generation requests with filtering and pagination.

**Query Parameters:**
- `filter` (optional): `all`, `pending`, `success`, `failed` (default: `all`). Use `failed` to list requests that failed (TSS error or timeout).
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
      "timepoint": "2026-02-17 13:05:29.157"
    }
  ]
}
```

**Response field descriptions (each item in `Data`):**
- `requestid`: Key generation request ID
- `ClientKeys`: Map of node public key (128 hex) to client key / placeholder (e.g. `"0x1234"` or `""`)
- `GroupId`: Group identifier (hash of sorted keyList)
- `KeyType`: Key type, e.g. `"secp256k1"` or `"ed25519"`
- `MsgCheck`: Message check type, e.g. `"tx-check"` or `"multi-agree"`
- `SigList`: Map of node public key (128 hex) to signature (hex) for nodes that agreed
- `Threshold`: Signing threshold (number of nodes required to sign is threshold + 1)
- `timepoint`: Timestamp when the request was recorded (with optional fractional seconds)

**Example:**
```bash
curl "http://localhost:8080/listKeyGenRequests?filter=success"
curl "http://localhost:8080/listKeyGenRequests?filter=all&pagenum=0&pagesize=10"
```

<a id="get-getkeygenrequestbyid"></a>
#### `GET /getKeyGenRequestById`
Gets a specific key generation request by ID.

**Query Parameters:**
- `id` (required): Key generation request ID

**Example:**
```bash
curl "http://localhost:8080/getKeyGenRequestById?id=KeyGen20260111003720999cf104d0f"
```

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

<a id="get-getkeygenresultbyid"></a>
#### `GET /getKeyGenResultById` ⭐
Gets a specific key generation result by ID. Returns the generated public key, addresses, and keyList.

A result is returned (Code 0) only when this node completed the TSS and has the full result (including local share), **and** at least **threshold+1** parties sent KEYGENRESULTCONFIRMSUCCESS within 7 days. If fewer parties completed by then, the keygen is useless for signing (cannot produce a signature); the result is then deleted and the keygen request is marked failed. If this node did not complete (e.g. worker timed out), it returns Code 1 "not ready". If one node returns "not ready" and another had completed, the client may need to call `getKeyGenResultById` on another node—but if fewer than threshold+1 parties completed overall, no node will keep the result (all will delete it after the 7-day timeout).

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
    "solanaaddress": "",
    "sorobanaddress": "",
    "nearaddress": "",
    "tonaddress": "",
    "savedata": "HIDE ENCRYPTED DATA",
    "timepoint": "2026-01-11T00:37:20.999Z"
  }
}
```

**Note:** The `keylist` field contains all node keys that participated in key generation. If it's `null` in the database, the endpoint will attempt to populate it from the group configuration.

**Example:**
```bash
curl "http://localhost:8080/getKeyGenResultById?id=KeyGen20260111003720999cf104d0f"
```

<a id="get-getkeygengroupid"></a>
#### `GET /getKeyGenGroupId` ⭐ **NEW**
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
curl "http://localhost:8080/getKeyGenGroupId?id=KeyGen20260111003720999cf104d0f"
```

**Use Cases:**
- Determine which group a keyGen belongs to
- Debug keyGen issues by identifying the group
- Query group-specific information

<a id="get-getallgroupids"></a>
#### `GET /getAllGroupIds` ⭐ **NEW**
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
    - `solanaaddress`: Solana address (for ed25519 keys)
    - `sorobanaddress`: Soroban/Stellar address (for ed25519 keys)
    - `nearaddress`: NEAR address (for ed25519 keys)
    - `tonaddress`: TON address (for ed25519 keys)
    - `groupid`: Group ID (redundant but included for convenience)
    - `threshold`: Signing threshold
    - `keytype`: Key type (`"secp256k1"` or `"ed25519"`)

**Note:** 
- `savedata` is excluded for security
- Groups with errors still appear with empty `keyGens` array
- Results are sorted by `timepoint` (newest first)

**Example:**
```bash
curl "http://localhost:8080/getAllGroupIds"
```

**Use Cases:**
- Get overview of all groups and their keyGens
- Verify that `keylist` is populated for all keyGens
- Debug missing keyList issues
- Monitor key generation across all groups

### 7. Pre-Signing

<a id="post-presignrequest"></a>
#### `POST /presignRequest`
Creates a new pre-signing request. **Requires management key authentication.**

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
curl -X POST http://localhost:8080/presignRequest \
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
curl "http://localhost:8080/listPresignRequests?filter=all&pagenum=0&pagesize=10"
```

<a id="get-getpresignrequestbyid"></a>
#### `GET /getPresignRequestById`
Gets a specific pre-signing request by ID.

**Query Parameters:**
- `id` (required): Presign request ID

**Example:**
```bash
curl "http://localhost:8080/getPresignRequestById?id=Presign20260111003720999cf104d0f"
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
curl "http://localhost:8080/listPresignResults?pagenum=0&pagesize=10"
```

<a id="get-getpresignresultbyid"></a>
#### `GET /getPresignResultById`
Gets a specific pre-signing result by ID.

**Query Parameters:**
- `id` (required): Presign request ID

**Example:**
```bash
curl "http://localhost:8080/getPresignResultById?id=Presign20260111003720999cf104d0f"
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
curl "http://localhost:8080/getPresigningStatus"
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

Management-key endpoints (keyGenRequest, presignRequest, newGroupRequest, etc.) are used by the node operator/frontend, not by the relayer; they require NodeMgtKey or PublicMgtKey signature.

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
curl -X POST http://localhost:8080/signRequest \
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
Creates a new signing request for **multi-agree keys only**. No relayer authentication; uses the same internal sign flow as `signRequest`. Nodes in the same GroupId must agree via `POST /signRequestAgree`; when enough nodes have agreed, the message in `msgRaw` is signed. Supports **gas token (native transfer) requests**: use optional `sendGas` and `value` for "Send gas" flows; they are part of the signed payload and stored in `ExtraJSON` so all nodes see them in `getSignRequestById` and `listSignRequests`.

**Request Body:**
```json
{
  "clientSig": "<client signature over request (same scheme as keyGenRequest)>",
  "keyList": ["node1_key", "node2_key", "node3_key"],
  "pubKey": "08caf50811eb4c2bed7b3f8dc9c292b5cf521ba3774ea49dcd949e8235a48b22e8c1f16b356710aae4095e498bfff8385eada1e53a47dbdd984d32ae4d20a5de",
  "msgHash": "751f68b43977269a16128143fa15e0e7ab3c15ba52484fe8278796561505698b",
  "msgRaw": "<raw message bytes, hex encoded>",
  "destinationChainID": "11155111",
  "destinationAddress": "0x...",
  "extraJSON": "{}",
  "sendGas": true,
  "value": "1000000000000000000"
}
```

**Field Descriptions:**
- `clientSig` (required): Client signature over the request (excluding `clientSig`), verified like keyGenRequest
- `keyList` (required): Array of node keys in the same GroupId that may participate; can be empty array `[]` to use keyList from KeyGenResult
- `pubKey` (required): Public key (128 hex characters) from key generation (must be multi-agree key)
- `msgHash` (required): Keccak256 hash of the message to sign. **EVM broadcast:** For secp256k1 keys, if the client will build a signed tx and call `eth_sendRawTransaction`, the recovered signer must match the keyGen's `ethereumaddress`. That only holds when the signature is over the **transaction signing hash** (hash of the serialized unsigned EIP-1559/legacy tx). If the client sends a different hash (e.g. only `keccak256(msgRaw)`), the MPC signs it correctly, but using that (r,s,v) on the full tx yields a different recovered address; send the tx signing hash as `msgHash` and use the same nonce/gas when building the signed tx.
- `msgRaw` (optional): Raw message bytes (hex encoded)
- `destinationChainID` (required): Destination chain ID for the signed message (EVM signatures only; stored and returned in `listSignRequests` / `getSignRequestById` so the node key knows which chain the signature is destined for)
- `destinationAddress` (optional): Destination address (EVM signatures only; stored and returned in `listSignRequests` / `getSignRequestById`)
- `extraJSON` (optional): Arbitrary JSON string for node context; used for **Ed25519** key types (not secp256k1). Stored and returned in `listSignRequests` / `getSignRequestById`. For send-gas requests, the backend merges `sendGas` and `value` into this object before storing.
- `signatureText` (optional): For EVM/secp256k1, a JSON string with structure `{"signature": "<function signature>", "names": ["<name1>", "<name2>", ...]}` where `signature` is the function selector text (e.g. `transfer(address,uint256)`) and `names` is an array of parameter names in order. Example: `{"signature": "transfer(address,uint256)", "names": ["to", "amount"]}`. Other chains: program name or custom text. Stored and returned in `listSignRequests` / `getSignRequestById`.
- `purpose` (optional): Text from the creator, max 256 characters; visible to nodes considering `signRequestAgree` (stored and returned in list/get endpoints and `getSignResultById`). Stored as a key/value map in `Purpose`: the creator node key (128 hex) is the key and the purpose text is the value, so which node created the request is identifiable in `getSignRequestById`, `listSignRequests`, and `listSignRequestsReady`. Example response: `"Purpose": { "04a1b2c3...128hex": "Bridge transfer to L2" }`.
- `sendGas` (optional, **multi-agree gas token only**): Set to `true` for native transfer requests created from the Assets "Send gas" dialog. Included in the signed payload when present. Stored in `ExtraJSON` and propagated; returned in `getSignRequestById` and `listSignRequests` via `ExtraJSON`.
- `value` (optional, **multi-agree gas token only**): Amount in wei for the native transfer. Included in the signed payload when present. Stored in `ExtraJSON` and propagated; returned in `getSignRequestById` and `listSignRequests` via `ExtraJSON`. Also available in sign result metadata for Execute.

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
curl -X POST http://localhost:8080/multiSignRequest \
  -H "Content-Type: application/json" \
  -d '{
    "clientSig": "0x...",
    "keyList": [],
    "pubKey": "08caf50811eb4c2bed7b3f8dc9c292b5cf521ba3774ea49dcd949e8235a48b22e8c1f16b356710aae4095e498bfff8385eada1e53a47dbdd984d32ae4d20a5de",
    "msgHash": "751f68b43977269a16128143fa15e0e7ab3c15ba52484fe8278796561505698b",
    "msgRaw": "",
    "destinationChainID": "11155111",
    "destinationAddress": "0x...",
    "extraJSON": "{}"
  }'
```

**Error Responses:**
- `400 Bad Request`: Key not found or key is not multi-agree type
- `401 Unauthorized`: Client signature invalid
- `500 Internal Server Error`: Internal processing error

<a id="get-listsignrequests"></a>
#### `GET /listSignRequests`
Lists all signing requests with filtering and pagination. Use this (and `getSignRequestById`) to see which node keys have already agreed: **SigList** contains node key → signature for each node that has agreed; any node in **KeyList** that is missing from SigList or has an empty signature can still call `POST /signRequestAgree`.


**Query Parameters:**
- `filter` (optional): `all`, `pending`, `success`, `originator`, `blocked` (default: `all`). Use `blocked` to list sign requests whose lifecycle status is `"blocked"` (cannot reach threshold+1 agreements).
  - `all`: All sign requests
  - `pending`: Requests this node can still agree to (not initiator, not completed, not already agreed, not rejected)
  - `success`: Requests where this node is the initiator or status is not "agree"
  - `originator`: Only sign requests **created by this node** (this node’s key is the key in the `Purpose` map)
- `pagenum` (optional, default: 0)
- `pagesize` (optional, default: 10)

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
- `MessageHash`, `MessageRaw`: Message to sign (Keccak256 hash and optional raw bytes)
- `KeyList`: Node keys that may participate in signing (same GroupId as the key)
- `PresignId`: If set, this request uses a presign; otherwise normal signing
- `ClientSigs`: Map of node key → client signature (from the node when agreeing); empty or missing means that node has not agreed yet
- `SigList`: Map of node key → agreement signature for nodes that have agreed. **If a node is in KeyList but missing from SigList or has an empty value, that node can call `POST /signRequestAgree`.**
- `IsTestTransaction`: Whether the request was created without source tx verification
- `DestinationChainID`: Chain ID the signature is destined for (EVM signatures only). Set for requests created via `multiSignRequest` or passed in `signRequest`; empty if not provided.
- `DestinationAddress`: Destination address when provided at request creation (EVM signatures only); empty if not provided.
- `ExtraJSON`: Arbitrary JSON string passed at request creation (e.g. for node context); stored and returned in listSignRequests; empty if not provided. For **multi-agree send-gas** requests, the backend merges `sendGas` and `value` into this object, so the app can read them for Join/Execute UI and for building the native transfer at Get Sig/Execute.
- `SignatureText`: For EVM/secp256k1, JSON string `{"signature": "<function signature>", "names": ["<name1>", ...]}` (signature = selector text, names = parameter names in order). Other chains: program name or custom text. Stored and returned in listSignRequests; empty if not provided.
- `RejectedBy`: (multi-agree only) List of node keys that declined to sign; those nodes no longer see this request in `filter=pending`.
- `Purpose`: Key/value map: node key (128 hex) → purpose text (max 256 chars per entry). Visible to nodes considering agree/reject. The key identifies which node created or submitted the request (multiSignRequest: creator node; signRequest/tx-check: node that received the request).
- `Thoughts`: Map of node key → optional comment (max 256 chars each) from each node when they called `signRequestAgree` (accept or reject).
- `KeyGenRequestId`: Key generation request ID (keyGenId) for the MPC key used by this sign request (same as the keygen request that produced `PubKey`). Included in listSignRequests, getSignRequestById, getSignResultById, and listSignRequestsReady.
- `status`: Sign request lifecycle status: `"live"` (default after creation), `"shelved"` (set by the originator via `POST /shelveSignRequest`), or `"blocked"` (set automatically when threshold+1 can no longer be reached, e.g. too many nodes have rejected). Omitted or `"live"` until set.
- `timepoint`: When the request was recorded

**Example:**
```bash
curl "http://localhost:8080/listSignRequests?filter=all&pagenum=0&pagesize=10"
curl "http://localhost:8080/listSignRequests?filter=originator&pagenum=0&pagesize=10"
curl "http://localhost:8080/listSignRequests?filter=blocked&pagenum=0&pagesize=10"
```

<a id="get-getsignrequestbyid"></a>
#### `GET /getSignRequestById`
Gets a specific signing request by ID. Returns the same structure as each item in `listSignRequests` (including `KeyGenRequestId`, `DestinationChainID`, `Purpose`, `TxParams` when set, etc.). Optional fields only appear if this node is running a build that includes them (see note under `listSignRequests`).

**Query Parameters:**
- `id` (required): Sign request ID
- `tx_params` (optional): If `1`, response `data` is **only** the TxParams object (same shape as below), not the full sign request. Use this when the client already has the sign request and only needs TxParams for Execute.

**TxParams** (when present) is stored only on the node that received `triggerSignRequestById`; it contains `nonce`, `gasLimit`, `txType`, and either EIP-1559 or legacy gas fields so the app can rebuild the same EVM transaction at Execute.

**Example:**
```bash
curl "http://localhost:8080/getSignRequestById?id=Sign20260111003720999cf104d0f"
```

**Example (TxParams only):**
```bash
curl "http://localhost:8080/getSignRequestById?id=Sign20260111003720999cf104d0f&tx_params=1"
```

<a id="post-signrequestagree"></a>
#### `POST /signRequestAgree`
Agrees to or rejects a signing request.

- **tx-check (relayer):** Unchanged. Request body is `requestId` + `clientSig`; no `accept` or `thoughts` field. Relayer flow is not affected.
- **multi-agree:** Optional `accept` (boolean). Omitted or `true` = agree to sign (same as before). `false` = reject: this node is recorded as having declined; the request **no longer appears in this node's `listSignRequests?filter=pending`**. The client must sign over the same body (including `accept` and `thoughts` when present). Other nodes may still agree; rejection is per-node.

**Request Body:**
- `requestId` (required): Sign request ID
- `clientSig` (required for multi-agree when client sig check enabled): Signature over the **exact** request body used for this call (including `requestId`, `clientSig` empty, `accept`, and `thoughts` when present). For **MetaMask** (Ethereum address client key), use `personal_sign`; send the same string in `signedMessage`. For P256 (128-hex client key), the backend hashes the JSON with SHA256 and verifies ECDSA P256.
- `accept` (optional, **multi-agree only**): `true` or omitted = agree to sign; `false` = reject (drops from this node's pending list). Ignored for tx-check.
- `thoughts` (optional): Comment from this node when agreeing or rejecting, max 256 characters; stored per node key and returned in list/get and `getSignResultById`.
- `signedMessage` (optional, **required for MetaMask**): The exact string the client signed (e.g. the JSON body with `clientSig: ""`). Required when the key's client key is an Ethereum address (MetaMask); optional for Ed25519 (backend can use canonical JSON if omitted). Ignored for P256.
- `signerAddress` (optional): The connected wallet address (e.g. from MetaMask). When provided together with `signedMessage`, the node verifies that `signerAddress` matches this node's **NodeMgtKey** (config) and verifies the signature with `VerifyMessageSignature(signedMessage, clientSig, signerAddress)`. Use this when the key was created on another node so this node's ClientKeys entry may be empty or a placeholder.

**Example (multi-agree agree):**
```json
{ "requestId": "Sign20260111003720999cf104d0f", "clientSig": "0x...", "accept": true }
```

**Example (multi-agree agree with thoughts):**
```json
{ "requestId": "Sign20260111003720999cf104d0f", "clientSig": "0x...", "accept": true, "thoughts": "Verified on explorer" }
```

**Example (multi-agree reject):**
```json
{ "requestId": "Sign20260111003720999cf104d0f", "clientSig": "0x...", "accept": false }
```

**Example (multi-agree reject with thoughts):**
```json
{ "requestId": "Sign20260111003720999cf104d0f", "clientSig": "0x...", "accept": false, "thoughts": "Risk too high" }
```

**Response:**
- On agree: `"data": "success to agree signrequest with requestid ..."`
- On reject (multi-agree only): `"data": "success to reject signrequest with requestid ..."`

<a id="get-listsignresults"></a>
#### `GET /listSignResults`
Lists sign results with optional filter and pagination. Each item in the response has the **same fields** as a single `GET /getSignResultById` result (requestid, messagehash, sigdata, sigr, sigs, sigrecover, timepoint, keylist, participatingkeys, signaturehex, keytype, signatureformat, DestinationChainID, DestinationAddress, ExtraJSON, RejectedBy, Purpose, Thoughts, KeyGenRequestId, status, transactionhash, shelved, and ethereumSignature when applicable).

**Query Parameters:**
- `filter` (optional, default `"all"`): `"all"` — all sign results; `"active"` — status is not `"executed"` and not `"shelved"` (i.e. not yet updated by originator); `"originator"` — only results where this node's key is the key in the **Purpose** map (i.e. created by this node via multiSignRequest).
- `pagenum` (optional): Page number (0-based). Used only when `pagesize` > 0.
- `pagesize` (optional): Page size. Use `0` to return all results for the filter (no pagination).

**Response:**
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
  ]
}
```

Results are sorted by **timepoint** descending. Field meanings are the same as in `GET /getSignResultById`.

**Example:**
```bash
curl "http://localhost:8080/listSignResults?filter=active&pagenum=0&pagesize=10"
curl "http://localhost:8080/listSignResults?filter=originator&pagesize=0"
```

<a id="get-getsignresultbyid"></a>
#### `GET /getSignResultById`
Gets a specific signing result by ID. Returns the signature data.

**Query Parameters:**
- `id` (required): Sign request ID

**Response:**
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

**Note:** `Purpose` in the result is a key/value map (node key → purpose text), so you can identify which node created or submitted the request. `KeyGenRequestId` is the key generation request ID (keyGenId) for the MPC key used by this sign request. **Status fields** (`status`, `transactionhash`, `shelved`) are set by the originator via `POST /updateSignResultStatusById`: `"executed"` with transaction hash when the tx was broadcast, or `"shelved"` with `shelved: true` when the transaction will not be broadcast.

**Field Descriptions:**
- `keylist`: Array of node keys that were selected to participate in signing (filtered to only online nodes)
- `participatingkeys`: Array of node keys that actually participated in signing (derived from `SigList`, sorted alphabetically). This is the definitive list of nodes that contributed to the signature.
- `signaturehex`: Full signature as hex string (64 bytes = 128 hex chars for both secp256k1 and ed25519)
- `keytype`: Key type used ("secp256k1" or "ed25519")
- `signatureformat`: Signature format ("ieee-p1363" for secp256k1, "ed25519" for ed25519)
- `DestinationChainID`, `DestinationAddress`, `ExtraJSON`, `RejectedBy`, `Purpose`, `Thoughts`, `KeyGenRequestId`: Same as in the sign request; merged from the latest sign request so the result includes this metadata. For **send-gas** (multi-agree native transfer) requests, `ExtraJSON` contains `sendGas` and `value` (wei) so the app can build the native transfer at Execute. `Purpose` is a key/value map (node key → purpose text); see note above and listSignRequests field descriptions. `KeyGenRequestId` is the key generation request ID (keyGenId) for the MPC key.
- `status`: Set by the originator via `POST /updateSignResultStatusById`: `"executed"` (transaction was broadcast) or `"shelved"` (will not be broadcast). Omitted until set.
- `transactionhash`: Hash of the broadcast transaction; set when `status` is `"executed"`. Omitted until set.
- `shelved`: Boolean; `true` when the originator marked the result as shelved (not to be broadcast). Set when `status` is `"shelved"`. Omitted or false until set.

**When `status` is `"shelved"`:** The API does not return the signature. The fields `sigdata`, `sigr`, `sigs`, `sigrecover`, `signaturehex`, and `ethereumsignature` are omitted from the response for both `GET /getSignResultById` and each item in `GET /listSignResults`.

**Example:**
```bash
curl "http://localhost:8080/getSignResultById?id=Sign20260111003720999cf104d0f"
```

<a id="get-issignrequestreadybyid"></a>
#### `GET /isSignRequestReadyById`
Returns whether a sign request is **ready to trigger** (multi-agree only). Ready means the request has at least **threshold+1** nodes in **SigList** (agreeing set). For tx-check or non–multi-agree keys, returns `ready: false`. Use this before calling `POST /triggerSignRequestById`.

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
curl "http://localhost:8080/isSignRequestReadyById?id=Sign20260111003720999cf104d0f"
```

<a id="get-listsignrequestsready"></a>
#### `GET /listSignRequestsReady`
Lists **multi-agree** sign requests that are **ready to trigger**: this node is in the agreeing set (**SigList**), at least threshold+1 have agreed, and the request has **not** yet been triggered (no sign result). Use `GET /getSignResultById` to see when the signature is ready after triggering. Supports pagination.

**Query Parameters:**
- `pagenum` (optional): Page number (default `0`).
- `pagesize` (optional): Page size (default `10`). Use `0` to return all.

**Response:** Same structure as `GET /listSignRequests` (array of sign request objects, including `KeyGenRequestId`). Only includes requests that are ready and where this node is in **SigList**.

**Rejections and keyGen:** Rejecting a sign request (`POST /signRequestAgree` with `accept: false`) only adds this node to **RejectedBy**; it does **not** remove or alter the keyGen request or keyGen result. "Ready" is based solely on **SigList** (agreeing nodes): if at least threshold+1 nodes are in SigList, the request is ready regardless of RejectedBy. If a request with threshold+1 agreements does **not** appear in `listSignRequestsReady` or `triggerSignRequestById` fails with "keygen result for pubkey ... not found", the **keyGen result** is missing on this node. The keyGen result is only deleted when **keygen** failed: fewer than threshold+1 parties sent KEYGENRESULTCONFIRMSUCCESS within 7 days; then the result is deleted and the keyGen **request** is marked `"failed"` (the request document is not deleted). In that case the key is unusable for signing. The keyGen request remains in the DB with status `"failed"`; only the keyGen **result** (the actual key material) is removed.

**Example:**
```bash
curl "http://localhost:8080/listSignRequestsReady?pagenum=0&pagesize=10"
```

<a id="post-triggersignrequestbyid"></a>
#### `POST /triggerSignRequestById`
**Multi-agree only.** When at least **threshold+1** nodes have accepted (and rejections are excluded), triggers signature generation: sends **SIGNREQUESTCONFIRMSUCCESS** and starts the sign worker. **Only the originator may call this:** the request’s **Purpose** map must have this node’s key as the (originator) key; otherwise the server returns an error. **If the sign request status is `"shelved"`** (set via `POST /shelveSignRequest`), the server returns an error and does not trigger. **Idempotent:** if the request was already triggered, returns success with data `"Already triggered"`. Does not affect tx-check flow. Requires management key signature (MetaMask or Ed25519).

**Request Body:**
```json
{
  "requestId": "Sign20260111003720999cf104d0f",
  "nonce": 1,
  "sig": "0x..."
}
```

- `requestId` (required): Sign request ID.
- `nonce`, `sig`: Management key signature over the JSON body with `sig` set to empty (same as other mgt-key endpoints).
- `txParams` (optional, **EVM**): Object with `nonce` (number), `gasLimit` (string), `txType` (`"eip1559"` or `"legacy"`), and for EIP-1559: `maxFeePerGas`, `maxPriorityFeePerGas` (strings); for legacy: `gasPrice` (string). Stored on **this node only** (not propagated). Returned in `getSignRequestById` so the app can rebuild the same tx at Execute.
- `messageHash` (optional, **EVM**): The **transaction signing hash** to sign. If provided, the backend updates the sign request's MessageHash on **this node only** before starting the sign worker; the MPC signs this hash. Not propagated to other nodes.

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

**Example:**
```bash
curl -X POST http://localhost:8080/triggerSignRequestById \
  -H "Content-Type: application/json" \
  -d '{
    "requestId": "Sign20260111003720999cf104d0f",
    "nonce": 1,
    "sig": "0x..."
  }'
```

<a id="post-updatesignresultstatusbyid"></a>
#### `POST /updateSignResultStatusById`
**Originator only.** Updates the sign result status so that nodes see it in `GET /getSignResultById`. Only the node that created the sign request (originator: node key in **Purpose**) may call. **The update can only happen once:** if status (executed/shelved) is already set, a second call returns an error. Requires management key signature (MetaMask or Ed25519).

**Status values:**
- **`executed`**: The transaction was broadcast. You must send `transactionHash` (hash of the transaction).
- **`shelved`**: The transaction will **not** be broadcast. Set `shelved: true` (or omit; backend sets true). No `transactionHash`.

**Request Body:**
```json
{
  "requestId": "Sign20260111003720999cf104d0f",
  "status": "executed",
  "transactionHash": "0xabc123...",
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

- `requestId` (required): Sign request ID (must already have a sign result, i.e. trigger was run).
- `status` (required): `"executed"` or `"shelved"`.
- `transactionHash` (required when `status` is `"executed"`): Hash of the broadcast transaction.
- `shelved` (optional when `status` is `"shelved"`): Set to `true`; if omitted, backend sets `shelved: true` when status is shelved.
- `nonce`, `sig`: Management key signature over the JSON body with `sig` set to empty.

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": "Updated"
}
```

**Errors:** Non-originator or missing Purpose (no originator key in map) returns 500 with message that only the originator can update. Sign result not found (trigger not run yet) or status already set (update can only happen once) returns 500.

**Example:**
```bash
curl -X POST http://localhost:8080/updateSignResultStatusById \
  -H "Content-Type: application/json" \
  -d '{
    "requestId": "Sign20260111003720999cf104d0f",
    "status": "executed",
    "transactionHash": "0xabc123...",
    "nonce": 1,
    "sig": "0x..."
  }'
```

<a id="post-shelvesignrequest"></a>
#### `POST /shelveSignRequest`
**Originator only.** Sets the sign request lifecycle status to `"shelved"`. Only the node that created the sign request (originator: node key in **Purpose**) may call. The update is propagated to other nodes so all nodes see the status in `GET /getSignRequestById` and `GET /listSignRequests`. **The update can only happen once:** if the sign request is already shelved or blocked, a second call returns an error. Requires management key signature (MetaMask or Ed25519). **Note:** When a node rejects via `POST /signRequestAgree` with `accept: false`, if the number of remaining nodes that could still agree falls below threshold+1, the backend automatically sets the sign request status to `"blocked"` and propagates it to other nodes; `GET /getSignRequestById` then returns `"status": "blocked"`.

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
curl -X POST http://localhost:8080/shelveSignRequest \
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
curl -X POST http://localhost:8080/admin/registerRelayer \
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
curl "http://localhost:8080/admin/listRelayers"
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
curl "http://localhost:8080/admin/getRelayer?publicKey=ed8639ee02b0e0cb8caade8ea24c71b1c60c55fa241032767e67c4da6e691f5fd08a36b005a2c1fd68c9b5a04137c406d458ba73b562aa269f52ceb6a285e41a"
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
curl -X POST http://localhost:8080/updateRelayer \
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
- **URL:** `http://localhost:8080/swagger/index.html`
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
curl "http://localhost:8080/getConfiguredNodeKeys"

# Step 2: Create group
curl -X POST http://localhost:8080/newGroupRequest \
  -H "Content-Type: application/json" \
  -d '{
    "keyList": ["node1_key", "node2_key", "node3_key"],
    "BrokerArray": ["ssl://82.180.145.77:8883"],
    "nonce": 1,
    "sig": "0x..."
  }'

# Step 3: Each node agrees
curl -X POST http://localhost:8080/newGroupRequestAgree \
  -H "Content-Type: application/json" \
  -d '{
    "requestId": "NewGroup20241228123456789abc123",
    "nonce": 1,
    "sig": "0x..."
  }'

# Step 4: Request key generation
# Note: clientPk should be generated by the client/dApp (not by the node)
curl -X POST http://localhost:8080/keyGenRequest \
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

# Step 5: Each node agrees to keygen
curl -X POST http://localhost:8080/keyGenRequestAgree \
  -H "Content-Type: application/json" \
  -d '{
    "requestId": "KeyGen20260111003720999cf104d0f",
    "nonce": 2,
    "sig": "0x..."
  }'

# Step 6: Get key generation result
curl "http://localhost:8080/getKeyGenResultById?id=KeyGen20260111003720999cf104d0f"
```

### 2. Signing a Transaction

```bash
# Step 1: Register relayer (one-time per node)
curl -X POST http://localhost:8080/admin/registerRelayer \
  -H "Content-Type: application/json" \
  -d '{
    "relayerPublicKey": "ed8639ee02b0e0cb8caade8ea24c71b1c60c55fa241032767e67c4da6e691f5fd08a36b005a2c1fd68c9b5a04137c406d458ba73b562aa269f52ceb6a285e41a",
    "relayerName": "my-relayer",
    "allowedChains": ["11155111"],
    "registeredBy": "operator"
  }'

# Step 2: Create sign request (from relayer)
curl -X POST http://localhost:8080/signRequest \
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
curl -X POST http://localhost:8080/signRequestAgree \
  -H "Content-Type: application/json" \
  -d '{
    "requestId": "Sign20260111003720999cf104d0f"
  }'

# Step 4: Get signature result
curl "http://localhost:8080/getSignResultById?id=Sign20260111003720999cf104d0f"
```

### 3. Multi-Agree Signing (Ready / Trigger Flow)

For **multi-agree** keys, nodes agree via `POST /signRequestAgree`. Once at least **threshold+1** nodes have agreed, **only the originator** (the node whose key is the key in the Purpose map, i.e. the one that created the request via multiSignRequest) may call `POST /triggerSignRequestById` to trigger signature generation. Use `GET /getSignResultById` to poll for the signature. The originator can then call `POST /updateSignResultStatusById` to set status to `"executed"` (with transaction hash) or `"shelved"` (transaction will not be broadcast); these fields appear in `getSignResultById`. The originator can also call `POST /shelveSignRequest` to set the **sign request** status to `"shelved"` (e.g. to cancel or defer the request before triggering); this status appears in `getSignRequestById` and `listSignRequests` and is propagated to all nodes.

```bash
# Step 1: Create multi-agree sign request (e.g. from dApp)
curl -X POST http://localhost:8080/multiSignRequest \
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
curl -X POST http://localhost:8080/signRequestAgree \
  -H "Content-Type: application/json" \
  -d '{"requestId": "Sign20260111003720999cf104d0f", "clientSig": "0x...", "accept": true}'

# Step 3: Check if ready, then trigger (any node)
curl "http://localhost:8080/isSignRequestReadyById?id=Sign20260111003720999cf104d0f"
# When data.ready is true:
curl -X POST http://localhost:8080/triggerSignRequestById \
  -H "Content-Type: application/json" \
  -d '{"requestId": "Sign20260111003720999cf104d0f", "nonce": 1, "sig": "0x..."}'

# Step 4: Get signature result (poll until available)
curl "http://localhost:8080/getSignResultById?id=Sign20260111003720999cf104d0f"

# Optional: list all sign requests ready to trigger (for this node)
curl "http://localhost:8080/listSignRequestsReady?pagenum=0&pagesize=10"
```

### 4. Checking System Health

```bash
# Check overall health
curl "http://localhost:8080/health"

# Check connectivity
curl "http://localhost:8080/connectivityHealth"

# Check specific group connectivity
curl "http://localhost:8080/connectivityHealth?groupId=566633a647306335d3ad6ab49829dcfad9abe1f4d1275e4ea3c3f8c292e20ee9"

# Get logs
curl "http://localhost:8080/getLogs?hours=24"
```

### 5. Querying Key Generation Information

```bash
# Get keyGen result
curl "http://localhost:8080/getKeyGenResultById?id=KeyGen20260111003720999cf104d0f"

# Get GroupId for a keyGen
curl "http://localhost:8080/getKeyGenGroupId?id=KeyGen20260111003720999cf104d0f"

# Get all groups and their keyGens
curl "http://localhost:8080/getAllGroupIds"
```

## See Also

- `API_docs.md` - Usage examples and workflows
- `README.md` - General project documentation
- `docs/swagger.yaml` - Complete API specification
- `node/managementapi.go` - API implementation source code

