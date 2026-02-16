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

## Endpoint Categories

### 1. Node Information Endpoints

#### `GET /version`
Returns the current node version.

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": "v1.0"
}
```

#### `GET /getMachineInfo`
Returns machine information (CPU, memory, etc.).

#### `GET /getNodeKey`
Returns the node's unique public key (node ID).

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": "<128-character hex string>"
}
```

#### `GET /getNodeMgtKey`
Returns the node management key (Ethereum address format).

#### `GET /getNodeMgtKeyNonce`
Returns the current nonce for the node management key.

#### `GET /getAllowedKeyTypes`
Returns list of allowed key types (e.g., "ecdsa", "eddsa").

#### `GET /getAllowedMsgCheckTypes`
Returns list of allowed message check types.

#### `GET /getSuccessRate`
Returns node success rate statistics for keygen and signing operations.

#### `GET /getPreSigningVerificationStatus`
Returns the status and configuration of pre-signing verification.

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

#### `POST /nodeRegister`
One-time registration of the node and relayer info. Requires a `NodeMgtKey` signature; rejected if the node is already registered.

Request body (NodeRegisterRequest):
```json
{
  "nodeName": "my-node-name",
  "relayerPublicKey": "<128-hex>",
  "forumHandle": "telegram_or_discord_handle",
  "forumType": "Telegram|Discord",
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

#### `GET /fetchNodeData`
Fetches node registration data by node ID (IP:port format).

**Query Parameters:**
- `id` (required): Node ID in format `http://ip:port` or `https://ip:port`

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
    "relayerPublicKey": "<128-hex>",
    "forumHandle": "telegram_or_discord_handle",
    "forumType": "Telegram",
    "email": "operator@example.com",
    "vpsProvider": "aws",
    "ramGB": 16,
    "cpuCores": 8,
    "didType": "optional",
    "did": "optional",
    "mpcGroups": [...],
    "createdAt": "2024-01-01T00:00:00Z"
  }
}
```

#### `GET /fetchNodeDataByPublicKey`
Fetches node registration data by node public key (128 hex chars).

**Query Parameters:**
- `publicKey` (required): Node public key (128 hex chars)

**Response:**
Same format as `/fetchNodeData` above.

### 3. Node Tools

#### `GET /generateClientKey`
Generates a new client key pair for dApps. **Note:** The node does not save this key.

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": {
    "PublicKey": "...",
    "PrivateKey": "..."
  }
}
```

### 3. Neighbor Node Management

#### `GET /addNeighborNodes`
Adds neighbor nodes to the node's neighbor list.

**Query Parameters:**
- `name` (array): Node names
- `key` (array): Node keys (128 hex characters)

#### `GET /listNeighborNodes`
Lists all neighbor nodes with pagination.

**Query Parameters:**
- `pagenum` (optional, default: 0)
- `pagesize` (optional, default: 10)

### 4. Node Ping

#### `GET /pingNodesRequest`
Sends a ping request to specified nodes to test connectivity.

**Query Parameters:**
- `nodekey` (array): Node keys to ping

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": "<request-id>"
}
```

#### `GET /getPingNodesResultById`
Retrieves ping results by request ID.

**Query Parameters:**
- `id` (required): Ping request ID

#### `GET /listPingResults`
Lists all ping results with filtering and pagination.

**Query Parameters:**
- `filter` (optional): `all`, `pending`, `success` (default: `all`)
- `pagenum` (optional, default: 0)
- `pagesize` (optional, default: 10)

### 5. Group Management

Groups can be created in two ways:
1. **Pre-configured** in `configs.yaml` (automatically created on node startup)
2. **Via API** using `POST /newGroupRequest` (dynamic creation)

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

#### `GET /listNewGroupRequests`
Lists all new group requests with filtering and pagination. **Use this endpoint to get a list of all groups without knowing their IDs.**

**Query Parameters:**
- `filter` (optional): `all`, `pending`, `success` (default: `all`)
  - Use `filter=success` to get only successfully created groups
  - Use `filter=pending` to get groups that are still being created
  - Use `filter=all` to get all groups regardless of status
- `pagenum` (optional, default: 0)
- `pagesize` (optional, default: 10)

**Example: List all successfully created groups:**
```bash
GET /listNewGroupRequests?filter=success&pagenum=0&pagesize=100
```

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
        "SigList": {...},
        "BrokerArray": ["ssl://82.180.145.77:8883"]
      },
      "Timepoint": "2024-12-28T12:34:56Z"
    }
  ]
}
```

#### `GET /getNewGroupRequestById`
Gets a specific group request by ID.

**Query Parameters:**
- `id` (required): Request ID from `newGroupRequest` response

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
  "data": "success to agree newgrouprequest with requestid NewGroup20241228123456789abc123"
}
```

**Note:** When a node agrees, it registers relay channels for the broker and sends a reply message back to the initiator.

#### `GET /getNewGroupResultById`
Gets a specific group result by ID (after group is successfully created).

**Query Parameters:**
- `id` (required): Request ID from `newGroupRequest` response

**Note:** To list all successfully created groups without knowing IDs, use `GET /listNewGroupRequests?filter=success` (see above). This returns all groups that have been successfully created, including their `RequestId` which can be used with this endpoint to get full details.

### 6. Key Generation

#### `POST /keyGenRequest`
Creates a new key generation request. **Requires management key authentication.**

**Request Body:**
```json
{
  "nonce": 1,
  "sig": "...",
  "clientPk": "...",
  "threshold": 2,
  "groupId": "...",
  "msgCheck": "multi-agree",
  "keyType": "ecdsa"
}
```

**Example Request:**
```bash
curl -X 'POST' 'http://'$IPADDR1':8080/keyGenRequest' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
    "groupId": "566633a647306335d3ad6ab49829dcfad9abe1f4d1275e4ea3c3f8c292e20ee9",
    "clientPk": "0x1234567890abcdef...",
    "threshold": 1,
    "keyType": "secp256k1",
    "msgCheck": "multi-agree",
    "nonce": 0,
    "sig": ""
  }'
```

**Note:** 
- Replace `$IPADDR1` with your actual node IP address
- The `nonce` should be obtained from `/getNodeMgtKeyNonce` before making the request
- The `sig` field should contain the management key signature over the request body (excluding the `sig` field itself)
- The `clientPk` can be generated using `/generateClientKey` or can be a placeholder if `IgnoreClientSigCheck: true` in configs.yaml

#### `GET /listKeyGenRequests`
Lists all key generation requests with filtering.

**Query Parameters:**
- `filter` (optional): `all`, `pending`, `success`
- `pagenum` (optional, default: 0)
- `pagesize` (optional, default: 10)

**Important:** Key generation requests and results are stored **locally on each node**. This endpoint only returns requests that:
- Were initiated on this node, OR
- This node participated in (agreed to)

If a node didn't participate in a key generation, it won't have that request in its database and won't appear in the list. To find all key generations across your network, you need to query each participating node individually.

#### `GET /getKeyGenRequestById`
Gets a specific key generation request by ID.

**Query Parameters:**
- `id` (required): Key generation request ID

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": {
    "requestid": "KeyGen202512310112349997366f244",
    "ClientKeys": {...},
    "GroupId": "...",
    "KeyType": "secp256k1",
    "MsgCheck": "multi-agree",
    "SigList": {...},
    "Threshold": 1,
    "timepoint": "2025-12-31 01:12:34.69"
  }
}
```

**Note:** The presence of signatures in `SigList` indicates nodes have agreed to participate, but the actual MPC key generation process happens asynchronously after all required nodes agree. The result will only be available via `getKeyGenResultById` after the MPC process completes successfully. Check `listKeyGenRequests?filter=success` to see if the key generation has completed.

#### `POST /keyGenRequestAgree`
Agrees to a key generation request. **Requires management key authentication.**

#### `GET /getKeyGenResultById`
Gets a specific key generation result by ID (requestId from `keyGenRequest`).

**Query Parameters:**
- `id` (required): Key generation request ID (e.g., "KeyGen20241228123456789abc123")

**Important:** 
- This endpoint requires the **request ID** returned from the original `POST /keyGenRequest` call. If you're using `GET /listKeyGenRequests?filter=success` to find successful key generations, make sure to use the `RequestId` field from that response, not any other ID field.
- **Results are stored locally on each participating node.** You can only retrieve results from nodes that:
  - Initiated the key generation request, OR
  - Participated in (agreed to) the key generation
  
If you query a node that didn't participate, you'll get "mongo: no documents in result" even if the key generation was successful. Query from a node that was part of the key generation process.

**Troubleshooting:**
- If you get "mongo: no documents in result" error, try these steps:

  1. **Verify the key generation completed successfully:**
     ```bash
     curl -X GET "http://${IPADDR1}:8080/listKeyGenRequests?filter=success"
     ```
     Check that your request ID appears in the list with a successful status.

  2. **Check the request status:**
     ```bash
     curl -X GET "http://${IPADDR1}:8080/getKeyGenRequestById?id=KeyGen202512310112349997366f244"
     ```
     This will show you the current status of the request.

  3. **Try querying from a different node:**
     If you have multiple nodes, try querying the result from each node that participated in the key generation. Results are stored locally on each node.

  4. **Verify the ID format:**
     The ID should match exactly what was returned from `POST /keyGenRequest`. If you're using an ID from `listKeyGenRequests`, make sure you're using the `RequestId` field, not any other field.

  5. **Check if the result exists on the initiating node:**
     The result might only be available on the node that initiated the `keyGenRequest`, or it might be distributed across all participating nodes. Try querying from the node that made the original request.

  6. **Wait a moment and retry:**
     If the key generation just completed, there might be a brief delay before the result is stored. Wait a few seconds and try again.

  7. **Request appears in success list but result not available:**
     If `listKeyGenRequests?filter=success` shows the request but `getKeyGenResultById` returns "mongo: no documents in result", this indicates:
     - The request was marked as successful, but the result storage may have failed
     - Check application logs for errors during result storage: `docker-compose logs app | grep -i "keygen\|error"`
     - The result might only be stored on the initiating node - try querying from the node that made the original `keyGenRequest`
     - There may have been an error during the MPC key generation process that prevented result storage
     - Try querying from all participating nodes - results are stored locally on each node

**Response (secp256k1 key example):**
```json
{
  "code": 0,
  "error": "",
  "data": {
    "requestid": "KeyGen20241228123456789abc123",
    "pubkeyhex": "033d741c45434993c6b994eb0b28debe18234188505425f827680a5d2ce82cb7509ea0bec0b652ba4a533d331631c5165e3e1415e378a39c942f0975c8e7d0bf",
    "ethereumaddress": "0x1234567890abcdef1234567890abcdef12345678",
    "keylist": ["node1_key", "node2_key", "node3_key"],
    "groupid": "f2f594b92389c386cac08f0b26e42e79faf09f1a8735785cce0b5f54cc5aa72a",
    "keytype": "secp256k1",
    "threshold": 2,
    "msgcheck": "multi-agree",
    "clientkeys": {
      "node1_key": "0x1234567890abcdef...",
      "node2_key": "0xabcdef1234567890...",
      "node3_key": "0xfedcba0987654321..."
    },
    "siglist": {...},
    "timepoint": "2024-12-28T12:34:56Z"
  }
}
```

**Response (ed25519 key example):**
```json
{
  "code": 0,
  "error": "",
  "data": {
    "requestid": "KeyGen20241228123456789abc123",
    "pubkeyhex": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    "solanaaddress": "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
    "sorobanaddress": "GABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUV",
    "nearaddress": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    "tonaddress": "EQDk8tR7Qv8R5v8R5v8R5v8R5v8R5v8R5v8R5v8R5v8R5v8R",
    "keylist": ["node1_key", "node2_key", "node3_key"],
    "groupid": "f2f594b92389c386cac08f0b26e42e79faf09f1a8735785cce0b5f54cc5aa72a",
    "keytype": "ed25519",
    "threshold": 2,
    "msgcheck": "multi-agree",
    "clientkeys": {
      "node1_key": "0x1234567890abcdef...",
      "node2_key": "0xabcdef1234567890...",
      "node3_key": "0xfedcba0987654321..."
    },
    "siglist": {...},
    "timepoint": "2024-12-28T12:34:56Z"
  }
}
```

**Field Descriptions:**
- `pubkeyhex`: The MPC signer public key
  - For `secp256k1`: 128 hex characters (uncompressed format: x || y, 64 bytes)
  - For `ed25519`: 64 hex characters (serialized public key, 32 bytes)
- `ethereumaddress`: The Ethereum address (42 characters: "0x" + 40 hex chars) derived from `pubkeyhex`. Only present for `secp256k1` keys. This is the address that can be used on Ethereum-compatible chains.
- `solanaaddress`: The Solana address (base58-encoded string) derived from `pubkeyhex`. Only present for `ed25519` keys. This is the address that can be used on Solana blockchain.
- `sorobanaddress`: The Soroban/Stellar address (strkey format, base32-encoded, starts with "G") derived from `pubkeyhex`. Only present for `ed25519` keys. This is the address that can be used on Stellar and Soroban smart contract platform.
- `nearaddress`: The NEAR implicit account address (64 hex characters) derived from `pubkeyhex`. Only present for `ed25519` keys. This is the implicit account ID that can be used on NEAR blockchain.
- `tonaddress`: The TON wallet address (base64url-encoded) derived from `pubkeyhex`. Only present for `ed25519` keys. This is the wallet address that can be used on TON (The Open Network) blockchain. Note: This is a simplified wallet v4 format.
- `clientkeys`: Map of node public keys to their client public keys (used for signature verification in signing requests)
- `keylist`: List of node public keys that participated in key generation
- `groupid`: The group ID this key belongs to
- `keytype`: Key type (e.g., "secp256k1", "ed25519")
- `threshold`: Threshold value used for this key
- `msgcheck`: Message check type (e.g., "multi-agree")
- `siglist`: Signatures from all participating nodes
- `timepoint`: Timestamp when key generation completed

**Note:** 
- The `pubkeyhex` field contains the MPC signer public key. The format depends on the key type:
  - `secp256k1`: 128 hex characters (x || y format)
  - `ed25519`: 64 hex characters (serialized 32-byte public key)
- The `ethereumaddress` field is automatically derived from `pubkeyhex` for `secp256k1` keys and represents the Ethereum address (40 hex characters after "0x" prefix) that corresponds to this MPC public key.
- The `solanaaddress` field is automatically derived from `pubkeyhex` for `ed25519` keys and represents the Solana address (base58-encoded) that corresponds to this MPC public key.
- The `sorobanaddress` field is automatically derived from `pubkeyhex` for `ed25519` keys and represents the Soroban/Stellar address (strkey format, base32-encoded with CRC16-XModem checksum, starts with "G") that corresponds to this MPC public key.
- The `nearaddress` field is automatically derived from `pubkeyhex` for `ed25519` keys and represents the NEAR implicit account address (64 hex characters, same as pubkeyhex) that corresponds to this MPC public key.
- The `tonaddress` field is automatically derived from `pubkeyhex` for `ed25519` keys and represents the TON wallet address (base64url-encoded with CRC16-CCITT checksum, wallet v4 format) that corresponds to this MPC public key. Note: This is a simplified implementation. Full TON address derivation requires the complete wallet contract code.
- The `clientkeys` map contains the client public keys for each node (these are the `clientPk` values provided during key generation).

### 7. Pre-Signing

#### `POST /presignRequest`
Creates a new pre-signing request. **Requires management key authentication.**

**Request Body:**
```json
{
  "nonce": 1,
  "sig": "...",
  "pubKey": "...",
  "keyList": ["..."],
  "presignAmt": 5
}
```

#### `GET /listPresignRequests`
Lists all pre-signing requests.

#### `GET /getPresignRequestById`
Gets a specific pre-signing request by ID.

#### `POST /presignRequestAgree`
Agrees to a pre-signing request. **Requires management key authentication.**

#### `GET /listPresignResults`
Lists all pre-signing results.

#### `GET /getPresignResultById`
Gets a specific pre-signing result by ID.

#### `GET /getPresigningStatus`
Returns presigning status including configuration and cache levels for all key groups.

### 8. Signing

#### `POST /signRequest`
Creates a new signing request. **Requires relayer authentication.**

**Request Body:**
```json
{
  "clientSig": "...",
  "keyList": ["..."],
  "presignId": "...",
  "pubKey": "...",
  "msgHash": "...",
  "msgRaw": "...",
  "relayerPublicKey": "...",
  "relayerSignature": "...",
  "chainID": "...",
  "sourceTxHash": "...",
  "sourceChainID": "..."
}
```

**Authentication:**
- Requires `relayerPublicKey` and `relayerSignature`
- Relayer must be whitelisted and active
- If `chainID` is provided, relayer must have access to that chain
- Supports pre-signing verification if enabled

#### `GET /listSignRequests`
Lists all signing requests with filtering.

#### `GET /getSignRequestById`
Gets a specific signing request by ID.

#### `POST /signRequestAgree`
Agrees to a signing request.

#### `GET /getSignResultById`
Gets a specific signing result by ID.

**Query Parameters:**
- `id` (required): Sign request ID

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": {
    "requestid": "Sign202512301234567890abcdef",
    "pubkey": "public_key_hex",
    "keytype": "secp256k1",
    "signatureformat": "ieee-p1363",
    "signaturehex": "r_component_hex + s_component_hex",
    "ethereumsignature": "r_component_hex + s_component_hex + recovery_byte_hex",
    "sigr": "r_component_hex (64 hex chars)",
    "sigs": "s_component_hex (64 hex chars)",
    "sigrecover": "recovery_byte_hex (for secp256k1)",
    "messagehash": "message_hash_hex",
    "sigdata": {
      "signature": "full_signature_bytes_base64",
      "r": "r_component_bytes_base64",
      "s": "s_component_bytes_base64",
      "m": "message_hash_bytes_base64"
    },
    "timepoint": "2025-12-30 12:34:56.789"
  }
}
```

**Response Fields:**
- `keytype`: The key type used for this signature (`"secp256k1"` or `"ed25519"`)
- `signatureformat`: The signature format (`"ieee-p1363"` for secp256k1, `"ed25519"` for ed25519)
- `signaturehex`: Hex-encoded full signature (convenience field)
  - For `secp256k1`: `r || s` (64 bytes = 128 hex chars)
  - For `ed25519`: `R || S` (64 bytes = 128 hex chars)
- `ethereumsignature`: Ethereum-compatible signature format `r || s || v` (65 bytes = 130 hex chars, only for secp256k1)
- `sigr`: Hex-encoded R component (64 hex chars)
- `sigs`: Hex-encoded S component (64 hex chars)
- `sigrecover`: Recovery byte for secp256k1 (used for Ethereum signature recovery)

**Blockchain-Specific Usage:**

**Ethereum (secp256k1):**
```javascript
// Use ethereumsignature field (r || s || v format)
const ethereumSig = response.data.ethereumsignature;
// Or construct manually:
const ethereumSig = response.data.sigr + response.data.sigs + response.data.sigrecover;
```

**Solana (ed25519):**
```javascript
// Use signaturehex field (R || S format, 128 hex chars)
const solanaSig = response.data.signaturehex;
// Or use sigdata.signature (base64) and convert to hex if needed
const sigBytes = Buffer.from(response.data.sigdata.signature, 'base64');
const solanaSig = sigBytes.toString('hex');
```

**Stellar/Soroban (ed25519):**
```javascript
// Use signaturehex field (R || S format, 128 hex chars)
const stellarSig = response.data.signaturehex;
```

**NEAR (ed25519):**
```javascript
// Use signaturehex field (R || S format, 128 hex chars)
const nearSig = response.data.signaturehex;
```

**TON (ed25519):**
```javascript
// Use signaturehex field (R || S format, 128 hex chars)
const tonSig = response.data.signaturehex;
// TON may require base64 encoding:
const tonSigBase64 = Buffer.from(response.data.signaturehex, 'hex').toString('base64');
```

**Message Hash Requirements:**

Different blockchains require different message hash formats:

- **Ethereum**: Keccak256 hash of the transaction or message (32 bytes)
- **Solana**: SHA256 hash of the serialized transaction (32 bytes)
- **Stellar/Soroban**: SHA256 hash of the transaction envelope (32 bytes)
- **NEAR**: SHA256 hash of the transaction (32 bytes)
- **TON**: SHA256 hash of the cell (32 bytes)

The `messagehash` field in the response contains the hash that was signed. Ensure you provide the correct hash format for your target blockchain when calling `/signRequest`.

### 9. Relayer Management

All relayer management endpoints are under the `/admin/` prefix.

#### `POST /admin/registerRelayer`
Registers a new relayer in the whitelist.

**Request Body:**
```json
{
  "relayerPublicKey": "...",
  "relayerName": "...",
  "allowedChains": ["..."],
  "registeredBy": "...",
  "metadata": {}
}
```

#### `GET /admin/listRelayers`
Lists all whitelisted relayers.

#### `GET /admin/getRelayer`
Gets a specific relayer by public key.

**Query Parameters:**
- `publicKey` (required): Relayer public key

(*Removed*: activateRelayer, deactivateRelayer, updateRelayerChains, deleteRelayer. Relayer control is managed by the relayer itself; node runners only register once and the relayer updates its own keys.)
Deletes a relayer from the whitelist.

#### `POST /updateRelayer`
Updates relayer public keys (self-managed, requires signature from existing key).

## Node Key Management

### Overview

The Distributed Auth system uses three types of keys:

1. **Node Public Key** (`nodeKey`): Unique identifier for each MPC node (128 hex characters)
2. **Node Management Key** (`NodeMgtKey`): Ethereum address format (0x followed by 40 hex characters) used for API authentication
3. **Client Public Key** (`clientPk`): Client authentication key used during key generation and signing operations

### Getting Node Keys

#### `GET /getNodeKey`
Retrieves the node's unique public key (node ID). This is the key used to identify the node in MPC groups.

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": "033d741c45434993c6b994eb0b28debe18234188505425f827680a5d2ce82cb7509ea0bec0b652ba4a533d331631c5165e3e1415e378a39c942f0975c8e7d0bf"
}
```

**Usage:**
- Use this key in `keyList` when creating groups via `/newGroupRequest`
- Each node has a unique public key generated on first startup
- The key is stored in the node's database and persists across restarts

#### `GET /getConfiguredNodeKeys`
Queries all node addresses configured in `MPCGroups` and returns their public keys. Useful for checking node availability before creating groups.

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": {
    "nodes": {
      "http://82.180.145.77:8080": {
        "address": "http://82.180.145.77:8080",
        "available": true,
        "publicKey": "033d741c45434993c6b994eb0b28debe18234188505425f827680a5d2ce82cb7509ea0bec0b652ba4a533d331631c5165e3e1415e378a39c942f0975c8e7d0bf"
      },
      "http://173.249.31.47:8080": {
        "address": "http://173.249.31.47:8080",
        "available": true,
        "publicKey": "7a5781dc05f06ad0e5c192a6762598ab5db53b6339b3faa63180cc5a68ea9f2eccd34e9b9c004c3fe855f0a81561db85fc4cd9149bbd321dc64ee2b5de54c742"
      }
    },
    "total": 2,
    "available": 2,
    "unavailable": 0
  }
}
```

### Getting Management Keys

#### `GET /getNodeMgtKey`
Retrieves the node's management key (Ethereum address format).

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": "0x1234567890ABCDEF1234567890ABCDEF12345678"
}
```

**Usage:**
- This is the key configured in `configs.yaml` as `NodeMgtKey`
- Used to sign management API requests (group creation, key generation, etc.)
- Must be an Ethereum address format (0x followed by 40 hex characters)

#### `GET /getNodeMgtKeyNonce`
Retrieves the current nonce for the node management key. The nonce increments with each signed request.

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": {
    "Key": "0x1234567890ABCDEF1234567890ABCDEF12345678",
    "Nonce": 5
  }
}
```

**Usage:**
- Always fetch the current nonce before signing a management API request
- The nonce must match the expected value (increments sequentially)
- If nonce is out of sync, the request will be rejected

### Generating Client Keys

#### `GET /generateClientKey`
Generates a new client key pair for dApps. **Note:** The node does not save this key - you must store it securely.

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": {
    "PublicKey": "0xabcdef1234567890...",
    "PrivateKey": "0x1234567890abcdef..."  // Keep this secret!
  }
}
```

**Usage:**
- Use the `PublicKey` as `clientPk` in `/keyGenRequest` and `/keyGenRequestAgree`
- Store the `PrivateKey` securely - you'll need it to sign signing requests later
- Each node can have a different `clientPk` for the same key generation

## Using Keys in API Requests

### Management Key Signatures

Endpoints marked with "**Requires management key authentication**" require:

1. **Get the management key:**
   ```bash
   curl -X GET 'http://node-ip:8080/getNodeMgtKey'
   ```

2. **Get the current nonce:**
   ```bash
   curl -X GET 'http://node-ip:8080/getNodeMgtKeyNonce'
   ```

3. **Create the request payload** (without the `sig` field):
   ```json
   {
     "keyList": ["node1_key", "node2_key", "node3_key"],
     "BrokerArray": ["ssl://82.180.145.77:8883"],
     "nonce": 5
   }
   ```

4. **Sign the payload** using the management key's private key:
   - Convert the JSON payload to a string (without the `sig` field)
   - Sign it using Ethereum's `eth_sign` or equivalent method
   - The signature should be a hex string (0x prefix optional)

   **Example using web3.js:**
   ```javascript
   const Web3 = require('web3');
   const web3 = new Web3();
   
   // Create payload without sig field
   const payload = {
     "keyList": ["node1_key", "node2_key", "node3_key"],
     "BrokerArray": ["ssl://82.180.145.77:8883"],
     "nonce": 5
   };
   
   // Convert to JSON string (must match exactly, no extra spaces)
   const payloadString = JSON.stringify(payload);
   
   // Sign using management key's private key
   const privateKey = '0x...'; // Your management key's private key
   const signature = web3.eth.accounts.sign(payloadString, privateKey).signature;
   
   // Add signature to payload
   payload.sig = signature;
   ```

   **Example using ethers.js:**
   ```javascript
   const { ethers } = require('ethers');
   
   // Create payload without sig field
   const payload = {
     "keyList": ["node1_key", "node2_key", "node3_key"],
     "BrokerArray": ["ssl://82.180.145.77:8883"],
     "nonce": 5
   };
   
   // Convert to JSON string (must match exactly, no extra spaces)
   const payloadString = JSON.stringify(payload);
   
   // Create wallet from private key
   const privateKey = '0x...'; // Your management key's private key
   const wallet = new ethers.Wallet(privateKey);
   
   // Sign the message
   const signature = await wallet.signMessage(payloadString);
   
   // Add signature to payload
   payload.sig = signature;
   ```

   **Example using Python (web3.py):**
   ```python
   from web3 import Web3
   import json
   
   # Create payload without sig field
   payload = {
       "keyList": ["node1_key", "node2_key", "node3_key"],
       "BrokerArray": ["ssl://82.180.145.77:8883"],
       "nonce": 5
   }
   
   # Convert to JSON string (must match exactly, no extra spaces)
   payload_string = json.dumps(payload, separators=(',', ':'))
   
   # Sign using management key's private key
   private_key = '0x...'  # Your management key's private key
   account = Web3().eth.account.from_key(private_key)
   
   # Sign the message (web3.py uses eth_sign message format)
   message_hash = Web3().keccak(text=f"\x19Ethereum Signed Message:\n{len(payload_string)}{payload_string}")
   signature = account.signHash(message_hash)
   
   # Add signature to payload
   payload['sig'] = signature.signature.hex()
   ```

   **Important Notes:**
   - The JSON string must be **exactly** as it appears in the request (no extra whitespace, same key order)
   - Use `JSON.stringify()` with no formatting (or `json.dumps()` with `separators=(',', ':')` in Python)
   - The signature format should match Ethereum's `eth_sign` standard
   - Some libraries may require the message to be prefixed with `\x19Ethereum Signed Message:\n<length><message>`

5. **Add the signature** to the request:
   ```json
   {
     "keyList": ["node1_key", "node2_key", "node3_key"],
     "BrokerArray": ["ssl://82.180.145.77:8883"],
     "nonce": 5,
     "sig": "0x1234567890abcdef..."
   }
   ```

**Example: Creating a Group Request**

```bash
# Step 1: Get management key
MGT_KEY=$(curl -s -X GET 'http://82.180.145.77:8080/getNodeMgtKey' | jq -r '.Data')

# Step 2: Get current nonce
NONCE=$(curl -s -X GET 'http://82.180.145.77:8080/getNodeMgtKeyNonce' | jq -r '.Data.Nonce')

# Step 3: Get node keys
NODE1_KEY=$(curl -s -X GET 'http://82.180.145.77:8080/getNodeKey' | jq -r '.Data')
NODE2_KEY=$(curl -s -X GET 'http://173.249.31.47:8080/getNodeKey' | jq -r '.Data')
NODE3_KEY=$(curl -s -X GET 'http://207.180.248.107:8080/getNodeKey' | jq -r '.Data')

# Step 4: Create payload (without sig)
PAYLOAD='{"keyList":["'$NODE1_KEY'","'$NODE2_KEY'","'$NODE3_KEY'"],"BrokerArray":["ssl://82.180.145.77:8883"],"nonce":'$NONCE'}'

# Step 5: Sign the payload (using your management key's private key)
# This requires a tool like web3.js, ethers.js, or a custom signing tool
SIG=$(sign_message "$PAYLOAD" "$MGT_KEY_PRIVATE_KEY")

# Step 6: Add signature to payload
FULL_PAYLOAD=$(echo "$PAYLOAD" | jq --arg sig "$SIG" '. + {sig: $sig}')

# Step 7: Send the request
curl -X POST 'http://82.180.145.77:8080/newGroupRequest' \
  -H 'Content-Type: application/json' \
  -d "$FULL_PAYLOAD"
```

**Note:** If `IgnoreMgtKeySigCheck: true` in `configs.yaml`, you can use an empty string for `sig`:
```json
{
  "keyList": ["..."],
  "BrokerArray": ["..."],
  "nonce": 0,
  "sig": ""
}
```

### Using Node Keys in Group Creation

When creating a group via `/newGroupRequest`, you need to collect all node public keys:

**Method 1: Manual Collection**
```bash
# Query each node individually
NODE1_KEY=$(curl -s 'http://82.180.145.77:8080/getNodeKey' | jq -r '.Data')
NODE2_KEY=$(curl -s 'http://173.249.31.47:8080/getNodeKey' | jq -r '.Data')
NODE3_KEY=$(curl -s 'http://207.180.248.107:8080/getNodeKey' | jq -r '.Data')

# Use in newGroupRequest
curl -X POST 'http://82.180.145.77:8080/newGroupRequest' \
  -H 'Content-Type: application/json' \
  -d '{
    "keyList": ["'$NODE1_KEY'", "'$NODE2_KEY'", "'$NODE3_KEY'"],
    "BrokerArray": ["ssl://82.180.145.77:8883"],
    "nonce": 0,
    "sig": ""
  }'
```

**Method 2: Using getConfiguredNodeKeys**
```bash
# Get all configured node keys at once
curl -s 'http://82.180.145.77:8080/getConfiguredNodeKeys' | jq '.Data.nodes'

# Extract keys from response
NODE1_KEY=$(curl -s 'http://82.180.145.77:8080/getConfiguredNodeKeys' | \
  jq -r '.Data.nodes["http://82.180.145.77:8080"].publicKey')
```

### Using Client Keys in Key Generation

When generating keys, each node provides its own `clientPk`:

**Step 1: Generate client key (optional - can use placeholder if `IgnoreClientSigCheck: true`)**
```bash
# Generate a client key pair
CLIENT_KEY=$(curl -s 'http://82.180.145.77:8080/generateClientKey' | jq -r '.Data')
CLIENT_PK=$(echo "$CLIENT_KEY" | jq -r '.PublicKey')
CLIENT_PRIVATE=$(echo "$CLIENT_KEY" | jq -r '.PrivateKey')  # Store securely!
```

**Step 2: Use in keyGenRequest**
```bash
curl -X POST 'http://82.180.145.77:8080/keyGenRequest' \
  -H 'Content-Type: application/json' \
  -d '{
    "groupId": "f2f594b92389c386cac08f0b26e42e79faf09f1a8735785cce0b5f54cc5aa72a",
    "threshold": 2,
    "clientPk": "'$CLIENT_PK'",
    "keyType": "secp256k1",
    "msgCheck": "multi-agree",
    "nonce": 0,
    "sig": ""
  }'
```

**Step 3: Each node agrees with its own clientPk**
```bash
# Node 1
curl -X POST 'http://82.180.145.77:8080/keyGenRequestAgree' \
  -H 'Content-Type: application/json' \
  -d '{
    "requestId": "KeyGen20241228123456789abc123",
    "clientPk": "'$NODE1_CLIENT_PK'",
    "nonce": 0,
    "sig": ""
  }'

# Node 2
curl -X POST 'http://173.249.31.47:8080/keyGenRequestAgree' \
  -H 'Content-Type: application/json' \
  -d '{
    "requestId": "KeyGen20241228123456789abc123",
    "clientPk": "'$NODE2_CLIENT_PK'",
    "nonce": 0,
    "sig": ""
  }'
```

**Note:** The `clientPk` is stored in `KeyGenResult.ClientKeys` map and used later to verify signatures in signing requests.

## Authentication

### Management Key Authentication

Endpoints marked with "**Requires management key authentication**" require:
1. A valid `NodeMgtKey` signature
2. A valid nonce (obtained via `/getNodeMgtKeyNonce`)
3. The signature must be over the request body (excluding the `sig` field)

**Signature Process:**
1. Get management key: `GET /getNodeMgtKey`
2. Get current nonce: `GET /getNodeMgtKeyNonce`
3. Create request payload (JSON string, without `sig` field)
4. Sign the payload using the management key's private key (Ethereum signature)
5. Add the signature to the request as the `sig` field

**Note:** Can be disabled for testing via `IgnoreMgtKeySigCheck: true` in config (NOT recommended for production). When disabled, use empty string `""` for `sig`.

### Relayer Authentication

Signing requests require:
1. `relayerPublicKey` and `relayerSignature` in the request
2. Relayer must be registered and active
3. Signature verification over the request data
4. Chain access control (if `chainID` is provided)

### Client Signature Authentication

For MPC operations (keygen, signing), client signatures are verified using the client key saved during key generation:
- The `clientPk` provided during `keyGenRequest` is stored in `KeyGenResult.ClientKeys`
- When signing requests are made, the client must sign using the private key corresponding to the `clientPk`
- The system verifies the signature using the stored `clientPk` from the key generation result

**Note:** Can be disabled for testing via `IgnoreClientSigCheck: true` in config (NOT recommended for production).

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
- **Location:** Configurable via `LogPath` in `configs.yaml` (default: `logs/DistributedAuth.log`)
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
   - Reads current log file: `logs/DistributedAuth.log`
   - Reads rotated files: `logs/DistributedAuth.log.1`, `logs/DistributedAuth.log.2`, etc.
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
LogPath: "logs/DistributedAuth.log"

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
   - Add metrics endpoint
   - Add health check endpoint
   - Add performance monitoring

4. **Security:**
   - Add rate limiting
   - Add request size limits
   - Add IP whitelisting options

## See Also

- `API_docs.md` - Usage examples and workflows
- `README.md` - General project documentation
- `docs/swagger.yaml` - Complete API specification
- `node/managementapi.go` - API implementation source code

