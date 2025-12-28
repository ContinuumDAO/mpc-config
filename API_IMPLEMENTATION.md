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
  "data": "v1.12"
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
Lists all new group requests with filtering and pagination.

**Query Parameters:**
- `filter` (optional): `all`, `pending`, `success` (default: `all`)
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
  "data": "success to aggree newgrouprequest with requestid NewGroup20241228123456789abc123"
}
```

**Note:** When a node agrees, it registers relay channels for the broker and sends a reply message back to the initiator.

#### `GET /getNewGroupResultById`
Gets a specific group result by ID (after group is successfully created).

**Query Parameters:**
- `id` (required): Request ID from `newGroupRequest` response

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

#### `GET /listKeyGenRequests`
Lists all key generation requests with filtering.

**Query Parameters:**
- `filter` (optional): `all`, `pending`, `success`
- `pagenum` (optional, default: 0)
- `pagesize` (optional, default: 10)

#### `GET /getKeyGenRequestById`
Gets a specific key generation request by ID.

#### `POST /keyGenRequestAgree`
Agrees to a key generation request. **Requires management key authentication.**

#### `GET /getKeyGenResultById`
Gets a specific key generation result by ID.

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

