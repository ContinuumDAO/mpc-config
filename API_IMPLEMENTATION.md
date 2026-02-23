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

#### `GET /getNodeMgtKey`
Returns the node management key (Ethereum address format). This key is used for authenticating management operations.

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

### 3. Node Tools

#### `GET /generateClientKey`
Generates a new client key pair for dApps. **This is a convenience utility - clients can also generate keys themselves using any ECDSA library (P256 curve, 128 hex character public key format).**

**Important Notes:**
- The node does **not** save this key - you must store it securely yourself
- Client keys are used for signing messages (`ClientSig` in `signRequest`), **not** for signing API requests
- API requests are signed with `NodeMgtKey` (management key), not client keys
- Client keys must be P256 ECDSA keys (same format as node keys)
- Public key format: 128 hex characters (64 bytes: 32 bytes X + 32 bytes Y)
- Private key format: 64 hex characters (32 bytes)

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": {
    "PublicKey": "08caf50811eb4c2bed7b3f8dc9c292b5cf521ba3774ea49dcd949e8235a48b22e8c1f16b356710aae4095e498bfff8385eada1e53a47dbdd984d32ae4d20a5de",
    "PrivateKey": "48b78d7eb09216c99b2401492c78c2e1b39d79dba5e243eae83582f88efb6346"
  }
}
```

**Example:**
```bash
curl "http://localhost:8080/generateClientKey"
```

**Security Warning:** The private key is returned in plaintext. Ensure you're using HTTPS and secure storage. The node does not retain this key.

**Alternative:** You can generate client keys yourself using any ECDSA library (e.g., `ethers.js`, `web3.js`, `crypto` in Node.js, etc.) as long as they use the P256 curve and produce keys in the same format.

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

#### `GET /connectivityHealth`
See [Node Information Endpoints](#1-node-information-endpoints) section above for detailed documentation.

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

#### `GET /listKeyGenRequests`
Lists all key generation requests with filtering and pagination.

**Query Parameters:**
- `filter` (optional): `all`, `pending`, `success` (default: `all`)
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

#### `GET /getKeyGenRequestById`
Gets a specific key generation request by ID.

**Query Parameters:**
- `id` (required): Key generation request ID

**Example:**
```bash
curl "http://localhost:8080/getKeyGenRequestById?id=KeyGen20260111003720999cf104d0f"
```

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

#### `GET /getKeyGenResultById` ⭐
Gets a specific key generation result by ID. Returns the generated public key, addresses, and keyList.

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

#### `GET /listPresignRequests`
Lists all pre-signing requests with filtering and pagination.

**Query Parameters:**
- `filter` (optional): `all`, `pending`, `success` (default: `all`)
- `pagenum` (optional, default: 0)
- `pagesize` (optional, default: 10)

**Example:**
```bash
curl "http://localhost:8080/listPresignRequests?filter=all&pagenum=0&pagesize=10"
```

#### `GET /getPresignRequestById`
Gets a specific pre-signing request by ID.

**Query Parameters:**
- `id` (required): Presign request ID

**Example:**
```bash
curl "http://localhost:8080/getPresignRequestById?id=Presign20260111003720999cf104d0f"
```

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

#### `GET /getPresignResultById`
Gets a specific pre-signing result by ID.

**Query Parameters:**
- `id` (required): Presign request ID

**Example:**
```bash
curl "http://localhost:8080/getPresignResultById?id=Presign20260111003720999cf104d0f"
```

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

#### `POST /multiSignRequest`
Creates a new signing request for **multi-agree keys only**. No relayer authentication; uses the same internal sign flow as `signRequest`. Nodes in the same GroupId must agree via `POST /signRequestAgree`; when enough nodes have agreed, the message in `msgRaw` is signed.

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
  "extraJSON": "{}"
}
```

**Field Descriptions:**
- `clientSig` (required): Client signature over the request (excluding `clientSig`), verified like keyGenRequest
- `keyList` (required): Array of node keys in the same GroupId that may participate; can be empty array `[]` to use keyList from KeyGenResult
- `pubKey` (required): Public key (128 hex characters) from key generation (must be multi-agree key)
- `msgHash` (required): Keccak256 hash of the message to sign
- `msgRaw` (optional): Raw message bytes (hex encoded)
- `destinationChainID` (required): Destination chain ID for the signed message (EVM signatures only; stored and returned in `listSignRequests` / `getSignRequestById` so the node key knows which chain the signature is destined for)
- `destinationAddress` (optional): Destination address (EVM signatures only; stored and returned in `listSignRequests` / `getSignRequestById`)
- `extraJSON` (optional): Arbitrary JSON string for node context; used for **Ed25519** key types (not secp256k1). Stored and returned in `listSignRequests` / `getSignRequestById`.
- `signatureText` (optional): For EVM/secp256k1, a JSON string with structure `{"signature": "<function signature>", "names": ["<name1>", "<name2>", ...]}` where `signature` is the function selector text (e.g. `transfer(address,uint256)`) and `names` is an array of parameter names in order. Example: `{"signature": "transfer(address,uint256)", "names": ["to", "amount"]}`. Other chains: program name or custom text. Stored and returned in `listSignRequests` / `getSignRequestById`.
- `purpose` (optional): Text from the creator, max 256 characters; visible to nodes considering `signRequestAgree` (stored and returned in list/get endpoints and `getSignResultById`)

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

#### `GET /listSignRequests`
Lists all signing requests with filtering and pagination. Use this (and `getSignRequestById`) to see which node keys have already agreed: **SigList** contains node key → signature for each node that has agreed; any node in **KeyList** that is missing from SigList or has an empty signature can still call `POST /signRequestAgree`.


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
      "Purpose": "Bridge transfer to L2",
      "Thoughts": {},
      "timepoint": "2026-01-11T00:37:20Z"
    }
  ]
}
```

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
- `ExtraJSON`: Arbitrary JSON string passed at request creation (e.g. for node context); stored and returned in listSignRequests; empty if not provided.
- `SignatureText`: For EVM/secp256k1, JSON string `{"signature": "<function signature>", "names": ["<name1>", ...]}` (signature = selector text, names = parameter names in order). Other chains: program name or custom text. Stored and returned in listSignRequests; empty if not provided.
- `RejectedBy`: (multi-agree only) List of node keys that declined to sign; those nodes no longer see this request in `filter=pending`.
- `Purpose`: Optional text from the sign request creator (max 256 chars); visible to nodes considering agree/reject.
- `Thoughts`: Map of node key → optional comment (max 256 chars each) from each node when they called `signRequestAgree` (accept or reject).
- `timepoint`: When the request was recorded

**Example:**
```bash
curl "http://localhost:8080/listSignRequests?filter=all&pagenum=0&pagesize=10"
```

#### `GET /getSignRequestById`
Gets a specific signing request by ID. Optional fields (e.g. `DestinationChainID`, `Purpose`) only appear if this node is running a build that includes them (see note under `listSignRequests`).

**Query Parameters:**
- `id` (required): Sign request ID

**Example:**
```bash
curl "http://localhost:8080/getSignRequestById?id=Sign20260111003720999cf104d0f"
```

#### `POST /signRequestAgree`
Agrees to or rejects a signing request.

- **tx-check (relayer):** Unchanged. Request body is `requestId` + `clientSig`; no `accept` field. Relayer flow is not affected.
- **multi-agree:** Optional `accept` (boolean). Omitted or `true` = agree to sign (same as before). `false` = reject: this node is recorded as having declined; the request **no longer appears in this node's `listSignRequests?filter=pending`**. The client must sign over the same body (including `accept`). Other nodes may still agree; rejection is per-node.

**Request Body:**
- `requestId` (required): Sign request ID
- `clientSig` (required for multi-agree when client sig check enabled): Signature over the request body (including `accept` for multi-agree)
- `accept` (optional, **multi-agree only**): `true` or omitted = agree; `false` = reject (drops from this node's pending list). Ignored for tx-check.
- `thoughts` (optional): Comment from this node when agreeing or rejecting, max 256 characters; stored per node key and returned in list/get and `getSignResultById`.

**Example (multi-agree agree):**
```json
{ "requestId": "Sign20260111003720999cf104d0f", "clientSig": "0x...", "accept": true }
```

**Example (multi-agree reject):**
```json
{ "requestId": "Sign20260111003720999cf104d0f", "clientSig": "0x...", "accept": false }
```

**Response:**
- On agree: `"data": "success to agree signrequest with requestid ..."`
- On reject (multi-agree only): `"data": "success to reject signrequest with requestid ..."`

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
    "Purpose": "Bridge transfer to L2",
    "Thoughts": {}
  }
}
```

**Field Descriptions:**
- `keylist`: Array of node keys that were selected to participate in signing (filtered to only online nodes)
- `participatingkeys`: Array of node keys that actually participated in signing (derived from `SigList`, sorted alphabetically). This is the definitive list of nodes that contributed to the signature.
- `signaturehex`: Full signature as hex string (64 bytes = 128 hex chars for both secp256k1 and ed25519)
- `keytype`: Key type used ("secp256k1" or "ed25519")
- `signatureformat`: Signature format ("ieee-p1363" for secp256k1, "ed25519" for ed25519)
- `DestinationChainID`, `DestinationAddress`, `ExtraJSON`, `RejectedBy`, `Purpose`, `Thoughts`: Same as in the sign request; merged from the latest sign request so the result includes this metadata (see listSignRequests field descriptions).

**Example:**
```bash
curl "http://localhost:8080/getSignResultById?id=Sign20260111003720999cf104d0f"
```

### 9. Relayer Management

All relayer management endpoints are under the `/admin/` prefix.

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

## Quick Reference: All Endpoints

### Node Information
- `GET /version` - Get node version
- `GET /getMachineInfo` - Get machine information (CPU, memory, disk)
- `GET /getNodeKey` - Get node public key (node ID)
- `GET /getNodeMgtKey` - Get node management key
- `GET /getNodeMgtKeyNonce` - Get current management key nonce
- `GET /hasPublicMgtKey` - Returns true if any Ed25519 management key is allowed (config or added via addManagementKey)
- `GET /getPublicMgtKeyNonce` - Get current nonce for an Ed25519 key (optional `?publicKey=` for added keys)
- `POST /addManagementKey` - Add another Ed25519 public key (request must be signed by an existing Ed25519 management key)
- `GET /getAllowedKeyTypes` - Get allowed key types
- `GET /getAllowedMsgCheckTypes` - Get allowed message check types
- `GET /getSuccessRate` - Get success rate statistics
- `GET /getPreSigningVerificationStatus` - Get presigning verification status
- `GET /getClientSigStatus` - Get client signature check status (IgnoreClientSigCheck)
- `GET /getSubscriptions` - Get MQTT subscriptions
- `GET /health` - Get comprehensive health status
- `GET /connectivityHealth` - Get connectivity health for nodes
- `GET /getLogs` - Get log entries
- `GET /getConfiguredNodeKeys` - Get node keys for configured addresses

### Node Registration
- `POST /nodeRegister` - Register node (one-time)
- `GET /fetchNodeData` - Fetch node data by node ID
- `GET /fetchNodeDataByPublicKey` - Fetch node data by public key

### Node Tools
- `GET /generateClientKey` - Generate client key pair (convenience utility)

### Node Ping & Connectivity
- `GET /pingNodesRequest` - Ping nodes to test connectivity
- `GET /getPingNodesResultById` - Get ping results by ID
- `GET /listPingResults` - List all ping results
- `GET /getInactiveNodes` - Get inactive nodes

### Group Management
- `POST /newGroupRequest` - Create new group request (requires mgt key)
- `GET /listNewGroupRequests` - List new group requests
- `GET /getNewGroupRequestById` - Get new group request by ID
- `POST /newGroupRequestAgree` - Agree to new group request (requires mgt key)
- `GET /getNewGroupResultById` - Get new group result by ID

### Key Generation
- `POST /keyGenRequest` - Create key generation request (requires mgt key)
- `GET /listKeyGenRequests` - List key generation requests
- `GET /getKeyGenRequestById` - Get key generation request by ID
- `POST /keyGenRequestAgree` - Agree to key generation request (requires mgt key)
- `GET /getKeyGenResultById` - Get key generation result by ID
- `GET /getKeyGenGroupId` - Get GroupId for a keyGen request
- `GET /getAllGroupIds` - Get all GroupIds with their keyGens

### Pre-Signing
- `POST /presignRequest` - Create presign request (requires mgt key)
- `GET /listPresignRequests` - List presign requests
- `GET /getPresignRequestById` - Get presign request by ID
- `POST /presignRequestAgree` - Agree to presign request (requires mgt key)
- `GET /listPresignResults` - List presign results
- `GET /getPresignResultById` - Get presign result by ID
- `GET /getPresigningStatus` - Get presigning status

### Signing
- `POST /signRequest` - Create sign request (requires relayer auth)
- `GET /listSignRequests` - List sign requests
- `GET /getSignRequestById` - Get sign request by ID
- `POST /signRequestAgree` - Agree to sign request
- `GET /getSignResultById` - Get sign result by ID

### Relayer Management
- `POST /admin/registerRelayer` - Register relayer (one-time per node)
- `GET /admin/listRelayers` - List all relayers
- `GET /admin/getRelayer` - Get relayer by public key
- `POST /updateRelayer` - Update relayer public keys (self-managed)

### Sub-Group (Deprecated)
- `POST /newSubGroupRequest` - Create sub-group request (deprecated)
- `GET /listNewSubGroupRequests` - List sub-group requests (deprecated)
- `POST /newSubGroupRequestAgree` - Agree to sub-group request (deprecated)

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

### 3. Checking System Health

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

### 4. Querying Key Generation Information

```bash
# Get keyGen result
curl "http://localhost:8080/getKeyGenResultById?id=KeyGen20260111003720999cf104d0f"

# Get GroupId for a keyGen
curl "http://localhost:8080/getKeyGenGroupId?id=KeyGen20260111003720999cf104d0f"

# Get all groups and their keyGens
curl "http://localhost:8080/getAllGroupIds"
```

## See Also

- `API_docs.md` - Usage examples and workflows (if present in mpc-auth source repo)
- `MPC_AUTH_README.md` - General mpc-auth project documentation (copied from mpc-auth)
- `docs/swagger.yaml` - Complete API specification
- In mpc-auth source: `node/managementapi.go` - API implementation source code

