# API Implementation Documentation

## Overview

The Distributed Auth Management API provides a RESTful interface for managing MPC (Multi-Party Computation) nodes, key generation, signing operations, and system monitoring. The API is implemented using the Gin web framework and follows a consistent response format.

## Architecture

### Base URL
- Management port: `ManagementAPIsPort` in `configs.yaml` (export as `MANAGEMENT_PORT`)
- Base path: `/`
- Swagger UI: `/swagger/index.html` (if docs are enabled)
- Environment form for automation: `"$MPC_AUTH_URL:$MANAGEMENT_PORT"` where `MPC_AUTH_URL` is host-only (for example `http://127.0.0.1` or `http://<IP>`) and `MANAGEMENT_PORT` is numeric.
- Many curl examples below use `$MPC_AUTH_URL:$MANAGEMENT_PORT` as a placeholder; replace with `"$MPC_AUTH_URL:$MANAGEMENT_PORT"` in real deployments.

<a id="public-discovery-http"></a>
### Public discovery HTTP
If **`PublicDiscoveryPort`** is set in `configs.yaml` (env `PublicDiscoveryPort`) **and** it differs from **`ManagementAPIsPort`**, the node starts an additional HTTP listener on that port with a **minimal** surface (no full management API): **`GET /getNodeMgtKey`**, **`GET /getPublicMgtKey`**, **`GET /getAllowedEd25519MgtKeys`**, **`GET /health`** (no JWT on this listener). This lets operators expose only discovery to the internet (e.g. port **18080**) while keeping **`$MANAGEMENT_PORT`** private. When **`PublicDiscoveryPort`** equals **`ManagementAPIsPort`**, a single listener serves the full API; **`GET /getPublicMgtKey`** is still available on that port.

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
- [`GET /getNodeMgtKeyNonce`](#get-getnodemgtkeynonce) - Next nonce for Ethereum **NodeMgtKey** only (`Data`: `{key, nonce}`)
- [`GET /hasPublicMgtKey`](#get-haspublicmgtkey) - Returns true if any Ed25519 management key is allowed (config or added via addManagementKey)
- [`GET /getAllowedEd25519MgtKeys`](#get-getalloweded25519mgtkeys) - List allowed Ed25519 management keys with labels (bootstrap + added) so the app can show "Which key?" **Also on `PublicDiscoveryPort`** (see [Public discovery HTTP](#public-discovery-http)).
- [`GET /getPublicMgtKey`](#get-getpublicmgtkey) - List allowed Ed25519 public keys (plain `[]string`, 64 hex); same allow-list as above. **Also served on `PublicDiscoveryPort`** (see [Public discovery HTTP](#public-discovery-http)) alongside `GET /getNodeMgtKey`.
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
- [`GET /getGlobalNonceByKeyGenId`](#get-getglobalnoncebykeygenid) - Get globalNonce by keyGen result id
- [`GET /getKeyGenGroupId`](#get-getkeygengroupid) - Get key generation result and GroupId by keyGen ID
- [`GET /getAllGroupIds`](#get-getallgroupids) - Get all GroupIds with their keyGens

### KeyGen Messaging
KeyGen messaging is documented in `./API_KEYGEN_MESSAGING.md`. Response format and conventions follow this document (`./API_IMPLEMENTATION.md`). **sendMessage, markMessageRead, multiMarkMessagesRead, deleteMessage, and multiDeleteMessages require a management key signature** (MetaMask or Ed25519, depending on the client key in the keyGen); see API_KEYGEN_MESSAGING.md for Nonce/Sig and getMessageToSign / getNodeMgtKeyNonce / getAllowedEd25519MgtKeys. For **Open Claw** (or similar), a poll-and-mark-read helper that uses `listMessages` + `multiMarkMessagesRead` is `$MPA_PATH/scripts/keygen_messaging_agent_poll.py`; scheduling and env are described in `../skill/SKILL.md` (**KeyGen inbox poll**). Ed25519 management signing: `./ED25519_MANAGEMENT_KEY_SIGNING.md`.
- `POST /sendMessage` - Send a message (top-level or reply) in a keyGen channel (mgt key required)
- `GET /listMessages` - List messages (with unread, time range, top_level, pagination)
- `GET /getMessageById` - Get a single message by id
- `GET /getMessageThread` - Get a top-level message and its reply tree (nested, max depth 3)
- `POST /markMessageRead` - Mark a message as read (add read receipt) (mgt key required)
- `POST /multiMarkMessagesRead` - Mark multiple messages as read (list of message ids) (mgt key required)
- `POST /deleteMessage` - Delete a message and all its replies (originator only) (mgt key required)
- `POST /multiDeleteMessages` - Delete multiple messages (and their reply trees); originator-only per message; mgt key required

### Maintenance (restart quiescence)
Use these on the **same** `ManagementAPIsPort` listener as the rest of the management API (SSH tunnel forwards that port; **no separate listener**). `POST /maintenance/requestRestartPrep` requires a normal **management key** signature (`VerifyMgtKeySig`, same pattern as `POST /configUpdatePlan`). **`GET /maintenance/restartGate`** is read-only and exempt from JWT on the browser HTTPS / loopback listeners (for polling from scripts). MQTT-driven protocol continuation is **not** covered by the HTTP in-flight counter — see [Restart quiescence (maintenance)](#restart-quiescence-maintenance-detail).
- `POST /maintenance/requestRestartPrep` — enter draining mode so new tracked mutations return `503` until `GET /maintenance/restartGate` reports `readyForProcessExit` (then restart the process from the host/docker).
- `GET /maintenance/restartGate` — returns `draining`, `inFlight`, `readyForProcessExit`, and a hint list of tracked POST paths.
- `POST /updateMpcAuth` — while **draining**, signed request with target **tag** (e.g. `latest`, `v1.1`, or another published tag); node queries **Docker Hub** for **`registryDigest`** (`sha256:…`) for **`MpcAuthDockerRepo`**. Response includes **`previousVersion`** / **`previousVersionDate`** and **`newVersionRequested`**. The API does **not** run Docker on the host; apply the digest with **`mpc-auth-docker-update.sh TAG digest`** (no `/etc/default` edit required for one shot)—see [Host apply (digest)—not the same process as the HTTP API](#post-updatempc-auth-host) and **`systemd/README.md`**.

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

**Signing:** `POST /maintenance/requestRestartPrep` accepts JSON `{"nonce": <int>, "sig": "<hex>"}`. The server verifies **`VerifyMgtKeySig`** over canonical JSON with **`sig` emptied** (same semantics as other management-signed POSTs). Verification uses **`configs.yaml` on disk** when present for **`NodeMgtKey`** and **`IgnoreMgtKeySigCheck`**, matching `POST /configUpdatePlan`.

**Flow:** (1) Sign and `POST /maintenance/requestRestartPrep`. (2) Poll `GET /maintenance/restartGate` until **`readyForProcessExit`** is `true` (`draining` is `true` and **`inFlight`** is `0`). (3) Restart the container or process on the host. Tracked paths include group/subgroup agree flows, keyGen, presign, sign/multiSign and related agrees/triggers/status/shelve, **KeyGen messaging** (`sendMessage`, read/delete variants), and **`configUpdatePlan` / `configUpdateImplement`**.

**MQTT caveat:** In-flight work that continues only over **MQTT** (without a matching management POST on this node) is **not** included in the HTTP ref-count. Pause clients or wait briefly if needed.

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

<a id="endpoint-categories"></a>
## Endpoint Categories

### 1. Node Information Endpoints

<a id="get-version"></a>
#### `GET /version`
Returns the current **application release** version (semver string) and the date it was set for that release.

**Docker tag vs. `data.version`:** Your compose file may pull **`continuumdao/mpc-auth:latest`** (or any other registry tag). That tag only selects **which image** to run. The **`version`** field here is **not** the Docker tag: it is the **mpc-auth build version** compiled into the binary when that image was produced (e.g. **`v1.1`**). So after **`docker compose pull`** and **`docker compose up -d`**, use **`GET /version`** on the management or public discovery port (per your deployment) to read the **semver of the running app**. Official **`latest`** builds should still embed a normal semver in the binary (so operators see **`v1.1`** in **`data.version`** even though the image reference is **`…:latest`**).

Also served on **PublicDiscoveryPort** (e.g. **18080**) when that listener is split from **ManagementAPIsPort**. **Not** registered on **Browser HTTPS** (**8443**); use discovery or management URL (no JWT for this route).

**Response:**
```json
{
  "code": 0,
  "error": "",
  "data": {
    "version": "v1.1",
    "versionDate": "2024-01-15"
  }
}
```

**Field Descriptions:**
- `version`: The current node **application** version string (e.g. **`v1.12`**) — from the running binary, not necessarily the Docker image tag (`latest`, `v1.0`, etc.).
- `versionDate`: The date when this version was set/changed (ISO 8601 date format, e.g., "2024-01-15")

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
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getNodeUptime"
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
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getNodeMgtKey"
```

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

**Ed25519 vs MetaMask:** If you authenticate with an **Ed25519** management key (config `PublicMgtKey` or keys from `addManagementKey`), nonce consumption is tracked under that **64-hex public key**, not under the Ethereum `NodeMgtKey`. In that case **`GET /getNodeMgtKeyNonce` can stay at `0`** even after many Ed25519-signed operations. Use [`GET /getPublicMgtKeyNonce`](#get-getpublicmgtkeynonce) (and `?publicKey=<64_hex>` for added keys) for the nonce that matches your signing key.

**Example:**
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getNodeMgtKeyNonce"
```

**Note:** Always fetch the latest nonce immediately before building the payload to sign; do not manually increment—use the value returned by this endpoint (Ethereum) or by `getPublicMgtKeyNonce` (Ed25519).

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
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/hasPublicMgtKey"
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

**Response (success):** `{ "code": 0, "error": "", "data": null }` — same [`APIResponse`](#response-format) envelope as other management endpoints. There is no extra payload; treat `code === 0` as confirmation. To confirm the new key appears in the allow-list, call [`GET /getAllowedEd25519MgtKeys`](#get-getalloweded25519mgtkeys) or [`GET /getPublicMgtKey`](#get-getpublicmgtkey).

**Response (failure):** `code` non-zero and `error` describes the reason (e.g. invalid or missing signature, nonce mismatch or already used, malformed or duplicate `newPublicKey`, signer not in the allowed set, or no Ed25519 management key configured). HTTP status may be `200` with `code`≠`0`, or `400` / `401` per server; always read `code` and `error` from the JSON body.

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
   curl $MPC_AUTH_URL:$MANAGEMENT_PORT/getNodeMgtKey
   curl $MPC_AUTH_URL:$MANAGEMENT_PORT/getNodeMgtKeyNonce
   ```

2. **Get the message to sign** (optional, but helpful):
   ```bash
   curl -X POST $MPC_AUTH_URL:$MANAGEMENT_PORT/getMessageToSign \
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
   curl -X POST $MPC_AUTH_URL:$MANAGEMENT_PORT/keyGenRequest \
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
  "data": ["secp256k1", "ed25519"]
}
```

**Example:**
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getAllowedKeyTypes"
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
  "baseFeeMultiplier": 200,
  "gasPrice": 25,
  "defaultGetSigFeeSpeed": "normal",
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
- `baseFee` (optional): Default base fee in gwei (EIP-1559). Omit or send `null` to leave unset so the client can refetch (e.g. "Use custom gas config").
- `priorityFee` (optional): Default priority fee in gwei (EIP-1559). Omit or send `null` to leave unset so the client can refetch.
- `baseFeeMultiplier` (optional): EIP-1559 only. Percentage applied to base fee for the base component of `maxFeePerGas` (e.g. 200 = 2× base). Must be ≥ 100 so that `maxFeePerGas ≥ baseFee + maxPriorityFeePerGas`. Omitted or 200 preserves previous default behaviour.
- `gasMultiplier` (optional): Gas multiplier for legacy chains.
- `gasPrice` (optional): Gas price in gwei for legacy chains.
- `defaultGetSigFeeSpeed` (optional): Default fee tier for the Execute tab **Get Sig / Get Sigs** step on this chain: `slow`, `normal`, or `fast` (RPC `eth_feeHistory`–based). Omit on older nodes; clients should treat missing as `normal`. Not used for `advanced` (user-edited gwei).
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
curl -s "$MPC_AUTH_URL:$MANAGEMENT_PORT/getNodeMgtKeyNonce" | jq .data

# 2. Build message (same as signedMessage), sign with MetaMask personal_sign, then:
curl -X POST $MPC_AUTH_URL:$MANAGEMENT_PORT/postChainDetails \
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
curl -s "$MPC_AUTH_URL:$MANAGEMENT_PORT/getNodeMgtKeyNonce" | jq .data

# 2. Build message, sign with MetaMask personal_sign (or Ed25519), then:
curl -X POST $MPC_AUTH_URL:$MANAGEMENT_PORT/removeChainDetails \
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

See `./TOKEN_STORAGE_SCHEMA.md` for the full JSON structure and CTMRWA1 transfer signatures.

### Known Addresses (local node only)

Known addresses are stored on the local node only (not propagated). Each entry is scoped by chain type (e.g. `ethereum`, `solana`) and includes an address, optional `name`, optional `chainIds` (empty = valid on all chains of that type), and `isContract` (false = EOA). See `./KNOWN_ADDRESSES_SCHEMA.md`.

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

See `./KNOWN_ADDRESSES_SCHEMA.md` for the full document shape.

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
4. Each node calls `POST /newGroupRequestAgree` to agree
5. When all nodes agree, group is created and nodes subscribe to the broker
6. Check results via `GET /getNewGroupResultById`

**Persistence:** Each node stores at most one `NewGroup` document per `requestid` (upsert on save, plus a unique index on `requestid` when the database allows it). Duplicate MQTT deliveries of the same `NEWGROUPREQUEST` therefore do not create duplicate rows in `GET /listNewGroupRequests`. The initiator is stored as **`MsgPb.From`** on that document; list/get new-group request APIs return it as **`originator`**.

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
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getNewGroupResultById?id=NewGroup20241228123456789abc123"
```

Query by group_id:
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getNewGroupResultById?group_id=566633a647306335d3ad6ab49829dcfad9abe1f4d1275e4ea3c3f8c292e20ee9"
```

**Note:** Groups can also be pre-configured in `configs.yaml` and will be automatically created on node startup. API-based creation is recommended for new groups to avoid the chicken-and-egg problem.

### 6. Key Generation

<a id="keygen-request-status-values"></a>
**KeyGen request `status` field (stored values):** Each node persists a keygen request document per request id. The JSON field **`status`** on that document can be one of:

| Value | Meaning |
|--------|---------|
| **`pending`** | Waiting for more nodes to complete the agreement: the request exists, but **not every** key in the group’s **`KeyList`** has a non-empty signature in **`SigList`** yet (peers still need to call `keyGenRequestAgree`, or the initiator is still merging partial `KEYGENREQUESTREPLY` updates). New requests are saved with this status. |
| **`agree`** | **All** group nodes have signed the keygen request off-chain. Set when **`KEYGENREQUESTREPLY`** / **`KEYGENREQUESTCONFIRMSUCCESS`** / **`POST /keyGenRequestAgree`** reflects a full **`SigList`**. The keygen **request** row can remain **`agree`** until TSS finishes; **`success`** is written when encrypted **`SaveData`** is stored on the keygen result. |
| **`success`** | TSS completed on this node: the keygen **result** document has non-nil **`savedata`** (encrypted share). The server sets **`status`** to **`success`** on the keygen request when **`UpdateKeyGenResultSaveDataFull`** / **`UpdateEDKeyGenResultSaveDataFull`** completes. |
| **`failed`** | Terminal failure: e.g. TSS/worker error or timeout, expiry of a long-pending request, or fewer than threshold+1 KEYGENRESULT confirmations within the configured window (the keygen **result** may be removed; the **request** row can remain with this status). |

**Initiator (`originator`):** The node that created the keygen request is stored as **`MsgPb.From`** on the keygen request document; **`GET /listKeyGenRequests`** and **`GET /getKeyGenRequestById`** return it as the JSON field **`originator`**.

**API “effective” status** (for **`GET /getKeyGenRequestById`**, **`GET /listKeyGenRequests`**, **`GET /getKeyGenResultById`**): if the stored request status is **`agree`** but this node’s keygen **result** row already has **`savedata`**, responses return **`status`** **`success`** (so clients see completion even if the request document was not yet updated to **`success`**).

**`GET /listKeyGenRequests` `filter` vs stored / effective status:** `filter=pending` → effective status is not **`agree`**, **`success`**, or **`failed`**; `filter=success` → effective status is **`success`** (TSS complete / **`SaveData`** present); `filter=agree` → **stored** status is **`agree`** and this node’s keygen result has **no** **`savedata`** yet (off-chain agreement done, TSS still in progress); `filter=failed` → stored **`status === "failed"`**.

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

<a id="get-listkeygenrequests"></a>
#### `GET /listKeyGenRequests`
Lists all key generation requests with filtering and pagination.

**Query Parameters:**
- `filter` (optional): `all`, `pending`, `success`, `failed`, `agree`, `originator` (default: `all`). For keygen: **`success`** = TSS complete (effective status includes **`SaveData`**); **`agree`** = stored **`agree`** with no **`savedata`** on the result yet; **`failed`** = failed keygen.
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
- `SigList`: Map of node public key (128 hex) to signature (hex) for nodes that agreed
- `Threshold`: Signing threshold (number of nodes required to sign is threshold + 1)
- `timepoint`: Timestamp when the request was recorded (with optional fractional seconds)
- `originator`: Node public key (128 hex characters) of the node that created the keygen **request**—the same value as **`MsgPb.From`** on the stored **`KEYGENREQUEST`** document. Omitted when empty.

**Example:**
```bash
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
    "timepoint": "2026-01-11T00:37:20.999Z",
    "globalnonce": 0,
    "status": "agree"
  }
}
```

**Note:** The `keylist` field contains all node keys that participated in key generation. **globalnonce** is the number of sign results created for this keyGen (secp256k1); it is also available via `GET /getGlobalNonceByKeyGenId`. If it's `null` in the database, the endpoint will attempt to populate it from the group configuration.

**`status`:** Same **effective** lifecycle as the keygen request (see [KeyGen request `status` field (stored values)](#keygen-request-status-values)): not stored on the keygen result row; if the request is still **`agree`** but this node has **`savedata`**, responses return **`success`**. Omitted if the request record cannot be loaded.

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
    "globalnonce": 5
  }
}
```

For keyGen results that are not secp256k1 (e.g. ed25519), the endpoint returns `globalnonce: 0` and optionally `keytype`.

**Example:**
```bash
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getGlobalNonceByKeyGenId?id=KeyGen20260111003720999cf104d0f"
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
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getKeyGenGroupId?id=KeyGen20260111003720999cf104d0f"
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
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/getAllGroupIds"
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

**Single vs batch:** For a **single** message, send `msgHash` (required) and optional `msgRaw`. For a **batch** of N messages (e.g. a sequence of transactions), send `messageHashes` (array of N hex strings, length ≥ 2) and optionally `messageRawBatch` (length 0 or N); do not send `msgHash`/`msgRaw` for batch. One agree and one trigger then produce one SignResult whose `batchSignatures` array holds the N signatures (see `GET /getSignResultById`).

**Client signature (`clientSig`), `signedMessage`, and `purpose` in the signed payload:**

The node verifies `clientSig` using the **KeyGen `ClientKeys`** entry for this node (and/or **PublicMgtKey** / **NodeMgtKey** where applicable), with the same key-type rules as mpc-auth (`VerifyMultiSignRequestPostSigFlex` and management-key paths).

- **`purpose` in JSON:** The `purpose` field is **always present** in the Go request struct’s JSON encoding: `encoding/json` emits **`"purpose"`** even when the value is `""`. Any **`messageToSign` / compact JSON** you build for **`signedMessage`** (compose helpers, agents) **must include the `purpose` key** (string, possibly empty). Omitting `purpose` from the bytes you sign will not match what the node verifies. This aligns with the stored **Purpose** map (creator node key → text, including empty text).
- **P256 (128-hex client key in ClientKeys):** The signed payload uses **deterministic JSON** (sorted object keys), with `clientSig` cleared; it **includes `"purpose"`** (possibly `"purpose":""`).
- **Ed25519 (64-hex client key):** If **`signedMessage`** is non-empty, verification uses that exact UTF-8 string. If **`signedMessage`** is **omitted or empty** and the node verifies via **PublicMgtKey** (or the ClientKeys Ed25519 path with canonical JSON), the node uses **`json.Marshal`** of the POST body with **`clientSig` and `signedMessage` set to empty strings** — that canonical string **always contains `"purpose"`**. Compose flows should either include `purpose` in `messageToSign` or match the node’s canonical marshal.
- **Ethereum address (MetaMask / `NodeMgtKey`):** **`signedMessage` is required** (non-empty). It must be the exact string passed to **`personal_sign`**. That JSON **must include `"purpose"`** (`""` if unused). The node returns **`400`** if `signedMessage` is empty on this path.

**Request Body (single):**
```json
{
  "clientSig": "<client signature over signedMessage (same scheme as keyGenRequest)>",
  "signedMessage": "<exact UTF-8 string signed; same as messageToSign from compose helpers — must include \"purpose\">",
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
- `clientSig` (required): Client signature over the management-auth message; see **Client signature (`clientSig`), `signedMessage`, and `purpose` in the signed payload** above.
- `signedMessage` (required for **MetaMask** / Ethereum `NodeMgtKey`; optional for some **Ed25519** paths): Exact UTF-8 string that was signed — typically the same compact JSON as the request fields **without** `clientSig` / `signedMessage` (compose helpers expose this as **`messageToSign`**). **Must include the `purpose` key** (string, possibly `""`) so the signed bytes match the node. **MetaMask:** `personal_sign` over `signedMessage`; empty `signedMessage` → **`400`**. **Ed25519 via PublicMgtKey:** if `signedMessage` is empty, the node verifies over **canonical JSON** of the full body (with `clientSig` / `signedMessage` cleared), which always includes `"purpose"`.
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
- `400 Bad Request`: Key not found or key is not multi-agree type; for single, missing `msgHash`; for batch, invalid `messageHashes` (e.g. non-hex or `messageRawBatch` length not 0 or N); MetaMask path with empty `signedMessage`
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
  - `blocked`: Sign requests with status `blocked` (threshold+1 agreements can no longer be reached)
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
- `status`: Sign request lifecycle status: `"live"` (default after creation), `"pending"` (set locally when this node has called `POST /signRequestAgree`; not propagated), `"shelved"` (set by the originator via `POST /shelveSignRequest`), `"blocked"` (set automatically when threshold+1 can no longer be reached), or `"success"` (set when a sign result is created). Omitted or `"live"` until set.
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
Agrees to or rejects a signing request.

- **tx-check (relayer):** Unchanged. Request body is `requestId` + `clientSig`; no `accept` or `thoughts` field. Relayer flow is not affected.
- **multi-agree:** Optional `accept` (boolean). Omitted or `true` = agree to sign (same as before). `false` = reject: this node is recorded as having declined in **RejectedBy**. The client must sign over the same body (including `accept` and `thoughts` when present). Other nodes may still agree; rejection is per-node.

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
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/isSignRequestReadyById?id=Sign20260111003720999cf104d0f"
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
curl "$MPC_AUTH_URL:$MANAGEMENT_PORT/listSignRequestsReady?pagenum=0&pagesize=10"
```

<a id="post-triggersignrequestbyid"></a>
#### `POST /triggerSignRequestById`
**Multi-agree only.** When at least **threshold+1** nodes have accepted (and rejections are excluded), triggers signature generation: sends **SIGNREQUESTCONFIRMSUCCESS** and starts the sign worker(s). For **single** requests, one signature is produced; for **batch** requests, one trigger produces one SignResult with N signatures (retrieved via `GET /getSignResultById` as the `batchSignatures` array). **Only the originator may call this:** the request’s **Purpose** map must have this node’s key as the (originator) key; otherwise the server returns an error. **If the sign request status is `"shelved"`** (set via `POST /shelveSignRequest`), the server returns an error and does not trigger. **Idempotent:** if the request was already triggered, returns success with data `"Already triggered"`. Does not affect tx-check flow. Requires management key signature (MetaMask or Ed25519).

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
**Originator only.** Updates the sign result status so that nodes see it in `GET /getSignResultById` and `GET /listSignResults`. Only the node that created the sign request (originator: node key in **Purpose**) may call. Requires management key signature (MetaMask or Ed25519).

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

For **multi-agree** keys, nodes agree via `POST /signRequestAgree`. Once at least **threshold+1** nodes have agreed, **only the originator** (the node whose key is the key in the Purpose map, i.e. the one that created the request via multiSignRequest) may call `POST /triggerSignRequestById` to trigger signature generation. Use `GET /getSignResultById` to poll for the signature. The originator can then call `POST /updateSignResultStatusById` to set status to `"executed"` (with transaction hash) or `"shelved"` (transaction will not be broadcast); these fields appear in `getSignResultById`. The originator can also call `POST /shelveSignRequest` to set the **sign request** status to `"shelved"` (e.g. to cancel or defer the request before triggering); this status appears in `getSignRequestById` and `listSignRequests` and is propagated to all nodes.

**Batch sign request:** To request N signatures in one go (e.g. a sequence of transactions), call `POST /multiSignRequest` with `messageHashes` (array of N hex hashes) and optionally `messageRawBatch`. One `POST /signRequestAgree` agrees to the entire batch. After trigger, `GET /getSignResultById` returns one result with `batchSignResult: true`, `batchSize: N`, and `batchSignatures` (array of N entries: `messagehash`, `sigr`, `sigs`, `sigrecover`, `signaturehex`, `ethereumsignature`). Use `data.batchSignatures[i]` for the i-th signature and execute transactions in order (e.g. consecutive nonces on EVM).

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
  -d '{"requestId": "Sign20260111003720999cf104d0f", "clientSig": "0x...", "accept": true}'

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

