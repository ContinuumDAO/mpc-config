# Distributed ChainInfo Authentication

Blockchain information (token / assets / chain) distributed authentication toolkit.

## Supported Signature Algorithms

- **ECDSA** (secp256k1) - Bitcoin, Ethereum, and most EVM chains
- **EdDSA** (ed25519) - Solana, Polkadot, and other modern chains
- **Schnorr Signature** - Bitcoin Taproot
- **SR25519** - Substrate/Polkadot
- **StarkCurve** - StarkNet
- **BLS** - Advanced threshold signatures
- And more...

## Key Features

- **Programmable authentication logic** - Flexible message validation
- **Multiple signature algorithms** - Support for various cryptographic schemes
- **TEE secured** - Trusted execution environment support
- **Configurable party weights** - Customizable threshold schemes
- **API-based group management** - Create groups without restarting nodes
- **Automatic presigning** - Background worker maintains presignature cache
- **Pre-signing verification** - Optional transaction validation before signing
- **MQTT TLS support** - Encrypted communication channels
- **Relayer management** - Whitelist and manage signing relayers
- **Node registration** - Decentralized node discovery and management

**Note:** Security verifiable code base from [Multichain FastMPC](https://github.com/anyswap/FastMulThreshold-DSA), [Binance tss-lib](https://github.com/bnb-chain/tss-lib).

---

## Quick Start

### Prerequisites

- **Docker & Docker Compose** (recommended)
- **MongoDB** (must be on localhost - each node uses its own local instance)
- **Mosquitto MQTT Broker** (can be shared or per-group)
- **Python 3 with PyYAML** (required for `process_config.sh` script - for YAML parsing)
- **Sudo/root access** (required on client nodes to create `/mosquitto/config/certs/` directory - see Certificate Setup section)
- **Same username with sudo access on all nodes** (recommended for simplified certificate sharing - see Certificate Setup section)

### Installation

#### 1. Install Docker Compose

```bash
sudo apt update && \
sudo apt-get install docker-compose -y
```

#### 2. Install Python 3 with PyYAML (Required for process_config.sh)

The `process_config.sh` script requires Python 3 with the PyYAML library for YAML configuration parsing:

**Ubuntu/Debian:**
```bash
sudo apt-get update && \
sudo apt-get install python3 python3-pip -y && \
pip3 install pyyaml
```

**CentOS/RHEL:**
```bash
sudo yum install python3 python3-pip -y && \
pip3 install pyyaml
```

**macOS:**
```bash
brew install python3 && \
pip3 install pyyaml
```

**Alternative: Install yq (YAML processor)**

If you prefer not to use Python, you can install `yq` instead:

**Ubuntu/Debian:**
```bash
sudo wget -qO /usr/local/bin/yq https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 && \
sudo chmod +x /usr/local/bin/yq
```

**macOS:**
```bash
brew install yq
```

**Note:** The `process_config.sh` script will use `yq` if available, otherwise it will fall back to Python 3 with PyYAML. If neither is available, some configuration validations will be skipped.

#### 3. MQTT Broker Setup (Per-Group, Default)

**Default Behavior:** Each MPC group uses its own MQTT broker. The broker address is automatically derived from the **first node's IP address** in the group's `nodeAddresses` list.

**How it works:**
- If `mqttBroker` is not specified in the group configuration, the system automatically extracts the host/IP from the first node's address
- The broker address is constructed as `tcp://<first-node-ip>:1883`
- Each node in the group must run mosquitto on port 1883 (or configure a custom broker address)

**Using Docker (Automatic Setup):**

If you're using Docker with `docker-compose.yml`, mosquitto is **automatically configured**:

**Deployment Order (IMPORTANT):**

1. **Deploy the broker node first (first node in the group):**
   ```bash
   cd mpc-auth
   sudo docker-compose up -d --build
   ```
   
   This starts:
   - **mongodb**: Local MongoDB instance (port 27017)
   - **mosquitto**: MQTT broker (ports 8883:8883 for TLS, 9999:1883 for unencrypted, 9001:9001 for websockets)
   - **app**: The mpc-auth node (port 8080)
   
   **Verify mosquitto is running:**
   ```bash
   docker ps | grep mosquitto
   docker logs <mosquitto-container-id>
   ```

2. **Generate TLS certificates (on relay node only):**
   
   The default `mosquitto/config/mosquitto.conf` uses TLS on port 8883. To generate certificates:
   
   ```bash
   cd console
   ./process_config.sh --no-copy-certs
   ```
   
   **On the relay node (first node):**
   - Validates configuration
   - Validates Relayer API connectivity (if PreSigningVerification is enabled)
   - Generates self-signed certificates (if needed)
   - Provides instructions for sharing the CA certificate with client nodes
   - **Note:** Use `--no-copy-certs` flag to skip automatic copying (recommended for decentralized setups)
   
   **On client nodes:**
   - Validates configuration
   - Validates Relayer API connectivity (if PreSigningVerification is enabled)
   - Creates `/mosquitto/config/certs/` directory if it doesn't exist (may require sudo)
   - Validates CA certificate is configured correctly
   - Does NOT generate certificates (only relay node does this)
   
   **Note:** Creating the certificate directory may require sudo/root access. The script will attempt to create it automatically, but if it fails, you'll need to create it manually:
   ```bash
   sudo mkdir -p /mosquitto/config/certs
   sudo chmod 755 /mosquitto/config/certs
   ```
   
   **Note:** If `PreSigningVerification.Enabled` is `true`, the script will test Relayer API connectivity. Ensure `RelayerAPIURL` is configured in `configs.yaml`.
   
   **Self-signed certificates are completely valid for production** - they just need to be shared with all nodes in the group.
   
   **Certificate Sharing (RECOMMENDED: Manual):**
   - The relay node operator shares the CA certificate (`ca.crt`) with each client node operator via secure method
   - Each client node operator manually copies the certificate to their node at `/mosquitto/config/certs/ca.crt`
   - Each client node operator updates their `configs.yaml` with the CA certificate path
   - This avoids requiring SSH passwords or key setup between nodes (better for decentralized setups)

3. **Deploy other nodes in the group:**
   - Once the broker node is running and certificates are distributed, deploy the remaining nodes
   - Run `./process_config.sh` on each client node to validate configuration, Relayer API connectivity (if PreSigningVerification is enabled), and CA certificate setup
   - Nodes will automatically connect to the broker when they join the group

4. **Port configuration (TLS is default):**
   
   The default `docker-compose.yml` is configured for TLS:
   - Port `8883:8883` (TLS encrypted - **default, recommended for production**)
   - Port `9999:1883` (unencrypted - optional, for testing only)
   - Port `9001:9001` (WebSocket)
   
   The default `mosquitto/config/mosquitto.conf` uses TLS on port 8883, so **no changes are needed** - TLS is ready to use after generating certificates.
   
   **Important:** 
   - **Default broker address:** Use `ssl://<first-node-ip>:8883` or `tls://<first-node-ip>:8883` (TLS is the default)
   - If you need unencrypted access for testing, uncomment the unencrypted listener in `mosquitto/config/mosquitto.conf` and use `tcp://<first-node-ip>:1883`

5. **Restart mosquitto after certificate generation:**
   ```bash
   sudo docker-compose restart mosquitto
   ```

**Note:** The mosquitto service in docker-compose runs on the first node (relay node) and serves as the broker for the MPC group. All nodes in the group connect to this broker using the first node's IP address.

**Production Setup:**
- The **first node** in each group runs the MQTT broker (via Docker or directly on the host)
- The broker address is automatically derived as `tcp://<first-node-ip>:1883` (or `ssl://<first-node-ip>:8883` for TLS)
- All other nodes in the group connect to this broker
- This is the default and recommended production setup

**Manual Setup (Non-Docker):**

If you're **not using Docker** and need to install mosquitto directly on the host system:

1. **Install mosquitto:**
   ```bash
   sudo add-apt-repository ppa:mosquitto-dev/mosquitto-ppa && \
   sudo apt update && \
   sudo apt install mosquitto mosquitto-clients -y
   ```

2. **Configure mosquitto:**
   ```bash
   sudo systemctl stop mosquitto
   sudo vim /etc/mosquitto/mosquitto.conf
   ```

   Add the following configuration:

   ```
   listener 1883 0.0.0.0
   allow_anonymous true
   ```

   For TLS support (recommended for production - self-signed certificates are valid):

   ```
   listener 8883 0.0.0.0
   allow_anonymous true
   cafile /mosquitto/config/certs/ca.crt
   certfile /mosquitto/config/certs/server.crt
   keyfile /mosquitto/config/certs/server.key
   ```
   
   **Note:** Self-signed certificates are completely valid for production use. Generate them using `./process_config.sh` and share the CA certificate with all nodes in the group.
   
   **Sharing the CA Certificate (RECOMMENDED: Manual):**
   
   After generating certificates on the first node (relay node), the CA certificate (`ca.crt`) must be shared with all client nodes.
   
   **Simplified Approach: Same Username with Sudo Access (RECOMMENDED)**
   
   If all nodes are created using the same username with sudo access, certificate sharing becomes much simpler:
   
   1. **Create the same user on all nodes:**
      ```bash
      # On each node (Ubuntu/Debian):
      sudo adduser mpcnode  # Replace 'mpcnode' with your desired username
      ```
   
   2. **Grant sudo access to the user:**
      
      **Method A: Add user to sudo group (Ubuntu/Debian - RECOMMENDED):**
      ```bash
      # On each node:
      sudo usermod -aG sudo mpcnode
      ```
      
      **Method B: Edit sudoers file directly (all Linux distributions):**
      ```bash
      # On each node, edit sudoers file:
      sudo visudo
      
      # Add this line at the end of the file (replace 'mpcnode' with your username):
      mpcnode ALL=(ALL:ALL) NOPASSWD: ALL
      
      # Or for password-protected sudo (more secure):
      mpcnode ALL=(ALL:ALL) ALL
      
      # Save and exit (Ctrl+X, then Y, then Enter in nano)
      ```
      
      **Verify sudo access:**
      ```bash
      su - mpcnode
      sudo whoami  # Should output 'root'
      sudo -v      # Should succeed without errors
      ```
      
      **Note:** The `NOPASSWD` option allows sudo without password prompts, which is useful for automated scripts. For production, consider using password-protected sudo or restricting sudo to specific commands.
   
   3. **Configure SSH keys (optional but recommended for automated copying):**
      ```bash
      # On relay node, generate SSH key if you don't have one:
      ssh-keygen -t ed25519 -C "mpc-relay-node"
      
      # Copy public key to each client node:
      ssh-copy-id mpcnode@CLIENT_NODE_IP
      ```
   
   4. **Benefits of this approach:**
      - Certificate directory ownership is consistent across all nodes
      - Automated certificate copying works seamlessly (no ownership issues)
      - No need to change ownership or use sudo for file operations
      - SSH key-based authentication simplifies automated operations
   
   5. **Certificate sharing workflow:**
      ```bash
      # On relay node:
      cd console
      ./process_config.sh  # Without --no-copy-certs for automated copying
      
      # The script will automatically copy certificates to all client nodes
      # using the same username, avoiding ownership and permission issues
      ```
   
   **Alternative: Manual Sharing (for different operators/users)**
   
   If different operators run different nodes with different usernames, manual sharing is recommended:
   
   1. **Relay node operator:**
      - After running `./process_config.sh --no-copy-certs`, locate the CA certificate at `mosquitto/config/certs/ca.crt`
      - Share this file securely with each client node operator (via secure file transfer, encrypted email, secure messaging, etc.)
   
   2. **Each client node operator:**
      - Receives `ca.crt` from the relay node operator
      - **Runs the validation script** (automatically creates the certificate directory):
        ```bash
        cd console
        ./process_config.sh  # Creates /mosquitto/config/certs/ automatically and sets ownership
        ```
        The script will:
        - Create `/mosquitto/config/certs/` directory if it doesn't exist (using sudo if needed)
        - Change ownership to your user so you can copy files without sudo
        - Validate your configuration
        - Provide instructions for copying the certificate
      - Copies the certificate to their node at `/mosquitto/config/certs/ca.crt`:
        ```bash
        # The script sets ownership, so you typically don't need sudo:
        scp relay-node-user@RELAY_NODE_IP:/mosquitto/config/certs/ca.crt /mosquitto/config/certs/ca.crt
        ```
        If the directory wasn't writable and ownership couldn't be changed, use:
        ```bash
        scp relay-node-user@RELAY_NODE_IP:/mosquitto/config/certs/ca.crt /tmp/ca.crt
        sudo mv /tmp/ca.crt /mosquitto/config/certs/ca.crt
        ```
      - Updates their `configs.yaml`:
        ```yaml
        MQTTTLS:
          CAFile: "/mosquitto/config/certs/ca.crt"
        ```
      - Ensures proper file permissions (readable by the application)
   
   **Note:** 
   - If all nodes use the same username with sudo access, automated certificate copying works seamlessly
   - In decentralized setups where different operators run different nodes, manual sharing is typically easier and more secure
   - The `process_config.sh` script will automatically attempt to copy certificates if SSH access is configured (without `--no-copy-certs` flag)

3. **Restart mosquitto:**
   ```bash
   sudo systemctl restart mosquitto
   ```

**Testing mosquitto:**

```bash
# Subscribe to a test topic (TLS - default)
mosquitto_sub -h localhost -p 8883 --cafile /mosquitto/config/certs/ca.crt -t "test/topic"

# Publish a test message (TLS - default)
mosquitto_pub -h localhost -p 8883 --cafile /mosquitto/config/certs/ca.crt -t "test/topic" -m "hello world"

# For unencrypted testing (not recommended):
# mosquitto_sub -h localhost -p 1883 -t "test/topic"
# mosquitto_pub -h localhost -p 1883 -t "test/topic" -m "hello world"
```

**Note:** If you want to use a different broker address (not the first node), you can explicitly specify `mqttBroker` in the group configuration or `BrokerArray` when creating groups via API.

**Optional: Shared Broker (Not Recommended)**

While technically possible, using a shared MQTT broker for all groups is **not recommended** as it reduces decentralization. If you must use a shared broker, explicitly specify the same `BrokerArray` for all groups when creating them.

#### 3. Configure the Node

Edit `console/configs.yaml` with your settings:

**Key Configuration Options:**

- **`NodeMgtKey`**: Ethereum address for API authentication (management endpoints)
- **`IgnoreMgtKeySigCheck`**: Set to `false` in production (enables signature verification)
- **`MongodbUri`**: Leave empty for default (`mongodb://localhost:27017`) or specify custom port
- **`DBName`**: Database name (default: "DistributedAuth" for backwards compatibility; new installs can use e.g. "MPCAuth" or "DA")
- **`ManagementAPIsPort`**: HTTP API server port (default: 8080)
- **`BrokerQos`**: MQTT QoS level (must be 1 or 2 for reliable MPC operations)
- **`MQTTTLS.CAFile`**: Path to CA certificate for TLS broker verification (required for self-signed certs, which are valid for production)
- **`PreSigningVerification`**: Optional transaction verification before signing
  - **Note:** If enabled, requires `RelayerAPIURL` to be configured in `configs.yaml`
  - The `process_config.sh` script will test Relayer API connectivity when `PreSigningVerification.Enabled` is `true`
  - Obtain `RelayerAPIURL` from the DAO
- **`InitiatePreSigning`**: Enable automatic presign request creation (background worker)
- **`PreSigningCacheSize`**: Target number of presignatures to maintain (1-50)
- **`NodePingTimeout`**: Timeout for node availability checks (e.g., "5s", "10s")

**Important:** MongoDB MUST be on localhost (127.0.0.1). Remote connections are not allowed. Each node uses its own local MongoDB instance.

#### 4. Build and Run

```bash
cd mpc-auth && \
sudo docker-compose up -d --build
```

The docker-compose.yml includes:
- **mongodb**: Local MongoDB instance (port 27017)
- **mosquitto**: MQTT broker (automatically configured from `mosquitto/config/mosquitto.conf` - port 8883 for TLS by default)
- **app**: The mpc-auth node (port 8080)

**Production Setup:**
- The **first node** in each group runs mosquitto (via Docker using docker-compose, or directly on the host)
- **Deploy the broker node FIRST** - it must be running before other nodes can join the group
- This broker serves all nodes in the group
- Self-signed certificates (generated by `./process_config.sh`) are valid for production
- The broker address is automatically derived from the first node's IP address

---

## Group Creation

There are **two methods** for creating MPC groups:

### Method 1: API-Based Group Creation (RECOMMENDED)

This solves the chicken-and-egg problem where nodes need keys before they exist.

**Workflow:**

1. **Start all nodes** WITHOUT `keyList` in `configs.yaml` (only provide `nodeAddresses` with placeholder keys)
2. **Query each node's key:**
   ```bash
   GET http://node-ip:8080/getNodeKey
   ```
3. **Create group via API:**
   ```bash
   POST http://first-node:8080/newGroupRequest
   {
     "KeyList": ["node1_pubkey", "node2_pubkey", "node3_pubkey"],
     "BrokerArray": ["ssl://203.0.113.10:8883"],  # Required: use first node's IP with TLS (default per-group broker)
     "Threshold": 2
   }
   ```
   
   **Note:** `BrokerArray` is required. The default and recommended approach is to use the first node's IP address with TLS on port 8883 (e.g., `ssl://<first-node-ip>:8883`). This ensures each group has its own encrypted broker for better decentralization and security.
4. **All nodes agree:**
   ```bash
   POST http://each-node:8080/newGroupRequestAgree
   {
     "requestId": "<request-id>",
     "nonce": 1,
     "sig": "<signature>"
   }
   ```
5. **Group is created** and stored in each node's local database

**Benefits:**
- No need to know node keys before starting nodes
- No need to update configs.yaml after collecting keys
- Groups can be created/updated without restarting nodes
- Completely decentralized (no backend required)

### Method 2: Pre-Configured Groups

For groups where all node keys are known beforehand.

**Workflow:**

1. Generate or collect all node public keys
2. Configure complete `keyList` in all nodes' `configs.yaml` files
3. Start all nodes
4. Nodes automatically join groups on startup

**Important:** All nodes must have the **SAME** `keyList` for the same group.

**Example Configuration:**

```yaml
MPCGroups:
  - keyList:
      - "node1_actual_public_key_128_chars_hex"
      - "node2_actual_public_key_128_chars_hex"
      - "node3_actual_public_key_128_chars_hex"
    nodeAddresses:
      node1_actual_public_key_128_chars_hex: "http://203.0.113.10:8080"
      node2_actual_public_key_128_chars_hex: "http://203.0.113.11:8080"
      node3_actual_public_key_128_chars_hex: "http://203.0.113.12:8080"
    # mqttBroker: ""  # Omit or leave empty to auto-derive from first node (ssl://203.0.113.10:8883 with TLS)
    # Or specify custom broker: mqttBroker: "tcp://custom-broker:1883"
    threshold: 2
```

**Note:** All addresses must use **EXTERNAL (public) IP addresses only**. Private IP ranges are NOT allowed. If nodes are behind NAT, use the public IP address or a public hostname.

---

## MQTT Broker Configuration

### Default Behavior: Per-Group Brokers

**By default, each MPC group uses its own MQTT broker.** The broker address is automatically derived from the first node's IP address in the group's `nodeAddresses` list.

- If `mqttBroker` is not specified → automatically uses `tcp://<first-node-ip>:1883`
- The first node in the group typically runs the mosquitto broker
- Each group is isolated with its own broker for better decentralization

### Broker Address Formats

When creating a group (via API or config), you can specify a custom broker address:

- **Auto-derived (default):** Omit `BrokerArray` or `mqttBroker` → uses first node's IP
- **Unencrypted:** `tcp://203.0.113.10:1883`
- **TLS/SSL:** `ssl://mqtt.example.com:8883` or `tls://mosquitto:8883`
- **Hostname:** `tcp://mqtt-group1.example.com:1883`
- **Multiple brokers (redundancy):** `["tcp://broker1:1883", "tcp://broker2:1883"]`

### TLS Configuration

For TLS-encrypted MQTT brokers:

1. **Broker side** (mosquitto.conf):
   ```
   listener 8883 0.0.0.0
   allow_anonymous true
   cafile /mosquitto/config/certs/ca.crt
   certfile /mosquitto/config/certs/server.crt
   keyfile /mosquitto/config/certs/server.key
   ```

2. **Node side** (configs.yaml):
   ```yaml
   MQTTTLS:
     CAFile: "/mosquitto/config/certs/ca.crt"  # Required for self-signed certs
   ```

   For Let's Encrypt/certbot certificates, leave `CAFile` empty - the system CA store will be used automatically.

### Automatic Subscription

When a node joins a group:
- The node receives the group's `BrokerArray` configuration (or it's auto-derived)
- The node **automatically connects** to that broker
- The node **automatically subscribes** to the group's topics
- **No manual configuration needed** on each node

**Important:** The broker **MUST be deployed and running** before nodes can join the group. Nodes will fail to connect if the broker is not available.

### Deployment Scenarios

**Scenario 1: Default - First node as broker with TLS (RECOMMENDED)**
```
Group with nodes at 203.0.113.10, 203.0.113.11, 203.0.113.12:
  
  Deployment order:
  1. Deploy first node (203.0.113.10) with mosquitto running on port 8883 (TLS)
  2. Generate TLS certificates: ./process_config.sh --no-copy-certs (on relay node - first node)
     - Validates configuration
     - Validates Relayer API connectivity (if PreSigningVerification is enabled)
     - Generates self-signed certificates
     - Provides instructions for sharing the CA certificate
  3. Share CA certificate manually:
     - Relay node operator shares `ca.crt` with each client node operator
     - Each client node operator copies it to `/mosquitto/config/certs/ca.crt` on their node
     - Update each client node's `configs.yaml` with the CA certificate path
  4. Ensure mosquitto is running and accessible on port 8883
  5. Deploy other nodes (203.0.113.11, 203.0.113.12)
  6. Run ./process_config.sh on each client node
     - Validates configuration
     - Validates Relayer API connectivity (if PreSigningVerification is enabled)
     - Validates CA certificate is configured correctly
     - Does NOT generate certificates (only relay node does this)
  7. Create group via API or config - nodes will automatically connect to broker
  
  Configuration:
  - Broker automatically derived: "ssl://203.0.113.10:8883"
  - All nodes connect to first node's broker using TLS
  - No explicit BrokerArray needed (auto-derived)
  - Certificates generated by ./process_config.sh on relay node
```

**Scenario 2: Custom TLS broker address**
```
Group A:
  - Custom TLS broker at 192.168.1.100:8883
  - Explicitly specify: "BrokerArray": ["ssl://192.168.1.100:8883"]

Group B:
  - Custom TLS broker at 192.168.1.200:8883
  - Explicitly specify: "BrokerArray": ["ssl://192.168.1.200:8883"]

A node can be in both groups - it will connect to both brokers automatically
```

**Scenario 3: Unencrypted broker (testing only, not recommended)**
```
Group with unencrypted broker:
  - Broker at mqtt.example.com:1883 (unencrypted)
  - Specify: "BrokerArray": ["tcp://mqtt.example.com:1883"]
  - Only use for testing - TLS is recommended for production
```

---

## API Documentation

The node exposes a comprehensive REST API for management and operations.

### Access API Documentation

- **Swagger UI:** `http://localhost:8080/swagger/index.html`
- **API Base URL:** `http://localhost:8080`
- **Port:** Configurable via `ManagementAPIsPort` in `configs.yaml` (default: 8080)

### Key Endpoints

#### Node Information
- `GET /version` - Node version
- `GET /getNodeKey` - Node's public key (128 hex characters)
- `GET /getNodeMgtKey` - Management key (Ethereum address)
- `GET /getAllowedKeyTypes` - Supported key types
- `GET /getLogs?hours=12` - Retrieve log entries

#### Group Management
- `POST /newGroupRequest` - Create new MPC group (requires management key auth)
- `POST /newGroupRequestAgree` - Agree to group creation
- `GET /listNewGroupRequests` - List pending group requests

#### Key Generation
- `POST /keyGenRequest` - Create key generation request
- `POST /keyGenRequestAgree` - Agree to key generation
- `GET /getKeyGenResultById` - Get key generation result

#### Pre-Signing
- `POST /presignRequest` - Create presign request (automatic if `InitiatePreSigning: true`)
- `GET /getPresigningStatus` - Check presignature cache levels
- `GET /listPresignResults` - List presign results

#### Signing
- `POST /signRequest` - Create signing request (requires relayer authentication)
- `GET /getSignResultById` - Get signing result

#### Relayer Management (Admin)
- `POST /admin/registerRelayer` - Register new relayer
- `GET /admin/listRelayers` - List all relayers

For complete API documentation, see:
- [API_IMPLEMENTATION.md](API_IMPLEMENTATION.md) - Detailed endpoint documentation
- Swagger UI at `/swagger/index.html` when running

---

## Configuration Reference

See `console/configs.yaml` for all available configuration options with detailed comments.

**Key Settings:**

| Setting | Description | Default |
|---------|-------------|---------|
| `NodeMgtKey` | Ethereum address for management API auth | Required |
| `IgnoreMgtKeySigCheck` | Skip signature verification (dev only) | `true` |
| `MongodbUri` | MongoDB connection (localhost only) | `""` (uses default) |
| `DBName` | Database name | `"DistributedAuth"` (new installs can use e.g. "MPCAuth" or "DA") |
| `LogLevel` | Log verbosity (0-7) | `6` (Trace) |
| `ManagementAPIsPort` | HTTP API port | `8080` |
| `BrokerQos` | MQTT QoS level (1 or 2) | `1` |
| `NodePingTimeout` | Node availability check timeout | `"5s"` |
| `InitiatePreSigning` | Enable automatic presigning | `false` |
| `PreSigningCacheSize` | Target presignatures per group | `5` |

---

## Important Notes

### Security

- **Production:** Set `IgnoreMgtKeySigCheck: false` and `IgnoreClientSigCheck: false`
- **Management API:** Requires `NodeMgtKey` signature for sensitive operations
- **Signing API:** Requires relayer authentication (whitelist-based)
- **MQTT TLS:** Recommended for production deployments

### MongoDB

- **MUST be on localhost** - Remote connections are not allowed
- Each node uses its own local MongoDB instance
- Data is stored locally on each node (decentralized)

### MQTT Broker

- **Default:** Each group uses its own broker, typically the first node's IP address
- **For config-based groups:** Broker is automatically derived from the first node's IP if `mqttBroker` is not specified (default: `ssl://<first-node-ip>:8883` with TLS)
- **For API-based groups:** `BrokerArray` is required - use the first node's IP with TLS (e.g., `ssl://<first-node-ip>:8883`)
- Sub-groups inherit broker configuration from parent group
- All nodes in a group must be able to reach the same broker address
- Nodes automatically handle connecting and subscribing
- **Per-group brokers are the default and recommended** - shared brokers are not recommended

### Group Configuration

- All nodes in a group must have the **SAME** `keyList` (for pre-configured groups)
- Node addresses must use **EXTERNAL (public) IPs only** - private IPs are rejected
- Threshold must be strictly less than the number of nodes (threshold < number of nodes)
- Minimum threshold: 1 (requires at least 2 nodes in the group)
- threshold + 1 nodes must agree to perform signing operations

### Pre-Signing

- Automatic presigning maintains a cache of presignatures for faster signing
- Configure `PreSigningCacheSize` and `PreSigningMinThreshold` to control cache behavior
- Pre-signing verification can validate transactions before signing (optional)
  - **Requires `RelayerAPIURL`** to be configured in `configs.yaml`
  - Relayer API connectivity is tested by `process_config.sh` when `PreSigningVerification.Enabled` is `true`
  - Obtain `RelayerAPIURL` from the DAO

---

## Troubleshooting

### Node won't start

- Check MongoDB is running on localhost: `sudo systemctl status mongod`
- Verify mosquitto is accessible:
  - TLS (default): `mosquitto_sub -h localhost -p 8883 --cafile /mosquitto/config/certs/ca.crt -t "test"`
  - Unencrypted: `mosquitto_sub -h localhost -p 1883 -t "test"`
- Check logs: `tail -f logs/MPCAuth.log`

### Group creation fails

- Ensure all nodes have the same `keyList` (for pre-configured groups)
- Verify all node addresses are external/public IPs
- Check broker connectivity from all nodes
- Review node logs for specific error messages

### MQTT connection issues

- Verify broker is accessible: `mosquitto_pub -h <broker-ip> -p <port> -t "test" -m "test"`
- For TLS: Ensure CA certificate path is correct in `configs.yaml`
- Check firewall rules allow MQTT port (1883 for unencrypted, 8883 for TLS)

### API authentication errors

- Verify `NodeMgtKey` matches the signing key
- Check nonce is incremented for each request
- Ensure signature is valid (use `/getNodeMgtKeyNonce` to get current nonce)

### PreSigningVerification API connectivity issues

If `PreSigningVerification.Enabled` is `true` and you're experiencing Relayer API connectivity issues:

- **Verify `RelayerAPIURL`** is correctly configured in `configs.yaml` (obtain from the DAO)
- **Test API connectivity manually:**
  ```bash
  curl -v http://<relayer-api-url>/v1/mpc/chain_info?chain_id=97
  ```
- **Check firewall rules** allow connections to the Relayer API host and port
- **Verify the API endpoint** is accessible from your node's network
- **Run `process_config.sh`** to test Relayer API connectivity automatically:
  ```bash
  cd console
  ./process_config.sh
  ```
  The script will validate Relayer API connectivity when `PreSigningVerification.Enabled` is `true`

---

## Additional Documentation

- [API_IMPLEMENTATION.md](API_IMPLEMENTATION.md) - Complete API reference
- [docs-internal/](docs-internal/) - Internal design documentation
- [how_to_run_ctm_node.md](how_to_run_ctm_node.md) - CTM-specific deployment guide

---

## License

See repository for license information.
# mpc-auth
