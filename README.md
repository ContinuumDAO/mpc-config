# MPC Node Configuration Repository

This repository contains the configuration files and setup scripts needed to deploy and configure MPC (Multi-Party Computation) nodes using the distributed-auth Docker image.

## What's Included

- **`configs.yaml`** - Main node configuration file
- **`process_config.sh`** - Configuration validator and certificate generator
- **`docker-compose.yml`** - Docker Compose configuration for running the node
- **`mosquitto/config/mosquitto.conf`** - MQTT broker configuration

## Quick Start

### 1. Clone This Repository

```bash
git clone https://github.com/ContinuumDAO/mpc-config.git
cd mpc-config
```

### 2. Configure Your Node

Edit `configs.yaml` with your settings:
- Set `NodeMgtKey` to your Ethereum address
- Configure `MPCGroups` with your node addresses
- Set `PreSigningVerification.RelayerAPIURL` if using pre-signing verification

### 3. Validate Configuration and Generate Certificates

```bash
./process_config.sh
```

This script will:
- Validate your configuration
- Test Relayer API connectivity (if enabled)
- Generate TLS certificates for the MQTT broker (on relay node)
- Create certificate directories (on client nodes)
- Provide instructions for certificate sharing

### 4. Deploy with Docker

```bash
docker-compose up -d
```

This starts:
- **MongoDB** - Local database (port 27017)
- **Mosquitto** - MQTT broker (port 8883 for TLS)
- **distributed-auth** - MPC node (port 8080)

The `docker-compose.yml` pulls the Docker image from the registry: `continuumdao/distributed-auth:v1.12`

**Note:** The default configuration uses version `v1.12`. To use a different version, edit `docker-compose.yml` and change the image tag (e.g., `continuumdao/distributed-auth:v1.13`).

## Documentation

For detailed setup instructions, certificate sharing, group creation, and more, see the full documentation in this README below.

---

# Distributed ChainInfo Authentication - Setup Guide

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

## Prerequisites

- **Docker & Docker Compose** (required)
- **Python 3 with PyYAML** (required for `process_config.sh` script - for YAML parsing)
- **Sudo/root access** (required on client nodes to create `/mosquitto/config/certs/` directory - see Certificate Setup section)
- **Same username with sudo access on all nodes** (recommended for simplified certificate sharing - see Certificate Setup section)

### Installation

#### 1. Install Docker Compose

```bash
sudo apt update && \
sudo apt-get install docker-compose -y
```

#### 1.1. Configure Docker Access on VPS (Required)

If you encounter the error `Couldn't connect to Docker daemon at http+docker://localhost - is it running?` when running `docker-compose up -d`, this is typically a permissions issue on VPS systems.

**Solution: Add your user to the docker group**

1. **Check if Docker is running:**
   ```bash
   sudo systemctl status docker
   ```
   If Docker is not running, start it:
   ```bash
   sudo systemctl start docker
   sudo systemctl enable docker  # Enable auto-start on boot
   ```

2. **Add your user to the docker group:**
   ```bash
   sudo usermod -aG docker $USER
   ```
   Replace `$USER` with your actual username if needed (e.g., `sudo usermod -aG docker mpcnode`).

3. **Apply the group changes:**
   You need to log out and log back in, or start a new session for the group changes to take effect:
   ```bash
   # Option 1: Log out and log back in (recommended)
   exit
   # Then SSH back into your VPS
   
   # Option 2: Use newgrp to activate the docker group in current session
   newgrp docker
   ```

4. **Verify Docker access:**
   ```bash
   docker ps
   ```
   This should work without `sudo`. If you still see permission errors, ensure Docker is running:
   ```bash
   sudo systemctl restart docker
   ```

5. **Test docker-compose:**
   ```bash
   docker-compose --version
   docker-compose up -d
   ```

**Note:** After adding your user to the docker group, you may need to restart your SSH session or run `newgrp docker` for the changes to take effect in your current terminal session.

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

1. **Deploy the broker node first (first node in the group - RELAY NODE ONLY):**
   ```bash
   cd mpc-config
   docker-compose up -d
   ```
   
   This starts:
   - **mongodb**: Local MongoDB instance (port 27017)
   - **mosquitto**: MQTT broker (ports 8883:8883 for TLS, 9999:1883 for unencrypted, 9001:9001 for websockets) - **ONLY ON RELAY NODE**
   - **app**: The distributed-auth node (port 8080)
   
   **Verify mosquitto is running:**
   ```bash
   docker ps | grep mosquitto
   docker logs <mosquitto-container-id>
   ```

   **IMPORTANT: Client nodes should NOT run mosquitto.** Only the relay node (first node in the group) runs the MQTT broker. Client nodes connect to the broker on the relay node. See "Client Node Setup" below for instructions on excluding mosquitto.

2. **Generate TLS certificates (on relay node only):**
   
   The default `mosquitto/config/mosquitto.conf` uses TLS on port 8883. To generate certificates:
   
   ```bash
   ./process_config.sh --no-copy-certs
   ```
   
   **Important:** The script generates certificates in `mosquitto/config/certs/` (relative to your project directory). For Docker deployments, this is the correct location since `docker-compose.yml` mounts `./mosquitto/config` to `/mosquitto/config` in the container.
   
   **On the relay node (first node):**
   - Validates configuration
   - Validates Relayer API connectivity (if PreSigningVerification is enabled)
   - Generates self-signed certificates in `mosquitto/config/certs/` (relative path)
   - Provides instructions for sharing the CA certificate
   
   **On client nodes:**
   - Validates configuration
   - Validates Relayer API connectivity (if PreSigningVerification is enabled)
   - Creates certificate directory (relative path: `mosquitto/config/certs/` for Docker, or `/mosquitto/config/certs/` for host installation)
   - Validates CA certificate configuration
   - Does NOT generate certificates (only relay node does this)

3. **Share CA Certificate with Client Nodes:**
   
   After generating certificates on the first node (relay node), the CA certificate (`ca.crt`) must be shared with all client nodes. **Manual sharing is recommended** as it avoids requiring SSH passwords or key setup between nodes in a decentralized setup.
   
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

4. **Restart mosquitto:**
   ```bash
   docker-compose restart mosquitto
   # Or using docker directly:
   # docker restart <mosquitto-container-name>
   ```
   
   **Verify mosquitto started successfully:**
   ```bash
   docker-compose logs mosquitto
   # Look for "mosquitto version X.X.X starting" and no certificate errors
   ```
   
   If you see certificate errors, see the "Certificate Issues" troubleshooting section below.

5. **Deploy client nodes (nodes 2, 3, etc. - DO NOT run mosquitto):**
   
   **IMPORTANT: Client nodes should NOT run mosquitto.** Only the relay node runs the MQTT broker. Client nodes connect to the broker on the relay node.
   
   **Option A: Comment out mosquitto service (Recommended - Simple)**
   
   On client nodes, edit `docker-compose.yml` and comment out:
   
   1. The entire mosquitto service:
   ```yaml
   # mosquitto:
   #   image: eclipse-mosquitto:2.0
   #   restart: always
   #   command: mosquitto -c /mosquitto/config/mosquitto.conf -v
   #   ports:
   #     - "8883:8883"
   #     - "9001:9001"
   #   volumes:
   #     - ./mosquitto/config:/mosquitto/config
   #     - ./mosquitto/data:/mosquitto/data
   #     - ./mosquitto/log:/mosquitto/log
   #   networks:
   #     - local-network
   #   healthcheck:
   #     test: ["CMD-SHELL", "pgrep mosquitto || exit 1"]
   #     interval: 10s
   #     timeout: 5s
   #     retries: 5
   ```
   
   2. The mosquitto dependency in the app service:
   ```yaml
   app:
     # ... other config
     depends_on:
       mongodb:
         condition: service_healthy
       # mosquitto:  # Comment this out on client nodes
       #   condition: service_started
   ```
   
   Then start services:
   ```bash
   docker-compose up -d
   ```
   
   **Option B: Use docker-compose profiles (Advanced)**
   
   If you want to keep the same docker-compose.yml file for both relay and client nodes, you can use profiles:
   
   1. Update `docker-compose.yml` to add a profile to mosquitto:
   ```yaml
   mosquitto:
     profiles: ["broker"]  # Add this line - mosquitto only starts with --profile broker
     image: eclipse-mosquitto:2.0
     # ... rest of config
   ```
   
   2. Also comment out or remove the mosquitto dependency in the app service (since it won't exist on client nodes):
   ```yaml
   app:
     # ... other config
     depends_on:
       mongodb:
         condition: service_healthy
       # mosquitto:  # Comment out - will be started via profile on relay node only
       #   condition: service_started
   ```
   
   3. On relay node: `docker-compose --profile broker up -d` (starts mosquitto)
   4. On client nodes: `docker-compose up -d` (does NOT start mosquitto)
   
   **Note:** With this approach, the app service on the relay node will start even if mosquitto isn't ready yet (since the dependency is commented out). This is usually fine since the app will retry connecting to the broker.
   
   **Option C: Use separate docker-compose file for client nodes**
   
   Create `docker-compose.client.yml` that excludes mosquitto, then use:
   ```bash
   docker-compose -f docker-compose.client.yml up -d
   ```

**Testing mosquitto:**
```bash
# Subscribe to a test topic (TLS - default)
docker exec <mosquitto-container> mosquitto_sub -h localhost -p 8883 --cafile /mosquitto/config/certs/ca.crt -t "test/topic"

# Publish a test message (TLS - default)
docker exec <mosquitto-container> mosquitto_pub -h localhost -p 8883 --cafile /mosquitto/config/certs/ca.crt -t "test/topic" -m "hello world"
```

**Note:** If you want to use a different broker address (not the first node), you can explicitly specify `mqttBroker` in the group configuration or `BrokerArray` when creating groups via API.

**Optional: Shared Broker (Not Recommended)**

While technically possible, using a shared MQTT broker for all groups is **not recommended** as it reduces decentralization. If you must use a shared broker, explicitly specify the same `BrokerArray` for all groups when creating them.

#### 4. Configure the Node

Edit `configs.yaml` with your settings:

**Key Configuration Options:**

- **`NodeMgtKey`**: Ethereum address for API authentication (management endpoints)
- **`IgnoreMgtKeySigCheck`**: Set to `false` in production (enables signature verification)
- **`MongodbUri`**: Leave empty for default (`mongodb://localhost:27017`) or specify custom port
- **`DBName`**: Database name (default: "DistributedAuth")
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

#### 5. Build and Run

```bash
cd mpc-config && \
docker-compose up -d
```

The docker-compose.yml includes:
- **mongodb**: Local MongoDB instance (port 27017)
- **mosquitto**: MQTT broker (automatically configured from `mosquitto/config/mosquitto.conf` - port 8883 for TLS by default)
- **app**: The distributed-auth node (port 8080) - pulls Docker image `continuumdao/distributed-auth:v1.12` from registry

**Note:** The default configuration uses version `v1.12`. If you encounter an error that the image is not found, see the Troubleshooting section below.

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

---

## Troubleshooting

### Docker Daemon Connection Issues (VPS)

If you see the error `Couldn't connect to Docker daemon at http+docker://localhost - is it running?`:

1. **Check if Docker service is running:**
   ```bash
   sudo systemctl status docker
   ```
   If not running, start it:
   ```bash
   sudo systemctl start docker
   sudo systemctl enable docker
   ```

2. **Verify your user is in the docker group:**
   ```bash
   groups
   ```
   You should see `docker` in the list. If not, add yourself:
   ```bash
   sudo usermod -aG docker $USER
   newgrp docker  # Or log out and back in
   ```

3. **Check Docker socket permissions:**
   ```bash
   ls -la /var/run/docker.sock
   ```
   Should show the docker group has read/write access. If not:
   ```bash
   sudo chmod 666 /var/run/docker.sock
   # Or better: ensure docker group exists and has proper permissions
   sudo groupadd docker 2>/dev/null || true
   sudo usermod -aG docker $USER
   ```

4. **Test Docker access:**
   ```bash
   docker ps
   ```
   Should work without `sudo`. If it still fails, restart Docker:
   ```bash
   sudo systemctl restart docker
   ```

5. **Verify docker-compose:**
   ```bash
   docker-compose --version
   docker-compose up -d
   ```

**Note:** After adding your user to the docker group, you must log out and log back in (or use `newgrp docker`) for the changes to take effect.

### Docker Image Not Found

If you see the error `manifest for continuumdao/distributed-auth:v1.12 not found: manifest unknown`:

**This means the Docker image version isn't available in the registry.**

**Solution 1: Use a Different Version (Recommended)**

Check what versions are available and update `docker-compose.yml`:

```bash
# Try pulling a different version
docker pull continuumdao/distributed-auth:v1.13  # Or another version
```

Then update `docker-compose.yml` to use the available version:
```yaml
app:
  image: continuumdao/distributed-auth:v1.13  # Replace with available version
```

**Solution 2: Check Docker Registry Access**

If the image should be available, verify you can access the registry:

```bash
# Test pulling the image directly
docker pull continuumdao/distributed-auth:v1.12

# If it's a private registry, you may need to log in first
docker login
# Or for a specific registry:
# docker login docker.io  # For Docker Hub
```

**Solution 2: Build Image Locally (Development Only)**

If you're a developer working on the `distributed-auth` codebase and need to test changes, you can build the image locally:

1. **Clone the distributed-auth repository** (if you haven't already):
   ```bash
   cd /home/marcel/Cryptocurrency/Continuum/Code
   git clone <distributed-auth-repo-url> distributed-auth
   ```

2. **Build the Docker image:**
   ```bash
   cd distributed-auth
   docker build -f dockerfile_app -t continuumdao/distributed-auth:latest .
   ```

3. **Verify the image was created:**
   ```bash
   docker images | grep distributed-auth
   ```

4. **Now run docker-compose:**
   ```bash
   cd ../mpc-config
   docker-compose up -d
   ```

**Note:** This is only for development/testing. Production deployments should use published images from the registry.

For detailed build instructions, see `../distributed-auth/docs-internal/DOCKER_IMAGE_BUILD_AND_PUBLISH.md` (if you have access to the distributed-auth repository).

### PreSigningVerification API connectivity issues

If you see errors related to Relayer API connectivity:

1. **Verify the API URL is correct:**
   - Check `PreSigningVerification.RelayerAPIURL` in `configs.yaml`
   - Obtain the correct URL from the DAO
   - Ensure the URL includes the protocol (`http://` or `https://`)

2. **Test connectivity manually:**
   ```bash
   curl http://relayer-api-url:8080/v1/mpc/chain_info?chain_id=97
   ```

3. **Check network connectivity:**
   - Ensure your node can reach the relayer API server
   - Check firewall rules
   - Verify DNS resolution if using hostnames

4. **Verify API endpoint:**
   - The endpoint should be `/v1/mpc/chain_info`
   - It should accept `chain_id` as a query parameter
   - It should return JSON with `chain_config` and `active_rpc` fields

5. **Check logs:**
   ```bash
   docker logs <app-container-name>
   ```

### Certificate Issues

If mosquitto fails to start or nodes can't connect:

1. **Verify certificates exist:**
   ```bash
   ls -la mosquitto/config/certs/
   ```

2. **Check certificate permissions:**
   ```bash
   chmod 644 mosquitto/config/certs/*.crt
   chmod 600 mosquitto/config/certs/*.key
   ```

3. **Validate certificates:**
   ```bash
   openssl x509 -in mosquitto/config/certs/ca.crt -text -noout
   openssl x509 -in mosquitto/config/certs/server.crt -text -noout
   ```

4. **Check mosquitto logs:**
   ```bash
   docker logs <mosquitto-container-name>
   # Or with docker-compose:
   docker-compose logs mosquitto
   ```

#### Mosquitto Container Restarting - Certificate Path Issue

If you see errors like:
```
Error: Unable to load CA certificates. Check cafile "/mosquitto/config/certs/ca.crt".
OpenSSL Error[0]: error:80000002:system library::No such file or directory
```

**This usually means the certificates are in the wrong location.**

**Problem:** Docker Compose mounts `./mosquitto/config` (relative path) to `/mosquitto/config` in the container. If your certificates are in an absolute path like `/mosquitto/config/certs/` on the host, the container won't be able to access them.

**Solution:**

1. **Navigate to your project directory** (where `docker-compose.yml` is located):
   ```bash
   cd ~/mpc-config  # or wherever your docker-compose.yml is
   ```

2. **Check if certificates exist in the relative path:**
   ```bash
   ls -la mosquitto/config/certs/
   ```
   You should see `ca.crt`, `server.crt`, and `server.key`.

3. **If certificates are missing or in the wrong location**, copy them to the correct relative path:
   ```bash
   # Create the directory if it doesn't exist
   mkdir -p mosquitto/config/certs
   
   # If certificates exist elsewhere (e.g., /mosquitto/config/certs/), copy them:
   cp /mosquitto/config/certs/ca.crt mosquitto/config/certs/
   cp /mosquitto/config/certs/server.crt mosquitto/config/certs/
   cp /mosquitto/config/certs/server.key mosquitto/config/certs/
   
   # Or if you need to generate them:
   ./process_config.sh --no-copy-certs
   ```

4. **Verify all three files exist:**
   ```bash
   ls -la mosquitto/config/certs/
   # Should show: ca.crt, server.crt, server.key
   ```

5. **Set correct permissions:**
   ```bash
   chmod 644 mosquitto/config/certs/*.crt
   chmod 600 mosquitto/config/certs/*.key
   ```

6. **Restart the mosquitto container:**
   ```bash
   docker-compose restart mosquitto
   ```

7. **Check logs to verify it started successfully:**
   ```bash
   docker-compose logs mosquitto
   ```

**Important:** The certificates must be in the **relative path** `mosquitto/config/certs/` (relative to where `docker-compose.yml` is located), not in an absolute path like `/mosquitto/config/certs/` on the host filesystem.

#### Mosquitto Error on Client Node - Server Certificate Missing

If you see errors like this on a **client node**:
```
Error: Unable to load server certificate "/mosquitto/config/certs/server.crt". Check certfile.
OpenSSL Error[0]: error:80000002:system library::No such file or directory
```

**This means mosquitto is trying to start on a client node, but it shouldn't.**

**Problem:** Only the relay node (first node in the group) should run mosquitto. Client nodes should NOT run mosquitto - they only connect to the broker on the relay node.

**Solution:**

1. **Stop and remove mosquitto on the client node:**
   ```bash
   docker-compose stop mosquitto
   docker-compose rm -f mosquitto
   ```

2. **Exclude mosquitto from starting** (see "Client Node Setup" section above for detailed instructions):
   
   **Quick fix:** Edit `docker-compose.yml` and comment out the entire `mosquitto:` service section, and also comment out the `mosquitto` dependency in the `app:` service's `depends_on:` section.

3. **Restart services:**
   ```bash
   docker-compose up -d
   ```

4. **Verify mosquitto is NOT running:**
   ```bash
   docker ps | grep mosquitto
   # Should return nothing (no mosquitto container)
   ```

5. **Verify the app service is running:**
   ```bash
   docker ps | grep app
   docker-compose logs app
   # The app should connect to the broker on the relay node
   ```

**Note:** Client nodes only need the `ca.crt` file (for TLS verification when connecting to the broker), but they do NOT need `server.crt` or `server.key` because they don't run a broker.

---

## Support

For issues, questions, or contributions, please contact the DAO or refer to the main distributed-auth repository documentation.
