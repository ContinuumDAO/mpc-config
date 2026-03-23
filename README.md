# MPC Node Configuration Repository

This repository contains the configuration files and setup scripts needed to deploy and configure MPC (Multi-Party Computation) nodes using the mpc-auth Docker image.

## What's Included

- **`configs.yaml`** - Main node configuration file
- **`configs-original.yaml`** - Pristine copy of the default `configs.yaml` from this repo; use `cp configs-original.yaml configs.yaml` to revert if something goes wrong. **`process_config.sh` copies it to `configs.yaml` automatically** if `configs.yaml` is missing.
- **`process_config.sh`** - Configuration validator and certificate generator
- **`docker-compose.yml`** - Docker Compose configuration for running the node
- **`mosquitto/config/mosquitto.conf`** - MQTT broker configuration
- **`sign-clipboard in tools/`** - Utility to sign Ed25519 messages
- **`webTLS/config/certs`** - certs to allow TLS 1.3 encryption to the browser

## Quick Start

### 1. Create `mpcnode` (with sudo) and clone this repository in its home folder

On each VPS, use a dedicated account **`mpcnode`** with **sudo** (see **Installation §0** for alternative sudo setup, e.g. `visudo`). Then clone the repo **as `mpcnode`** into the home directory (the clone creates `~/mpc-config`):

```bash
# Once per machine, as root or another user with sudo:
sudo adduser mpcnode
sudo usermod -aG sudo mpcnode

# Log in as mpcnode (e.g. ssh mpcnode@<your-vps-ip> or: su - mpcnode)
cd ~
git clone https://github.com/ContinuumDAO/mpc-config.git
cd mpc-config
```

### 2. Configure Your Node

- Choose which Ethereum address you wish to manage your node (in configs.yaml - NodeMgtKey), and/or which ed25519 key (in configs.yaml PublicMgtKey).
One or both of these will be required by process_config.sh (the next step)
- Decide what IPv4 addresses will be included in the Node Addresses in your config. You may need to coordinate with other people to fetch these.
You can see your own IP address using the command hostname -i
You will be asked to enter each IPv4 address in process_config.sh and you and the other nodes in your group must add the same IPs IN THE SAME ORDER 
on each node. this is IMPORTANT. The FIRST node IP address is the RELAY node for your group. The other nodes can be added afterwards manually if required.

### 3. Validate Configuration and Generate Certificates

```bash
./process_config.sh
```

This script will:
- Validate your configuration
- Add your NodeMgtKey and/or your PublicMgtKey
- Add the IPv4 addresses of each node in your group.
- Add the Relayer IP address, so that your wallet can help secure cross-chain transactions, if you wish to.
- Generate TLS certificates for the MQTT broker (on relay node)
- Create certificate directories (on client nodes)
- Provide instructions for certificate sharing
- Configure your node for https TLS 1.3 encryption, so that all data to the MPA app is encrypted **EXCEPT your IP address**, which will be public.

### 4. Deploy with Docker

```bash
docker-compose up -d
```

This starts:
- **MongoDB** - Local database (port 27017)
- **Mosquitto** - MQTT broker (port 8883 for TLS) BUT ONLY on the RELAY node. The other nodes are clients.
- **mpc-auth** - MPC node: HTTP management API on **:8080** (`ManagementAPIsPort`); optional **Browser HTTPS** (TLS 1.3) on a separate port when `BrowserHTTPS` is enabled in `configs.yaml` (browser-facing API with JWT on GET; see comments in `configs.yaml`)

The `docker-compose.yml` pulls the Docker image from the registry: `continuumdao/mpc-auth:v1.0`

**Note:** The default configuration uses version `v1.0`. To use a different version, edit `docker-compose.yml` and change the image tag (e.g., `continuumdao/mpc-auth:v1.1`).

## Documentation

For detailed setup instructions, certificate sharing, group creation, and more, see the full documentation in this README below.

---

# Distributed ChainInfo Authentication - Setup Guide

Blockchain information (token / assets / chain) distributed authentication toolkit.

## Signature Algorithms

- **ECDSA** (secp256k1) - Bitcoin, Ethereum, and most EVM chains
- **EdDSA** (ed25519) - Solana, Polkadot, and other modern chains
- **Schnorr Signature** - Bitcoin Taproot (Coming)
- **SR25519** - Substrate/Polkadot (Coming)
- **StarkCurve** - StarkNet (Coming)
- **BLS** - Advanced threshold signatures
- And more...

## Key Features

- **A Multi-Party Agent wallet** - allows multiple addresses/chains. Suitable to run with AI agents through an API
- **Multiple signature algorithms** - Support for various cryptographic schemes
- **TEE secured** - Trusted execution environment support
- **Configurable party weights** - Customizable threshold schemes
- **API-based group management** - Create groups without restarting nodes
- **Automatic presigning** - Background worker maintains presignature cache
- **Pre-signing verification** - Optional transaction validation before signing
- **MQTT TLS support** - Encrypted communication channels
- **Relayer management** - Whitelist and manage signing relayers
- **Node registration** - Decentralized node discovery and management
- **Self signed certs** for TLS encryption with the browser

**Note:** Security verifiable code base from [Multichain FastMPC](https://github.com/anyswap/FastMulThreshold-DSA), [Binance tss-lib](https://github.com/bnb-chain/tss-lib).

---

## Prerequisites

- **Dedicated OS user `mpcnode` with sudo** (recommended on every VPS; same steps as the [mpc-auth](https://github.com/ContinuumDAO/mpc-auth) repo — see **Installation §0** below)
- **Docker & Docker Compose** (required)
- **Python 3 with ruamel.yaml** (required for `process_config.sh`; on Debian/Ubuntu install **`python3-ruamel.yaml`)
- **Sudo/root access** (may be required on client nodes to create `mosquitto/config/certs/` directory - see Certificate Setup section)
- **Same username with sudo access on all nodes** (recommended for simplified certificate sharing; use **`mpcnode`** on each node if following §0)

### Installation

#### 0. Create the `mpcnode` user and grant sudo (recommended; aligns with mpc-auth)

Run node operations as a dedicated account (default name **`mpcnode`**) with **sudo** on **each** VPS. This matches the **mpc-auth** repository and keeps ownership consistent for Docker, `process_config.sh`, and CA certificate workflows.

**1. Create the user on each node (Ubuntu/Debian):**

```bash
# On each node (Ubuntu/Debian):
sudo adduser mpcnode  # Replace 'mpcnode' with your desired username
```

**2. Grant sudo access to the user**

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

**3. Next steps:** SSH into the VPS as `mpcnode` (`ssh mpcnode@<vps-ip>`) and continue with **§1** (install packages) and **§1.1** (add **`mpcnode`** to the **`docker`** group).

#### 1. Install Docker, Docker Compose, base tools, and Python (Debian / Ubuntu)

On a minimal VPS, install everything in **one** step: Docker engine, Compose, TLS/HTTPS basics, common CLI tools, OpenSSL (certificates), Git, **Python 3** plus **`python3-ruamel.yaml`** (required by `process_config.sh` for reading and writing `configs.yaml` with comments preserved), and `jq`. **Run as root or with `sudo`.** Optionally run `sudo apt upgrade -y` first for security patches.

```bash
sudo apt update && \
sudo apt install -y \
  ca-certificates \
  curl \
  wget \
  git \
  openssl \
  gnupg \
  iptables \
  docker.io \
  docker-compose \
  python3 \
  python3-pip \
  python3-ruamel.yaml \
  jq \
  && sudo systemctl enable --now docker
```

**Notes:**
- **`docker.io`** is the Docker daemon; **`docker-compose`** provides the `docker-compose` command used in this README. If your release has no `docker-compose` package, install **`docker-compose-plugin`** and use **`docker compose`** (with a space) instead of `docker-compose`.
- **`python3-ruamel.yaml`** provides **`ruamel.yaml`**. The script does **not** use PyYAML (`python3-yaml`); Python fallbacks for YAML use **ruamel.yaml** only (read paths prefer **`yq`** when installed).
- **Ubuntu/Debian:** There is no separate Python install step—**§1** is the only `apt install` you need for Python + YAML on Debian/Ubuntu.
- After install, confirm: `docker --version`, `docker-compose --version` or `docker compose version`, `curl --version`, `python3 -c "import ruamel.yaml"`.

#### 1.1. Configure Docker Access on VPS (Required)

If you encounter the error `Couldn't connect to Docker daemon at http+docker://localhost - is it running?` when running `docker-compose up -d`, this is typically a permissions issue on VPS systems.

**Solution: Add your user to the docker group** (use **`mpcnode`** if you followed **§0**)

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
   sudo usermod -aG docker mpcnode
   ```
   If you use a different account than `mpcnode`, replace it (or use `sudo usermod -aG docker $USER` while logged in as that user).

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

#### 2. Python / YAML for `process_config.sh` (non-Debian, or reference)

The `process_config.sh` script uses **`ruamel.yaml`** for reading and writing `configs.yaml` (node addresses, management keys, Relayer URL, Browser HTTPS, ScannerAPIURLs, etc.) so **comments in the prototype file are preserved**. Read paths prefer **`yq`** when installed; Python fallbacks use **ruamel.yaml** only (not PyYAML).

**Ubuntu/Debian:** Install **§1** above—**`python3`**, **`python3-pip`**, and **`python3-ruamel.yaml`** are already included there. Do not duplicate a second `apt install` for Python.

**CentOS/RHEL:**
```bash
sudo yum install python3 python3-pip -y && \
pip3 install ruamel.yaml
```

**macOS:**
```bash
brew install python3 && \
pip3 install ruamel.yaml
```

**Optional: Install yq (YAML processor)**

`yq` speeds up some **read-only** parsing when available (optional; not a substitute for **ruamel.yaml** on writes):

**Ubuntu/Debian:**
```bash
sudo wget -qO /usr/local/bin/yq https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 && \
sudo chmod +x /usr/local/bin/yq
```

**macOS:**
```bash
brew install yq
```

**Note:** **Updating** `configs.yaml` requires **`ruamel.yaml`** (on Debian/Ubuntu: **`python3-ruamel.yaml`** from **Installation §1**). Without it, the script will error when a merge step runs.

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
   - **app**: The mpc-auth node (**127.0.0.1:8080** management, **18080**/**18081**/**8443** per `docker-compose.yml`)
   
   **Verify mosquitto is running:**
   ```bash
   docker ps | grep mosquitto
   docker logs <mosquitto-container-id>
   ```

   **IMPORTANT: Client nodes should NOT run mosquitto.** Only the relay node (first node in the group) runs the MQTT broker. Client nodes connect to the broker on the relay node. See "Client Node Setup" below for instructions on excluding mosquitto.

2. **Generate TLS certificates (on relay node only):**
   
   The default `mosquitto/config/mosquitto.conf` uses TLS on port 8883. To generate certificates:
   
   ```bash
   ./process_config.sh
   ```
   
   **Important:** The script generates certificates in `mosquitto/config/certs/` (relative to your project directory). For Docker deployments, this is the correct location since `docker-compose.yml` mounts `./mosquitto/config` to `/mosquitto/config` in the container.
   
   **On the relay node (first node):**
   - Validates configuration
   - Generates self-signed certificates in `mosquitto/config/certs/` (relative path)
   - Provides instructions for sharing the CA certificate
   - **Note:** By default the script does **not** copy the CA over SSH; use **`--copy-certs`** on the relay if you want automated copying (same SSH user across nodes)
   
   **On client nodes:**
   - Validates configuration
   - Creates certificate directory at `mosquitto/config/certs/` (relative path - same as relay node for Docker compatibility)
   - Validates CA certificate configuration
   - Does NOT generate certificates (only relay node does this)
   - **Note:** The script creates the directory in the relative path `mosquitto/config/certs/` so Docker can mount it correctly

3. **Share CA Certificate with Client Nodes:**
   
   After generating certificates on the first node (relay node), the CA certificate (`ca.crt`) must be shared with all client nodes. **Manual sharing is recommended** as it avoids requiring SSH passwords or key setup between nodes in a decentralized setup.
   
   **Simplified Approach: Same Username with Sudo Access (RECOMMENDED)**
   
   If all nodes are created using the same username with sudo access, certificate sharing becomes much simpler. **If you already completed Installation §0** (`mpcnode` + sudo on each VPS), skip to step **3** below.
   
   1. **Create the same user on all nodes** (skip if §0 is done):
      ```bash
      # On each node (Ubuntu/Debian):
      sudo adduser mpcnode  # Replace 'mpcnode' with your desired username
      ```
   
   2. **Grant sudo access to the user** (skip if §0 is done):
      
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
      ./process_config.sh --copy-certs
      
      # Copies the CA to all client nodes over SSH (requires SSH key access)
      ```
   
   **Alternative: Manual Sharing (for different operators/users)**
   
   If different operators run different nodes with different usernames, manual sharing is recommended:
   
   1. **Relay node operator:**
      - After running `./process_config.sh` (default), locate the CA certificate at `mosquitto/config/certs/ca.crt`
      - Share this file securely with each client node operator (via secure file transfer, encrypted email, secure messaging, etc.)
   
   2. **Each client node operator:**
      - Receives `ca.crt` from the relay node operator
      - **Runs the validation script** (automatically creates the certificate directory):
        ```bash
        ./process_config.sh  # Creates mosquitto/config/certs/ automatically and sets ownership
        ```
        The script will:
        - Create `mosquitto/config/certs/` directory (relative path) if it doesn't exist
        - Change ownership to your user so you can copy files without sudo
        - Validate your configuration
        - Provide instructions for copying the certificate
      - Copies the certificate to their node at `mosquitto/config/certs/ca.crt` (relative path):
        ```bash
        # The script sets ownership, so you typically don't need sudo:
        scp relay-node-user@RELAY_NODE_IP:mosquitto/config/certs/ca.crt mosquitto/config/certs/ca.crt
        # Or if the relay node path is different:
        scp relay-node-user@RELAY_NODE_IP:~/mpc-config/mosquitto/config/certs/ca.crt mosquitto/config/certs/ca.crt
        ```
        If the directory wasn't writable and ownership couldn't be changed, use:
        ```bash
        scp relay-node-user@RELAY_NODE_IP:mosquitto/config/certs/ca.crt /tmp/ca.crt
        mv /tmp/ca.crt mosquitto/config/certs/ca.crt
        ```
      - Updates their `configs.yaml`:
        ```yaml
        MQTTTLS:
          CAFile: "/mosquitto/config/certs/ca.crt"  # Path inside Docker container
        ```
        **Note:** The path in `configs.yaml` is the path inside the Docker container. Docker mounts `mosquitto/config` to `/mosquitto/config` in the container, so the relative path on the host maps to the absolute path in the container.
      - Ensures proper file permissions (readable by the application)
   
   **Note:** 
   - If all nodes use the same username with sudo access, automated certificate copying works seamlessly
   - In decentralized setups where different operators run different nodes, manual sharing is typically easier and more secure
   - The `process_config.sh` script copies the CA over SSH only when you pass **`--copy-certs`** on the relay node

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
   
   **Option A: Use process_config.sh (Recommended)**
   
   On each client node, run the configuration script before starting Docker. It detects that the node is a client (not first in `nodeAddresses`) and configures `docker-compose.yml` accordingly (copies from `docker-compose.client.yml`, which has mosquitto disabled):
   
   ```bash
   cd mpc-config
   ./process_config.sh
   docker-compose up -d
   ```
   
   The script will:
   - Detect this machine as a CLIENT NODE
   - Copy `docker-compose.client.yml` to `docker-compose.yml` (mosquitto service disabled, app does not depend on mosquitto)
   - Validate config and certificate setup
   
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
- **`InitiatePreSigning`**: Enable automatic presign request creation (background worker)
- **`PreSigningCacheSize`**: Target number of presignatures to maintain (1-50)
- **`NodePingTimeout`**: Timeout for node availability checks (e.g., "5s", "10s")

**Important:** MongoDB MUST be on localhost (127.0.0.1). Remote connections are not allowed. Each node uses its own local MongoDB instance.

#### 5. Build and Run

```bash
cd mpc-config && \
docker-compose up -d
```

The docker-compose files include:
- **mongodb**: Local MongoDB instance (port 27017, **127.0.0.1** only)
- **mosquitto**: MQTT broker (automatically configured from `mosquitto/config/mosquitto.conf` - port 8883 for TLS by default)
- **app**: The mpc-auth node — pulls Docker image **`continuumdao/mpc-auth:v1.0`** (rebuild/push when upgrading node code)
  - **`127.0.0.1:8080:8080`** — management API (**localhost on the host** only; use **SSH tunnel** for remote `curl` / Swagger)
  - **`18080`** — public discovery (`PublicDiscoveryPort`): **`GET /getNodeMgtKey`**, **`GET /getPublicMgtKey`**, **`GET /health`**, **`GET /getNodeKey`**, **`GET /getConfiguredNodeKeys`** (no JWT on this port)
  - **`18081`** — scanner/relayer HTTP when **`ScannerRelayerPort`** is set in `configs.yaml` (e.g. **`POST /signRequest`**)
  - **`8443`** — Browser HTTPS (DAO app; JWT on GET per `BrowserHTTPS` in `configs.yaml`)

**Note:** The default configuration uses image tag **`v1.0`**. If you encounter an error that the image is not found, see the Troubleshooting section below.

#### Management API exposure (`ManagementAPIsPort`, default 8080)

**Defaults in this repo**

- **`docker-compose*.yml` publish management as `127.0.0.1:8080:8080`** — the full management API is **not** reachable on the host’s public IP; use **`ssh -L 8080:127.0.0.1:8080 user@node`** (or similar) for remote admin.
- **`process_config.sh` does not add a UFW “allow” rule for the management port** unless you set **`UFW_OPEN_MANAGEMENT_PORT=1`**. Other ports (SSH, Browser HTTPS, PublicDiscovery, ScannerRelayer when configured, MQTT on relay) are still added as before.

**Peer key probes (`GET /getConfiguredNodeKeys`)**

- Probes use **`http://<peer>:<PublicDiscoveryPort>/getNodeKey`** (e.g. **18080**), then **`http://<peer>:<ManagementAPIsPort>/getNodeKey`**. Peers should use the **same** **`PublicDiscoveryPort`** in `configs.yaml`. See **`API_IMPLEMENTATION.md`** in the **mpc-auth** repo.

**Redeploy:** Changing **only** compose port mapping needs **`docker compose up -d --force-recreate app`**. New **mpc-auth** features require a **new image** (build/push **`continuumdao/mpc-auth:…`**) and **`docker compose pull`** or **`--build`**.

**If you intentionally need `http://<node-public-ip>:8080/...` from the internet (not recommended for production)**

1. Change the publish line to **`"8080:8080"`** and use **`UFW_OPEN_MANAGEMENT_PORT=1 ./process_config.sh`** or a **scoped** UFW rule, e.g. `sudo ufw allow from <admin-cidr> to any port 8080 proto tcp`.
2. **Protection** remains **application-layer** (signatures, `NodeMgtKey`, relayer auth).

**Lockdown (this repo’s default)**

- Management is **loopback-only** on the host via **`127.0.0.1:8080:8080`**. Remote **peer** **`getNodeKey`** probes use **18080** (then **8080** if needed), plus **18081** for scanner/relayer as designed — not raw **8080** on the public internet for management.

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
      node1_actual_public_key_128_chars_hex: "http://203.0.113.10:8081"
      node2_actual_public_key_128_chars_hex: "http://203.0.113.11:8081"
      node3_actual_public_key_128_chars_hex: "http://203.0.113.12:8081"
    # mqttBroker: ""  # Omit or leave empty to auto-derive from first node (ssl://203.0.113.10:8883 with TLS)
    # Or specify custom broker: mqttBroker: "tcp://custom-broker:1883"
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

If you see the error `manifest for continuumdao/mpc-auth:v1.0 not found: manifest unknown`:

**This means the Docker image version isn't available in the registry.**

**Solution 1: Use a Different Version (Recommended)**

Check what versions are available and update `docker-compose.yml`:

```bash
# Try pulling a different version
docker pull continuumdao/mpc-auth:v1.1  # Or another version
```

Then update `docker-compose.yml` to use the available version:
```yaml
app:
  image: continuumdao/mpc-auth:v1.1  # Replace with available version
```

**Solution 2: Check Docker Registry Access**

If the image should be available, verify you can access the registry:

```bash
# Test pulling the image directly
docker pull continuumdao/mpc-auth:v1.0

# If it's a private registry, you may need to log in first
docker login
# Or for a specific registry:
# docker login docker.io  # For Docker Hub
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
   ./process_config.sh
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

### Node won't start

- **Check MongoDB** is running on localhost: `docker-compose ps mongodb` (or `systemctl status mongod` if not using Docker).
- **Verify mosquitto** is accessible (relay node only): `docker exec <mosquitto-container> mosquitto_sub -h localhost -p 8883 --cafile /mosquitto/config/certs/ca.crt -t "test"` or check `docker-compose logs mosquitto`.
- **Check app logs:** `docker-compose logs app` or `tail -f data/app/logs/*.log`.

### Group creation fails

- Ensure all nodes have the same `keyList` (for pre-configured groups).
- Verify all node addresses use **external/public IPs** only (no private IPs).
- Check broker connectivity from all nodes (relay node must be reachable on port 8883 for TLS).
- Review node logs for specific error messages.

### MQTT connection issues

- Verify broker is reachable: `mosquitto_pub -h <broker-ip> -p 8883 -t "test" -m "test"` (use `--cafile` for TLS).
- For TLS: ensure `MQTTTLS.CAFile` in `configs.yaml` points to the correct CA certificate.
- Check firewall rules allow MQTT (1883 unencrypted, 8883 TLS).

### API authentication errors

- Verify `NodeMgtKey` in `configs.yaml` matches the key used to sign requests.
- Get current nonce: `GET /getNodeMgtKeyNonce` and use it in the request.
- Ensure the request body is signed correctly (signature over JSON body excluding the `sig` field).

---

## Additional documentation

- **[docs/API_IMPLEMENTATION.md](docs/API_IMPLEMENTATION.md)** – Full API reference (endpoints, request/response formats, Swagger).
- **[docs/AGENT_ED25519_SETUP.md](docs/AGENT_ED25519_SETUP.md)** – Ed25519 agent setup for node management (no MetaMask).

---

## Support

For issues, questions, or contributions, please contact the DAO or refer to the main mpc-auth repository documentation.
