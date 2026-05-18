# MPC Node Configuration Repository

This repository contains the configuration files and setup scripts needed to deploy and configure MPC (Multi-Party Computation) nodes using the mpc-auth Docker image.

## What's Included

- **`configs.yaml`** - Main node configuration file
- **`configs-original.yaml`** - Pristine copy of the default `configs.yaml` from this repo; use `cp configs-original.yaml configs.yaml` to revert if something goes wrong. **`process_config.sh` copies it to `configs.yaml` automatically** if `configs.yaml` is missing.
- **`process_config.sh`** - Configuration validator and certificate generator; **generates `docker-compose.yml`** (not committed) from **`docker-compose.relay.yml`** (relay / first node) or **`docker-compose.client.yml`** (other nodes)
- **`scripts/provision-node.sh`** - Non-interactive helper for a **fresh** `configs.yaml`: copies `configs-original.yaml`, sets management keys and a two-node **`nodeAddresses`** layout, then runs **`process_config.sh`**. Stable **`nodeKey`** requires **`DeterministicNodeKey: true`** and **`bootstrap_key/ed25519_private.hex`** (**`tools/bootstrap_key_provision.py`**). For reinstalls see **Automated provisioning** pattern **2**.
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

- Choose which Ethereum address you wish to manage your node (in `configs.yaml` — **NodeMgtKey**), and/or which Ed25519 key (in `configs.yaml` — **PublicMgtKey**). At least one must end up valid before **`./process_config.sh`** can finish.
- **Deterministic reinstall:** **`PublicMgtKey`** plus **`DeterministicNodeKey: true`** and **`bootstrap_key/ed25519_private.hex`** (matching seed) make **fresh Mongo** initialise with the **current** mpc-auth deterministic P-256 **`nodeKey`** (derived from bootstrap + **`PublicMgtKey`**). Older installs may still have persisted a **legacy random **`nodeKey`**: backups taken then embed that **`nodeKeyPublic`** (~**`8b78…`** in your envelope), which **does not** match deterministic **`dedbd…`**. Matching **`PublicMgtKey`/seed fixes config only** — it **cannot** magically equal a legacy **`nodeKeyPublic`** in an old backup file unless mpc-auth derives the same curve point (never true across random-vs-deterministic boundaries). Encrypted payloads bound to **`8b78…`** need **Mongo / node state restored from before the switch** or another **mpc-auth**-supported path, not a fresh deterministic init alone.
- Decide what IPv4 addresses will be included in the Node Addresses in your config. You may need to coordinate with other people to fetch these.
You can see your own IP address using the command hostname -i
You will be asked to enter each IPv4 address in process_config.sh and you and the other nodes in your group must add the same IPs IN THE SAME ORDER 
on each node. this is IMPORTANT. The FIRST node IP address is the RELAY node for your group. The other nodes can be added afterwards manually if required.

For a **non-interactive** first-time setup on a VPS (no prompts for keys or `nodeAddresses`), use **`scripts/provision-node.sh`** after cloning—see **Automated provisioning** under step 3.

### 3. Validate Configuration and Generate Certificates

```bash
./process_config.sh
```

This script will:
- Validate your configuration
- Run **`tools/bootstrap_key_provision.py`** on every **`process_config.sh`**: provisions **`bootstrap_key/`** when **`PublicMgtKey`** is empty, **or** when **`PublicMgtKey`** is preset verifies **`bootstrap_key/ed25519_private.hex`** and writes **`DeterministicNodeKey`** (deterministic **`nodeKey`**) — see **Automated provisioning**
- Add the IPv4 addresses of each node in your group.
- Add the Relayer IP address, so that your wallet can help secure cross-chain transactions, if you wish to.
- Generate TLS certificates for the MQTT broker (on relay node)
- Create certificate directories (on client nodes)
- Provide instructions for certificate sharing
- Configure your node for https TLS 1.3 encryption, so that all data to the MPA app is encrypted **EXCEPT your IP address**, which will be public.

### Automated provisioning (`scripts/provision-node.sh`)

Use this when you want **one command** to replace the interactive parts of steps 2–3 (management keys and `nodeAddresses`), for example on a new droplet with cloud-init or SSH as root.

**Deterministic node identity:** With **`DeterministicNodeKey: true`** and **`bootstrap_key/ed25519_private.hex`**, mpc-auth derives **`nodeKey`** from that bootstrap material (paired with **`PublicMgtKey`**). That enables two provisioning patterns:

1. **New install — omit the Ed25519 public key** (e.g. pass only **`--node-mgt-key`**). The script leaves **`PublicMgtKey`** empty in the fresh `configs.yaml`; **`process_config.sh`** runs **`tools/bootstrap_key_provision.py`**, which creates **`bootstrap_key/`**, sets **`PublicMgtKey`** and **`DeterministicNodeKey`**, and aligns mpc-auth. **Back up `bootstrap_key/`** with your other secrets.
2. **Recover / migrate:** pass **`--public-mgt-key`** (**64 hex** or **`ssh-ed25519 …`** line, same as the original node) alongside **`--node-mgt-key`**. Copy **`bootstrap_key/ed25519_private.hex`** into this repo beside **`configs.yaml`** **before** **`sudo ./scripts/provision-node.sh`** (same 32-byte seed **`PublicMgtKey`** was derived from). **`process_config.sh`** runs **`bootstrap_key_provision.py`**, verifies the seed, and sets **`DeterministicNodeKey: true`**. **Python cryptography** must be installed. **Wipe or recreate Mongo**, then bring up mpc-auth so first init loads **`DeterministicNodeKey`** and the bootstrap file. If mpc-auth already started once with stale data, **`process_config.sh` only fixes **`configs.yaml`** — reset the Mongo **volume**/data dir before **`docker compose up`**.

The same PublicMgtKey / bootstrap behavior applies when you run **`./process_config.sh`** interactively: supply an existing Ed25519 public key, or skip it and allow auto-bootstrap when eligible.

**Requirements**

- Run as **root** (e.g. `sudo`).
- **`configs.yaml` must not exist** in the repo root—the script copies **`configs-original.yaml`** to **`configs.yaml`** and refuses to overwrite an existing file.
- **Python 3**, **ruamel.yaml**, and **`cryptography`** (required for **`tools/bootstrap_key_provision.py`** on every provisioning path).
- Provide **at least one** command-line management key: **`--node-mgt-key`** / **`-k`** (Ethereum **`0x` + 40 hex**) and/or **`--public-mgt-key`** (**64 hex** or **`ssh-ed25519 …`** — quote spaces). Omit **`--public-mgt-key`** only when **`--node-mgt-key`** is set (pattern 1 above).

**What it writes**

- Sets **`NodeMgtKey`** / **`PublicMgtKey`** in the new `configs.yaml` (**`PublicMgtKey`** may be filled in later by **`process_config.sh`** when you omit **`--public-mgt-key`**).
- Sets **`MPCGroups[0].nodeAddresses`** to **two** entries in order:
  - **`node1_key`** → `http://<relay-placeholder>:<port>` (default relay placeholder host **`0.0.0.0`**, meaning “real relay IP to be filled later” for `process_config.sh`).
  - **`node2_key`** → `http://<this-host>:<port>` (this machine’s address for the management API URLs).
- Default HTTP port for those URLs is **8081** (matches `process_config.sh`’s `MPC_NODE_HTTP_PORT`). Override with **`--http-port`** or **`PROVISION_HTTP_PORT`**.

With **`0.0.0.0`** first, `process_config.sh` treats the machine as a **client** path for MQTT relay steps until the real relay is the first entry; your app or operators can align full group `nodeAddresses` later.

**Environment and flags**

- **`PROCESS_CONFIG_NONINTERACTIVE`** defaults to **`1`** (set to **`0`** before `sudo -E` if you want `process_config.sh` to prompt where it still can).
- **`SKIP_NODE_ADDRESS_MENU`** defaults to **`1`** when invoked from this script.
- Pass **`RELAYER_API_URL`** if you need a non-default relayer (use **`sudo -E`** so the variable survives `sudo`).
- **`PROVISION_NODE_IP`** — same as **`--ip`** if the host cannot infer the correct public IPv4 (NAT / wrong default route).
- **`PROVISION_RELAY_PLACEHOLDER_HOST`** — override the first peer host (default **`0.0.0.0`**).
- **`--install-systemd`** — forwards **`--install-mpc-auth-systemd`** to `process_config.sh`.
- **`--no-loopback`** — disables browser loopback HTTP (otherwise the script enables loopback for non-TTY runs).
- **`--no-firewall`** — passes **`--no-firewall`** to `process_config.sh`.
- **`--force-browser-https-certs`** — passes **`--force-browser-https-certs`**.

Full options: **`sudo ./scripts/provision-node.sh --help`**.

**Examples**

Ethereum wallet management only (no `--public-mgt-key`), install systemd unit for the Docker stack:

```bash
cd ~/mpc-config   # or your clone path
sudo -E RELAYER_API_URL="http://example:8080" ./scripts/provision-node.sh \
  --node-mgt-key "0xYour40HexCharacters..." \
  --install-systemd
```

Ed25519 management only (64-hex public key):

```bash
sudo ./scripts/provision-node.sh --public-mgt-key "abcdef0123..." 
```

Both keys; set this node’s peer IP explicitly (e.g. public IPv4 behind NAT):

```bash
sudo ./scripts/provision-node.sh \
  --ip "203.0.113.50" \
  -k "0x..." \
  --public-mgt-key "$(cat ~/.ssh/your_mpc_ed25519.pub)"
```

Then continue with **step 4** (`docker compose up -d` / `docker-compose up -d`) as usual.

### 4. Deploy with Docker

After **`./process_config.sh`** finishes—whether you ran it yourself (step 3) or **`scripts/provision-node.sh`** ran it for you—**`docker-compose.yml`** exists in the project directory (copied from the relay or client template). Then:

```bash
docker-compose up -d
```

This starts:
- **MongoDB** - Local database (port 27017)
- **Mosquitto** - MQTT broker (port 8883 for TLS) BUT ONLY on the RELAY node. The other nodes are clients.
- **mpc-auth** - MPC node: HTTP management API on **:8080** (`ManagementAPIsPort`); optional **Browser HTTPS** (TLS 1.3) on a separate port when `BrowserHTTPS` is enabled in `configs.yaml` (browser-facing API with JWT on GET; see comments in `configs.yaml`)

The generated **`docker-compose.yml`** pulls the app image **`continuumdao/mpc-auth:latest`** by default. Set **`MPC_AUTH_COMPOSE_APP_IMAGE`** before running **`./process_config.sh`** to override the registry or tag and pin a concrete image line in the generated compose file.

**Release vs. image tag:** `latest` chooses which container image to run. The **application semver** your node reports ( **`GET /version`** → **`data.version`**, e.g. **`v1.1`**) comes from the mpc-auth binary **built inside that image**, not from the Docker tag string. After upgrading with **`docker compose pull`** / **`docker compose up -d`**, confirm the running release with **`GET /version`** (management or public discovery port, per deployment).

**Note:** The default configuration uses **`latest`** on **`mpc-auth`**. To pin a specific semver tag instead, edit **`docker-compose.relay.yml`** or **`docker-compose.client.yml`** (then run **`./process_config.sh`** again so **`docker-compose.yml`** is regenerated), or edit the generated **`docker-compose.yml`** directly.

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

- **Dedicated OS user `mpcnode` with sudo** (recommended on every VPS; repo — see **Installation §0** below)
- **Docker & Docker Compose** (required)
- **Python 3 with ruamel.yaml** (required for `process_config.sh`; on Debian/Ubuntu install **`python3-ruamel.yaml`)
- **Sudo/root access** (may be required on client nodes to create `mosquitto/config/certs/` directory - see Certificate Setup section)
- **Same username with sudo access on all nodes** (recommended for simplified certificate sharing; use **`mpcnode`** on each node if following §0)

### Installation

#### 0. Create the `mpcnode` user and grant sudo (recommended)

Run node operations as a dedicated account (default name **`mpcnode`**) with **sudo** on **each** VPS. This keeps ownership consistent for Docker, `process_config.sh`, and CA certificate workflows.

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
- **`containerd.io` vs `containerd`:** If `apt` fails with `containerd.io : Conflicts: containerd`, you already have **Docker CE** (from Docker’s apt repo) or a leftover **`containerd.io`** package. **Either** remove the Docker CE stack and then install **`docker.io`** as below, **or** skip **`docker.io`** / **`docker-compose`** in §1 and only install the non-Docker packages—Docker CE already satisfies the prerequisite. To switch to Ubuntu’s packages:  
  `sudo apt remove -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin docker-ce-rootless-extras 2>/dev/null; sudo apt autoremove -y`  
  then re-run the §1 `apt install` line.
- **`docker.io`** is the Docker daemon; **`docker-compose`** provides the `docker-compose` command used in this README. If your release has no `docker-compose` package, try **`docker-compose-plugin`** and **`docker compose`** (with a space). **Default Ubuntu/Debian repos often lack `docker-compose-plugin`** while still shipping old **`docker-compose` 1.25.x** — if **`apt`** cannot find the plugin or Compose errors on **`version: '3.8'`**, see **Troubleshooting → Compose file version unsupported** (install Compose V2 from Docker’s repo or as a CLI plugin binary).
- **`python3-ruamel.yaml`** provides **`ruamel.yaml`**. The script does **not** use PyYAML (`python3-yaml`); Python fallbacks for YAML use **ruamel.yaml** only (read paths prefer **`yq`** when installed).
- **Ubuntu/Debian:** There is no separate Python install step—**§1** is the only `apt install` you need for Python + YAML on Debian/Ubuntu.
- After install, confirm: `docker --version`, `docker-compose --version` or `docker compose version`, `curl --version`, `python3 -c "import ruamel.yaml"`.

**Docker Compose v2 (Ubuntu / Debian only):** Host **`systemd`** scripts for mpc-auth use **`docker compose`** when the plugin is installed; legacy **`docker-compose` 1.29.x** often fails on current engines (**`KeyError: 'ContainerConfig'`**). From your **mpc-config** clone on the VPS:

```bash
cd /path/to/mpc-config    # e.g. ~/mpc-config
sudo ./scripts/docker-V2_debian_ubuntu.sh
```

Optional flags / overrides (see also **`./scripts/docker-V2_debian_ubuntu.sh --help`**):

```bash
sudo ./scripts/docker-V2_debian_ubuntu.sh --force-repo   # rewrite Docker apt entries, then install plugin
sudo ./scripts/docker-V2_debian_ubuntu.sh --verbose       # trace steps; full diagnostic if compose v2 still missing

# If suite detection is wrong for your derivative:
sudo DOCKER_V2_REPO=ubuntu DOCKER_V2_CODENAME=jammy ./scripts/docker-V2_debian_ubuntu.sh
```

Then confirm: `docker compose version`. Non-Debian systems are rejected with a clear message; manual install paths are in **`internal/DOCKER_COMPOSE_V2_UPGRADE.md`**.

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

If you're using Docker with the **generated** `docker-compose.yml` (from `process_config.sh`), mosquitto is **automatically configured**:

**Deployment Order (IMPORTANT):**

1. **Deploy the broker node first (first node in the group - RELAY NODE ONLY):**
   ```bash
   cd mpc-config
   docker-compose up -d
   ```
   
   This starts:
   - **mongodb**: Local MongoDB instance (port 27017)
   - **mosquitto**: MQTT broker (ports 8883:8883 for TLS, 9999:1883 for unencrypted, 9001:9001 for websockets) - **ONLY ON RELAY NODE**
   - **app**: The mpc-auth node (**127.0.0.1:8080** management, **18080**/**18081**/**8443** per the compose templates / generated file)
   
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
   
   **Important:** The script generates certificates in `mosquitto/config/certs/` (relative to your project directory). For Docker deployments, this is the correct location since the generated **`docker-compose.yml`** mounts `./mosquitto/config` to `/mosquitto/config` in the container.
   
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
   
   On each client node, run the configuration script before starting Docker. It detects that the node is a client (not first in `nodeAddresses`) and **writes `docker-compose.yml`** accordingly (copies from `docker-compose.client.yml`, which has mosquitto disabled):
   
   ```bash
   cd mpc-config
   ./process_config.sh
   docker-compose up -d
   ```
   
   The script will:
   - Detect this machine as a CLIENT NODE
   - Generate **`docker-compose.yml`** from **`docker-compose.client.yml`** (mosquitto service disabled, app does not depend on mosquitto)
   - Validate config and certificate setup
   
   **Option B: Use docker-compose profiles (Advanced)**
   
   If you want to keep the same **`docker-compose.yml`** for both relay and client nodes, you can use profiles (edit **`docker-compose.relay.yml`** before running **`process_config.sh`**, or edit the generated compose file if you do not rely on regeneration):
   
   1. Add a profile to mosquitto:
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
   
   **Option C: Use the client template file directly**
   
   This repo already includes **`docker-compose.client.yml`** (no mosquitto). Either run **`./process_config.sh`** (recommended) to generate **`docker-compose.yml`**, or:
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
- **`MongodbUri`**: Leave empty for defaults (`mongodb://localhost:27017` on host, `mongodb://mongodb:27017` in Docker). For **MongoDB authentication** (recommended), use **`.env`** at the repo root with **`MongodbUri=…`** matching **`DBName`** (default **DistributedAuth**), plus **`MONGO_*`** variables (**`.env.example`**); **`MongodbUri` in the container environment overrides this YAML field when non-empty**.
- **`DBName`**: Database name (default: "DistributedAuth")
- **`ManagementAPIsPort`**: HTTP API server port (default: 8080)
- **`BrokerQos`**: MQTT QoS level (must be 1 or 2 for reliable MPC operations)
- **`MQTTTLS.CAFile`**: Path to CA certificate for TLS broker verification (required for self-signed certs, which are valid for production)
- **`InitiatePreSigning`**: Enable automatic presign request creation (background worker)
- **`PreSigningCacheSize`**: Target number of presignatures to maintain (1-50)
- **`NodePingTimeout`**: Timeout for node availability checks (e.g., "5s", "10s")

**Important:** MongoDB MUST be on localhost (127.0.0.1). Remote connections are not allowed. Each node uses its own local MongoDB instance.

**MongoDB authentication (recommended):** Copy **`.env.example`** to **`.env`** by hand, **or** run **`process_config.sh`** from the compose directory: if **`.env`** is missing and **`docker-compose.relay.yml`** or **`docker-compose.client.yml`** lives next to **`configs.yaml`**, the script copies **`.env.example` → `.env`** (even when Mongo passwords are not set — legacy **no-auth** template). Export **`MONGO_INITDB_ROOT_PASSWORD`** and **`MONGO_APP_PASSWORD`** (and optional **`MONGO_*` / `MongodbUri`**) so **`process_config.sh`** also merges those keys into **`.env`** (and builds **`MongodbUri`** if unset). If **`.env`** already exists, use **`PROCESS_CONFIG_MERGE_DOTENV_FROM_ENV=1`** for that merge, or edit **`.env`** yourself. On a **new** install with an **empty** **`./data/mongodb`**, the stock **`mongo:6.0`** image creates a **MongoDB admin** account **only if both** **`MONGO_INITDB_ROOT_USERNAME`** and **`MONGO_INITDB_ROOT_PASSWORD`** are set (example username **`mongoRoot`** — not the Linux superuser); omit **both** for legacy **no-auth** volumes. **`mongodb/docker-entrypoint-initdb.d/01-mpc-auth-app-user.sh`** creates an application **`readWrite`** user on **`MONGO_APP_DATABASE`** when root and app passwords are set. **Existing** data directories that were created **without** auth need a one-time manual migration (create users, enable auth, then set **`.env`**) or a fresh volume—do not set **`MongodbUri`** with credentials until Mongo accepts them.

**Host loopback hardening:** After **`process_config.sh`** applies UFW (not with **`--no-firewall`**), it patches **`/etc/ufw/after.rules`** so **non-root OS users** cannot open TCP to **`127.0.0.1:27017`** (Compose publish). This pairs with auth: **root** can still use **`mongosh`** on the host; the **app** container uses **`mongodb:27017`** on the bridge and is unaffected. Disable with **`APPLY_LOOPBACK_MONGO_OWNER_FW=0`**. Details: **`docs/internal/PROCESS_CONFIG_FIREWALL.md`**.

**`.env` permissions:** The file must be **readable and writable only by its owner** (mode **`0600`**, e.g. **`chmod u=rw,go= .env`**). **`process_config.sh`** sets **`0600`** when it creates or merges **`.env`**; after a manual **`cp .env.example .env`**, run **`chmod`** yourself.

#### 5. Build and Run

```bash
cd mpc-config && \
docker-compose up -d
```

The docker-compose files include:
- **mongodb**: Local MongoDB instance (port 27017, **127.0.0.1** only); optional strong auth via **`.env`** / **`.env.example`** and **`mongodb/docker-entrypoint-initdb.d/`** on first-run empty `./data/mongodb`.
- **mosquitto**: MQTT broker (automatically configured from `mosquitto/config/mosquitto.conf` - port 8883 for TLS by default)
- **app**: The mpc-auth node — default Docker image **`continuumdao/mpc-auth:latest`** (**`MPC_AUTH_COMPOSE_APP_IMAGE`** overrides). **`GET /version`** (management or discovery port) returns the **application semver** (e.g. **`v1.1`**) embedded in the binary for that image — not the literal string **`latest`**.
  - **`127.0.0.1:8080:8080`** — management API (**localhost on the host** only; use **SSH tunnel** for remote `curl` / Swagger)
  - **`18080`** — public discovery (`PublicDiscoveryPort`): **`GET /getNodeMgtKey`**, **`GET /getPublicMgtKey`**, **`GET /getAllowedEd25519MgtKeys`**, **`GET /health`**, **`GET /getNodeKey`**, **`GET /getConfiguredNodeKeys`** (no JWT on this port)
  - **`18081`** — scanner/relayer HTTP when **`ScannerRelayerPort`** is set in `configs.yaml` (e.g. **`POST /signRequest`**)
  - **`8443`** — Browser HTTPS (DAO app; JWT on GET per `BrowserHTTPS` in `configs.yaml`)
  - **`./configs.yaml:/app/configs.yaml`** — mounted **writable** so management **`POST /configUpdateImplement`** can merge peer/config updates onto disk (read-only mounts block merges).
  - **`console/apply_planned_configs_ruamel.py`** — bind-mounted over **`/app/console/apply_planned_configs_ruamel.py`** in the container. This mpc-config copy uses rename-or-copy when installing merged YAML so Docker bind mounts do not raise **`EBUSY`** on **`configs.yaml.tmp` → `configs.yaml`**.

**Note:** The default configuration uses image tag **`latest`**. If you encounter an error that the image is not found, see the Troubleshooting section below.

#### Management API exposure (`ManagementAPIsPort`, default 8080)

**Defaults in this repo**

- **`docker-compose*.yml` publish management as `127.0.0.1:8080:8080`** — the full management API is **not** reachable on the host’s public IP; use **`ssh -L 8080:127.0.0.1:8080 user@node`** (or similar) for remote admin.
- **`process_config.sh` does not add a UFW “allow” rule for the management port** unless you set **`UFW_OPEN_MANAGEMENT_PORT=1`**. Other ports (SSH, Browser HTTPS, PublicDiscovery, ScannerRelayer when configured, MQTT on relay) are still added as before.

**Peer key probes (`GET /getConfiguredNodeKeys`)**

- Probes use **`http://<peer>:<PublicDiscoveryPort>/getNodeKey`** (e.g. **18080**), then **`http://<peer>:<ManagementAPIsPort>/getNodeKey`**. Peers should use the **same** **`PublicDiscoveryPort`** in `configs.yaml`. 

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

### Compose file version unsupported (`version: '3.8'`)

If `docker-compose up -d` fails with:

```text
ERROR: Version in "./docker-compose.yml" is unsupported. You might be seeing this error because you're using the wrong Compose file version.
```

**Cause:** The compose file **templates** (`docker-compose.relay.yml` / `docker-compose.client.yml`) and the generated **`docker-compose.yml`** declare **`version: '3.8'`**. Older **standalone** Compose binaries (for example **`docker-compose` 1.25.x** from some distro packages) do not implement that schema version, even when **Docker Engine** itself is new (e.g. 26.x).

**Check what you have:**

```bash
docker-compose --version   # standalone 1.x is often the problem
docker compose version     # Compose V2 plugin (note the space)
```

**Fix (recommended): use Compose V2** — the **`docker compose`** subcommand (space, not hyphen) implements the current file format.

**1. Try your distro package (when available):**

```bash
sudo apt update && sudo apt install -y docker-compose-plugin
docker compose version
```

**2. If you see `E: Unable to locate package docker-compose-plugin`** — many default **Ubuntu/Debian** mirrors only ship old standalone **`docker-compose`** (1.25.x) with **`docker.io`**, not the V2 plugin. Use either path below.

- **A. Docker’s APT repository (plugin via `apt`)** — follow Docker’s guide to [install Docker Engine on Ubuntu](https://docs.docker.com/engine/install/ubuntu/) or [Debian](https://docs.docker.com/engine/install/debian/) (add Docker’s repo, then `sudo apt install docker-compose-plugin`). If you use **`docker.io`** from Ubuntu and do not want to switch the engine, prefer **B**.

- **B. Compose V2 binary as a CLI plugin (no `docker-compose-plugin` package)** — works with the **`docker`** you already have. Pick a current **`v2.x`** tag from [Compose releases](https://github.com/docker/compose/releases), then (example — replace **`v2.32.4`** with that tag):

```bash
VERSION="v2.32.4"
sudo mkdir -p /usr/local/lib/docker/cli-plugins
sudo curl -fSL "https://github.com/docker/compose/releases/download/${VERSION}/docker-compose-linux-$(uname -m)" \
  -o /usr/local/lib/docker/cli-plugins/docker-compose
sudo chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
docker compose version
```

Then:

```bash
docker compose up -d
```

Use **`docker compose`** everywhere this README shows **`docker-compose`** (e.g. `docker compose ps`, `docker compose logs app`).

**Alternative:** replace the standalone **`docker-compose`** executable with a [current v1.x release](https://github.com/docker/compose/releases) that supports Compose file **3.8** (less ideal than V2). See also Docker’s [Compose install overview](https://docs.docker.com/compose/install/).

**Do not** downgrade the repo’s compose templates just to satisfy an obsolete `docker-compose` 1.25 — upgrading Compose is the supported path.

### Docker Image Not Found

If you see an error such as `manifest for continuumdao/mpc-auth:latest not found: manifest unknown` (or similar for another tag):

**This means the Docker image tag isn't available in the registry (or the tag name is wrong).**

**Solution 1: Pin a Tagged Release (Recommended)**

Check what tags are published and update **`docker-compose.relay.yml`** / **`docker-compose.client.yml`** (then re-run **`./process_config.sh`**) or the generated **`docker-compose.yml`**:

```bash
docker pull continuumdao/mpc-auth:v1.1  # use a tag published by the project
```

Then update the compose file to use an available tag:
```yaml
app:
  image: continuumdao/mpc-auth:v1.1  # or another published tag
```

**Solution 2: Check Docker Registry Access**

If the image should be available, verify you can access the registry:

```bash
# Test pulling the image directly (default in this repo: mpc-auth:latest)
docker pull continuumdao/mpc-auth:latest

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

1. **Navigate to your project directory** (where **`docker-compose.yml`** is generated after **`./process_config.sh`**):
   ```bash
   cd ~/mpc-config  # or wherever you cloned this repo
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

**Important:** The certificates must be in the **relative path** `mosquitto/config/certs/` (relative to the project directory / the generated **`docker-compose.yml`**), not in an absolute path like `/mosquitto/config/certs/` on the host filesystem.

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
   
   **Quick fix:** Run **`./process_config.sh`** on the client so **`docker-compose.yml`** is regenerated from **`docker-compose.client.yml`**, or edit **`docker-compose.client.yml`** and re-run **`process_config.sh`**. Manually editing **`docker-compose.yml`** is possible but will be overwritten on the next **`process_config.sh`** run unless you change the **template** instead.

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

- **[docs/skill/SKILL.md](docs/skill/SKILL.md)** – **mpa-wallet** skill: agent defaults (`multiSignRequest` helpers, **`executeSignResult.py`** only for EVM execute, environment).
- **[docs/references/AI_AGENT_NEW_SESSION.md](docs/references/AI_AGENT_NEW_SESSION.md)** – Agent session bootstrap: **`.env`**, symlinks, **`GET /health`**, **`KEYGEN_ID`**.
- **[docs/references/API_IMPLEMENTATION.md](docs/references/API_IMPLEMENTATION.md)** – Full API reference (endpoints, request/response formats, Swagger).
- **[docs/references/ED25519_MANAGEMENT_KEY_SIGNING.md](docs/references/ED25519_MANAGEMENT_KEY_SIGNING.md)** – Ed25519 management signing for agents (allow-list, nonces, tools).
- **[docs/CONFIGURING_ED25519_KEYS.md](docs/CONFIGURING_ED25519_KEYS.md)** – Node owner: creating keys, **`PublicMgtKey`**, **`addManagementKey`**, private key storage.
- **[docs/internal/README.md](docs/internal/README.md)** – Index of internal operator notes ( **`process_config.sh`**, Browser HTTPS, firewall).
- **[docs/internal/MULTI_SIGNREQUEST_DESIGN.md](docs/internal/MULTI_SIGNREQUEST_DESIGN.md)** – Batch **`multiSignRequest`** design detail (signing flow).

---

## Support

For issues, questions, or contributions, please contact the DAO.
