# MPC Node Configuration Repository

Configuration and setup scripts for ContinuumDAO **mpc-auth** MPC / MPA wallet nodes.

This README is an **install index** plus operator notes that are easy to get wrong. It is **not** a second install walkthrough.

| Who | Start here |
|-----|------------|
| **AI agent — greenfield Ubuntu/Debian VPS** | [`docs/CREATE_NODE_ONESHOT.md`](docs/CREATE_NODE_ONESHOT.md) then [Agent provision and configure](https://docs.continuumdao.org/ContinuumDAO/MPAWallet/AgentProvision) |
| **Human — easiest** | [Install a node](https://docs.continuumdao.org/ContinuumDAO/MPAWallet/Install) (node map **`+`**) |
| **Human — Windows / macOS home PC** | Docker Desktop + **Continuum Node** extension (below). Agents **coach only** — [Agent install anti-patterns](https://docs.continuumdao.org/ContinuumDAO/MPAWallet/AgentInstallAntiPatterns) |
| **Advanced interactive VPS** | [Node Running Instructions](https://docs.continuumdao.org/ContinuumDAO/RunningInstructions/NodeRunningInstruction) |
| **Uninstall** | [`docs/UNINSTALL_NODE.md`](docs/UNINSTALL_NODE.md) |

Wrong install (root-only tree, custom folder, remapped ports): [Agent install anti-patterns](https://docs.continuumdao.org/ContinuumDAO/MPAWallet/AgentInstallAntiPatterns).

**KeyGen types** this stack actually supports: **`secp256k1`**, **`ed25519`**, **`bitcoin-taproot`** (`AllowedKeyTypeList` in `configs-original.yaml`; `GET /getAllowedKeyTypes`). FROST types need an mpc-auth image built with **`-tags rust`**.

## What's Included

- **`configs.yaml`** / **`configs-original.yaml`** — node config; copy the original to revert. `process_config.sh` copies it to `configs.yaml` if missing.
- **`process_config.sh`** — validator, certs, UFW, generates **`docker-compose.yml`** from **`docker-compose.relay.yml`** (first / relay node) or **`docker-compose.client.yml`**.
- **`scripts/provision-node.sh`** — non-interactive **fresh** `configs.yaml` then `process_config.sh`. Used by the VPS one-shot. Full flags: **`--help`**.
- **`scripts/install-node-debian-ubuntu.sh`** — **one-shot VPS** (root on Ubuntu/Debian): packages, **`mpcnode`**, clone, provision, **`docker compose up -d`**.
- **`scripts/install-node-docker-desktop.sh`**, **`install-node-macos-docker-desktop.sh`**, **`install-node-linux-docker-desktop.sh`** — Docker Desktop profiles (used by the extension / orchestrator).
- **`scripts/desktop-local-orchestrate.sh`** — clone **`~/mpc-config`** then run the matching desktop installer.
- **`scripts/verify-node-install.sh`** / **`verify-node-install-macos-desktop.sh`** — read-only layout checks after install.
- **`scripts/uninstall-node-debian-ubuntu.sh`**, **`uninstall-node-docker-desktop.sh`**, **`uninstall-node-macos-docker-desktop.sh`**.
- **`tools/provision-command.js`** — MPA frontend curl/SSH command builder.
- **`tools/bootstrap_key_provision.py`** — Ed25519 bootstrap / **`DeterministicNodeKey`**.
- **`mosquitto/config/`**, **`webTLS/config/certs/`** — MQTT TLS and browser HTTPS material.

## One-shot VPS install

**AI agents:** this is the install step only. Mesh (peers, MQTT, Group, KeyGen): [Agent provision](https://docs.continuumdao.org/ContinuumDAO/MPAWallet/AgentProvision). Script: **`scripts/install-node-debian-ubuntu.sh`**. Guide: **[`docs/CREATE_NODE_ONESHOT.md`](docs/CREATE_NODE_ONESHOT.md)**. Repo entry: **[`AGENTS.md`](AGENTS.md)**.

Run **as root on the VPS** (or pipe over SSH from your PC). The MPA app at [https://mpa.continuumdao.org](https://mpa.continuumdao.org) can generate this command. No wallet signing is required at install time.

The clone tracks **`main`**. After the node is running, update from the node app **Maintenance** tab (`git pull` + **`updateMpcAuth`**).

```bash
# A) On the VPS (ssh root@YOUR_VPS_IP, then paste):
curl -fsSL "https://raw.githubusercontent.com/ContinuumDAO/mpc-config/main/scripts/install-node-debian-ubuntu.sh" \
  | bash -s -- \
      --node-mgt-key "0xYour40HexCharacters..." \
      --ip "YOUR_VPS_PUBLIC_IP"

# B) From your PC (curl still runs ON the VPS):
ssh -o StrictHostKeyChecking=accept-new root@YOUR_VPS_PUBLIC_IP \
  'curl -fsSL "https://raw.githubusercontent.com/ContinuumDAO/mpc-config/main/scripts/install-node-debian-ubuntu.sh" | bash -s -- --node-mgt-key "0xYour40HexCharacters..." --ip "YOUR_VPS_PUBLIC_IP"'
```

**Required:** at least one of `--node-mgt-key` / `-k` (`0x` + 40 hex) or `--public-mgt-key` (64 hex or `ssh-ed25519 …` line). **`--ip`** is the public IPv4 peers will use.

New node: omit `--public-mgt-key` so Ed25519 bootstrap is generated; back up bootstrap + database via the node app ([Backup and restoration](https://docs.continuumdao.org/ContinuumDAO/MPAWallet/BackupAndRestoration)). Restore / same Node Key: pass `--public-mgt-key` and place **`bootstrap_key/ed25519_private.hex`** as in **Restore / deterministic nodeKey** below.

The installer creates **`mpcnode`** with **password-protected sudo** and **no login password**. After it finishes:

```bash
ssh root@YOUR_VPS_PUBLIC_IP 'passwd mpcnode'
```

**Preflight:** the installer exits if **`/home/mpcnode/mpc-config/configs.yaml`** already exists or MPC containers are running. Use **Maintenance** to update an existing node.

**Verify** (required before mesh / attach):

```bash
curl -fsSL "https://raw.githubusercontent.com/ContinuumDAO/mpc-config/main/scripts/verify-node-install.sh" | bash -s
```

Systemd helpers are installed by default (`--no-systemd` to skip). Full flags: **`./scripts/install-node-debian-ubuntu.sh --help`**.

Then attach at [https://mpa.continuumdao.org](https://mpa.continuumdao.org) — loopback ports **3333 / 8080 / 18080 / 8446** only; one node at a time from this PC. See [Attach your node](https://docs.continuumdao.org/ContinuumDAO/MPAWallet/AttachYourNode).

Frontend integrators: **`tools/provision-command.js`**. Tests: **`node tools/provision-command.test.js`**.

---

## Docker Desktop (home PC)

**Not** the VPS curl script. No `mpcnode` OS user. Canonical clone: **`~/mpc-config`** (WSL home on Windows; macOS home).

**Primary path:** install **Docker Desktop**, enable **Extensions**, install **Continuum Node** (`continuumdao/continuum-node-installer`). Enter management key and **public** WAN IPv4, click **Install**. Then attach at [mpa.continuumdao.org](https://mpa.continuumdao.org) (**Node hosted app (local PC)**).

| Platform | Guide |
|----------|--------|
| Windows 11 + WSL2 | [`docs/INSTALL_NODE_WINDOWS_DOCKER_DESKTOP.md`](docs/INSTALL_NODE_WINDOWS_DOCKER_DESKTOP.md) |
| macOS | [`docs/INSTALL_NODE_MACOS_DOCKER_DESKTOP.md`](docs/INSTALL_NODE_MACOS_DOCKER_DESKTOP.md) |
| Home router ports | [`docs/PORT_FORWARDING_HOME_NETWORK.md`](docs/PORT_FORWARDING_HOME_NETWORK.md) |
| Extension build / QA | [`docker-extension/README.md`](docker-extension/README.md) |

**AI agents:** do not run desktop install scripts. Coach the operator through the extension or node map. After a Mac install, verify:

```bash
curl -fsSL "https://raw.githubusercontent.com/ContinuumDAO/mpc-config/main/scripts/verify-node-install-macos-desktop.sh" | bash -s
```

**Advanced (human at the keyboard):** `scripts/desktop-local-orchestrate.sh` or the platform `install-node-*-docker-desktop.sh` — `--help` on each script.

---

## Uninstall

**AI agents:** [`docs/UNINSTALL_NODE.md`](docs/UNINSTALL_NODE.md) and [`docs/skills/`](docs/skills/). Published: [Uninstall](https://docs.continuumdao.org/ContinuumDAO/MPAWallet/Uninstall).

Before you delete a node: **back up** bootstrap + encrypted database (store them separately), **or Eject** KeyGens, **or transfer** assets. Other KeyGen members may drop below the TSS threshold (a 2-of-2 wallet freezes).

Ubuntu/Debian VPS as **root**. Agents pass **`--yes`**:

```bash
curl -fsSL "https://raw.githubusercontent.com/ContinuumDAO/mpc-config/main/scripts/uninstall-node-debian-ubuntu.sh" \
  | bash -s -- --yes
```

Windows/WSL: [`scripts/uninstall-node-docker-desktop.sh`](scripts/uninstall-node-docker-desktop.sh). macOS: [`scripts/uninstall-node-macos-docker-desktop.sh`](scripts/uninstall-node-macos-docker-desktop.sh). These remove the compose stack, Continuum images, host automation, `mpc-config`, and (VPS) **`mpcnode`**. They do **not** uninstall Docker Engine or OS packages.

---

## Operator notes

### Ports

| Port | Bind | Role |
|------|------|------|
| **3333** | host (node-app) | Local dashboard. SSH tunnel left **and** right: `127.0.0.1:3333`. |
| **8080** | `127.0.0.1` | Management API (`ManagementAPIsPort`). Attach at **`127.0.0.1:8080`**. |
| **18080** | public | Discovery (`PublicDiscoveryPort`). |
| **18081** | public | Scanner / relayer (`ScannerRelayerPort`). |
| **8443** | public | Browser HTTPS (self-signed `browser.crt`). |
| **8446** | `127.0.0.1` | continuum-mcp `/mcp` (Path A). |
| **8883** | public on **relay** | MQTT TLS. |
| **8081** | not a listener | Default port in **`nodeAddresses`** peer URLs (`process_config.sh` `MPC_NODE_HTTP_PORT`). **Not** attach. |

Attach / SSH from one PC: use **3333, 8080, 18080, 8446** only — same local and remote `-L` ports. One tunnel and one node at a time.

### Compose stack

`process_config.sh` writes **`docker-compose.yml`**. Use **`docker compose`** (v2, space), not standalone `docker-compose` 1.x.

Typical services:

- **mongodb** — `127.0.0.1:27017` only
- **app** (mpc-auth) — `continuumdao/mpc-auth:latest` unless **`MPC_AUTH_COMPOSE_APP_IMAGE`** is set **before** `process_config.sh`
- **dashboard** — `continuumdao/continuumdao-node-app:latest` on **3333**
- **continuum-mcp** — loopback **8446**
- **mosquitto** — **relay template only** (first IP in `nodeAddresses`)

Application semver is **`GET /version`** on management or discovery — not the Docker tag string `latest`. To pin an image, set **`MPC_AUTH_COMPOSE_APP_IMAGE`** or edit the **template** (`docker-compose.relay.yml` / `docker-compose.client.yml`) and re-run **`process_config.sh`**.

### `provision-node.sh` (already-cloned repo)

For a **new VPS**, prefer the one-shot (it calls this). Run **as root** only on a tree **without** `configs.yaml` (copies `configs-original.yaml`; refuses to overwrite).

Provide **at least one** management key (`--node-mgt-key` and/or `--public-mgt-key`). **`--ip`** if auto-detect is wrong. **`--install-systemd`** for host helpers. Full flags: **`sudo ./scripts/provision-node.sh --help`**.

Needs **Python 3**, **ruamel.yaml**, and **cryptography**. Then **`docker compose up -d`** from the clone (one-shot already does this).

### Restore / deterministic nodeKey

With **`DeterministicNodeKey: true`** and **`bootstrap_key/ed25519_private.hex`**, mpc-auth derives **`nodeKey`** from that seed plus **`PublicMgtKey`**.

1. **New install** — omit `--public-mgt-key`. `process_config.sh` creates `bootstrap_key/`, sets **`PublicMgtKey`**. **Back up `bootstrap_key/`**.
2. **Recover / migrate** — pass the original **`--public-mgt-key`**, copy **`bootstrap_key/ed25519_private.hex`** next to `configs.yaml` **before** provision. **Wipe or recreate the Mongo volume** if mpc-auth already started with other data; `process_config.sh` only fixes YAML.

A legacy backup whose envelope **`nodeKeyPublic`** was a **random** key will not match a fresh deterministic init. Restore Mongo/node state from before that switch, or use another mpc-auth-supported restore path.

### MongoDB and `.env`

Mongo is **localhost only**. For auth, copy **`.env.example`** → **`.env`** (or let `process_config.sh` do it) and set **`MONGO_INITDB_ROOT_PASSWORD`** / **`MONGO_APP_PASSWORD`**. Root user is created **only if both** username and password are set on a **new empty** `./data/mongodb`. Existing no-auth volumes need a one-time migration — do not put credentials in **`MongodbUri`** until Mongo accepts them. **`.env`** must be **`0600`**.

### MQTT (relay vs peers)

Peers use **`ssl://<relay-wan-ip>:8883`**. On the **relay host**, mpc-auth inside Docker cannot reliably dial its own WAN IP — set **`mqttBroker: ssl://mosquitto:8883`** there (`process_config.sh --sync-compose-role-only` or a full relay `process_config.sh`). Check **`GET /health`** → **`data.mqtt.errors`**.

Certificates live under **`mosquitto/config/certs/`** relative to the clone (Docker mounts `./mosquitto/config`). Client nodes need **`ca.crt`** only; they must **not** run mosquitto. Share the CA via the node app (**Inter Node Communication**) or a secure file transfer — not a custom “same username everywhere” install.

Groups and KeyGens: [Groups](https://docs.continuumdao.org/ContinuumDAO/MPCSigner/Groups), [KeyGens](https://docs.continuumdao.org/ContinuumDAO/MPCSigner/KeyGens), [Agent provision](https://docs.continuumdao.org/ContinuumDAO/MPAWallet/AgentProvision). API detail: [`docs/references/API_IMPLEMENTATION.md`](docs/references/API_IMPLEMENTATION.md).

---

## Troubleshooting

**Docker daemon:** `sudo systemctl status docker` — start/enable if needed. On a VPS one-shot, **`mpcnode`** is already in the **`docker`** group; log out and back in (or `newgrp docker`) if `docker ps` still fails.

**`version: '3.8'` unsupported:** old standalone **`docker-compose` 1.25**. Use **`docker compose version`**. From a clone: **`sudo ./scripts/docker-V2_debian_ubuntu.sh`** (the VPS one-shot already runs this).

**Mosquitto missing certs:** files must be `mosquitto/config/certs/{ca,server}.{crt,key}` **relative to the project directory**, not `/mosquitto/config/certs/` on the host. Then `docker compose restart mosquitto`.

**Mosquitto on a client:** stop and remove it; regenerate compose with **`./process_config.sh`** (client template has no broker). Clients only need **`ca.crt`**.

**MQTT connected on peers but not on the relay:** see **MQTT (relay vs peers)** above.

**API auth errors:** `NodeMgtKey` / Ed25519 signer must match; get nonce via **`GET /getNodeMgtKeyNonce`** (over the **8080** tunnel). See [`docs/references/ED25519_MANAGEMENT_KEY_SIGNING.md`](docs/references/ED25519_MANAGEMENT_KEY_SIGNING.md).

---

## Additional documentation

- [Install](https://docs.continuumdao.org/ContinuumDAO/MPAWallet/Install) · [Agent provision](https://docs.continuumdao.org/ContinuumDAO/MPAWallet/AgentProvision) · [Attach](https://docs.continuumdao.org/ContinuumDAO/MPAWallet/AttachYourNode) · [Uninstall](https://docs.continuumdao.org/ContinuumDAO/MPAWallet/Uninstall)
- [Node Running Instructions](https://docs.continuumdao.org/ContinuumDAO/RunningInstructions/NodeRunningInstruction) — advanced / manual
- [`docs/CREATE_NODE_ONESHOT.md`](docs/CREATE_NODE_ONESHOT.md) · [`docs/UNINSTALL_NODE.md`](docs/UNINSTALL_NODE.md) · [`AGENTS.md`](AGENTS.md)
- [`docs/references/API_IMPLEMENTATION.md`](docs/references/API_IMPLEMENTATION.md)
- [`docs/CONFIGURING_ED25519_KEYS.md`](docs/CONFIGURING_ED25519_KEYS.md) · [`docs/references/ED25519_MANAGEMENT_KEY_SIGNING.md`](docs/references/ED25519_MANAGEMENT_KEY_SIGNING.md)
- [`docs/AGENT_HOOKS.md`](docs/AGENT_HOOKS.md)
- [AI harness](https://docs.continuumdao.org/ContinuumDAO/MPAWallet/AIHarness/Overview) — bundled skills: [`agent_llm_config.defaults/Skills/`](agent_llm_config.defaults/Skills/)
- Host systemd helpers: [`systemd/README.md`](systemd/README.md) (present in the clone)

## Support

For issues, questions, or contributions, contact the DAO.
