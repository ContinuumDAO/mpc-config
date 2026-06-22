# systemd helpers: mpc-auth Docker restart and image update

These units complement the mpc-auth **maintenance** HTTP API (`POST /maintenance/requestRestartPrep`, **`GET /maintenance/restartGate`**, **`POST /updateMpcAuth`** for registry digest, **`POST /reboot`** for a host reboot trigger).

**Why the app does not upgrade Docker for you:** `POST /updateMpcAuth` runs **inside** the mpc-auth container. Pulling a new image requires the **host’s Docker socket** and often **root**. The API response includes **`registryDigest`** so your **host-side** update script can verify **`docker pull`**; the HTTP process does not invoke **`docker`** itself (least privilege).

**You do not need to edit `/etc/default/mpc-auth-docker` on every upgrade.** The update script accepts **`registryDigest` as the second argument** (see [Run](#run)). Only persist **`MPC_AUTH_EXPECTED_DIGEST`** in `/etc/default` if you prefer **`systemctl start mpc-auth-docker-update@TAG.service`** alone (that unit does not pass digest on the command line—use **script** invocation for one-shot digests).

## Why `POST /updateMpcAuth` can fail (and leave mpc-auth down)

The host update script runs as a **systemd oneshot** with cwd `/`, not your compose directory. It needs either:

| Requirement | Purpose |
|-------------|---------|
| **`MPC_AUTH_COMPOSE_WORKDIR`** | Absolute path to the directory containing **`docker-compose.yml`** (e.g. `/home/mpcnode/mpc-config`) |
| **or `MPC_AUTH_POST_UPDATE_CMD`** | Full shell command instead of default `docker compose up …` |

If **`MPC_AUTH_COMPOSE_WORKDIR` is empty**, older **`mpc-auth-docker-update.sh`** versions could **stop/remove** the `app` container, then fail at compose — leaving Mongo/continuumdao-node-app/MCP up but **no mpc-auth** (what you saw).

**Prevention on new nodes:** run **`./process_config.sh`** (syncs workdir) and/or **`sudo ./install-mpc-auth-docker-systemd.sh`** from this repo (installer now sets **`MPC_AUTH_COMPOSE_WORKDIR`** to the mpc-config parent of **`systemd/`** and skips enabling **`pending-update.path`** until workdir is valid). Current **`mpc-auth-docker-update.sh`** checks workdir **before** stop/rm.

**Existing hosts:** set workdir once, then `docker compose up -d --no-deps --force-recreate app`, or re-run install after `git pull`:

```bash
cd /path/to/mpc-config/systemd
sudo ./install-mpc-auth-docker-systemd.sh --no-env-backup   # refreshes scripts; sets workdir if installing env
# or keep env and only sync workdir:
grep MPC_AUTH_COMPOSE_WORKDIR /etc/default/mpc-auth-docker
sudo systemctl enable --now mpc-auth-docker-pending-update.path
```

## Fully automated upgrades (recommended)

**Preferred:** **`systemd.path`** + **bind mount** — the mpc-auth process **never** holds the Docker socket. After a successful **`POST /updateMpcAuth`**, **mpc-auth** writes one JSON file **atomically** to **`/var/lib/mpc-auth-docker/pending-update.json`** (same inode on host + container). **`mpc-auth-docker-pending-update.path`** starts **`mpc-auth-docker-pending-update.service`**, which runs **`mpc-auth-apply-pending-update.sh`**: it **`mv`** claims the file, sets **`MPC_AUTH_PENDING_RESTART_ONLY`** / **`MPC_AUTH_PENDING_FORCE_RECREATE`** from the JSON, and runs **`mpc-auth-docker-update.sh`** with **tag** and **digest** (digest may be empty when **`restartOnly`** is true). Install enables the path unit; **`docker-compose*.yml`** mounts **`/var/lib/mpc-auth-docker:/var/lib/mpc-auth-docker`** (see templates in this repo).

**Alternative — Docker socket (`/var/run/docker.sock`) in the app container:** the process can run **`docker pull`** itself. That grants **effective host-root-level control via the Docker API** (start privileged containers, mount host dirs, …). Avoid unless you accept that risk and shrink the attack surface elsewhere.

**Host reboot:** After a successful signed **`POST /reboot`** (while draining), mpc-auth can write **`pending-reboot.json`** to the same bind-mounted directory. **`mpc-auth-docker-pending-reboot.path`** starts **`mpc-auth-apply-pending-reboot.sh`**, which validates JSON and invokes **`systemctl reboot`** only (**no `shutdown(8)` fallback** — non-systemd or broken **`systemctl`** installs must reboot manually).

**Non-interactive reboot / “are you sure?” prompts:** The oneshot runs **without a controlling terminal** (**`StandardInput=null`**), so nothing in this path can answer interactive questions. Maintainer scripts during shutdown often respect **`DEBIAN_FRONTEND=noninteractive`** (set in the unit). Desktop sessions can register **logind inhibitors** that delay reboot; the script tries **`systemctl reboot --check-inhibitors=no`** first (systemd **247+**), then plain **`systemctl reboot`** if that option is unknown. If a reboot still does not occur, inspect **`systemd-inhibit --list`**, **`journalctl -u mpc-auth-docker-pending-reboot.service`**, and Polkit rules for **`org.freedesktop.login1.reboot`** — the fix belongs on the host, not in the container API.

JSON contract (written by mpc-auth):

```json
{"tag":"v1.1","registryDigest":"sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}
```

**Optional fields:** **`restartOnly`** (boolean) — omit **`registryDigest`** when true; host still runs **`git pull`** in **`MPC_AUTH_COMPOSE_WORKDIR`** (unless **`MPC_AUTH_SKIP_GIT_PULL=1`**), then skips Docker image pull/rmi and restarts or recreates only. **`forceRecreate`** (boolean) — run **`docker compose up -d --no-deps --force-recreate`** for the configured service (**`app`**, not Mongo/MQTT dependents). The apply script exports **`MPC_AUTH_PENDING_RESTART_ONLY`** and **`MPC_AUTH_PENDING_FORCE_RECREATE`** as **`0`** or **`1`** before **`mpc-auth-docker-update.sh`**.

(Optionally **`newVersionRequested`** / **`registry_digest`** aliases are accepted by **`mpc-auth-apply-pending-update.sh`**.)

**Reboot trigger JSON** (written by mpc-auth for **`pending-reboot.json`**):

```json
{"kind":"hostReboot","requestedAt":"2026-04-30T12:00:00.123456789Z"}
```

### Where units go on Debian / Ubuntu

Use **`/etc/systemd/system/`** for administrator-installed units. **`/etc/systemd/`** (without **`system/`**) is for systemd-wide snippets such as **`journald.conf`**; do not drop `*.service` files there—**`/etc/systemd/system/*.service`** is correct.

## What is included

| File | Purpose |
|------|---------|
| **`install-mpc-auth-docker-systemd.sh`** | **`sudo ./install-mpc-auth-docker-systemd.sh`** — installs scripts under **`/usr/local/libexec/mpc-auth/`**, **`mpc-auth-docker.env`** as **`/etc/default/mpc-auth-docker`**, **`*.service`** under **`/etc/systemd/system/`**, then **`systemctl daemon-reload`**. `--no-env` skips env file; **`--no-env-backup`** overwrites env without a **`.bak`**. |
| **`mpc-auth-docker-restart.sh`** | **`docker restart`** on **`MPC_AUTH_CONTAINER_NAME`**; if that container does not exist, restarts the **only** **`docker ps -a`** row whose **`Image`** matches **`*mpc-auth*`** (helps when Compose project prefix differs); if several match or none, exits **1** (set **`MPC_AUTH_CONTAINER_NAME`** or **`MPC_AUTH_RESTART_STRICT=1`** to force exactly the configured name only). |
| **`mpc-auth-docker-update.sh`** | Stop/remove container (if **`MPC_AUTH_CONTAINER_NAME`** matches), `docker rmi --force` previous image ref, `docker pull`, **digest check** ( **`MPC_AUTH_EXPECTED_DIGEST`** or 2nd CLI arg), then **compose**: if **`MPC_AUTH_POST_UPDATE_CMD`** is **non-blank**, runs that; **otherwise** requires **`MPC_AUTH_COMPOSE_WORKDIR`**, then runs **`docker compose`** / **`docker-compose`** with **`cd`** into that directory and **`up -d --no-deps --force-recreate MPC_AUTH_COMPOSE_SERVICE`** (default **`app`**) so only mpc-auth is recreated — **MongoDB / Mosquitto are not touched** unless relay promotion requires it (see **`mpc-auth-sync-compose-role.sh`**). Optionally pulls **continuumdao-node-app** (**`dashboard`**) and **continuum-mcp-server** (**`continuum-mcp`**) (see README “Update script behavior”). |
| **`mpc-auth-sync-compose-role.sh`** | Before restart/update compose: runs **`process_config.sh --sync-compose-role-only`** in **`MPC_AUTH_COMPOSE_WORKDIR`** so **`docker-compose.yml`** switches **relay ↔ client** when **`configs.yaml`** **`nodeAddresses`** changes (e.g. provision with **`0.0.0.0`** first, then DAO app sets this node relay). Generates MQTT broker certs on first relay promotion; when **`needs_full_stack=1`**, **`mpc-auth-docker-update.sh`** runs **`docker compose up -d`** (full stack, starts **mosquitto**) instead of **`--no-deps`** app-only. Set **`MPC_AUTH_SKIP_COMPOSE_ROLE_SYNC=1`** to disable. |
| **`mpc-auth-docker.env`** | Default **`MPC_AUTH_CONTAINER_NAME=mpc-config-app-1`** (typical Compose v2 name when the project directory is **`mpc-config`** and service is **`app`**); copy to `/etc/default/mpc-auth-docker`. |
| **`mpc-auth-docker.env.example`** | Same keys as **`mpc-auth-docker.env`**; keep in sync when changing conventions. |
| **`mpc-auth-docker-restart.service`** | `Type=oneshot` wrapper around the restart script. |
| **`mpc-auth-docker-update@.service`** | Template unit: instance **is the image tag**. Example: `systemctl start mpc-auth-docker-update@latest.service`. |
| **`mpc-auth-docker-pending-update.path`** | Watches **`/var/lib/mpc-auth-docker/pending-update.json`**; starts apply service when mpc-auth writes the file (after **`POST /updateMpcAuth`**). |
| **`mpc-auth-docker-pending-update.service`** | Oneshot: runs **`mpc-auth-apply-pending-update.sh`** (parse JSON → **`mpc-auth-docker-update.sh`**). |
| **`mpc-auth-apply-pending-update.sh`** | Parses pending JSON (**`tag`**, **`registryDigest`** unless **`restartOnly`**, **`restartOnly`**, **`forceRecreate`**) then delegates to **`mpc-auth-docker-update.sh`**. |
| **`mpc-auth-docker-pending-reboot.path`** | Watches **`/var/lib/mpc-auth-docker/pending-reboot.json`**; starts apply service when mpc-auth writes the file (after **`POST /reboot`**). |
| **`mpc-auth-docker-pending-reboot.service`** | Oneshot: runs **`mpc-auth-apply-pending-reboot.sh`** → host **`systemctl reboot`**. |
| **`mpc-auth-apply-pending-reboot.sh`** | Claims **`pending-reboot.json`**, archives to **`applied/`**, runs **`systemctl reboot`** (with inhibitor bypass when supported). |
| **`mpc-auth-vpn-pending.path`** | Watches **`/var/lib/mpc-auth-docker/pending-vpn.json`**; starts apply service when mpc-auth writes the file (after **`POST /vpn/setEnabled`**). |
| **`mpc-auth-vpn-pending.service`** | Oneshot: runs **`mpc-auth-apply-pending-vpn.sh`** → **`mpc-auth-vpn-enable.sh`** or **`mpc-auth-vpn-disable.sh`**. |
| **`mpc-auth-wireguard-wg0.service`** | **`wg-quick up/down wg0`** — WireGuard server interface. |
| **`mpc-auth-vpn-mgmt-proxy.service`** | **`socat`** on **`10.8.0.1:8080`** → **`127.0.0.1:8080`** so VPN clients reach the management API. |
| **`mpc-auth-shadowsocks.service`** | **`ssserver`** for optional WireGuard transport obfuscation (**`/var/lib/mpc-auth-docker/shadowsocks/ssserver.json`**). |

**Compose:** **`docker-compose.relay.yml`** and **`docker-compose.client.yml`** both set **`MPC_AUTH_VPN_PENDING_FILE`** / **`MPC_AUTH_VPN_STATE_FILE`** and bind-mount **`/var/lib/mpc-auth-docker`**. **`process_config.sh`** copies the relay or client template to **`docker-compose.yml`** and can patch older compose files via **`apply_docker_compose_vpn_env`**.

**Host packages (VPS / Linux Docker Desktop):** **`wireguard`** and **`socat`** must be installed on the host (`wg-quick`, `socat`). Fresh installs via **`scripts/install-node-debian-ubuntu.sh`** include them; **`install-mpc-auth-docker-systemd.sh`** also runs **`apt install wireguard socat`** when missing (e.g. after **`git pull`** + **`process_config.sh`** on an older node). **Shadowsocks obfuscation** optionally installs **`shadowsocks-rust`** via **`ensure_shadowsocks_host_packages`** (warn-only — VPN works without it).

### WireGuard VPN — host firewall (UFW + Docker)

On VPS hosts with **UFW active** and **Docker**, `ufw allow 51820/udp` alone is often **not enough**: handshake packets can reach **`eth0`** but WireGuard never completes (client shows **`0 B received`**). **`mpc-auth-vpn-enable.sh`** (via **`scripts/lib/mpc-auth-vpn-wg0-hooks.sh`**) therefore:

1. Adds UFW allow rules for **`51820/udp`**, **`8080/tcp` from the VPN CIDR**, and **`allow in on wg0`**
2. Inserts **`PostUp` / `PostDown`** **`iptables -I INPUT`** rules under **`[Interface]`** in **`/etc/wireguard/wg0.conf`** (must be **before** **`[Peer]`** — never append at EOF)

**Provider firewall:** many VPS panels (Contabo, etc.) also filter **inbound UDP 51820** before traffic hits the VM. Open that in the provider panel if tcpdump on the host shows **no** packets on **`51820`**.

**Multi-node groups:** **`GET /vpn/status`** **`endpointHost`** and downloaded client configs use **this node's** public IP (KeyList index + egress IP match in **`nodeAddresses`**), not the relay's first entry. Optional override: **`WireGuard.EndpointHost`** in **`configs.yaml`** (mpc-auth).

**Peer egress (`wg-egress`) — UFW:** like admin **`wg0`**, `ufw status` can list **`51830/udp ALLOW`** while **`ufw-user-input`** has no live rule (especially when UFW was disabled but stale UFW iptables chains remain). **`mpc-auth-vpn-egress-enable.sh`** calls **`mpc_auth_vpn_egress_ensure_ufw_listen_port`**: re-enables UFW when needed, reloads, verifies **`ufw-user-input`**, and inserts **`PostUp`** **`iptables -I INPUT`** accepts on **`wg-egress.conf`** when UFW is active.

**Peer egress (`wg-egress`):** **`GET /vpn/egress/status`** on **ManagementAPIsPort** (**8080**) — read-only, no secrets; configured peers probe each other on the same management port as other inter-node HTTP. **`GET /vpn/egress/availableExits`** calls peer **`/vpn/egress/status`** on **ManagementAPIsPort** only (not PublicDiscoveryPort). **Client config issuance** uses the **MQTT relay** (existing **8883** broker path): consumer **`POST /vpn/egress/requestClientConfig`** on **:8080** (localhost) → **`VpnEgressIssueRequest`** → egress → **`VpnEgressIssueReply`**. **`POST /vpn/egress/issueClientConfig`** remains on management **:8080** (loopback / signed debug only). **`WireGuardEgress.EndpointHost`** in **`configs.yaml`** (auto-set by **`process_config.sh`**) supplies the WireGuard **`Endpoint`** in issued client configs.

**Operator flow (no SSH after install):** MPA **VPN Panel** → **`POST /vpn/setEnabled`** → host applies **`wg0`** + mgmt proxy → download client **`.conf`** → **`wg-quick up`** on the workstation. Verify with **`curl http://10.8.0.1:8080/health`** over the tunnel (ping is optional).

**Do not** edit **`PostUp`** manually at the bottom of **`wg0.conf`**. Re-enable VPN from the panel (or run **`mpc-auth-vpn-enable.sh`**) after **`git pull`** so hooks are regenerated.

### Shadowsocks transport obfuscation (optional)

When the VPN Panel enables **`obfuscation: shadowsocks`** (mpc-auth writes **`pending-vpn.json`** with that field):

1. **`mpc-auth-vpn-enable.sh`** starts **`mpc-auth-shadowsocks.service`** (**`ssserver`**) and adds **`iptables`** **`DROP`** for public UDP **`51820`** (non-loopback).
2. UFW allows **`Shadowsocks.ListenPort`** (default **`8388`**) TCP+UDP instead of **`51820/udp`**.
3. Operators download **`sslocal`** tunnel JSON + modified WireGuard client config from **`POST /vpn/clientConfig`**.
4. Client workflow: **`sslocal -c continuum-sslocal.json`**, then **`wg-quick up`** (Endpoint **`127.0.0.1:51821`**).

Requires **shadowsocks-rust** on the host (**`ensure_shadowsocks_host_packages`** — optional, warn-only at install). See **`docs/references/MPC_AUTH_VPN_SHADOWSOCKS.md`** and **`docs/references/API_IMPLEMENTATION.md`** (Shadowsocks section).

**Provider firewall:** open **TCP+UDP 8388** (or configured SS port), not UDP 51820, when obfuscation is active.

### Update script behavior

1. Reads optional `/etc/default/mpc-auth-docker` (`MPC_AUTH_CONTAINER_NAME`, **`MPC_AUTH_EXPECTED_DIGEST`**, `MPC_AUTH_POST_UPDATE_CMD`, …).
2. **`git pull`** in **`MPC_AUTH_COMPOSE_WORKDIR`** as the checkout owner (or parent directory owner when the repo is root-owned), via **`runuser`** / **`su`**, so SSH/credential helpers match the home user — not as root. Runs on **full** and **`restartOnly`** updates. Skipped when **`MPC_AUTH_SKIP_GIT_PULL=1`** or the path is not a git repo. On failure the oneshot exits before Docker pull (full update) or before restart/recreate (**`restartOnly`**).
2b. **Relay/client compose sync** (unless **`MPC_AUTH_SKIP_COMPOSE_ROLE_SYNC=1`**): **`mpc-auth-sync-compose-role.sh`** → **`process_config.sh --sync-compose-role-only`** copies **`docker-compose.relay.yml`** or **`docker-compose.client.yml`** to **`docker-compose.yml`** from **`configs.yaml`**. When the role **changes** (promotion or demotion) or **mosquitto** is missing on a relay, the update script runs **`docker compose up -d`** on the **full** stack (**`--remove-orphans`** when the role changed, so demoted nodes stop the old **mosquitto** container). After demotion, obtain the new relay’s MQTT CA and set **`MQTTTLS.CAFile`** in **`configs.yaml`** (same as a fresh client provision).
3. If the named container exists, records `docker inspect … .Config.Image`, then `docker stop` and `docker rm`. If **`MPC_AUTH_CONTAINER_NAME`** does not match the live container, a **warning** is printed and stop/rm is skipped — post-pull compose still runs **`up -d --no-deps --force-recreate`** so only the app service is replaced and the process actually restarts.
4. If an old image ref was recorded, runs `docker rmi --force` on it (ignore failure if already gone).
5. Runs `docker pull "${MPC_AUTH_IMAGE}:${TAG}"`.
6. If **`MPC_AUTH_EXPECTED_DIGEST`** (or **second CLI argument**) is set, compares **`docker image inspect … RepoDigests`** to that **`sha256:`** value; on mismatch exits **1** — **compose is skipped**.
7. **Compose image tag:** templates use **`image: ${MPC_AUTH_COMPOSE_APP_IMAGE:-continuumdao/mpc-auth:latest}`**. The script pulls **`${MPC_AUTH_IMAGE}:${TAG}`** (e.g. **`v1.1.1`**). Before **`compose up`**, it runs **`docker tag`** so **`${MPC_AUTH_IMAGE}:latest`** (or **`MPC_AUTH_COMPOSE_IMAGE_REF`**) points at the verified pull; otherwise **`up --force-recreate`** would still run the previous **`latest`** layers. Set **`MPC_AUTH_SKIP_RETAG_LATEST=1`** to skip.
8. Compose after pull (**digest must pass first**):
   - If **`MPC_AUTH_POST_UPDATE_CMD`** is **non-blank**, runs it verbatim (non-zero exit fails the unit).
   - If **unset/blank**, requires **`MPC_AUTH_COMPOSE_WORKDIR`**, then runs **`docker compose up -d --no-deps --force-recreate &lt;service&gt;`** (or **`docker-compose`** v1 equivalent) after **`cd`**, so the service container is always recreated even when step 3 skipped stop/rm — **without recreating dependency services** (avoids accidental Mongo teardown). **`MPC_AUTH_COMPOSE_SERVICE`** defaults to **`app`**.
9. **Companion continuumdao-node-app:** when **`MPC_AUTH_UPDATE_NODE_APP=1`** (default) and **`NODE_APP_IMAGE`** is set, runs **`docker pull $NODE_APP_IMAGE:$NODE_APP_TAG`** and **`docker compose up -d --no-deps --force-recreate $MPC_AUTH_NODE_APP_COMPOSE_SERVICE`** (default **`dashboard`**) so **continuumdao-node-app** tracks new registry layers when mpc-auth is updated.
10. **Companion MCP server:** when **`MPC_AUTH_UPDATE_MCP_SERVER=1`** (default) and **`MCP_SERVER_IMAGE`** is set, runs **`docker pull $MCP_SERVER_IMAGE:$MCP_SERVER_TAG`** and **`docker compose up -d --no-deps --force-recreate $MPC_AUTH_MCP_SERVER_COMPOSE_SERVICE`** (default **`continuum-mcp`**) so **continuum-mcp-server** tracks new registry layers the same way. **`process_config.sh`** syncs **`ContinuumdaoNodeApp`** and **`ContinuumMcpServer`** from **`configs.yaml`** into **`/etc/default/mpc-auth-docker`**.
11. **Prune old images:** after a successful full update (not **`restartOnly`**), removes unused **`continuumdao/mpc-auth`** images — superseded version tags (e.g. **`v1.2.6`**) and dangling **`<none>`** layers from same-tag digest bumps — while keeping the verified pull, compose ref (usually **`:latest`**), and any image still referenced by a container. Also prunes companion repos when configured. Set **`MPC_AUTH_PRUNE_OLD_IMAGES=0`** in **`/etc/default/mpc-auth-docker`** to disable.

**Docker Compose v2 vs legacy `docker-compose` v1:** Prefer the **`docker compose`** plugin (v2). Distro **`docker-compose`** 1.29.x often hits **`KeyError: 'ContainerConfig'`** on modern Docker engines when recreating containers with images that lack the legacy field — install [Compose v2](https://docs.docker.com/compose/install/linux/) on the host if you see that traceback.

For production upgrades, call **`POST /updateMpcAuth`** (while draining) with the target tag, then apply the digest on the host using **one** of [Run](#run) (script with 2nd argument is enough—no `/etc/default` edit).

## Install (typical)

### Via `process_config.sh` (optional)

After MQTT/Browser HTTPS steps complete, **`./process_config.sh`** may offer (**[Y/n]**, default **Yes**):

- **Fresh host:** install units + **`/etc/default/mpc-auth-docker`** via **`systemd/install-mpc-auth-docker-systemd.sh`** (requires **`sudo`**).
- **Already installed:** re-copy scripts + **`*.service`** with **`--no-env`** (keeps **`/etc/default`**) then **`daemon-reload`**, **[Y/n]** default **Yes**.
- **Every run:** if **`/etc/default/mpc-auth-docker`** exists, **`MPC_AUTH_COMPOSE_WORKDIR`** is set to the **absolute path of this mpc-config directory** (so moving/recloning the repo and re-running **`process_config.sh`** updates the path for **`mpc-auth-docker-pending-update`** / compose).
- **Every run (unless `--no-systemd`):** if **`mpc-auth-docker-restart.service`** or **`mpc-auth-docker-pending-update.service`** or **`mpc-auth-docker-pending-reboot.service`** is already under **`/etc/systemd/system/`**, **`process_config.sh`** runs **`install-mpc-auth-docker-systemd.sh --no-env`** so **`/usr/local/libexec/mpc-auth/*.sh`** and unit files match the repo (**`git pull` alone does not update those copies**).
- **Optional:** **`systemctl start mpc-auth-docker-restart.service`** (**restarts mpc-auth container**) **[Y/n]** default **Yes**.

Skip prompts: **`--no-systemd`** or **`PROCESS_CONFIG_SKIP_SYSTEMD=1`**. Non-interactive install: **`--install-mpc-auth-systemd`** or **`PROCESS_CONFIG_INSTALL_SYSTEMD=1`**.

### After `git pull` (repo up to date ≠ host scripts up to date)

**`systemd` runs the installed files under `/usr/local/libexec/mpc-auth/`**, not the copies next to your clone in **`~/mpc-config/systemd/`**. Pulling newer **`mpc-config`** does not replace those by itself.

**`./process_config.sh`** (without **`--no-systemd`**) now runs **`install-mpc-auth-docker-systemd.sh --no-env`** automatically when **`mpc-auth-docker-restart.service`**, **`mpc-auth-docker-pending-update.service`**, or **`mpc-auth-docker-pending-reboot.service`** is already installed — so **`git pull` → `process_config.sh`** refreshes libexec and unit files (**`/etc/default/mpc-auth-docker`** is preserved).

Manual one-liner if you only want scripts:

```bash
cd /path/to/mpc-config/systemd
sudo ./install-mpc-auth-docker-systemd.sh --no-env
```

**`--no-env`** keeps your existing **`/etc/default/mpc-auth-docker`**. Re-run **`./process_config.sh`** from that clone if you rely on it syncing **`MPC_AUTH_COMPOSE_WORKDIR`**, or set **`MPC_AUTH_COMPOSE_WORKDIR`** and **`MPC_AUTH_CONTAINER_NAME`** manually to match **`docker ps`**.

### Manual

From this directory (`mpc-config/systemd/` in the repo):

```bash
sudo ./install-mpc-auth-docker-systemd.sh
sudoedit /etc/default/mpc-auth-docker   # tweak container name / image only if differs from bundled defaults
```

Manual install (same result):

```bash
sudo mkdir -p /usr/local/libexec/mpc-auth
sudo install -m 0755 mpc-auth-docker-restart.sh mpc-auth-docker-update.sh mpc-auth-apply-pending-update.sh mpc-auth-apply-pending-reboot.sh /usr/local/libexec/mpc-auth/
sudo cp mpc-auth-docker.env /etc/default/mpc-auth-docker
sudoedit /etc/default/mpc-auth-docker   # tweak MPC_AUTH_CONTAINER_NAME / MPC_AUTH_IMAGE if your `docker ps` NAMES differ

sudo cp mpc-auth-docker-restart.service mpc-auth-docker-update@.service mpc-auth-docker-pending-update.path mpc-auth-docker-pending-update.service mpc-auth-docker-pending-reboot.path mpc-auth-docker-pending-reboot.service /etc/systemd/system/
sudo mkdir -p /var/lib/mpc-auth-docker/applied && sudo chmod 0755 /var/lib/mpc-auth-docker /var/lib/mpc-auth-docker/applied
sudo systemctl daemon-reload
sudo systemctl enable --now mpc-auth-docker-pending-update.path
sudo systemctl enable --now mpc-auth-docker-pending-reboot.path
```

### Run

**Preferred (digest from API, no `/etc/default` edit):** pass **`registryDigest`** as the **second argument** (tag = first arg, same tag you sent to **`POST /updateMpcAuth`**):

```bash
sudo /usr/local/libexec/mpc-auth/mpc-auth-docker-update.sh v1.1 sha256:216dbe264b1f9b8528dff053cb333958952251d3002a544e9261da06efa43aac
```

Alternative (same effect, env for one process only):

```bash
sudo env MPC_AUTH_EXPECTED_DIGEST='sha256:216dbe264b1f9b8528dff053cb333958952251d3002a544e9261da06efa43aac' \
  /usr/local/libexec/mpc-auth/mpc-auth-docker-update.sh v1.1
```

**Via systemd template** (digest must be in **`/etc/default/mpc-auth-docker`** as **`MPC_AUTH_EXPECTED_DIGEST=…`**, or omit digest and accept the script warning):

```bash
# 1) Drain (API), 2) POST /updateMpcAuth { tag } → optional: set digest in /etc/default OR use direct script invocation above
sudo systemctl start 'mpc-auth-docker-update@latest.service'

# Simple restart (same image) after maintenance gate — no registry pull:
sudo systemctl start mpc-auth-docker-restart.service

# Update without digest verification — script warns; avoid in prod:
sudo systemctl start 'mpc-auth-docker-update@v1.1.service'
```
### Troubleshooting restart failures

If **`systemctl start mpc-auth-docker-restart.service`** fails but **`sudo docker ps`** shows your app container:

1. **`docker ps` NAMES** must equal **`MPC_AUTH_CONTAINER_NAME`** in **`/etc/default/mpc-auth-docker`**, unless the restart script finds a **single** container whose **Image** column contains **`mpc-auth`** — then it uses that automatically (Compose project prefixes differ by clone path; e.g. **`otherdir-app-1`** vs **`mpc-config-app-1`**). If **more than one** such image container exists, set **`MPC_AUTH_CONTAINER_NAME`** explicitly.
2. **`MPC_AUTH_RESTART_STRICT=1`** in **`/etc/default/mpc-auth-docker`** disables that auto-pick and always uses **`MPC_AUTH_CONTAINER_NAME`** only.
3. Re-sync defaults: **`sudo nano /etc/default/mpc-auth-docker`**, set **`MPC_AUTH_CONTAINER_NAME`** to your **`NAMES`** column exactly, **or** re-run **`install-mpc-auth-docker-systemd.sh`** **without** **`--no-env`** after pulling this repo so the bundled env replaces the old file (**back up** first).
4. After changing the script under **`/usr/local/libexec/mpc-auth/`**, ensure you copied the updated **`mpc-auth-docker-restart.sh`** from this repo (install script or **`sudo install -m 0755 ...`**).

## Permissions

- Default units assume **root** can use the Docker socket. If your policy uses the **docker** group without root, add `Group=docker` (and appropriate `User=`) in a **drop-in** under `/etc/systemd/system/…d/`.
