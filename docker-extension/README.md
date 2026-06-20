# Continuum Node — Docker Desktop Extension

Install a local Continuum MPC node on **Windows**, **Linux**, or **macOS** using Docker Desktop. This is the **primary** path for local installs from the [Continuum node app](https://github.com/ContinuumDAO/continuumdao-node-app). Remote VPS installs use the [VPS one-shot script](../scripts/install-node-debian-ubuntu.sh).

**Windows 11 end-user guide:** [`docs/INSTALL_NODE_WINDOWS_DOCKER_DESKTOP.md`](../docs/INSTALL_NODE_WINDOWS_DOCKER_DESKTOP.md) (router NAT: [`docs/PORT_FORWARDING_HOME_NETWORK.md`](../docs/PORT_FORWARDING_HOME_NETWORK.md)).

**macOS end-user guide:** [`docs/INSTALL_NODE_MACOS_DOCKER_DESKTOP.md`](../docs/INSTALL_NODE_MACOS_DOCKER_DESKTOP.md).

## What it does

The extension detects the host OS via `ddClient.host.platform` (`win32`, `linux`, `darwin`). If detection fails, the user selects Windows, Linux, or macOS from a dropdown.

| Host OS | Install script | Execution |
|---------|----------------|-----------|
| **Windows** | [`install-node-docker-desktop.sh`](../scripts/install-node-docker-desktop.sh) | `continuum-wsl.cmd` → WSL → orchestrator `--profile windows` |
| **Linux** | [`install-node-linux-docker-desktop.sh`](../scripts/install-node-linux-docker-desktop.sh) | `continuum-linux.sh` → host `bash` → orchestrator `--profile linux` → `sudo` install |
| **macOS** | [`install-node-macos-docker-desktop.sh`](../scripts/install-node-macos-docker-desktop.sh) | `continuum-macos.sh` → host `bash` → orchestrator `--profile macos` |

Common flow:

1. Extension UI invokes **`host.cli.exec`** on the host → **`scripts/desktop-local-orchestrate.sh`** with `--profile windows|linux|macos`.
2. Orchestrator **git clones** mpc-config to **`~/mpc-config`**.
3. Profile-specific install script runs `provision-node.sh` + `process_config.sh`, then **`docker compose up -d`**.
4. Both desktop scripts call [`configure-desktop-compose-discovery.sh`](../scripts/lib/configure-desktop-compose-discovery.sh) so the dashboard container reaches mpc-auth via the compose service `app`.
5. Stack containers appear under **Docker Desktop → Containers**.

The extension **backend image is UI-only** (no baked `/mpc-config`, no `docker.sock`). Config, keys, and compose bind mounts live under **`~/mpc-config`** on the host (WSL on Windows; home directory on Linux and macOS).

**Windows profile:** no apt docker, no UFW, no systemd; pip/venv Python deps in WSL; WSL pending-update watcher.

**Linux profile:** apt packages (except `docker.io`), UFW + systemd via provision; requires **passwordless sudo** for the install step (extension cannot enter a password).

**macOS profile:** Homebrew packages (`wireguard-tools`, `socat`, `yq`); no UFW/systemd; **passwordless sudo** for `/var/lib/mpc-auth-docker`; macos-desktop pending watcher + launchd LaunchAgent.

## Prerequisites (end users)

1. [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running.
2. **Settings → Extensions** — enable **Docker Extensions** (disabled by default).
3. For unpublished builds: disable **Allow only Marketplace extensions**.
4. **Windows:** WSL 2 + Docker Desktop WSL integration. Python provision deps via `pip --target` when possible.
5. **Linux:** Debian/Ubuntu host with passwordless `sudo` recommended for extension-driven install.
6. **macOS:** Homebrew; passwordless `sudo` recommended for extension-driven install.

## Install the extension (sideload)

After the image is published or built locally:

```bash
docker extension install continuumdao/continuum-node-installer:0.1.17
```

Open **Docker Desktop → Extensions → Continuum Node** and complete the wizard.

## Build and publish extension image

Bump `EXT_TAG` for each release and keep it in sync across:

| Location | Field |
|----------|--------|
| `docker-extension/Dockerfile` | header comments + `com.docker.extension.changelog` |
| `docker-extension/README.md` | sideload / build examples |
| [continuumdao-node-app `dockerExtensionInstall.ts`](https://github.com/ContinuumDAO/continuumdao-node-app/blob/main/app/utils/dockerExtensionInstall.ts) | `CONTINUUM_DOCKER_EXTENSION_TAG` |

**Build UI + image (local sideload):**

```bash
# From mpc-config repo root
export EXT_TAG=0.1.17

cd docker-extension/ui && npm ci && npm run build && cd ../..

docker build -f docker-extension/Dockerfile -t continuumdao/continuum-node-installer:${EXT_TAG} .
docker extension install continuumdao/continuum-node-installer:${EXT_TAG}
```

**Multi-arch publish to Docker Hub** (Apple Silicon + Intel Macs, Windows, Linux hosts):

```bash
docker buildx build --platform linux/amd64,linux/arm64 \
  -f docker-extension/Dockerfile \
  -t continuumdao/continuum-node-installer:${EXT_TAG} \
  --push .
```

The extension backend image is `linux/amd64` + `linux/arm64` only. **darwin host binaries** (`continuum-macos.sh`, etc.) ship inside the image and are copied to the Mac host by Docker Desktop at extension install time.

**macOS QA after sideload:** Docker Desktop → Extensions → Continuum Node → Install with a test key and public IP; confirm `~/mpc-config`, containers running, and `~/mpc-config/macos-desktop/status-watcher.sh` reports running.

## Build on Linux (developers)

From the **mpc-config repo root**:

```bash
cd docker-extension/ui && npm ci && npm run build && cd ../..
docker build -f docker-extension/Dockerfile -t continuumdao/continuum-node-installer:0.1.17 .
docker extension install continuumdao/continuum-node-installer:0.1.17   # requires Docker Desktop on host
```

Push to Docker Hub (multi-arch recommended for Windows):

```bash
docker buildx build --platform linux/amd64,linux/arm64 \
  -f docker-extension/Dockerfile \
  -t continuumdao/continuum-node-installer:0.1.17 \
  --push .
```

## Windows compose bind-mount strategy

Compose templates ([`docker-compose.client.yml`](../docker-compose.client.yml)) use **repo-relative bind mounts** (`./configs.yaml`, `./bootstrap_key`, `./added_keys`, `./mosquitto/config`, etc.).

**Windows:** mpc-config lives at **`~/mpc-config` in the user's WSL distro**.

| Layer | Path |
|-------|------|
| mpc-config clone | WSL `~/mpc-config` (Windows) or `~/mpc-config` (Linux) |
| Windows Explorer | `\\wsl$\<Distro>\home\<user>\mpc-config` |
| Install orchestrator | Extension → host CLI → `desktop-local-orchestrate.sh` |
| Docker engine | Docker Desktop |

## Install progress UI (manual QA)

Install scripts emit structured progress on stdout (`@continuum/progress` JSON lines when `CONTINUUM_INSTALL_PROGRESS=json`).

**Windows WSL dry-run:**

```bash
cd ~/mpc-config
CONTINUUM_INSTALL_PROGRESS=json ./scripts/install-node-docker-desktop.sh \
  --dry-run --no-start --repo-dir "$(pwd)" \
  --node-mgt-key "0xYOUR40HEX…" --ip "203.0.113.50" 2>/dev/null | grep '@continuum/progress'
```

**Linux Docker Desktop dry-run:**

```bash
cd ~/mpc-config
CONTINUUM_INSTALL_PROGRESS=json sudo ./scripts/install-node-linux-docker-desktop.sh \
  --dry-run --no-start --skip-clone --repo-dir "$(pwd)" \
  --node-mgt-key "0xYOUR40HEX…" --ip "203.0.113.50" 2>/dev/null | grep '@continuum/progress'
```

## Maintenance on desktop

**Windows (WSL + Docker Desktop):** systemd is not used in WSL. Host restart automation is a **pending-update file watcher** installed under `~/mpc-config/wsl-desktop/`:

| Action | Mechanism |
|--------|-----------|
| Restart node service / image update | mpc-auth writes `/var/lib/mpc-auth-docker/pending-update.json` → WSL watcher → `mpc-auth-docker-update.sh` → `docker compose` in `~/mpc-config` |
| WireGuard admin VPN | mpc-auth writes `/var/lib/mpc-auth-docker/pending-vpn.json` → same WSL watcher → `wg-quick` + socat on `10.8.0.1:8080` (split-tunnel recommended; full-tunnel NAT is limited on WSL2). Optional Shadowsocks obfuscation: background `ssserver` — panel toggle hidden until mpc-auth sets `obfuscationAvailable: true` |
| Full host reboot | Not supported on Windows local nodes (Maintenance **Reboot** hidden in the node app) |

After extension install, the UI registers a Windows **logon Scheduled Task** (`ContinuumNodeMpcAuthWatcher`) that runs `~/mpc-config/wsl-desktop/start-watcher.sh` in your WSL distro. Check status in WSL:

```bash
~/mpc-config/wsl-desktop/status-watcher.sh
tail -f ~/mpc-config/wsl-desktop/watcher.log
```

Manual start/stop: `start-watcher.sh` / `stop-watcher.sh`. Re-install watcher (including VPN libexec): `bash ~/mpc-config/wsl-desktop/install-wsl-desktop-host-automation.sh --repo-dir ~/mpc-config`.

**VPN on Windows:** allow **UDP 51820** through Windows Firewall for inbound WireGuard. Remote clients connecting to your home/office PC must reach the WSL WireGuard listener (WSL2 NAT/port forwarding may be required; split-tunnel admin access is the supported profile).

**macOS (Docker Desktop):** no systemd. Host restart automation is a **pending-update file watcher** under `~/mpc-config/macos-desktop/` plus a **launchd LaunchAgent** (`com.continuumdao.mpc-auth-watcher`):

| Action | Mechanism |
|--------|-----------|
| Restart node service / image update | `pending-update.json` → macOS watcher → `mpc-auth-docker-update.sh` |
| WireGuard admin VPN | `pending-vpn.json` → same watcher → `wg-quick` + socat on `10.8.0.1:8080`. Optional Shadowsocks: background `ssserver` (requires `brew install shadowsocks-rust` or install script helper) |
| Full host reboot | Not supported on macOS local nodes (Maintenance **Reboot** hidden in the node app) |

Check status:

```bash
~/mpc-config/macos-desktop/status-watcher.sh
tail -f ~/mpc-config/macos-desktop/watcher.log
launchctl list | grep continuumdao
```

Re-install: `bash ~/mpc-config/macos-desktop/install-macos-desktop-host-automation.sh --repo-dir ~/mpc-config`.

**Linux (Docker Desktop):** systemd units are installed — Maintenance auto-restart uses `mpc-auth-docker-pending-update.path` (same as VPS). Docker Desktop hosts may lack the distro `docker.socket` unit; the pending-update service uses `Wants=docker.socket` so the path still runs.

| Action | Mechanism |
|--------|-----------|
| Restart node service / image update | `pending-update.json` → `mpc-auth-docker-pending-update.path` |
| WireGuard admin VPN | `pending-vpn.json` → `mpc-auth-vpn-pending.path` → `wg-quick@wg0` + socat on `10.8.0.1:8080` (requires `wireguard` + `socat` apt packages). **Shadowsocks obfuscation fully supported** (same systemd path as VPS; optional `shadowsocks-rust` via install helper) |

**Manual fallback (both profiles):**

```bash
cd ~/mpc-config
docker compose restart app
```

## Manual install without extension (advanced)

**Windows (WSL):**

```bash
curl -fsSL "https://raw.githubusercontent.com/ContinuumDAO/mpc-config/main/scripts/desktop-local-orchestrate.sh" \
  -o /tmp/continuum-desktop-orchestrate.sh
bash /tmp/continuum-desktop-orchestrate.sh --profile windows --node-mgt-key "0x…" --ip "YOUR_PUBLIC_IP"
```

**Linux:**

```bash
curl -fsSL "https://raw.githubusercontent.com/ContinuumDAO/mpc-config/main/scripts/desktop-local-orchestrate.sh" \
  -o /tmp/continuum-desktop-orchestrate.sh
bash /tmp/continuum-desktop-orchestrate.sh --profile linux --node-mgt-key "0x…" --ip "YOUR_PUBLIC_IP"
```

**macOS:**

```bash
curl -fsSL "https://raw.githubusercontent.com/ContinuumDAO/mpc-config/main/scripts/desktop-local-orchestrate.sh" \
  -o /tmp/continuum-desktop-orchestrate.sh
bash /tmp/continuum-desktop-orchestrate.sh --profile macos --node-mgt-key "0x…" --ip "YOUR_PUBLIC_IP"
```

## Image layout

| Path | Purpose |
|------|---------|
| `/ui` | Extension tab (built from `ui/`) |
| `/metadata.json` | Extension manifest |
| `/host/windows/continuum-wsl.cmd` | Windows host binary — WSL entry point for `host.cli.exec` |
| `/host/linux/continuum-linux.sh` | Linux host binary — delegates to host `PATH` (`curl`, `bash`, etc.) |
| `/host/darwin/continuum-macos.sh` | macOS host binary — delegates to host `PATH` (`curl`, `bash`, etc.) |
| `/host/darwin/continuum-register-launchagent.sh` | Registers launchd LaunchAgent for pending-update watcher |
| `/docker-compose.yaml` | Minimal backend keeper container |

On Windows, Docker Desktop copies **`continuum-wsl.cmd`** to the host when the extension is installed (`metadata.json` → `host.binaries`). On Linux, it copies **`continuum-linux.sh`** the same way — `host.cli.exec` only runs shipped host binaries, not arbitrary system commands.

## Troubleshooting

| Symptom | Check |
|---------|--------|
| macOS Install fails (passwordless sudo) | Run `sudo -k && sudo -n true` in Terminal (not just `sudo -n` after a recent login). Visudo line must match the user shown in the install log (`Docker Desktop host exec user:`). Reinstall the extension after updating — host binaries ship inside the image. |
| macOS watcher not running | `bash ~/mpc-config/macos-desktop/install-launchagent.sh --repo-dir ~/mpc-config` |
| Linux `sudo` password prompt / install hangs | Configure passwordless sudo for your user, or run orchestrator manually in a terminal |
| `this installer requires WSL2` on Windows | Run inside WSL, not PowerShell |
| `passwordless sudo required` / install stops before clone | From PowerShell: `wsl -d <distro> -u root`, then `visudo` and add `<user> ALL=(ALL) NOPASSWD: ALL`. Verify: `wsl -d <distro> bash -lc 'sudo -n true && echo OK'` |
| Could not run commands in WSL distro | Distro name must match `wsl -l -v` exactly |
| `spawn …/host/curl ENOENT` on Linux | Extension missing Linux host wrapper — reinstall a build that ships `continuum-linux.sh`, or run the orchestrator manually (see below) |
| `curl: (23) Failed writing body` on Linux | Host exec cannot write to `/tmp` — use a build that bundles `continuum-orchestrate.sh` (no curl download) |
| `dashboard` / `continuum-mcp` exit 139 (~10s restart loop) | Broken `node:22.22.3-bookworm-slim` base on Docker Hub (truncated `/usr/local/bin/node`). Pin image tags to a rebuild with digest-pinned Node base, or use `v1.1.9` / `v1.0.41` until republished |
| `apt` hangs on `mongodb-database-tools` | Stale `~/mpc-config` from a failed attempt — run `cd ~/mpc-config && git pull`, or remove the directory and retry Install |
| `configs.yaml already exists` | Fresh install only; use Maintenance for updates |
