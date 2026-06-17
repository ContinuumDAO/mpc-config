# Continuum Node — Docker Desktop Extension

Install a local Continuum MPC node on **Windows** or **Linux** using Docker Desktop. This is the **primary** path for Windows local installs from the [Continuum node app](https://github.com/ContinuumDAO/continuumdao-node-app). Remote VPS installs use the [VPS one-shot script](../scripts/install-node-debian-ubuntu.sh). **macOS** is listed in the UI but install is not yet available.

## What it does

The extension detects the host OS via `ddClient.host.platform` (`win32`, `linux`, `darwin`). If detection fails, the user selects Windows, Linux, or macOS from a dropdown.

| Host OS | Install script | Execution |
|---------|----------------|-----------|
| **Windows** | [`install-node-docker-desktop.sh`](../scripts/install-node-docker-desktop.sh) | `continuum-wsl.cmd` → WSL → orchestrator `--profile windows` |
| **Linux** | [`install-node-linux-docker-desktop.sh`](../scripts/install-node-linux-docker-desktop.sh) | `continuum-linux.sh` → host `bash` → orchestrator `--profile linux` → `sudo` install |
| **macOS** | *(not yet available)* | Install button disabled |

Common flow:

1. Extension UI invokes **`host.cli.exec`** on the host → **`scripts/desktop-local-orchestrate.sh`** with `--profile windows|linux`.
2. Orchestrator **git clones** mpc-config to **`~/mpc-config`**.
3. Profile-specific install script runs `provision-node.sh` + `process_config.sh`, then **`docker compose up -d`**.
4. Both desktop scripts call [`configure-desktop-compose-discovery.sh`](../scripts/lib/configure-desktop-compose-discovery.sh) so the dashboard container reaches mpc-auth via the compose service `app`.
5. Stack containers appear under **Docker Desktop → Containers**.

The extension **backend image is UI-only** (no baked `/mpc-config`, no `docker.sock`). Config, keys, and compose bind mounts live under **`~/mpc-config`** on the host (WSL on Windows).

**Windows profile:** no apt docker, no UFW, no systemd; pip/venv Python deps in WSL.

**Linux profile:** apt packages (except `docker.io`), UFW + systemd via provision; requires **passwordless sudo** for the install step (extension cannot enter a password).

## Prerequisites (end users)

1. [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running.
2. **Settings → Extensions** — enable **Docker Extensions** (disabled by default).
3. For unpublished builds: disable **Allow only Marketplace extensions**.
4. **Windows:** WSL 2 + Docker Desktop WSL integration. Python provision deps via `pip --target` when possible.
5. **Linux:** Debian/Ubuntu host with passwordless `sudo` recommended for extension-driven install.

## Install the extension (sideload)

After the image is published or built locally:

```bash
docker extension install continuumdao/continuum-node-installer:0.1.7
```

Open **Docker Desktop → Extensions → Continuum Node** and complete the wizard.

## Build on Linux (developers)

From the **mpc-config repo root**:

```bash
cd docker-extension/ui && npm ci && npm run build && cd ../..
docker build -f docker-extension/Dockerfile -t continuumdao/continuum-node-installer:0.1.7 .
docker extension install continuumdao/continuum-node-installer:0.1.7   # requires Docker Desktop on host
```

Push to Docker Hub (multi-arch recommended for Windows):

```bash
docker buildx build --platform linux/amd64,linux/arm64 \
  -f docker-extension/Dockerfile \
  -t continuumdao/continuum-node-installer:0.1.7 \
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

**Windows:** systemd is not installed — after `git pull` or config changes:

```bash
cd ~/mpc-config
docker compose restart
```

**Linux:** systemd units are installed — Maintenance auto-restart may apply after config updates.

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

## Image layout

| Path | Purpose |
|------|---------|
| `/ui` | Extension tab (built from `ui/`) |
| `/metadata.json` | Extension manifest |
| `/host/windows/continuum-wsl.cmd` | Windows host binary — WSL entry point for `host.cli.exec` |
| `/host/linux/continuum-linux.sh` | Linux host binary — delegates to host `PATH` (`curl`, `bash`, etc.) |
| `/docker-compose.yaml` | Minimal backend keeper container |

On Windows, Docker Desktop copies **`continuum-wsl.cmd`** to the host when the extension is installed (`metadata.json` → `host.binaries`). On Linux, it copies **`continuum-linux.sh`** the same way — `host.cli.exec` only runs shipped host binaries, not arbitrary system commands.

## Troubleshooting

| Symptom | Check |
|---------|--------|
| macOS Install disabled | Expected — macOS script not yet available |
| Linux `sudo` password prompt / install hangs | Configure passwordless sudo for your user, or run orchestrator manually in a terminal |
| `this installer requires WSL2` on Windows | Run inside WSL, not PowerShell |
| Could not run commands in WSL distro | Distro name must match `wsl -l -v` exactly |
| `spawn …/host/curl ENOENT` on Linux | Extension missing Linux host wrapper — reinstall a build that ships `continuum-linux.sh`, or run the orchestrator manually (see below) |
| `docker info` fails in log | Start Docker Desktop |
| `configs.yaml already exists` | Fresh install only; use Maintenance for updates |
