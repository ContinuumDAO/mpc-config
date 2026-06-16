# Continuum Node — Docker Desktop Extension

Install a local Continuum MPC node on **Windows** or **macOS** using Docker Desktop. This is the **primary** path for Windows local installs from the [Continuum node app](https://github.com/ContinuumDAO/continuumdao-node-app). Remote VPS and native Linux installs use the [VPS one-shot script](../scripts/install-node-debian-ubuntu.sh) instead.

## What it does

1. Extension UI invokes **`host.cli.exec`** on the Windows host → shipped **`continuum-wsl.cmd`** → **`scripts/desktop-local-orchestrate.sh`** inside your WSL distro.
2. Orchestrator **git clones** mpc-config to **`~/mpc-config`** (standard desktop path, same bind-mount layout as manual WSL / VPS).
3. **`install-node-docker-desktop.sh`** runs there: `provision-node.sh` + `process_config.sh` (`--no-firewall`, no systemd), then **`docker compose up -d`** via Docker Desktop WSL integration.
4. Stack containers (**mongo**, **mpc-auth**, **continuum-mcp**, **continuumdao-node-app**, etc.) appear under **Docker Desktop → Containers**.

The extension **backend image is UI-only** (no baked `/mpc-config`, no `docker.sock`, no VM install path). All config, keys, and compose bind mounts live under **`~/mpc-config` in WSL** on Windows.

**Skipped on desktop (vs VPS):** apt `docker.io`, UFW, systemd units, `mpcnode` OS user, SSH password setup.

## Prerequisites (end users)

1. [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running.
2. **Settings → Extensions** — enable **Docker Extensions** (disabled by default).
3. For unpublished builds: disable **Allow only Marketplace extensions**.
4. **Windows only:** WSL 2 + Docker Desktop WSL integration. **0.1.7+** installs Python provision deps via `pip --target` (no `python3-venv` required). If auto-install fails, run Option A from the install log once in WSL.

## Install the extension (sideload)

After the image is published or built locally:

```bash
docker extension install continuumdao/continuum-node-installer:0.1.7
```

Open **Docker Desktop → Extensions → Continuum Node** and complete the wizard.

## Build on Linux (developers)

From the **mpc-config repo root**:

```bash
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

**Implemented approach:** mpc-config lives at **`~/mpc-config` in the user's WSL distro**. The extension clones/uses that path and runs `docker compose` from WSL with Docker Desktop WSL integration — the same model as manual WSL install and compatible with key operations (`POST /postBootstrapKey`, `POST /addManagementKey`, Maintenance `git pull`).

| Layer | Path |
|-------|------|
| mpc-config clone | WSL `~/mpc-config` |
| Windows Explorer | `\\wsl$\<Distro>\home\<user>\mpc-config` |
| Install orchestrator | Extension → `continuum-wsl.cmd` → `desktop-local-orchestrate.sh` in WSL |
| Docker engine | Docker Desktop (WSL integration for chosen distro) |
| Protocol containers | Docker Desktop → **Containers** (mongo, app, continuum-mcp, continuumdao-node-app, …) |

The extension backend container does **not** bind-mount or bake `~/mpc-config`. Host-side WSL orchestration is the only install path on Windows.

## Windows QA checklist (deferred)

Run on a Windows machine with Docker Desktop — **not required to merge initial Linux implementation**.

1. [ ] Docker Desktop + Extensions enabled + WSL2 engine + Ubuntu WSL integration
2. [ ] `docker extension install continuumdao/continuum-node-installer:0.1.7`
3. [ ] Extension wizard completes → containers visible in Desktop **Containers**
4. [ ] `mosquitto/config/certs` and `webTLS/config/certs` populated under repo; `mpc-auth` healthy
5. [ ] Attach node at [mpa.continuumdao.org](https://mpa.continuumdao.org) via loopback/HTTPS URL
6. [ ] Node map wizard: Windows primary (extension) + advanced WSL fallback smoke test

## Install progress UI (manual QA)

Install scripts emit structured progress on stdout (`@continuum/progress` JSON lines when `CONTINUUM_INSTALL_PROGRESS=json`). The extension parses these into per-topic bars plus a pinned **Overall** row with spinner.

**Desktop JSON dry-run (WSL / Linux):**

```bash
cd ~/mpc-config   # or your mpc-config clone
CONTINUUM_INSTALL_PROGRESS=json ./scripts/install-node-docker-desktop.sh \
  --dry-run --no-start --repo-dir "$(pwd)" \
  --node-mgt-key "0xYOUR40HEX…" --ip "203.0.113.50" 2>/dev/null | grep '@continuum/progress'
```

Expect `init`, multiple `topic` lines, `overall` with `"spinner":true`, and `finish` with `"ok":true`.

**VPS plain progress (root shell on Debian/Ubuntu):**

```bash
sudo CONTINUUM_INSTALL_PROGRESS=plain ./scripts/install-node-debian-ubuntu.sh \
  --dry-run --skip-clone --skip-packages --skip-user --no-start \
  --repo-dir /path/to/empty-mpc-config-tree \
  --node-mgt-key "0xYOUR40HEX…" --ip "203.0.113.50"
```

Expect `==> Overall N%` lines and per-topic percentages on stdout; verbose logs on stderr.

**Extension UI:** after rebuild/sideload, run Install — the progress panel should list topics (clone, Python deps, process_config phases, docker pulls, start stack) with animated bars; detail log stays collapsible for stderr/errors.

## Maintenance on desktop

Systemd pending-update paths are **not** installed. After `git pull` or config changes:

```bash
cd ~/mpc-config
docker compose restart
```

Use the node app **Maintenance** section for guided updates when available.

## Manual install without extension (advanced)

In WSL with Docker Desktop integration (same `~/mpc-config` path as the extension):

```bash
curl -fsSL "https://raw.githubusercontent.com/ContinuumDAO/mpc-config/main/scripts/desktop-local-orchestrate.sh" \
  | bash -s -- --node-mgt-key "0x…" --ip "YOUR_PUBLIC_IP"
```

Or after clone:

```bash
cd ~/mpc-config
./scripts/install-node-docker-desktop.sh --node-mgt-key "0x…" --ip "YOUR_PUBLIC_IP"
```

## Image layout

| Path | Purpose |
|------|---------|
| `/ui` | Extension tab (built from `ui/`; styles synced from [continuumdao-node-app](https://github.com/ContinuumDAO/continuumdao-node-app) `app/globals.css`) |
| `/metadata.json` | Extension manifest |
| `/host/windows/continuum-wsl.cmd` | Windows host binary — sole WSL entry point for `host.cli.exec` |
| `/docker-compose.yaml` | Minimal backend keeper container (no docker.sock, no mpc-config tree) |

Live node data after install: **WSL `~/mpc-config`** (Windows) or **`~/mpc-config`** (macOS host shell).

On Windows, Docker Desktop copies **`continuum-wsl.cmd`** to the host when the extension is installed (`metadata.json` → `host.binaries`). All WSL list, probe, and install commands go through that wrapper.

## Troubleshooting

| Symptom | Check |
|---------|--------|
| `python3-venv` / ensurepip / PEP 668 errors | Use extension **0.1.7+** — tries `pip install --target ~/mpc-config/.provision-py` first (no apt). If all auto paths fail, run Option A from the error log once in WSL. |
| Install stops at `sudo: preserving the entire environment` | Use extension **0.1.7+** scripts on `main`. Desktop path no longer uses sudo. Remove partial `~/mpc-config/configs.yaml` and retry. |
| `shell operators are not allowed` in install log | Rebuild extension **0.1.7+** — orchestrator uses `curl -o` then `bash` (no `\|` pipe through SDK) |
| Could not run commands in WSL distro | Distro name must match `wsl -l -v` exactly. Reinstall extension so **`continuum-wsl.cmd`** is copied to the host. Quit and restart Docker Desktop. |
| False “WSL is required” on Windows | Rebuild **0.1.7** — uses `wsl -l -v` not `wsl --status`; set exact distro name |
| Install shows empty log panel | Rebuild **0.1.7** — fixes streaming `host.cli.exec` (install waits for output) |
| Install button clears fields, no log output | Rebuild **0.1.7** — UI JS loads from `./assets/` (not `/assets/`). You should see **Ready** under the title. |
| `Docker Desktop host CLI API unavailable` | Update Docker Desktop; reload extension |
| `WSL is required on Windows` | Install WSL distro + enable integration in Docker Desktop |
| `curl: 404` in install log | `desktop-local-orchestrate.sh` not on GitHub `main` yet — push mpc-config or install manually in WSL |
| `docker info` fails in log | Start Docker Desktop; enable WSL integration for your distro |
| `configs.yaml already exists` | Fresh install only; use Maintenance for updates |
| Bind mount errors on Windows | Confirm hybrid A paths; see QA checklist |
