# systemd helpers: mpc-auth Docker restart and image update

These units complement the mpc-auth **maintenance** HTTP API (`POST /maintenance/requestRestartPrep`, **`GET /maintenance/restartGate`**, **`POST /updateMpcAuth`** for registry digest). **`updateMpcAuth` does not invoke systemd**; copy **`registryDigest`** into **`/etc/default/mpc-auth-docker`** as **`MPC_AUTH_EXPECTED_DIGEST`**, then run the update unit on the Docker host.

### Where units go on Debian / Ubuntu

Use **`/etc/systemd/system/`** for administrator-installed units. **`/etc/systemd/`** (without **`system/`**) is for systemd-wide snippets such as **`journald.conf`**; do not drop `*.service` files there—**`/etc/systemd/system/*.service`** is correct.

## What is included

| File | Purpose |
|------|---------|
| **`install-mpc-auth-docker-systemd.sh`** | **`sudo ./install-mpc-auth-docker-systemd.sh`** — installs scripts under **`/usr/local/libexec/mpc-auth/`**, **`mpc-auth-docker.env`** as **`/etc/default/mpc-auth-docker`**, **`*.service`** under **`/etc/systemd/system/`**, then **`systemctl daemon-reload`**. `--no-env` skips env file; **`--no-env-backup`** overwrites env without a **`.bak`**. |
| **`mpc-auth-docker-restart.sh`** | **`docker restart`** on **`MPC_AUTH_CONTAINER_NAME`**; if that container does not exist, restarts the **only** **`docker ps -a`** row whose **`Image`** matches **`*mpc-auth*`** (helps when Compose project prefix differs); if several match or none, exits **1** (set **`MPC_AUTH_CONTAINER_NAME`** or **`MPC_AUTH_RESTART_STRICT=1`** to force exactly the configured name only). |
| **`mpc-auth-docker-update.sh`** | Stop/remove container, `docker rmi --force` previous image ref, `docker pull`, **digest check** ( **`MPC_AUTH_EXPECTED_DIGEST`** or 2nd CLI arg), then **compose**: if **`MPC_AUTH_POST_UPDATE_CMD`** is **non-blank**, runs that; **otherwise** prefers **`docker compose`** (v2 plugin), else **`docker-compose`** (v1), with **`cd MPC_AUTH_COMPOSE_WORKDIR`** when set, then **`up -d MPC_AUTH_COMPOSE_SERVICE`** (default **`app`**). |
| **`mpc-auth-docker.env`** | Default container name **`mpc-config_app_1`** (Compose v2 naming for project **`mpc-config`**, service **`app`**); copy to `/etc/default/mpc-auth-docker`. |
| **`mpc-auth-docker.env.example`** | Same keys as **`mpc-auth-docker.env`**; keep in sync when changing conventions. |
| **`mpc-auth-docker-restart.service`** | `Type=oneshot` wrapper around the restart script. |
| **`mpc-auth-docker-update@.service`** | Template unit: instance **is the image tag**. Example: `systemctl start mpc-auth-docker-update@v1.0.service`. |

### Update script behavior

1. Reads optional `/etc/default/mpc-auth-docker` (`MPC_AUTH_CONTAINER_NAME`, **`MPC_AUTH_EXPECTED_DIGEST`**, `MPC_AUTH_POST_UPDATE_CMD`, …).
2. If the named container exists, records `docker inspect … .Config.Image`, then `docker stop` and `docker rm`.
3. If an old image ref was recorded, runs `docker rmi --force` on it (ignore failure if already gone).
4. Runs `docker pull "${MPC_AUTH_IMAGE}:${TAG}"`.
5. If **`MPC_AUTH_EXPECTED_DIGEST`** (or **second CLI argument**) is set, compares **`docker image inspect … RepoDigests`** to that **`sha256:`** value; on mismatch exits **1** — **compose is skipped**.
6. Compose after pull (**digest must pass first**):
   - If **`MPC_AUTH_POST_UPDATE_CMD`** is **non-blank**, runs it verbatim.
   - If **unset/blank**, runs **`docker compose up -d &lt;service&gt;`** when the Compose v2 plugin exists, **`docker-compose`** when only v1 exists, after optional **`cd MPC_AUTH_COMPOSE_WORKDIR`**.
7. **`MPC_AUTH_COMPOSE_WORKDIR`** (and legacy alias **`MPC_AUTH_COMPOSE_DIR`**) must point at the compose project when using the automatic compose path; **`MPC_AUTH_COMPOSE_SERVICE`** defaults to **`app`**.

For production upgrades, call **`POST /updateMpcAuth`** (while draining) with the target tag, then paste **`Data.registryDigest`** into **`MPC_AUTH_EXPECTED_DIGEST`** before **`systemctl start mpc-auth-docker-update@…`**.

## Install (typical)

### Via `process_config.sh` (optional)

After MQTT/Browser HTTPS steps complete, **`./process_config.sh`** may offer (defaults **No**):

- **Fresh host:** install units + **`/etc/default/mpc-auth-docker`** via **`systemd/install-mpc-auth-docker-systemd.sh`** (requires **`sudo`**).
- **Already installed:** re-copy scripts + **`*.service`** with **`--no-env`** (keeps **`/etc/default`**) then **`daemon-reload`**, **[y/N]** default **No**.
- **Optional:** **`systemctl start mpc-auth-docker-restart.service`** (**restarts mpc-auth container**) **[y/N]** default **No**.

Skip prompts: **`--no-systemd`** or **`PROCESS_CONFIG_SKIP_SYSTEMD=1`**. Non-interactive install: **`--install-mpc-auth-systemd`** or **`PROCESS_CONFIG_INSTALL_SYSTEMD=1`**.

### Manual

From this directory (`mpc-config/systemd/` in the repo):

```bash
sudo ./install-mpc-auth-docker-systemd.sh
sudoedit /etc/default/mpc-auth-docker   # tweak container name / image only if differs from bundled defaults
```

Manual install (same result):

```bash
sudo mkdir -p /usr/local/libexec/mpc-auth
sudo install -m 0755 mpc-auth-docker-restart.sh mpc-auth-docker-update.sh /usr/local/libexec/mpc-auth/
sudo cp mpc-auth-docker.env /etc/default/mpc-auth-docker
sudoedit /etc/default/mpc-auth-docker   # tweak MPC_AUTH_CONTAINER_NAME / MPC_AUTH_IMAGE if your `docker ps` NAMES differ

sudo cp mpc-auth-docker-restart.service mpc-auth-docker-update@.service /etc/systemd/system/
sudo systemctl daemon-reload
```

### Run

```bash
# 1) Drain (API), 2) POST /updateMpcAuth { tag } → copy Data.registryDigest to /etc/default:
#    MPC_AUTH_EXPECTED_DIGEST=sha256:...
# 3) Then (example tag v1.0):
sudo systemctl start 'mpc-auth-docker-update@v1.0.service'

# Simple restart (same image) after maintenance gate — no registry pull:
sudo systemctl start mpc-auth-docker-restart.service

# Update without API digest (warns; skips check) — avoid in production:
sudo systemctl start 'mpc-auth-docker-update@latest.service'
```

Invoke the update unit with the **same** tag passed to **`POST /updateMpcAuth`**. Alternatively run the script directly:

`/usr/local/libexec/mpc-auth/mpc-auth-docker-update.sh v1.0 sha256:…`

### Troubleshooting restart failures

If **`systemctl start mpc-auth-docker-restart.service`** fails but **`sudo docker ps`** shows your app container:

1. **`docker ps` NAMES** must equal **`MPC_AUTH_CONTAINER_NAME`** in **`/etc/default/mpc-auth-docker`**, unless the restart script finds a **single** container whose **Image** column contains **`mpc-auth`** — then it uses that automatically (Compose project prefixes differ by clone path; e.g. **`otherdir_app_1`** vs **`mpc-config_app_1`**). If **more than one** **`mpc-auth`** image container exists, set **`MPC_AUTH_CONTAINER_NAME`** explicitly.
2. **`MPC_AUTH_RESTART_STRICT=1`** in **`/etc/default/mpc-auth-docker`** disables that auto-pick and always uses **`MPC_AUTH_CONTAINER_NAME`** only.
3. Re-sync defaults: **`sudo nano /etc/default/mpc-auth-docker`**, set **`MPC_AUTH_CONTAINER_NAME`** to your **`NAMES`** column exactly, **or** re-run **`install-mpc-auth-docker-systemd.sh`** **without** **`--no-env`** after pulling this repo so the bundled env replaces the old file (**back up** first).
4. After changing the script under **`/usr/local/libexec/mpc-auth/`**, ensure you copied the updated **`mpc-auth-docker-restart.sh`** from this repo (install script or **`sudo install -m 0755 ...`**).

## Permissions

- Default units assume **root** can use the Docker socket. If your policy uses the **docker** group without root, add `Group=docker` (and appropriate `User=`) in a **drop-in** under `/etc/systemd/system/…d/`.
