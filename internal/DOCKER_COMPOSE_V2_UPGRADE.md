# Upgrading the host to Docker Compose V2

Node operators running **`docker-compose`** (Python **1.29.x** from Debian/Ubuntu) on a current **Docker Engine** often hit:

```text
KeyError: 'ContainerConfig'
```

when Compose **recreates** containers (e.g. `app` after an image update). That is a known **docker-compose v1** incompatibility with modern image/engine APIs.

**Fix:** install the **Compose V2 plugin** and use **`docker compose`** (space — a Docker CLI plugin), not **`docker-compose`** (hyphen — legacy standalone).

The mpc-config **`systemd`** scripts try **`docker compose` first** and only fall back to **`docker-compose`**; installing V2 removes the failure mode for normal upgrades.

---

## 1. See what you have

```bash
docker --version
docker compose version    # V2 plugin — may say “not found” if not installed
docker-compose --version    # legacy v1 — often 1.29.x on Ubuntu/Debian
```

- If **`docker compose version`** prints a version (e.g. `v2.x.x`), you are done; use **`docker compose`** everywhere below.
- If only **`docker-compose`** works, continue with §2.

---

## 2. Install Compose V2 (plugin)

### If you see `E: Unable to locate package docker-compose-plugin`

That package is **not** in Ubuntu’s/Debian’s **default** apt sources. It is published in **Docker’s official apt repository**. You must either add that repository, use Ubuntu’s optional **`docker-compose-v2`** package (if available), or install the plugin **manually** (§2.D).

---

Pick the path that matches your host.

### A. Docker already installed from Docker’s repository (`docker-ce`)

If you followed [Install Docker Engine on Ubuntu](https://docs.docker.com/engine/install/ubuntu/) or [Debian](https://docs.docker.com/engine/install/debian/), the repo is already configured:

```bash
sudo apt-get update
sudo apt-get install docker-compose-plugin
```

### B. Add Docker’s apt repository, then install the plugin (typical fix for “unable to locate package”)

Use this when Docker came from **`apt install docker.io`** (Ubuntu/Debian archive) or otherwise **without** `docker.list`.

**Ubuntu** — copy the “Set up Docker’s apt repository” steps from Docker’s guide (summary):

```bash
sudo apt-get update
sudo apt-get install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Replace $UBUNTU_CODENAME with your release: jammy, noble, etc. (must match /etc/os-release)
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${UBUNTU_CODENAME:-$( . /etc/os-release && echo "$VERSION_CODENAME" )} stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install docker-compose-plugin
```

**Debian** — same idea; use Docker’s [Debian install](https://docs.docker.com/engine/install/debian/) URLs (`https://download.docker.com/linux/debian`, keyring steps as in that page) and your codename (`bookworm`, `trixie`, …).

**Derivatives** (Linux Mint, Pop!\_OS, etc.): set the codename to the **Ubuntu/Debian base** your derivative tracks, or follow Docker’s docs for that distro — wrong codename yields empty package lists.

After install, **`docker compose version`** must work. Your existing **`docker.io`** engine usually continues to work alongside **`docker-compose-plugin`**; if apt proposes removing/replacing the engine, read the prompt carefully or install the plugin manually (§2.D) instead.

### C. Ubuntu archive only: try `docker-compose-v2`

On some releases this exists **without** Docker’s repo (`universe` may need to be enabled):

```bash
sudo apt-get update
sudo apt-get install docker-compose-v2
docker compose version
```

If this package is also missing, use **§2.B** or **§2.D**.

### D. Manual plugin binary (no extra apt repository)

Works with **`docker.io`** from Debian/Ubuntu. Install Compose as a CLI plugin under Docker’s plugin directory so **`docker compose`** invokes it. Versions and checksums: [Compose releases](https://github.com/docker/compose/releases).

**Example (x86_64):** downloads the **current latest** v2 release from GitHub:

```bash
DOCKER_CONFIG=${DOCKER_CONFIG:-$HOME/.docker}
mkdir -p "$DOCKER_CONFIG/cli-plugins"
curl -fSL "https://github.com/docker/compose/releases/latest/download/docker-compose-linux-x86_64" \
  -o "$DOCKER_CONFIG/cli-plugins/docker-compose"
chmod +x "$DOCKER_CONFIG/cli-plugins/docker-compose"
docker compose version
```

For **system-wide** (all users, including **sudo** without a home plugin):

```bash
sudo mkdir -p /usr/local/lib/docker/cli-plugins
sudo curl -fSL "https://github.com/docker/compose/releases/latest/download/docker-compose-linux-x86_64" \
  -o /usr/local/lib/docker/cli-plugins/docker-compose
sudo chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
sudo docker compose version
```

On **ARM64**, replace **`linux-x86_64`** with **`linux-aarch64`** (`uname -m` → `aarch64`). To pin a specific version, use a tag URL from [Compose releases](https://github.com/docker/compose/releases) instead of **`/latest/download/`**.

Official overview: [Install Docker Compose — Linux](https://docs.docker.com/compose/install/linux/).

---

## 3. Verify

```bash
docker compose version
```

Expect **v2.x**. Then from your compose project directory (e.g. **`~/mpc-config`**):

```bash
cd ~/mpc-config   # or your clone path
sudo docker compose up -d
```

Use **`docker compose`** (with a space) for all project commands: `up`, `down`, `ps`, `logs`, etc.

---

## 4. Legacy `docker-compose` (v1) on PATH

Having **both** installed is fine. The **V2** command is **`docker compose`**; the old binary is often **`/usr/bin/docker-compose`**.

- **Do not** rely on **`docker-compose up`** on modern engines for **recreating** services; use **`docker compose up`**.
- You may **`sudo apt remove docker-compose`** **only if** nothing else on the host depends on the distro package — optional cleanup, not required.

---

## 5. mpc-config-specific notes

- **`systemd/mpc-auth-docker-update.sh`** runs **`docker compose`** when the plugin is present; install V2 on the **host** so automated mpc-auth image updates do not fall through to buggy v1.
- Compose files in this repo are compatible with **Compose V2**; no file format change is required for typical `docker-compose.yml` usage.
- Official reference: [Install Docker Compose](https://docs.docker.com/compose/install/linux/).

---

## 6. If `app` is stuck after past v1 errors

After V2 is installed:

```bash
cd ~/mpc-config
sudo docker compose ps -a
```

If an **`app`** container is **dead** or half-recreated, you can remove **only** that container and bring the stack up again (Mongo data is unchanged if **`./data/mongodb`** bind mount is intact):

```bash
sudo docker rm -f <app_container_name_or_id>
sudo docker compose up -d
```

Use **`docker compose`**, not **`docker-compose`**, for the above.
