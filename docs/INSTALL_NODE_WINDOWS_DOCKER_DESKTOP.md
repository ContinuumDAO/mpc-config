# Install a Continuum node on Windows 11 (Docker Desktop + WSL2)

This guide walks through installing a local Continuum MPC node on **Windows 11** using **WSL2** and **Docker Desktop**, via the **Continuum Node** Docker extension. After install, day‑to‑day use matches other platforms — this document ends once the node is running and you can open the local dashboard.

## Overview

| Component | Role |
|-----------|------|
| **WSL2** | Linux environment where the extension clones `~/mpc-config` and runs install scripts |
| **Docker Desktop** | Container engine; integrates with your default WSL distro |
| **Continuum Node extension** | Wizard UI for keys, public IP, and one-click install |

Canonical config path on disk: **`~/mpc-config`** inside your WSL distro (Windows Explorer: `\\wsl$\<Distro>\home\<user>\mpc-config`).

---

## 1. Install WSL2 and a Linux distro

On **Windows 11**, open **PowerShell** or **Terminal** as Administrator and install WSL with a recent Ubuntu image (example below uses **Ubuntu 26.04**; any recent **Debian-based** distro such as Ubuntu 24.04 LTS is fine):

```powershell
wsl --install -d Ubuntu-26.04
```

If WSL is already installed, list distros and install another:

```powershell
wsl --list --online
wsl --install -d Ubuntu-26.04
```

Reboot if Windows asks you to.

### Create your Linux user

The first launch of the distro opens a console and prompts you to create a **username** and **password**. **Write down the username** — you need it in the next steps. Example: `mpcnode`.

Verify WSL2:

```powershell
wsl -l -v
```

Your distro should show **VERSION 2**. If it shows 1, convert it:

```powershell
wsl --set-version Ubuntu-26.04 2
```

---

## 2. Install Docker Desktop for Windows

1. Download and install [Docker Desktop for Windows](https://www.docker.com/products/docker-desktop/).
2. Start Docker Desktop and complete first-run setup (WSL 2 backend is recommended).
3. Sign in to Docker if you use Docker Hub features (optional for this install).

---

## 3. Enable passwordless sudo for your WSL user

The extension install path may run `sudo` steps inside WSL. Configure **passwordless sudo** for the user you created in step 1.

1. Open your distro as **root** (from PowerShell):

   ```powershell
   wsl -d Ubuntu-26.04 -u root
   ```

   Adjust the distro name if yours differs (`wsl -l -v`).

2. Edit sudoers safely:

   ```bash
   visudo
   ```

3. Scroll to the **bottom** of the file and add one line (replace `YOUR_USERNAME` with your actual user):

   ```
   YOUR_USERNAME ALL=(ALL:ALL) NOPASSWD: ALL
   ```

   Example:

   ```
   mpcnode ALL=(ALL:ALL) NOPASSWD: ALL
   ```

4. Save and exit (`Ctrl+O`, `Enter`, `Ctrl+X` in nano, or `:wq` in vim).

5. Leave the root session:

   ```bash
   exit
   ```

6. Open WSL as your normal user (exit and re-open the distro, or from PowerShell):

   ```powershell
   wsl -d Ubuntu-26.04 -u YOUR_USERNAME
   ```

---

## 4. Install the Continuum Node extension (as your user)

In WSL, **as your regular user** (not root), install the extension image so Docker Desktop can load it:

```bash
docker extension install continuumdao/continuum-node-installer:0.1.18
```

Ensure Docker Desktop is running before you run this command.

---

## 5. Configure Docker Desktop

Open **Docker Desktop → Settings**.

### General

| Setting | Value |
|---------|--------|
| **Start Docker Desktop when you sign in to your computer** | **Enabled** |
| **Open Docker Dashboard when Docker Desktop starts** | **Disabled** (optional preference) |
| **Use the WSL 2 based engine** | **Enabled** |

### Extensions

Under **Settings → Extensions**, ensure **Docker Extensions** are **enabled**. If you did not install `continuum-node-installer` over the marketplace (as in our case), you will need to disable **Allow only Marketplace extensions**.

### WSL integration

**Settings → Resources → WSL integration**

| Setting | Value |
|---------|--------|
| **Enable integration with my default WSL distro** | **Enabled** |
| Integration for your Ubuntu distro (e.g. Ubuntu-26.04) | **Enabled** |

Click **Apply & restart** if prompted.

---

## 6. Run the Continuum Node extension

1. In Docker Desktop, open **Extensions → Continuum Node**.
2. Fill in the wizard:
   - **Ethereum node management key** (optional) — your `0x…` 20-byte NodeMgtKey if you already have one; omit for a new node to auto-generate bootstrap material.
   - **Public management key** (optional) — Ed25519 public key for restore/migrate scenarios.
   - **Public IPv4 of this machine** — the address peers use on the internet.

### Find your public IPv4

Open [https://ip.me](https://ip.me) in a browser on the same network as the PC, or run in WSL:

```bash
curl -fsSL https://ip.me
```

Enter that IPv4 in the extension. It must match what other nodes will use in `nodeAddresses` (not a private `192.168.x.x` or `10.x.x.x` address).

### Home / office PC behind a router

If this machine sits on a **local network** (not a cloud VPS), remote peers reach you via your **router’s WAN IP**. You must forward ports from the router to this PC.

Follow **[PORT_FORWARDING_HOME_NETWORK.md](./PORT_FORWARDING_HOME_NETWORK.md)** to:

1. **Reserve a LAN IP** for your PC’s MAC address (DHCP reservation).
2. Add **NAT / port forwarding** to that LAN IP for:
   - **18080** (`continuum-public-discovery`)
   - **8883** (`continuum-mqtt`, relay nodes only)

Complete router setup before or immediately after install so discovery and MQTT work for remote peers.

3. Click **Install** in the extension and wait for the progress log to finish. The stack (mongo, mpc-auth, continuum-mcp, continuumdao-node-app) appears under **Docker Desktop → Containers**.

---

## 7. Open the local node dashboard

In a browser on this PC, open:

**http://localhost:3333**

(or **http://127.0.0.1:3333**)

To attach and manage the node you will need:

- The **Ethereum address** configured as your node management key — connect a browser wallet (for example MetaMask) with that account on this page.
- Your **external WAN IPv4** from step 6 (the same value you gave the installer), when the app asks for the node’s public address.

Back up **`~/mpc-config/bootstrap_key/`** in WSL if the install generated new key material.

---

## Windows-specific maintenance (optional)

- **Config and compose**: `~/mpc-config` in WSL (`docker compose` commands run from that directory).
- **Auto-restart watcher**: after extension install, a Windows logon task may run `~/mpc-config/wsl-desktop/start-watcher.sh`. Status: `~/mpc-config/wsl-desktop/status-watcher.sh`.
- **Manual restart**: `cd ~/mpc-config && docker compose restart app`

Details: [`docker-extension/README.md`](../docker-extension/README.md).

---

## From here — same as every other OS

Once the node is installed and you can use **localhost:3333**, follow the standard Continuum workflow:

- Attach and operate the node from the hosted app at [https://mpa.continuumdao.org](https://mpa.continuumdao.org), or continue via the local dashboard.
- Peer configuration, maintenance updates, and MPC group setup are **not Windows-specific** — see the main **[README.md](../README.md)** and **[API documentation](./references/API_IMPLEMENTATION.md)**.

**This Windows install guide ends here.**

---

## Troubleshooting

| Issue | What to check |
|-------|----------------|
| `this installer requires WSL2` | Run install from inside WSL, not PowerShell-only |
| `docker info` fails | Start Docker Desktop; confirm WSL integration is on |
| Install hangs on `sudo` | Passwordless sudo line in `visudo` for your user |
| Extension not listed | Re-run `docker extension install …`; enable Extensions in Settings |
| Remote peers cannot connect | [Port forwarding guide](./PORT_FORWARDING_HOME_NETWORK.md), Windows Firewall, correct public IP |
| `configs.yaml already exists` | Fresh install only; use Maintenance in the node app for updates |

For extension build notes and manual WSL install without the UI: [`docker-extension/README.md`](../docker-extension/README.md).
