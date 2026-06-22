# Install a Continuum MPC node on macOS (Docker Desktop)

End-user guide for a **local macOS** node using [Docker Desktop](https://www.docker.com/products/docker-desktop/). Remote VPS installs use the [Debian/Ubuntu one-shot script](../scripts/install-node-debian-ubuntu.sh).

## Recommended: Docker Desktop Extension

1. Install and start **Docker Desktop for Mac**.
2. **Settings → Extensions** — enable Docker Extensions.
3. Install the **Continuum Node** extension (`continuumdao/continuum-node-installer`) from the Marketplace or sideload a build (see [docker-extension/README.md](../docker-extension/README.md)).
4. Open the extension, enter your management key and public IPv4, and click **Install node**.

The extension clones mpc-config to `~/mpc-config`, provisions configs and certificates, starts `docker compose`, and registers a **launchd LaunchAgent** for maintenance (image update / restart / VPN).

## Alternative: shell install (Terminal)

```bash
curl -fsSL "https://raw.githubusercontent.com/ContinuumDAO/mpc-config/main/scripts/install-node-macos-docker-desktop.sh" \
  | bash -s -- \
      --node-mgt-key "0xYOUR40HEX…" \
      --ip "YOUR_PUBLIC_IP"
```

Or via the orchestrator:

```bash
curl -fsSL "https://raw.githubusercontent.com/ContinuumDAO/mpc-config/main/scripts/desktop-local-orchestrate.sh" \
  -o /tmp/continuum-desktop-orchestrate.sh
bash /tmp/continuum-desktop-orchestrate.sh --profile macos --node-mgt-key "0x…" --ip "YOUR_PUBLIC_IP"
```

## Prerequisites

- Docker Desktop with **docker compose v2**
- **Homebrew** (recommended): `brew install python@3 yq wireguard-tools socat`
- **Passwordless sudo** for extension-driven install (creates `/var/lib/mpc-auth-docker`). On macOS the default `%admin` rule requires a password — add a NOPASSWD line in `/etc/sudoers.d/` (loaded after the main sudoers file):

  ```bash
  sudo visudo -f /etc/sudoers.d/$(whoami)
  # Add: youruser ALL=(ALL) NOPASSWD: ALL
  sudo -k
  sudo -n true && echo OK
  ```

## After install

1. Attach at [mpa.continuumdao.org](https://mpa.continuumdao.org).
2. Back up `~/mpc-config/bootstrap_key/` if a new PublicMgtKey was generated.
3. Maintenance **Restart node service** uses the macOS pending-update watcher:

   ```bash
   ~/mpc-config/macos-desktop/status-watcher.sh
   tail -f ~/mpc-config/macos-desktop/watcher.log
   launchctl list | grep continuumdao
   ```

4. **VPN** (node app → VPN panel): allow **UDP 51820** in macOS firewall for WireGuard.

Host **reboot** from Maintenance is not available on macOS local nodes (use Restart node service).

## Manual fallback

```bash
cd ~/mpc-config
docker compose restart app
```
