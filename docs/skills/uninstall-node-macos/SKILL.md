---
name: uninstall-node-macos
description: >-
  Uninstall a ContinuumDAO MPC / MPA wallet node on macOS (Docker Desktop),
  locally or over SSH, or use a Mac to uninstall a remote Linux VPS. Use when
  the operator asks to uninstall, remove, decommission, wipe, or delete a macOS
  node, LaunchAgent, or a VPS node from a Mac.
---

# Uninstall a macOS node

Harness-agnostic. Published page: https://docs.continuumdao.org/ContinuumDAO/MPAWallet/Uninstall

**Local script:** [`scripts/uninstall-node-macos-docker-desktop.sh`](../../../scripts/uninstall-node-macos-docker-desktop.sh)  
**Raw URL:** `https://raw.githubusercontent.com/ContinuumDAO/mpc-config/main/scripts/uninstall-node-macos-docker-desktop.sh`  
**Remote VPS:** use the [Linux skill](../uninstall-node-linux/SKILL.md) over SSH.

Refuses Linux and WSL (prints the correct script).

Desktop installs do **not** create an `mpcnode` OS user. Repo is `~/mpc-config`.

## Mandatory preflight

Do **not** run `--yes` until the operator confirmed **backup** (bootstrap + DB, separate stores), **eject**, or **asset transfer**. Warn that other KeyGen nodes may miss the **TSS signing threshold** (2-of-2 freezes; 2-of-3 can continue).

- [Backup and restoration](https://docs.continuumdao.org/ContinuumDAO/MPAWallet/BackupAndRestoration)
- [Eject to Private Key](https://docs.continuumdao.org/ContinuumDAO/MPAWallet/EjectConversion)

## Local (this Mac)

Docker Desktop must be running. Run as **root**:

```bash
curl -fsSL "https://raw.githubusercontent.com/ContinuumDAO/mpc-config/main/scripts/uninstall-node-macos-docker-desktop.sh" \
  | sudo bash -s -- --yes
```

From a clone: `sudo ./scripts/uninstall-node-macos-docker-desktop.sh --yes`

The script stops the pending watcher, `launchctl bootout` of `com.continuumdao.mpc-auth-watcher`, removes `~/Library/LaunchAgents/com.continuumdao.mpc-auth-watcher.plist`, then images / `/var/lib/mpc-auth-docker` / `~/mpc-config`.

Optional: `docker extension rm continuumdao/continuum-node-installer`

## Remote (SSH login — not a tunnel)

This is an **SSH login**, not `ssh -N -L` (that tunnel is for MCP / attach). Do not use `curl | ssh bash -s`.

**Linux VPS from this Mac:**

1. **Ask** for the VPS **public IPv4**. Do not invent an IP.
2. After preflight, give **one** copy-paste line with that IPv4 filled in. They run it **on this Mac** (Terminal):

```bash
ssh -o StrictHostKeyChecking=accept-new root@203.0.113.50 \
  'curl -fsSL "https://raw.githubusercontent.com/ContinuumDAO/mpc-config/main/scripts/uninstall-node-debian-ubuntu.sh" | bash -s -- --yes'
```

**Remote Mac:** ask for that Mac’s reachable IPv4 (or hostname), SSH in, then run the **local** script (LaunchAgent is per-user; sudo uses `SUDO_USER` for `~/Library/LaunchAgents`).

## What it removes / leaves

Removes: compose stack, Continuum images, LaunchAgent, watcher, `/var/lib/mpc-auth-docker`, `~/mpc-config`.

Leaves: Docker Desktop, Homebrew packages, the macOS login user.

## Verify

- `docker ps` — no `mpc-config-*` containers
- `test ! -d ~/mpc-config`
- `test ! -f ~/Library/LaunchAgents/com.continuumdao.mpc-auth-watcher.plist`

## Other OS

- Linux/VPS: [`../uninstall-node-linux/SKILL.md`](../uninstall-node-linux/SKILL.md)
- Windows/WSL: [`../uninstall-node-windows/SKILL.md`](../uninstall-node-windows/SKILL.md)
- Router: [`../../UNINSTALL_NODE.md`](../../UNINSTALL_NODE.md)
