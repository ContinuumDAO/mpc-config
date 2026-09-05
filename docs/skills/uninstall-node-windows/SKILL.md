---
name: uninstall-node-windows
description: >-
  Uninstall a ContinuumDAO MPC / MPA wallet node on Windows (WSL2 + Docker
  Desktop), locally or remotely, or use a Windows PC to uninstall a remote Linux
  VPS. Use when the operator asks to uninstall, remove, decommission, wipe, or
  delete a Windows / WSL node, Scheduled Tasks, or a VPS node from Windows.
---

# Uninstall a Windows (WSL) node

Harness-agnostic. Published page: https://docs.continuumdao.org/ContinuumDAO/MPAWallet/Uninstall

**Local script:** [`scripts/uninstall-node-docker-desktop.sh`](../../../scripts/uninstall-node-docker-desktop.sh)  
**Raw URL:** `https://raw.githubusercontent.com/ContinuumDAO/mpc-config/main/scripts/uninstall-node-docker-desktop.sh`  
**Remote VPS:** use the [Linux skill](../uninstall-node-linux/SKILL.md) over SSH.

Refuses native Linux and macOS (prints the correct script). Must run **inside WSL**.

Desktop installs do **not** create an `mpcnode` OS user. Repo is `~/mpc-config` inside WSL.

## Mandatory preflight

Do **not** run `--yes` until the operator confirmed **backup** (bootstrap + DB, separate stores), **eject**, or **asset transfer**. Warn that other KeyGen nodes may miss the **TSS signing threshold** (2-of-2 freezes; 2-of-3 can continue).

- [Backup and restoration](https://docs.continuumdao.org/ContinuumDAO/MPAWallet/BackupAndRestoration)
- [Eject to Private Key](https://docs.continuumdao.org/ContinuumDAO/MPAWallet/EjectConversion)

## Local (this Windows PC)

Run **as root inside WSL** (Ubuntu). Docker Desktop must be running for `docker compose down`.

```bash
curl -fsSL "https://raw.githubusercontent.com/ContinuumDAO/mpc-config/main/scripts/uninstall-node-docker-desktop.sh" \
  | sudo bash -s -- --yes
```

From a clone in WSL: `sudo ./scripts/uninstall-node-docker-desktop.sh --yes`

The script stops the WSL watcher, deletes Scheduled Tasks `ContinuumNodeMpcAuthWatcher` and `ContinuumNodeMpcAuthWatcherPoll` (via `powershell.exe`), clears the WSL `[boot] command`, removes images / `/var/lib/mpc-auth-docker` / `~/mpc-config`.

If `powershell.exe` is unavailable, give the operator these Windows commands:

```text
schtasks /Delete /TN ContinuumNodeMpcAuthWatcher /F
schtasks /Delete /TN ContinuumNodeMpcAuthWatcherPoll /F
```

Optional: `docker extension rm continuumdao/continuum-node-installer`

## Remote (SSH login — not a tunnel)

This is an **SSH login**, not `ssh -N -L` (that tunnel is for MCP / attach). Do not use `curl | ssh bash -s`.

**Linux VPS from this Windows PC** (OpenSSH in Terminal or Command Prompt):

1. **Ask** for the VPS **public IPv4**. Do not invent an IP.
2. After preflight, give **one** copy-paste line with that IPv4 filled in. They run it **on this PC**:

```bash
ssh -o StrictHostKeyChecking=accept-new root@203.0.113.50 \
  'curl -fsSL "https://raw.githubusercontent.com/ContinuumDAO/mpc-config/main/scripts/uninstall-node-debian-ubuntu.sh" | bash -s -- --yes'
```

**Remote Windows node:** ask for that PC’s reachable IPv4 (or hostname), then SSH into its WSL and run the **local** script above. Scheduled Tasks need `powershell.exe` / Windows host access — WSL-only SSH cannot delete them.

## What it removes / leaves

Removes: compose stack, Continuum images, watcher, Scheduled Tasks, WSL boot hook, `/var/lib/mpc-auth-docker`, `~/mpc-config`.

Leaves: Docker Desktop, WSL distro, the login user.

## Verify

- In WSL: `docker ps` — no `mpc-config-*` containers; `test ! -d ~/mpc-config`
- Windows: `schtasks /Query /TN ContinuumNodeMpcAuthWatcher` fails

## Other OS

- Linux/VPS: [`../uninstall-node-linux/SKILL.md`](../uninstall-node-linux/SKILL.md)
- macOS: [`../uninstall-node-macos/SKILL.md`](../uninstall-node-macos/SKILL.md)
- Router: [`../../UNINSTALL_NODE.md`](../../UNINSTALL_NODE.md)
