---
name: uninstall-node-linux
description: >-
  Uninstall a ContinuumDAO MPC / MPA wallet node on Linux (Ubuntu/Debian VPS or
  Linux Docker Desktop), locally or over SSH. Use when the operator asks to
  uninstall, remove, decommission, wipe, or delete a Linux node, mpcnode user,
  systemd helpers, or a remote VPS node from a Linux machine.
---

# Uninstall a Linux node

Harness-agnostic. Published page: https://docs.continuumdao.org/ContinuumDAO/MPAWallet/Uninstall

**Script:** [`scripts/uninstall-node-debian-ubuntu.sh`](../../../scripts/uninstall-node-debian-ubuntu.sh)  
**Raw URL:** `https://raw.githubusercontent.com/ContinuumDAO/mpc-config/main/scripts/uninstall-node-debian-ubuntu.sh`

Refuses WSL and macOS (prints the Windows/macOS script to use instead). VPS vs Linux Desktop is auto-detected (`mpcnode` / `/home/mpcnode/mpc-config`).

## Mandatory preflight

Do **not** run `--yes` until the operator has confirmed one of:

1. **Backup** — bootstrap key pair **and** encrypted database backup, stored in **separate** places. [Backup and restoration](https://docs.continuumdao.org/ContinuumDAO/MPAWallet/BackupAndRestoration)
2. **Eject** KeyGens. [Eject to Private Key](https://docs.continuumdao.org/ContinuumDAO/MPAWallet/EjectConversion)
3. **Transfer** all assets to another wallet.

Then warn: deleting this node can leave other KeyGen members **below the TSS signing threshold**. 2-of-2 freezes; 2-of-3 can still sign if the other two remain.

## Local (this Linux host)

**VPS (default):** repo `/home/mpcnode/mpc-config`, user `mpcnode`.

```bash
curl -fsSL "https://raw.githubusercontent.com/ContinuumDAO/mpc-config/main/scripts/uninstall-node-debian-ubuntu.sh" \
  | bash -s -- --yes
```

Or from a clone: `sudo ./scripts/uninstall-node-debian-ubuntu.sh --yes`

**Linux Docker Desktop:** repo `~/mpc-config`, do not delete the login user.

```bash
sudo ./scripts/uninstall-node-debian-ubuntu.sh --profile linux-desktop --yes
```

Preview: add `--dry-run` (omit `--yes` if they want prompts).

## Remote (SSH login — not a tunnel)

This is an **SSH login** that runs the uninstall script **on** the VPS as **root**. Do **not** give an `ssh -N -L` tunnel (that is for MCP / attach, not uninstall). Do not use `curl | ssh bash -s`.

1. **Ask** the operator for the node’s **public IPv4** (the address they used at install / peer config). Do not invent an IP.
2. After preflight (backup / eject / transfer + TSS), give **one** copy-paste line with that IPv4 filled in. They run it **on this PC** (Terminal). Substitute only the IP:

```bash
ssh -o StrictHostKeyChecking=accept-new root@203.0.113.50 \
  'curl -fsSL "https://raw.githubusercontent.com/ContinuumDAO/mpc-config/main/scripts/uninstall-node-debian-ubuntu.sh" | bash -s -- --yes'
```

User is `root@` (the script deletes `mpcnode`). Omit `--yes` only if they want the script’s prompts on the VPS (`ssh -t` so they have a TTY).

## What it removes / leaves

Removes: compose stack, Continuum images, all `mpc-auth-*` systemd units + `/usr/local/libexec/mpc-auth`, `/var/lib/mpc-auth-docker`, install logs, `mpc-config` dir, VPS `mpcnode` user + `/etc/sudoers.d/mpcnode`.

Leaves: Docker Engine, UFW, WireGuard, apt packages.

## Verify

- `docker ps` — no `mpc-config-*` containers
- `test ! -d /home/mpcnode/mpc-config` (VPS) or `test ! -d "$HOME/mpc-config"` (desktop)
- VPS: `id mpcnode` fails
- `systemctl list-unit-files | grep mpc-auth` empty

## Other OS

- Windows/WSL: [`../uninstall-node-windows/SKILL.md`](../uninstall-node-windows/SKILL.md)
- macOS: [`../uninstall-node-macos/SKILL.md`](../uninstall-node-macos/SKILL.md)
- Router: [`../../UNINSTALL_NODE.md`](../../UNINSTALL_NODE.md)
