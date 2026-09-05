---
title: Uninstall an MPC / MPA node
audience: ai-agent
task: uninstall-mpc-node
keywords:
  - uninstall node
  - remove node
  - decommission
  - wipe mpcnode
  - MPA wallet
primary_script: scripts/uninstall-node-debian-ubuntu.sh
raw_url: https://raw.githubusercontent.com/ContinuumDAO/mpc-config/main/scripts/uninstall-node-debian-ubuntu.sh
repo: https://github.com/ContinuumDAO/mpc-config
user_docs: https://docs.continuumdao.org/ContinuumDAO/MPAWallet/Uninstall
backup_docs: https://docs.continuumdao.org/ContinuumDAO/MPAWallet/BackupAndRestoration
eject_docs: https://docs.continuumdao.org/ContinuumDAO/MPAWallet/EjectConversion
---

# Uninstall a node (for AI agents)

**If your task is to uninstall / remove / decommission a Continuum MPA node, start here.** Load the OS skill that matches the **operator’s machine** (or the target host). Do not invent ad-hoc `rm` / `docker system prune` steps.

## Before any delete

Tell the operator they must do **one** of:

1. **Back up** the bootstrap key pair **and** an encrypted database backup — store them in **separate** places. [Backup and restoration](https://docs.continuumdao.org/ContinuumDAO/MPAWallet/BackupAndRestoration)
2. **Eject** KeyGens. [Eject to Private Key](https://docs.continuumdao.org/ContinuumDAO/MPAWallet/EjectConversion)
3. **Transfer** all assets to another wallet.

Then: if they delete this node, other nodes in the KeyGen may **not reach the TSS signing threshold**. A 2-of-2 wallet freezes; 2-of-3 can still sign if the other two remain.

Scripts print this even with `--yes`. You may skip interactive prompts with `--yes` **only after** the operator confirmed.

## Choose a skill

| Target | Skill | Script |
|--------|--------|--------|
| Linux VPS or Linux Docker Desktop | [`docs/skills/uninstall-node-linux/SKILL.md`](skills/uninstall-node-linux/SKILL.md) | [`scripts/uninstall-node-debian-ubuntu.sh`](../scripts/uninstall-node-debian-ubuntu.sh) |
| Windows + WSL + Docker Desktop | [`docs/skills/uninstall-node-windows/SKILL.md`](skills/uninstall-node-windows/SKILL.md) | [`scripts/uninstall-node-docker-desktop.sh`](../scripts/uninstall-node-docker-desktop.sh) |
| macOS Docker Desktop | [`docs/skills/uninstall-node-macos/SKILL.md`](skills/uninstall-node-macos/SKILL.md) | [`scripts/uninstall-node-macos-docker-desktop.sh`](../scripts/uninstall-node-macos-docker-desktop.sh) |

Each script **checks the host OS** (`linux` / `wsl` / `macos`) and exits with the correct script name if you ran the wrong one.

**Remote VPS from any OS:** **ask** for the public IPv4, then give one copy-paste **SSH login** (not an `ssh -N -L` tunnel). Curl runs **on** the VPS as `root@`. Skills for Windows/macOS document that path.

## Minimal VPS command (root on the server)

```bash
curl -fsSL "https://raw.githubusercontent.com/ContinuumDAO/mpc-config/main/scripts/uninstall-node-debian-ubuntu.sh" \
  | bash -s -- --yes
```

From an operator PC — **ask for the IPv4 first**, then substitute it (example `203.0.113.50`):

```bash
ssh -o StrictHostKeyChecking=accept-new root@203.0.113.50 \
  'curl -fsSL "https://raw.githubusercontent.com/ContinuumDAO/mpc-config/main/scripts/uninstall-node-debian-ubuntu.sh" | bash -s -- --yes'
```

Preview: `--dry-run`. Interactive (human): omit `--yes`.

## Scope

**Removes:** compose stack, Continuum Docker images, systemd / LaunchAgent / Scheduled Tasks, `/var/lib/mpc-auth-docker`, `mpc-config` folder, VPS `mpcnode` user.

**Leaves:** Docker Engine / Docker Desktop, UFW, WireGuard, Homebrew, apt packages.

Systemd-helpers-only (keep the node): [`scripts/uninstall-mpc-auth-docker-systemd.sh`](../scripts/uninstall-mpc-auth-docker-systemd.sh).

## Related

- [AGENTS.md](../AGENTS.md)
- [CREATE_NODE_ONESHOT.md](CREATE_NODE_ONESHOT.md) — install, not uninstall
- Published: https://docs.continuumdao.org/ContinuumDAO/MPAWallet/Uninstall
