---
title: Create an MPC / MPA node (one-shot install)
audience: ai-agent
task: create-mpc-node
keywords:
  - one-shot
  - install node
  - provision VPS
  - install-node-debian-ubuntu.sh
  - mpcnode
  - MPA wallet
primary_script: scripts/install-node-debian-ubuntu.sh
raw_url: https://raw.githubusercontent.com/ContinuumDAO/mpc-config/main/scripts/install-node-debian-ubuntu.sh
repo: https://github.com/ContinuumDAO/mpc-config
user_docs: https://docs.continuumdao.org/ContinuumDAO/MPAWallet/Install
agent_playbook: https://docs.continuumdao.org/ContinuumDAO/MPAWallet/AgentProvision
---

# Create a node — one-shot install (for AI agents)

**If your task is to provision and configure a node (topology, peers, MQTT, Group, KeyGen), start at [Agent provision and configure](https://docs.continuumdao.org/ContinuumDAO/MPAWallet/AgentProvision)** — this page is the **install script only**.

**If your task is only to create / install containers on an Ubuntu/Debian VPS, use this page.** Do not start from the long interactive `process_config.sh` walkthrough unless the one-shot script cannot run.

## Canonical one-shot script

| Item | Value |
|------|--------|
| **Script (repo)** | [`scripts/install-node-debian-ubuntu.sh`](../scripts/install-node-debian-ubuntu.sh) |
| **Raw URL (pipe to bash)** | `https://raw.githubusercontent.com/ContinuumDAO/mpc-config/main/scripts/install-node-debian-ubuntu.sh` |
| **Who runs it** | **root** on the target Ubuntu/Debian VPS |
| **What it does** | apt packages → user `mpcnode` → clone mpc-config → `scripts/provision-node.sh` → `docker compose up -d` |
| **Help** | `./scripts/install-node-debian-ubuntu.sh --help` |

## Minimal command (run on the VPS as root)

```bash
curl -fsSL "https://raw.githubusercontent.com/ContinuumDAO/mpc-config/main/scripts/install-node-debian-ubuntu.sh" \
  | bash -s -- \
      --node-mgt-key "0xYour40HexCharacters..." \
      --ip "YOUR_VPS_PUBLIC_IP"
```

From an operator PC (curl still runs **on** the VPS):

```bash
ssh -o StrictHostKeyChecking=accept-new root@YOUR_VPS_PUBLIC_IP \
  'curl -fsSL "https://raw.githubusercontent.com/ContinuumDAO/mpc-config/main/scripts/install-node-debian-ubuntu.sh" | bash -s -- --node-mgt-key "0xYour40HexCharacters..." --ip "YOUR_VPS_PUBLIC_IP"'
```

**Required:** at least one of `--node-mgt-key` / `-k` (Ethereum `0x` + 40 hex) or `--public-mgt-key` (Ed25519 64 hex or `ssh-ed25519 …` line).  
**Strongly recommended on VPS:** `--ip` = public IPv4 peers will use.

New node (typical): omit `--public-mgt-key` so Ed25519 bootstrap is generated; then back up bootstrap + database via the node app ([Backup and restoration](https://docs.continuumdao.org/ContinuumDAO/MPAWallet/BackupAndRestoration)).

Restore / same Node Key: pass `--public-mgt-key` and ensure `bootstrap_key/ed25519_private.hex` is available as documented in the [README](../README.md#one-shot-vps-install) and [Backup and restoration](https://docs.continuumdao.org/ContinuumDAO/MPAWallet/BackupAndRestoration).

## After install (agent checklist)

Continue the full playbook: [Agent provision and configure](https://docs.continuumdao.org/ContinuumDAO/MPAWallet/AgentProvision) — user SSH tunnel to **8446**, Path A MCP (`node_config`), peers / MQTT, Group, KeyGen, then hand-off. Do not stop at a single node.

1. Confirm containers: `docker ps` as `mpcnode` (or via root).
2. Ask the operator to tunnel `continuum-mcp` to `127.0.0.1:8446` (and **3333** for later attach).
3. Configure peers / MQTT via MCP (or the UI **Node Peer IP Editing** + Inter Node Communication). A lone node cannot create a KeyGen; prefer **2-of-3** across regions and providers (see the playbook).
4. Prefer the UI **Maintenance** path to update an existing node — the one-shot installer **refuses** if `configs.yaml` or MPC containers already exist.

## Not this script

| Goal | Use instead |
|------|-------------|
| Human / interactive install | Node map **`+`**: https://mpa.continuumdao.org/node-map — [Install](https://docs.continuumdao.org/ContinuumDAO/MPAWallet/Install) |
| Windows/macOS Docker Desktop | Extension **Continuum Node**, or `scripts/desktop-local-orchestrate.sh` / `install-node-docker-desktop.sh` — [README § Docker Desktop](../README.md#docker-desktop-windows-local) |
| Already cloned repo, only config | `scripts/provision-node.sh` then `docker compose up -d` |
| Step-by-step manual VPS | [Node Running Instructions](https://docs.continuumdao.org/ContinuumDAO/RunningInstructions/NodeRunningInstruction) |

## Related in this repo

- [README — One-shot VPS install](../README.md#one-shot-vps-install)
- [`AGENTS.md`](../AGENTS.md) — agent entrypoint for this repository
- [`scripts/provision-node.sh`](../scripts/provision-node.sh) — non-interactive config helper used by the one-shot
- Frontend command builder: `tools/provision-command.js`
