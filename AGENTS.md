# Agent notes — ContinuumDAO mpc-config

This repository configures and installs **mpc-auth** MPC / MPA wallet nodes.

## Create a node (read this first)

**Task keywords:** create node, install node, provision VPS, one-shot install, bootstrap mpcnode, deploy MPA wallet node.

| | |
|--|--|
| **Full playbook (provision + configure)** | https://docs.continuumdao.org/ContinuumDAO/MPAWallet/AgentProvision |
| **Canonical install guide** | [`docs/CREATE_NODE_ONESHOT.md`](docs/CREATE_NODE_ONESHOT.md) |
| **One-shot script** | [`scripts/install-node-debian-ubuntu.sh`](scripts/install-node-debian-ubuntu.sh) |
| **Raw URL** | `https://raw.githubusercontent.com/ContinuumDAO/mpc-config/main/scripts/install-node-debian-ubuntu.sh` |
| **README section** | [One-shot VPS install](README.md#one-shot-vps-install) |
| **Published user docs** | https://docs.continuumdao.org/ContinuumDAO/MPAWallet/Install |

**Default action on Ubuntu/Debian VPS (as root):**

```bash
curl -fsSL "https://raw.githubusercontent.com/ContinuumDAO/mpc-config/main/scripts/install-node-debian-ubuntu.sh" \
  | bash -s -- \
      --node-mgt-key "0xYour40HexCharacters..." \
      --ip "YOUR_VPS_PUBLIC_IP"
```

Do **not** prefer the long interactive `process_config.sh` / Node Running Instructions path for a greenfield VPS unless the one-shot script is unsuitable.

## Uninstall a node

**Task keywords:** uninstall node, remove node, decommission, wipe mpcnode, delete MPA wallet node.

| | |
|--|--|
| **Published user + agent page** | https://docs.continuumdao.org/ContinuumDAO/MPAWallet/Uninstall |
| **Canonical agent guide** | [`docs/UNINSTALL_NODE.md`](docs/UNINSTALL_NODE.md) |
| **Linux skill** | [`docs/skills/uninstall-node-linux/SKILL.md`](docs/skills/uninstall-node-linux/SKILL.md) |
| **Windows skill** | [`docs/skills/uninstall-node-windows/SKILL.md`](docs/skills/uninstall-node-windows/SKILL.md) |
| **macOS skill** | [`docs/skills/uninstall-node-macos/SKILL.md`](docs/skills/uninstall-node-macos/SKILL.md) |
| **VPS script** | [`scripts/uninstall-node-debian-ubuntu.sh`](scripts/uninstall-node-debian-ubuntu.sh) |
| **Raw URL** | `https://raw.githubusercontent.com/ContinuumDAO/mpc-config/main/scripts/uninstall-node-debian-ubuntu.sh` |

Warn first: back up bootstrap + database (separate stores), **or** Eject KeyGens, **or** transfer assets. Deleting a node can leave other KeyGen members below the TSS signing threshold.

**Remote:** ask the operator for the VPS **public IPv4**, then give one copy-paste **SSH login** (not an `ssh -N -L` tunnel) with that IP filled in.

**Default action on Ubuntu/Debian VPS (as root), after the operator confirmed:**

```bash
curl -fsSL "https://raw.githubusercontent.com/ContinuumDAO/mpc-config/main/scripts/uninstall-node-debian-ubuntu.sh" \
  | bash -s -- --yes
```

From an operator PC (substitute their IPv4):

```bash
ssh -o StrictHostKeyChecking=accept-new root@THEIR_VPS_IPV4 \
  'curl -fsSL "https://raw.githubusercontent.com/ContinuumDAO/mpc-config/main/scripts/uninstall-node-debian-ubuntu.sh" | bash -s -- --yes'
```

Agents skip prompts with `--yes`. Humans omit `--yes` for interactive confirmations. Desktop: Windows [`scripts/uninstall-node-docker-desktop.sh`](scripts/uninstall-node-docker-desktop.sh), macOS [`scripts/uninstall-node-macos-docker-desktop.sh`](scripts/uninstall-node-macos-docker-desktop.sh).

## Other common agent paths

| Task | Where |
|------|--------|
| Day-to-day agent operation (already installed node) | [AI harness](https://docs.continuumdao.org/ContinuumDAO/MPAWallet/AIHarness/Overview), [Configure](https://docs.continuumdao.org/ContinuumDAO/MPAWallet/AIHarness/Configure), [`agent_llm_config.defaults/Skills/`](agent_llm_config.defaults/Skills/) |
| Management API | [`docs/references/API_IMPLEMENTATION.md`](docs/references/API_IMPLEMENTATION.md) |
| Ed25519 management keys | [`docs/CONFIGURING_ED25519_KEYS.md`](docs/CONFIGURING_ED25519_KEYS.md), [`docs/references/ED25519_MANAGEMENT_KEY_SIGNING.md`](docs/references/ED25519_MANAGEMENT_KEY_SIGNING.md) |
| Agent hooks / webhooks | [`docs/AGENT_HOOKS.md`](docs/AGENT_HOOKS.md) |
| Telegram / ngrok | [Telegram Mini App](https://docs.continuumdao.org/ContinuumDAO/MPAWallet/AIHarness/TelegramMiniApp) (user); [`docs/TELEGRAM_WEBHOOK_NGROK.md`](docs/TELEGRAM_WEBHOOK_NGROK.md) (operator) |
| Docker Desktop (not VPS curl) | [`docs/INSTALL_NODE_WINDOWS_DOCKER_DESKTOP.md`](docs/INSTALL_NODE_WINDOWS_DOCKER_DESKTOP.md), [`docs/INSTALL_NODE_MACOS_DOCKER_DESKTOP.md`](docs/INSTALL_NODE_MACOS_DOCKER_DESKTOP.md) |
