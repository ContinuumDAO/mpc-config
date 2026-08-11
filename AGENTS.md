# Agent notes — ContinuumDAO mpc-config

This repository configures and installs **mpc-auth** MPC / MPA wallet nodes.

## Create a node (read this first)

**Task keywords:** create node, install node, provision VPS, one-shot install, bootstrap mpcnode, deploy MPA wallet node.

| | |
|--|--|
| **Canonical guide** | [`docs/CREATE_NODE_ONESHOT.md`](docs/CREATE_NODE_ONESHOT.md) |
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

## Other common agent paths

| Task | Where |
|------|--------|
| Day-to-day agent operation (already installed node) | [AI harness](https://docs.continuumdao.org/ContinuumDAO/MPAWallet/AIHarness/Overview), [Configure](https://docs.continuumdao.org/ContinuumDAO/MPAWallet/AIHarness/Configure), [`agent_llm_config.defaults/Skills/`](agent_llm_config.defaults/Skills/) |
| Management API | [`docs/references/API_IMPLEMENTATION.md`](docs/references/API_IMPLEMENTATION.md) |
| Ed25519 management keys | [`docs/CONFIGURING_ED25519_KEYS.md`](docs/CONFIGURING_ED25519_KEYS.md), [`docs/references/ED25519_MANAGEMENT_KEY_SIGNING.md`](docs/references/ED25519_MANAGEMENT_KEY_SIGNING.md) |
| Agent hooks / webhooks | [`docs/AGENT_HOOKS.md`](docs/AGENT_HOOKS.md) |
| Telegram / ngrok | [Telegram Mini App](https://docs.continuumdao.org/ContinuumDAO/MPAWallet/AIHarness/TelegramMiniApp) (user); [`docs/TELEGRAM_WEBHOOK_NGROK.md`](docs/TELEGRAM_WEBHOOK_NGROK.md) (operator) |
| Docker Desktop (not VPS curl) | [`docs/INSTALL_NODE_WINDOWS_DOCKER_DESKTOP.md`](docs/INSTALL_NODE_WINDOWS_DOCKER_DESKTOP.md), [`docs/INSTALL_NODE_MACOS_DOCKER_DESKTOP.md`](docs/INSTALL_NODE_MACOS_DOCKER_DESKTOP.md) |
