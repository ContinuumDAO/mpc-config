# References Index

This directory contains reference docs for node APIs, agent workflows, and local schemas. The built-in node AI harness is documented for users at [docs.continuumdao.org — AI harness](https://docs.continuumdao.org/ContinuumDAO/MPAWallet/AIHarness/Overview). Bundled runtime skills live under [`../../agent_llm_config.defaults/Skills/`](../../agent_llm_config.defaults/Skills/).

## Markdown Documents

| File | Description |
|------|-------------|
| [`../CREATE_NODE_ONESHOT.md`](../CREATE_NODE_ONESHOT.md) | **AI agents — create a node:** canonical one-shot VPS script (`scripts/install-node-debian-ubuntu.sh`). Also [`../../AGENTS.md`](../../AGENTS.md). |
| [`../UNINSTALL_NODE.md`](../UNINSTALL_NODE.md) | **AI agents — uninstall a node:** OS skills under [`../skills/`](../skills/) + `scripts/uninstall-node-*.sh`. User page: [Uninstall](https://docs.continuumdao.org/ContinuumDAO/MPAWallet/Uninstall). |
| `../CONFIGURING_ED25519_KEYS.md` | Technical lifecycle: bootstrap + added Ed25519 management keys, on-disk paths, preferred signer. User UI: [Default Ed25519 signer](https://docs.continuumdao.org/ContinuumDAO/MPAWallet/DefaultEd25519Signer). Operational signing: `./ED25519_MANAGEMENT_KEY_SIGNING.md`. |
| `./ED25519_MANAGEMENT_KEY_SIGNING.md` | Ed25519 management API signing for agents (allow-list, nonces, KeyGen `ClientKeys`). |
| `./API_IMPLEMENTATION.md` | Full management API behavior, endpoint contracts, and conventions. Includes **agent hook listener** routes on port **18090** (`POST /hooks/inbound/{webhookId}`, Telegram chart Mini App **`GET /telegram/chart/*`**). § **`POST /triggerSignRequestById`** documents **EVM** trigger (**`txParams`/`messageHash`/`txParamsBatch`**) for supported automation (**continuum-node-sdk** MCP, **continuumdao-node-app**). |
| `./API_KEYGEN_MESSAGING.md` | KeyGen-scoped messaging API model and endpoint usage. |
| [`../AGENT_HOOKS.md`](../AGENT_HOOKS.md) | **User guide:** inbound webhooks (all types), KeyGen `@agent` hooks, Plan mode, and orchestration (`mpc-orchestrate`). |
| [`../TELEGRAM_WEBHOOK_NGROK.md`](../TELEGRAM_WEBHOOK_NGROK.md) | **Telegram + free ngrok:** Agent Endpoint tunnel to hook port **18090** (Docker container network included); chart menus and **Mini App** (`GET /telegram/chart/*`) setup. User guide: [Telegram Mini App](https://docs.continuumdao.org/ContinuumDAO/MPAWallet/AIHarness/TelegramMiniApp). |
| `./KNOWN_ADDRESSES_SCHEMA.md` | Local storage schema for known addresses. |
| `./TOKEN_STORAGE_SCHEMA.md` | Local storage schema for token configuration data. |

## Tools (under `mpc-config/tools/`)

Small CLIs live next to **`scripts/`** at the **mpc-config** repo root. The main index for Ed25519-related tools is **[`./ED25519_MANAGEMENT_KEY_SIGNING.md`](./ED25519_MANAGEMENT_KEY_SIGNING.md)** § **6. Tools** (`sign-clipboard`, **`ed25519_private_to_pubkey_hex.py`**, **`check_ed25519_mgt_keygen.py`**). **`check_ed25519_mgt_keygen.py`** validates a management private key against **`getAllowedEd25519MgtKeys`** and a KeyGen’s **`ClientKeys`** (see that doc **§8** troubleshooting).

## API Specification

| File | Description |
|------|-------------|
| **`./swagger.yaml`** · **`./swagger.json`** | OpenAPI/Swagger schema for the management API. **Canonical copy lives in the mpc-auth repo:** run `python3 scripts/generate_management_swagger.py` there, then run **`./scripts/sync_swagger_from_mpc_auth.sh`** from the mpc-config repo root (or copy **`swagger.json`** / **`swagger.yaml`** into **`docs/references/`** and **`docs/`** yourself). |
