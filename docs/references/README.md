# References Index

This directory contains reference docs for node APIs, agent workflows, and local schemas. The bundled **Open Claw** skill (**mpa-wallet**) that ties these together is **[`../skill/SKILL.md`](../skill/SKILL.md)**; session bootstrap is **[`./AI_AGENT_NEW_SESSION.md`](./AI_AGENT_NEW_SESSION.md)**.

## Markdown Documents

| File | Description |
|------|-------------|
| `../CONFIGURING_ED25519_KEYS.md` | Node owner: Ed25519 **`PublicMgtKey`**, **`addManagementKey`**, private key storage (operational signing: `./ED25519_MANAGEMENT_KEY_SIGNING.md`). |
| `./ED25519_MANAGEMENT_KEY_SIGNING.md` | Ed25519 management API signing for agents (allow-list, nonces, KeyGen `ClientKeys`). |
| `./AI_AGENT_COMPOSE_MULTISIGNREQUEST.md` | Authoritative guide for **`multiSignRequest`** payloads: recipes, compose + Foundry helpers, **`multiSignJoin`**, **`messageToSign`** rules. |
| `./AI_AGENT_FORGE_SIGNREQUEST.md` | Foundry broadcast JSON → **`bodyForSign`** / **`messageToSign`** (same envelope as compose). |
| `./AI_AGENT_NEW_SESSION.md` | Agent startup: read `$MPA_PATH/.env`, symlinks to `MPC_CONFIG_PATH`, `GET /health`, then `KEYGEN_ID` or KeyGen creation. |
| `./API_IMPLEMENTATION.md` | Full management API behavior, endpoint contracts, and conventions. § **`POST /triggerSignRequestById`** documents **EVM** trigger (**`txParams`/`messageHash`/`txParamsBatch`**) for supported automation (**executeSignResult.py**, **continuumdao-node-app**). |
| `$MPA_PATH/scripts/mpc_sign_request_digest.py` | Reserved hook for future non–unsigned-tx trigger rules; digest-only detection is currently disabled (automation always uses standard EVM trigger fields). |
| `./API_KEYGEN_MESSAGING.md` | KeyGen-scoped messaging API model and endpoint usage. |
| `./instructions.md` | End-to-end operational instructions for agent-managed node workflows. |
| `./KNOWN_ADDRESSES_SCHEMA.md` | Local storage schema for known addresses. |
| `./TOKEN_STORAGE_SCHEMA.md` | Local storage schema for token configuration data. |

## Tools (under `mpc-config/tools/`)

Small CLIs live next to **`scripts/`** and **`recipes/`** at the **mpc-config** repo root. The main index for Ed25519-related tools is **[`./ED25519_MANAGEMENT_KEY_SIGNING.md`](./ED25519_MANAGEMENT_KEY_SIGNING.md)** § **6. Tools** (`sign-clipboard`, **`ed25519_private_to_pubkey_hex.py`**, **`check_ed25519_mgt_keygen.py`**). **`check_ed25519_mgt_keygen.py`** validates a management private key against **`getAllowedEd25519MgtKeys`** and a KeyGen’s **`ClientKeys`** (see that doc **§8** troubleshooting).

## API Specification

| File | Description |
|------|-------------|
| **`./swagger.yaml`** · **`./swagger.json`** | OpenAPI/Swagger schema for the management API. **Canonical copy lives in the mpc-auth repo:** run `python3 scripts/generate_management_swagger.py` there, then run **`./scripts/sync_swagger_from_mpc_auth.sh`** from the mpc-config repo root (or copy **`swagger.json`** / **`swagger.yaml`** into **`docs/references/`** and **`docs/`** yourself). |
