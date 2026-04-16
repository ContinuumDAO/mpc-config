# References Index

This directory contains reference docs for node APIs, agent workflows, and local schemas. The bundled **Open Claw** skill (**mpa-wallet**) that ties these together is **[`../skill/SKILL.md`](../skill/SKILL.md)**; session bootstrap is **[`./AI_AGENT_NEW_SESSION.md`](./AI_AGENT_NEW_SESSION.md)**.

## Markdown Documents

| File | Description |
|------|-------------|
| `../CONFIGURING_ED25519_KEYS.md` | Node owner: Ed25519 **`PublicMgtKey`**, **`addManagementKey`**, private key storage (operational signing: `./ED25519_MANAGEMENT_KEY_SIGNING.md`). |
| `./ED25519_MANAGEMENT_KEY_SIGNING.md` | Ed25519 management API signing for agents (allow-list, nonces, KeyGen `ClientKeys`). |
| `./AI_AGENT_COMPOSE_MULTISIGNREQUEST.md` | Authoritative guide for **`multiSignRequest`** payloads: recipes, compose + Foundry helpers, **`multiSignJoin`**, **`messageToSign`** rules. |
| `./AI_AGENT_FORGE_SIGNREQUEST.md` | Build `POST /multiSignRequest` payloads from Foundry script output. |
| `./AI_AGENT_NEW_SESSION.md` | Agent startup: read `$MPA_PATH/.env`, symlinks to `MPC_CONFIG_PATH`, `GET /health`, then `KEYGEN_ID` or KeyGen creation. |
| `./API_IMPLEMENTATION.md` | Full management API behavior, endpoint contracts, and conventions. |
| `./API_KEYGEN_MESSAGING.md` | KeyGen-scoped messaging API model and endpoint usage. |
| `./instructions.md` | End-to-end operational instructions for agent-managed node workflows. |
| `./KNOWN_ADDRESSES_SCHEMA.md` | Local storage schema for known addresses. |
| `./TOKEN_STORAGE_SCHEMA.md` | Local storage schema for token configuration data. |

## API Specification

| File | Description |
|------|-------------|
| **`./swagger.yaml`** | OpenAPI/Swagger schema for the management API. |
