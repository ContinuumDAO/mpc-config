# user_folder

Writable directory bind-mounted to `/app/user_folder` in the mpc-auth `app` container.

Writes must land in a subtree — not loose files at this root. Seeded layout (on first native-tool / API use):

| Path | Purpose |
|------|--------|
| `skills/`, `scripts/`, `plans/`, `data/`, `memory/` | Agent workspace |
| `evm/` | Foundry / Solidity (`foundry.toml`, `src/`, `lib/`, `out/`, `broadcast/`) |
| `solana/`, `near/`, `stellar/`, `ton/`, `sui/` | Other chain projects |
| `data/vpn/` | VPN client configs from Continuum MCP download tools |
| `.foundry/`, `.svm/` | Foundry toolchain + solc cache (`HOME` is this folder) |
| `.mcp-foundry-workspace/` | Foundry MCP project when `useUserFolder: true` |

Agent MCP servers with `useUserFolder: true` (default **foundry**) run with `HOME` set to this path so tools can persist files on the host (e.g. Foundry MCP workspace at `.mcp-foundry-workspace/`). Native `forge` belongs under `evm/`.

Created by `process_config.sh` beside `configs.yaml`. Do not commit generated artefacts (see repo `.gitignore`).

Runtime install markers for MCP servers (`runtime.uvToolPackage` in `MCP_default_servers.json` / `MCP_servers.json`) are stored under `.mcp-runtime/<server-id>/` after a successful `uv tool install`.
