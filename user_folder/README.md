# user_folder

Writable directory bind-mounted to `/app/user_folder` in the mpc-auth `app` container.

Agent MCP servers with `useUserFolder: true` (default **foundry**) run with `HOME` set to this path so tools can persist files on the host (e.g. Foundry MCP workspace at `.mcp-foundry-workspace/`).

Created by `process_config.sh` beside `configs.yaml`. Do not commit generated artefacts (see repo `.gitignore`).

Runtime install markers for MCP servers (`runtime.uvToolPackage` in `MCP_default_servers.json` / `MCP_servers.json`) are stored under `.mcp-runtime/<server-id>/` after a successful `uv tool install`.
