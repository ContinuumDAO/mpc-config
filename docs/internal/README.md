# Internal operator notes (`docs/internal/`)

Material here supplements **`configs.yaml`** comments and **`./process_config.sh --help`**. It is **not** aimed at AI agent skills (see **`docs/references/`** for API and agent guides).

| Document | When to read |
|----------|----------------|
| [PROCESS_CONFIG_BROWSER_HTTPS.md](./PROCESS_CONFIG_BROWSER_HTTPS.md) | Browser HTTPS (TLS for browser-facing node API), JWKS / issuer defaults, cert paths, **`python3`** merge step |
| [PROCESS_CONFIG_FIREWALL.md](./PROCESS_CONFIG_FIREWALL.md) | Host **`ufw`** rules **`process_config.sh`** adds, ports, **`UFW_OPEN_MANAGEMENT_PORT`**, **`--no-firewall`** |
| [MULTI_SIGNREQUEST_DESIGN.md](./MULTI_SIGNREQUEST_DESIGN.md) | Batch **`multiSignRequest`** protocol design (signing) |

For a full list of flags and prompts, run **`./process_config.sh --help`** from the **mpc-config** repo root.
