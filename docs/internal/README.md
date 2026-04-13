# Internal operator notes (`docs/internal/`)

Material here supplements **`configs.yaml`** comments and **`./process_config.sh --help`**. It is **not** aimed at AI agent skills (see **`docs/references/`** for API and agent guides).

### Python on the host (two environments)

- **`process_config.sh`** (Browser HTTPS merge, firewall URL resolution, etc.) uses **system** **`python3`** with **`ruamel.yaml`** where documented—e.g. **`python3-ruamel.yaml`** on Debian/Ubuntu for YAML round-trip (**[PROCESS_CONFIG_BROWSER_HTTPS.md](./PROCESS_CONFIG_BROWSER_HTTPS.md)**). That is **not** the same tree as the MPA automation venv.
- **Signing / agent helpers** (`$MPA_PATH/scripts`, `$MPA_PATH/recipes`, …) use a dedicated venv **`$MPA_PATH/.venv`** and **`$MPA_PATH/.venv/bin/python`**. Bootstrap and packages: **[`docs/skill/SKILL.md`](../skill/SKILL.md)** **Python dependencies**.

| Document | When to read |
|----------|----------------|
| [PROCESS_CONFIG_BROWSER_HTTPS.md](./PROCESS_CONFIG_BROWSER_HTTPS.md) | Browser HTTPS (TLS for browser-facing node API), JWKS / issuer defaults, cert paths, **system `python3` + ruamel.yaml** merge step (not `$MPA_PATH/.venv`) |
| [PROCESS_CONFIG_FIREWALL.md](./PROCESS_CONFIG_FIREWALL.md) | Host **`ufw`** rules **`process_config.sh`** adds, ports, **`UFW_OPEN_MANAGEMENT_PORT`**, **`--no-firewall`** |
| [MULTI_SIGNREQUEST_DESIGN.md](./MULTI_SIGNREQUEST_DESIGN.md) | Batch **`multiSignRequest`** protocol design (signing) |

For a full list of flags and prompts, run **`./process_config.sh --help`** from the **mpc-config** repo root.
