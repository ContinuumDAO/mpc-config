# Browser HTTPS and `process_config.sh`

This describes what **`process_config.sh`** does for **Browser HTTPS** (TLS in front of the browser-oriented node API) and what you must configure if automation cannot merge **`configs.yaml`** for you.

## What the script sets up

- **TLS key pair** for the node’s public IP (SAN), typically under **`webTLS/config/certs/`** on the host (`browser.crt` / `browser.key`).
- **Docker** maps a listener (default **8443/tcp**) and mounts certs into the container (paths such as **`/webTLS/config/certs/browser.crt`** in **`configs.yaml`** → **`BrowserHTTPS`** block).
- **`configs.yaml` → `BrowserHTTPS`**: merged with **`python3`** and **ruamel.yaml** so existing comments in the file are preserved. Fields include **`Port`**, **`CertFile`**, **`KeyFile`**, **`AllowedOrigins`**, **`JWKSURL`**, **`ExpectedIssuer`**, **`ExpectedAudience`**, **`EnforceNodeIPClaim`**, etc.

## Dependencies

- **`python3`** must be available for the merge step. If it is missing, the script only warns: you must edit **`BrowserHTTPS`** in **`configs.yaml`** yourself (JWKS URL, issuer, cert paths, origins, audience).
- **`ruamel.yaml`** is required for YAML round-trip with comments (e.g. **`sudo apt install python3-ruamel.yaml`** on Debian/Ubuntu). The script’s **`--help`** text lists this explicitly.

## JWKS and issuer defaults (“Pattern B”)

The merge step applies **defaults aligned with the public DAO app** when fields are empty:

- **`JWKSURL`**: `https://mpa.continuumdao.org/api/node-read/jwks`
- **`ExpectedIssuer`**: `https://mpa.continuumdao.org`
- **`AllowedOrigins`**: includes `https://mpa.continuumdao.org` when none are set

If you run your **own** issuer/JWKS (standalone deployment), set **`JWKSURL`** and **`ExpectedIssuer`** in **`configs.yaml`** to your values (**“Pattern A”** in script messages).

## Regenerating certificates

- **`--force-browser-https-certs`** (or **`FORCE_REGENERATE_BROWSER_HTTPS_CERTS=1`**) allows regenerating **`browser.crt` / `browser.key`** when the IP SAN no longer matches (e.g. the VPS IP changed).

## Relay vs client nodes

- **Relay (first) node**: generates MQTT certs, enables Browser HTTPS block and Docker **8443**, does not copy the MQTT CA to other nodes unless **`--copy-certs`**.
- **Client nodes**: validate config and CA, generate a **Browser HTTPS** cert for **that** node’s IP and merge **`BrowserHTTPS`**.

## See also

- **`./process_config.sh --help`** — full argument and environment variable list.
- **`configs.yaml`** — inline comments on **`BrowserHTTPS`**.
