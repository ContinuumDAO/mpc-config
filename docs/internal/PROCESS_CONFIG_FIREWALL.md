# Host firewall and `process_config.sh`

By default, **`process_config.sh`** runs a **baseline `ufw`** step (when **`ufw`** is installed) so new nodes are not left wide open. This document summarizes behavior; exact ports come from **`configs.yaml`**.

## Skipping the step

- **`--no-firewall`**: skips all **`ufw allow`** logic. The script warns that this is a poor choice for production or financial MPC nodes—you should still configure **ufw**, **nftables**, or **cloud security groups** yourself.

## Ports and rules (typical defaults)

Read from **`configs.yaml`** where noted:

| Purpose | Default / source | Notes |
|--------|------------------|--------|
| SSH | **22/tcp** | Added first to reduce lockout risk if you later **`ufw enable`**. |
| Browser HTTPS | **`BrowserHTTPS.Port`** or **8443** | Public browser API (TLS). |
| Public discovery | **`PublicDiscoveryPort`** (often **18080**) | Discovery HTTP. |
| Scanner / relayer | **`ScannerRelayerPort`** (e.g. **18081**) when non-zero | Prefer **scoped** rules (see below). |
| Management API | **`ManagementAPIsPort`** (export as **`MANAGEMENT_PORT`**) | **Not** opened in **`ufw`** unless **`UFW_OPEN_MANAGEMENT_PORT=1`** — see next section. |
| MQTT TLS (relay only) | **8883/tcp** | When the node is the **relay** (`docker-compose` MQTT). |

## Management API port

By default, **`process_config.sh`** does **not** add **`ufw allow`** for **`ManagementAPIsPort`**. Use **`127.0.0.1:$MANAGEMENT_PORT:$MANAGEMENT_PORT`** in **`docker-compose`**, **SSH tunnel**, **VPN**, or **cloud security groups** for access.

To add a host **`ufw`** rule for the management port (e.g. co-located tooling or a chosen network path):

```bash
UFW_OPEN_MANAGEMENT_PORT=1 ./process_config.sh
```

## Scanner / relayer scoped rules

When **`ScannerRelayerPort`** is set and distinct from other listeners, the script tries to resolve **IPv4 sources** from:

- **`PreSigningVerification.RelayerAPIURL`**
- **`ScannerAPIURLs`** (and defaults when the list is empty)

For each resolved source it runs **`ufw allow from <ip-or-cidr> to any port <ScannerRelayerPort>`**. If **no** sources resolve (or **`python3`** is missing for resolution), the script may open the scanner/relayer port **to the world** and print a **warning**—fix **`RelayerAPIURL`** / **`ScannerAPIURLs`** or tighten rules manually.

That **`python3`** is whatever is on the **host PATH** for **`process_config.sh`**’s helper logic—not **`$MPA_PATH/.venv/bin/python`** (the MPA signing/agent venv; see **[`docs/skill/SKILL.md`](../skill/SKILL.md)** **Python dependencies**).

## Dual stack

Ubuntu often has **IPv6 enabled** in **`/etc/default/ufw`**, so a plain **`ufw allow <port>/tcp`** may add **IPv4 and IPv6** rules. Adjust manually if you need IPv4-only listeners.

## Enabling `ufw`

If **`ufw`** is **inactive**, the script warns and may prompt (when a TTY is available) to run **`sudo ufw enable`**. Confirm **SSH (22)** is allowed before enabling, or you risk locking yourself out.

## See also

- **`./process_config.sh --help`** — **Host firewall** subsection.
- **`configs.yaml`** — **`ManagementAPIsPort`**, **`PublicDiscoveryPort`**, **`BrowserHTTPS`**, **`ScannerRelayerPort`**, **`PreSigningVerification`**, **`ScannerAPIURLs`**.
