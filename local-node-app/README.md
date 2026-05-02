# Local ContinuumDAO node dashboard (Docker)

Run the pre-built **continuumdao/continuumdao-node-app** image next to your mpc-config stack. This is intended for **local operators** (same machine or LAN as mpc-auth), not for public hosting.

## Prerequisites

- Docker Engine and **Docker Compose v2** (`docker compose …`)
- A [Reown (WalletConnect) Cloud](https://cloud.reown.com) project (for the wallet button in the UI)

## One-time setup

From this directory:

```bash
cd local-node-app
cp .env.example .env
```

Edit `.env` and set at least **REOWN_PROJECT_ID** to your Reown project id.

### Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| **REOWN_PROJECT_ID** | Yes | Reown Cloud project id (wallet modal). |
| **ENABLE_PLAIN_HTTP_ATTACH** | Yes (local image) | Set to `1` so the attach UI offers **Plain HTTP** (local/LAN). Omit or `0` on **Railway** production so only Browser HTTPS + SSH tunnel appear. `.env.example` includes `1`. |
| **NODE_READ_DISCOVERY_ALLOW_PRIVATE** | Recommended locally | Set to `1` so the Next.js server can proxy discovery calls to **private / RFC1918 / localhost** addresses where mpc-auth usually listens in dev. |
| **NODE_READ_DISCOVERY_LOCAL_BIND_ALIASES** | No | NAT hairpin: comma-separated `PublicIPv4=127.0.0.1` (or another bind host). Lets server-side discovery proxies dial the node when `nodeAddresses` use your **WAN** IP but mpc-auth is **reached on loopback** from this stack. See below. |
| **NODE_READ_DISCOVERY_HAIRPIN_FALLBACK** | No | With **NODE_READ_DISCOVERY_ALLOW_PRIVATE=1** only: after “no route” / unreachable on a **public** IPv4, retry once via `127.0.0.1`. Dev convenience; prefer **LOCAL_BIND_ALIASES** when you know the IP. |
| **NODE_APP_IMAGE** | No | Docker image repository (default `continuumdao/continuumdao-node-app`). |
| **NODE_APP_TAG** | No | Image tag (default `latest`). |
| **NODE_APP_PORT** | No | Host port mapped to the app (default `3333` → container port `3000`). |
| **DEFAULT_NODE_DISCOVERY_PORT** | No | If set, must match your node **PublicDiscoveryPort** (often `18080`). |
| **BROWSER_HTTPS_PORT** | No | Browser HTTPS / read-JWT port if not default `8443`. |
| **MANAGEMENT_API_PORT** | No | Management API port if not default `8080`. |

The compose file also injects the whole `.env` into the container; only variables the app understands have effect. Image/pull settings (`NODE_APP_*`) are for Docker Compose substitution and are harmless inside the container.

## Scripts

Make them executable once if needed: `chmod +x *.sh`

1. **`pull-node-app.sh`** — Downloads the image (`docker pull`) using `NODE_APP_IMAGE` and `NODE_APP_TAG` from `.env`.

2. **`install-or-update-node-app.sh`** — First run: creates `.env` from `.env.example` if missing (then exits so you can edit). Next runs: **pull + `docker compose up -d --force-recreate`**. Use this after publishing a new image or to (re)start the stack in the background.

3. **`run-node-app.sh`** — Foreground **`docker compose up`** (logs in the terminal; Ctrl+C stops). Optional: `./run-node-app.sh --detach` runs in the background.

Typical flow after editing `.env`:

```bash
./install-or-update-node-app.sh
```

Open **http://127.0.0.1:3333/** (or `http://localhost:${NODE_APP_PORT}/` if you changed the port).

## Connecting the frontend to your node (Plain HTTP)

When **`ENABLE_PLAIN_HTTP_ATTACH=1`**, the dashboard shows **Plain HTTP** in the attach UI — use that for local installs (no read-JWT on GETs). Without it (typical **Railway** deploy), use **Browser HTTPS** or an **SSH tunnel** only.

1. In the dashboard, choose the **Plain HTTP** transport.
2. Enter your mpc-auth base URL as you reach it from **your browser**, for example:
   - **Management API**: `http://YOUR_NODE_IP:8080` (replace with your **ManagementAPIsPort** from `configs.yaml`).
   - If your setup publishes HTTP on another host/port, use that URL — the UI must be able to `fetch` `/getNodeMgtKey` from the browser.

Use the **real node LAN or public IP** when required (not `127.0.0.1` from the browser’s perspective, unless the browser is on the same host and mpc-auth binds to loopback).

Keep **NODE_READ_DISCOVERY_ALLOW_PRIVATE=1** in `.env` so server-side routes like `/api/node-read/node-version` can reach private discovery addresses when you use local or RFC1918 hosts.

### NAT hairpin (same machine as mpc-auth, WAN IP in `nodeAddresses`)

If **mpc-auth** is configured with **public** IPv4s in `nodeAddresses` (as `process_config.sh` expects behind NAT), the **Next.js** process may still fail to open `http://<that-public-ip>:18080` (or `:8080`) to itself — many routers do not support loopback to the WAN address. Symptoms: discovery proxy errors (“no route to host”) while the UI is otherwise local.

1. **Preferred:** set **`NODE_READ_DISCOVERY_LOCAL_BIND_ALIASES`** in `.env`. Use the same public IPv4 you list in node config on the **left**; on the **right**, use an address the **Next.js container** can dial to reach mpc-auth on the Docker **host** (not `127.0.0.1`, which inside the dashboard container is the container itself). This compose file adds **`host.docker.internal` → host** (`extra_hosts`), so you can use e.g. `203.0.113.5=host.docker.internal` and, for Plain HTTP attach to `http://127.0.0.1:8080`, also `127.0.0.1=host.docker.internal`.
2. **Dev-only shortcut:** with **`NODE_READ_DISCOVERY_ALLOW_PRIVATE=1`**, you may set **`NODE_READ_DISCOVERY_HAIRPIN_FALLBACK=1`** so failed dials to a public IPv4 retry via `127.0.0.1` (see **continuumdao-node-app** `app/api/node-read/_lib.ts`). That retry still fails if mpc-auth is only on the host and the dashboard is in bridge networking — prefer **`host.docker.internal`** on the right-hand side of aliases instead. Do not rely on hairpin for hosted dashboards reaching **remote** nodes.

**Note:** If the dashboard runs **only in Docker** with `bridge` networking, `127.0.0.1` inside the container is **not** the host’s mpc-auth. Use **`host.docker.internal`** (this compose adds it) or the bridge gateway IP (often `172.17.0.1`) on the **right-hand** side of **`NODE_READ_DISCOVERY_LOCAL_BIND_ALIASES`**.

## Building and publishing the image

The dashboard image is built from the **continuumdao-node-app** repository (`local/Dockerfile` and `local/push-image.sh`). Default registry name: **continuumdao/continuumdao-node-app** (same Docker Hub org as **continuumdao/mpc-auth**).

To publish a new image, use **continuumdao-node-app** (`local/push-image.sh`). That script can load **`mpc-config/.env.docker-registry`** (same directory as this README’s parent) if you set **IMAGE_NAME** there.
