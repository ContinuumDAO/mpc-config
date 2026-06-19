# Home router port forwarding (WAN → LAN)

Use this guide when you run a Continuum node on a **local PC** (for example Windows + Docker Desktop + WSL2) and need peers on the internet to reach it. Your router must forward two inbound ports from your **public WAN IP** to your PC’s **reserved LAN IP**.

## What you are configuring

| Service | Port | Protocol | Purpose |
|---------|------|----------|---------|
| **continuum-public-discovery** | **18080** | TCP | Public discovery HTTP (`getNodeMgtKey`, `getPublicMgtKey`, `getNodeKey`, etc.) |
| **continuum-mqtt** | **8883** | TCP | MQTT broker TLS (relay nodes only; client nodes connect outbound to a relay) |

If this PC is a **client** node (not the relay), you still need **18080** forwarded so other nodes can discover yours. **8883** is only required on the machine that runs the Mosquitto relay broker.

## Before you start

1. Know your PC’s **LAN IP** today (for example `192.168.1.42`). In Windows: **Settings → Network & Internet → Properties** on your active adapter, or `ipconfig` in PowerShell.
2. Know your PC’s **MAC address** for the same adapter (needed for DHCP reservation). In PowerShell: `getmac /v /fo list`.
3. Know your **public IPv4** (for example from [https://ip.me](https://ip.me)). That is what you enter in the Continuum Node installer and what remote peers use.

Router admin UIs differ by brand (ASUS, TP-Link, Netgear, Fritz!Box, etc.). The concepts are the same: **DHCP reservation** (static LAN IP) and **port forwarding** / **NAT** / **virtual server**.

## Step 1 — Reserve a LAN IP for your PC

Goal: your PC always receives the same private address so port-forward rules do not break after reboot.

1. Sign in to your router’s admin page (often `192.168.0.1` or `192.168.1.1`).
2. Open **DHCP**, **LAN**, or **Address reservation** (names vary).
3. Add a reservation:
   - **MAC address**: your PC’s Ethernet or Wi‑Fi MAC (use the adapter that stays connected).
   - **IP address**: pick an unused address in your LAN range (for example `192.168.1.50`).
4. Save and apply. Reboot the PC or renew DHCP (`ipconfig /renew` on Windows) and confirm the PC now has that IP.

Write down the reserved IP — call it **`<LAN_IP>`** below.

## Step 2 — Create NAT / port-forward rules

In the router UI, find **Port forwarding**, **NAT**, **Virtual server**, or **Firewall → Port mapping**.

Create **two** inbound rules to **`<LAN_IP>`**:

| Rule name (suggested) | External / WAN port | Internal / LAN port | Internal IP | Protocol |
|-----------------------|---------------------|---------------------|-------------|----------|
| `continuum-public-discovery` | 18080 | 18080 | `<LAN_IP>` | TCP |
| `continuum-mqtt` | 8883 | 8883 | `<LAN_IP>` | TCP |

Save and apply. Some routers require a reboot.

### Windows Firewall (local PC)

Docker Desktop publishes these ports on the Windows host. If inbound tests fail after router setup, allow the ports in **Windows Defender Firewall** (or temporarily disable the firewall only to confirm the router rules work, then add explicit allow rules).

## Step 3 — Verify from outside your LAN

From a **phone on cellular** (not Wi‑Fi) or another network:

```bash
curl -sS "http://YOUR_PUBLIC_IP:18080/health"
```

A JSON health response means discovery is reachable. For a relay, MQTT TLS on **8883** is harder to curl; confirm the port is open with an external port-check tool or from a second node’s logs.

If it fails:

- Confirm the PC is on and Docker containers are running (`docker compose ps` in WSL under `~/mpc-config`).
- Confirm the PC still has **`<LAN_IP>`** (reservation working).
- Confirm forwards point to **`<LAN_IP>`**, not an old IP.
- Confirm your ISP does not use **CGNAT** (carrier-grade NAT). If your WAN IP on the router differs from [ip.me](https://ip.me), you may need a business line, IPv6, or a tunnel — outside the scope of this guide.

## CGNAT and double-NAT

If you are behind CGNAT or nested routers (modem + mesh), you may need forwarding on **both** layers or a single router in bridge mode. The reserved LAN IP must still be the machine running Docker Desktop.

## Related

- Windows install: [INSTALL_NODE_WINDOWS_DOCKER_DESKTOP.md](./INSTALL_NODE_WINDOWS_DOCKER_DESKTOP.md)
- Extension and stack details: [`docker-extension/README.md`](../docker-extension/README.md)
