# mpc-auth: wg-obfuscator VPN transport obfuscation

Implement in the **mpc-auth** Go repository. Host automation lives in mpc-config; panel integration in continuumdao-node-app.

Upstream: [ClusterM/wg-obfuscator](https://github.com/ClusterM/wg-obfuscator) (UDP obfuscation, shared key).

## Config (`configs.yaml`)

```yaml
WgObfuscator:
  ListenPort: 51822       # public UDP port on VPS
  LocalTunnelPort: 51821  # client localhost port (WireGuard Endpoint)
  ClientMtu: 1280
```

## Files written by mpc-auth (bind-mounted `/var/lib/mpc-auth-docker`)

| Path | When |
|------|------|
| `wg-obfuscator/keys.json` | First enable with `obfuscation: wg_obfuscator` |
| `wg-obfuscator/server.conf` | Server-side wg-obfuscator INI config |
| `wireguard/wg0.conf` | Existing WireGuard flow (ListenPort stays internal) |
| `pending-vpn.json` | `obfuscation: wg_obfuscator` |
| `vpn-state.json` | `wgObfuscatorListenPort`, `directWireGuardBlocked: true` |

### Server config shape

```ini
[main]
source-lport = 51822
target = 127.0.0.1:51820
key = <generated-shared-key>
```

### Client config (download bundle)

```ini
[main]
source-lport = 51821
target = VPS_PUBLIC_IP:51822
key = <same-key>
```

## API

- `GET /vpn/status`: `availableObfuscations` includes `wg_obfuscator` when `wg-obfuscator` is on PATH; `wgObfuscatorListenPort`.
- `POST /vpn/setEnabled`: `obfuscation: wg_obfuscator` writes keys + server.conf, pending JSON.
- `POST /vpn/clientConfig`: returns generic `transportConfigText`, `transportFilename`, `transportBinary` plus patched `wireGuardConfigText`.

## Host automation (VPS systemd)

| Component | Path |
|-----------|------|
| systemd unit | [`systemd/mpc-auth-wg-obfuscator.service`](../../systemd/mpc-auth-wg-obfuscator.service) |
| hooks | [`scripts/lib/mpc-auth-vpn-wg-obfuscator-hooks.sh`](../../scripts/lib/mpc-auth-vpn-wg-obfuscator-hooks.sh) |
| dispatcher | [`scripts/lib/mpc-auth-vpn-obfuscation-hooks.sh`](../../scripts/lib/mpc-auth-vpn-obfuscation-hooks.sh) |
| install helper | [`scripts/lib/ensure-wg-obfuscator-host-packages.sh`](../../scripts/lib/ensure-wg-obfuscator-host-packages.sh) |

On enable: start `mpc-auth-wg-obfuscator.service`, block public UDP WireGuard (`51820`) via wg0 PostUp iptables (same as Shadowsocks), UFW allow UDP `51822`.

## Client workflow

1. Install `wg-obfuscator` from [GitHub releases](https://github.com/ClusterM/wg-obfuscator/releases).
2. `wg-obfuscator --config continuum-wg-obfuscator.conf` (keep running).
3. Save WireGuard config from panel; `sudo wg-quick up cont-vpn-full.conf`.
4. Full tunnel: PreUp/PostDown bypass route to VPS IP is included automatically.

## Verify

```bash
ss -unp | grep wg-obfuscator
sudo tcpdump -i any udp port 51822   # obfuscated traffic, not raw WG on 51820
wg show   # endpoint: 127.0.0.1:51821
```
