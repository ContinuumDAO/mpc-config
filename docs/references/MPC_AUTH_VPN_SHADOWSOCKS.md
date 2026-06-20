# mpc-auth: Shadowsocks VPN transport obfuscation

Implement in the **mpc-auth** Go repository. This document is the contract between mpc-auth, mpc-config host automation, and continuumdao-node-app.

Reference Python implementation (port to Go): [`scripts/lib/mpc-auth-vpn-shadowsocks-config.py`](../../scripts/lib/mpc-auth-vpn-shadowsocks-config.py).

## Config (`configs.yaml`)

```yaml
Shadowsocks:
  ListenPort: 8388
  Method: chacha20-ietf-poly1305
  LocalTunnelPort: 51821
  ClientMtu: 1280
```

Documented in [`configs-original.yaml`](../../configs-original.yaml).

## Files written by mpc-auth (bind-mounted `/var/lib/mpc-auth-docker`)

| Path | When |
|------|------|
| `shadowsocks/ssserver.json` | First enable with `obfuscation: shadowsocks` (or password rotation) |
| `shadowsocks/password` (optional) | Persist generated password (mode 0600) |
| `wireguard/wg0.conf` | Existing WireGuard flow |
| `pending-vpn.json` | Extended schema below |
| `vpn-state.json` | Read-only for status; written by host scripts |

### `pending-vpn.json`

```json
{
  "action": "enable",
  "profile": "split",
  "obfuscation": "shadowsocks"
}
```

- `obfuscation`: `"none"` | `"shadowsocks"` (default `"none"`).
- Host parser: [`systemd/mpc-auth-apply-pending-vpn.sh`](../../systemd/mpc-auth-apply-pending-vpn.sh).

### `ssserver.json` shape

Use template [`systemd/shadowsocks/ssserver.json.template`](../../systemd/shadowsocks/ssserver.json.template). Generate password with `crypto/rand` (≥ 32 bytes, URL-safe base64).

## `GET /vpn/status`

Add to existing response `data`:

```go
Obfuscation            string `json:"obfuscation"`            // from vpn-state.json; "none" when inactive
ObfuscationAvailable   bool   `json:"obfuscationAvailable"`   // ssserver on PATH + host profile
ShadowsocksListenPort  int    `json:"shadowsocksListenPort"`
ShadowsocksMethod      string `json:"shadowsocksMethod"`
DirectWireGuardBlocked bool   `json:"directWireGuardBlocked"`
```

### `obfuscationAvailable` logic

```go
func obfuscationAvailable(hostProfile string) bool {
    if hostProfile == "wsl_desktop" || hostProfile == "macos_desktop" {
        return false // panel hides toggle; host scripts exist but NAT/firewall caveats
    }
    _, err := exec.LookPath("ssserver")
    return err == nil
}
```

Detect `hostProfile` from `vpn-state.json` `hostProfile` field when present, else assume VPS/systemd.

## `POST /vpn/setEnabled`

Request body — add optional field:

```json
{ "enabled": true, "profile": "split", "obfuscation": "shadowsocks" }
```

1. Normalize `obfuscation` to `none` | `shadowsocks`.
2. If `shadowsocks` and `!obfuscationAvailable`, return **400**.
3. On enable with `shadowsocks`: ensure password exists; write `ssserver.json` atomically (temp + rename).
4. Write `pending-vpn.json` including `obfuscation`.
5. Existing WireGuard key generation unchanged.

## `POST /vpn/clientConfig`

When active obfuscation (from state or request) is `shadowsocks`:

Return extended `data` (see [`API_IMPLEMENTATION.md`](./API_IMPLEMENTATION.md#post-vpn-clientconfig)):

- Port logic from `mpc-auth-vpn-shadowsocks-config.py`:
  - `patch_wireguard_client_for_obfuscation` — Endpoint `127.0.0.1:{LocalTunnelPort}`, MTU
  - `build_sslocal_tunnel_config` — forward to `127.0.0.1:51820` on server
  - `build_shadowsocks_uri` — optional mobile URI

When `obfuscation` is `none`, keep existing `{ configText, filename }` response for backward compatibility.

## `GET /health` (optional)

Extend `vpn.*` fields to mirror status: `vpn.obfuscation`, `vpn.directWireGuardBlocked`.

## Security

- Shadowsocks password same trust level as WireGuard client private key.
- Store under `/var/lib/mpc-auth-docker/shadowsocks/` with directory mode 0700, files 0600.
- Do not log passwords.

## Testing (with mpc-config host scripts)

1. Install shadowsocks-rust on VPS: `ensure_shadowsocks_host_packages` or `apt install shadowsocks-rust`.
2. Enable VPN with obfuscation via API; verify `ssserver` running, UDP 51820 blocked externally.
3. Download client bundle; run `sslocal` + `wg-quick up`; curl `http://10.8.0.1:8080/health`.
