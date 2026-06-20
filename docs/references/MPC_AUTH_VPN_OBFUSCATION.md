# mpc-auth: Multi-protocol VPN transport obfuscation

Overview for all WireGuard transport obfuscation options. Per-protocol details:

| Protocol | ID | Doc |
|----------|-----|-----|
| Shadowsocks | `shadowsocks` | [MPC_AUTH_VPN_SHADOWSOCKS.md](MPC_AUTH_VPN_SHADOWSOCKS.md) |
| wg-obfuscator | `wg_obfuscator` | [MPC_AUTH_VPN_WG_OBFUSCATOR.md](MPC_AUTH_VPN_WG_OBFUSCATOR.md) |
| LWO | `lwo` | (planned — `obfuscation/lwo/`) |
| udp2raw | `udp2raw` | (planned) |

## Shared pattern

```text
wg-quick → 127.0.0.1:LocalTunnelPort → transport proxy → VPS public port → server proxy → wg0
```

- `obfuscation` enum: `none` | `shadowsocks` | `wg_obfuscator` | `lwo` | `udp2raw`
- `GET /vpn/status`: `availableObfuscations[]` — only protocols whose binary is on PATH and host profile allows obfuscation
- `POST /vpn/clientConfig`: generic fields `transportConfigText`, `transportFilename`, `transportBinary` (Shadowsocks keeps legacy field names too)
- Full tunnel: PreUp/PostDown bypass route to VPS public IP before default route hijack

## Host automation dispatcher

[`scripts/lib/mpc-auth-vpn-obfuscation-hooks.sh`](../../scripts/lib/mpc-auth-vpn-obfuscation-hooks.sh) normalizes obfuscation IDs and starts/stops per-protocol systemd units.

Pending parser whitelist: [`systemd/mpc-auth-apply-pending-vpn.sh`](../../systemd/mpc-auth-apply-pending-vpn.sh).

## WSL / macOS desktop

Obfuscation is gated off in mpc-auth for `hostProfile` `wsl_desktop` and `macos_desktop` until background daemon + firewall flows are validated.
