# Continuum LWO (Lightweight WireGuard Obfuscation)

Mullvad-compatible LWO codec — server and client binaries for VPN panel transport obfuscation.

Reference: Mullvad [`tunnel-obfuscation/src/lwo.rs`](https://github.com/mullvad/mullvadvpn-app/blob/main/tunnel-obfuscation/src/lwo.rs).

## Build

```bash
cd obfuscation/lwo
cargo build --release
install -m 0755 target/release/continuum-lwo-server /usr/local/bin/
install -m 0755 target/release/continuum-lwo-client /usr/local/bin/
```

Or run the systemd install script on the VPS host — it calls `ensure_lwo_host_packages` when `cargo` is available.

mpc-auth exposes `lwo` in `availableObfuscations` when both binaries are on PATH (recorded in `vpn-host-obfuscation.json`).

## Usage

**Server** (VPS, via systemd `mpc-auth-lwo.service`):

```bash
continuum-lwo-server --config /var/lib/mpc-auth-docker/lwo/server.json
```

**Client** (admin machine):

```bash
continuum-lwo-client --config continuum-lwo-client.json
wg-quick up wg0.conf   # Endpoint 127.0.0.1:<local_port>
```
