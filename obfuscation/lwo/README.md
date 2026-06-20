# Continuum LWO (Lightweight WireGuard Obfuscation)

Mullvad-compatible LWO codec — server and client binaries for VPN panel transport obfuscation.

**Status:** scaffold only. Implement in Phase 3 per [MPC_AUTH_VPN_OBFUSCATION.md](../../docs/references/MPC_AUTH_VPN_OBFUSCATION.md).

Reference: Mullvad [`tunnel-obfuscation/src/lwo.rs`](https://github.com/mullvad/mullvadvpn-app/blob/main/tunnel-obfuscation/src/lwo.rs).

## Build (when implemented)

```bash
cd obfuscation/lwo
cargo build --release
install -m 0755 target/release/continuum-lwo-server /usr/local/bin/
install -m 0755 target/release/continuum-lwo-client /usr/local/bin/
```

mpc-auth exposes `lwo` in `availableObfuscations` when both binaries are on PATH.
