#!/usr/bin/env bash
# Disable WireGuard admin VPN on the Docker host after mpc-auth POST /vpn/setEnabled.

set -euo pipefail

WG_HOST_DIR="${MPC_AUTH_WIREGUARD_HOST_DIR:-/etc/wireguard}"
STATE_FILE="${MPC_AUTH_VPN_STATE_FILE:-/var/lib/mpc-auth-docker/vpn-state.json}"
LISTEN_PORT="${MPC_AUTH_WIREGUARD_LISTEN_PORT:-51820}"
VPN_CIDR="${MPC_AUTH_WIREGUARD_VPN_CIDR:-10.8.0.0/24}"
MGMT_PORT="${MPC_AUTH_VPN_MGMT_PORT:-8080}"

if command -v systemctl >/dev/null 2>&1; then
	systemctl stop mpc-auth-vpn-mgmt-proxy.service 2>/dev/null || true
	systemctl disable mpc-auth-vpn-mgmt-proxy.service 2>/dev/null || true
	systemctl stop mpc-auth-wireguard-wg0.service 2>/dev/null || true
	systemctl disable mpc-auth-wireguard-wg0.service 2>/dev/null || true
elif command -v wg-quick >/dev/null 2>&1 && [[ -f "${WG_HOST_DIR}/wg0.conf" ]]; then
	wg-quick down wg0 2>/dev/null || true
fi

if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi "Status: active"; then
	ufw delete allow "${LISTEN_PORT}/udp" 2>/dev/null || true
	ufw delete allow from "${VPN_CIDR}" to any port "${MGMT_PORT}" proto tcp 2>/dev/null || true
fi

mkdir -p "$(dirname "$STATE_FILE")"
export STATE_FILE LISTEN_PORT
python3 - <<'PY'
import json, datetime, os
path = os.environ["STATE_FILE"]
payload = {
    "active": False,
    "profile": "",
    "listenPort": int(os.environ.get("LISTEN_PORT", "51820")),
    "updatedAt": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
}
with open(path + ".tmp", "w") as f:
    json.dump(payload, f)
os.rename(path + ".tmp", path)
PY

echo "mpc-auth-vpn-disable: WireGuard VPN disabled"
