#!/usr/bin/env bash
# Disable WireGuard admin VPN on the Docker host after mpc-auth POST /vpn/setEnabled.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${HERE}/mpc-auth-vpn-ss-hooks.sh" ]]; then
	# shellcheck source=mpc-auth-vpn-ss-hooks.sh
	. "${HERE}/mpc-auth-vpn-ss-hooks.sh"
elif [[ -f "${HERE}/../scripts/lib/mpc-auth-vpn-ss-hooks.sh" ]]; then
	# shellcheck source=../scripts/lib/mpc-auth-vpn-ss-hooks.sh
	. "${HERE}/../scripts/lib/mpc-auth-vpn-ss-hooks.sh"
fi

WG_HOST_DIR="${MPC_AUTH_WIREGUARD_HOST_DIR:-/etc/wireguard}"
STATE_FILE="${MPC_AUTH_VPN_STATE_FILE:-/var/lib/mpc-auth-docker/vpn-state.json}"
LISTEN_PORT="${MPC_AUTH_WIREGUARD_LISTEN_PORT:-51820}"
VPN_CIDR="${MPC_AUTH_WIREGUARD_VPN_CIDR:-10.8.0.0/24}"
MGMT_PORT="${MPC_AUTH_VPN_MGMT_PORT:-8080}"
SS_PORT="${MPC_AUTH_SHADOWSOCKS_LISTEN_PORT:-8388}"

if [[ -f "$STATE_FILE" ]] && command -v python3 >/dev/null 2>&1; then
	SS_PORT="$(python3 - "$STATE_FILE" "$SS_PORT" <<'PY'
import json, sys
path, default = sys.argv[1], int(sys.argv[2])
try:
    with open(path, encoding="utf-8") as f:
        d = json.load(f)
except (OSError, json.JSONDecodeError, ValueError):
    print(default)
    raise SystemExit(0)
print(int(d.get("shadowsocksListenPort", default)))
PY
)" || SS_PORT="${MPC_AUTH_SHADOWSOCKS_LISTEN_PORT:-8388}"
fi

if declare -F mpc_auth_vpn_stop_shadowsocks_systemd >/dev/null 2>&1; then
	mpc_auth_vpn_stop_shadowsocks_systemd
fi

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
	ufw delete allow "${SS_PORT}/tcp" 2>/dev/null || true
	ufw delete allow "${SS_PORT}/udp" 2>/dev/null || true
	ufw delete allow from "${VPN_CIDR}" to any port "${MGMT_PORT}" proto tcp 2>/dev/null || true
	default_if="$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')"
	default_if="${default_if:-eth0}"
	ufw delete route allow in on wg0 out on "${default_if}" 2>/dev/null || true
	ufw delete route allow in on "${default_if}" out on wg0 2>/dev/null || true
fi

mkdir -p "$(dirname "$STATE_FILE")"
export STATE_FILE LISTEN_PORT
python3 - <<'PY'
import json, datetime, os
path = os.environ["STATE_FILE"]
payload = {
    "active": False,
    "profile": "",
    "obfuscation": "none",
    "listenPort": int(os.environ.get("LISTEN_PORT", "51820")),
    "directWireGuardBlocked": False,
    "updatedAt": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
}
with open(path + ".tmp", "w") as f:
    json.dump(payload, f)
os.rename(path + ".tmp", path)
PY

echo "mpc-auth-vpn-disable: WireGuard VPN disabled"
