#!/usr/bin/env bash
# Disable WireGuard admin VPN in WSL (Windows Docker Desktop profile).

set -euo pipefail

if [[ -n "${MPC_AUTH_WSL_ENV_FILE:-}" && -r "${MPC_AUTH_WSL_ENV_FILE}" ]]; then
	# shellcheck source=/dev/null
	. "${MPC_AUTH_WSL_ENV_FILE}"
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
if [[ -f "${HERE}/_lib.sh" ]]; then
	. "${HERE}/_lib.sh"
else
	. "${HERE}/../_lib.sh"
fi

WG_HOST_DIR="${MPC_AUTH_WIREGUARD_HOST_DIR:-/etc/wireguard}"
STATE_FILE="${MPC_AUTH_VPN_STATE_FILE:-/var/lib/mpc-auth-docker/vpn-state.json}"
LISTEN_PORT="${MPC_AUTH_WIREGUARD_LISTEN_PORT:-51820}"
PROXY_PIDFILE="${MPC_AUTH_VPN_MGMT_PROXY_PIDFILE:-${HERE}/../vpn-mgmt-proxy.pid}"

if [[ -f "$PROXY_PIDFILE" ]]; then
	pid="$(cat "$PROXY_PIDFILE" 2>/dev/null || true)"
	if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
		kill "$pid" 2>/dev/null || true
	fi
	rm -f "$PROXY_PIDFILE"
fi

if command -v wg-quick >/dev/null 2>&1; then
	wsl_desktop_sudo wg-quick down wg0 2>/dev/null || true
elif [[ -f "${WG_HOST_DIR}/wg0.conf" ]]; then
	wsl_desktop_sudo wg-quick down "${WG_HOST_DIR}/wg0.conf" 2>/dev/null || true
fi

wsl_desktop_sudo mkdir -p "$(dirname "$STATE_FILE")"
export STATE_FILE LISTEN_PORT
wsl_desktop_sudo env STATE_FILE="$STATE_FILE" LISTEN_PORT="$LISTEN_PORT" python3 - <<'PY'
import json, datetime, os
path = os.environ["STATE_FILE"]
payload = {
    "active": False,
    "profile": "",
    "listenPort": int(os.environ.get("LISTEN_PORT", "51820")),
    "hostProfile": "wsl_desktop",
    "updatedAt": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
}
with open(path + ".tmp", "w") as f:
    json.dump(payload, f)
os.rename(path + ".tmp", path)
PY

echo "mpc-auth-vpn-disable-wsl: WireGuard VPN disabled in WSL"
