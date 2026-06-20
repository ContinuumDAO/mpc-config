#!/usr/bin/env bash
# Disable WireGuard admin VPN on macOS (Docker Desktop profile).

set -euo pipefail

if [[ -n "${MPC_AUTH_MACOS_ENV_FILE:-}" && -r "${MPC_AUTH_MACOS_ENV_FILE}" ]]; then
	# shellcheck source=/dev/null
	. "${MPC_AUTH_MACOS_ENV_FILE}"
elif [[ -n "${MPC_AUTH_WSL_ENV_FILE:-}" && -r "${MPC_AUTH_WSL_ENV_FILE}" ]]; then
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

WG_HOST_DIR="$(macos_desktop_wireguard_host_dir)"
STATE_FILE="${MPC_AUTH_VPN_STATE_FILE:-/var/lib/mpc-auth-docker/vpn-state.json}"
LISTEN_PORT="${MPC_AUTH_WIREGUARD_LISTEN_PORT:-51820}"
PROXY_PIDFILE="${MPC_AUTH_VPN_MGMT_PROXY_PIDFILE:-${HERE}/../vpn-mgmt-proxy.pid}"
SS_PIDFILE="${MPC_AUTH_SHADOWSOCKS_PIDFILE:-${HERE}/../shadowsocks-server.pid}"

REPO_ROOT="$(cd "${HERE}/.." && pwd)"
# shellcheck source=../scripts/lib/mpc-auth-vpn-ss-hooks.sh
. "${REPO_ROOT}/scripts/lib/mpc-auth-vpn-ss-hooks.sh"

mpc_auth_vpn_stop_shadowsocks_background "$SS_PIDFILE"

if [[ -f "$PROXY_PIDFILE" ]]; then
	pid="$(cat "$PROXY_PIDFILE" 2>/dev/null || true)"
	if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
		kill "$pid" 2>/dev/null || true
	fi
	rm -f "$PROXY_PIDFILE"
fi

if command -v wg-quick >/dev/null 2>&1; then
	macos_desktop_sudo wg-quick down wg0 2>/dev/null || true
elif [[ -f "${WG_HOST_DIR}/wg0.conf" ]]; then
	macos_desktop_sudo wg-quick down "${WG_HOST_DIR}/wg0.conf" 2>/dev/null || true
fi

macos_desktop_sudo mkdir -p "$(dirname "$STATE_FILE")"
export STATE_FILE LISTEN_PORT
macos_desktop_sudo env STATE_FILE="$STATE_FILE" LISTEN_PORT="$LISTEN_PORT" python3 - <<'PY'
import json, datetime, os
path = os.environ["STATE_FILE"]
payload = {
    "active": False,
    "profile": "",
    "obfuscation": "none",
    "listenPort": int(os.environ.get("LISTEN_PORT", "51820")),
    "directWireGuardBlocked": False,
    "hostProfile": "macos_desktop",
    "updatedAt": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
}
with open(path + ".tmp", "w") as f:
    json.dump(payload, f)
os.rename(path + ".tmp", path)
PY

echo "mpc-auth-vpn-disable-macos: WireGuard VPN disabled"
