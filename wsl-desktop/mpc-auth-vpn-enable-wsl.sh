#!/usr/bin/env bash
# Enable WireGuard admin VPN in WSL (Windows Docker Desktop profile — no systemd).
# Invoked by libexec/mpc-auth-apply-pending-vpn.sh via the WSL pending watcher.

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

REPO_ROOT="$(cd "${HERE}/.." && pwd)"
# shellcheck source=../scripts/lib/mpc-auth-vpn-wg0-hooks.sh
. "${REPO_ROOT}/scripts/lib/mpc-auth-vpn-wg0-hooks.sh"

WG_HOST_DIR="${MPC_AUTH_WIREGUARD_HOST_DIR:-/etc/wireguard}"
WG_SRC_DIR="${MPC_AUTH_WIREGUARD_SRC_DIR:-/var/lib/mpc-auth-docker/wireguard}"
STATE_FILE="${MPC_AUTH_VPN_STATE_FILE:-/var/lib/mpc-auth-docker/vpn-state.json}"
LISTEN_PORT="${MPC_AUTH_WIREGUARD_LISTEN_PORT:-51820}"
VPN_CIDR="${MPC_AUTH_WIREGUARD_VPN_CIDR:-10.8.0.0/24}"
MGMT_PORT="${MPC_AUTH_VPN_MGMT_PORT:-8080}"
PROFILE="${MPC_AUTH_VPN_PROFILE:-split}"
PROXY_PIDFILE="${MPC_AUTH_VPN_MGMT_PROXY_PIDFILE:-${HERE}/../vpn-mgmt-proxy.pid}"

if [[ ! -f "${WG_SRC_DIR}/wg0.conf" ]]; then
	echo "mpc-auth-vpn-enable-wsl: missing ${WG_SRC_DIR}/wg0.conf (mpc-auth must write WireGuard config first)" >&2
	exit 1
fi

if ! command -v wg-quick >/dev/null 2>&1; then
	echo "mpc-auth-vpn-enable-wsl: wg-quick not found — run: sudo apt install wireguard-tools" >&2
	exit 1
fi

if [[ "$PROFILE" == "full" ]]; then
	echo "mpc-auth-vpn-enable-wsl: warning — full-tunnel NAT is limited on WSL2; split-tunnel admin access is recommended." >&2
fi

wsl_desktop_sudo mkdir -p "$WG_HOST_DIR"
wsl_desktop_sudo chmod 0700 "$WG_HOST_DIR"
wsl_desktop_sudo install -m 0600 "${WG_SRC_DIR}/wg0.conf" "${WG_HOST_DIR}/wg0.conf"

# Render hooks into a temp copy (WSL may not have repo libexec); run python as root on host wg0.conf path.
_tmp_hooks="$(mktemp)"
cp "${WG_SRC_DIR}/wg0.conf" "$_tmp_hooks"
mpc_auth_vpn_prepare_wg0_conf "$_tmp_hooks" "$PROFILE" "$LISTEN_PORT" "$VPN_CIDR" "$MGMT_PORT"
wsl_desktop_sudo install -m 0600 "$_tmp_hooks" "${WG_HOST_DIR}/wg0.conf"
rm -f "$_tmp_hooks"

wsl_desktop_sudo wg-quick down wg0 2>/dev/null || true
wsl_desktop_sudo wg-quick up "${WG_HOST_DIR}/wg0.conf"

if command -v socat >/dev/null 2>&1; then
	if [[ -f "$PROXY_PIDFILE" ]]; then
		old_pid="$(cat "$PROXY_PIDFILE" 2>/dev/null || true)"
		if [[ -n "$old_pid" ]] && kill -0 "$old_pid" 2>/dev/null; then
			kill "$old_pid" 2>/dev/null || true
		fi
		rm -f "$PROXY_PIDFILE"
	fi
	nohup socat "TCP-LISTEN:${MGMT_PORT},bind=10.8.0.1,reuseaddr,fork" "TCP:127.0.0.1:${MGMT_PORT}" \
		>>"${HERE}/../vpn-mgmt-proxy.log" 2>&1 &
	echo $! >"$PROXY_PIDFILE"
else
	echo "mpc-auth-vpn-enable-wsl: socat not installed — run: sudo apt install socat" >&2
fi

wsl_desktop_sudo mkdir -p "$(dirname "$STATE_FILE")"
export STATE_FILE PROFILE LISTEN_PORT
wsl_desktop_sudo env STATE_FILE="$STATE_FILE" PROFILE="$PROFILE" LISTEN_PORT="$LISTEN_PORT" python3 - <<'PY'
import json, datetime, os
path = os.environ["STATE_FILE"]
payload = {
    "active": True,
    "profile": os.environ.get("PROFILE", "split"),
    "listenPort": int(os.environ.get("LISTEN_PORT", "51820")),
    "hostProfile": "wsl_desktop",
    "updatedAt": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
}
with open(path + ".tmp", "w") as f:
    json.dump(payload, f)
os.rename(path + ".tmp", path)
PY

echo "mpc-auth-vpn-enable-wsl: WireGuard VPN enabled in WSL (profile=${PROFILE})"
