#!/usr/bin/env bash
# Enable WireGuard admin VPN on macOS (Docker Desktop profile — no systemd).
# Invoked by libexec/mpc-auth-apply-pending-vpn.sh via the macOS pending watcher.

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

REPO_ROOT="$(cd "${HERE}/.." && pwd)"
# shellcheck source=../scripts/lib/mpc-auth-vpn-wg0-hooks.sh
. "${REPO_ROOT}/scripts/lib/mpc-auth-vpn-wg0-hooks.sh"
# shellcheck source=../scripts/lib/mpc-auth-vpn-ss-hooks.sh
. "${REPO_ROOT}/scripts/lib/mpc-auth-vpn-ss-hooks.sh"
# shellcheck source=../scripts/lib/mpc-auth-vpn-obfuscation-hooks.sh
. "${REPO_ROOT}/scripts/lib/mpc-auth-vpn-obfuscation-hooks.sh"

WG_HOST_DIR="$(macos_desktop_wireguard_host_dir)"
WG_SRC_DIR="${MPC_AUTH_WIREGUARD_SRC_DIR:-/var/lib/mpc-auth-docker/wireguard}"
STATE_FILE="${MPC_AUTH_VPN_STATE_FILE:-/var/lib/mpc-auth-docker/vpn-state.json}"
LISTEN_PORT="${MPC_AUTH_WIREGUARD_LISTEN_PORT:-51820}"
VPN_CIDR="${MPC_AUTH_WIREGUARD_VPN_CIDR:-10.8.0.0/24}"
MGMT_PORT="${MPC_AUTH_VPN_MGMT_PORT:-8080}"
PROXY_PIDFILE="${MPC_AUTH_VPN_MGMT_PROXY_PIDFILE:-${HERE}/../vpn-mgmt-proxy.pid}"
SS_PIDFILE="${MPC_AUTH_SHADOWSOCKS_PIDFILE:-${HERE}/../shadowsocks-server.pid}"
SS_LOG="${MPC_AUTH_SHADOWSOCKS_LOG:-${HERE}/../shadowsocks-server.log}"

normalize_vpn_profile() {
	local v="${1:-${MPC_AUTH_VPN_PROFILE:-split}}"
	v="${v,,}"
	v="${v// /}"
	if [[ "$v" != "split" && "$v" != "full" ]]; then
		v="split"
	fi
	printf '%s' "$v"
}

PROFILE="$(normalize_vpn_profile "${1:-}")"
OBFUSCATION="$(mpc_auth_vpn_normalize_obfuscation "${MPC_AUTH_VPN_OBFUSCATION:-}")"
export MPC_AUTH_VPN_OBFUSCATION="$OBFUSCATION"
SS_PORT="$(mpc_auth_vpn_read_shadowsocks_listen_port)"
export MPC_AUTH_SHADOWSOCKS_LISTEN_PORT="$SS_PORT"

echo "mpc-auth-vpn-enable-macos: profile=${PROFILE} obfuscation=${OBFUSCATION}" >&2

if [[ ! -f "${WG_SRC_DIR}/wg0.conf" ]]; then
	echo "mpc-auth-vpn-enable-macos: missing ${WG_SRC_DIR}/wg0.conf (mpc-auth must write WireGuard config first)" >&2
	exit 1
fi

if [[ "$OBFUSCATION" == "shadowsocks" && ! -f "$(mpc_auth_vpn_shadowsocks_config_path)" ]]; then
	echo "mpc-auth-vpn-enable-macos: missing $(mpc_auth_vpn_shadowsocks_config_path)" >&2
	exit 1
fi

if ! command -v wg-quick >/dev/null 2>&1; then
	echo "mpc-auth-vpn-enable-macos: wg-quick not found — run: brew install wireguard-tools" >&2
	exit 1
fi

if [[ "$PROFILE" == "full" ]]; then
	echo "mpc-auth-vpn-enable-macos: warning — full-tunnel NAT is limited on macOS Docker Desktop; split-tunnel admin access is recommended." >&2
fi

if [[ "$OBFUSCATION" == "shadowsocks" ]]; then
	echo "mpc-auth-vpn-enable-macos: warning — allow TCP/UDP ${SS_PORT} through macOS Firewall for remote Shadowsocks clients." >&2
fi

macos_desktop_sudo mkdir -p "$WG_HOST_DIR"
macos_desktop_sudo chmod 0700 "$WG_HOST_DIR"
macos_desktop_sudo install -m 0600 "${WG_SRC_DIR}/wg0.conf" "${WG_HOST_DIR}/wg0.conf"

_tmp_hooks="$(mktemp)"
cp "${WG_SRC_DIR}/wg0.conf" "$_tmp_hooks"
mpc_auth_vpn_prepare_wg0_conf "$_tmp_hooks" "$PROFILE" "$LISTEN_PORT" "$VPN_CIDR" "$MGMT_PORT" "$OBFUSCATION" "$SS_PORT"
macos_desktop_sudo install -m 0600 "$_tmp_hooks" "${WG_HOST_DIR}/wg0.conf"
rm -f "$_tmp_hooks"

macos_desktop_sudo wg-quick down wg0 2>/dev/null || true
macos_desktop_sudo wg-quick up "${WG_HOST_DIR}/wg0.conf"

if [[ "$OBFUSCATION" == "shadowsocks" ]]; then
	mpc_auth_vpn_start_shadowsocks_background "$SS_PIDFILE" "$SS_LOG"
fi

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
	echo "mpc-auth-vpn-enable-macos: socat not installed — run: brew install socat" >&2
fi

macos_desktop_sudo mkdir -p "$(dirname "$STATE_FILE")"
export STATE_FILE PROFILE LISTEN_PORT OBFUSCATION SS_PORT
macos_desktop_sudo env STATE_FILE="$STATE_FILE" PROFILE="$PROFILE" LISTEN_PORT="$LISTEN_PORT" OBFUSCATION="$OBFUSCATION" SS_PORT="$SS_PORT" python3 - <<'PY'
import json, datetime, os
path = os.environ["STATE_FILE"]
obfuscation = os.environ.get("OBFUSCATION", "none")
payload = {
    "active": True,
    "profile": os.environ.get("PROFILE", "split"),
    "obfuscation": obfuscation,
    "listenPort": int(os.environ.get("LISTEN_PORT", "51820")),
    "directWireGuardBlocked": obfuscation == "shadowsocks",
    "hostProfile": "macos_desktop",
    "updatedAt": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
}
if obfuscation == "shadowsocks":
    payload["shadowsocksListenPort"] = int(os.environ.get("SS_PORT", "8388"))
with open(path + ".tmp", "w") as f:
    json.dump(payload, f)
os.rename(path + ".tmp", path)
PY

echo "mpc-auth-vpn-enable-macos: WireGuard VPN enabled (profile=${PROFILE}, obfuscation=${OBFUSCATION})"
