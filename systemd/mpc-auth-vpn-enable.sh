#!/usr/bin/env bash
# Enable WireGuard admin VPN on the Docker host after mpc-auth POST /vpn/setEnabled.
# Invoked by mpc-auth-apply-pending-vpn.sh (systemd.path on pending-vpn.json).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_lib() {
	local name="$1"
	if [[ -f "${HERE}/${name}" ]]; then
		# shellcheck source=/dev/null
		. "${HERE}/${name}"
	elif [[ -f "${HERE}/../scripts/lib/${name}" ]]; then
		# shellcheck source=/dev/null
		. "${HERE}/../scripts/lib/${name}"
	else
		echo "mpc-auth-vpn-enable: missing ${name} (re-run install-mpc-auth-docker-systemd.sh)" >&2
		exit 1
	fi
}

_lib mpc-auth-vpn-wg0-hooks.sh
_lib mpc-auth-vpn-ss-hooks.sh
_lib mpc-auth-vpn-wg-obfuscator-hooks.sh
_lib mpc-auth-vpn-lwo-hooks.sh
_lib mpc-auth-vpn-udp2raw-hooks.sh
_lib mpc-auth-vpn-obfuscation-hooks.sh

LIBEXEC="/usr/local/libexec/mpc-auth"
WG_HOST_DIR="${MPC_AUTH_WIREGUARD_HOST_DIR:-/etc/wireguard}"
WG_SRC_DIR="${MPC_AUTH_WIREGUARD_SRC_DIR:-/var/lib/mpc-auth-docker/wireguard}"
STATE_FILE="${MPC_AUTH_VPN_STATE_FILE:-/var/lib/mpc-auth-docker/vpn-state.json}"
LISTEN_PORT="${MPC_AUTH_WIREGUARD_LISTEN_PORT:-51820}"
VPN_CIDR="${MPC_AUTH_WIREGUARD_VPN_CIDR:-10.8.0.0/24}"
MGMT_PORT="${MPC_AUTH_VPN_MGMT_PORT:-8080}"

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

TRANSPORT_PORT=0
case "$OBFUSCATION" in
shadowsocks)
	TRANSPORT_PORT="$(mpc_auth_vpn_read_shadowsocks_listen_port)"
	export MPC_AUTH_SHADOWSOCKS_LISTEN_PORT="$TRANSPORT_PORT"
	;;
wg_obfuscator)
	TRANSPORT_PORT="$(mpc_auth_vpn_read_wg_obfuscator_listen_port)"
	export MPC_AUTH_WG_OBFUSCATOR_LISTEN_PORT="$TRANSPORT_PORT"
	;;
lwo)
	TRANSPORT_PORT="$(mpc_auth_vpn_read_lwo_listen_port)"
	export MPC_AUTH_LWO_LISTEN_PORT="$TRANSPORT_PORT"
	;;
udp2raw)
	TRANSPORT_PORT="$(mpc_auth_vpn_read_udp2raw_listen_port)"
	export MPC_AUTH_UDP2RAW_LISTEN_PORT="$TRANSPORT_PORT"
	;;
esac
export MPC_AUTH_VPN_TRANSPORT_PORT="$TRANSPORT_PORT"

echo "mpc-auth-vpn-enable: profile=${PROFILE} obfuscation=${OBFUSCATION}" >&2

if [[ ! -f "${WG_SRC_DIR}/wg0.conf" ]]; then
	echo "mpc-auth-vpn-enable: missing ${WG_SRC_DIR}/wg0.conf (mpc-auth must write WireGuard config first)" >&2
	exit 1
fi

if [[ "$OBFUSCATION" == "shadowsocks" && ! -f "$(mpc_auth_vpn_shadowsocks_config_path)" ]]; then
	echo "mpc-auth-vpn-enable: missing $(mpc_auth_vpn_shadowsocks_config_path) (mpc-auth must write Shadowsocks config first)" >&2
	exit 1
fi

if [[ "$OBFUSCATION" == "wg_obfuscator" && ! -f "$(mpc_auth_vpn_wg_obfuscator_config_path)" ]]; then
	echo "mpc-auth-vpn-enable: missing $(mpc_auth_vpn_wg_obfuscator_config_path) (mpc-auth must write wg-obfuscator config first)" >&2
	exit 1
fi

if [[ "$OBFUSCATION" == "lwo" && ! -f "$(mpc_auth_vpn_lwo_server_config_path)" ]]; then
	echo "mpc-auth-vpn-enable: missing $(mpc_auth_vpn_lwo_server_config_path) (mpc-auth must write LWO config first)" >&2
	exit 1
fi

if [[ "$OBFUSCATION" == "udp2raw" && ! -f "$(mpc_auth_vpn_udp2raw_server_env_path)" ]]; then
	echo "mpc-auth-vpn-enable: missing $(mpc_auth_vpn_udp2raw_server_env_path) (mpc-auth must write udp2raw config first)" >&2
	exit 1
fi

if ! command -v wg-quick >/dev/null 2>&1; then
	echo "mpc-auth-vpn-enable: wg-quick not found — install wireguard package" >&2
	exit 1
fi

mkdir -p "$WG_HOST_DIR"
chmod 0700 "$WG_HOST_DIR"
install -m 0600 "${WG_SRC_DIR}/wg0.conf" "${WG_HOST_DIR}/wg0.conf"

mpc_auth_vpn_prepare_wg0_conf "${WG_HOST_DIR}/wg0.conf" "$PROFILE" "$LISTEN_PORT" "$VPN_CIDR" "$MGMT_PORT" "$OBFUSCATION" "$TRANSPORT_PORT"

systemctl daemon-reload
systemctl enable mpc-auth-wireguard-wg0.service
systemctl restart mpc-auth-wireguard-wg0.service

if [[ "$OBFUSCATION" != "none" ]]; then
	mpc_auth_vpn_start_obfuscation_systemd "$OBFUSCATION"
fi

if command -v socat >/dev/null 2>&1; then
	systemctl enable mpc-auth-vpn-mgmt-proxy.service
	systemctl restart mpc-auth-vpn-mgmt-proxy.service
else
	echo "mpc-auth-vpn-enable: socat not installed — VPN clients cannot reach management API on 10.8.0.1:${MGMT_PORT}" >&2
fi

mkdir -p "$(dirname "$STATE_FILE")"
export STATE_FILE PROFILE LISTEN_PORT OBFUSCATION TRANSPORT_PORT
python3 - <<'PY'
import json, datetime, os
path = os.environ["STATE_FILE"]
obfuscation = os.environ.get("OBFUSCATION", "none")
transport_port = int(os.environ.get("TRANSPORT_PORT", "0") or "0")
payload = {
    "active": True,
    "profile": os.environ.get("PROFILE", "split"),
    "obfuscation": obfuscation,
    "listenPort": int(os.environ.get("LISTEN_PORT", "51820")),
    "directWireGuardBlocked": obfuscation in ("shadowsocks", "wg_obfuscator", "lwo", "udp2raw"),
    "updatedAt": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
}
if obfuscation == "shadowsocks" and transport_port > 0:
    payload["shadowsocksListenPort"] = transport_port
if obfuscation == "wg_obfuscator" and transport_port > 0:
    payload["wgObfuscatorListenPort"] = transport_port
if obfuscation == "lwo" and transport_port > 0:
    payload["lwoListenPort"] = transport_port
if obfuscation == "udp2raw" and transport_port > 0:
    payload["udp2rawListenPort"] = transport_port
with open(path + ".tmp", "w") as f:
    json.dump(payload, f)
os.rename(path + ".tmp", path)
PY

echo "mpc-auth-vpn-enable: WireGuard VPN enabled (profile=${PROFILE}, obfuscation=${OBFUSCATION})"
