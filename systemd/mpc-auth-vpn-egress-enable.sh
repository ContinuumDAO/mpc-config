#!/usr/bin/env bash
# Enable WireGuard peer egress VPN (wg-egress) after mpc-auth POST /vpn/egress/setSharing.

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
		echo "mpc-auth-vpn-egress-enable: missing ${name}" >&2
		exit 1
	fi
}

_lib mpc-auth-vpn-wg0-hooks.sh
_lib mpc-auth-vpn-wg-egress-hooks.sh
_lib mpc-auth-vpn-obfuscation-hooks.sh
_lib mpc-auth-vpn-ss-hooks.sh

WG_HOST_DIR="${MPC_AUTH_WIREGUARD_HOST_DIR:-/etc/wireguard}"
WG_SRC_DIR="${MPC_AUTH_WIREGUARD_EGRESS_SRC_DIR:-/var/lib/mpc-auth-docker/wireguard-egress}"
STATE_FILE="${MPC_AUTH_VPN_EGRESS_STATE_FILE:-/var/lib/mpc-auth-docker/vpn-egress-state.json}"
LISTEN_PORT="${MPC_AUTH_WIREGUARD_EGRESS_LISTEN_PORT:-51830}"
VPN_CIDR="${MPC_AUTH_WIREGUARD_EGRESS_VPN_CIDR:-10.9.0.0/24}"
OBFUSCATION="$(mpc_auth_vpn_normalize_obfuscation "${MPC_AUTH_VPN_EGRESS_OBFUSCATION:-none}")"
export MPC_AUTH_VPN_EGRESS_OBFUSCATION="$OBFUSCATION"

TRANSPORT_PORT=0
case "$OBFUSCATION" in
shadowsocks)
	TRANSPORT_PORT="${MPC_AUTH_SHADOWSOCKS_EGRESS_LISTEN_PORT:-8390}"
	export MPC_AUTH_SHADOWSOCKS_LISTEN_PORT="$TRANSPORT_PORT"
	;;
esac

echo "mpc-auth-vpn-egress-enable: obfuscation=${OBFUSCATION}" >&2

if [[ ! -f "${WG_SRC_DIR}/wg-egress.conf" ]]; then
	echo "mpc-auth-vpn-egress-enable: missing ${WG_SRC_DIR}/wg-egress.conf" >&2
	exit 1
fi

if [[ "$OBFUSCATION" == "shadowsocks" && ! -f "/var/lib/mpc-auth-docker/shadowsocks-egress/ssserver.json" ]]; then
	echo "mpc-auth-vpn-egress-enable: missing shadowsocks-egress ssserver.json" >&2
	exit 1
fi

if ! command -v wg-quick >/dev/null 2>&1; then
	echo "mpc-auth-vpn-egress-enable: wg-quick not found" >&2
	exit 1
fi

mkdir -p "$WG_HOST_DIR"
chmod 0700 "$WG_HOST_DIR"
install -m 0600 "${WG_SRC_DIR}/wg-egress.conf" "${WG_HOST_DIR}/wg-egress.conf"

mpc_auth_vpn_egress_prepare_wg_conf "${WG_HOST_DIR}/wg-egress.conf" "$VPN_CIDR" "$LISTEN_PORT" "$OBFUSCATION" "$TRANSPORT_PORT"

if ! mpc_auth_vpn_egress_ensure_ufw_listen_port "$LISTEN_PORT" "$OBFUSCATION" "$TRANSPORT_PORT"; then
	echo "mpc-auth-vpn-egress-enable: UFW/firewall check failed for peer egress UDP (see above)" >&2
	exit 1
fi

systemctl daemon-reload
systemctl enable mpc-auth-wireguard-wg-egress.service
systemctl restart mpc-auth-wireguard-wg-egress.service

if [[ "$OBFUSCATION" == "shadowsocks" ]]; then
	systemctl enable mpc-auth-shadowsocks-egress.service 2>/dev/null || true
	systemctl restart mpc-auth-shadowsocks-egress.service 2>/dev/null || true
fi

LIMITS_FILE="${WG_SRC_DIR}/peer-rate-limits.json"
if [[ -f "$LIMITS_FILE" ]]; then
	mpc_auth_vpn_egress_apply_tc_limits wg-egress "$LIMITS_FILE" || true
fi

mkdir -p "$(dirname "$STATE_FILE")"
export STATE_FILE LISTEN_PORT OBFUSCATION TRANSPORT_PORT
python3 - <<'PY'
import json, datetime, os
path = os.environ["STATE_FILE"]
obfuscation = os.environ.get("OBFUSCATION", "none")
transport_port = int(os.environ.get("TRANSPORT_PORT", "0") or "0")
payload = {
    "active": True,
    "obfuscation": obfuscation,
    "listenPort": int(os.environ.get("LISTEN_PORT", "51830")),
    "sharingEnabled": True,
    "directWireGuardBlocked": obfuscation in ("shadowsocks", "wg_obfuscator", "lwo", "udp2raw"),
    "updatedAt": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
}
if obfuscation == "shadowsocks" and transport_port > 0:
    payload["shadowsocksListenPort"] = transport_port
with open(path + ".tmp", "w") as f:
    json.dump(payload, f)
os.rename(path + ".tmp", path)
PY

echo "mpc-auth-vpn-egress-enable: wg-egress enabled (obfuscation=${OBFUSCATION})"
