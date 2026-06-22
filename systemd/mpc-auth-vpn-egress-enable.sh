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
_lib mpc-auth-vpn-wg-obfuscator-egress-hooks.sh
_lib mpc-auth-vpn-udp2raw-egress-hooks.sh

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
	if [[ -f "/var/lib/mpc-auth-docker/shadowsocks-egress/ssserver.json" ]] && command -v python3 >/dev/null 2>&1; then
		TRANSPORT_PORT="$(python3 - "/var/lib/mpc-auth-docker/shadowsocks-egress/ssserver.json" "$TRANSPORT_PORT" <<'PY'
import json, sys
path, default = sys.argv[1], int(sys.argv[2])
try:
    with open(path, encoding="utf-8") as f:
        d = json.load(f)
    servers = d.get("servers") or []
    if servers:
        print(int(servers[0].get("server_port", default)))
    else:
        print(default)
except (OSError, json.JSONDecodeError, ValueError, TypeError):
    print(default)
PY
)" || TRANSPORT_PORT="${MPC_AUTH_SHADOWSOCKS_EGRESS_LISTEN_PORT:-8390}"
	fi
	export MPC_AUTH_SHADOWSOCKS_EGRESS_LISTEN_PORT="$TRANSPORT_PORT"
	;;
wg_obfuscator)
	TRANSPORT_PORT="$(mpc_auth_vpn_read_wg_obfuscator_egress_listen_port)"
	export MPC_AUTH_WG_OBFUSCATOR_EGRESS_LISTEN_PORT="$TRANSPORT_PORT"
	;;
udp2raw)
	TRANSPORT_PORT="$(mpc_auth_vpn_read_udp2raw_egress_listen_port)"
	export MPC_AUTH_UDP2RAW_EGRESS_LISTEN_PORT="$TRANSPORT_PORT"
	;;
esac

echo "mpc-auth-vpn-egress-enable: obfuscation=${OBFUSCATION}" >&2

if [[ ! -f "${WG_SRC_DIR}/wg-egress.conf" ]]; then
	echo "mpc-auth-vpn-egress-enable: missing ${WG_SRC_DIR}/wg-egress.conf" >&2
	exit 1
fi

case "$OBFUSCATION" in
shadowsocks)
	if [[ ! -f "/var/lib/mpc-auth-docker/shadowsocks-egress/ssserver.json" ]]; then
		echo "mpc-auth-vpn-egress-enable: missing shadowsocks-egress ssserver.json" >&2
		exit 1
	fi
	;;
wg_obfuscator)
	if [[ ! -f "$(mpc_auth_vpn_wg_obfuscator_egress_config_path)" ]]; then
		echo "mpc-auth-vpn-egress-enable: missing $(mpc_auth_vpn_wg_obfuscator_egress_config_path)" >&2
		exit 1
	fi
	;;
udp2raw)
	if [[ ! -f "$(mpc_auth_vpn_udp2raw_egress_server_env_path)" ]]; then
		echo "mpc-auth-vpn-egress-enable: missing $(mpc_auth_vpn_udp2raw_egress_server_env_path)" >&2
		exit 1
	fi
	;;
esac

if ! command -v wg-quick >/dev/null 2>&1; then
	echo "mpc-auth-vpn-egress-enable: wg-quick not found" >&2
	exit 1
fi

mkdir -p "$WG_HOST_DIR"
chmod 0700 "$WG_HOST_DIR"
install -m 0600 "${WG_SRC_DIR}/wg-egress.conf" "${WG_HOST_DIR}/wg-egress.conf"

mpc_auth_vpn_egress_prepare_wg_conf "${WG_HOST_DIR}/wg-egress.conf" "$VPN_CIDR" "$LISTEN_PORT" "$OBFUSCATION" "$TRANSPORT_PORT"

if ! mpc_auth_vpn_egress_ensure_ufw_listen_port "$LISTEN_PORT" "$OBFUSCATION" "$TRANSPORT_PORT"; then
	echo "mpc-auth-vpn-egress-enable: UFW/firewall check failed for peer egress (see above)" >&2
	exit 1
fi

systemctl daemon-reload
systemctl enable mpc-auth-wireguard-wg-egress.service
systemctl restart mpc-auth-wireguard-wg-egress.service

if [[ "$OBFUSCATION" != "none" ]]; then
	mpc_auth_vpn_start_obfuscation_egress_systemd "$OBFUSCATION"
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
    "directWireGuardBlocked": obfuscation in ("shadowsocks", "wg_obfuscator", "udp2raw"),
    "updatedAt": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
}
if obfuscation == "shadowsocks" and transport_port > 0:
    payload["shadowsocksListenPort"] = transport_port
if obfuscation == "wg_obfuscator" and transport_port > 0:
    payload["wgObfuscatorListenPort"] = transport_port
if obfuscation == "udp2raw" and transport_port > 0:
    payload["udp2rawListenPort"] = transport_port
with open(path + ".tmp", "w") as f:
    json.dump(payload, f)
os.rename(path + ".tmp", path)
PY

echo "mpc-auth-vpn-egress-enable: wg-egress enabled (obfuscation=${OBFUSCATION})"
