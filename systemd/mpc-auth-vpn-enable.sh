#!/usr/bin/env bash
# Enable WireGuard admin VPN on the Docker host after mpc-auth POST /vpn/setEnabled.
# Invoked by mpc-auth-apply-pending-vpn.sh (systemd.path on pending-vpn.json).

set -euo pipefail

LIBEXEC="/usr/local/libexec/mpc-auth"
WG_HOST_DIR="${MPC_AUTH_WIREGUARD_HOST_DIR:-/etc/wireguard}"
WG_SRC_DIR="${MPC_AUTH_WIREGUARD_SRC_DIR:-/var/lib/mpc-auth-docker/wireguard}"
STATE_FILE="${MPC_AUTH_VPN_STATE_FILE:-/var/lib/mpc-auth-docker/vpn-state.json}"
LISTEN_PORT="${MPC_AUTH_WIREGUARD_LISTEN_PORT:-51820}"
VPN_CIDR="${MPC_AUTH_WIREGUARD_VPN_CIDR:-10.8.0.0/24}"
MGMT_PORT="${MPC_AUTH_VPN_MGMT_PORT:-8080}"
PROFILE="${MPC_AUTH_VPN_PROFILE:-split}"

if [[ ! -f "${WG_SRC_DIR}/wg0.conf" ]]; then
	echo "mpc-auth-vpn-enable: missing ${WG_SRC_DIR}/wg0.conf (mpc-auth must write WireGuard config first)" >&2
	exit 1
fi

if ! command -v wg-quick >/dev/null 2>&1; then
	echo "mpc-auth-vpn-enable: wg-quick not found — install wireguard package" >&2
	exit 1
fi

mkdir -p "$WG_HOST_DIR"
chmod 0700 "$WG_HOST_DIR"
install -m 0600 "${WG_SRC_DIR}/wg0.conf" "${WG_HOST_DIR}/wg0.conf"

if [[ "$PROFILE" == "full" ]]; then
	default_if="$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')"
	default_if="${default_if:-eth0}"
	{
		echo ""
		echo "# full-tunnel NAT (appended by mpc-auth-vpn-enable.sh)"
		echo "PostUp = sysctl -w net.ipv4.ip_forward=1; iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o ${default_if} -j MASQUERADE"
		echo "PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o ${default_if} -j MASQUERADE"
	} >>"${WG_HOST_DIR}/wg0.conf"
fi

if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi "Status: active"; then
	ufw allow "${LISTEN_PORT}/udp" comment 'Continuum WireGuard VPN' || true
	ufw allow from "${VPN_CIDR}" to any port "${MGMT_PORT}" proto tcp comment 'Continuum VPN management API' || true
fi

systemctl daemon-reload
systemctl enable mpc-auth-wireguard-wg0.service
systemctl restart mpc-auth-wireguard-wg0.service

if command -v socat >/dev/null 2>&1; then
	systemctl enable mpc-auth-vpn-mgmt-proxy.service
	systemctl restart mpc-auth-vpn-mgmt-proxy.service
else
	echo "mpc-auth-vpn-enable: socat not installed — VPN clients cannot reach management API on 10.8.0.1:${MGMT_PORT}" >&2
fi

mkdir -p "$(dirname "$STATE_FILE")"
export STATE_FILE PROFILE LISTEN_PORT
python3 - <<'PY'
import json, datetime, os
path = os.environ["STATE_FILE"]
payload = {
    "active": True,
    "profile": os.environ.get("PROFILE", "split"),
    "listenPort": int(os.environ.get("LISTEN_PORT", "51820")),
    "updatedAt": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
}
with open(path + ".tmp", "w") as f:
    json.dump(payload, f)
os.rename(path + ".tmp", path)
PY

echo "mpc-auth-vpn-enable: WireGuard VPN enabled (profile=${PROFILE})"
