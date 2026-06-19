#!/usr/bin/env bash
# Enable WireGuard admin VPN on the Docker host after mpc-auth POST /vpn/setEnabled.
# Invoked by mpc-auth-apply-pending-vpn.sh (systemd.path on pending-vpn.json).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${HERE}/mpc-auth-vpn-wg0-hooks.sh" ]]; then
	# shellcheck source=mpc-auth-vpn-wg0-hooks.sh
	. "${HERE}/mpc-auth-vpn-wg0-hooks.sh"
elif [[ -f "${HERE}/../scripts/lib/mpc-auth-vpn-wg0-hooks.sh" ]]; then
	# shellcheck source=../scripts/lib/mpc-auth-vpn-wg0-hooks.sh
	. "${HERE}/../scripts/lib/mpc-auth-vpn-wg0-hooks.sh"
else
	echo "mpc-auth-vpn-enable: missing mpc-auth-vpn-wg0-hooks.sh (re-run install-mpc-auth-docker-systemd.sh)" >&2
	exit 1
fi

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

mpc_auth_vpn_prepare_wg0_conf "${WG_HOST_DIR}/wg0.conf" "$PROFILE" "$LISTEN_PORT" "$VPN_CIDR" "$MGMT_PORT"

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
