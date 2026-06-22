#!/usr/bin/env bash
# Disable WireGuard peer egress VPN (wg-egress).

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
	fi
}

_lib mpc-auth-vpn-obfuscation-hooks.sh
_lib mpc-auth-vpn-wg-obfuscator-egress-hooks.sh
_lib mpc-auth-vpn-udp2raw-egress-hooks.sh

STATE_FILE="${MPC_AUTH_VPN_EGRESS_STATE_FILE:-/var/lib/mpc-auth-docker/vpn-egress-state.json}"

if declare -F mpc_auth_vpn_stop_obfuscation_egress_systemd >/dev/null 2>&1; then
	mpc_auth_vpn_stop_obfuscation_egress_systemd
fi

systemctl stop mpc-auth-wireguard-wg-egress.service 2>/dev/null || true
systemctl disable mpc-auth-wireguard-wg-egress.service 2>/dev/null || true

if command -v wg-quick >/dev/null 2>&1; then
	wg-quick down wg-egress 2>/dev/null || true
fi

if command -v tc >/dev/null 2>&1; then
	tc qdisc del dev wg-egress root 2>/dev/null || true
fi

mkdir -p "$(dirname "$STATE_FILE")"
python3 - <<'PY'
import json, datetime, os
path = os.environ.get("STATE_FILE", "/var/lib/mpc-auth-docker/vpn-egress-state.json")
payload = {
    "active": False,
    "sharingEnabled": False,
    "updatedAt": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
}
with open(path + ".tmp", "w") as f:
    json.dump(payload, f)
os.rename(path + ".tmp", path)
PY

echo "mpc-auth-vpn-egress-disable: wg-egress disabled"
