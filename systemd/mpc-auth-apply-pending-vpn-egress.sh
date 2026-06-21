#!/usr/bin/env bash
# Consume pending-vpn-egress.json written by mpc-auth egress API.

set -euo pipefail

PENDING_FILE="${MPC_AUTH_VPN_EGRESS_PENDING_FILE:-/var/lib/mpc-auth-docker/pending-vpn-egress.json}"
LIBEXEC="/usr/local/libexec/mpc-auth"
ENABLE_SCRIPT="${LIBEXEC}/mpc-auth-vpn-egress-enable.sh"
DISABLE_SCRIPT="${LIBEXEC}/mpc-auth-vpn-egress-disable.sh"
DONE_DIR="$(dirname "$PENDING_FILE")/applied"
PROCESSING="${PENDING_FILE}.processing"

mkdir -p "$DONE_DIR"

if [[ ! -f "$PENDING_FILE" ]]; then
	exit 0
fi

if ! mv "$PENDING_FILE" "$PROCESSING"; then
	echo "mpc-auth-apply-pending-vpn-egress: failed to claim ${PENDING_FILE}" >&2
	exit 1
fi

_stamp() { date +%Y%m%d%H%M%S; }

if ! command -v python3 >/dev/null 2>&1; then
	mv -f "$PROCESSING" "${DONE_DIR}/failed-$(_stamp).nopython.json" || true
	exit 1
fi

export MPC_APPLY_PENDING_VPN_EGRESS_JSON="$PROCESSING"
eval "$(python3 <<'PY'
import json, os, shlex, sys
path = os.environ["MPC_APPLY_PENDING_VPN_EGRESS_JSON"]
with open(path) as f:
    d = json.load(f)
action = (d.get("action") or "").strip().lower()
obfuscation = (d.get("obfuscation") or "none").strip().lower()
rate = d.get("defaultRateLimitMbps") or 0
if action not in ("enable", "disable", "sync"):
    sys.stderr.write(f"unexpected action {action!r}\n")
    sys.exit(2)
if obfuscation not in ("none", "shadowsocks", "wg_obfuscator", "lwo", "udp2raw"):
    obfuscation = "none"
print(f"export MPC_AUTH_VPN_EGRESS_ACTION={shlex.quote(action)}")
print(f"export MPC_AUTH_VPN_EGRESS_OBFUSCATION={shlex.quote(obfuscation)}")
print(f"export MPC_AUTH_VPN_EGRESS_DEFAULT_RATE_MBPS={shlex.quote(str(rate))}")
PY
)" || {
	echo "mpc-auth-apply-pending-vpn-egress: invalid JSON" >&2
	mv -f "$PROCESSING" "${DONE_DIR}/failed-$(_stamp).bad.json" || true
	exit 1
}

run_script() {
	local script="$1"
	if [[ ! -x "$script" ]]; then
		echo "mpc-auth-apply-pending-vpn-egress: missing ${script}" >&2
		mv -f "$PROCESSING" "${DONE_DIR}/failed-$(_stamp).missing-script.json" || true
		exit 1
	fi
	"$script"
}

case "$MPC_AUTH_VPN_EGRESS_ACTION" in
enable | sync)
	run_script "$ENABLE_SCRIPT"
	;;
disable)
	run_script "$DISABLE_SCRIPT"
	;;
esac

mv -f "$PROCESSING" "${DONE_DIR}/ok-$(_stamp).json" || rm -f "$PROCESSING"
