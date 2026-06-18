#!/usr/bin/env bash
# Consume pending-vpn.json written by mpc-auth POST /vpn/setEnabled (host path bind-mounted into container).
# systemd.path → this oneshot → mpc-auth-vpn-enable.sh or mpc-auth-vpn-disable.sh.

set -euo pipefail

PENDING_FILE="${MPC_AUTH_VPN_PENDING_FILE:-/var/lib/mpc-auth-docker/pending-vpn.json}"
LIBEXEC="/usr/local/libexec/mpc-auth"
ENABLE_SCRIPT="${LIBEXEC}/mpc-auth-vpn-enable.sh"
DISABLE_SCRIPT="${LIBEXEC}/mpc-auth-vpn-disable.sh"
DONE_DIR="$(dirname "$PENDING_FILE")/applied"
PROCESSING="${PENDING_FILE}.processing"

mkdir -p "$DONE_DIR"

if [[ ! -f "$PENDING_FILE" ]]; then
	exit 0
fi

if ! mv "$PENDING_FILE" "$PROCESSING"; then
	echo "mpc-auth-apply-pending-vpn: failed to claim ${PENDING_FILE}" >&2
	exit 1
fi

_stamp() {
	date +%Y%m%d%H%M%S
}

abort_bad_json() {
	echo "mpc-auth-apply-pending-vpn: invalid JSON in ${PROCESSING}" >&2
	mv -f "$PROCESSING" "${DONE_DIR}/failed-$(_stamp).bad.json" || true
	exit 1
}

if ! command -v python3 >/dev/null 2>&1; then
	echo "mpc-auth-apply-pending-vpn: python3 required to parse pending JSON" >&2
	mv -f "$PROCESSING" "${DONE_DIR}/failed-$(_stamp).nopython.json" || true
	exit 1
fi

export MPC_APPLY_PENDING_VPN_JSON="$PROCESSING"
eval "$(python3 <<'PY'
import json, os, shlex, sys
path = os.environ["MPC_APPLY_PENDING_VPN_JSON"]
with open(path) as f:
    d = json.load(f)
action = (d.get("action") or "").strip().lower()
profile = (d.get("profile") or "split").strip().lower()
if action not in ("enable", "disable"):
    sys.stderr.write(f"mpc-auth-apply-pending-vpn: unexpected action {action!r}\n")
    sys.exit(2)
if profile not in ("split", "full"):
    profile = "split"
print(f"export MPC_AUTH_VPN_ACTION={shlex.quote(action)}")
print(f"export MPC_AUTH_VPN_PROFILE={shlex.quote(profile)}")
PY
)" || abort_bad_json

run_apply() {
	local script="$1"
	if [[ ! -x "$script" ]]; then
		echo "mpc-auth-apply-pending-vpn: missing ${script}" >&2
		mv -f "$PROCESSING" "${DONE_DIR}/failed-$(_stamp).noscript.json" || true
		exit 1
	fi
	export MPC_AUTH_VPN_PROFILE
	if "$script"; then
		mv -f "$PROCESSING" "${DONE_DIR}/ok-$(_stamp).json" || rm -f "$PROCESSING"
		exit 0
	fi
	mv -f "$PROCESSING" "${DONE_DIR}/failed-$(_stamp).apply.json" || true
	exit 1
}

if [[ "$MPC_AUTH_VPN_ACTION" == "enable" ]]; then
	run_apply "$ENABLE_SCRIPT"
else
	run_apply "$DISABLE_SCRIPT"
fi
