#!/usr/bin/env bash
# Consume pending-telegram-ngrok.json written by mpc-auth POST /telegramNgrok/setEnabled.
# systemd.path → this oneshot → mpc-auth-telegram-ngrok-{enable,disable}.sh

set -euo pipefail

PENDING_FILE="${MPC_AUTH_TELEGRAM_NGROK_PENDING_FILE:-/var/lib/mpc-auth-docker/pending-telegram-ngrok.json}"
LIBEXEC="/usr/local/libexec/mpc-auth"
ENABLE_SCRIPT="${LIBEXEC}/mpc-auth-telegram-ngrok-enable.sh"
DISABLE_SCRIPT="${LIBEXEC}/mpc-auth-telegram-ngrok-disable.sh"
DONE_DIR="$(dirname "$PENDING_FILE")/applied"
PROCESSING="${PENDING_FILE}.processing"

mkdir -p "$DONE_DIR"

if [[ ! -f "$PENDING_FILE" ]]; then
	exit 0
fi

if ! mv "$PENDING_FILE" "$PROCESSING"; then
	echo "mpc-auth-apply-pending-telegram-ngrok: failed to claim ${PENDING_FILE}" >&2
	exit 1
fi

_stamp() {
	date +%Y%m%d%H%M%S
}

abort_bad_json() {
	echo "mpc-auth-apply-pending-telegram-ngrok: invalid JSON in ${PROCESSING}" >&2
	mv -f "$PROCESSING" "${DONE_DIR}/failed-$(_stamp).bad.json" || true
	exit 1
}

if ! command -v python3 >/dev/null 2>&1; then
	echo "mpc-auth-apply-pending-telegram-ngrok: python3 required to parse pending JSON" >&2
	mv -f "$PROCESSING" "${DONE_DIR}/failed-$(_stamp).nopython.json" || true
	exit 1
fi

export MPC_APPLY_PENDING_TELEGRAM_NGROK_JSON="$PROCESSING"
eval "$(python3 <<'PY'
import json, os, shlex, sys
path = os.environ["MPC_APPLY_PENDING_TELEGRAM_NGROK_JSON"]
with open(path, encoding="utf-8") as f:
    d = json.load(f)
action = (d.get("action") or "").strip().lower()
if action not in ("enable", "disable"):
    sys.stderr.write(f"mpc-auth-apply-pending-telegram-ngrok: unexpected action {action!r}\n")
    sys.exit(2)
print(f"export MPC_AUTH_TELEGRAM_NGROK_ACTION={shlex.quote(action)}")
PY
)" || abort_bad_json

finalize_ok() {
	mv -f "$PROCESSING" "${DONE_DIR}/ok-$(_stamp).json" || rm -f "$PROCESSING"
	exit 0
}

finalize_fail() {
	mv -f "$PROCESSING" "${DONE_DIR}/failed-$(_stamp).apply.json" || true
	exit 1
}

run_script() {
	local script="$1"
	if [[ ! -x "$script" ]]; then
		echo "mpc-auth-apply-pending-telegram-ngrok: missing ${script}" >&2
		finalize_fail
	fi
	export MPC_APPLY_PENDING_TELEGRAM_NGROK_JSON
	"$script" || finalize_fail
}

if [[ "$MPC_AUTH_TELEGRAM_NGROK_ACTION" == "enable" ]]; then
	run_script "$ENABLE_SCRIPT"
	finalize_ok
else
	run_script "$DISABLE_SCRIPT"
	finalize_ok
fi
