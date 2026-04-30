#!/usr/bin/env bash
# Consume pending-reboot.json written by mpc-auth POST /reboot (host path bind-mounted into container).
# systemd.path → this oneshot → systemctl reboot (systemd hosts only — no legacy shutdown fallback).
#
# Unattended reboot: try `systemctl reboot --check-inhibitors=no` first (systemd 247+) so a desktop session's
# logind "idle" inhibitor does not block maintenance reboots; fall back to plain `systemctl reboot` if the
# option is unsupported. This unit has no TTY (see .service StandardInput=) so interactive "are you sure?"
# prompts from this script path are not possible — anything that still blocks shutdown must be fixed on the
# host (inhibitors, Polkit, or broken poweroff scripts); see systemd/README.md.

set -euo pipefail

PENDING_FILE="${MPC_AUTH_PENDING_REBOOT_FILE:-/var/lib/mpc-auth-docker/pending-reboot.json}"
LIBEXEC="/usr/local/libexec/mpc-auth"
DONE_DIR="$(dirname "$PENDING_FILE")/applied"
PROCESSING="${PENDING_FILE}.processing"

mkdir -p "$DONE_DIR"

if [[ ! -f "$PENDING_FILE" ]]; then
	exit 0
fi

if ! mv "$PENDING_FILE" "$PROCESSING"; then
	echo "mpc-auth-apply-pending-reboot: failed to claim ${PENDING_FILE}" >&2
	exit 1
fi

_stamp() {
	date +%Y%m%d%H%M%S
}

abort_bad_json() {
	echo "mpc-auth-apply-pending-reboot: invalid JSON in ${PROCESSING}" >&2
	mv -f "$PROCESSING" "${DONE_DIR}/failed-$(_stamp).bad.json" || true
	exit 1
}

if ! command -v python3 >/dev/null 2>&1; then
	echo "mpc-auth-apply-pending-reboot: python3 required to validate pending JSON" >&2
	mv -f "$PROCESSING" "${DONE_DIR}/failed-$(_stamp).nopython.json" || true
	exit 1
fi

export MPC_APPLY_PENDING_REBOOT_JSON="$PROCESSING"
if ! python3 <<'PY'
import json, os, sys
path = os.environ["MPC_APPLY_PENDING_REBOOT_JSON"]
with open(path) as f:
    d = json.load(f)
kind = (d.get("kind") or "").strip()
if kind and kind != "hostReboot":
    sys.stderr.write(f"mpc-auth-apply-pending-reboot: unexpected kind {kind!r}\n")
    sys.exit(2)
PY
then
	abort_bad_json
fi

echo "mpc-auth-apply-pending-reboot: scheduling host reboot (claimed ${PROCESSING})"
mv -f "$PROCESSING" "${DONE_DIR}/ok-$(_stamp).json" || rm -f "$PROCESSING"

if ! command -v systemctl >/dev/null 2>&1; then
	echo "mpc-auth-apply-pending-reboot: systemctl not found — this automation requires systemd on the host; reconfigure or reboot manually." >&2
	exit 1
fi

# Prefer skipping logind inhibitors (e.g. GUI "inhibit idle" / power key handling) for API-driven maintenance.
set +e
systemctl reboot --check-inhibitors=no
rc=$?
set -e
if [[ "$rc" -eq 0 ]]; then
	exit 0
fi

exec systemctl reboot
