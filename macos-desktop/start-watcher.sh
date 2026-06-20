#!/usr/bin/env bash
# Start mpc-auth macOS pending-update watcher (idempotent).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
. "${HERE}/_lib.sh"

pidfile="$(macos_desktop_pidfile)"
watcher="${HERE}/mpc-auth-macos-pending-watcher.sh"
logfile="$(macos_desktop_logfile)"

if [[ ! -x "$watcher" ]]; then
	echo "error: missing executable ${watcher}" >&2
	exit 1
fi

if [[ -f "$pidfile" ]]; then
	old_pid="$(cat "$pidfile" 2>/dev/null || true)"
	if [[ -n "$old_pid" ]] && kill -0 "$old_pid" 2>/dev/null; then
		echo "Watcher already running (pid ${old_pid})."
		exit 0
	fi
	rm -f "$pidfile"
fi

mkdir -p "$(dirname "$logfile")"
macos_desktop_sudo mkdir -p "$(dirname "$(macos_desktop_pending_file)")" "$(dirname "$(macos_desktop_pending_file)")/applied"

nohup "$watcher" >>"$logfile" 2>&1 &
echo $! >"$pidfile"
echo "Started macOS pending watcher (pid $(cat "$pidfile")). Log: ${logfile}"
