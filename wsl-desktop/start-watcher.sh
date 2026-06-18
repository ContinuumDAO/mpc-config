#!/usr/bin/env bash
# Start mpc-auth WSL pending-update watcher (idempotent).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
. "${HERE}/_lib.sh"

pidfile="$(wsl_desktop_pidfile)"
watcher="${HERE}/mpc-auth-wsl-pending-watcher.sh"
logfile="$(wsl_desktop_logfile)"

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
wsl_desktop_sudo mkdir -p "$(dirname "$(wsl_desktop_pending_file)")" "$(dirname "$(wsl_desktop_pending_file)")/applied"

nohup "$watcher" >>"$logfile" 2>&1 &
echo $! >"$pidfile"
echo "Started WSL pending watcher (pid $(cat "$pidfile")). Log: ${logfile}"
