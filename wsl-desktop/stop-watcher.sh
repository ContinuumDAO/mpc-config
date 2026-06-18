#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
. "${HERE}/_lib.sh"

pidfile="$(wsl_desktop_pidfile)"

if [[ ! -f "$pidfile" ]]; then
	echo "Watcher not running (no pidfile)."
	exit 0
fi

pid="$(cat "$pidfile" 2>/dev/null || true)"
if [[ -z "$pid" ]]; then
	rm -f "$pidfile"
	echo "Watcher not running (empty pidfile)."
	exit 0
fi

if kill -0 "$pid" 2>/dev/null; then
	kill "$pid" 2>/dev/null || true
	sleep 1
	if kill -0 "$pid" 2>/dev/null; then
		kill -9 "$pid" 2>/dev/null || true
	fi
	echo "Stopped watcher (pid ${pid})."
else
	echo "Watcher not running (stale pid ${pid})."
fi
rm -f "$pidfile"
