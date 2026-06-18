#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
. "${HERE}/_lib.sh"

pidfile="$(wsl_desktop_pidfile)"
logfile="$(wsl_desktop_logfile)"
pending="$(wsl_desktop_pending_file)"
repo="$(wsl_desktop_repo_dir)"

echo "repo: ${repo}"
echo "pending file: ${pending}"
echo "env: $(wsl_desktop_env_file)"
echo "libexec: $(wsl_desktop_libexec)"
echo "log: ${logfile}"

if [[ -f "$pidfile" ]]; then
	pid="$(cat "$pidfile" 2>/dev/null || true)"
	if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
		echo "status: running (pid ${pid})"
		exit 0
	fi
	echo "status: not running (stale pidfile: ${pid:-empty})"
	exit 1
fi

echo "status: not running"
exit 1
