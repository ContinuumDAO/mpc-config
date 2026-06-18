#!/usr/bin/env bash
# Long-running WSL host watcher: pending-update.json → mpc-auth-apply-pending-update.sh
# Windows Docker Desktop profile (replaces systemd.path on WSL; no WSL systemd required).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
. "${HERE}/_lib.sh"

POLL_SECS="${CONTINUUM_WATCHER_POLL_SECS:-2}"
pending="$(wsl_desktop_pending_file)"
pending_dir="$(dirname "$pending")"
logfile="$(wsl_desktop_logfile)"

mkdir -p "$pending_dir" "${pending_dir}/applied" 2>/dev/null || true

log() {
	printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$logfile" >&2
}

apply_once() {
	if [[ ! -f "$pending" ]]; then
		return 0
	fi
	log "pending update detected — applying via mpc-auth-apply-pending-update.sh"
	if wsl_desktop_apply_pending; then
		log "apply finished OK"
	else
		log "apply failed (see above)"
	fi
}

log "Continuum mpc-auth WSL pending watcher started (poll=${POLL_SECS}s, file=${pending})"

if command -v inotifywait >/dev/null 2>&1; then
	log "using inotifywait on ${pending_dir}"
	while true; do
		inotifywait -q -e close_write,moved_to,create "${pending_dir}" 2>/dev/null || sleep "$POLL_SECS"
		apply_once
	done
else
	log "inotifywait not found — polling every ${POLL_SECS}s (optional: sudo apt install inotify-tools)"
	while true; do
		apply_once
		sleep "$POLL_SECS"
	done
fi
