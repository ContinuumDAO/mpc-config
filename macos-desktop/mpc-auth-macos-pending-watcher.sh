#!/usr/bin/env bash
# Long-running macOS host watcher: pending-update.json + pending-vpn.json (Docker Desktop; no launchd path units).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
. "${HERE}/_lib.sh"

POLL_SECS="${CONTINUUM_WATCHER_POLL_SECS:-2}"
pending="$(macos_desktop_pending_file)"
vpn_pending="$(macos_desktop_vpn_pending_file)"
pending_dir="$(dirname "$pending")"
logfile="$(macos_desktop_logfile)"

macos_desktop_sudo mkdir -p "$pending_dir" "${pending_dir}/applied"

log() {
	printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$logfile" >&2
}

apply_vpn_once() {
	if [[ ! -f "$vpn_pending" ]]; then
		return 0
	fi
	log "pending VPN change detected — applying via mpc-auth-apply-pending-vpn.sh"
	if macos_desktop_apply_pending_vpn; then
		log "VPN apply finished OK"
	else
		log "VPN apply failed (see above)"
	fi
}

apply_once() {
	if [[ ! -f "$pending" ]]; then
		return 0
	fi
	log "pending update detected — applying via mpc-auth-apply-pending-update.sh"
	if macos_desktop_apply_pending; then
		log "apply finished OK"
	else
		log "apply failed (see above)"
	fi
}

log "Continuum mpc-auth macOS pending watcher started (poll=${POLL_SECS}s, update=${pending}, vpn=${vpn_pending})"

if command -v fswatch >/dev/null 2>&1; then
	log "using fswatch on ${pending_dir}"
	while true; do
		fswatch -1 -r "$pending_dir" >/dev/null 2>&1 || sleep "$POLL_SECS"
		apply_once
		apply_vpn_once
	done
else
	log "fswatch not found — polling every ${POLL_SECS}s (optional: brew install fswatch)"
	while true; do
		apply_once
		apply_vpn_once
		sleep "$POLL_SECS"
	done
fi
