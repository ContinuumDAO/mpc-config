#!/usr/bin/env bash
# Long-running WSL host watcher: pending-update.json + pending-vpn.json + pending-telegram-ngrok.json
# (Windows Docker Desktop; no WSL systemd).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
. "${HERE}/_lib.sh"

POLL_SECS="${CONTINUUM_WATCHER_POLL_SECS:-2}"
pending="$(wsl_desktop_pending_file)"
vpn_pending="$(wsl_desktop_vpn_pending_file)"
ngrok_pending="$(wsl_desktop_telegram_ngrok_pending_file)"
pending_dir="$(dirname "$pending")"
logfile="$(wsl_desktop_logfile)"

wsl_desktop_sudo mkdir -p "$pending_dir" "${pending_dir}/applied"

log() {
	printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$logfile" >&2
}

apply_vpn_once() {
	if [[ ! -f "$vpn_pending" ]]; then
		return 0
	fi
	log "pending VPN change detected — applying via mpc-auth-apply-pending-vpn.sh"
	if wsl_desktop_apply_pending_vpn; then
		log "VPN apply finished OK"
	else
		log "VPN apply failed (see above)"
	fi
}

apply_telegram_ngrok_once() {
	if [[ ! -f "$ngrok_pending" ]]; then
		return 0
	fi
	log "pending Telegram ngrok change detected — applying via mpc-auth-apply-pending-telegram-ngrok.sh"
	if wsl_desktop_apply_pending_telegram_ngrok; then
		log "Telegram ngrok apply finished OK"
	else
		log "Telegram ngrok apply failed (see above)"
	fi
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

apply_all() {
	apply_once
	apply_vpn_once
	apply_telegram_ngrok_once
}

log "Continuum mpc-auth WSL pending watcher started (poll=${POLL_SECS}s, update=${pending}, vpn=${vpn_pending}, telegram-ngrok=${ngrok_pending})"

# Always poll so Docker Desktop bind-mount events that miss inotify still apply.
# inotifywait -t wakes early on close_write/create; timeout falls through to poll.
if command -v inotifywait >/dev/null 2>&1; then
	log "using inotifywait + ${POLL_SECS}s poll on ${pending_dir}"
	while true; do
		inotifywait -q -t "$POLL_SECS" -e close_write,moved_to,create "${pending_dir}" 2>/dev/null || true
		apply_all
	done
else
	log "inotifywait not found — polling every ${POLL_SECS}s (optional: sudo apt install inotify-tools)"
	while true; do
		apply_all
		sleep "$POLL_SECS"
	done
fi
