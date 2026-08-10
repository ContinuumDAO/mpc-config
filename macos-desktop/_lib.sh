#!/usr/bin/env bash
# Shared helpers for macos-desktop host automation (sourced, not executed).
set -euo pipefail

# Non-interactive sudo for Docker extension installs (passwordless sudo required).
macos_desktop_sudo() {
	if [[ "$(id -u)" -eq 0 ]]; then
		"$@"
	else
		sudo -n "$@"
	fi
}

macos_desktop_root() {
	local src="${BASH_SOURCE[1]:-${BASH_SOURCE[0]}}"
	cd "$(dirname "$src")" && pwd
}

macos_desktop_repo_dir() {
	local root
	root="$(macos_desktop_root)"
	if [[ -f "${root}/repo-dir.txt" ]]; then
		cat "${root}/repo-dir.txt"
		return 0
	fi
	cd "${root}/.." && pwd
}

macos_desktop_env_file() {
	printf '%s/mpc-auth-docker.env' "$(macos_desktop_root)"
}

macos_desktop_libexec() {
	printf '%s/libexec' "$(macos_desktop_root)"
}

macos_desktop_load_env() {
	local env_file
	env_file="$(macos_desktop_env_file)"
	if [[ -r "$env_file" ]]; then
		# shellcheck source=/dev/null
		. "$env_file"
	fi
	if [[ -r /etc/default/mpc-auth-docker ]]; then
		# shellcheck source=/dev/null
		. /etc/default/mpc-auth-docker
	fi
}

macos_desktop_pidfile() {
	printf '%s/watcher.pid' "$(macos_desktop_root)"
}

macos_desktop_logfile() {
	printf '%s/watcher.log' "$(macos_desktop_root)"
}

macos_desktop_pending_file() {
	macos_desktop_load_env
	printf '%s' "${MPC_AUTH_DOCKER_PENDING_FILE:-/var/lib/mpc-auth-docker/pending-update.json}"
}

macos_desktop_vpn_pending_file() {
	macos_desktop_load_env
	printf '%s' "${MPC_AUTH_VPN_PENDING_FILE:-/var/lib/mpc-auth-docker/pending-vpn.json}"
}

macos_desktop_telegram_ngrok_pending_file() {
	macos_desktop_load_env
	printf '%s' "${MPC_AUTH_TELEGRAM_NGROK_PENDING_FILE:-/var/lib/mpc-auth-docker/pending-telegram-ngrok.json}"
}

macos_desktop_apply_pending() {
	local libexec apply env_file
	libexec="$(macos_desktop_libexec)"
	apply="${libexec}/mpc-auth-apply-pending-update.sh"
	env_file="$(macos_desktop_env_file)"
	if [[ ! -x "$apply" ]]; then
		echo "error: missing ${apply} — run install-macos-desktop-host-automation.sh" >&2
		return 1
	fi
	export MPC_AUTH_MACOS_ENV_FILE="$env_file"
	export MPC_AUTH_SYNC_COMPOSE_ROLE_SCRIPT="${libexec}/mpc-auth-sync-compose-role.sh"
	macos_desktop_sudo env MPC_AUTH_MACOS_ENV_FILE="$env_file" \
		MPC_AUTH_SYNC_COMPOSE_ROLE_SCRIPT="${libexec}/mpc-auth-sync-compose-role.sh" \
		"$apply"
}

macos_desktop_apply_pending_vpn() {
	local libexec apply env_file
	libexec="$(macos_desktop_libexec)"
	apply="${libexec}/mpc-auth-apply-pending-vpn.sh"
	env_file="$(macos_desktop_env_file)"
	if [[ ! -x "$apply" ]]; then
		echo "error: missing ${apply} — run install-macos-desktop-host-automation.sh" >&2
		return 1
	fi
	export MPC_AUTH_MACOS_ENV_FILE="$env_file"
	macos_desktop_sudo env MPC_AUTH_MACOS_ENV_FILE="$env_file" "$apply"
}

macos_desktop_apply_pending_telegram_ngrok() {
	local libexec apply env_file
	libexec="$(macos_desktop_libexec)"
	apply="${libexec}/mpc-auth-apply-pending-telegram-ngrok.sh"
	env_file="$(macos_desktop_env_file)"
	if [[ ! -x "$apply" ]]; then
		echo "error: missing ${apply} — run install-macos-desktop-host-automation.sh" >&2
		return 1
	fi
	export MPC_AUTH_MACOS_ENV_FILE="$env_file"
	macos_desktop_sudo env MPC_AUTH_MACOS_ENV_FILE="$env_file" "$apply"
}

macos_desktop_wireguard_host_dir() {
	if [[ -n "${MPC_AUTH_WIREGUARD_HOST_DIR:-}" ]]; then
		printf '%s' "$MPC_AUTH_WIREGUARD_HOST_DIR"
		return 0
	fi
	if command -v brew >/dev/null 2>&1; then
		printf '%s/etc/wireguard' "$(brew --prefix)"
		return 0
	fi
	printf '/usr/local/etc/wireguard'
}
