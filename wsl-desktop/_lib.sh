#!/usr/bin/env bash
# Shared helpers for wsl-desktop host automation (sourced, not executed).
set -euo pipefail

# Non-interactive sudo for Docker extension installs (passwordless sudo required).
wsl_desktop_sudo() {
	if [[ "$(id -u)" -eq 0 ]]; then
		"$@"
	else
		sudo -n "$@"
	fi
}

wsl_desktop_root() {
	local src="${BASH_SOURCE[1]:-${BASH_SOURCE[0]}}"
	cd "$(dirname "$src")" && pwd
}

wsl_desktop_repo_dir() {
	local root env_file
	root="$(wsl_desktop_root)"
	if [[ -f "${root}/repo-dir.txt" ]]; then
		cat "${root}/repo-dir.txt"
		return 0
	fi
	cd "${root}/.." && pwd
}

wsl_desktop_env_file() {
	printf '%s/mpc-auth-docker.env' "$(wsl_desktop_root)"
}

wsl_desktop_libexec() {
	printf '%s/libexec' "$(wsl_desktop_root)"
}

wsl_desktop_load_env() {
	local env_file
	env_file="$(wsl_desktop_env_file)"
	if [[ -r "$env_file" ]]; then
		# shellcheck source=/dev/null
		. "$env_file"
	fi
	if [[ -r /etc/default/mpc-auth-docker ]]; then
		# shellcheck source=/dev/null
		. /etc/default/mpc-auth-docker
	fi
}

wsl_desktop_pidfile() {
	printf '%s/watcher.pid' "$(wsl_desktop_root)"
}

wsl_desktop_logfile() {
	printf '%s/watcher.log' "$(wsl_desktop_root)"
}

wsl_desktop_pending_file() {
	wsl_desktop_load_env
	printf '%s' "${MPC_AUTH_DOCKER_PENDING_FILE:-/var/lib/mpc-auth-docker/pending-update.json}"
}

wsl_desktop_vpn_pending_file() {
	wsl_desktop_load_env
	printf '%s' "${MPC_AUTH_VPN_PENDING_FILE:-/var/lib/mpc-auth-docker/pending-vpn.json}"
}

wsl_desktop_apply_pending() {
	local libexec apply env_file
	libexec="$(wsl_desktop_libexec)"
	apply="${libexec}/mpc-auth-apply-pending-update.sh"
	env_file="$(wsl_desktop_env_file)"
	if [[ ! -x "$apply" ]]; then
		echo "error: missing ${apply} — run install-wsl-desktop-host-automation.sh" >&2
		return 1
	fi
	export MPC_AUTH_WSL_ENV_FILE="$env_file"
	export MPC_AUTH_SYNC_COMPOSE_ROLE_SCRIPT="${libexec}/mpc-auth-sync-compose-role.sh"
	wsl_desktop_sudo env MPC_AUTH_WSL_ENV_FILE="$env_file" \
		MPC_AUTH_SYNC_COMPOSE_ROLE_SCRIPT="${libexec}/mpc-auth-sync-compose-role.sh" \
		"$apply"
}

wsl_desktop_apply_pending_vpn() {
	local libexec apply env_file
	libexec="$(wsl_desktop_libexec)"
	apply="${libexec}/mpc-auth-apply-pending-vpn.sh"
	env_file="$(wsl_desktop_env_file)"
	if [[ ! -x "$apply" ]]; then
		echo "error: missing ${apply} — run install-wsl-desktop-host-automation.sh" >&2
		return 1
	fi
	export MPC_AUTH_WSL_ENV_FILE="$env_file"
	wsl_desktop_sudo env MPC_AUTH_WSL_ENV_FILE="$env_file" "$apply"
}
