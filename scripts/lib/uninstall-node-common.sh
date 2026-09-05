#!/usr/bin/env bash
# Shared helpers for Continuum MPC / MPA node uninstall scripts (sourced, not executed).
# Node artifacts only: compose stack, Continuum images, host automation state, repo, VPS user.
# Does not remove Docker Engine, UFW, WireGuard, Homebrew, or apt packages.

UNINSTALL_BACKUP_DOCS="https://docs.continuumdao.org/ContinuumDAO/MPAWallet/BackupAndRestoration"
UNINSTALL_EJECT_DOCS="https://docs.continuumdao.org/ContinuumDAO/MPAWallet/EjectConversion"
UNINSTALL_PUBLISHED_DOCS="https://docs.continuumdao.org/ContinuumDAO/MPAWallet/Uninstall"

UNINSTALL_CONTINUUM_IMAGES=(
	"continuumdao/mpc-auth"
	"continuumdao/continuumdao-node-app"
	"continuumdao/continuum-mcp-server"
	"continuumdao/continuum-node-installer"
)

UNINSTALL_OPTIONAL_IMAGES=(
	"mongo:6.0"
	"eclipse-mosquitto:2.0"
	"ngrok/ngrok:latest"
	"ngrok/ngrok"
	"curlimages/curl:8.7.1"
)

uninstall_print_warnings() {
	cat <<EOF >&2

========================================================================
UNINSTALL WARNING — this deletes the node on this machine
========================================================================

Before you continue, do ONE of the following:

  1. Back up this node's bootstrap key pair AND an encrypted database
     backup. Store them in SEPARATE places (not the same folder or vault).
     ${UNINSTALL_BACKUP_DOCS}

  2. OR Eject your KeyGens (export the full private key, then retire MPC
     for that address):
     ${UNINSTALL_EJECT_DOCS}

  3. OR transfer all assets to another wallet first.

TSS / threshold: if you delete this node, other nodes in the same KeyGen
may no longer reach the signing threshold. A 2-of-2 wallet freezes if this
node is gone. A 2-of-3 wallet can still sign if the other two remain.

This script removes node artifacts only (containers, Continuum images,
host automation, mpc-config, and on a VPS the mpcnode user). It does not
uninstall Docker Engine, UFW, WireGuard, or OS packages.

Published guide: ${UNINSTALL_PUBLISHED_DOCS}
========================================================================

EOF
}

uninstall_is_tty() {
	[[ -t 0 && -t 1 ]]
}

uninstall_confirm() {
	# Usage: uninstall_confirm
	# Honors UNINSTALL_YES=true to skip prompts (agents).
	if [[ "${UNINSTALL_YES:-false}" == true ]]; then
		echo "Non-interactive (--yes): proceeding after printed warnings." >&2
		return 0
	fi
	if ! uninstall_is_tty; then
		echo "error: no TTY — re-run with --yes after the operator confirmed backup/eject and TSS risk." >&2
		return 1
	fi
	local ans
	read -r -p "Have you backed up bootstrap+database, ejected KeyGens, or transferred assets? [y/N] " ans
	case "${ans}" in
	y | Y | yes | YES) ;;
	*)
		echo "Aborted. Complete a backup, eject, or transfer first." >&2
		return 1
		;;
	esac
	read -r -p "Do you understand that other KeyGen nodes may miss the TSS signing threshold? [y/N] " ans
	case "${ans}" in
	y | Y | yes | YES) ;;
	*)
		echo "Aborted." >&2
		return 1
		;;
	esac
	read -r -p "Proceed with uninstall and permanently delete this node? [y/N] " ans
	case "${ans}" in
	y | Y | yes | YES) return 0 ;;
	*)
		echo "Aborted." >&2
		return 1
		;;
	esac
}

uninstall_run() {
	if [[ "${UNINSTALL_DRY_RUN:-false}" == true ]]; then
		printf '[dry-run] '
		printf '%q ' "$@"
		printf '\n'
		return 0
	fi
	"$@"
}

uninstall_require_root() {
	if [[ "${EUID:-0}" -ne 0 ]]; then
		echo "error: run as root (sudo)" >&2
		return 1
	fi
}

# Prints macos | wsl | linux | unknown
uninstall_host_kind() {
	local uname_s
	uname_s="$(uname -s 2>/dev/null || true)"
	case "$uname_s" in
	Darwin)
		printf '%s\n' macos
		return 0
		;;
	esac
	if [[ -n "${WSL_DISTRO_NAME:-}" ]]; then
		printf '%s\n' wsl
		return 0
	fi
	if [[ -r /proc/version ]] && grep -qi microsoft /proc/version 2>/dev/null; then
		printf '%s\n' wsl
		return 0
	fi
	case "$uname_s" in
	Linux)
		printf '%s\n' linux
		return 0
		;;
	esac
	printf '%s\n' unknown
}

# Usage: uninstall_require_host linux|wsl|macos
uninstall_require_host() {
	local want="$1"
	local got
	got="$(uninstall_host_kind)"
	if [[ "$got" == "$want" ]]; then
		return 0
	fi
	echo "error: this script is for ${want} hosts; this machine looks like ${got}." >&2
	case "$got" in
	linux)
		echo "  Use: scripts/uninstall-node-debian-ubuntu.sh" >&2
		echo "  Raw: https://raw.githubusercontent.com/ContinuumDAO/mpc-config/main/scripts/uninstall-node-debian-ubuntu.sh" >&2
		;;
	wsl)
		echo "  Use: scripts/uninstall-node-docker-desktop.sh (inside WSL)" >&2
		echo "  Raw: https://raw.githubusercontent.com/ContinuumDAO/mpc-config/main/scripts/uninstall-node-docker-desktop.sh" >&2
		;;
	macos)
		echo "  Use: scripts/uninstall-node-macos-docker-desktop.sh" >&2
		echo "  Raw: https://raw.githubusercontent.com/ContinuumDAO/mpc-config/main/scripts/uninstall-node-macos-docker-desktop.sh" >&2
		;;
	*)
		echo "  Linux VPS: uninstall-node-debian-ubuntu.sh" >&2
		echo "  Windows/WSL: uninstall-node-docker-desktop.sh" >&2
		echo "  macOS: uninstall-node-macos-docker-desktop.sh" >&2
		;;
	esac
	return 1
}

uninstall_login_user() {
	if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
		printf '%s\n' "$SUDO_USER"
		return 0
	fi
	if [[ -n "${UNINSTALL_LOGIN_USER:-}" ]]; then
		printf '%s\n' "$UNINSTALL_LOGIN_USER"
		return 0
	fi
	id -un
}

uninstall_login_home() {
	local user home
	user="$(uninstall_login_user)"
	if command -v getent >/dev/null 2>&1; then
		home="$(getent passwd "$user" 2>/dev/null | cut -d: -f6 || true)"
	fi
	if [[ -z "${home:-}" ]]; then
		home="$(eval echo "~${user}" 2>/dev/null || true)"
	fi
	if [[ -z "${home:-}" || "$home" == "~${user}" ]]; then
		if [[ "$user" == "root" ]]; then
			home="/root"
		else
			home="/home/${user}"
		fi
	fi
	printf '%s\n' "$home"
}

uninstall_docker_bin() {
	if command -v docker >/dev/null 2>&1; then
		command -v docker
		return 0
	fi
	echo ""
	return 1
}

uninstall_compose_down() {
	local repo_dir="$1"
	local docker_bin
	docker_bin="$(uninstall_docker_bin || true)"
	if [[ -z "$docker_bin" ]]; then
		echo "docker not found — skipping compose down." >&2
		return 0
	fi
	if [[ ! -d "$repo_dir" ]]; then
		echo "No repo at ${repo_dir} — skipping compose down." >&2
		return 0
	fi
	if [[ -f "${repo_dir}/docker-compose.yml" ]]; then
		echo "Stopping docker compose stack in ${repo_dir}..." >&2
		if [[ "${UNINSTALL_DRY_RUN:-false}" == true ]]; then
			echo "[dry-run] docker compose -f ${repo_dir}/docker-compose.yml down" >&2
		else
			(cd "$repo_dir" && docker compose down) || true
		fi
	else
		echo "No docker-compose.yml in ${repo_dir} — skipping compose down." >&2
	fi
}

uninstall_remove_sidecar() {
	local docker_bin
	docker_bin="$(uninstall_docker_bin || true)"
	if [[ -z "$docker_bin" ]]; then
		return 0
	fi
	if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -qx 'mpc-auth-telegram-ngrok'; then
		echo "Removing sidecar container mpc-auth-telegram-ngrok..." >&2
		uninstall_run docker rm -f mpc-auth-telegram-ngrok || true
	fi
}

uninstall_image_in_use() {
	local ref="$1"
	local ids
	ids="$(docker ps -a --filter "ancestor=${ref}" -q 2>/dev/null || true)"
	[[ -n "$ids" ]]
}

uninstall_remove_image_ref() {
	local ref="$1"
	local ids
	ids="$(docker images -q "$ref" 2>/dev/null || true)"
	if [[ -z "$ids" ]]; then
		return 0
	fi
	echo "Removing docker image ${ref}..." >&2
	# shellcheck disable=SC2086
	uninstall_run docker rmi $ids || true
}

uninstall_remove_images() {
	local docker_bin ref
	docker_bin="$(uninstall_docker_bin || true)"
	if [[ -z "$docker_bin" ]]; then
		echo "docker not found — skipping image removal." >&2
		return 0
	fi
	if [[ "${UNINSTALL_KEEP_IMAGES:-false}" == true ]]; then
		echo "Keeping docker images (--keep-images)." >&2
		return 0
	fi
	for ref in "${UNINSTALL_CONTINUUM_IMAGES[@]}"; do
		uninstall_remove_image_ref "$ref" || true
	done
	for ref in "${UNINSTALL_OPTIONAL_IMAGES[@]}"; do
		if uninstall_image_in_use "$ref"; then
			echo "Leaving ${ref} (still used by another container)." >&2
			continue
		fi
		uninstall_remove_image_ref "$ref" || true
	done
}

uninstall_remove_var_lib() {
	if [[ -d /var/lib/mpc-auth-docker ]]; then
		echo "Removing /var/lib/mpc-auth-docker..." >&2
		uninstall_run rm -rf /var/lib/mpc-auth-docker
	else
		echo "No /var/lib/mpc-auth-docker directory." >&2
	fi
}

uninstall_remove_repo() {
	local repo_dir="$1"
	if [[ "${UNINSTALL_KEEP_REPO:-false}" == true ]]; then
		echo "Keeping repo at ${repo_dir} (--keep-repo)." >&2
		return 0
	fi
	if [[ -z "$repo_dir" || "$repo_dir" == "/" || "$repo_dir" == "/home" || "$repo_dir" == "/Users" ]]; then
		echo "error: refusing to remove unsafe repo path: ${repo_dir:-empty}" >&2
		return 1
	fi
	if [[ ! -d "$repo_dir" ]]; then
		echo "No repo directory ${repo_dir}." >&2
		return 0
	fi
	echo "Removing ${repo_dir}..." >&2
	uninstall_run rm -rf "$repo_dir"
}

uninstall_remove_install_logs() {
	local f
	for f in /var/log/continuumdao-mpc-install.log /var/log/continuumdao-mpc-linux-desktop-install.log; do
		if [[ -f "$f" ]]; then
			echo "Removing ${f}..." >&2
			uninstall_run rm -f "$f"
		fi
	done
}

uninstall_fetch_raw() {
	# Usage: uninstall_fetch_raw RELATIVE_PATH DEST
	local rel="$1" dest="$2"
	local ref="${MPC_CONFIG_REF:-main}"
	local url="https://raw.githubusercontent.com/ContinuumDAO/mpc-config/${ref}/${rel}"
	curl -fsSL "$url" -o "$dest"
}
