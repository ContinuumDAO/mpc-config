#!/usr/bin/env bash
# Classify a Linux host for the Continuum node installer.
# Source this file; do not execute it directly.
#
# continuum_linux_family_from_release [os-release-path]
#   Prints "debian", "arch", or "unsupported".
#   debian: Ubuntu, Debian, Linux Mint, and ID_LIKE debian/ubuntu.
#   arch: systemd Arch derivatives (Arch, Omarchy, Manjaro, EndeavourOS,
#         Garuda, CachyOS, ArcoLinux, and other ID_LIKE=arch hosts).
#   unsupported: Artix, Obarun, SteamOS, and anything else.
#   This function only reads os-release. Callers that select the pacman
#   installer must also require pacman and systemctl.

continuum_linux_family_from_release() {
	local release_file="${1:-/etc/os-release}"
	if [ ! -r "$release_file" ]; then
		printf 'unsupported\n'
		return 0
	fi
	(
		# shellcheck source=/dev/null
		. "$release_file"
		local id="${ID:-}" id_like="${ID_LIKE:-}"
		case "$id" in
		steamos | artix | obarun)
			printf 'unsupported\n'
			return 0
			;;
		esac
		case "$id" in
		debian | ubuntu | linuxmint)
			printf 'debian\n'
			return 0
			;;
		arch | omarchy)
			printf 'arch\n'
			return 0
			;;
		esac
		if [[ "$id_like" == *debian* || "$id_like" == *ubuntu* ]]; then
			printf 'debian\n'
			return 0
		fi
		if [[ "$id" == *arch* || "$id_like" == *arch* || "$id_like" == *omarchy* ]]; then
			printf 'arch\n'
			return 0
		fi
		printf 'unsupported\n'
	)
}

# Script path relative to the mpc-config repo root.
continuum_linux_install_script_for_family() {
	case "${1:-}" in
	debian)
		printf 'scripts/install-node-debian-ubuntu.sh\n'
		;;
	arch)
		printf 'scripts/install-node-arch.sh\n'
		;;
	*)
		return 1
		;;
	esac
}

# pacman -S --needed, syncing the database only when the first attempt fails.
# Honors CONTINUUM_INSTALL_DRY_RUN=true.
continuum_pacman_install() {
	if [ "$#" -eq 0 ]; then
		return 0
	fi
	if [ "${CONTINUUM_INSTALL_DRY_RUN:-false}" = true ]; then
		printf '[dry-run] pacman -S --needed --noconfirm %s\n' "$*" >&2
		return 0
	fi
	if pacman -S --needed --noconfirm "$@"; then
		return 0
	fi
	printf '==> Syncing pacman database and retrying\n' >&2
	pacman -Sy --needed --noconfirm "$@"
}
