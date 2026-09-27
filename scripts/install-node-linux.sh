#!/usr/bin/env bash
# Linux entry point for the Continuum MPA node one-shot install.
# Reads /etc/os-release and runs the Debian/Ubuntu, Arch-family, or Fedora installer
# with the same arguments.
#
#   curl -fsSL "https://raw.githubusercontent.com/ContinuumDAO/mpc-config/main/scripts/install-node-linux.sh" \
#     | bash -s -- --node-mgt-key "0xYour40Hex..." --ip "203.0.113.50"
#
# Supported: Ubuntu, Debian, and derivatives (apt); systemd Arch derivatives
# (Arch, Omarchy, Manjaro, EndeavourOS, Garuda, CachyOS, ArcoLinux) via pacman;
# Fedora Workstation and Fedora Server via dnf; openSUSE Leap and Tumbleweed
# via zypper.
# Refused: Artix, Obarun (no systemd), SteamOS (immutable root), Fedora
# Silverblue, Kinoite, Atomic, Bazzite, openSUSE MicroOS, Aeon, and Kalpa.
#
set -euo pipefail

MPC_CONFIG_REF="${MPC_CONFIG_REF:-main}"
_raw_base="https://raw.githubusercontent.com/ContinuumDAO/mpc-config/${MPC_CONFIG_REF}"

die() {
	printf 'error: %s\n' "$*" >&2
	exit 1
}

SCRIPT_DIR=""
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
	SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi

if [ -n "$SCRIPT_DIR" ] && [ -f "${SCRIPT_DIR}/lib/linux-os-family.sh" ]; then
	# shellcheck source=lib/linux-os-family.sh
	. "${SCRIPT_DIR}/lib/linux-os-family.sh"
else
	_family_tmp="$(mktemp)"
	curl -fsSL "${_raw_base}/scripts/lib/linux-os-family.sh" -o "$_family_tmp"
	# shellcheck source=/dev/null
	. "$_family_tmp"
	rm -f "$_family_tmp"
fi

if [ ! -r /etc/os-release ]; then
	die "cannot read /etc/os-release"
fi

family="$(continuum_linux_family_from_release /etc/os-release)"
case "$family" in
debian)
	target_name="install-node-debian-ubuntu.sh"
	;;
arch)
	if ! command -v pacman >/dev/null 2>&1; then
		die "Arch-family host has no pacman — cannot install packages"
	fi
	if ! command -v systemctl >/dev/null 2>&1; then
		die "systemd (systemctl) is required. Artix and Obarun are not supported."
	fi
	target_name="install-node-arch.sh"
	;;
fedora)
	if ! command -v dnf >/dev/null 2>&1; then
		die "Fedora host has no dnf — cannot install packages"
	fi
	if ! command -v systemctl >/dev/null 2>&1; then
		die "systemd (systemctl) is required."
	fi
	if [ -f /run/ostree-booted ]; then
		die "immutable Fedora (Silverblue, Kinoite, Atomic) is not supported. Use Fedora Workstation or Fedora Server."
	fi
	target_name="install-node-fedora.sh"
	;;
opensuse)
	if ! command -v zypper >/dev/null 2>&1; then
		die "openSUSE host has no zypper — cannot install packages"
	fi
	if ! command -v systemctl >/dev/null 2>&1; then
		die "systemd (systemctl) is required."
	fi
	target_name="install-node-opensuse.sh"
	;;
*)
	# shellcheck source=/dev/null
	. /etc/os-release
	die "unsupported OS: ${PRETTY_NAME:-unknown}. Supported: Ubuntu/Debian (apt), systemd Arch derivatives (Arch, Omarchy, Manjaro, EndeavourOS, Garuda, CachyOS, ArcoLinux), Fedora Workstation or Server (dnf), and openSUSE Leap or Tumbleweed (zypper). Not supported: Artix, Obarun, SteamOS, Fedora Silverblue, Kinoite, Atomic, Bazzite, openSUSE MicroOS, Aeon, Kalpa."
	;;
esac

if [ -n "$SCRIPT_DIR" ] && [ -f "${SCRIPT_DIR}/${target_name}" ]; then
	exec bash "${SCRIPT_DIR}/${target_name}" "$@"
fi

curl -fsSL "${_raw_base}/scripts/${target_name}" | bash -s -- "$@"
