#!/usr/bin/env bash
# Ensure wg-quick and socat are installed for WireGuard VPN host automation (systemd / WSL).
# Sourced by install scripts and systemd/install-mpc-auth-docker-systemd.sh — do not execute directly.

ensure_vpn_host_packages() {
	local dry_run="${CONTINUUM_INSTALL_DRY_RUN:-false}"
	if command -v wg-quick >/dev/null 2>&1 && command -v socat >/dev/null 2>&1; then
		return 0
	fi
	if [ "$dry_run" = true ]; then
		printf '[dry-run] apt-get install -y wireguard socat\n' >&2
		return 0
	fi
	if ! command -v apt-get >/dev/null 2>&1; then
		printf 'warning: wireguard and/or socat missing — install distro packages for VPN (wg-quick, socat)\n' >&2
		return 1
	fi
	printf '==> Installing wireguard and socat (VPN host automation)\n' >&2
	apt-get update -qq || return 1
	apt-get install -y wireguard socat || return 1
	command -v wg-quick >/dev/null 2>&1 && command -v socat >/dev/null 2>&1
}
