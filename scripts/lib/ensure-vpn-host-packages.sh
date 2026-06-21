#!/usr/bin/env bash
# Ensure wg-quick, socat, and iproute2 (tc/ip) are installed for WireGuard VPN host automation (systemd / WSL).
# Sourced by install scripts and systemd/install-mpc-auth-docker-systemd.sh — do not execute directly.

ensure_vpn_host_packages() {
	local dry_run="${CONTINUUM_INSTALL_DRY_RUN:-false}"
	if command -v wg-quick >/dev/null 2>&1 \
		&& command -v socat >/dev/null 2>&1 \
		&& command -v tc >/dev/null 2>&1 \
		&& command -v ip >/dev/null 2>&1; then
		return 0
	fi
	if [ "$dry_run" = true ]; then
		printf '[dry-run] apt-get install -y wireguard socat iproute2\n' >&2
		return 0
	fi
	if ! command -v apt-get >/dev/null 2>&1; then
		printf 'warning: wireguard, socat, and/or iproute2 missing — install distro packages for VPN (wg-quick, socat, tc, ip)\n' >&2
		return 1
	fi
	printf '==> Installing wireguard, socat, and iproute2 (VPN host automation + egress rate limits)\n' >&2
	apt-get update -qq || return 1
	apt-get install -y wireguard socat iproute2 || return 1
	command -v wg-quick >/dev/null 2>&1 \
		&& command -v socat >/dev/null 2>&1 \
		&& command -v tc >/dev/null 2>&1 \
		&& command -v ip >/dev/null 2>&1
}
