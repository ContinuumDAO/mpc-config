#!/usr/bin/env bash
# wg-obfuscator transport obfuscation for WireGuard admin VPN.
# Sourced via mpc-auth-vpn-obfuscation-hooks.sh on systemd and desktop hosts.

# mpc_auth_vpn_wg_obfuscator_config_path
mpc_auth_vpn_wg_obfuscator_config_path() {
	local dir="${MPC_AUTH_WG_OBFUSCATOR_SRC_DIR:-/var/lib/mpc-auth-docker/wg-obfuscator}"
	printf '%s/server.conf' "$dir"
}

# mpc_auth_vpn_wg_obfuscator_bin — resolve wg-obfuscator binary path.
mpc_auth_vpn_wg_obfuscator_bin() {
	if [[ -n "${MPC_AUTH_WG_OBFUSCATOR_BIN:-}" && -x "${MPC_AUTH_WG_OBFUSCATOR_BIN}" ]]; then
		printf '%s' "${MPC_AUTH_WG_OBFUSCATOR_BIN}"
		return 0
	fi
	if command -v wg-obfuscator >/dev/null 2>&1; then
		command -v wg-obfuscator
		return 0
	fi
	return 1
}

# mpc_auth_vpn_read_wg_obfuscator_listen_port — from server.conf or env default.
mpc_auth_vpn_read_wg_obfuscator_listen_port() {
	local cfg port
	cfg="$(mpc_auth_vpn_wg_obfuscator_config_path)"
	port="${MPC_AUTH_WG_OBFUSCATOR_LISTEN_PORT:-51822}"
	if [[ -f "$cfg" ]]; then
		local parsed
		parsed="$(awk -F= '/^[[:space:]]*source-lport[[:space:]]*=/ {gsub(/ /,"",$2); print $2; exit}' "$cfg" 2>/dev/null || true)"
		if [[ -n "$parsed" ]]; then
			port="$parsed"
		fi
	fi
	printf '%s' "$port"
}

# mpc_auth_vpn_start_wg_obfuscator_systemd
mpc_auth_vpn_start_wg_obfuscator_systemd() {
	local cfg
	cfg="$(mpc_auth_vpn_wg_obfuscator_config_path)"
	if [[ ! -f "$cfg" ]]; then
		echo "mpc-auth-vpn-wg-obfuscator-hooks: missing ${cfg} (mpc-auth must write wg-obfuscator config first)" >&2
		return 1
	fi
	if ! mpc_auth_vpn_wg_obfuscator_bin >/dev/null; then
		echo "mpc-auth-vpn-wg-obfuscator-hooks: wg-obfuscator not found — install from GitHub releases" >&2
		return 1
	fi
	if ! command -v systemctl >/dev/null 2>&1; then
		echo "mpc-auth-vpn-wg-obfuscator-hooks: systemctl required for wg-obfuscator service" >&2
		return 1
	fi
	systemctl daemon-reload
	systemctl enable mpc-auth-wg-obfuscator.service
	systemctl restart mpc-auth-wg-obfuscator.service
}

# mpc_auth_vpn_stop_wg_obfuscator_systemd
mpc_auth_vpn_stop_wg_obfuscator_systemd() {
	if command -v systemctl >/dev/null 2>&1; then
		systemctl stop mpc-auth-wg-obfuscator.service 2>/dev/null || true
		systemctl disable mpc-auth-wg-obfuscator.service 2>/dev/null || true
	fi
}
