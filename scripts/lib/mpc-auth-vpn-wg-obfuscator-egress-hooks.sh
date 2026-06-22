#!/usr/bin/env bash
# wg-obfuscator transport obfuscation for WireGuard peer egress (wg-egress).

mpc_auth_vpn_wg_obfuscator_egress_config_path() {
	local dir="${MPC_AUTH_WG_OBFUSCATOR_EGRESS_SRC_DIR:-/var/lib/mpc-auth-docker/wg-obfuscator-egress}"
	printf '%s/server.conf' "$dir"
}

mpc_auth_vpn_read_wg_obfuscator_egress_listen_port() {
	local cfg port
	cfg="$(mpc_auth_vpn_wg_obfuscator_egress_config_path)"
	port="${MPC_AUTH_WG_OBFUSCATOR_EGRESS_LISTEN_PORT:-51832}"
	if [[ -f "$cfg" ]]; then
		local parsed
		parsed="$(awk -F= '/^[[:space:]]*source-lport[[:space:]]*=/ {gsub(/ /,"",$2); print $2; exit}' "$cfg" 2>/dev/null || true)"
		if [[ -n "$parsed" ]]; then
			port="$parsed"
		fi
	fi
	printf '%s' "$port"
}

mpc_auth_vpn_start_wg_obfuscator_egress_systemd() {
	local cfg
	cfg="$(mpc_auth_vpn_wg_obfuscator_egress_config_path)"
	if [[ ! -f "$cfg" ]]; then
		echo "mpc-auth-vpn-wg-obfuscator-egress-hooks: missing ${cfg}" >&2
		return 1
	fi
	if ! command -v wg-obfuscator >/dev/null 2>&1; then
		echo "mpc-auth-vpn-wg-obfuscator-egress-hooks: wg-obfuscator not found" >&2
		return 1
	fi
	systemctl daemon-reload
	systemctl enable mpc-auth-wg-obfuscator-egress.service
	systemctl restart mpc-auth-wg-obfuscator-egress.service
}

mpc_auth_vpn_stop_wg_obfuscator_egress_systemd() {
	if command -v systemctl >/dev/null 2>&1; then
		systemctl stop mpc-auth-wg-obfuscator-egress.service 2>/dev/null || true
		systemctl disable mpc-auth-wg-obfuscator-egress.service 2>/dev/null || true
	fi
}
