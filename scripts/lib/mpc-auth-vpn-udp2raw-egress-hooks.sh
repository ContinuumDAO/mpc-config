#!/usr/bin/env bash
# udp2raw fake-TCP transport obfuscation for WireGuard peer egress (wg-egress).

mpc_auth_vpn_udp2raw_egress_server_env_path() {
	local dir="${MPC_AUTH_UDP2RAW_EGRESS_SRC_DIR:-/var/lib/mpc-auth-docker/udp2raw-egress}"
	printf '%s/server.env' "$dir"
}

mpc_auth_vpn_read_udp2raw_egress_listen_port() {
	local cfg port
	cfg="$(mpc_auth_vpn_udp2raw_egress_server_env_path)"
	port="${MPC_AUTH_UDP2RAW_EGRESS_LISTEN_PORT:-8443}"
	if [[ -f "$cfg" ]]; then
		local parsed
		parsed="$(awk -F= '/^[[:space:]]*LISTEN_PORT[[:space:]]*=/ {gsub(/ /,"",$2); print $2; exit}' "$cfg" 2>/dev/null || true)"
		if [[ -n "$parsed" ]]; then
			port="$parsed"
		fi
	fi
	printf '%s' "$port"
}

mpc_auth_vpn_start_udp2raw_egress_systemd() {
	local env_file
	env_file="$(mpc_auth_vpn_udp2raw_egress_server_env_path)"
	if [[ ! -f "$env_file" ]]; then
		echo "mpc-auth-vpn-udp2raw-egress-hooks: missing ${env_file}" >&2
		return 1
	fi
	if ! command -v udp2raw >/dev/null 2>&1; then
		echo "mpc-auth-vpn-udp2raw-egress-hooks: udp2raw not found" >&2
		return 1
	fi
	systemctl daemon-reload
	systemctl enable mpc-auth-udp2raw-egress.service
	systemctl restart mpc-auth-udp2raw-egress.service
}

mpc_auth_vpn_stop_udp2raw_egress_systemd() {
	if command -v systemctl >/dev/null 2>&1; then
		systemctl stop mpc-auth-udp2raw-egress.service 2>/dev/null || true
		systemctl disable mpc-auth-udp2raw-egress.service 2>/dev/null || true
	fi
}
