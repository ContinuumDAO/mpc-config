#!/usr/bin/env bash
# Shadowsocks transport obfuscation for WireGuard admin VPN (shadowsocks-rust ssserver).
# Sourced by mpc-auth-vpn-enable/disable scripts on systemd and desktop hosts.

# mpc_auth_vpn_normalize_obfuscation [VALUE]
mpc_auth_vpn_normalize_obfuscation() {
	local v="${1:-${MPC_AUTH_VPN_OBFUSCATION:-none}}"
	v="${v,,}"
	v="${v// /}"
	if [[ "$v" == "shadowsocks" ]]; then
		printf '%s' "shadowsocks"
	else
		printf '%s' "none"
	fi
}

# mpc_auth_vpn_shadowsocks_config_path
mpc_auth_vpn_shadowsocks_config_path() {
	local dir="${MPC_AUTH_SHADOWSOCKS_SRC_DIR:-/var/lib/mpc-auth-docker/shadowsocks}"
	printf '%s/ssserver.json' "$dir"
}

# mpc_auth_vpn_ssserver_bin — resolve ssserver binary path.
mpc_auth_vpn_ssserver_bin() {
	if [[ -n "${MPC_AUTH_SHADOWSOCKS_SSSERVER_BIN:-}" && -x "${MPC_AUTH_SHADOWSOCKS_SSSERVER_BIN}" ]]; then
		printf '%s' "${MPC_AUTH_SHADOWSOCKS_SSSERVER_BIN}"
		return 0
	fi
	if command -v ssserver >/dev/null 2>&1; then
		command -v ssserver
		return 0
	fi
	return 1
}

# mpc_auth_vpn_read_shadowsocks_listen_port — from ssserver.json or env default.
mpc_auth_vpn_read_shadowsocks_listen_port() {
	local cfg port
	cfg="$(mpc_auth_vpn_shadowsocks_config_path)"
	port="${MPC_AUTH_SHADOWSOCKS_LISTEN_PORT:-8388}"
	if [[ -f "$cfg" ]] && command -v python3 >/dev/null 2>&1; then
		port="$(python3 - "$cfg" "$port" <<'PY'
import json, sys
path, default = sys.argv[1], int(sys.argv[2])
try:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
except (OSError, json.JSONDecodeError, ValueError):
    print(default)
    raise SystemExit(0)
servers = data.get("servers")
if isinstance(servers, list) and servers:
    port = int(servers[0].get("server_port", default))
elif "server_port" in data:
    port = int(data.get("server_port", default))
print(port)
PY
)" || port="${MPC_AUTH_SHADOWSOCKS_LISTEN_PORT:-8388}"
	fi
	printf '%s' "$port"
}

# mpc_auth_vpn_apply_obfuscation_ufw_rules SS_PORT LISTEN_PORT VPN_CIDR MGMT_PORT
mpc_auth_vpn_apply_obfuscation_ufw_rules() {
	local ss_port="${1:-8388}"
	local listen_port="${2:-51820}"
	local vpn_cidr="${3:-10.8.0.0/24}"
	local mgmt_port="${4:-8080}"
	if ! mpc_auth_vpn_ufw_active; then
		return 0
	fi
	ufw allow "${ss_port}/tcp" comment 'Continuum Shadowsocks obfuscation' || true
	ufw allow "${ss_port}/udp" comment 'Continuum Shadowsocks obfuscation' || true
	ufw allow from "${vpn_cidr}" to any port "${mgmt_port}" proto tcp comment 'Continuum VPN management API' || true
	ufw allow in on wg0 comment 'Continuum WireGuard wg0' || true
}

# mpc_auth_vpn_remove_obfuscation_ufw_rules SS_PORT LISTEN_PORT
mpc_auth_vpn_remove_obfuscation_ufw_rules() {
	local ss_port="${1:-8388}"
	local listen_port="${2:-51820}"
	if ! command -v ufw >/dev/null 2>&1; then
		return 0
	fi
	ufw delete allow "${ss_port}/tcp" 2>/dev/null || true
	ufw delete allow "${ss_port}/udp" 2>/dev/null || true
	ufw delete allow "${listen_port}/udp" 2>/dev/null || true
}

# mpc_auth_vpn_start_shadowsocks_systemd
mpc_auth_vpn_start_shadowsocks_systemd() {
	local cfg
	cfg="$(mpc_auth_vpn_shadowsocks_config_path)"
	if [[ ! -f "$cfg" ]]; then
		echo "mpc-auth-vpn-ss-hooks: missing ${cfg} (mpc-auth must write Shadowsocks config first)" >&2
		return 1
	fi
	if ! mpc_auth_vpn_ssserver_bin >/dev/null; then
		echo "mpc-auth-vpn-ss-hooks: ssserver not found — install shadowsocks-rust" >&2
		return 1
	fi
	if ! command -v systemctl >/dev/null 2>&1; then
		echo "mpc-auth-vpn-ss-hooks: systemctl required for Shadowsocks service" >&2
		return 1
	fi
	systemctl daemon-reload
	systemctl enable mpc-auth-shadowsocks.service
	systemctl restart mpc-auth-shadowsocks.service
}

# mpc_auth_vpn_stop_shadowsocks_systemd
mpc_auth_vpn_stop_shadowsocks_systemd() {
	if command -v systemctl >/dev/null 2>&1; then
		systemctl stop mpc-auth-shadowsocks.service 2>/dev/null || true
		systemctl disable mpc-auth-shadowsocks.service 2>/dev/null || true
	fi
}

# mpc_auth_vpn_start_shadowsocks_background PIDFILE LOGFILE
mpc_auth_vpn_start_shadowsocks_background() {
	local pidfile="${1:?pidfile required}"
	local logfile="${2:-${pidfile}.log}"
	local cfg bin
	cfg="$(mpc_auth_vpn_shadowsocks_config_path)"
	if [[ ! -f "$cfg" ]]; then
		echo "mpc-auth-vpn-ss-hooks: missing ${cfg}" >&2
		return 1
	fi
	if ! bin="$(mpc_auth_vpn_ssserver_bin)"; then
		echo "mpc-auth-vpn-ss-hooks: ssserver not found" >&2
		return 1
	fi
	if [[ -f "$pidfile" ]]; then
		local old_pid
		old_pid="$(cat "$pidfile" 2>/dev/null || true)"
		if [[ -n "$old_pid" ]] && kill -0 "$old_pid" 2>/dev/null; then
			kill "$old_pid" 2>/dev/null || true
		fi
		rm -f "$pidfile"
	fi
	nohup "$bin" -c "$cfg" >>"$logfile" 2>&1 &
	echo $! >"$pidfile"
}

# mpc_auth_vpn_stop_shadowsocks_background PIDFILE
mpc_auth_vpn_stop_shadowsocks_background() {
	local pidfile="${1:?pidfile required}"
	if [[ ! -f "$pidfile" ]]; then
		return 0
	fi
	local pid
	pid="$(cat "$pidfile" 2>/dev/null || true)"
	if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
		kill "$pid" 2>/dev/null || true
	fi
	rm -f "$pidfile"
}
