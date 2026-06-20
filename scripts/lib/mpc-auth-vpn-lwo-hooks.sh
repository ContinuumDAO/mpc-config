#!/usr/bin/env bash
# LWO transport obfuscation for WireGuard admin VPN.

mpc_auth_vpn_lwo_server_config_path() {
	local dir="${MPC_AUTH_LWO_SRC_DIR:-/var/lib/mpc-auth-docker/lwo}"
	printf '%s/server.json' "$dir"
}

mpc_auth_vpn_read_lwo_listen_port() {
	local cfg port
	cfg="$(mpc_auth_vpn_lwo_server_config_path)"
	port="${MPC_AUTH_LWO_LISTEN_PORT:-51824}"
	if [[ -f "$cfg" ]] && command -v python3 >/dev/null 2>&1; then
		port="$(python3 - "$cfg" "$port" <<'PY'
import json, sys
path, default = sys.argv[1], int(sys.argv[2])
try:
    with open(path, encoding="utf-8") as f:
        d = json.load(f)
except (OSError, json.JSONDecodeError, ValueError):
    print(default)
    raise SystemExit(0)
print(int(d.get("listen_port", default)))
PY
)" || port="${MPC_AUTH_LWO_LISTEN_PORT:-51824}"
	fi
	printf '%s' "$port"
}

mpc_auth_vpn_start_lwo_systemd() {
	local cfg
	cfg="$(mpc_auth_vpn_lwo_server_config_path)"
	if [[ ! -f "$cfg" ]]; then
		echo "mpc-auth-vpn-lwo-hooks: missing ${cfg}" >&2
		return 1
	fi
	if ! command -v continuum-lwo-server >/dev/null 2>&1; then
		echo "mpc-auth-vpn-lwo-hooks: continuum-lwo-server not found" >&2
		return 1
	fi
	systemctl daemon-reload
	systemctl enable mpc-auth-lwo.service
	systemctl restart mpc-auth-lwo.service
}

mpc_auth_vpn_stop_lwo_systemd() {
	if command -v systemctl >/dev/null 2>&1; then
		systemctl stop mpc-auth-lwo.service 2>/dev/null || true
		systemctl disable mpc-auth-lwo.service 2>/dev/null || true
	fi
}
