#!/usr/bin/env bash
# Shared VPN transport obfuscation dispatcher (Shadowsocks, wg-obfuscator, LWO, udp2raw).
# Sourced by mpc-auth-vpn-enable/disable scripts on systemd and desktop hosts.

# mpc_auth_vpn_normalize_obfuscation [VALUE]
mpc_auth_vpn_normalize_obfuscation() {
	local v="${1:-${MPC_AUTH_VPN_OBFUSCATION:-none}}"
	v="${v,,}"
	v="${v// /}"
	v="${v//-/_}"
	case "$v" in
	shadowsocks) printf '%s' "shadowsocks" ;;
	wg_obfuscator | wgobfuscator) printf '%s' "wg_obfuscator" ;;
	lwo) printf '%s' "lwo" ;;
	udp2raw) printf '%s' "udp2raw" ;;
	*) printf '%s' "none" ;;
	esac
}

# mpc_auth_vpn_obfuscation_blocks_direct_wg OBFUSCATION
mpc_auth_vpn_obfuscation_blocks_direct_wg() {
	local obfuscation
	obfuscation="$(mpc_auth_vpn_normalize_obfuscation "${1:-}")"
	case "$obfuscation" in
	shadowsocks | wg_obfuscator | lwo | udp2raw) return 0 ;;
	*) return 1 ;;
	esac
}

# mpc_auth_vpn_read_transport_listen_port OBFUSCATION STATE_FILE DEFAULT
mpc_auth_vpn_read_transport_listen_port() {
	local obfuscation state_file default_port key
	obfuscation="$(mpc_auth_vpn_normalize_obfuscation "${1:-}")"
	state_file="${2:-${MPC_AUTH_VPN_STATE_FILE:-/var/lib/mpc-auth-docker/vpn-state.json}}"
	default_port="${3:-0}"
	case "$obfuscation" in
	shadowsocks) key="shadowsocksListenPort" ;;
	wg_obfuscator) key="wgObfuscatorListenPort" ;;
	lwo) key="lwoListenPort" ;;
	udp2raw) key="udp2rawListenPort" ;;
	*) printf '%s' "$default_port"; return 0 ;;
	esac
	if [[ -f "$state_file" ]] && command -v python3 >/dev/null 2>&1; then
		python3 - "$state_file" "$key" "$default_port" <<'PY'
import json, sys
path, key, default = sys.argv[1], sys.argv[2], int(sys.argv[3])
try:
    with open(path, encoding="utf-8") as f:
        d = json.load(f)
except (OSError, json.JSONDecodeError, ValueError):
    print(default)
    raise SystemExit(0)
print(int(d.get(key, default)))
PY
	else
		printf '%s' "$default_port"
	fi
}

# mpc_auth_vpn_start_obfuscation_systemd OBFUSCATION
mpc_auth_vpn_start_obfuscation_systemd() {
	local obfuscation
	obfuscation="$(mpc_auth_vpn_normalize_obfuscation "${1:-}")"
	case "$obfuscation" in
	shadowsocks)
		mpc_auth_vpn_start_shadowsocks_systemd
		;;
	wg_obfuscator)
		mpc_auth_vpn_start_wg_obfuscator_systemd
		;;
	*)
		return 0
		;;
	esac
}

# mpc_auth_vpn_stop_obfuscation_systemd [OBFUSCATION]
mpc_auth_vpn_stop_obfuscation_systemd() {
	local obfuscation="${1:-}"
	if [[ -z "$obfuscation" ]]; then
		mpc_auth_vpn_stop_shadowsocks_systemd
		mpc_auth_vpn_stop_wg_obfuscator_systemd
		return 0
	fi
	obfuscation="$(mpc_auth_vpn_normalize_obfuscation "$obfuscation")"
	case "$obfuscation" in
	shadowsocks) mpc_auth_vpn_stop_shadowsocks_systemd ;;
	wg_obfuscator) mpc_auth_vpn_stop_wg_obfuscator_systemd ;;
	esac
}
