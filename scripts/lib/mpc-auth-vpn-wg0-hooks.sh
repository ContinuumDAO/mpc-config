#!/usr/bin/env bash
# Shared WireGuard wg0.conf hook logic for VPS systemd and WSL VPN enable scripts.
# PostUp/PostDown must live under [Interface] (before [Peer]); never append after [Peer].

# mpc_auth_vpn_ufw_active — exit 0 when UFW is enabled.
mpc_auth_vpn_ufw_active() {
	command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi "Status: active"
}

# mpc_auth_vpn_apply_ufw_rules LISTEN_PORT VPN_CIDR MGMT_PORT [OBFUSCATION] [SS_PORT]
mpc_auth_vpn_apply_ufw_rules() {
	local listen_port="${1:-51820}"
	local vpn_cidr="${2:-10.8.0.0/24}"
	local mgmt_port="${3:-8080}"
	local obfuscation="${4:-none}"
	local ss_port="${5:-8388}"
	if ! mpc_auth_vpn_ufw_active; then
		return 0
	fi
	if [[ "$obfuscation" == "shadowsocks" ]]; then
		ufw allow "${ss_port}/tcp" comment 'Continuum Shadowsocks obfuscation' || true
		ufw allow "${ss_port}/udp" comment 'Continuum Shadowsocks obfuscation' || true
	else
		ufw allow "${listen_port}/udp" comment 'Continuum WireGuard VPN' || true
	fi
	ufw allow from "${vpn_cidr}" to any port "${mgmt_port}" proto tcp comment 'Continuum VPN management API' || true
	ufw allow in on wg0 comment 'Continuum WireGuard wg0' || true
}

# mpc_auth_vpn_insert_wg0_hooks WG0_CONF POST_UP POST_DOWN
# Removes stray PostUp/PostDown lines and inserts hooks immediately before [Peer].
mpc_auth_vpn_insert_wg0_hooks() {
	local wg0_conf="$1"
	local post_up="$2"
	local post_down="$3"
	if [[ -z "$wg0_conf" || -z "$post_up" || -z "$post_down" ]]; then
		echo "mpc-auth-vpn-wg0-hooks: wg0 conf path and PostUp/PostDown required" >&2
		return 1
	fi
	if ! command -v python3 >/dev/null 2>&1; then
		echo "mpc-auth-vpn-wg0-hooks: python3 required to insert wg0 hooks" >&2
		return 1
	fi
	export WG0_CONF="$wg0_conf" WG0_POST_UP="$post_up" WG0_POST_DOWN="$post_down"
	python3 - <<'PY'
import os
import sys

path = os.environ["WG0_CONF"]
post_up_cmds = [ln.strip() for ln in os.environ.get("WG0_POST_UP", "").splitlines() if ln.strip()]
post_down_cmds = [ln.strip() for ln in os.environ.get("WG0_POST_DOWN", "").splitlines() if ln.strip()]

with open(path, encoding="utf-8") as f:
    lines = f.readlines()

def is_hook(line: str) -> bool:
    s = line.strip()
    return s.startswith("PostUp") or s.startswith("PostDown")

out = []
inserted = False
for line in lines:
    if is_hook(line):
        continue
    if not inserted and line.strip() == "[Peer]":
        for cmd in post_up_cmds:
            out.append(f"PostUp = {cmd}\n")
        for cmd in post_down_cmds:
            out.append(f"PostDown = {cmd}\n")
        if post_up_cmds or post_down_cmds:
            out.append("\n")
        inserted = True
    out.append(line)

if not inserted:
    sys.stderr.write(f"{path}: missing [Peer] section\n")
    sys.exit(1)

with open(path, "w", encoding="utf-8") as f:
    f.writelines(out)
PY
}

# mpc_auth_vpn_prepare_wg0_conf WG0_CONF PROFILE LISTEN_PORT [VPN_CIDR] [MGMT_PORT] [OBFUSCATION] [SS_PORT]
# Copies are expected already installed at WG0_CONF. Adds UFW rules and wg-quick hooks when needed.
mpc_auth_vpn_prepare_wg0_conf() {
	local wg0_conf="$1"
	local profile="${2:-split}"
	local listen_port="${3:-51820}"
	local vpn_cidr="${4:-10.8.0.0/24}"
	local mgmt_port="${5:-8080}"
	local obfuscation="${6:-${MPC_AUTH_VPN_OBFUSCATION:-none}}"
	local ss_port="${7:-${MPC_AUTH_SHADOWSOCKS_LISTEN_PORT:-8388}}"

	local -a post_up_parts=()
	local -a post_down_parts=()

	if [[ "$profile" == "full" ]]; then
		local default_if
		default_if="$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')"
		default_if="${default_if:-eth0}"
		post_up_parts+=("sysctl -w net.ipv4.ip_forward=1")
		post_up_parts+=("iptables -A FORWARD -i wg0 -o ${default_if} -j ACCEPT")
		post_up_parts+=("iptables -A FORWARD -i ${default_if} -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT")
		post_up_parts+=("iptables -t nat -A POSTROUTING -s ${vpn_cidr} -o ${default_if} -j MASQUERADE")
		post_down_parts+=("iptables -D FORWARD -i wg0 -o ${default_if} -j ACCEPT || true")
		post_down_parts+=("iptables -D FORWARD -i ${default_if} -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT || true")
		post_down_parts+=("iptables -t nat -D POSTROUTING -s ${vpn_cidr} -o ${default_if} -j MASQUERADE || true")
		if mpc_auth_vpn_ufw_active; then
			post_up_parts+=("ufw route allow in on wg0 out on ${default_if} || true")
			post_up_parts+=("ufw route allow in on ${default_if} out on wg0 || true")
			post_down_parts+=("ufw route delete allow in on wg0 out on ${default_if} || true")
			post_down_parts+=("ufw route delete allow in on ${default_if} out on wg0 || true")
		fi
	fi

	if [[ "$obfuscation" == "shadowsocks" ]]; then
		post_up_parts+=("iptables -I INPUT -p udp --dport ${listen_port} ! -i lo -j DROP")
		post_down_parts+=("iptables -D INPUT -p udp --dport ${listen_port} ! -i lo -j DROP || true")
	fi

	if mpc_auth_vpn_ufw_active; then
		mpc_auth_vpn_apply_ufw_rules "$listen_port" "$vpn_cidr" "$mgmt_port" "$obfuscation" "$ss_port"
		if [[ "$obfuscation" == "shadowsocks" ]]; then
			post_up_parts+=("iptables -I INPUT -i wg0 -j ACCEPT")
			post_down_parts+=("iptables -D INPUT -i wg0 -j ACCEPT || true")
		else
			post_up_parts+=("iptables -I INPUT -p udp --dport ${listen_port} -j ACCEPT")
			post_up_parts+=("iptables -I INPUT -i wg0 -j ACCEPT")
			post_down_parts+=("iptables -D INPUT -p udp --dport ${listen_port} -j ACCEPT || true")
			post_down_parts+=("iptables -D INPUT -i wg0 -j ACCEPT || true")
		fi
	fi

	if [[ ${#post_up_parts[@]} -eq 0 ]]; then
		return 0
	fi

	local post_up post_down
	post_up="$(printf '%s\n' "${post_up_parts[@]}")"
	post_down="$(printf '%s\n' "${post_down_parts[@]}")"
	mpc_auth_vpn_insert_wg0_hooks "$wg0_conf" "$post_up" "$post_down"
}
