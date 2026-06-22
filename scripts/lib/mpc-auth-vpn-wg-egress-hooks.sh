#!/usr/bin/env bash
# WireGuard wg-egress hooks: full-tunnel NAT for peer egress (no management API proxy).
# Source mpc-auth-vpn-wg0-hooks.sh first (mpc_auth_vpn_ufw_active).

# mpc_auth_vpn_egress_ufw_listen_port_live PORT — true when ufw-user-input ACCEPTs UDP PORT.
mpc_auth_vpn_egress_ufw_listen_port_live() {
	local port="${1:?port required}"
	command -v iptables >/dev/null 2>&1 || return 1
	iptables -L ufw-user-input -n 2>/dev/null | grep -qE "ACCEPT[[:space:]].*udp dpt:${port}([[:space:]]|$)"
}

# mpc_auth_vpn_ufw_chains_present — INPUT still jumps through UFW chains (even if ufw disabled).
mpc_auth_vpn_ufw_chains_present() {
	command -v iptables >/dev/null 2>&1 || return 1
	iptables -L INPUT -n 2>/dev/null | grep -q 'ufw-before-input'
}

# mpc_auth_vpn_egress_ensure_ufw_listen_port LISTEN_PORT [OBFUSCATION] [TRANSPORT_PORT]
# Ensures peer egress WireGuard UDP (or Shadowsocks transport) is accepted in live UFW/iptables.
# Exits 1 when UFW is active (or stale UFW chains remain) but the accept rule cannot be applied.
mpc_auth_vpn_egress_ensure_ufw_listen_port() {
	local listen_port="${1:-51830}"
	local obfuscation="${2:-none}"
	local transport_port="${3:-8390}"
	local verify_port="$listen_port"

	command -v ufw >/dev/null 2>&1 || return 0

	if mpc_auth_vpn_ufw_chains_present && ! mpc_auth_vpn_ufw_active; then
		echo "mpc-auth-vpn-wg-egress-hooks: UFW inactive but iptables UFW chains remain — enabling UFW" >&2
		ufw --force enable || {
			echo "mpc-auth-vpn-wg-egress-hooks: ufw --force enable failed" >&2
			return 1
		}
	fi

	if ! mpc_auth_vpn_ufw_active; then
		return 0
	fi

	case "$obfuscation" in
	shadowsocks)
		ufw allow "${transport_port}/tcp" comment 'Continuum egress Shadowsocks' || true
		ufw allow "${transport_port}/udp" comment 'Continuum egress Shadowsocks' || true
		verify_port="$transport_port"
		;;
	*)
		ufw allow "${listen_port}/udp" comment 'Continuum wg-egress' || true
		;;
	esac
	ufw allow in on wg-egress comment 'Continuum wg-egress' || true
	ufw reload || true

	if mpc_auth_vpn_egress_ufw_listen_port_live "$verify_port"; then
		echo "mpc-auth-vpn-wg-egress-hooks: UFW accept for UDP ${verify_port} is live in ufw-user-input" >&2
		return 0
	fi

	echo "mpc-auth-vpn-wg-egress-hooks: UFW rule for UDP ${verify_port} missing from ufw-user-input — inserting iptables ACCEPT" >&2
	iptables -I ufw-user-input -p udp --dport "$verify_port" -j ACCEPT || true

	if mpc_auth_vpn_egress_ufw_listen_port_live "$verify_port"; then
		return 0
	fi

	echo "mpc-auth-vpn-wg-egress-hooks: failed to activate UFW accept for UDP ${verify_port} (peer egress handshakes will fail)" >&2
	return 1
}

# mpc_auth_vpn_egress_apply_tc_limits WG_IFACE LIMITS_JSON
# LIMITS_JSON: {"peers":[{"assignedIp":"10.9.0.10/32","rateLimitMbps":20}]}
mpc_auth_vpn_egress_apply_tc_limits() {
	local iface="${1:-wg-egress}"
	local limits_json="${2:-}"
	if [[ -z "$limits_json" || ! -f "$limits_json" ]]; then
		return 0
	fi
	if ! command -v tc >/dev/null 2>&1; then
		echo "mpc-auth-vpn-wg-egress-hooks: tc not installed — skipping rate limits" >&2
		return 0
	fi
	if ! command -v python3 >/dev/null 2>&1; then
		echo "mpc-auth-vpn-wg-egress-hooks: python3 required for tc limits" >&2
		return 0
	fi
	export WG_EGRESS_IFACE="$iface" WG_EGRESS_LIMITS_JSON="$limits_json"
	python3 - <<'PY'
import json, os, subprocess, sys

iface = os.environ.get("WG_EGRESS_IFACE", "wg-egress")
path = os.environ.get("WG_EGRESS_LIMITS_JSON", "")
try:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
except (OSError, json.JSONDecodeError) as e:
    sys.stderr.write(f"rate limits: read {path}: {e}\n")
    sys.exit(0)

peers = data.get("peers") or []
subprocess.run(["tc", "qdisc", "del", "dev", iface, "root"], check=False, capture_output=True)
if not peers:
    sys.exit(0)
subprocess.run(["tc", "qdisc", "add", "dev", iface, "root", "handle", "1:", "htb", "default", "999"], check=True)
subprocess.run(["tc", "class", "add", "dev", iface, "parent", "1:", "classid", "1:999", "htb", "rate", "10gbit"], check=False)
for i, peer in enumerate(peers, start=1):
    ip_cidr = (peer.get("assignedIp") or "").strip()
    mbps = float(peer.get("rateLimitMbps") or 0)
    if not ip_cidr or mbps <= 0:
        continue
    ip = ip_cidr.split("/")[0]
    cid = f"1:{i}"
    rate = f"{mbps}mbit"
    ceil = rate
    subprocess.run(["tc", "class", "add", "dev", iface, "parent", "1:", "classid", cid, "htb", "rate", rate, "ceil", ceil], check=True)
    subprocess.run(["tc", "filter", "add", "dev", iface, "protocol", "ip", "parent", "1:", "prio", str(i), "u32", "match", "ip", "src", ip, "flowid", cid], check=True)
PY
}

# mpc_auth_vpn_egress_prepare_wg_conf WG_EGRESS_CONF VPN_CIDR LISTEN_PORT [OBFUSCATION] [TRANSPORT_PORT]
mpc_auth_vpn_egress_prepare_wg_conf() {
	local wg_conf="$1"
	local vpn_cidr="${2:-10.9.0.0/24}"
	local listen_port="${3:-51830}"
	local obfuscation="${4:-none}"
	local transport_port="${5:-8390}"

	local default_if
	default_if="$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')"
	default_if="${default_if:-eth0}"

	local -a post_up_parts=()
	local -a post_down_parts=()

	post_up_parts+=("sysctl -w net.ipv4.ip_forward=1")
	post_up_parts+=("iptables -A FORWARD -i wg-egress -o ${default_if} -j ACCEPT")
	post_up_parts+=("iptables -A FORWARD -i ${default_if} -o wg-egress -m state --state RELATED,ESTABLISHED -j ACCEPT")
	post_up_parts+=("iptables -t nat -A POSTROUTING -s ${vpn_cidr} -o ${default_if} -j MASQUERADE")
	post_down_parts+=("iptables -D FORWARD -i wg-egress -o ${default_if} -j ACCEPT || true")
	post_down_parts+=("iptables -D FORWARD -i ${default_if} -o wg-egress -m state --state RELATED,ESTABLISHED -j ACCEPT || true")
	post_down_parts+=("iptables -t nat -D POSTROUTING -s ${vpn_cidr} -o ${default_if} -j MASQUERADE || true")

	case "$obfuscation" in
	shadowsocks)
		post_up_parts+=("iptables -I INPUT -p udp --dport ${listen_port} ! -i lo -j DROP")
		post_down_parts+=("iptables -D INPUT -p udp --dport ${listen_port} ! -i lo -j DROP || true")
		;;
	esac

	if mpc_auth_vpn_ufw_active; then
		case "$obfuscation" in
		shadowsocks)
			post_up_parts+=("iptables -I INPUT -i wg-egress -j ACCEPT")
			post_down_parts+=("iptables -D INPUT -i wg-egress -j ACCEPT || true")
			;;
		*)
			post_up_parts+=("iptables -I INPUT -p udp --dport ${listen_port} -j ACCEPT")
			post_up_parts+=("iptables -I INPUT -i wg-egress -j ACCEPT")
			post_down_parts+=("iptables -D INPUT -p udp --dport ${listen_port} -j ACCEPT || true")
			post_down_parts+=("iptables -D INPUT -i wg-egress -j ACCEPT || true")
			;;
		esac
	fi

	local post_up post_down
	post_up="$(printf '%s\n' "${post_up_parts[@]}")"
	post_down="$(printf '%s\n' "${post_down_parts[@]}")"
	mpc_auth_vpn_insert_wg0_hooks "$wg_conf" "$post_up" "$post_down"
}
