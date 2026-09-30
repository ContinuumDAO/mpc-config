#!/usr/bin/env bash
# Apply or refresh the node-local VPN DNS filter (blocky or dnsmasq).
# Reads MPC_AUTH_VPN_DNS_FILTER / vpn-state.json. Does not restart WireGuard.

set -euo pipefail

MODE="${1:-apply}"
STATE_FILE="${MPC_AUTH_VPN_STATE_FILE:-/var/lib/mpc-auth-docker/vpn-state.json}"
CFG_DIR="${MPC_AUTH_VPN_DNS_FILTER_DIR:-/var/lib/mpc-auth-docker/dns-filter}"
BLOCKLIST_URL="${MPC_AUTH_VPN_DNS_BLOCKLIST_URL:-https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/light.txt}"
LIBEXEC="/usr/local/libexec/mpc-auth"

engine_from_state() {
	python3 - "$STATE_FILE" <<'PY'
import json, sys
path = sys.argv[1]
try:
    with open(path, encoding="utf-8") as f:
        d = json.load(f)
except (OSError, json.JSONDecodeError):
    print("none")
    raise SystemExit(0)
engine = str(d.get("dnsFilter") or "none").strip().lower()
print(engine if engine in ("none", "blocky", "dnsmasq") else "none")
PY
}

resolve_engine() {
	local engine="${MPC_AUTH_VPN_DNS_FILTER:-}"
	engine="${engine,,}"
	if [[ "$engine" != "none" && "$engine" != "blocky" && "$engine" != "dnsmasq" ]]; then
		engine=""
	fi
	if [[ -z "$engine" ]] && command -v python3 >/dev/null 2>&1; then
		engine="$(engine_from_state)"
	fi
	if [[ "$engine" != "blocky" && "$engine" != "dnsmasq" ]]; then
		engine="none"
	fi
	printf '%s' "$engine"
}

resolve_upstream() {
	local upstream="${MPC_AUTH_VPN_DNS_UPSTREAM:-1.1.1.1}"
	if [[ ! "$upstream" =~ ^[A-Za-z0-9.:-]+$ ]]; then
		upstream="1.1.1.1"
	fi
	printf '%s' "$upstream"
}

iface_ipv4() {
	local iface="$1"
	ip -4 -o addr show dev "$iface" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1
}

redirect_iface() {
	local iface="$1" mode="$2" proto
	command -v iptables >/dev/null 2>&1 || return 0
	ip link show dev "$iface" >/dev/null 2>&1 || return 0
	for proto in udp tcp; do
		if [[ "$mode" == add ]]; then
			iptables -t nat -C PREROUTING -i "$iface" -p "$proto" --dport 53 -j REDIRECT --to-ports 53 2>/dev/null \
				|| iptables -t nat -A PREROUTING -i "$iface" -p "$proto" --dport 53 -j REDIRECT --to-ports 53
		else
			while iptables -t nat -C PREROUTING -i "$iface" -p "$proto" --dport 53 -j REDIRECT --to-ports 53 2>/dev/null; do
				iptables -t nat -D PREROUTING -i "$iface" -p "$proto" --dport 53 -j REDIRECT --to-ports 53 || break
			done
		fi
	done
}

stop_resolvers() {
	if command -v systemctl >/dev/null 2>&1; then
		systemctl disable --now mpc-auth-blocky.service >/dev/null 2>&1 || true
		systemctl disable --now mpc-auth-dnsmasq.service >/dev/null 2>&1 || true
	fi
	redirect_iface wg0 del
	redirect_iface wg-egress del
}

write_blocky_config() {
	local upstream="$1"
	shift
	local dest="${CFG_DIR}/blocky.yml"
	{
		echo "upstreams:"
		echo "  groups:"
		echo "    default:"
		echo "      - ${upstream}"
		echo "blocking:"
		echo "  denylists:"
		echo "    ads:"
		echo "      - ${BLOCKLIST_URL}"
		echo "  clientGroupsBlock:"
		echo "    default:"
		echo "      - ads"
		echo "  blockType: zeroIp"
		echo "  loading:"
		echo "    refreshPeriod: 4h"
		echo "ports:"
		echo "  dns:"
		local addr
		for addr in "$@"; do
			echo "    - ${addr}:53"
		done
		echo "bootstrapDns:"
		echo "  - ${upstream}"
	} >"$dest"
}

write_dnsmasq_config() {
	local upstream="$1"
	shift
	local dest="${CFG_DIR}/dnsmasq.conf"
	{
		echo "bind-interfaces"
		echo "except-interface=lo"
		echo "no-resolv"
		echo "server=${upstream}"
		echo "cache-size=10000"
		local addr
		for addr in "$@"; do
			echo "listen-address=${addr}"
		done
		echo "conf-file=${CFG_DIR}/dnsmasq-blocklist.conf"
	} >"$dest"
	if [[ ! -f "${CFG_DIR}/dnsmasq-blocklist.conf" ]]; then
		: >"${CFG_DIR}/dnsmasq-blocklist.conf"
	fi
}

refresh_blocklist() {
	mkdir -p "$CFG_DIR"
	local raw="${CFG_DIR}/blocklist.txt" out="${CFG_DIR}/dnsmasq-blocklist.conf" tmp
	tmp="$(mktemp)"
	if command -v curl >/dev/null 2>&1 && curl -fsSL "$BLOCKLIST_URL" -o "$tmp"; then
		mv -f "$tmp" "$raw"
	else
		rm -f "$tmp"
		echo "mpc-auth-vpn-dns-filter: blocklist download failed" >&2
		return 1
	fi
	python3 - "$raw" "$out" <<'PY'
import sys
src, dest = sys.argv[1], sys.argv[2]
seen = set()
with open(src, encoding="utf-8", errors="replace") as f, open(dest + ".tmp", "w", encoding="utf-8") as out:
    for line in f:
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        domain = parts[-1] if parts and parts[0][:1].isdigit() else parts[0]
        domain = domain.lstrip("*.").rstrip("^").strip(".")
        if not domain or "/" in domain or domain in seen:
            continue
        if not all(c.isalnum() or c in ".-" for c in domain):
            continue
        seen.add(domain)
        out.write(f"address=/{domain}/0.0.0.0\n")
import os
os.replace(dest + ".tmp", dest)
PY
	if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet mpc-auth-dnsmasq.service; then
		systemctl kill -s HUP mpc-auth-dnsmasq.service >/dev/null 2>&1 || true
	fi
}

collect_listen_addrs() {
	local addr
	LISTEN_ADDRS=()
	for iface in wg0 wg-egress; do
		addr="$(iface_ipv4 "$iface" || true)"
		if [[ -n "$addr" ]]; then
			LISTEN_ADDRS+=("$addr")
		fi
	done
}

apply_filter() {
	local engine upstream
	engine="$(resolve_engine)"
	upstream="$(resolve_upstream)"
	mkdir -p "$CFG_DIR"
	collect_listen_addrs
	if [[ "$engine" == "none" || ${#LISTEN_ADDRS[@]} -eq 0 ]]; then
		stop_resolvers
		echo "mpc-auth-vpn-dns-filter: engine=${engine} listen=${#LISTEN_ADDRS[@]}"
		return 0
	fi
	if [[ "$engine" == "blocky" ]]; then
		if ! command -v blocky >/dev/null 2>&1; then
			echo "mpc-auth-vpn-dns-filter: blocky not installed" >&2
			return 1
		fi
		write_blocky_config "$upstream" "${LISTEN_ADDRS[@]}"
		systemctl disable --now mpc-auth-dnsmasq.service >/dev/null 2>&1 || true
		systemctl enable mpc-auth-blocky.service
		systemctl restart mpc-auth-blocky.service
	else
		if ! command -v dnsmasq >/dev/null 2>&1; then
			echo "mpc-auth-vpn-dns-filter: dnsmasq not installed" >&2
			return 1
		fi
		write_dnsmasq_config "$upstream" "${LISTEN_ADDRS[@]}"
		systemctl disable --now mpc-auth-blocky.service >/dev/null 2>&1 || true
		systemctl enable mpc-auth-dnsmasq.service
		systemctl restart mpc-auth-dnsmasq.service
	fi
	local iface addr
	for iface in wg0 wg-egress; do
		addr="$(iface_ipv4 "$iface" || true)"
		if [[ -n "$addr" ]]; then
			redirect_iface "$iface" add
		else
			redirect_iface "$iface" del
		fi
	done
	echo "mpc-auth-vpn-dns-filter: engine=${engine} addrs=${LISTEN_ADDRS[*]}"
}

case "$MODE" in
apply) apply_filter ;;
refresh-list) refresh_blocklist ;;
*)
	echo "usage: mpc-auth-vpn-dns-filter.sh [apply|refresh-list]" >&2
	exit 2
	;;
esac
