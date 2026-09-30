#!/usr/bin/env bash
# Write vpn-host-dns-filter.json for mpc-auth GET /vpn/status.

write_vpn_host_dns_filter_capabilities() {
	local out_dir="${1:-/var/lib/mpc-auth-docker}"
	local out_file="${out_dir}/vpn-host-dns-filter.json"
	local -a engines=()

	if command -v blocky >/dev/null 2>&1; then
		engines+=("blocky")
	fi
	if command -v dnsmasq >/dev/null 2>&1; then
		engines+=("dnsmasq")
	fi

	if ! command -v python3 >/dev/null 2>&1; then
		echo "write-vpn-host-dns-filter-capabilities: python3 required" >&2
		return 1
	fi

	local tmp
	tmp="$(mktemp)"
	MPC_VPN_DNS_ENGINES="${engines[*]}" MPC_VPN_DNS_OUT="$tmp" python3 <<'PY'
import datetime, json, os, sys
engines = [p for p in os.environ.get("MPC_VPN_DNS_ENGINES", "").split() if p]
payload = {
    "engines": engines,
    "updatedAt": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
}
path = os.environ["MPC_VPN_DNS_OUT"]
with open(path, "w", encoding="utf-8") as f:
    json.dump(payload, f, indent=2)
    f.write("\n")
print(", ".join(engines) or "none", file=sys.stderr)
PY
	local install_cmd=(install -m 0644 "$tmp" "$out_file")
	if [[ -w "$out_dir" ]] || [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
		mkdir -p "$out_dir"
		"${install_cmd[@]}"
	elif command -v sudo >/dev/null 2>&1; then
		sudo mkdir -p "$out_dir"
		sudo "${install_cmd[@]}"
	else
		rm -f "$tmp"
		echo "write-vpn-host-dns-filter-capabilities: need root to write ${out_file}" >&2
		return 1
	fi
	rm -f "$tmp"
	echo "write-vpn-host-dns-filter-capabilities: wrote ${out_file} (${engines[*]:-none})"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
	write_vpn_host_dns_filter_capabilities "${1:-/var/lib/mpc-auth-docker}"
fi
