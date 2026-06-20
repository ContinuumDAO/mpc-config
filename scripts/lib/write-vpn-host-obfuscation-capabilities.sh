#!/usr/bin/env bash
# Write vpn-host-obfuscation.json for mpc-auth GET /vpn/status.
# Shadowsocks and wg-obfuscator are always offered on systemd VPS hosts (latest mpc-auth);
# this file records optional protocols (LWO, udp2raw) detected on the host at install time.

write_vpn_host_obfuscation_capabilities() {
	local out_dir="${1:-/var/lib/mpc-auth-docker}"
	local out_file="${out_dir}/vpn-host-obfuscation.json"
	local -a protocols=()

	if command -v ssserver >/dev/null 2>&1; then
		protocols+=("shadowsocks")
	fi
	if command -v wg-obfuscator >/dev/null 2>&1; then
		protocols+=("wg_obfuscator")
	fi
	if command -v continuum-lwo-server >/dev/null 2>&1 && command -v continuum-lwo-client >/dev/null 2>&1; then
		protocols+=("lwo")
	fi
	if command -v udp2raw >/dev/null 2>&1; then
		protocols+=("udp2raw")
	fi

	if ! command -v python3 >/dev/null 2>&1; then
		echo "write-vpn-host-obfuscation-capabilities: python3 required" >&2
		return 1
	fi

	local tmp
	tmp="$(mktemp)"
	MPC_VPN_HOST_OBF_PROTOCOLS="${protocols[*]}" MPC_VPN_HOST_OBF_OUT="$tmp" python3 <<'PY'
import datetime, json, os, sys
protocols = [p for p in os.environ.get("MPC_VPN_HOST_OBF_PROTOCOLS", "").split() if p]
payload = {
    "protocols": protocols,
    "updatedAt": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
}
path = os.environ["MPC_VPN_HOST_OBF_OUT"]
with open(path, "w", encoding="utf-8") as f:
    json.dump(payload, f, indent=2)
    f.write("\n")
print(", ".join(protocols) or "none", file=sys.stderr)
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
		echo "write-vpn-host-obfuscation-capabilities: need root to write ${out_file} (try: sudo $0 or run install script as root)" >&2
		return 1
	fi
	rm -f "$tmp"
	echo "write-vpn-host-obfuscation-capabilities: wrote ${out_file} (${protocols[*]:-none})"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
	write_vpn_host_obfuscation_capabilities "${1:-/var/lib/mpc-auth-docker}"
fi
