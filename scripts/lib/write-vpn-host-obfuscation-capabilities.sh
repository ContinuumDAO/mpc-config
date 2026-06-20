#!/usr/bin/env bash
# Write vpn-host-obfuscation.json for mpc-auth GET /vpn/status (host binaries, not container PATH).
# Called from install-mpc-auth-docker-systemd.sh after ensure-* package helpers.

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

	mkdir -p "$out_dir"
	if ! command -v python3 >/dev/null 2>&1; then
		echo "write-vpn-host-obfuscation-capabilities: python3 required" >&2
		return 1
	fi

	MPC_VPN_HOST_OBF_PROTOCOLS="${protocols[*]}" MPC_VPN_HOST_OBF_OUT="$out_file" python3 <<'PY'
import datetime, json, os
protocols = [p for p in os.environ.get("MPC_VPN_HOST_OBF_PROTOCOLS", "").split() if p]
payload = {
    "protocols": protocols,
    "updatedAt": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
}
path = os.environ["MPC_VPN_HOST_OBF_OUT"]
with open(path + ".tmp", "w", encoding="utf-8") as f:
    json.dump(payload, f, indent=2)
    f.write("\n")
os.rename(path + ".tmp", path)
print(f"write-vpn-host-obfuscation-capabilities: wrote {path} ({', '.join(protocols) or 'none'})")
PY
}
