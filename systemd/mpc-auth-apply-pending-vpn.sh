#!/usr/bin/env bash
# Consume pending-vpn.json written by mpc-auth POST /vpn/setEnabled (host path bind-mounted into container).
# systemd.path → this oneshot → mpc-auth-vpn-enable.sh or mpc-auth-vpn-disable.sh.

set -euo pipefail

PENDING_FILE="${MPC_AUTH_VPN_PENDING_FILE:-/var/lib/mpc-auth-docker/pending-vpn.json}"
LIBEXEC="/usr/local/libexec/mpc-auth"
ENABLE_SCRIPT="${LIBEXEC}/mpc-auth-vpn-enable.sh"
DISABLE_SCRIPT="${LIBEXEC}/mpc-auth-vpn-disable.sh"
STATE_FILE="${MPC_AUTH_VPN_STATE_FILE:-/var/lib/mpc-auth-docker/vpn-state.json}"
DONE_DIR="$(dirname "$PENDING_FILE")/applied"
PROCESSING="${PENDING_FILE}.processing"

mkdir -p "$DONE_DIR"

if [[ ! -f "$PENDING_FILE" ]]; then
	exit 0
fi

if ! mv "$PENDING_FILE" "$PROCESSING"; then
	echo "mpc-auth-apply-pending-vpn: failed to claim ${PENDING_FILE}" >&2
	exit 1
fi

_stamp() {
	date +%Y%m%d%H%M%S
}

abort_bad_json() {
	echo "mpc-auth-apply-pending-vpn: invalid JSON in ${PROCESSING}" >&2
	mv -f "$PROCESSING" "${DONE_DIR}/failed-$(_stamp).bad.json" || true
	exit 1
}

if ! command -v python3 >/dev/null 2>&1; then
	echo "mpc-auth-apply-pending-vpn: python3 required to parse pending JSON" >&2
	mv -f "$PROCESSING" "${DONE_DIR}/failed-$(_stamp).nopython.json" || true
	exit 1
fi

export MPC_APPLY_PENDING_VPN_JSON="$PROCESSING"
eval "$(python3 <<'PY'
import json, os, shlex, sys
path = os.environ["MPC_APPLY_PENDING_VPN_JSON"]
with open(path) as f:
    d = json.load(f)
action = (d.get("action") or "").strip().lower()
profile = (d.get("profile") or "split").strip().lower()
obfuscation = (d.get("obfuscation") or "none").strip().lower()
dns_filter = (d.get("dnsFilter") or "none").strip().lower()
dns_upstream = (d.get("dnsUpstream") or "1.1.1.1").strip()
if action not in ("enable", "disable", "dnsfilter"):
    sys.stderr.write(f"mpc-auth-apply-pending-vpn: unexpected action {action!r}\n")
    sys.exit(2)
if profile not in ("split", "full"):
    profile = "split"
if obfuscation not in ("none", "shadowsocks", "wg_obfuscator", "lwo", "udp2raw"):
    obfuscation = "none"
if dns_filter not in ("none", "blocky", "dnsmasq"):
    dns_filter = "none"
print(f"export MPC_AUTH_VPN_ACTION={shlex.quote(action)}")
print(f"export MPC_AUTH_VPN_PROFILE={shlex.quote(profile)}")
print(f"export MPC_AUTH_VPN_OBFUSCATION={shlex.quote(obfuscation)}")
print(f"export MPC_AUTH_VPN_DNS_FILTER={shlex.quote(dns_filter)}")
print(f"export MPC_AUTH_VPN_DNS_UPSTREAM={shlex.quote(dns_upstream)}")
PY
)" || abort_bad_json

finalize_ok() {
	mv -f "$PROCESSING" "${DONE_DIR}/ok-$(_stamp).json" || rm -f "$PROCESSING"
	exit 0
}

finalize_fail() {
	mv -f "$PROCESSING" "${DONE_DIR}/failed-$(_stamp).apply.json" || true
	exit 1
}

run_script() {
	local script="$1"
	shift
	if [[ ! -x "$script" ]]; then
		echo "mpc-auth-apply-pending-vpn: missing ${script}" >&2
		finalize_fail
	fi
	export MPC_AUTH_VPN_PROFILE
	export MPC_AUTH_VPN_OBFUSCATION
	export MPC_AUTH_VPN_DNS_FILTER
	export MPC_AUTH_VPN_DNS_UPSTREAM
	"$script" "$@"
}

active_vpn_profile() {
	if [[ ! -f "$STATE_FILE" ]]; then
		return 0
	fi
	python3 - <<'PY'
import json, os, sys
path = os.environ.get("STATE_FILE", "")
try:
    with open(path, encoding="utf-8") as f:
        d = json.load(f)
except (OSError, json.JSONDecodeError):
    sys.exit(0)
if not d.get("active"):
    sys.exit(0)
print((d.get("profile") or "").strip().lower())
PY
}

active_vpn_obfuscation() {
	if [[ ! -f "$STATE_FILE" ]]; then
		return 0
	fi
	python3 - <<'PY'
import json, os, sys
path = os.environ.get("STATE_FILE", "")
try:
    with open(path, encoding="utf-8") as f:
        d = json.load(f)
except (OSError, json.JSONDecodeError):
    sys.exit(0)
if not d.get("active"):
    sys.exit(0)
print((d.get("obfuscation") or "none").strip().lower())
PY
}

if [[ "$MPC_AUTH_VPN_ACTION" == "dnsfilter" ]]; then
	export MPC_AUTH_VPN_DNS_FILTER MPC_AUTH_VPN_DNS_UPSTREAM
	if [[ -x "${LIBEXEC}/mpc-auth-vpn-dns-filter.sh" ]]; then
		if ! "${LIBEXEC}/mpc-auth-vpn-dns-filter.sh"; then
			finalize_fail
		fi
	fi
	finalize_ok
fi

if [[ "$MPC_AUTH_VPN_ACTION" == "enable" ]]; then
	export STATE_FILE
	cur_profile="$(active_vpn_profile || true)"
	cur_obfuscation="$(active_vpn_obfuscation || true)"
	if [[ -n "$cur_profile" && ( "$cur_profile" != "$MPC_AUTH_VPN_PROFILE" || "$cur_obfuscation" != "$MPC_AUTH_VPN_OBFUSCATION" ) ]]; then
		echo "mpc-auth-apply-pending-vpn: switching VPN profile ${cur_profile}/${cur_obfuscation} -> ${MPC_AUTH_VPN_PROFILE}/${MPC_AUTH_VPN_OBFUSCATION} (disable then enable)"
		run_script "$DISABLE_SCRIPT"
	fi
	run_script "$ENABLE_SCRIPT" "$MPC_AUTH_VPN_PROFILE"
	finalize_ok
else
	run_script "$DISABLE_SCRIPT"
	finalize_ok
fi
