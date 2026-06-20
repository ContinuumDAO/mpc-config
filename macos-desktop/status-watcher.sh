#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
. "${HERE}/_lib.sh"

macos_desktop_load_env

pidfile="$(macos_desktop_pidfile)"
logfile="$(macos_desktop_logfile)"
pending="$(macos_desktop_pending_file)"
vpn_pending="$(macos_desktop_vpn_pending_file)"
repo="$(macos_desktop_repo_dir)"
state_file="${MPC_AUTH_VPN_STATE_FILE:-/var/lib/mpc-auth-docker/vpn-state.json}"
proxy_pidfile="${HERE}/vpn-mgmt-proxy.pid"

echo "repo: ${repo}"
echo "pending file: ${pending}"
echo "vpn pending file: ${vpn_pending}"
echo "env: $(macos_desktop_env_file)"
echo "libexec: $(macos_desktop_libexec)"
echo "log: ${logfile}"

if [[ -f "$pidfile" ]]; then
	pid="$(cat "$pidfile" 2>/dev/null || true)"
	if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
		echo "status: running (pid ${pid})"
	else
		echo "status: not running (stale pidfile: ${pid:-empty})"
		exit 1
	fi
else
	echo "status: not running"
	exit 1
fi

echo ""
echo "LaunchAgent:"
if launchctl list 2>/dev/null | grep -q com.continuumdao.mpc-auth-watcher; then
	echo "  com.continuumdao.mpc-auth-watcher: loaded"
else
	echo "  com.continuumdao.mpc-auth-watcher: not loaded"
fi

echo ""
echo "VPN:"
if [[ -f "$state_file" ]]; then
	echo "  state file: ${state_file}"
	export STATE_FILE="$state_file"
	python3 - <<'PY' 2>/dev/null || cat "$state_file"
import json, os
with open(os.environ["STATE_FILE"]) as f:
    d = json.load(f)
print(f"  active: {d.get('active', False)}")
print(f"  profile: {d.get('profile', '') or '—'}")
print(f"  hostProfile: {d.get('hostProfile', '—')}")
PY
else
	echo "  state file: (none)"
fi

if command -v wg >/dev/null 2>&1; then
	if wg show wg0 >/dev/null 2>&1; then
		echo "  wg0: up ($(wg show wg0 listen-port 2>/dev/null || echo '?')/udp)"
	else
		echo "  wg0: down"
	fi
else
	echo "  wg: wireguard-tools not installed (brew install wireguard-tools)"
fi

if [[ -f "$proxy_pidfile" ]]; then
	proxy_pid="$(cat "$proxy_pidfile" 2>/dev/null || true)"
	if [[ -n "$proxy_pid" ]] && kill -0 "$proxy_pid" 2>/dev/null; then
		echo "  mgmt proxy: running (pid ${proxy_pid}, 10.8.0.1:${MPC_AUTH_VPN_MGMT_PORT:-8080})"
	else
		echo "  mgmt proxy: not running (stale pidfile)"
	fi
else
	echo "  mgmt proxy: not running"
fi

if [[ -f "$vpn_pending" ]]; then
	echo "  note: pending VPN change waiting (${vpn_pending})"
fi

exit 0
