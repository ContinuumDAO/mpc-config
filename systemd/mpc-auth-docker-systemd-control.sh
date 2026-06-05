#!/usr/bin/env bash
# Stop or restart mpc-auth Docker systemd units installed by install-mpc-auth-docker-systemd.sh.
#
# Usage:
#   sudo ./mpc-auth-docker-systemd-control.sh stop
#   sudo ./mpc-auth-docker-systemd-control.sh restart
#
# stop     — stops path watcher units (auto-update, reboot trigger, agent LLM config).
# restart  — restarts path watcher units and restarts the mpc-auth Docker container
#            (via mpc-auth-docker-restart.service).

set -euo pipefail

PATH_UNITS=(
	"mpc-auth-docker-pending-update.path"
	"mpc-auth-docker-pending-reboot.path"
	"mpc-auth-agent-llm-config.path"
)

usage() {
	cat <<'EOF'
Usage:
  sudo ./mpc-auth-docker-systemd-control.sh stop
  sudo ./mpc-auth-docker-systemd-control.sh restart

Commands:
  stop      Stop mpc-auth path watcher units.
  restart   Restart path watcher units and restart the mpc-auth Docker container.
EOF
	exit 2
}

if [[ "${EUID:-}" -ne 0 ]]; then
	echo "error: run as root (sudo)" >&2
	exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
	echo "error: systemctl not found — not a systemd host?" >&2
	exit 1
fi

ACTION="${1:-}"
case "$ACTION" in
stop)
	for u in "${PATH_UNITS[@]}"; do
		if systemctl is-active --quiet "$u" 2>/dev/null; then
			echo "Stopping $u"
			systemctl stop "$u"
		else
			echo "Already stopped or not installed: $u"
		fi
	done
	;;
restart)
	for u in "${PATH_UNITS[@]}"; do
		if systemctl list-unit-files --no-legend "$u" 2>/dev/null | grep -q .; then
			echo "Restarting $u"
			systemctl restart "$u" || systemctl start "$u"
		else
			echo "Not installed, skipping: $u"
		fi
	done
	echo "Restarting mpc-auth Docker container (mpc-auth-docker-restart.service)"
	systemctl start mpc-auth-docker-restart.service
	;;
-h | --help) usage ;;
*) usage ;;
esac
