#!/usr/bin/env bash
# Remove mpc-auth Docker systemd integration installed by mpc-config/systemd/install-mpc-auth-docker-systemd.sh
# (typically invoked via process_config.sh --install-mpc-auth-systemd or the interactive systemd prompts).
#
# Stops/disables units, removes unit drop-ins under /etc/systemd/system, removes /usr/local/libexec/mpc-auth helpers,
# and optionally clears host state under /var/lib/mpc-auth-docker and journal retention (see below).
#
# Usage:
#   sudo ./scripts/uninstall-mpc-auth-docker-systemd.sh [options]
#
# Journal note: systemd stores journal entries in shared binary files; there is no supported way to erase only logs
# from these units. This script runs journalctl --rotate by default; optional --journal-vacuum-time applies a
# GLOBAL vacuum for ALL journals on the machine (same as `journalctl --vacuum-time=…`).
#
set -euo pipefail

LIBEXEC="/usr/local/libexec/mpc-auth"
UNIT_DIR="/etc/systemd/system"
DEFAULT_ENV="/etc/default/mpc-auth-docker"
VAR_LIB="/var/lib/mpc-auth-docker"

# Basenames matching systemd/install-mpc-auth-docker-systemd.sh (plus globbed template instances).
UNIT_FILES=(
	"mpc-auth-docker-restart.service"
	"mpc-auth-docker-update@.service"
	"mpc-auth-docker-pending-update.path"
	"mpc-auth-docker-pending-update.service"
	"mpc-auth-docker-pending-reboot.path"
	"mpc-auth-docker-pending-reboot.service"
	"mpc-auth-vpn-pending.path"
	"mpc-auth-vpn-pending.service"
	"mpc-auth-wireguard-wg0.service"
	"mpc-auth-vpn-mgmt-proxy.service"
	"mpc-auth-shadowsocks.service"
	"mpc-auth-wg-obfuscator.service"
	"mpc-auth-udp2raw.service"
	"mpc-auth-lwo.service"
	"mpc-auth-vpn-egress-pending.path"
	"mpc-auth-vpn-egress-pending.service"
	"mpc-auth-wireguard-wg-egress.service"
	"mpc-auth-shadowsocks-egress.service"
	"mpc-auth-wg-obfuscator-egress.service"
	"mpc-auth-udp2raw-egress.service"
	"mpc-auth-telegram-ngrok-pending.path"
	"mpc-auth-telegram-ngrok-pending.service"
	"mpc-auth-agent-llm-config.path"
	"mpc-auth-agent-llm-config.service"
)

LIBEXEC_SCRIPTS=(
	"mpc-auth-docker-restart.sh"
	"mpc-auth-docker-update.sh"
	"mpc-auth-apply-pending-update.sh"
	"mpc-auth-apply-pending-reboot.sh"
	"mpc-auth-apply-pending-vpn.sh"
	"mpc-auth-vpn-enable.sh"
	"mpc-auth-vpn-disable.sh"
	"mpc-auth-apply-pending-vpn-egress.sh"
	"mpc-auth-vpn-egress-enable.sh"
	"mpc-auth-vpn-egress-disable.sh"
	"mpc-auth-apply-pending-telegram-ngrok.sh"
	"mpc-auth-telegram-ngrok-enable.sh"
	"mpc-auth-telegram-ngrok-disable.sh"
	"mpc-auth-apply-agent-llm-config.sh"
	"mpc-auth-sync-compose-role.sh"
	"mpc-auth-vpn-wg0-hooks.sh"
	"mpc-auth-vpn-ss-hooks.sh"
	"mpc-auth-vpn-wg-obfuscator-hooks.sh"
	"mpc-auth-vpn-lwo-hooks.sh"
	"mpc-auth-vpn-udp2raw-hooks.sh"
	"mpc-auth-vpn-obfuscation-hooks.sh"
	"mpc-auth-vpn-wg-egress-hooks.sh"
	"mpc-auth-vpn-wg-obfuscator-egress-hooks.sh"
	"mpc-auth-vpn-udp2raw-egress-hooks.sh"
	"mpc-auth-udp2raw-run.sh"
	"mpc-auth-udp2raw-egress-run.sh"
)

KEEP_ENV=false
PURGE_VAR_LIB=false
PURGE_ENV_BACKUPS=false
JOURNAL_VACUUM_TIME=""
FORCE_GLOBAL_JOURNAL_VACUUM=false
DRY_RUN=false

usage() {
	cat <<'EOF'
Usage:
  sudo ./scripts/uninstall-mpc-auth-docker-systemd.sh [options]

Removes systemd units, libexec scripts, and (unless --keep-env) /etc/default/mpc-auth-docker installed by
mpc-config systemd/install-mpc-auth-docker-systemd.sh.

Options:
  --keep-env              Keep /etc/default/mpc-auth-docker (still removes units + libexec).
  --purge-var-lib         Delete /var/lib/mpc-auth-docker (pending-update/reboot/vpn JSON, wireguard/, applied/*.json).
  --purge-env-backups     Remove /etc/default/mpc-auth-docker.bak.* created by the installer.
  --journal-vacuum-time=T  Run journalctl --vacuum-time=T for the WHOLE system journal (not unit-specific).
                           Requires --force-global-journal-vacuum (safety gate).
  --force-global-journal-vacuum
                          Acknowledge that --journal-vacuum-time affects all journals on this host.
  --dry-run               Print actions instead of changing the system (still requires root for journal probes).

Journal:
  Without --journal-vacuum-time, only `journalctl --rotate` is run (does not delete historical entries).

Examples:
  sudo ./scripts/uninstall-mpc-auth-docker-systemd.sh
  sudo ./scripts/uninstall-mpc-auth-docker-systemd.sh --purge-var-lib --purge-env-backups
EOF
	exit 2
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	--keep-env) KEEP_ENV=true ;;
	--purge-var-lib) PURGE_VAR_LIB=true ;;
	--purge-env-backups) PURGE_ENV_BACKUPS=true ;;
	--journal-vacuum-time=*)
		JOURNAL_VACUUM_TIME="${1#*=}"
		;;
	--journal-vacuum-time)
		JOURNAL_VACUUM_TIME="${2:?missing value for --journal-vacuum-time}"
		shift
		;;
	--force-global-journal-vacuum) FORCE_GLOBAL_JOURNAL_VACUUM=true ;;
	--dry-run) DRY_RUN=true ;;
	-h | --help) usage ;;
	*) usage ;;
	esac
	shift
done

if [[ "${EUID:-}" -ne 0 ]]; then
	echo "error: run as root (sudo)" >&2
	exit 1
fi

if [[ -n "$JOURNAL_VACUUM_TIME" && "$FORCE_GLOBAL_JOURNAL_VACUUM" != true ]]; then
	echo "error: --journal-vacuum-time affects ALL journals; pass --force-global-journal-vacuum to confirm." >&2
	exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
	echo "error: systemctl not found — not a systemd host?" >&2
	exit 1
fi

run() {
	if [[ "$DRY_RUN" == true ]]; then
		printf '+ '
		printf '%q ' "$@"
		printf '\n'
		return 0
	fi
	"$@"
}

mpc_auth_disable_template_instances() {
	local f bn
	shopt -s nullglob
	for f in "${UNIT_DIR}/mpc-auth-docker-update@"*.service; do
		[[ -e "$f" ]] || continue
		bn="$(basename "$f")"
		run systemctl stop "$bn" 2>/dev/null || true
		run systemctl disable "$bn" 2>/dev/null || true
	done
	shopt -u nullglob
}

mpc_auth_stop_disable_known_units() {
	local u f bn
	for u in "${UNIT_FILES[@]}"; do
		run systemctl stop "$u" 2>/dev/null || true
		run systemctl disable "$u" 2>/dev/null || true
		run systemctl reset-failed "$u" 2>/dev/null || true
	done

	mpc_auth_disable_template_instances

	# Enabled instances often omit a separate unit file; disable anything still registered.
	local listed
	listed="$(systemctl list-unit-files --no-pager --no-legend 2>/dev/null | awk '$1 ~ /^mpc-auth-/ {print $1}' || true)"
	while IFS= read -r line; do
		[[ -z "$line" ]] && continue
		run systemctl stop "$line" 2>/dev/null || true
		run systemctl disable "$line" 2>/dev/null || true
		run systemctl reset-failed "$line" 2>/dev/null || true
	done <<<"$listed"

	for f in "${UNIT_FILES[@]}"; do
		[[ -f "${UNIT_DIR}/${f}" ]] || continue
		run rm -f "${UNIT_DIR}/${f}"
	done

	shopt -s nullglob
	for f in "${UNIT_DIR}/mpc-auth-docker-update@"*.service "${UNIT_DIR}/mpc-auth-"*.service "${UNIT_DIR}/mpc-auth-"*.path; do
		[[ -e "$f" ]] || continue
		run rm -f "$f"
	done
	shopt -u nullglob

	run systemctl daemon-reload
}

mpc_auth_remove_libexec() {
	local s
	for s in "${LIBEXEC_SCRIPTS[@]}"; do
		[[ -f "${LIBEXEC}/${s}" ]] || continue
		run rm -f "${LIBEXEC}/${s}"
	done
	# Sweep leftovers so future installer helpers are not left behind.
	if [[ -d "$LIBEXEC" ]]; then
		shopt -s nullglob
		local leftover
		for leftover in "${LIBEXEC}/mpc-auth-"*; do
			[[ -e "$leftover" ]] || continue
			run rm -f "$leftover"
		done
		shopt -u nullglob
	fi
	if [[ "$DRY_RUN" != true ]] && [[ -d "$LIBEXEC" ]]; then
		rmdir "$LIBEXEC" 2>/dev/null || true
	elif [[ "$DRY_RUN" == true ]] && [[ -d "$LIBEXEC" ]]; then
		printf '+ rmdir %q 2>/dev/null || true\n' "$LIBEXEC"
	fi
}

mpc_auth_remove_env() {
	if [[ "$KEEP_ENV" == true ]]; then
		echo "Keeping ${DEFAULT_ENV} (--keep-env)."
		return 0
	fi
	if [[ -f "$DEFAULT_ENV" ]]; then
		run rm -f "$DEFAULT_ENV"
		echo "Removed ${DEFAULT_ENV}."
	else
		echo "No ${DEFAULT_ENV} present."
	fi

	if [[ "$PURGE_ENV_BACKUPS" == true ]]; then
		shopt -s nullglob
		local b
		for b in "${DEFAULT_ENV}.bak."*; do
			run rm -f "$b"
		done
		shopt -u nullglob
	fi
}

mpc_auth_remove_var_lib() {
	if [[ "$PURGE_VAR_LIB" != true ]]; then
		echo "Leaving ${VAR_LIB} (use --purge-var-lib to delete)."
		return 0
	fi
	if [[ -d "$VAR_LIB" ]]; then
		run rm -rf "$VAR_LIB"
		echo "Removed ${VAR_LIB}."
	else
		echo "No ${VAR_LIB} directory."
	fi
}

mpc_auth_journal_touch() {
	if ! command -v journalctl >/dev/null 2>&1; then
		echo "journalctl not found — skipping journal steps."
		return 0
	fi
	if [[ "$DRY_RUN" == true ]]; then
		echo '+ journalctl --rotate'
		if [[ -n "$JOURNAL_VACUUM_TIME" ]]; then
			printf '+ journalctl --vacuum-time=%q\n' "$JOURNAL_VACUUM_TIME"
		fi
		return 0
	fi
	journalctl --rotate || true
	if [[ -n "$JOURNAL_VACUUM_TIME" ]]; then
		echo "Running GLOBAL journal vacuum: journalctl --vacuum-time=$(printf %q "$JOURNAL_VACUUM_TIME")"
		journalctl --vacuum-time="$JOURNAL_VACUUM_TIME"
	fi
}

echo "Uninstalling mpc-auth-docker systemd helpers (dry-run=${DRY_RUN})..."
mpc_auth_stop_disable_known_units
mpc_auth_remove_libexec
mpc_auth_remove_env
mpc_auth_remove_var_lib
mpc_auth_journal_touch

echo "Done. Unit templates under ${UNIT_DIR} named mpc-auth-* should be gone; libexec cleared under ${LIBEXEC}."
