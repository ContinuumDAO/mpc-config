#!/usr/bin/env bash
# Install mpc-auth Docker systemd units and helpers (Ubuntu / Debian / any systemd OS).
#
# Unit files belong in /etc/systemd/system/ — not bare /etc/systemd/ (that directory holds
# system.conf snippets and journal.conf; packaged units override from /usr/lib/systemd/system/).
#
# Usage: sudo ./install-mpc-auth-docker-systemd.sh
#        sudo ./install-mpc-auth-docker-systemd.sh --no-env       # scripts + units only (keep /etc/default)
#        sudo ./install-mpc-auth-docker-systemd.sh --no-env-backup # overwrite ENV without copying .bak first
#

set -euo pipefail

INSTALL_ENV=true
SKIP_ENV_BACKUP=false

usage() {
	echo "usage: sudo $0 [--no-env] [--no-env-backup]" >&2
	exit 2
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	--no-env) INSTALL_ENV=false ;;
	--no-env-backup) SKIP_ENV_BACKUP=true ;;
	-h | --help) usage ;;
	*) usage ;;
	esac
	shift
done

if [[ "${EUID:-}" -ne 0 ]]; then
	echo "error: run as root (sudo)" >&2
	exit 1
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
# shellcheck source=../scripts/lib/ensure-vpn-host-packages.sh
. "${REPO_ROOT}/scripts/lib/ensure-vpn-host-packages.sh"
# shellcheck source=../scripts/lib/ensure-shadowsocks-host-packages.sh
. "${REPO_ROOT}/scripts/lib/ensure-shadowsocks-host-packages.sh"
LIBEXEC="/usr/local/libexec/mpc-auth"
UNIT_DIR="/etc/systemd/system"
DEFAULT_ENV="/etc/default/mpc-auth-docker"

mkdir -p "$LIBEXEC"

install -m 0755 \
	"$HERE/mpc-auth-docker-restart.sh" \
	"$HERE/mpc-auth-docker-update.sh" \
	"$HERE/mpc-auth-apply-pending-update.sh" \
	"$HERE/mpc-auth-apply-pending-reboot.sh" \
	"$HERE/mpc-auth-apply-pending-vpn.sh" \
	"$HERE/mpc-auth-vpn-enable.sh" \
	"$HERE/mpc-auth-vpn-disable.sh" \
	"$HERE/mpc-auth-apply-agent-llm-config.sh" \
	"$HERE/mpc-auth-sync-compose-role.sh" \
	"${REPO_ROOT}/scripts/lib/mpc-auth-vpn-wg0-hooks.sh" \
	"${REPO_ROOT}/scripts/lib/mpc-auth-vpn-ss-hooks.sh" \
	"$LIBEXEC/"

if [[ "$INSTALL_ENV" == true ]]; then
	if [[ -f "$DEFAULT_ENV" && "$SKIP_ENV_BACKUP" != true ]]; then
		cp -a "$DEFAULT_ENV" "${DEFAULT_ENV}.bak.$(date +%Y%m%d%H%M%S)"
		echo "Backed up existing $DEFAULT_ENV"
	fi
	install -m 0644 "$HERE/mpc-auth-docker.env" "$DEFAULT_ENV"
	# Default compose project root = parent of systemd/ (this mpc-config checkout).
	COMPOSE_ROOT="$(cd "$HERE/.." && pwd)"
	if [[ -f "${COMPOSE_ROOT}/docker-compose.yml" || -f "${COMPOSE_ROOT}/docker-compose.client.yml" || -f "${COMPOSE_ROOT}/docker-compose.relay.yml" ]]; then
		sed -i "s|^MPC_AUTH_COMPOSE_WORKDIR=.*|MPC_AUTH_COMPOSE_WORKDIR=${COMPOSE_ROOT}|" "$DEFAULT_ENV"
		echo "Set MPC_AUTH_COMPOSE_WORKDIR=${COMPOSE_ROOT} in $DEFAULT_ENV"
	else
		echo "WARNING: no docker-compose.yml next to ${COMPOSE_ROOT} — set MPC_AUTH_COMPOSE_WORKDIR in $DEFAULT_ENV before POST /updateMpcAuth." >&2
	fi
	echo "Installed $DEFAULT_ENV"
fi

install -m 0644 \
	"$HERE/mpc-auth-docker-restart.service" \
	"$HERE/mpc-auth-docker-update@.service" \
	"$HERE/mpc-auth-docker-pending-update.path" \
	"$HERE/mpc-auth-docker-pending-update.service" \
	"$HERE/mpc-auth-docker-pending-reboot.path" \
	"$HERE/mpc-auth-docker-pending-reboot.service" \
	"$HERE/mpc-auth-vpn-pending.path" \
	"$HERE/mpc-auth-vpn-pending.service" \
	"$HERE/mpc-auth-wireguard-wg0.service" \
	"$HERE/mpc-auth-vpn-mgmt-proxy.service" \
	"$HERE/mpc-auth-shadowsocks.service" \
	"$HERE/mpc-auth-agent-llm-config.path" \
	"$HERE/mpc-auth-agent-llm-config.service" \
	"$UNIT_DIR/"

mkdir -p /var/lib/mpc-auth-docker/applied
chmod 0755 /var/lib/mpc-auth-docker /var/lib/mpc-auth-docker/applied || true

systemctl daemon-reload

_mpc_auth_auto_update_ready() {
	local w explicit
	if [[ ! -r "$DEFAULT_ENV" ]]; then
		return 1
	fi
	# shellcheck source=/dev/null
	. "$DEFAULT_ENV"
	w="${MPC_AUTH_COMPOSE_WORKDIR:-${MPC_AUTH_COMPOSE_DIR:-}}"
	w="${w#"${w%%[![:space:]]*}"}"
	w="${w%"${w##*[![:space:]]}"}"
	explicit="${MPC_AUTH_POST_UPDATE_CMD:-}"
	explicit="${explicit#"${explicit%%[![:space:]]*}"}"
	explicit="${explicit%"${explicit##*[![:space:]]}"}"
	[[ -n "$explicit" ]] && return 0
	[[ -n "$w" && -d "$w" ]] && return 0
	return 1
}

if _mpc_auth_auto_update_ready; then
	systemctl enable mpc-auth-docker-pending-update.path
	systemctl restart mpc-auth-docker-pending-update.path || systemctl start mpc-auth-docker-pending-update.path
else
	echo "WARNING: MPC_AUTH_COMPOSE_WORKDIR unset or missing — NOT enabling mpc-auth-docker-pending-update.path." >&2
	echo "  Set MPC_AUTH_COMPOSE_WORKDIR in $DEFAULT_ENV (or MPC_AUTH_POST_UPDATE_CMD), then:" >&2
	echo "  sudo systemctl enable --now mpc-auth-docker-pending-update.path" >&2
fi

systemctl enable mpc-auth-docker-pending-reboot.path
systemctl restart mpc-auth-docker-pending-reboot.path || systemctl start mpc-auth-docker-pending-reboot.path

systemctl enable mpc-auth-agent-llm-config.path
systemctl restart mpc-auth-agent-llm-config.path || systemctl start mpc-auth-agent-llm-config.path

if ! ensure_vpn_host_packages; then
	echo "WARNING: VPN host packages (wireguard, socat) not installed — POST /vpn/setEnabled will fail until they are." >&2
	echo "  On Debian/Ubuntu: sudo apt install -y wireguard socat" >&2
fi

if ! ensure_shadowsocks_host_packages; then
	echo "WARNING: shadowsocks-rust (ssserver) not installed — VPN obfuscation unavailable until installed." >&2
	echo "  On Debian/Ubuntu: sudo apt install -y shadowsocks-rust (or re-run install with optional package helper)" >&2
fi

systemctl enable mpc-auth-vpn-pending.path
systemctl restart mpc-auth-vpn-pending.path || systemctl start mpc-auth-vpn-pending.path

echo
echo "Installed:"
echo "  $LIBEXEC/mpc-auth-docker-{restart,update}.sh + mpc-auth-apply-pending-{update,reboot}.sh"
[[ "$INSTALL_ENV" == true ]] && echo "  $DEFAULT_ENV"
echo "  $UNIT_DIR/mpc-auth-docker-restart.service"
echo "  $UNIT_DIR/mpc-auth-docker-update@.service"
echo "  $UNIT_DIR/mpc-auth-docker-pending-update.{path,service} (auto image update — bind-mount /var/lib/mpc-auth-docker in compose)"
echo "  $UNIT_DIR/mpc-auth-docker-pending-reboot.{path,service} (POST mpc-auth /reboot — host reboot)"
echo "  $UNIT_DIR/mpc-auth-agent-llm-config.{path,service} (agent LLM config stamp — optional restart)"
echo "  $LIBEXEC/mpc-auth-apply-agent-llm-config.sh"
echo "  $LIBEXEC/mpc-auth-apply-pending-update.sh"
echo "  $LIBEXEC/mpc-auth-apply-pending-reboot.sh"
echo "  $LIBEXEC/mpc-auth-sync-compose-role.sh (relay/client docker-compose.yml sync before restart)"
echo "  $LIBEXEC/mpc-auth-apply-pending-vpn.sh + mpc-auth-vpn-{enable,disable}.sh (POST /vpn/setEnabled — WireGuard VPN)"
echo "  $UNIT_DIR/mpc-auth-vpn-pending.{path,service} (bind-mount /var/lib/mpc-auth-docker in compose)"
	echo "  $UNIT_DIR/mpc-auth-wireguard-wg0.service + mpc-auth-vpn-mgmt-proxy.service + mpc-auth-shadowsocks.service"
echo
echo "Run: sudo systemctl start mpc-auth-docker-restart.service"
echo "(Optional automation) mpc-auth-docker-pending-update.path watches /var/lib/mpc-auth-docker/pending-update.json — bind-mount that dir in compose."
echo "(Optional) mpc-auth-docker-pending-reboot.path watches pending-reboot.json after POST /reboot (same bind mount; set MPC_AUTH_PENDING_REBOOT_FILE in compose)."
