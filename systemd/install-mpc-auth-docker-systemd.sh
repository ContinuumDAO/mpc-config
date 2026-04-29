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
LIBEXEC="/usr/local/libexec/mpc-auth"
UNIT_DIR="/etc/systemd/system"
DEFAULT_ENV="/etc/default/mpc-auth-docker"

mkdir -p "$LIBEXEC"

install -m 0755 \
	"$HERE/mpc-auth-docker-restart.sh" \
	"$HERE/mpc-auth-docker-update.sh" \
	"$HERE/mpc-auth-apply-pending-update.sh" \
	"$LIBEXEC/"

if [[ "$INSTALL_ENV" == true ]]; then
	if [[ -f "$DEFAULT_ENV" && "$SKIP_ENV_BACKUP" != true ]]; then
		cp -a "$DEFAULT_ENV" "${DEFAULT_ENV}.bak.$(date +%Y%m%d%H%M%S)"
		echo "Backed up existing $DEFAULT_ENV"
	fi
	install -m 0644 "$HERE/mpc-auth-docker.env" "$DEFAULT_ENV"
	echo "Installed $DEFAULT_ENV"
fi

install -m 0644 \
	"$HERE/mpc-auth-docker-restart.service" \
	"$HERE/mpc-auth-docker-update@.service" \
	"$HERE/mpc-auth-docker-pending-update.path" \
	"$HERE/mpc-auth-docker-pending-update.service" \
	"$UNIT_DIR/"

mkdir -p /var/lib/mpc-auth-docker/applied
chmod 0755 /var/lib/mpc-auth-docker /var/lib/mpc-auth-docker/applied || true

systemctl daemon-reload

systemctl enable mpc-auth-docker-pending-update.path
systemctl restart mpc-auth-docker-pending-update.path || systemctl start mpc-auth-docker-pending-update.path

echo
echo "Installed:"
echo "  $LIBEXEC/mpc-auth-docker-{restart,update}.sh + mpc-auth-apply-pending-update.sh"
[[ "$INSTALL_ENV" == true ]] && echo "  $DEFAULT_ENV"
echo "  $UNIT_DIR/mpc-auth-docker-restart.service"
echo "  $UNIT_DIR/mpc-auth-docker-update@.service"
echo "  $UNIT_DIR/mpc-auth-docker-pending-update.{path,service} (auto image update — bind-mount /var/lib/mpc-auth-docker in compose)"
echo "  $LIBEXEC/mpc-auth-apply-pending-update.sh"
echo
echo "Run: sudo systemctl start mpc-auth-docker-restart.service"
echo "(Optional automation) mpc-auth-docker-pending-update.path watches /var/lib/mpc-auth-docker/pending-update.json — bind-mount that dir in compose."
