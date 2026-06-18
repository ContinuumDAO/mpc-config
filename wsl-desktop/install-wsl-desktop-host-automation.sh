#!/usr/bin/env bash
# Install WSL host automation for Windows Docker Desktop (pending-update.json + pending-vpn.json watcher).
# Reuses systemd/ scripts from this repo — no WSL systemd required.
#
# Usage:
#   bash wsl-desktop/install-wsl-desktop-host-automation.sh --repo-dir ~/mpc-config
#
set -euo pipefail

REPO_DIR=""
DRY_RUN=false

usage() {
	cat <<'EOF'
Usage:
  bash wsl-desktop/install-wsl-desktop-host-automation.sh --repo-dir PATH

Installs libexec copies, repo-local mpc-auth-docker.env, /var/lib/mpc-auth-docker,
and starts the pending-update + pending-vpn watcher.
EOF
}

log() { printf '==> %s\n' "$*" >&2; }
warn() { printf 'warning: %s\n' "$*" >&2; }

while [[ $# -gt 0 ]]; do
	case "$1" in
	--repo-dir)
		REPO_DIR="${2:?}"
		shift 2
		;;
	--dry-run)
		DRY_RUN=true
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		echo "error: unknown option: $1" >&2
		usage
		exit 1
		;;
	esac
done

if [[ -z "$REPO_DIR" ]]; then
	echo "error: --repo-dir required" >&2
	exit 1
fi

REPO_DIR="$(cd "$REPO_DIR" && pwd)"
WSL_ROOT="${REPO_DIR}/wsl-desktop"
SYSTEMD_ROOT="${REPO_DIR}/systemd"
LIBEXEC="${WSL_ROOT}/libexec"

if [[ ! -d "$SYSTEMD_ROOT" ]]; then
	echo "error: missing ${SYSTEMD_ROOT}" >&2
	exit 1
fi

for f in mpc-auth-apply-pending-update.sh mpc-auth-docker-update.sh mpc-auth-sync-compose-role.sh mpc-auth-docker-restart.sh; do
	if [[ ! -f "${SYSTEMD_ROOT}/${f}" ]]; then
		echo "error: missing ${SYSTEMD_ROOT}/${f}" >&2
		exit 1
	fi
done

for f in mpc-auth-vpn-enable-wsl.sh mpc-auth-vpn-disable-wsl.sh; do
	if [[ ! -f "${WSL_ROOT}/${f}" ]]; then
		echo "error: missing ${WSL_ROOT}/${f}" >&2
		exit 1
	fi
done

if [[ "$DRY_RUN" = true ]]; then
	printf '[dry-run] install wsl-desktop host automation under %q\n' "$WSL_ROOT"
	exit 0
fi

log "Installing WSL desktop host automation (repo ${REPO_DIR})"

# shellcheck source=_lib.sh
. "${WSL_ROOT}/_lib.sh"

mkdir -p "$LIBEXEC"
wsl_desktop_sudo mkdir -p /var/lib/mpc-auth-docker/applied
wsl_desktop_sudo chmod 0755 /var/lib/mpc-auth-docker /var/lib/mpc-auth-docker/applied

install -m 0755 \
	"${SYSTEMD_ROOT}/mpc-auth-apply-pending-update.sh" \
	"${SYSTEMD_ROOT}/mpc-auth-docker-update.sh" \
	"${SYSTEMD_ROOT}/mpc-auth-sync-compose-role.sh" \
	"${SYSTEMD_ROOT}/mpc-auth-docker-restart.sh" \
	"$LIBEXEC/"

# Repo-local libexec (apply script hardcodes /usr/local/libexec/mpc-auth).
sed -i 's|^LIBEXEC="/usr/local/libexec/mpc-auth"|LIBEXEC="$(cd "$(dirname "${BASH_SOURCE[0]}")" \&\& pwd)"|' \
	"${LIBEXEC}/mpc-auth-apply-pending-update.sh"

# Prefer repo-local env file when MPC_AUTH_WSL_ENV_FILE is set (wsl-desktop profile).
sed -i 's|^if \[\[ -r /etc/default/mpc-auth-docker \]\]; then|if [[ -n "${MPC_AUTH_WSL_ENV_FILE:-}" \&\& -r "${MPC_AUTH_WSL_ENV_FILE}" ]]; then\n\t# shellcheck source=/dev/null\n\t. "${MPC_AUTH_WSL_ENV_FILE}"\nelif [[ -r /etc/default/mpc-auth-docker ]]; then|' \
	"${LIBEXEC}/mpc-auth-docker-update.sh"

# Default compose role sync to repo libexec copy.
sed -i 's|/usr/local/libexec/mpc-auth/mpc-auth-sync-compose-role.sh|"$(cd "$(dirname "${BASH_SOURCE[0]}")" \&\& pwd)/mpc-auth-sync-compose-role.sh"|' \
	"${LIBEXEC}/mpc-auth-docker-update.sh"

if [[ -f "${SYSTEMD_ROOT}/mpc-auth-apply-pending-vpn.sh" ]]; then
	install -m 0755 "${SYSTEMD_ROOT}/mpc-auth-apply-pending-vpn.sh" "${LIBEXEC}/mpc-auth-apply-pending-vpn.sh"
	sed -i 's|LIBEXEC="/usr/local/libexec/mpc-auth"|LIBEXEC="'"${LIBEXEC}"'"|' \
		"${LIBEXEC}/mpc-auth-apply-pending-vpn.sh"
	sed -i 's|^set -euo pipefail|set -euo pipefail\nif [[ -n "${MPC_AUTH_WSL_ENV_FILE:-}" \&\& -r "${MPC_AUTH_WSL_ENV_FILE}" ]]; then\n\t# shellcheck source=/dev/null\n\t. "${MPC_AUTH_WSL_ENV_FILE}"\nfi|' \
		"${LIBEXEC}/mpc-auth-apply-pending-vpn.sh"
fi

install -m 0755 "${WSL_ROOT}/mpc-auth-vpn-enable-wsl.sh" "${LIBEXEC}/mpc-auth-vpn-enable.sh"
install -m 0755 "${WSL_ROOT}/mpc-auth-vpn-disable-wsl.sh" "${LIBEXEC}/mpc-auth-vpn-disable.sh"

ENV_FILE="${WSL_ROOT}/mpc-auth-docker.env"
if [[ -f "${WSL_ROOT}/mpc-auth-docker.env" ]]; then
	:
else
	echo "error: missing template ${ENV_FILE}" >&2
	exit 1
fi

if grep -q '^MPC_AUTH_COMPOSE_WORKDIR=' "$ENV_FILE"; then
	sed -i "s|^MPC_AUTH_COMPOSE_WORKDIR=.*|MPC_AUTH_COMPOSE_WORKDIR=${REPO_DIR}|" "$ENV_FILE"
else
	echo "MPC_AUTH_COMPOSE_WORKDIR=${REPO_DIR}" >>"$ENV_FILE"
fi

printf '%s\n' "$REPO_DIR" >"${WSL_ROOT}/repo-dir.txt"

chmod +x "${WSL_ROOT}"/*.sh 2>/dev/null || true

log "Starting pending-update watcher"
bash "${WSL_ROOT}/start-watcher.sh"

log "WSL desktop host automation ready."
log "  status: ${WSL_ROOT}/status-watcher.sh"
log "  log:    ${WSL_ROOT}/watcher.log"
log "  manual: ${LIBEXEC}/mpc-auth-docker-restart.sh"
log "  VPN:    pending-vpn.json → ${LIBEXEC}/mpc-auth-apply-pending-vpn.sh"
