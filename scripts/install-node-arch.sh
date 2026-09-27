#!/usr/bin/env bash
# One-shot MPC / MPA wallet node install for systemd Arch derivatives (run as root).
#
# Covers Arch Linux, Omarchy, Manjaro, EndeavourOS, Garuda, CachyOS, ArcoLinux,
# and other hosts with pacman, systemctl, and ID or ID_LIKE of arch/omarchy.
# Refuses Artix, Obarun, and SteamOS.
#
# Prefer the dispatcher, which also selects the Debian/Ubuntu script:
#   curl -fsSL "https://raw.githubusercontent.com/ContinuumDAO/mpc-config/main/scripts/install-node-linux.sh" \
#     | bash -s -- --node-mgt-key "0xYour40Hex..." --ip "203.0.113.50"
#
# Direct:
#   curl -fsSL "https://raw.githubusercontent.com/ContinuumDAO/mpc-config/main/scripts/install-node-arch.sh" \
#     | bash -s -- --node-mgt-key "0xYour40Hex..." --ip "203.0.113.50"
#
set -euo pipefail

CONTINUUM_INSTALL_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"
# shellcheck source=lib/load-install-progress.sh
if [ -n "$CONTINUUM_INSTALL_SCRIPT_DIR" ] && [ -f "${CONTINUUM_INSTALL_SCRIPT_DIR}/lib/load-install-progress.sh" ]; then
	# shellcheck source=lib/load-install-progress.sh
	. "${CONTINUUM_INSTALL_SCRIPT_DIR}/lib/load-install-progress.sh"
	# shellcheck source=lib/install-progress-docker.sh
	. "${CONTINUUM_INSTALL_SCRIPT_DIR}/lib/install-progress-docker.sh"
else
	_bootstrap_tmp="$(mktemp -d 2>/dev/null || echo "/tmp/continuum-bootstrap-$$")"
	_raw_base="https://raw.githubusercontent.com/ContinuumDAO/mpc-config/${MPC_CONFIG_REF:-main}"
	mkdir -p "${_bootstrap_tmp}/lib"
	if curl -fsSL "${_raw_base}/scripts/lib/load-install-progress.sh" -o "${_bootstrap_tmp}/lib/load-install-progress.sh" 2>/dev/null; then
		CONTINUUM_INSTALL_SCRIPT_DIR="${_bootstrap_tmp}"
		# shellcheck source=/dev/null
		. "${_bootstrap_tmp}/lib/load-install-progress.sh"
		if curl -fsSL "${_raw_base}/scripts/lib/install-progress-docker.sh" -o "${_bootstrap_tmp}/lib/install-progress-docker.sh" 2>/dev/null; then
			# shellcheck source=/dev/null
			. "${_bootstrap_tmp}/lib/install-progress-docker.sh"
		fi
	else
		CONTINUUM_INSTALL_PROGRESS=off
		export CONTINUUM_INSTALL_PROGRESS
	fi
fi

if [ -n "$CONTINUUM_INSTALL_SCRIPT_DIR" ] && [ -f "${CONTINUUM_INSTALL_SCRIPT_DIR}/lib/linux-os-family.sh" ]; then
	# shellcheck source=lib/linux-os-family.sh
	. "${CONTINUUM_INSTALL_SCRIPT_DIR}/lib/linux-os-family.sh"
else
	_family_tmp="$(mktemp)"
	_raw_base="https://raw.githubusercontent.com/ContinuumDAO/mpc-config/${MPC_CONFIG_REF:-main}"
	curl -fsSL "${_raw_base}/scripts/lib/linux-os-family.sh" -o "$_family_tmp"
	# shellcheck source=/dev/null
	. "$_family_tmp"
	rm -f "$_family_tmp"
fi

INSTALL_SCRIPT_VERSION="1.0.0"
INSTALL_LOG="${INSTALL_LOG:-/var/log/continuumdao-mpc-install.log}"

MPC_CONFIG_REPO="${MPC_CONFIG_REPO:-https://github.com/ContinuumDAO/mpc-config.git}"
MPC_CONFIG_REF="${MPC_CONFIG_REF:-main}"
MPC_USER="${MPC_USER:-mpcnode}"
REPO_DIR="${MPC_REPO_DIR:-/home/${MPC_USER}/mpc-config}"

INSTALL_SYSTEMD=true
SKIP_PACKAGES=false
SKIP_USER=false
SKIP_CLONE=false
DRY_RUN=false
NO_START=false
FORCE_FRESH_INSTALL=false
PROVISION_NODE_IP=""

PROVISION_ARGS=()

usage() {
	cat <<'EOF'
Usage:
  curl -fsSL "https://raw.githubusercontent.com/ContinuumDAO/mpc-config/REF/scripts/install-node-arch.sh" \
    | bash -s -- [install options] [provision options]

Run as root on a systemd Arch derivative (Arch, Omarchy, Manjaro, EndeavourOS,
Garuda, CachyOS, ArcoLinux). Installs packages with pacman, creates mpcnode,
clones mpc-config, runs scripts/provision-node.sh, then docker compose up -d.

Not supported: Artix, Obarun (no systemd), SteamOS (immutable root).
Ubuntu/Debian: use scripts/install-node-linux.sh (it selects the apt installer).

Provision options (at least one management key required):
  -k, --node-mgt-key ADDR     Ethereum NodeMgtKey (0x + 40 hex)
      --public-mgt-key KEY    Ed25519 PublicMgtKey (64 hex or ssh-ed25519 line)
  -i, --ip ADDRESS            This node's public IPv4 (strongly recommended on VPS)
  -p, --http-port PORT        nodeAddresses HTTP port (default 8081)
      --relay-host HOST       Relay placeholder (default 0.0.0.0)
      --force-browser-certs   Pass --force-browser-https-certs to process_config.sh
      --no-loopback             Disable browser loopback HTTP
      --no-firewall             Skip UFW setup in process_config.sh
      --no-agent-llm-config-path

Install options:
      --install-systemd           Enable systemd units (default; accepted for compatibility with generated commands)
      --no-systemd              Do not pass --install-systemd to provision-node.sh
      --mpc-user USER           OS user (default: mpcnode)
      --repo-dir PATH           Clone path (default: /home/mpcnode/mpc-config)
      --ref REF                 Git branch (default: main; same branch Maintenance git pull uses)
      --repo-url URL            Git remote (default: ContinuumDAO/mpc-config)
      --skip-clone              Use existing repo at --repo-dir
      --skip-packages           Skip pacman install (repo already has deps)
      --skip-user               Skip mpcnode user creation
      --no-start                Provision only; skip docker compose up -d
      --dry-run                 Print actions without executing
      --force-fresh-install     Continue if MPC Docker containers are running (configs.yaml must still be absent)
  -h, --help                    Show this help

Environment:
  MPC_CONFIG_REF, MPC_CONFIG_REPO, MPC_USER, MPC_REPO_DIR, RELAYER_API_URL

Examples:
  bash -s -- --node-mgt-key "0xabc..." --ip "203.0.113.50"
  bash -s -- --public-mgt-key "64hex..." --ip "203.0.113.50"
EOF
}

log() {
	printf '==> %s\n' "$*" >&2
	if [ "$DRY_RUN" = false ]; then
		printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >>"$INSTALL_LOG" 2>/dev/null || true
	fi
}

warn() {
	printf 'warning: %s\n' "$*" >&2
	if [ "$DRY_RUN" = false ]; then
		printf '[%s] warning: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >>"$INSTALL_LOG" 2>/dev/null || true
	fi
}

die() {
	printf 'error: %s\n' "$*" >&2
	if [ "$DRY_RUN" = false ]; then
		printf '[%s] error: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >>"$INSTALL_LOG" 2>/dev/null || true
	fi
	exit 1
}

on_err() {
	local ec=$?
	install_progress_finish false 2>/dev/null || true
	printf 'error: install failed at line %s (exit %s). See %s on the server.\n' "${BASH_LINENO[0]:-?}" "$ec" "$INSTALL_LOG" >&2
	exit "$ec"
}

require_root() {
	if [ "${EUID:-0}" -ne 0 ]; then
		die "run as root on the target machine (e.g. ssh root@HOST, then paste this script)"
	fi
}

require_arch_family() {
	if ! command -v pacman >/dev/null 2>&1; then
		die "this installer needs pacman (systemd Arch derivatives)"
	fi
	if ! command -v systemctl >/dev/null 2>&1; then
		die "systemd (systemctl) is required. Artix and Obarun are not supported."
	fi
	if [ ! -r /etc/os-release ]; then
		die "cannot read /etc/os-release"
	fi
	local family
	family="$(continuum_linux_family_from_release /etc/os-release)"
	if [ "$family" != "arch" ]; then
		# shellcheck source=/dev/null
		. /etc/os-release
		die "unsupported OS: ${PRETTY_NAME:-unknown} (need a systemd Arch derivative: Arch, Omarchy, Manjaro, EndeavourOS, Garuda, CachyOS, ArcoLinux). Artix, Obarun, and SteamOS are not supported. Ubuntu/Debian: use scripts/install-node-linux.sh."
	fi
}

run_or_dry() {
	if [ "$DRY_RUN" = true ]; then
		printf '[dry-run] %s\n' "$*"
	else
		"$@"
	fi
}

packages_already_installed() {
	command -v docker >/dev/null 2>&1 \
		&& command -v git >/dev/null 2>&1 \
		&& command -v python3 >/dev/null 2>&1 \
		&& python3 -c "import ruamel.yaml, cryptography" 2>/dev/null \
		&& command -v wg-quick >/dev/null 2>&1 \
		&& command -v socat >/dev/null 2>&1 \
		&& command -v tc >/dev/null 2>&1 \
		&& command -v ip >/dev/null 2>&1 \
		&& command -v ufw >/dev/null 2>&1 \
		&& docker compose version >/dev/null 2>&1
}

maybe_auto_skip_packages() {
	if [ "$SKIP_PACKAGES" = true ]; then
		return 0
	fi
	if packages_already_installed; then
		warn "Required packages already installed — skipping pacman (resume after interrupted install)"
		SKIP_PACKAGES=true
	fi
}

preflight_check_fresh_install() {
	local cfg="${REPO_DIR}/configs.yaml"

	if [ -f "$cfg" ]; then
		printf 'error: %s already exists — this installer is for a new node only.\n' "$cfg" >&2
		printf 'Remove or back up that file (and stop containers) before reprovisioning, or use MPA Maintenance to update.\n' >&2
		exit 1
	fi

	local docker_block=0
	if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
		local project line name image
		project="$(basename "$REPO_DIR")"
		if docker ps --filter "label=com.docker.compose.project=${project}" -q 2>/dev/null | grep -q .; then
			docker_block=1
			printf 'error: Docker Compose project %q has running containers:\n' "$project" >&2
			docker ps --filter "label=com.docker.compose.project=${project}" \
				--format '  {{.Names}}  ({{.Image}})  {{.Status}}' >&2 || true
		else
			while IFS= read -r line; do
				[ -z "$line" ] && continue
				name="${line%%$'\t'*}"
				image="${line#*$'\t'}"
				case "$image" in
				continuumdao/mpc-auth* | mongo:6* | continuumdao/continuumdao-node-app* | continuumdao/continuum-mcp-server* | eclipse-mosquitto:2*)
					if [ "$docker_block" -eq 0 ]; then
						printf 'error: MPC node Docker containers are already running:\n' >&2
					fi
					docker_block=1
					printf '  %s  (%s)\n' "$name" "$image" >&2
					;;
				esac
			done < <(docker ps --format '{{.Names}}	{{.Image}}' 2>/dev/null || true)
		fi
	fi

	if [ "$docker_block" -ne 0 ]; then
		printf '\n' >&2
		printf 'Stop the existing stack first (e.g. cd %s && docker compose down).\n' "$REPO_DIR" >&2
		printf 'To update a running node use https://mpa.continuumdao.org (Maintenance).\n' >&2
		printf 'Override (containers only): --force-fresh-install\n' >&2
		if [ "$FORCE_FRESH_INSTALL" = true ]; then
			warn "--force-fresh-install set — continuing despite running containers"
			log "Preflight OK: configs.yaml absent; running containers ignored by --force-fresh-install"
			return 0
		fi
		exit 1
	fi

	log "Preflight OK: no existing configs.yaml or MPC Docker stack detected at ${REPO_DIR}"
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	-k | --node-mgt-key | --public-mgt-key | -i | --ip | -p | --http-port | --relay-host)
		if [[ $# -lt 2 ]]; then
			die "option $1 requires a value"
		fi
		if [ "$1" = "-i" ] || [ "$1" = "--ip" ]; then
			PROVISION_NODE_IP="$2"
		fi
		PROVISION_ARGS+=("$1" "$2")
		shift 2
		;;
	--force-browser-certs | --no-loopback | --no-firewall | --no-agent-llm-config-path)
		PROVISION_ARGS+=("$1")
		shift
		;;
	--install-systemd)
		INSTALL_SYSTEMD=true
		shift
		;;
	--no-systemd)
		INSTALL_SYSTEMD=false
		shift
		;;
	--mpc-user)
		MPC_USER="${2:?}"
		REPO_DIR="${MPC_REPO_DIR:-/home/${MPC_USER}/mpc-config}"
		shift 2
		;;
	--repo-dir)
		REPO_DIR="${2:?}"
		shift 2
		;;
	--ref)
		MPC_CONFIG_REF="${2:?}"
		shift 2
		;;
	--repo-url)
		MPC_CONFIG_REPO="${2:?}"
		shift 2
		;;
	--skip-clone)
		SKIP_CLONE=true
		shift
		;;
	--skip-packages)
		SKIP_PACKAGES=true
		shift
		;;
	--skip-user)
		SKIP_USER=true
		shift
		;;
	--no-start)
		NO_START=true
		shift
		;;
	--dry-run)
		DRY_RUN=true
		shift
		;;
	--force-fresh-install)
		FORCE_FRESH_INSTALL=true
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	-*)
		die "unknown option: $1 (try --help)"
		;;
	*)
		die "unexpected argument: $1 (try --help)"
		;;
	esac
done

if [ "$INSTALL_SYSTEMD" = true ]; then
	PROVISION_ARGS+=(--install-systemd)
fi

require_root
require_arch_family
trap on_err ERR

if [ "$DRY_RUN" = false ]; then
	install -d -m 0755 "$(dirname "$INSTALL_LOG")" 2>/dev/null || true
	printf '[%s] install start v%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$INSTALL_SCRIPT_VERSION" >>"$INSTALL_LOG" 2>/dev/null || true
fi

log "ContinuumDAO MPC node one-shot install (Arch-family installer v${INSTALL_SCRIPT_VERSION})"
log "Install log: ${INSTALL_LOG}"
log "Target repo: ${REPO_DIR} (ref: ${MPC_CONFIG_REF})"

export CONTINUUM_INSTALL_DRY_RUN="$DRY_RUN"
install_progress_init vps

install_progress_topic_begin preflight
preflight_check_fresh_install
install_progress_topic_done preflight

maybe_auto_skip_packages
if [ "$SKIP_PACKAGES" = true ]; then
	install_progress_mark_done_if packages true
fi

if [ "$SKIP_PACKAGES" = false ]; then
	log "Installing system packages (pacman)"
	install_progress_topic_begin packages
	install_progress_spinner_start
	install_progress_topic_set packages 40
	continuum_pacman_install \
		ca-certificates \
		curl \
		wget \
		git \
		openssl \
		gnupg \
		iptables \
		sudo \
		unzip \
		docker \
		docker-compose \
		python \
		python-pip \
		python-ruamel-yaml \
		python-cryptography \
		wireguard-tools \
		socat \
		iproute2 \
		ufw \
		jq
	install_progress_topic_set packages 85
	if [ "$DRY_RUN" = false ]; then
		systemctl enable --now docker
		if ! docker compose version >/dev/null 2>&1; then
			die "'docker compose' (v2) is required — pacman package docker-compose should provide it"
		fi
	else
		printf '[dry-run] systemctl enable --now docker\n'
		printf '[dry-run] docker compose version\n'
	fi
	install_progress_spinner_stop
	install_progress_topic_done packages
	log "Packages phase complete"
fi

if [ -z "${CONTINUUM_INSTALL_SCRIPT_DIR:-}" ]; then
	CONTINUUM_INSTALL_SCRIPT_DIR="$(mktemp -d 2>/dev/null || echo "/tmp/continuum-bootstrap-$$")"
fi
_ensure_vpn_lib="${CONTINUUM_INSTALL_SCRIPT_DIR}/lib/ensure-vpn-host-packages.sh"
if [ ! -f "$_ensure_vpn_lib" ]; then
	_raw_base="https://raw.githubusercontent.com/ContinuumDAO/mpc-config/${MPC_CONFIG_REF:-main}"
	mkdir -p "${CONTINUUM_INSTALL_SCRIPT_DIR}/lib"
	curl -fsSL "${_raw_base}/scripts/lib/ensure-vpn-host-packages.sh" -o "$_ensure_vpn_lib"
fi
# shellcheck source=lib/ensure-vpn-host-packages.sh
. "$_ensure_vpn_lib"
export CONTINUUM_INSTALL_DRY_RUN="$DRY_RUN"
ensure_vpn_host_packages || warn "wireguard-tools/socat/iproute2 missing — VPN enable will fail until: sudo pacman -S --needed wireguard-tools socat iproute2"
log "WireGuard host packages ready. If admin VPN handshakes fail later, allow inbound UDP 51820 in the host firewall (UFW rules are applied automatically on enable)."

_ensure_ss_lib="${CONTINUUM_INSTALL_SCRIPT_DIR}/lib/ensure-shadowsocks-host-packages.sh"
if [ ! -f "$_ensure_ss_lib" ]; then
	_raw_base="${_raw_base:-https://raw.githubusercontent.com/ContinuumDAO/mpc-config/${MPC_CONFIG_REF:-main}}"
	mkdir -p "${CONTINUUM_INSTALL_SCRIPT_DIR}/lib"
	curl -fsSL "${_raw_base}/scripts/lib/ensure-shadowsocks-host-packages.sh" -o "$_ensure_ss_lib" 2>/dev/null || true
fi
if [ -f "$_ensure_ss_lib" ]; then
	# shellcheck source=lib/ensure-shadowsocks-host-packages.sh
	. "$_ensure_ss_lib"
	ensure_shadowsocks_host_packages || warn "shadowsocks-rust missing — VPN obfuscation unavailable until installed"
fi

if [ "$SKIP_USER" = false ]; then
	log "Ensuring OS user ${MPC_USER} with password-protected sudo"
	install_progress_topic_begin os-user
	if [ "$DRY_RUN" = false ]; then
		if ! id "$MPC_USER" >/dev/null 2>&1; then
			useradd -m -s /bin/bash -c "ContinuumDAO MPC node" "$MPC_USER"
		fi
		if getent group wheel >/dev/null 2>&1; then
			usermod -aG wheel "$MPC_USER" 2>/dev/null || true
		fi
		if getent group sudo >/dev/null 2>&1; then
			usermod -aG sudo "$MPC_USER" 2>/dev/null || true
		fi
		if getent group docker >/dev/null 2>&1; then
			usermod -aG docker "$MPC_USER" 2>/dev/null || true
		fi
		install -d -m 0750 /etc/sudoers.d
		printf '%s ALL=(ALL:ALL) ALL\n' "$MPC_USER" >"/etc/sudoers.d/${MPC_USER}"
		chmod 0440 "/etc/sudoers.d/${MPC_USER}"
		visudo -cf "/etc/sudoers.d/${MPC_USER}" >/dev/null
	else
		printf '[dry-run] useradd -m %s, sudoers.d, docker and wheel groups\n' "$MPC_USER"
	fi
	install_progress_topic_done os-user
else
	install_progress_mark_done_if os-user true
fi

if [ "$SKIP_CLONE" = false ]; then
	log "Cloning mpc-config to ${REPO_DIR}"
	install_progress_topic_begin clone
	install_progress_spinner_start
	if [ "$DRY_RUN" = false ]; then
		if [ -d "$REPO_DIR" ]; then
			if [ -f "${REPO_DIR}/configs.yaml" ]; then
				die "refusing to proceed: ${REPO_DIR}/configs.yaml already exists (remove or use --skip-clone on an empty tree)"
			fi
			if [ -d "${REPO_DIR}/.git" ]; then
				warn "${REPO_DIR} exists without configs.yaml — using existing clone"
			else
				die "${REPO_DIR} exists and is not a git repo — remove it or choose --repo-dir"
			fi
		else
			install -d -o "$MPC_USER" -g "$MPC_USER" "$(dirname "$REPO_DIR")"
			sudo -u "$MPC_USER" git clone --depth 1 --branch "$MPC_CONFIG_REF" "$MPC_CONFIG_REPO" "$REPO_DIR"
		fi
	else
		printf '[dry-run] git clone --branch %s %s %s\n' "$MPC_CONFIG_REF" "$MPC_CONFIG_REPO" "$REPO_DIR"
	fi
	install_progress_spinner_stop
	install_progress_topic_done clone
else
	log "Skipping clone (--skip-clone); using ${REPO_DIR}"
	[ -d "$REPO_DIR" ] || die "repo directory not found: $REPO_DIR"
	install_progress_mark_done_if clone true
fi

PROVISION_SH="${REPO_DIR}/scripts/provision-node.sh"

if [ "$DRY_RUN" = false ]; then
	[ -f "$PROVISION_SH" ] || die "missing ${PROVISION_SH} — check clone/ref"
fi

log "Checking Docker Compose v2 (pacman docker-compose; not the Debian apt plugin script)"
install_progress_topic_begin docker-v2
install_progress_spinner_start
if [ "$DRY_RUN" = true ]; then
	printf '[dry-run] docker compose version\n'
else
	if ! docker compose version >/dev/null 2>&1; then
		die "'docker compose' (v2) is required — install the distro docker-compose package (sudo pacman -S --needed docker-compose)"
	fi
fi
install_progress_spinner_stop
install_progress_topic_done docker-v2

log "Provisioning node (scripts/provision-node.sh)"
export CONTINUUM_INSTALL_SCRIPT_DIR="${REPO_DIR}/scripts"
install_progress_register_pc_topics 0 0
if [ "$DRY_RUN" = true ]; then
	printf '[dry-run] bash %s %s\n' "$PROVISION_SH" "${PROVISION_ARGS[*]:-}"
	install_progress_topic_done provision-setup 2>/dev/null || true
	install_progress_topic_done configure-node 2>/dev/null || true
else
	cd "$REPO_DIR"
	CONTINUUM_INSTALL_PROGRESS_SUPPRESS_SYNC=1 bash "$PROVISION_SH" "${PROVISION_ARGS[@]}"
	install_progress_topic_done provision-setup
	install_progress_topic_done configure-node
fi

if [ "$DRY_RUN" = false ]; then
	log "Setting ownership to ${MPC_USER}"
	chown -R "${MPC_USER}:${MPC_USER}" "$REPO_DIR"
fi

if [ "$NO_START" = false ]; then
	log "Pulling images and starting Docker stack"
	if [ "$DRY_RUN" = true ]; then
		printf '[dry-run] install_progress_docker_pull_and_up %q\n' "$REPO_DIR"
		install_progress_register_compose_pull_topics "$REPO_DIR" 2>/dev/null || true
		install_progress_topic_done start-stack 2>/dev/null || true
	else
		cd "$REPO_DIR"
		if ! docker compose version >/dev/null 2>&1; then
			die "'docker compose' (v2) is required — sudo pacman -S --needed docker-compose"
		fi
		_docker_progress_lib="${REPO_DIR}/scripts/lib/install-progress-docker.sh"
		if [ ! -f "$_docker_progress_lib" ]; then
			_docker_progress_lib="${CONTINUUM_INSTALL_SCRIPT_DIR}/lib/install-progress-docker.sh"
		fi
		if [ ! -f "$_docker_progress_lib" ]; then
			_raw_base="https://raw.githubusercontent.com/ContinuumDAO/mpc-config/${MPC_CONFIG_REF:-main}"
			mkdir -p "${CONTINUUM_INSTALL_SCRIPT_DIR}/lib"
			_docker_progress_lib="${CONTINUUM_INSTALL_SCRIPT_DIR}/lib/install-progress-docker.sh"
			curl -fsSL "${_raw_base}/scripts/lib/install-progress-docker.sh" -o "$_docker_progress_lib"
		fi
		# shellcheck source=/dev/null
		. "$_docker_progress_lib"
		install_progress_docker_pull_and_up "$REPO_DIR"
		log "Running containers:"
		docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' 2>/dev/null || docker ps
	fi
else
	log "Skipping docker compose (--no-start)"
	install_progress_mark_done_if start-stack true
fi

install_progress_finish true

if [ -n "$PROVISION_NODE_IP" ]; then
	MPC_PASSWD_SSH="ssh root@${PROVISION_NODE_IP} 'passwd ${MPC_USER}'"
else
	MPC_PASSWD_SSH="ssh root@YOUR_HOST_IP 'passwd ${MPC_USER}'"
fi

cat <<EOF

==> Node provision complete
    Repo:     ${REPO_DIR}
    Ref:      ${MPC_CONFIG_REF}
    OS user:  ${MPC_USER} (password-protected sudo; no login password set yet)

Next steps:
  1. Set ${MPC_USER} login password (same root shell: passwd ${MPC_USER}), or over SSH:
       ${MPC_PASSWD_SSH}
  2. Attach your node at https://mpa.continuumdao.org
  3. Back up ${REPO_DIR}/bootstrap_key/ if PublicMgtKey was auto-generated
  4. Configure peer IPs and MQTT certs in the MPA Nodes page
  5. Admin VPN (optional): enable from the MPA VPN Panel; allow inbound UDP 51820 if the client shows 0 B received

EOF
