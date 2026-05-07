#!/usr/bin/env bash
# Install Docker Compose v2 (docker compose plugin) on Debian/Ubuntu and derivatives.
#
# - If the package is already available (Docker CE repo or distro extras), installs docker-compose-plugin only.
# - Otherwise adds Docker's official apt repository (Ubuntu one-line list or Debian deb822 sources) and installs.
#
# Run as root when you need to install packages:
#   sudo ./scripts/docker-V2_debian_ubuntu.sh
# If Docker Compose v2 already works for your user, the script exits 0 without sudo (unless --force-repo).
#
# Overrides (optional):
#   DOCKER_V2_REPO=ubuntu|debian   Force apt suite (default: auto from /etc/os-release)
#   DOCKER_V2_CODENAME=noble       Force suite codename (e.g. jammy, bookworm) when detection is wrong
#
# See: internal/DOCKER_COMPOSE_V2_UPGRADE.md
#
set -euo pipefail

# 0=quiet, 1=extra progress and diagnostics (also: DOCKER_V2_VERBOSE=1).
DVC_VERBOSE=0

usage() {
	cat <<'EOF'
Usage:
  sudo ./scripts/docker-V2_debian_ubuntu.sh [options]

Options:
  --force-repo   Rewrite Docker apt sources using detected (or overridden) suite, then install plugin.
  -v, --verbose  Print each step and full diagnostics when something fails (or when the plugin installs but docker compose does not work).
  -h, --help     Show this help

Environment:
  DOCKER_V2_REPO=ubuntu|debian     Override detected repository family
  DOCKER_V2_CODENAME=<codename>    Override VERSION_CODENAME / UBUNTU_CODENAME (derivatives)
  DOCKER_V2_VERBOSE=1              Same as --verbose
EOF
}

vlog() {
	[[ "$DVC_VERBOSE" -eq 1 ]] || return 0
	printf '[docker-V2] %s\n' "$*" >&2
}

require_root() {
	if [[ "${EUID:-0}" -ne 0 ]]; then
		echo "error: run as root (e.g. sudo $0)" >&2
		exit 1
	fi
}

compose_v2_ok() {
	command -v docker &>/dev/null || return 1
	docker compose version &>/dev/null
}

# Explain why docker compose might fail (stderr). Safe to call anytime.
diagnose_compose_v2() {
	echo "=== docker / compose diagnostic ===" >&2
	if command -v docker &>/dev/null; then
		command -v docker >&2
		docker --version >&2 || true
	else
		echo "docker: not found in PATH (install docker.io or Docker CE first)." >&2
	fi
	echo "--- docker compose version (expected: v2 plugin) ---" >&2
	docker compose version >&2 || true
	echo "--- legacy hyphenated binary (not updated by this script) ---" >&2
	if command -v docker-compose &>/dev/null; then
		command -v docker-compose >&2
		docker-compose --version >&2 || true
	else
		echo "docker-compose: not in PATH" >&2
	fi
	echo "--- CLI plugin directories (compose plugin should appear as 'docker-compose') ---" >&2
	local d
	for d in /usr/local/lib/docker/cli-plugins /usr/libexec/docker/cli-plugins /usr/lib/docker/cli-plugins "${DOCKER_CONFIG:-$HOME/.docker}/cli-plugins"; do
		if [[ -d "$d" ]]; then
			echo "  $d" >&2
			ls -la "$d" 2>/dev/null | sed 's/^/    /' >&2 || true
		fi
	done
	echo "--- apt: docker-compose-plugin ---" >&2
	apt-cache policy docker-compose-plugin 2>/dev/null | head -25 >&2 || echo "(apt-cache unavailable)" >&2
	echo "--- dpkg: docker-compose-plugin ---" >&2
	dpkg -l docker-compose-plugin 2>/dev/null >&2 || true
	echo "=== end diagnostic ===" >&2
}

# Exit 0 if Compose v2 works (unless force_repo). Call before or after sudo depending on context.
exit_if_compose_v2_already_working() {
	local force_repo="$1"
	if [[ "$force_repo" -ne 0 ]]; then
		vlog "--force-repo: skipping early exit even if compose v2 already works."
		return 1
	fi
	if compose_v2_ok; then
		echo "Docker Compose v2 is already installed and working — nothing to do."
		docker compose version
		exit 0
	fi
	vlog "'docker compose' not working yet (will try apt install / add Docker repo)."
	[[ "$DVC_VERBOSE" -eq 1 ]] && diagnose_compose_v2
	return 1
}

# Clear error and exit if this is not a Debian/Ubuntu-family host with apt (no root required).
require_debian_ubuntu_host() {
	if ! command -v apt-get &>/dev/null; then
		cat >&2 <<'EOF'
This script only installs Docker Compose v2 on Debian and Ubuntu (and typical derivatives) using apt.

  No apt-get found on this system. For Fedora, RHEL, Arch, Alpine, etc., use Docker’s Compose install guide:
  https://docs.docker.com/compose/install/linux/
EOF
		exit 2
	fi

	[[ -r /etc/os-release ]] || {
		echo "error: cannot read /etc/os-release — cannot verify distribution." >&2
		exit 2
	}
	# shellcheck source=/dev/null
	. /etc/os-release

	local id="${ID:-}"
	local id_like="${ID_LIKE:-}"
	local pretty="${PRETTY_NAME:-unknown}"
	local supported=0

	case "$id" in
		debian | ubuntu | linuxmint) supported=1 ;;
	esac
	if [[ "$supported" -eq 0 ]]; then
		if [[ "$id_like" == *"ubuntu"* || "$id_like" == *"debian"* ]]; then
			supported=1
		fi
	fi

	vlog "Host check: PRETTY_NAME=$pretty ID=$id ID_LIKE=$id_like VERSION_CODENAME=${VERSION_CODENAME:-}"

	if [[ "$supported" -eq 0 ]]; then
		cat >&2 <<EOF
This script only supports Ubuntu, Debian, and their common derivatives (apt-based).

  Detected system: ${pretty}
  ID=${id:-unknown}  ID_LIKE=${id_like:-<empty>}

On other distributions, install the Compose v2 plugin using Docker’s documentation (or your distro’s packages):
  https://docs.docker.com/compose/install/linux/
  Local reference: internal/DOCKER_COMPOSE_V2_UPGRADE.md (manual plugin binary, §2.D)
EOF
		exit 2
	fi
}

docker_apt_configured() {
	local f
	for f in /etc/apt/sources.list.d/docker.list /etc/apt/sources.list.d/docker.sources; do
		if [[ -f "$f" ]] && grep -q 'download\.docker\.com' "$f" 2>/dev/null; then
			vlog "Docker apt file present: $f"
			return 0
		fi
	done
	vlog "No docker.list/docker.sources pointing at download.docker.com found."
	return 1
}

# Sets globals: _DVC_REPO (ubuntu|debian), _DVC_CODENAME
detect_docker_apt_target() {
	[[ -r /etc/os-release ]] || {
		echo "error: cannot read /etc/os-release" >&2
		exit 1
	}
	# shellcheck source=/dev/null
	. /etc/os-release

	local id="${ID:-}"
	local id_like="${ID_LIKE:-}"
	_DVC_REPO=""
	_DVC_CODENAME="${DOCKER_V2_CODENAME:-}"

	vlog "Detection: ID=$id ID_LIKE=$id_like DOCKER_V2_REPO=${DOCKER_V2_REPO:-<unset>} DOCKER_V2_CODENAME=${DOCKER_V2_CODENAME:-<unset>}"

	# Unknown derivative: allow manual DOCKER_V2_REPO + DOCKER_V2_CODENAME (both required).
	if [[ -n "${DOCKER_V2_REPO:-}" && -n "${_DVC_CODENAME}" ]]; then
		case "${DOCKER_V2_REPO,,}" in
			ubuntu | debian)
				_DVC_REPO="${DOCKER_V2_REPO,,}"
				vlog "Using explicit repo+codename override → ${_DVC_REPO} ${_DVC_CODENAME}"
				return 0
				;;
			*)
				echo "error: DOCKER_V2_REPO must be ubuntu or debian (got: ${DOCKER_V2_REPO})" >&2
				exit 1
				;;
		esac
	fi

	if [[ -n "${DOCKER_V2_REPO:-}" ]]; then
		case "${DOCKER_V2_REPO,,}" in
			ubuntu | debian) _DVC_REPO="${DOCKER_V2_REPO,,}" ;;
			*)
				echo "error: DOCKER_V2_REPO must be ubuntu or debian (got: ${DOCKER_V2_REPO})" >&2
				exit 1
				;;
		esac
	fi

	if [[ "$id" == "debian" ]]; then
		[[ -n "$_DVC_REPO" ]] || _DVC_REPO="debian"
		[[ -n "$_DVC_CODENAME" ]] || _DVC_CODENAME="${VERSION_CODENAME:-}"
	elif [[ "$id" == "ubuntu" ]]; then
		[[ -n "$_DVC_REPO" ]] || _DVC_REPO="ubuntu"
		[[ -n "$_DVC_CODENAME" ]] || _DVC_CODENAME="${VERSION_CODENAME:-}"
	elif [[ "$id" == "linuxmint" ]]; then
		[[ -n "$_DVC_REPO" ]] || _DVC_REPO="ubuntu"
		[[ -n "$_DVC_CODENAME" ]] || _DVC_CODENAME="${UBUNTU_CODENAME:-${VERSION_CODENAME:-}}"
	elif [[ "$id_like" == *"ubuntu"* ]]; then
		[[ -n "$_DVC_REPO" ]] || _DVC_REPO="ubuntu"
		[[ -n "$_DVC_CODENAME" ]] || _DVC_CODENAME="${UBUNTU_CODENAME:-${VERSION_CODENAME:-}}"
	elif [[ "$id_like" == *"debian"* ]]; then
		[[ -n "$_DVC_REPO" ]] || _DVC_REPO="debian"
		[[ -n "$_DVC_CODENAME" ]] || _DVC_CODENAME="${VERSION_CODENAME:-}"
	else
		cat >&2 <<EOF
error: could not map this Debian/Ubuntu system to a Docker apt suite.

  ID=${id:-unknown}  ID_LIKE=${id_like:-}  VERSION_CODENAME=${VERSION_CODENAME:-<empty>}

Set both overrides, for example:
  DOCKER_V2_REPO=ubuntu|debian  DOCKER_V2_CODENAME=<jammy|bookworm|…> sudo $0
EOF
		exit 1
	fi

	if [[ -z "$_DVC_CODENAME" ]]; then
		echo "error: could not detect apt suite codename. Set DOCKER_V2_CODENAME." >&2
		exit 1
	fi
}

add_docker_apt_repo() {
	local arch
	arch="$(dpkg --print-architecture)"
	vlog "Adding Docker apt repo: family=${_DVC_REPO} codename=${_DVC_CODENAME} arch=${arch}"

	apt-get install -y ca-certificates curl
	install -m 0755 -d /etc/apt/keyrings
	curl -fsSL "https://download.docker.com/linux/${_DVC_REPO}/gpg" -o /etc/apt/keyrings/docker.asc
	chmod a+r /etc/apt/keyrings/docker.asc

	if [[ "$_DVC_REPO" == "debian" ]]; then
		tee /etc/apt/sources.list.d/docker.sources >/dev/null <<EOF
Types: deb
URIs: https://download.docker.com/linux/debian
Suites: ${_DVC_CODENAME}
Components: stable
Architectures: ${arch}
Signed-By: /etc/apt/keyrings/docker.asc
EOF
		vlog "Wrote /etc/apt/sources.list.d/docker.sources"
	else
		tee /etc/apt/sources.list.d/docker.list >/dev/null <<EOF
deb [arch=${arch} signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${_DVC_CODENAME} stable
EOF
		vlog "Wrote /etc/apt/sources.list.d/docker.list"
	fi
}

main() {
	local force_repo=0
	case "${DOCKER_V2_VERBOSE:-}" in
		1 | yes | true | TRUE) DVC_VERBOSE=1 ;;
	esac

	while [[ $# -gt 0 ]]; do
		case "$1" in
			-h | --help)
				usage
				exit 0
				;;
			-v | --verbose)
				DVC_VERBOSE=1
				shift
				;;
			--force-repo)
				force_repo=1
				shift
				;;
			*)
				echo "error: unknown option: $1" >&2
				usage >&2
				exit 1
				;;
		esac
	done

	vlog "verbose mode on"

	require_debian_ubuntu_host
	set +e
	exit_if_compose_v2_already_working "$force_repo"
	set -e

	require_root
	set +e
	exit_if_compose_v2_already_working "$force_repo"
	set -e

	vlog "Running apt-get update (existing sources)…"
	apt-get update

	vlog "Trying: apt-get install -y docker-compose-plugin (no new repo if already indexed)…"
	if [[ "$force_repo" -eq 0 ]]; then
		if apt-get install -y docker-compose-plugin; then
			if compose_v2_ok; then
				echo "Installed docker-compose-plugin from existing apt sources."
				docker compose version
				vlog "Note: /usr/bin/docker-compose (v1) may still exist; mpc-config uses 'docker compose' (v2)."
				exit 0
			fi
			echo "warning: docker-compose-plugin installed but 'docker compose' still fails." >&2
			[[ "$DVC_VERBOSE" -eq 1 ]] && diagnose_compose_v2
		else
			vlog "apt-get install docker-compose-plugin failed (package missing or error); will add Docker repo if needed."
			[[ "$DVC_VERBOSE" -eq 1 ]] && apt-cache policy docker-compose-plugin 2>/dev/null | head -20 >&2 || true
		fi
	else
		vlog "--force-repo: skipping direct install attempt before repo rewrite."
	fi

	detect_docker_apt_target
	echo "Docker apt target: repo=${_DVC_REPO} codename=${_DVC_CODENAME}"

	if docker_apt_configured && [[ "$force_repo" -eq 0 ]]; then
		echo "Docker apt repository already present; installing docker-compose-plugin…"
		if ! apt-get install -y docker-compose-plugin; then
			echo "error: apt install docker-compose-plugin failed." >&2
			[[ "$DVC_VERBOSE" -eq 1 ]] && diagnose_compose_v2
			exit 1
		fi
	else
		if [[ "$force_repo" -eq 1 ]] && docker_apt_configured; then
			echo "Rewriting Docker apt entries (--force-repo)…"
		fi
		echo "Adding Docker's official apt repository and installing docker-compose-plugin…"
		add_docker_apt_repo
		vlog "apt-get update (after adding Docker repo)…"
		apt-get update
		if ! apt-get install -y docker-compose-plugin; then
			echo "error: apt install docker-compose-plugin failed after adding Docker apt repository." >&2
			echo "  Wrong suite? Try: DOCKER_V2_CODENAME=<jammy|bookworm|…> DOCKER_V2_REPO=<ubuntu|debian> $0" >&2
			[[ "$DVC_VERBOSE" -eq 1 ]] && diagnose_compose_v2
			exit 1
		fi
	fi

	if ! compose_v2_ok; then
		echo "error: docker compose still not available after install." >&2
		echo "  This script installs the v2 *plugin* ('docker compose'). It does not replace /usr/bin/docker-compose (v1)." >&2
		[[ "$DVC_VERBOSE" -eq 0 ]] && echo "  Re-run with: sudo $0 --verbose" >&2
		[[ "$DVC_VERBOSE" -eq 1 ]] && diagnose_compose_v2
		exit 1
	fi

	echo "Compose v2 is ready:"
	docker compose version
	vlog "Success. Use 'docker compose' (space). Legacy 'docker-compose' (hyphen) may still be v1."
}

main "$@"
