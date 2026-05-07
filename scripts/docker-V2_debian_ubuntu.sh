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

usage() {
	cat <<'EOF'
Usage:
  sudo ./scripts/docker-V2_debian_ubuntu.sh [--force-repo]

Options:
  --force-repo   Rewrite Docker apt sources using detected (or overridden) suite, then install the plugin.
  -h, --help     Show this help

Environment:
  DOCKER_V2_REPO=ubuntu|debian    Override detected repository family
  DOCKER_V2_CODENAME=<codename>   Override VERSION_CODENAME / UBUNTU_CODENAME (derivatives)
EOF
}

require_root() {
	if [[ "${EUID:-0}" -ne 0 ]]; then
		echo "error: run as root (e.g. sudo $0)" >&2
		exit 1
	fi
}

compose_v2_ok() {
	command -v docker &>/dev/null && docker compose version &>/dev/null
}

# Exit 0 if Compose v2 works (unless force_repo). Call before or after sudo depending on context.
exit_if_compose_v2_already_working() {
	local force_repo="$1"
	if [[ "$force_repo" -ne 0 ]]; then
		return 1
	fi
	if ! compose_v2_ok; then
		return 1
	fi
	echo "Docker Compose v2 is already installed and working — nothing to do."
	docker compose version
	exit 0
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
			return 0
		fi
	done
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

	# Unknown derivative: allow manual DOCKER_V2_REPO + DOCKER_V2_CODENAME (both required).
	if [[ -n "${DOCKER_V2_REPO:-}" && -n "${_DVC_CODENAME}" ]]; then
		case "${DOCKER_V2_REPO,,}" in
			ubuntu | debian)
				_DVC_REPO="${DOCKER_V2_REPO,,}"
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
		# Host was Debian/Ubuntu-family but mapping failed (e.g. missing codename).
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
	else
		tee /etc/apt/sources.list.d/docker.list >/dev/null <<EOF
deb [arch=${arch} signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${_DVC_CODENAME} stable
EOF
	fi
}

main() {
	local force_repo=0
	while [[ $# -gt 0 ]]; do
		case "$1" in
			-h | --help)
				usage
				exit 0
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

	require_debian_ubuntu_host
	exit_if_compose_v2_already_working "$force_repo"

	require_root
	exit_if_compose_v2_already_working "$force_repo"

	apt-get update
	if [[ "$force_repo" -eq 0 ]] && apt-get install -y docker-compose-plugin && compose_v2_ok; then
		echo "Installed docker-compose-plugin from existing apt sources."
		docker compose version
		exit 0
	fi

	detect_docker_apt_target
	echo "Docker apt target: repo=${_DVC_REPO} codename=${_DVC_CODENAME}"

	if docker_apt_configured && [[ "$force_repo" -eq 0 ]]; then
		echo "Docker apt repository already present; installing docker-compose-plugin…"
		if ! apt-get install -y docker-compose-plugin; then
			echo "error: apt install docker-compose-plugin failed. Check: apt-cache policy docker-compose-plugin" >&2
			exit 1
		fi
	else
		if [[ "$force_repo" -eq 1 ]] && docker_apt_configured; then
			echo "Rewriting Docker apt entries (--force-repo)…"
		fi
		echo "Adding Docker's official apt repository and installing docker-compose-plugin…"
		add_docker_apt_repo
		apt-get update
		if ! apt-get install -y docker-compose-plugin; then
			echo "error: apt install docker-compose-plugin failed after adding Docker apt repository." >&2
			echo "  Wrong suite? Try: DOCKER_V2_CODENAME=<jammy|bookworm|…> DOCKER_V2_REPO=<ubuntu|debian> $0" >&2
			exit 1
		fi
	fi

	if ! compose_v2_ok; then
		echo "error: docker compose still not available after install." >&2
		echo "  Try: apt-cache policy docker-compose-plugin" >&2
		exit 1
	fi

	echo "Compose v2 is ready:"
	docker compose version
}

main "$@"
