#!/usr/bin/env bash
# Install continuum-lwo-server / continuum-lwo-client for VPN transport obfuscation.
# On Debian/Ubuntu VPS hosts, installs vendored prebuilt binaries from mpc-config.
# On other platforms, falls back to a local cargo build when sources and cargo are available.

LWO_INSTALL_DIR="${LWO_INSTALL_DIR:-/usr/local/bin}"
LWO_SRC_DIR="${LWO_SRC_DIR:-}"

_ensure_lwo_host_tools_present() {
	command -v continuum-lwo-server >/dev/null 2>&1 && command -v continuum-lwo-client >/dev/null 2>&1
}

_ensure_lwo_host_is_debian_ubuntu() {
	if ! command -v apt-get >/dev/null 2>&1; then
		return 1
	fi
	if [[ ! -r /etc/os-release ]]; then
		return 1
	fi
	# shellcheck source=/dev/null
	. /etc/os-release
	local id="${ID:-}" id_like="${ID_LIKE:-}"
	case "$id" in
	debian | ubuntu | linuxmint) return 0 ;;
	esac
	if [[ "$id_like" == *"ubuntu"* || "$id_like" == *"debian"* ]]; then
		return 0
	fi
	return 1
}

_ensure_lwo_repo_root() {
	local script_dir repo_root
	if [[ -n "$LWO_SRC_DIR" && -d "$LWO_SRC_DIR" ]]; then
		repo_root="$(cd "${LWO_SRC_DIR}/../.." && pwd)"
		if [[ -d "${repo_root}/obfuscation/lwo/prebuilt/debian-ubuntu" ]]; then
			printf '%s' "$repo_root"
			return 0
		fi
	fi
	script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
	repo_root="$(cd "${script_dir}/../.." && pwd)"
	if [[ -d "${repo_root}/obfuscation/lwo/prebuilt/debian-ubuntu" ]]; then
		printf '%s' "$repo_root"
		return 0
	fi
	return 1
}

_ensure_lwo_prebuilt_arch() {
	local arch
	arch="$(uname -m)"
	case "$arch" in
	x86_64 | amd64) printf '%s' "x86_64" ;;
	aarch64 | arm64) printf '%s' "aarch64" ;;
	*) return 1 ;;
	esac
}

_ensure_lwo_install_prebuilt() {
	local repo_root arch prebuilt_dir server_bin client_bin
	repo_root="$(_ensure_lwo_repo_root)" || return 1
	arch="$(_ensure_lwo_prebuilt_arch)" || return 1
	prebuilt_dir="${repo_root}/obfuscation/lwo/prebuilt/debian-ubuntu/${arch}"
	server_bin="${prebuilt_dir}/continuum-lwo-server"
	client_bin="${prebuilt_dir}/continuum-lwo-client"
	if [[ ! -x "$server_bin" || ! -x "$client_bin" ]]; then
		return 1
	fi
	install -m 0755 "$server_bin" "${LWO_INSTALL_DIR}/continuum-lwo-server"
	install -m 0755 "$client_bin" "${LWO_INSTALL_DIR}/continuum-lwo-client"
	_ensure_lwo_host_tools_present
}

_ensure_lwo_repo_dir() {
	if [[ -n "$LWO_SRC_DIR" && -d "$LWO_SRC_DIR" ]]; then
		printf '%s' "$LWO_SRC_DIR"
		return 0
	fi
	local script_dir repo_root
	script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
	repo_root="$(cd "${script_dir}/../.." && pwd)"
	if [[ -f "${repo_root}/obfuscation/lwo/Cargo.toml" ]]; then
		printf '%s/obfuscation/lwo' "$repo_root"
		return 0
	fi
	return 1
}

_ensure_lwo_build_and_install() {
	local lwo_dir server_bin client_bin
	if ! command -v cargo >/dev/null 2>&1; then
		return 1
	fi
	lwo_dir="$(_ensure_lwo_repo_dir)" || return 1
	if ! (cd "$lwo_dir" && cargo build --release); then
		return 1
	fi
	server_bin="${lwo_dir}/target/release/continuum-lwo-server"
	client_bin="${lwo_dir}/target/release/continuum-lwo-client"
	if [[ ! -x "$server_bin" || ! -x "$client_bin" ]]; then
		return 1
	fi
	install -m 0755 "$server_bin" "${LWO_INSTALL_DIR}/continuum-lwo-server"
	install -m 0755 "$client_bin" "${LWO_INSTALL_DIR}/continuum-lwo-client"
	_ensure_lwo_host_tools_present
}

ensure_lwo_host_packages() {
	local dry_run="${CONTINUUM_INSTALL_DRY_RUN:-false}"
	if _ensure_lwo_host_tools_present; then
		return 0
	fi
	if [ "$dry_run" = true ]; then
		printf '[dry-run] install continuum-lwo\n' >&2
		return 0
	fi
	if _ensure_lwo_host_is_debian_ubuntu; then
		printf '==> Installing continuum-lwo prebuilt binaries (Debian/Ubuntu)\n' >&2
		if _ensure_lwo_install_prebuilt; then
			return 0
		fi
		printf 'warning: continuum-lwo prebuilt binaries missing for this architecture\n' >&2
	fi
	if _ensure_lwo_build_and_install; then
		return 0
	fi
	printf 'warning: continuum-lwo not installed — VPN lwo obfuscation unavailable\n' >&2
	if _ensure_lwo_host_is_debian_ubuntu; then
		printf '  Re-run install-mpc-auth-docker-systemd.sh after pulling mpc-config with prebuilt binaries\n' >&2
	else
		printf '  Prebuilt binaries ship for Debian/Ubuntu only; build from obfuscation/lwo with cargo elsewhere\n' >&2
	fi
	return 1
}
