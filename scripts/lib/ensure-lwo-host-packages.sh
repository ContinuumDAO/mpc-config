#!/usr/bin/env bash
# Build and install continuum-lwo-server / continuum-lwo-client for VPN transport obfuscation.

LWO_INSTALL_DIR="${LWO_INSTALL_DIR:-/usr/local/bin}"
LWO_SRC_DIR="${LWO_SRC_DIR:-}"

_ensure_lwo_host_tools_present() {
	command -v continuum-lwo-server >/dev/null 2>&1 && command -v continuum-lwo-client >/dev/null 2>&1
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
		printf '[dry-run] build/install continuum-lwo\n' >&2
		return 0
	fi
	printf '==> Building continuum-lwo from mpc-config obfuscation/lwo\n' >&2
	if _ensure_lwo_build_and_install; then
		return 0
	fi
	printf 'warning: continuum-lwo not installed — VPN lwo obfuscation unavailable\n' >&2
	printf '  Install Rust (cargo) and run: cd obfuscation/lwo && cargo build --release\n' >&2
	return 1
}
