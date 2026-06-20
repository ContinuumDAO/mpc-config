#!/usr/bin/env bash
# Optional udp2raw binary for WireGuard fake-TCP transport obfuscation.

UDP2RAW_VERSION="${UDP2RAW_VERSION:-20230206.0}"
UDP2RAW_INSTALL_DIR="${UDP2RAW_INSTALL_DIR:-/usr/local/bin}"

_ensure_udp2raw_host_tool_present() {
	command -v udp2raw >/dev/null 2>&1
}

_ensure_udp2raw_cleanup_tmpdir() {
	local dir="${1:-}"
	if [[ -n "$dir" && -d "$dir" ]]; then
		rm -rf "$dir"
	fi
}

_ensure_udp2raw_install_static_binary() {
	local arch asset url tmpdir="" bin_name=""
	if ! command -v curl >/dev/null 2>&1; then
		return 1
	fi
	arch="$(uname -m)"
	case "$arch" in
	x86_64) bin_name="udp2raw_amd64" ;;
	aarch64 | arm64) bin_name="udp2raw_arm" ;;
	i686 | i386 | x86) bin_name="udp2raw_x86" ;;
	*) return 1 ;;
	esac
	asset="udp2raw_binaries.tar.gz"
	url="https://github.com/wangyu-/udp2raw/releases/download/${UDP2RAW_VERSION}/${asset}"
	tmpdir="$(mktemp -d)"
	if ! curl -fsSL "$url" -o "${tmpdir}/archive.tar.gz"; then
		_ensure_udp2raw_cleanup_tmpdir "$tmpdir"
		return 1
	fi
	if ! tar -xzf "${tmpdir}/archive.tar.gz" -C "$tmpdir"; then
		_ensure_udp2raw_cleanup_tmpdir "$tmpdir"
		return 1
	fi
	if [[ ! -f "${tmpdir}/${bin_name}" ]]; then
		_ensure_udp2raw_cleanup_tmpdir "$tmpdir"
		return 1
	fi
	if ! install -m 0755 "${tmpdir}/${bin_name}" "${UDP2RAW_INSTALL_DIR}/udp2raw"; then
		_ensure_udp2raw_cleanup_tmpdir "$tmpdir"
		return 1
	fi
	_ensure_udp2raw_cleanup_tmpdir "$tmpdir"
	_ensure_udp2raw_host_tool_present
}

ensure_udp2raw_host_packages() {
	local dry_run="${CONTINUUM_INSTALL_DRY_RUN:-false}"
	if _ensure_udp2raw_host_tool_present; then
		return 0
	fi
	if [ "$dry_run" = true ]; then
		printf '[dry-run] install udp2raw\n' >&2
		return 0
	fi
	printf '==> Downloading udp2raw static binary (%s)\n' "$UDP2RAW_VERSION" >&2
	if _ensure_udp2raw_install_static_binary; then
		return 0
	fi
	printf 'warning: udp2raw not installed — VPN udp2raw obfuscation unavailable\n' >&2
	printf '  Install manually from https://github.com/wangyu-/udp2raw/releases\n' >&2
	return 1
}
