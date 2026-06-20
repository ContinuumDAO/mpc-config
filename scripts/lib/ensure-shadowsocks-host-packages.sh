#!/usr/bin/env bash
# Optional shadowsocks-rust (ssserver, sslocal) for WireGuard transport obfuscation.
# Sourced by install scripts — warn-only at call sites; never abort node install.

SHADOWSOCKS_RUST_VERSION="${SHADOWSOCKS_RUST_VERSION:-v1.24.0}"
SHADOWSOCKS_RUST_INSTALL_DIR="${SHADOWSOCKS_RUST_INSTALL_DIR:-/usr/local/bin}"

_ensure_shadowsocks_host_tools_present() {
	command -v ssserver >/dev/null 2>&1 && command -v sslocal >/dev/null 2>&1
}

_ensure_shadowsocks_install_static_binaries() {
	local arch os base url tmpdir
	if ! command -v curl >/dev/null 2>&1; then
		return 1
	fi
	arch="$(uname -m)"
	case "$arch" in
	x86_64) arch="x86_64" ;;
	aarch64 | arm64) arch="aarch64" ;;
	*) return 1 ;;
	esac
	os="$(uname -s | tr '[:upper:]' '[:lower:]')"
	case "$os" in
	linux) os="unknown-linux-musl" ;;
	darwin) os="apple-darwin" ;;
	*) return 1 ;;
	esac
	base="https://github.com/shadowsocks/shadowsocks-rust/releases/download/${SHADOWSOCKS_RUST_VERSION}"
	url="${base}/shadowsocks-${SHADOWSOCKS_RUST_VERSION}.${arch}-${os}.tar.xz"
	tmpdir="$(mktemp -d)"
	trap 'rm -rf "$tmpdir"' RETURN
	if ! curl -fsSL "$url" -o "${tmpdir}/ss.tar.xz"; then
		return 1
	fi
	if ! tar -xJf "${tmpdir}/ss.tar.xz" -C "$tmpdir"; then
		return 1
	fi
	install -m 0755 "${tmpdir}/ssserver" "${SHADOWSOCKS_RUST_INSTALL_DIR}/ssserver"
	install -m 0755 "${tmpdir}/sslocal" "${SHADOWSOCKS_RUST_INSTALL_DIR}/sslocal"
	_ensure_shadowsocks_host_tools_present
}

ensure_shadowsocks_host_packages() {
	local dry_run="${CONTINUUM_INSTALL_DRY_RUN:-false}"
	if _ensure_shadowsocks_host_tools_present; then
		return 0
	fi
	if [ "$dry_run" = true ]; then
		printf '[dry-run] install shadowsocks-rust (ssserver, sslocal)\n' >&2
		return 0
	fi
	if command -v apt-get >/dev/null 2>&1; then
		printf '==> Trying apt install shadowsocks-rust (optional VPN obfuscation)\n' >&2
		if apt-get update -qq && apt-get install -y shadowsocks-rust 2>/dev/null; then
			_ensure_shadowsocks_host_tools_present && return 0
		fi
	fi
	if command -v brew >/dev/null 2>&1; then
		printf '==> Trying brew install shadowsocks-rust (optional VPN obfuscation)\n' >&2
		if brew install shadowsocks-rust 2>/dev/null; then
			_ensure_shadowsocks_host_tools_present && return 0
		fi
	fi
	printf '==> Downloading shadowsocks-rust static binaries (%s)\n' "$SHADOWSOCKS_RUST_VERSION" >&2
	if _ensure_shadowsocks_install_static_binaries; then
		return 0
	fi
	printf 'warning: shadowsocks-rust (ssserver, sslocal) not installed — VPN obfuscation unavailable\n' >&2
	return 1
}
