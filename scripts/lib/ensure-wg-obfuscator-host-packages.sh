#!/usr/bin/env bash
# Optional wg-obfuscator binary for WireGuard transport obfuscation.
# Sourced by install scripts — warn-only at call sites; never abort node install.

WG_OBFUSCATOR_VERSION="${WG_OBFUSCATOR_VERSION:-v1.5}"
WG_OBFUSCATOR_INSTALL_DIR="${WG_OBFUSCATOR_INSTALL_DIR:-/usr/local/bin}"

_ensure_wg_obfuscator_host_tool_present() {
	command -v wg-obfuscator >/dev/null 2>&1
}

_ensure_wg_obfuscator_cleanup_tmpdir() {
	local dir="${1:-}"
	if [[ -n "$dir" && -d "$dir" ]]; then
		rm -rf "$dir"
	fi
}

_ensure_wg_obfuscator_install_static_binary() {
	local arch os asset url tmpdir=""
	if ! command -v curl >/dev/null 2>&1; then
		return 1
	fi
	arch="$(uname -m)"
	case "$arch" in
	x86_64) arch="x64" ;;
	aarch64 | arm64) arch="arm64" ;;
	*) return 1 ;;
	esac
	os="$(uname -s | tr '[:upper:]' '[:lower:]')"
	case "$os" in
	linux) asset="wg-obfuscator-${WG_OBFUSCATOR_VERSION}-linux-${arch}.tar.gz" ;;
	darwin)
		if [[ "$arch" == "arm64" ]]; then
			asset="wg-obfuscator-${WG_OBFUSCATOR_VERSION}-macos-arm64.zip"
		else
			asset="wg-obfuscator-${WG_OBFUSCATOR_VERSION}-macos-x64.zip"
		fi
		;;
	*) return 1 ;;
	esac
	url="https://github.com/ClusterM/wg-obfuscator/releases/download/${WG_OBFUSCATOR_VERSION}/${asset}"
	tmpdir="$(mktemp -d)"
	if ! curl -fsSL "$url" -o "${tmpdir}/archive"; then
		_ensure_wg_obfuscator_cleanup_tmpdir "$tmpdir"
		return 1
	fi
	case "$asset" in
	*.tar.gz)
		if ! tar -xzf "${tmpdir}/archive" -C "$tmpdir"; then
			_ensure_wg_obfuscator_cleanup_tmpdir "$tmpdir"
			return 1
		fi
		;;
	*.zip)
		if ! command -v unzip >/dev/null 2>&1; then
			_ensure_wg_obfuscator_cleanup_tmpdir "$tmpdir"
			return 1
		fi
		if ! unzip -q "${tmpdir}/archive" -d "$tmpdir"; then
			_ensure_wg_obfuscator_cleanup_tmpdir "$tmpdir"
			return 1
		fi
		;;
	esac
	local bin=""
	if [[ -f "${tmpdir}/wg-obfuscator/wg-obfuscator" && -x "${tmpdir}/wg-obfuscator/wg-obfuscator" ]]; then
		bin="${tmpdir}/wg-obfuscator/wg-obfuscator"
	elif [[ -f "${tmpdir}/wg-obfuscator" && -x "${tmpdir}/wg-obfuscator" ]]; then
		bin="${tmpdir}/wg-obfuscator"
	elif [[ -x "${tmpdir}/wg-obfuscator-${WG_OBFUSCATOR_VERSION}/wg-obfuscator" ]]; then
		bin="${tmpdir}/wg-obfuscator-${WG_OBFUSCATOR_VERSION}/wg-obfuscator"
	else
		bin="$(find "$tmpdir" -type f -name 'wg-obfuscator' -perm -111 2>/dev/null | head -n1 || true)"
	fi
	if [[ -z "$bin" || ! -x "$bin" ]]; then
		_ensure_wg_obfuscator_cleanup_tmpdir "$tmpdir"
		return 1
	fi
	if ! install -m 0755 "$bin" "${WG_OBFUSCATOR_INSTALL_DIR}/wg-obfuscator"; then
		_ensure_wg_obfuscator_cleanup_tmpdir "$tmpdir"
		return 1
	fi
	_ensure_wg_obfuscator_cleanup_tmpdir "$tmpdir"
	_ensure_wg_obfuscator_host_tool_present
}

ensure_wg_obfuscator_host_packages() {
	local dry_run="${CONTINUUM_INSTALL_DRY_RUN:-false}"
	if _ensure_wg_obfuscator_host_tool_present; then
		return 0
	fi
	if [ "$dry_run" = true ]; then
		printf '[dry-run] install wg-obfuscator\n' >&2
		return 0
	fi
	printf '==> Downloading wg-obfuscator static binary (%s)\n' "$WG_OBFUSCATOR_VERSION" >&2
	if _ensure_wg_obfuscator_install_static_binary; then
		return 0
	fi
	printf 'warning: wg-obfuscator not installed — VPN wg_obfuscator obfuscation unavailable\n' >&2
	printf '  Install manually from https://github.com/ClusterM/wg-obfuscator/releases\n' >&2
	return 1
}
