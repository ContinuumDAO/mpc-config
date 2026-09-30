#!/usr/bin/env bash
# Optional Blocky and dnsmasq for VPN DNS ad blocking.
# Sourced by install scripts — warn-only at call sites; never abort node install.

BLOCKY_VERSION="${BLOCKY_VERSION:-v0.35.0}"
BLOCKY_INSTALL_DIR="${BLOCKY_INSTALL_DIR:-/usr/local/bin}"

_ensure_blocky_present() {
	command -v blocky >/dev/null 2>&1
}

_ensure_dnsmasq_present() {
	command -v dnsmasq >/dev/null 2>&1
}

_ensure_blocky_cleanup_tmpdir() {
	local dir="${1:-}"
	if [[ -n "$dir" && -d "$dir" ]]; then
		rm -rf "$dir"
	fi
}

_ensure_blocky_disable_distro_dnsmasq() {
	if ! command -v systemctl >/dev/null 2>&1; then
		return 0
	fi
	systemctl disable --now dnsmasq.service >/dev/null 2>&1 || true
	systemctl mask dnsmasq.service >/dev/null 2>&1 || true
}

_ensure_blocky_install_binary() {
	local arch asset url tmpdir="" bin=""
	if ! command -v curl >/dev/null 2>&1; then
		return 1
	fi
	case "$(uname -m)" in
	x86_64) arch="x86_64" ;;
	aarch64 | arm64) arch="arm64" ;;
	*) return 1 ;;
	esac
	case "$(uname -s)" in
	Linux) asset="blocky_${BLOCKY_VERSION}_Linux_${arch}.tar.gz" ;;
	*) return 1 ;;
	esac
	url="https://github.com/0xERR0R/blocky/releases/download/${BLOCKY_VERSION}/${asset}"
	tmpdir="$(mktemp -d)"
	if ! curl -fsSL "$url" -o "${tmpdir}/blocky.tar.gz"; then
		_ensure_blocky_cleanup_tmpdir "$tmpdir"
		return 1
	fi
	if ! tar -xzf "${tmpdir}/blocky.tar.gz" -C "$tmpdir"; then
		_ensure_blocky_cleanup_tmpdir "$tmpdir"
		return 1
	fi
	if [[ -x "${tmpdir}/blocky" ]]; then
		bin="${tmpdir}/blocky"
	else
		bin="$(find "$tmpdir" -type f -name blocky -perm -111 2>/dev/null | head -n1 || true)"
	fi
	if [[ -z "$bin" || ! -x "$bin" ]]; then
		_ensure_blocky_cleanup_tmpdir "$tmpdir"
		return 1
	fi
	if ! install -m 0755 "$bin" "${BLOCKY_INSTALL_DIR}/blocky"; then
		_ensure_blocky_cleanup_tmpdir "$tmpdir"
		return 1
	fi
	_ensure_blocky_cleanup_tmpdir "$tmpdir"
	_ensure_blocky_present
}

_ensure_dnsmasq_package() {
	if _ensure_dnsmasq_present; then
		_ensure_blocky_disable_distro_dnsmasq
		return 0
	fi
	if command -v apt-get >/dev/null 2>&1; then
		apt-get update -qq && apt-get install -y dnsmasq && _ensure_dnsmasq_present && _ensure_blocky_disable_distro_dnsmasq && return 0
	fi
	if command -v dnf >/dev/null 2>&1; then
		dnf install -y dnsmasq && _ensure_dnsmasq_present && _ensure_blocky_disable_distro_dnsmasq && return 0
	fi
	if command -v pacman >/dev/null 2>&1; then
		pacman -Sy --noconfirm dnsmasq && _ensure_dnsmasq_present && _ensure_blocky_disable_distro_dnsmasq && return 0
	fi
	if command -v zypper >/dev/null 2>&1; then
		zypper --non-interactive install dnsmasq && _ensure_dnsmasq_present && _ensure_blocky_disable_distro_dnsmasq && return 0
	fi
	return 1
}

ensure_vpn_dns_filter_packages() {
	local dry_run="${CONTINUUM_INSTALL_DRY_RUN:-false}"
	local ok=0
	if _ensure_blocky_present && _ensure_dnsmasq_present; then
		_ensure_blocky_disable_distro_dnsmasq
		return 0
	fi
	if [[ "$dry_run" == true ]]; then
		printf '[dry-run] install blocky and dnsmasq\n' >&2
		return 0
	fi
	if ! _ensure_blocky_present; then
		printf '==> Downloading blocky %s\n' "$BLOCKY_VERSION" >&2
		_ensure_blocky_install_binary || ok=1
	fi
	if ! _ensure_dnsmasq_package; then
		ok=1
	fi
	if _ensure_blocky_present && _ensure_dnsmasq_present; then
		return 0
	fi
	return "$ok"
}
