#!/usr/bin/env bash
# Fixture os-release checks for continuum_linux_family_from_release.
# Does not read the live machine's /etc/os-release.
set -euo pipefail

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/linux-os-family.sh"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fail() {
	printf 'linux-os-family.test.sh: %s\n' "$*" >&2
	exit 1
}

expect_family() {
	local name="$1" body="$2" want="$3" got
	printf '%s\n' "$body" >"${tmp}/${name}"
	got="$(continuum_linux_family_from_release "${tmp}/${name}")"
	if [ "$got" != "$want" ]; then
		fail "${name}: got ${got}, want ${want}"
	fi
}

expect_family arch $'NAME="Arch Linux"\nID=arch\n' arch
expect_family omarchy $'NAME="Omarchy"\nID=omarchy\nID_LIKE=arch\n' arch
expect_family manjaro $'NAME="Manjaro Linux"\nID=manjaro\nID_LIKE=arch\n' arch
expect_family ubuntu $'NAME="Ubuntu"\nID=ubuntu\nID_LIKE=debian\n' debian
expect_family debian $'NAME="Debian GNU/Linux"\nID=debian\n' debian
expect_family artix $'NAME="Artix Linux"\nID=artix\nID_LIKE=arch\n' unsupported
expect_family steamos $'NAME="SteamOS"\nID=steamos\nID_LIKE=arch\n' unsupported
expect_family obarun $'NAME="Obarun"\nID=obarun\nID_LIKE=arch\n' unsupported

script="$(continuum_linux_install_script_for_family arch)"
[ "$script" = "scripts/install-node-arch.sh" ] || fail "arch script: ${script}"
script="$(continuum_linux_install_script_for_family debian)"
[ "$script" = "scripts/install-node-debian-ubuntu.sh" ] || fail "debian script: ${script}"

printf 'linux-os-family.test.sh: ok\n'
