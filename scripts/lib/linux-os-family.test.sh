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
expect_family fedora-workstation $'NAME="Fedora Linux"\nID=fedora\nVARIANT_ID=workstation\n' fedora
expect_family fedora-server $'NAME="Fedora Linux"\nID=fedora\nVARIANT_ID=server\n' fedora
expect_family fedora-cloud $'NAME="Fedora Linux"\nID=fedora\nVARIANT_ID=cloud\n' fedora
expect_family silverblue $'NAME="Fedora Linux"\nID=fedora\nVARIANT_ID=silverblue\nOSTREE_VERSION=41.20250101.0\n' unsupported
expect_family kinoite $'NAME="Fedora Linux"\nID=fedora\nVARIANT_ID=kinoite\n' unsupported
expect_family bazzite $'NAME="Bazzite"\nID=bazzite\nID_LIKE=fedora\n' unsupported
expect_family rhel $'NAME="Red Hat Enterprise Linux"\nID=rhel\nID_LIKE="fedora"\n' unsupported
expect_family nobara $'NAME="Nobara Linux"\nID=nobara\nID_LIKE=fedora\n' unsupported
expect_family leap $'NAME="openSUSE Leap"\nID=opensuse-leap\nID_LIKE="opensuse suse"\n' opensuse
expect_family tumbleweed $'NAME="openSUSE Tumbleweed"\nID=opensuse-tumbleweed\nID_LIKE="opensuse suse"\n' opensuse
expect_family microos $'NAME="openSUSE MicroOS"\nID=opensuse-microos\nID_LIKE="opensuse suse"\n' unsupported
expect_family aeon $'NAME="openSUSE Aeon"\nID=opensuse-aeon\nID_LIKE="opensuse suse"\n' unsupported
expect_family kalpa $'NAME="openSUSE Kalpa"\nID=opensuse-kalpa\nID_LIKE="opensuse suse"\n' unsupported
expect_family sles $'NAME="SLES"\nID=sles\nID_LIKE="suse opensuse"\n' unsupported

script="$(continuum_linux_install_script_for_family arch)"
[ "$script" = "scripts/install-node-arch.sh" ] || fail "arch script: ${script}"
script="$(continuum_linux_install_script_for_family debian)"
[ "$script" = "scripts/install-node-debian-ubuntu.sh" ] || fail "debian script: ${script}"
script="$(continuum_linux_install_script_for_family fedora)"
[ "$script" = "scripts/install-node-fedora.sh" ] || fail "fedora script: ${script}"
script="$(continuum_linux_install_script_for_family opensuse)"
[ "$script" = "scripts/install-node-opensuse.sh" ] || fail "opensuse script: ${script}"

printf 'linux-os-family.test.sh: ok\n'
