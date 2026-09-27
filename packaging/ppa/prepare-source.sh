#!/usr/bin/env bash
# Assemble a Launchpad source package from this repo and the debian/ directory.
# Does not sign or upload. See the internal PPA guide for dput.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHANGELOG="${HERE}/debian/changelog"

version="$(sed -n '1s/^mpa-wallet (\([^)]*\)).*/\1/p' "$CHANGELOG")"
if [ -z "$version" ]; then
	printf 'error: could not read the version from %s\n' "$CHANGELOG" >&2
	exit 1
fi
case "$version" in
*-*)
	printf 'error: %s uses a native source format, so the version must not contain a hyphen (got %s)\n' "$CHANGELOG" "$version" >&2
	exit 1
	;;
esac

work="$(mktemp -d)"
src="${work}/mpa-wallet-${version}"
mkdir -p "${src}/scripts/lib" "${src}/bin"

for script in install-node-debian-ubuntu.sh uninstall-node-debian-ubuntu.sh verify-node-install.sh; do
	if [ ! -f "${ROOT}/scripts/${script}" ]; then
		printf 'error: scripts/%s is missing\n' "$script" >&2
		exit 1
	fi
	cp "${ROOT}/scripts/${script}" "${src}/scripts/${script}"
	chmod 755 "${src}/scripts/${script}"
done

shopt -s nullglob
for lib in "${ROOT}/scripts/lib/"*; do
	[ -f "$lib" ] || continue
	case "$lib" in
	*.pyc|*.test.sh) continue ;;
	esac
	cp "$lib" "${src}/scripts/lib/$(basename "$lib")"
	if [ -x "$lib" ] || [[ "$lib" == *.sh || "$lib" == *.py ]]; then
		chmod 755 "${src}/scripts/lib/$(basename "$lib")"
	fi
done
shopt -u nullglob

if [ ! -f "${src}/scripts/lib/load-install-progress.sh" ]; then
	printf 'error: scripts/lib/load-install-progress.sh was not copied\n' >&2
	exit 1
fi

cp "${HERE}/mpa-wallet-install" "${src}/bin/mpa-wallet-install"
cp "${HERE}/mpa-wallet-uninstall" "${src}/bin/mpa-wallet-uninstall"
chmod 755 "${src}/bin/mpa-wallet-install" "${src}/bin/mpa-wallet-uninstall"
cp "${ROOT}/LICENSE" "${src}/LICENSE"
cp -a "${HERE}/debian" "${src}/debian"
chmod 755 "${src}/debian/rules" "${src}/debian/mpa-wallet.postinst"

printf 'Source tree: %s\n' "$src"
# Source-only. Launchpad runs debian/rules; the upload machine does not need debhelper.
(
	cd "$work"
	dpkg-source -b "mpa-wallet-${version}"
)
(
	cd "$src"
	dpkg-genchanges -S > "../mpa-wallet_${version}_source.changes"
)
printf 'Source package files:\n'
find "$work" -maxdepth 1 -type f -printf '  %p\n'
printf 'Sign and upload the .changes file. The tree is in %s\n' "$work"
