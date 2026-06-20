#!/usr/bin/env bash
# Rebuild vendored continuum-lwo binaries for Debian/Ubuntu VPS hosts (x86_64 + aarch64).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

PREBUILT_ROOT="${HERE}/prebuilt/debian-ubuntu"
TARGETS=(x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu)

if ! command -v cargo >/dev/null 2>&1; then
	echo "build-prebuilt: cargo required" >&2
	exit 1
fi

for triple in "${TARGETS[@]}"; do
	rustup target add "$triple" >/dev/null 2>&1 || true
done

if ! command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
	echo "build-prebuilt: install cross linker: sudo apt install gcc-aarch64-linux-gnu" >&2
	exit 1
fi

export CARGO_TARGET_DIR="${HERE}/target"
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc

for triple in "${TARGETS[@]}"; do
	echo "==> cargo build --release --target ${triple}"
	cargo build --release --target "$triple"
done

arch_dir() {
	case "$1" in
	x86_64-unknown-linux-gnu) printf '%s' "x86_64" ;;
	aarch64-unknown-linux-gnu) printf '%s' "aarch64" ;;
	*) return 1 ;;
	esac
}

for triple in "${TARGETS[@]}"; do
	arch="$(arch_dir "$triple")"
	dest="${PREBUILT_ROOT}/${arch}"
	mkdir -p "$dest"
	install -m 0755 "${CARGO_TARGET_DIR}/${triple}/release/continuum-lwo-server" "${dest}/"
	install -m 0755 "${CARGO_TARGET_DIR}/${triple}/release/continuum-lwo-client" "${dest}/"
done

built_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
if command -v python3 >/dev/null 2>&1; then
	MANIFEST_PATH="${PREBUILT_ROOT}/MANIFEST.json" BUILT_AT="$built_at" python3 <<'PY'
import json, os
path = os.environ["MANIFEST_PATH"]
with open(path, encoding="utf-8") as f:
    data = json.load(f)
data["builtAt"] = os.environ["BUILT_AT"]
with open(path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
PY
fi

echo "==> Installed prebuilt binaries under ${PREBUILT_ROOT}/"
ls -lh "${PREBUILT_ROOT}"/x86_64/* "${PREBUILT_ROOT}"/aarch64/*
