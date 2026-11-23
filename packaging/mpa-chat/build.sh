#!/usr/bin/env bash
# Build mpa-chat .deb and Arch packages from an mpc-auth checkout.
# MPC_AUTH_DIR defaults to the sibling checkout ../mpc-auth.
# VERSION defaults to 0.1.0. A tag mpa-chat-v0.1.0 is stripped to 0.1.0.
# Output goes to packaging/mpa-chat/dist/.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
config_root="$(cd "$here/../.." && pwd)"
src="${MPC_AUTH_DIR:-"$config_root/../mpc-auth"}"
version="${VERSION:-0.1.0}"
version="${version#mpa-chat-v}"
out="$here/dist"
mkdir -p "$out"

if [[ ! -d "$src/cli/mpa-chat" ]]; then
  echo "mpc-auth checkout not found at $src (set MPC_AUTH_DIR)" >&2
  exit 1
fi

nfpm_version="${NFPM_VERSION:-v2.41.3}"
run_nfpm() {
  if type -P nfpm >/dev/null 2>&1; then
    nfpm "$@"
  else
    go run "github.com/goreleaser/nfpm/v2/cmd/nfpm@${nfpm_version}" "$@"
  fi
}

pack() {
  local goarch="$1" debarch="$2" pkgarch="$3"
  local bin="$out/mpa-chat-$goarch"
  echo "building linux/$goarch"
  (
    cd "$src"
    CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" go build -trimpath -o "$bin" ./cli/mpa-chat
  )
  local cfg="$out/nfpm-$debarch.yaml"
  write_nfpm() {
    local arch="$1" dep="$2"
    cat >"$cfg" <<EOF
name: mpa-chat
arch: ${arch}
platform: linux
version: ${version}
version_schema: none
section: utils
priority: optional
maintainer: ContinuumDAO <https://github.com/ContinuumDAO/mpc-config>
description: Terminal chat for the AI agent on a Continuum node
homepage: https://github.com/ContinuumDAO/mpc-config
license: BUSL-1.1
depends:
  - ${dep}
contents:
  - src: ${bin}
    dst: /usr/bin/mpa-chat
    file_info:
      mode: 0755
EOF
  }
  local deb="$out/mpa-chat_${version}_${debarch}.deb"
  local pkg="$out/mpa-chat-${version}-1-${pkgarch}.pkg.tar.zst"
  write_nfpm "$debarch" openssh-client
  (cd "$out" && run_nfpm package -f "$cfg" -p deb -t "$deb")
  write_nfpm "$pkgarch" openssh
  (cd "$out" && run_nfpm package -f "$cfg" -p archlinux -t "$pkg")
  rm -f "$bin" "$cfg"
  echo "wrote $deb"
  echo "wrote $pkg"
}

pack amd64 amd64 x86_64
pack arm64 arm64 aarch64
