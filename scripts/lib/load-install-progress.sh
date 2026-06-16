#!/usr/bin/env bash
# Bootstrap: source install-progress.sh from repo checkout or raw GitHub (curl|bash installs).
set -euo pipefail

if [ -n "${INSTALL_PROGRESS_LIB_LOADED:-}" ]; then
    return 0 2>/dev/null || exit 0
fi

_load_install_progress__raw_base() {
    local repo="${MPC_CONFIG_REPO:-https://github.com/ContinuumDAO/mpc-config.git}"
    local ref="${MPC_CONFIG_REF:-main}"
    local path="$repo"
    path="${path#https://github.com/}"
    path="${path#http://github.com/}"
    path="${path%.git}"
    printf 'https://raw.githubusercontent.com/%s/%s' "$path" "$ref"
}

_load_install_progress() {
    local caller_dir="${1:-}"
    if [ -n "$caller_dir" ] && [ -f "${caller_dir}/lib/install-progress.sh" ]; then
        # shellcheck source=install-progress.sh
        . "${caller_dir}/lib/install-progress.sh"
        return 0
    fi
    local tmp base
    tmp="$(mktemp -d 2>/dev/null || echo "/tmp/continuum-progress-$$")"
    base="$(_load_install_progress__raw_base)"
    if ! curl -fsSL "${base}/scripts/lib/install-progress.sh" -o "${tmp}/install-progress.sh" 2>/dev/null; then
        CONTINUUM_INSTALL_PROGRESS=off
        export CONTINUUM_INSTALL_PROGRESS
        return 0
    fi
    # shellcheck source=/dev/null
    . "${tmp}/install-progress.sh"
}

_load_install_progress "${CONTINUUM_INSTALL_SCRIPT_DIR:-}"
