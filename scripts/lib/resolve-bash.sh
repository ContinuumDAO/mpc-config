#!/usr/bin/env bash
# Pick bash 4+ when available (macOS /bin/bash is 3.2 — install-progress needs 4+).
# Source from orchestrators; do not execute directly.

: "${RESOLVE_BASH_LIB_LOADED:=}"
if [ -n "$RESOLVE_BASH_LIB_LOADED" ]; then
    return 0 2>/dev/null || exit 0
fi
RESOLVE_BASH_LIB_LOADED=1

resolve_bash() {
    local candidate
    for candidate in \
        "${CONTINUUM_BASH:-}" \
        /opt/homebrew/bin/bash \
        /usr/local/bin/bash \
        /bin/bash \
        bash; do
        [ -n "$candidate" ] || continue
        if command -v "$candidate" >/dev/null 2>&1; then
            if "$candidate" -c '(( BASH_VERSINFO[0] >= 4 ))' 2>/dev/null; then
                command -v "$candidate"
                return 0
            fi
        fi
    done
    command -v bash 2>/dev/null || printf '%s\n' bash
}

resolve_bash_major() {
    local bash_bin="${1:-$(resolve_bash)}"
    "$bash_bin" -c 'printf "%s" "${BASH_VERSINFO[0]}"' 2>/dev/null || printf '0'
}

if [[ "${BASH_SOURCE[0]:-}" == "${0}" ]]; then
    resolve_bash
fi
