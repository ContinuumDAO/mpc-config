#!/usr/bin/env bash
# Pull docker compose images with per-image install progress topics, then compose up -d.
#
# Usage:
#   docker-compose-pull-with-progress.sh [repo_dir]
#
# Requires: docker compose v2, install-progress.sh sourced by caller or auto-sourced.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=install-progress.sh
. "${SCRIPT_DIR}/install-progress.sh"

REPO_DIR="${1:-${MPC_REPO_DIR:-$(cd "$SCRIPT_DIR/../.." && pwd)}}"
DRY_RUN="${CONTINUUM_INSTALL_DRY_RUN:-false}"
PULL_WEIGHT=3

install_progress__pull_topic_id() {
    local image="$1"
    printf 'pull:%s' "${image//[^a-zA-Z0-9._-]/_}"
}

install_progress__pull_label() {
    local image="$1"
    local short="${image##*/}"
    short="${short:-$image}"
    printf 'Pull %s' "$short"
}

install_progress__parse_pull_pct() {
    local line="$1" cur="${2:-10}"
    if [[ "$line" =~ [Pp]ull[[:space:]]+complete ]]; then
        printf '100'
        return
    fi
    if [[ "$line" =~ [Ee]xtracting ]]; then
        if [[ "$line" =~ ([0-9]+(\.[0-9]+)?)[[:space:]]*MB/([0-9]+(\.[0-9]+)?)[[:space:]]*MB ]]; then
            local got="${BASH_REMATCH[1]}" total="${BASH_REMATCH[3]}"
            if awk -v g="$got" -v t="$total" 'BEGIN { if (t > 0) printf "%d", 50 + int(g/t*40); else print 70 }'; then
                return
            fi
        fi
        printf '75'
        return
    fi
    if [[ "$line" =~ [Dd]ownloading ]]; then
        if [[ "$line" =~ ([0-9]+(\.[0-9]+)?)[[:space:]]*MB/([0-9]+(\.[0-9]+)?)[[:space:]]*MB ]]; then
            local got="${BASH_REMATCH[1]}" total="${BASH_REMATCH[3]}"
            awk -v g="$got" -v t="$total" 'BEGIN { if (t > 0) printf "%d", 10 + int(g/t*35); else print 25 }'
            return
        fi
        printf '25'
        return
    fi
    if [[ "$line" =~ [Vv]erifying ]]; then
        printf '90'
        return
    fi
    printf '%s' "$cur"
}

pull_one_image() {
    local image="$1"
    local topic_id
    topic_id="$(install_progress_register_pull_topic "$image")"
    install_progress_topic_begin "$topic_id" "$(install_progress__pull_label "$image")"

    if [ "$DRY_RUN" = true ]; then
        printf '[dry-run] docker pull %s\n' "$image" >&2
        install_progress_topic_done "$topic_id"
        return 0
    fi

    install_progress_spinner_start
    local pct=10 line
    install_progress_topic_set "$topic_id" "$pct"

    while IFS= read -r line; do
        printf '%s\n' "$line" >&2
        pct="$(install_progress__parse_pull_pct "$line" "$pct")"
        install_progress_topic_set "$topic_id" "$pct"
    done < <(docker pull --progress=plain "$image" 2>&1)

    install_progress_spinner_stop
    install_progress_topic_done "$topic_id"
}

main() {
    [ -d "$REPO_DIR" ] || { printf 'error: repo not found: %s\n' "$REPO_DIR" >&2; exit 1; }
    cd "$REPO_DIR"

    if ! docker compose version >/dev/null 2>&1; then
        printf 'error: docker compose v2 required\n' >&2
        exit 1
    fi

    local images=()
    local img
    while IFS= read -r img; do
        [ -n "$img" ] || continue
        images+=("$img")
    done < <(docker compose config --images 2>/dev/null | sort -u)

    if [ "${#images[@]}" -eq 0 ]; then
        printf 'warning: no images from docker compose config — skipping pulls\n' >&2
    else
        for img in "${images[@]}"; do
            pull_one_image "$img"
        done
    fi

    install_progress_topic_begin start-stack "Start containers"

    if [ "$DRY_RUN" = true ]; then
        printf '[dry-run] docker compose up -d\n' >&2
        install_progress_topic_done start-stack
        return 0
    fi

    install_progress_spinner_start
    install_progress_topic_set start-stack 20
    docker compose up -d 2>&1 | while IFS= read -r line; do printf '%s\n' "$line" >&2; done
    install_progress_spinner_stop
    install_progress_topic_done start-stack
}

main "$@"
