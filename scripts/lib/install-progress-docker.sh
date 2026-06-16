#!/usr/bin/env bash
# Docker pull + compose up progress (sourced by install scripts — not a separate progress process).
# Requires install-progress.sh already sourced.

: "${INSTALL_PROGRESS_DOCKER_LOADED:=}"
if [ -n "$INSTALL_PROGRESS_DOCKER_LOADED" ]; then
    return 0 2>/dev/null || exit 0
fi
INSTALL_PROGRESS_DOCKER_LOADED=1

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
    local line="$1" cur="${2:-5}"
    local got total

    if [[ "$line" =~ [Pp]ull[[:space:]]+complete ]] \
        || [[ "$line" =~ [Aa]lready[[:space:]]+exists ]] \
        || [[ "$line" =~ [Pp]ull[[:space:]]+complete[[:space:]]+sha256 ]] \
        || [[ "$line" =~ [Dd]ownloaded[[:space:]]+newer ]] \
        || [[ "$line" =~ [Ss]tatus:[[:space:]]*Downloaded ]]; then
        printf '100'
        return
    fi
    if [[ "$line" =~ [Vv]erifying ]]; then
        printf '92'
        return
    fi
    if [[ "$line" =~ [Ee]xtracting ]]; then
        if [[ "$line" =~ ([0-9]+(\.[0-9]+)?)[[:space:]]*(B|kB|KB|MB|GB|TB)?/([0-9]+(\.[0-9]+)?)[[:space:]]*(B|kB|KB|MB|GB|TB)? ]]; then
            got="${BASH_REMATCH[1]}"
            total="${BASH_REMATCH[4]}"
            awk -v g="$got" -v t="$total" 'BEGIN { if (t > 0) printf "%d", 55 + int(g/t*35); else print 75 }'
            return
        fi
        printf '75'
        return
    fi
    if [[ "$line" =~ [Dd]ownloading ]] || [[ "$line" =~ [Pp]ulling[[:space:]]+fs[[:space:]]+layer ]]; then
        if [[ "$line" =~ ([0-9]+(\.[0-9]+)?)[[:space:]]*(B|kB|KB|MB|GB|TB)?/([0-9]+(\.[0-9]+)?)[[:space:]]*(B|kB|KB|MB|GB|TB)? ]]; then
            got="${BASH_REMATCH[1]}"
            total="${BASH_REMATCH[4]}"
            awk -v g="$got" -v t="$total" 'BEGIN { if (t > 0) printf "%d", 8 + int(g/t*45); else print 20 }'
            return
        fi
        if [[ "$line" =~ [Pp]ulling[[:space:]]+from ]]; then
            printf '5'
            return
        fi
        printf '20'
        return
    fi
    if [[ "$line" =~ [Ww]aiting ]]; then
        printf '3'
        return
    fi
    printf '%s' "$cur"
}

install_progress__parse_compose_up_pct() {
    local line="$1" cur="${2:-10}" started="${3:-0}" total="${4:-1}"
    if [[ "$line" =~ [Ss]tarted ]]; then
        if [ "$total" -gt 0 ]; then
            awk -v s="$started" -v t="$total" -v c="$cur" 'BEGIN { p = 15 + int(s/t*80); if (p > 95) p = 95; if (p < c) p = c; printf "%d", p }'
            return
        fi
        printf '90'
        return
    fi
    if [[ "$line" =~ [Cc]reated ]] || [[ "$line" =~ [Cc]reating ]]; then
        if [ "$cur" -lt 25 ]; then printf '25'; else printf '%s' "$cur"; fi
        return
    fi
    if [[ "$line" =~ [Pp]ulling ]] || [[ "$line" =~ [Dd]ownloading ]]; then
        if [ "$cur" -lt 15 ]; then printf '15'; else printf '%s' "$cur"; fi
        return
    fi
    if [[ "$line" =~ [Hh]ealthy ]] || [[ "$line" =~ [Rr]unning ]]; then
        printf '98'
        return
    fi
    printf '%s' "$cur"
}

install_progress__pull_one_image() {
    local image="$1" topic_id="$2"
    local dry_run="${CONTINUUM_INSTALL_DRY_RUN:-false}"

    install_progress_topic_begin "$topic_id" "$(install_progress__pull_label "$image")"

    if [ "$dry_run" = true ]; then
        printf '[dry-run] docker pull %s\n' "$image" >&2
        install_progress_topic_done "$topic_id"
        return 0
    fi

    install_progress_spinner_start
    local pct=5 line
    install_progress_topic_set "$topic_id" "$pct"

    while IFS= read -r line; do
        [ -n "$line" ] || continue
        printf '%s\n' "$line" >&2
        pct="$(install_progress__parse_pull_pct "$line" "$pct")"
        install_progress_topic_set "$topic_id" "$pct"
    done < <(docker pull --progress=plain "$image" 2>&1)

    install_progress_spinner_stop
    install_progress_topic_done "$topic_id"
}

# Pull all compose images and run docker compose up -d (same shell progress state as parent).
install_progress_docker_pull_and_up() {
    local repo_dir="${1:-}"
    local dry_run="${CONTINUUM_INSTALL_DRY_RUN:-false}"

    [ -d "$repo_dir" ] || { printf 'error: repo not found: %s\n' "$repo_dir" >&2; return 1; }
    cd "$repo_dir"

    if ! docker compose version >/dev/null 2>&1; then
        printf 'error: docker compose v2 required\n' >&2
        return 1
    fi

    install_progress_register_compose_pull_topics "$repo_dir"

    local images=() ids=() img
    while IFS= read -r img; do
        [ -n "$img" ] || continue
        images+=("$img")
        ids+=("$(install_progress__pull_topic_id "$img")")
    done < <(docker compose config --images 2>/dev/null | sort -u)

    if [ "${#images[@]}" -eq 0 ]; then
        printf 'warning: no images from docker compose config — skipping pulls\n' >&2
    else
        local i
        for i in "${!images[@]}"; do
            install_progress__pull_one_image "${images[$i]}" "${ids[$i]}"
        done
    fi

    install_progress_topic_begin start-stack "Start containers"

    if [ "$dry_run" = true ]; then
        printf '[dry-run] docker compose up -d\n' >&2
        install_progress_topic_done start-stack
        return 0
    fi

    local service_total started=0 pct=10 line
    service_total="$(docker compose config --services 2>/dev/null | wc -l | tr -d ' ')"
    [ "$service_total" -gt 0 ] || service_total=1

    install_progress_spinner_start
    install_progress_topic_set start-stack "$pct"

    while IFS= read -r line; do
        [ -n "$line" ] || continue
        printf '%s\n' "$line" >&2
        if [[ "$line" =~ [Ss]tarted ]]; then
            started=$((started + 1))
        fi
        pct="$(install_progress__parse_compose_up_pct "$line" "$pct" "$started" "$service_total")"
        install_progress_topic_set start-stack "$pct"
    done < <(docker compose up -d 2>&1)

    install_progress_spinner_stop
    install_progress_topic_done start-stack
}
