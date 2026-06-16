#!/usr/bin/env bash
# Shared install progress UI for VPS and Docker Desktop provision scripts.
# Source from install scripts; do not execute directly.
#
# Render modes (CONTINUUM_INSTALL_PROGRESS):
#   tty   — auto when stdout is a TTY
#   json  — @continuum/progress lines for Docker extension
#   plain — text bars, no ANSI (non-TTY)
#   off   — disabled
#
# Progress frames go to stdout; callers should keep verbose logs on stderr.

: "${INSTALL_PROGRESS_LIB_LOADED:=}"
if [ -n "$INSTALL_PROGRESS_LIB_LOADED" ]; then
    return 0 2>/dev/null || exit 0
fi
INSTALL_PROGRESS_LIB_LOADED=1

# --- internal state ---
_INSTALL_PROGRESS_MODE=""
_INSTALL_PROGRESS_PROFILE=""
_INSTALL_PROGRESS_ACTIVE=false
_INSTALL_PROGRESS_FINISHED=false
_INSTALL_PROGRESS_SPINNER_IDX=0
_INSTALL_PROGRESS_SPINNER_FRAMES=(⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏)
_INSTALL_PROGRESS_TOPIC_ORDER=()
declare -g -A _INSTALL_PROGRESS_TOPIC_LABEL
declare -g -A _INSTALL_PROGRESS_TOPIC_WEIGHT
declare -g -A _INSTALL_PROGRESS_TOPIC_PCT
declare -g -A _INSTALL_PROGRESS_TOPIC_STATE
declare -g -A _INSTALL_PROGRESS_TOPIC_REGISTERED
_INSTALL_PROGRESS_FRAME_LINES=0
_INSTALL_PROGRESS_SPINNER_PID=""

install_progress__resolve_lib_dir() {
    if [ -n "${INSTALL_PROGRESS_LIB_DIR:-}" ] && [ -f "${INSTALL_PROGRESS_LIB_DIR}/install-progress.sh" ]; then
        printf '%s\n' "$INSTALL_PROGRESS_LIB_DIR"
        return 0
    fi
    local src="${BASH_SOURCE[1]:-${BASH_SOURCE[0]}}"
    if [ -n "$src" ] && [ -f "$(dirname "$src")/install-progress.sh" ]; then
        printf '%s\n' "$(cd "$(dirname "$src")" && pwd)"
        return 0
    fi
    printf '%s\n' "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
}

INSTALL_PROGRESS_LIB_DIR="$(install_progress__resolve_lib_dir)"

install_progress__detect_mode() {
    local flag="${CONTINUUM_INSTALL_PROGRESS:-}"
    case "$flag" in
        off|0|false|OFF) printf 'off'; return ;;
        json|JSON) printf 'json'; return ;;
        plain|PLAIN) printf 'plain'; return ;;
        tty|TTY) printf 'tty'; return ;;
    esac
    if [ -t 1 ]; then
        printf 'tty'
    else
        printf 'plain'
    fi
}

install_progress_ui_active() {
    [ "$_INSTALL_PROGRESS_MODE" != "off" ] && [ "$_INSTALL_PROGRESS_ACTIVE" = true ] && [ "$_INSTALL_PROGRESS_FINISHED" = false ]
}

install_progress__topic_index() {
    local id="$1" i
    for i in "${!_INSTALL_PROGRESS_TOPIC_ORDER[@]}"; do
        if [ "${_INSTALL_PROGRESS_TOPIC_ORDER[$i]}" = "$id" ]; then
            printf '%s' "$i"
            return 0
        fi
    done
    return 1
}

install_progress__register_topic() {
    local id="$1" label="$2" weight="${3:-1}"
    if [ "${_INSTALL_PROGRESS_TOPIC_REGISTERED[$id]:-}" = "1" ]; then
        return 0
    fi
    _INSTALL_PROGRESS_TOPIC_REGISTERED[$id]=1
    _INSTALL_PROGRESS_TOPIC_ORDER+=("$id")
    _INSTALL_PROGRESS_TOPIC_LABEL[$id]="$label"
    _INSTALL_PROGRESS_TOPIC_WEIGHT[$id]="$weight"
    _INSTALL_PROGRESS_TOPIC_PCT[$id]=0
    _INSTALL_PROGRESS_TOPIC_STATE[$id]=pending
}

install_progress__profile_topics() {
    local profile="$1"
    case "$profile" in
        vps)
            install_progress__register_topic preflight "Preflight check" 2
            install_progress__register_topic packages "System packages" 14
            install_progress__register_topic os-user "OS user & sudo" 3
            install_progress__register_topic clone "Clone mpc-config" 5
            install_progress__register_topic docker-v2 "Docker Compose v2" 4
            install_progress__register_topic provision-setup "Node config bootstrap" 4
            install_progress__register_topic start-stack "Start containers" 4
            ;;
        desktop)
            install_progress__register_topic clone "Clone mpc-config" 8
            install_progress__register_topic python-deps "Python dependencies" 10
            install_progress__register_topic provision-setup "Node config bootstrap" 5
            install_progress__register_topic desktop-patch "Dashboard discovery patch" 3
            install_progress__register_topic start-stack "Start containers" 4
            ;;
        *)
            install_progress__register_topic preflight "Preflight check" 1
            ;;
    esac
}

# Register process_config sub-topics (call before process_config.sh runs).
install_progress_register_pc_topics() {
    local skip_firewall="${1:-0}" skip_systemd="${2:-0}"
    install_progress__register_topic pc-config "Load & prepare configs" 6
    install_progress__register_topic pc-keys "Management keys & peers" 6
    install_progress__register_topic pc-validate "Validate configuration" 8
    install_progress__register_topic pc-mqtt-config "MQTT broker setup" 5
    install_progress__register_topic pc-compose "Generate docker-compose" 8
    install_progress__register_topic pc-browser-https "Browser HTTPS certificates" 8
    install_progress__register_topic pc-relayer "Relayer API check" 6
    if [ "$skip_firewall" != "1" ]; then
        install_progress__register_topic pc-firewall "Host firewall (UFW)" 5
    fi
    if [ "$skip_systemd" != "1" ]; then
        install_progress__register_topic pc-systemd "Systemd helpers" 4
    fi
    install_progress__register_topic pc-mqtt-certs "MQTT TLS certificates" 6
    install_progress__emit_init_if_needed
}

install_progress_register_pull_topic() {
    local image="$1"
    local short="${image##*/}"
    short="${short:-$image}"
    local id="pull:${image//[^a-zA-Z0-9._-]/_}"
    install_progress__register_topic "$id" "Pull ${short}" 3
    install_progress__emit_init_if_needed
    printf '%s' "$id"
}

install_progress__emit_init_if_needed() {
    [ "$_INSTALL_PROGRESS_MODE" = "json" ] || return 0
    [ "${_INSTALL_PROGRESS_JSON_INIT_EMITTED:-0}" = "1" ] && return 0
    _INSTALL_PROGRESS_JSON_INIT_EMITTED=1
    local topics_json="" id w label
    local first=true
    for id in "${_INSTALL_PROGRESS_TOPIC_ORDER[@]}"; do
        label="${_INSTALL_PROGRESS_TOPIC_LABEL[$id]}"
        w="${_INSTALL_PROGRESS_TOPIC_WEIGHT[$id]}"
        if [ "$first" = true ]; then first=false; else topics_json+=","; fi
        topics_json+="{\"id\":\"$(install_progress__json_escape "$id")\",\"label\":\"$(install_progress__json_escape "$label")\",\"weight\":${w}}"
    done
    install_progress__json_line "{\"type\":\"init\",\"profile\":\"${_INSTALL_PROGRESS_PROFILE}\",\"topics\":[${topics_json}]}"
}

install_progress__json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    printf '%s' "$s"
}

install_progress__json_line() {
    printf '@continuum/progress\t%s\n' "$1"
}

install_progress__overall_pct() {
    local total_w=0 weighted=0 id w pct state
    for id in "${_INSTALL_PROGRESS_TOPIC_ORDER[@]}"; do
        state="${_INSTALL_PROGRESS_TOPIC_STATE[$id]}"
        [ "$state" = "skipped" ] && continue
        w="${_INSTALL_PROGRESS_TOPIC_WEIGHT[$id]:-1}"
        pct="${_INSTALL_PROGRESS_TOPIC_PCT[$id]:-0}"
        total_w=$((total_w + w))
        weighted=$((weighted + w * pct))
    done
    if [ "$total_w" -le 0 ]; then
        printf '0'
        return
    fi
    printf '%s' $((weighted / total_w))
}

install_progress__bar() {
    local pct="$1" width="${2:-10}"
    local filled=$((pct * width / 100))
    local i out=""
    for ((i = 0; i < width; i++)); do
        if [ "$i" -lt "$filled" ]; then out+='█'; else out+='░'; fi
    done
    printf '%s' "$out"
}

install_progress__state_marker() {
    local state="$1"
    case "$state" in
        done) printf '[done]' ;;
        active) printf '[====]' ;;
        failed) printf '[FAIL]' ;;
        skipped) printf '[skip]' ;;
        *) printf '[    ]' ;;
    esac
}

install_progress__spinner_char() {
    printf '%s' "${_INSTALL_PROGRESS_SPINNER_FRAMES[$_INSTALL_PROGRESS_SPINNER_IDX]}"
}

install_progress__tty_hide_cursor() {
    [ "$_INSTALL_PROGRESS_MODE" = "tty" ] && printf '\033[?25l' >&1
}

install_progress__tty_show_cursor() {
    [ "$_INSTALL_PROGRESS_MODE" = "tty" ] && printf '\033[?25h' >&1
}

install_progress__tty_redraw() {
    [ "$_INSTALL_PROGRESS_MODE" != "tty" ] && return 0
    local lines="$1"
    if [ "$lines" -gt 0 ]; then
        printf '\033[%dA' "$lines" >&1
    fi
    local id label pct state marker bar overall spinner line_count=0
    printf 'Continuum node install\n\n' >&1
    line_count=$((line_count + 2))
    for id in "${_INSTALL_PROGRESS_TOPIC_ORDER[@]}"; do
        label="${_INSTALL_PROGRESS_TOPIC_LABEL[$id]}"
        pct="${_INSTALL_PROGRESS_TOPIC_PCT[$id]:-0}"
        state="${_INSTALL_PROGRESS_TOPIC_STATE[$id]:-pending}"
        marker="$(install_progress__state_marker "$state")"
        bar="$(install_progress__bar "$pct")"
        printf '  %s %-28s %s %3s%%\n' "$marker" "$label" "$bar" "$pct" >&1
        line_count=$((line_count + 1))
    done
    overall="$(install_progress__overall_pct)"
    spinner="$(install_progress__spinner_char)"
    printf '\n  Overall %-28s %s %3s%%  %s Working…\n' "" "$(install_progress__bar "$overall")" "$overall" "$spinner" >&1
    line_count=$((line_count + 2))
    _INSTALL_PROGRESS_FRAME_LINES=$line_count
}

install_progress__plain_redraw() {
    [ "$_INSTALL_PROGRESS_MODE" != "plain" ] && return 0
    local id label pct state overall
    overall="$(install_progress__overall_pct)"
    printf '==> Overall %s%%\n' "$overall" >&1
    for id in "${_INSTALL_PROGRESS_TOPIC_ORDER[@]}"; do
        state="${_INSTALL_PROGRESS_TOPIC_STATE[$id]:-pending}"
        [ "$state" = "pending" ] && continue
        label="${_INSTALL_PROGRESS_TOPIC_LABEL[$id]}"
        pct="${_INSTALL_PROGRESS_TOPIC_PCT[$id]:-0}"
        printf '    %s: %s%%\n' "$label" "$pct" >&1
    done
}

install_progress__emit_json_topic() {
    local id="$1"
    install_progress__json_line "{\"type\":\"topic\",\"id\":\"$(install_progress__json_escape "$id")\",\"pct\":${_INSTALL_PROGRESS_TOPIC_PCT[$id]:-0},\"state\":\"${_INSTALL_PROGRESS_TOPIC_STATE[$id]:-pending}\"}"
}

install_progress__emit_json_overall() {
    local overall spinner="${1:-true}"
    local spin_json=false
    [ "$spinner" = "true" ] && spin_json=true
    install_progress__json_line "{\"type\":\"overall\",\"pct\":$(install_progress__overall_pct),\"spinner\":${spin_json}}"
}

install_progress_redraw() {
    install_progress_ui_active || return 0
    case "$_INSTALL_PROGRESS_MODE" in
        tty)
            install_progress__tty_redraw "${_INSTALL_PROGRESS_FRAME_LINES:-0}"
            ;;
        json)
            install_progress__emit_json_overall true
            ;;
        plain)
            install_progress__plain_redraw
            ;;
    esac
}

install_progress_tick() {
    install_progress_ui_active || return 0
    _INSTALL_PROGRESS_SPINNER_IDX=$(( (_INSTALL_PROGRESS_SPINNER_IDX + 1) % ${#_INSTALL_PROGRESS_SPINNER_FRAMES[@]} ))
    install_progress_redraw
}

install_progress__spinner_loop() {
    while [ -f "${INSTALL_PROGRESS_SPINNER_STOP:-/dev/null}" ]; do
        install_progress_tick
        sleep 0.12 2>/dev/null || sleep 1
    done
}

install_progress_spinner_start() {
    install_progress_ui_active || return 0
    [ -n "$_INSTALL_PROGRESS_SPINNER_PID" ] && return 0
    INSTALL_PROGRESS_SPINNER_STOP="$(mktemp 2>/dev/null || echo "/tmp/continuum-install-spinner-$$")"
    touch "$INSTALL_PROGRESS_SPINNER_STOP"
    (
        install_progress__spinner_loop
    ) &
    _INSTALL_PROGRESS_SPINNER_PID=$!
}

install_progress_spinner_stop() {
    if [ -n "$_INSTALL_PROGRESS_SPINNER_PID" ]; then
        rm -f "${INSTALL_PROGRESS_SPINNER_STOP:-}" 2>/dev/null || true
        wait "$_INSTALL_PROGRESS_SPINNER_PID" 2>/dev/null || true
        _INSTALL_PROGRESS_SPINNER_PID=""
    fi
    INSTALL_PROGRESS_SPINNER_STOP=""
}

install_progress_init() {
    local profile="${1:-vps}"
    _INSTALL_PROGRESS_MODE="$(install_progress__detect_mode)"
    _INSTALL_PROGRESS_PROFILE="$profile"
    _INSTALL_PROGRESS_ACTIVE=true
    _INSTALL_PROGRESS_FINISHED=false
    _INSTALL_PROGRESS_FRAME_LINES=0
    _INSTALL_PROGRESS_JSON_INIT_EMITTED=0
    _INSTALL_PROGRESS_TOPIC_ORDER=()
    _INSTALL_PROGRESS_TOPIC_REGISTERED=()
    _INSTALL_PROGRESS_TOPIC_LABEL=()
    _INSTALL_PROGRESS_TOPIC_WEIGHT=()
    _INSTALL_PROGRESS_TOPIC_PCT=()
    _INSTALL_PROGRESS_TOPIC_STATE=()

    [ "$_INSTALL_PROGRESS_MODE" = "off" ] && return 0

    install_progress__profile_topics "$profile"
    install_progress__emit_init_if_needed

    case "$_INSTALL_PROGRESS_MODE" in
        tty)
            install_progress__tty_hide_cursor
            install_progress__tty_redraw 0
            ;;
        json)
            install_progress__emit_json_overall true
            ;;
        plain)
            printf 'Continuum node install\n' >&1
            ;;
    esac
}

install_progress_topic_begin() {
    local id="$1" label="${2:-}"
    install_progress_ui_active || return 0
    if [ -n "$label" ]; then
        install_progress__register_topic "$id" "$label" "${_INSTALL_PROGRESS_TOPIC_WEIGHT[$id]:-3}"
    fi
    _INSTALL_PROGRESS_TOPIC_STATE[$id]=active
    _INSTALL_PROGRESS_TOPIC_PCT[$id]=0
    install_progress__emit_init_if_needed
    case "$_INSTALL_PROGRESS_MODE" in
        json) install_progress__emit_json_topic "$id" ;;
    esac
    install_progress_redraw
}

install_progress_topic_set() {
    local id="$1" pct="$2"
    install_progress_ui_active || return 0
    if [ -z "${_INSTALL_PROGRESS_TOPIC_REGISTERED[$id]:-}" ]; then
        install_progress__register_topic "$id" "$id" 3
    fi
    if [ "$pct" -lt 0 ]; then pct=0; fi
    if [ "$pct" -gt 100 ]; then pct=100; fi
    _INSTALL_PROGRESS_TOPIC_PCT[$id]=$pct
    if [ "${_INSTALL_PROGRESS_TOPIC_STATE[$id]:-pending}" = "pending" ]; then
        _INSTALL_PROGRESS_TOPIC_STATE[$id]=active
    fi
    case "$_INSTALL_PROGRESS_MODE" in
        json) install_progress__emit_json_topic "$id" ;;
    esac
    install_progress_redraw
}

install_progress_topic_done() {
    local id="$1"
    install_progress_ui_active || return 0
    _INSTALL_PROGRESS_TOPIC_PCT[$id]=100
    _INSTALL_PROGRESS_TOPIC_STATE[$id]=done
    case "$_INSTALL_PROGRESS_MODE" in
        json) install_progress__emit_json_topic "$id" ;;
    esac
    install_progress_redraw
}

install_progress_topic_skip() {
    local id="$1"
    install_progress_ui_active || return 0
    _INSTALL_PROGRESS_TOPIC_PCT[$id]=100
    _INSTALL_PROGRESS_TOPIC_STATE[$id]=skipped
    case "$_INSTALL_PROGRESS_MODE" in
        json) install_progress__emit_json_topic "$id" ;;
    esac
    install_progress_redraw
}

install_progress_topic_fail() {
    local id="$1"
    install_progress_ui_active || return 0
    _INSTALL_PROGRESS_TOPIC_STATE[$id]=failed
    case "$_INSTALL_PROGRESS_MODE" in
        json) install_progress__emit_json_topic "$id" ;;
    esac
    install_progress_redraw
}

install_progress_finish() {
    local ok="${1:-true}"
    install_progress_spinner_stop
    [ "$_INSTALL_PROGRESS_MODE" = "off" ] && return 0
    [ "$_INSTALL_PROGRESS_FINISHED" = true ] && return 0
    _INSTALL_PROGRESS_FINISHED=true

    local id
    if [ "$ok" = "true" ]; then
        for id in "${_INSTALL_PROGRESS_TOPIC_ORDER[@]}"; do
            case "${_INSTALL_PROGRESS_TOPIC_STATE[$id]:-pending}" in
                pending|active)
                    _INSTALL_PROGRESS_TOPIC_PCT[$id]=100
                    _INSTALL_PROGRESS_TOPIC_STATE[$id]=done
                    ;;
            esac
        done
    fi

    case "$_INSTALL_PROGRESS_MODE" in
        tty)
            install_progress__tty_redraw "${_INSTALL_PROGRESS_FRAME_LINES:-0}"
            install_progress__tty_show_cursor
            if [ "$ok" = "true" ]; then
                printf '\nInstall complete.\n' >&1
            else
                printf '\nInstall failed.\n' >&1
            fi
            ;;
        json)
            install_progress__emit_json_overall false
            install_progress__json_line "{\"type\":\"finish\",\"ok\":$([ "$ok" = "true" ] && printf true || printf false)}"
            ;;
        plain)
            if [ "$ok" = "true" ]; then
                printf '==> Install complete (100%%)\n' >&1
            else
                printf '==> Install failed\n' >&1
            fi
            ;;
    esac
    _INSTALL_PROGRESS_ACTIVE=false
}

install_progress_run() {
    local topic_id="$1"
    shift
    install_progress_topic_begin "$topic_id"
    install_progress_spinner_start
    local ec=0
    "$@" || ec=$?
    install_progress_spinner_stop
    if [ "$ec" -eq 0 ]; then
        install_progress_topic_done "$topic_id"
    else
        install_progress_topic_fail "$topic_id"
    fi
    return "$ec"
}

# Mark resume skips (e.g. packages already installed).
install_progress_mark_done_if() {
    local topic_id="$1" condition="$2"
    if [ "$condition" = "true" ] || [ "$condition" = "1" ]; then
        install_progress_topic_begin "$topic_id"
        install_progress_topic_skip "$topic_id"
    fi
}

install_progress_topic_if_registered() {
    local action="$1" topic_id="$2" pct="${3:-}"
    [ "${_INSTALL_PROGRESS_TOPIC_REGISTERED[$topic_id]:-}" = "1" ] || return 0
    case "$action" in
        begin) install_progress_topic_begin "$topic_id" ;;
        done) install_progress_topic_done "$topic_id" ;;
        set) install_progress_topic_set "$topic_id" "$pct" ;;
    esac
}
