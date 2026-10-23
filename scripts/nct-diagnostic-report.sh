#!/bin/sh
set -eu

umask 077

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
CONTAINER="nct"
OUTPUT_ROOT="${NCT_DIAGNOSTIC_DIR:-/var/lib/nct/deployment/diagnostics}"
DOCKER_PROBE_TIMEOUT="${NCT_DIAGNOSTIC_DOCKER_PROBE_TIMEOUT:-15}"
DOCKER_HELPER_TIMEOUT="${NCT_DIAGNOSTIC_DOCKER_HELPER_TIMEOUT:-45}"
PROBE=""
RUN_DIR=""
REPORT=""
JSON_REPORT=""
CHECKSUM=""
DB_HELPER_NAME=""
RENDER_HELPER_NAME=""
PRESERVE_PROBE=0

usage() {
    cat <<'EOF'
Create a private, read-only NCT diagnostic report.

Usage:
  sh scripts/nct-diagnostic-report.sh [--container NAME] [--output-dir ABSOLUTE_PATH]

Defaults:
  container: nct
  output root: /var/lib/nct/deployment/diagnostics

The command works with running, stopped, and restarting containers. It does not
restart, stop, reset, repair, migrate, or upload anything.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --container)
            [ "$#" -ge 2 ] || { usage >&2; exit 2; }
            CONTAINER=$2
            shift 2
            ;;
        --output-dir)
            [ "$#" -ge 2 ] || { usage >&2; exit 2; }
            OUTPUT_ROOT=$2
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf '%s\n' "Unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

case "$CONTAINER" in
    ''|*[!A-Za-z0-9_.-]*)
        printf '%s\n' "HALT: container names may contain only letters, numbers, dot, underscore, and dash." >&2
        exit 2
        ;;
esac
case "$OUTPUT_ROOT" in
    /*) ;;
    *) printf '%s\n' "HALT: --output-dir must be an absolute path." >&2; exit 2 ;;
esac
case "$DOCKER_PROBE_TIMEOUT:$DOCKER_HELPER_TIMEOUT" in
    *[!0-9:]*|0:*|*:0)
        printf '%s\n' "HALT: diagnostic timeout values must be positive whole seconds." >&2
        exit 2
        ;;
esac
case "$OUTPUT_ROOT" in
    /) printf '%s\n' "HALT: --output-dir may not be the filesystem root." >&2; exit 2 ;;
    *'/../'*|*'/./'*|*/..|*/.)
        printf '%s\n' "HALT: --output-dir may not contain dot path segments." >&2
        exit 2
        ;;
esac

path_has_symlink_component() {
    candidate=${1%/}
    while [ "$candidate" != "/" ] && [ -n "$candidate" ]; do
        [ ! -L "$candidate" ] || return 0
        candidate=$(dirname -- "$candidate")
    done
    return 1
}

paths_overlap() {
    first=${1%/}
    second=${2%/}
    [ "$first" = "$second" ] && return 0
    case "$first/" in "$second/"*) return 0 ;; esac
    case "$second/" in "$first/"*) return 0 ;; esac
    return 1
}

terminal_partial() {
    reason=$1
    details=${2:-}
    next_step=${3:-"Keep the current container and data unchanged, resolve the stated problem, and run the diagnostic again."}
    printf '%s\n' "NCT diagnostic could not create a report safely. Nothing was restarted, reset, changed, or uploaded."
    printf '%s\n' "Report completeness: partial"
    printf '%s\n' "Not checked — $reason"
    [ -z "$details" ] || printf '%s\n' "$details"
    printf '%s\n' "Next step: $next_step"
}

remove_and_confirm_helper() {
    helper_name=$1
    timeout -k 2 "$DOCKER_PROBE_TIMEOUT" docker rm -f "$helper_name" >/dev/null 2>&1 || true
    remaining=$(timeout -k 2 "$DOCKER_PROBE_TIMEOUT" docker ps -a \
        --filter "name=^/${helper_name}$" --format '{{.Names}}' 2>/dev/null) || return 1
    [ -z "$remaining" ]
}

cleanup() {
    unresolved=0
    if command -v timeout >/dev/null 2>&1 && command -v docker >/dev/null 2>&1; then
        if [ -n "$DB_HELPER_NAME" ]; then
            if remove_and_confirm_helper "$DB_HELPER_NAME"; then DB_HELPER_NAME=""; else unresolved=1; fi
        fi
        if [ -n "$RENDER_HELPER_NAME" ]; then
            if remove_and_confirm_helper "$RENDER_HELPER_NAME"; then RENDER_HELPER_NAME=""; else unresolved=1; fi
        fi
    elif [ -n "$DB_HELPER_NAME$RENDER_HELPER_NAME" ]; then
        unresolved=1
    fi
    if [ "$unresolved" -eq 0 ] && [ "$PRESERVE_PROBE" -eq 0 ]; then
        [ -z "$PROBE" ] || rm -rf -- "$PROBE"
    elif [ "$unresolved" -eq 0 ]; then
        printf '%s\n' "NOTICE: diagnostic helper absence was confirmed during final cleanup; the report-recorded private probe workspace remains at $PROBE" >&2
    else
        printf '%s\n' "WARNING: diagnostic helper cleanup remains unverified; the private probe workspace was retained at $PROBE" >&2
    fi
}
trap cleanup EXIT HUP INT TERM

docker_probe() {
    timeout -k 2 "$DOCKER_PROBE_TIMEOUT" docker "$@"
}

docker_helper() {
    timeout -k 5 "$DOCKER_HELPER_TIMEOUT" docker "$@"
}

prepare_output() {
    if path_has_symlink_component "$OUTPUT_ROOT"; then
        terminal_partial "The report path uses a symbolic-link path component."
        return 1
    fi
    if [ -e "$OUTPUT_ROOT" ] && [ ! -d "$OUTPUT_ROOT" ]; then
        terminal_partial "The report root is not a directory: $OUTPUT_ROOT"
        return 1
    fi
    mkdir -p -- "$OUTPUT_ROOT" || {
        terminal_partial "The private report root could not be created: $OUTPUT_ROOT"
        return 1
    }
    if path_has_symlink_component "$OUTPUT_ROOT"; then
        terminal_partial "The report path changed to a symbolic-link path during report creation."
        return 1
    fi
    timestamp=$(date -u +%Y%m%dT%H%M%SZ)
    RUN_DIR="$OUTPUT_ROOT/nct-diagnostic-$timestamp-$$"
    mkdir -m 700 -- "$RUN_DIR" || {
        terminal_partial "A fresh private report directory could not be created under $OUTPUT_ROOT"
        return 1
    }
    REPORT="$RUN_DIR/report.txt"
    JSON_REPORT="$RUN_DIR/report.json"
    CHECKSUM="$REPORT.sha256"
}

json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr '\r\n' '  '
}

checksum_report() {
    if command -v sha256sum >/dev/null 2>&1; then
        digest=$(sha256sum "$REPORT" | awk 'NR == 1 { print $1; exit }')
        printf '%s  %s\n' "$digest" "$REPORT" > "$CHECKSUM"
        chmod 600 "$CHECKSUM"
    else
        digest="not-checked-sha256sum-unavailable"
    fi
}

print_result() {
    completeness=$1
    next_step=$2
    size=$(wc -c < "$REPORT" | tr -d ' ')
    printf '%s\n' "NCT diagnostic complete. Nothing was restarted, reset, changed, or uploaded."
    printf '%s\n' "Report: $REPORT"
    printf '%s\n' "JSON: $JSON_REPORT"
    printf '%s\n' "Size: $size bytes"
    printf '%s\n' "SHA-256: $digest"
    [ -f "$CHECKSUM" ] && printf '%s\n' "Checksum file: $CHECKSUM"
    printf '%s\n' "Report completeness: $completeness"
    printf '%s\n' "Next step: $next_step"
}

partial_report() {
    reason=$1
    details=${2:-}
    next_step=${3:-"Keep the current container and data unchanged. Resolve the stated access or selection problem, then run this command again."}
    {
        printf '%s\n' "NCT READ-ONLY DIAGNOSTIC REPORT"
        printf '\n%s\n%s\n' "What happened" "-------------"
        printf '%s\n' "Report completeness: partial"
        printf '%s\n' "Not checked — $reason"
        [ -z "$details" ] || printf '%s\n' "$details"
        printf '%s\n' "This command did not restart, stop, reset, repair, migrate, or change NCT."
        printf '\n%s\n%s\n' "What is safe to do next" "-----------------------"
        printf '%s\n' "$next_step"
        printf '%s\n' "Do not delete containers, data, locks, WAL files, evidence, or database rows during diagnosis."
        printf '\n%s\n%s\n' "Privacy" "-------"
        printf '%s\n' "Passwords, tokens, environment values, raw logs, raw device configurations, raw evidence, and raw database rows are excluded."
        printf '%s\n' "Container names and host paths may still be sensitive. Review this report before sharing it."
        printf '%s\n' "The report stayed on this host; nothing was uploaded."
        printf '\n%s\n' "Rerun: sh scripts/nct-diagnostic-report.sh --container $CONTAINER --output-dir $OUTPUT_ROOT"
    } > "$REPORT"
    chmod 600 "$REPORT"
    printf '{\n  "report_contract": "nct-read-only-diagnostic:1",\n  "completeness": "partial",\n  "reason": "%s",\n  "details": "%s",\n  "next_step": "%s",\n  "raw_logs_retained": false\n}\n' \
        "$(json_escape "$reason")" "$(json_escape "$details")" "$(json_escape "$next_step")" > "$JSON_REPORT"
    chmod 600 "$JSON_REPORT"
    checksum_report
    print_result "partial" "$next_step"
}

helper_cleanup_failure() {
    helper_name=$1
    PRESERVE_PROBE=1
    partial_report \
        "Cleanup could not be verified for diagnostic helper '$helper_name'. Its private snapshot and probe workspace may still exist." \
        "Private probe workspace retained at: $PROBE" \
        "Keep NCT unchanged. Have an administrator confirm whether helper '$helper_name' exists, remove only that helper if present, confirm it is absent, then remove the retained private probe workspace '$PROBE' and run the diagnostic again."
}

if path_has_symlink_component "$OUTPUT_ROOT"; then
    printf '%s\n' "HALT: --output-dir may not use a symbolic-link path component." >&2
    exit 2
fi
if [ -e "$OUTPUT_ROOT" ] && [ ! -d "$OUTPUT_ROOT" ]; then
    printf '%s\n' "HALT: --output-dir must name a directory." >&2
    exit 2
fi
if ! command -v timeout >/dev/null 2>&1; then
    terminal_partial "The required timeout command is unavailable, so Docker cannot be queried with a safe deadline."
    exit 1
fi
if ! command -v docker >/dev/null 2>&1; then
    terminal_partial "Docker is not installed or not on this shell's PATH."
    exit 1
fi
if ! docker_probe info >/dev/null 2>&1; then
    terminal_partial "Docker access was denied, unavailable, or did not respond within ${DOCKER_PROBE_TIMEOUT} seconds."
    exit 1
fi

PROBE=$(mktemp -d "${TMPDIR:-/tmp}/nct-diagnostic.XXXXXX") || {
    terminal_partial "A private temporary probe directory could not be created."
    exit 1
}
chmod 700 "$PROBE"

if ! docker_probe inspect "$CONTAINER" >/dev/null 2>&1; then
    candidates=$(docker_probe ps -a --format '{{.Names}}' 2>/dev/null | grep -i 'nct' | head -20 || true)
    if [ -n "$candidates" ]; then
        details="Container '$CONTAINER' was not found. Possible NCT container names (no selection was guessed): $(printf '%s' "$candidates" | tr '\n' ' ')"
    else
        details="Container '$CONTAINER' was not found and no NCT-named candidates were visible."
    fi
    terminal_partial "The requested container could not be selected." "$details"
    exit 1
fi

capture_state() {
    destination=$1
    docker_probe inspect --format 'CONTAINER_ID={{.Id}}
STATE={{.State.Status}}
HEALTH={{with index .State "Health"}}{{.Status}}{{else}}none{{end}}
RESTART_COUNT={{.RestartCount}}
EXIT_CODE={{.State.ExitCode}}
OOM_KILLED={{.State.OOMKilled}}
STARTED_AT={{.State.StartedAt}}
FINISHED_AT={{.State.FinishedAt}}
IMAGE_ID={{.Image}}' "$CONTAINER" > "$destination"
}

capture_state "$PROBE/container-before.env" || {
    terminal_partial "The selected container changed or Docker timed out before its saved state could be read."
    exit 1
}
docker_probe version --format 'Server {{.Server.Version}} / API {{.Server.APIVersion}}' > "$PROBE/docker-version.txt" 2>/dev/null || true
docker_probe inspect --format '{{json .Mounts}}' "$CONTAINER" > "$PROBE/mounts.json" 2>> "$PROBE/probe-errors.txt" || true
docker_probe inspect --format '{{json .HostConfig.PortBindings}}' "$CONTAINER" > "$PROBE/ports.json" 2>> "$PROBE/probe-errors.txt" || true
docker_probe inspect --format '{{json .HostConfig.RestartPolicy}}' "$CONTAINER" > "$PROBE/restart-policy.json" 2>> "$PROBE/probe-errors.txt" || true
docker_probe logs --tail 400 "$CONTAINER" 2>&1 | tail -c 262144 > "$PROBE/logs.raw" || true

data_count=$(docker_probe inspect --format '{{range .Mounts}}{{if eq .Destination "/data"}}x{{println}}{{end}}{{end}}' "$CONTAINER" | awk 'NF { count++ } END { print count + 0 }') || {
    terminal_partial "Docker timed out while NCT data storage was being identified."
    exit 1
}
if [ "$data_count" -ne 1 ]; then
    terminal_partial "The saved container has $data_count mounts for /data; exactly one is required. No mount was guessed."
    exit 1
fi
data_type=$(docker_probe inspect --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Type}}{{end}}{{end}}' "$CONTAINER") || {
    terminal_partial "Docker timed out while the NCT data-storage type was being read."
    exit 1
}
data_source=$(docker_probe inspect --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Source}}{{end}}{{end}}' "$CONTAINER") || {
    terminal_partial "Docker timed out while the NCT data-storage location was being read."
    exit 1
}
data_name=$(docker_probe inspect --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Name}}{{end}}{{end}}' "$CONTAINER") || {
    terminal_partial "Docker timed out while the NCT data-storage name was being read."
    exit 1
}
image_id=$(awk -F= '$1 == "IMAGE_ID" { print substr($0, index($0, "=") + 1); exit }' "$PROBE/container-before.env")

case "$data_type" in
    bind)
        case "$data_source" in /*) ;; *) terminal_partial "The /data bind source is unavailable or not absolute."; exit 1 ;; esac
        case "$data_source" in *','*) terminal_partial "The /data bind source cannot be represented safely."; exit 1 ;; esac
        if paths_overlap "$OUTPUT_ROOT" "$data_source"; then
            terminal_partial "The report root must be outside NCT retained data, and no report directory was created."
            exit 1
        fi
        DATA_MOUNT="type=bind,src=$data_source,dst=/data,readonly"
        ;;
    volume)
        case "$data_source" in /*) ;; *) terminal_partial "The /data volume backing location is unavailable or not absolute."; exit 1 ;; esac
        case "$data_source" in *','*) terminal_partial "The /data volume backing location cannot be represented safely."; exit 1 ;; esac
        case "$data_name" in *','*|'') terminal_partial "The /data volume name is unavailable or cannot be represented safely."; exit 1 ;; esac
        if paths_overlap "$OUTPUT_ROOT" "$data_source"; then
            terminal_partial "The report root must be outside NCT retained data, and no report directory was created."
            exit 1
        fi
        DATA_MOUNT="type=volume,src=$data_name,dst=/data,readonly"
        ;;
    *)
        terminal_partial "The /data mount type '$data_type' is not supported by the read-only diagnostic helper."
        exit 1
        ;;
esac

prepare_output || exit 1
timeout -k 2 10 df -Pk "$RUN_DIR" > "$PROBE/host-disk.txt" 2>/dev/null || true

if ! docker_probe image inspect "$image_id" >/dev/null 2>&1; then
    capture_state "$PROBE/container-after.env" || true
    partial_report "The exact image used by the saved container is no longer available locally."
    exit 1
fi

RUN_UID=$(id -u)
RUN_GID=$(id -g)
HELPER_TOKEN=$(date -u +%Y%m%dT%H%M%SZ)-$$
DB_HELPER_NAME="nct-diagnostic-db-$HELPER_TOKEN"
set +e
docker_helper run --name "$DB_HELPER_NAME" --rm --network none --read-only --user "$RUN_UID:$RUN_GID" \
    --cap-drop ALL --security-opt no-new-privileges --security-opt label=disable \
    --pids-limit 64 --memory 256m --cpus 1 --tmpfs /tmp:rw,noexec,nosuid,size=16m \
    --mount "$DATA_MOUNT" \
    --mount "type=bind,src=$SCRIPT_DIR/nct-diagnostic-report.py,dst=/opt/nct-diagnostic-report.py,readonly" \
    --mount "type=bind,src=$PROBE,dst=/probe" \
    --entrypoint python "$image_id" /opt/nct-diagnostic-report.py \
    --probe-dir /probe --data-root /data --database-only-output /probe/database.json \
    > "$PROBE/database-helper.out" 2>> "$PROBE/probe-errors.txt"
database_rc=$?
set -e
if remove_and_confirm_helper "$DB_HELPER_NAME"; then
    DB_HELPER_NAME=""
else
    helper_cleanup_failure "$DB_HELPER_NAME"
    exit 1
fi
[ "$database_rc" -eq 0 ] || printf '%s\n' "Read-only database helper was unavailable or timed out (exit $database_rc)." >> "$PROBE/probe-errors.txt"

capture_state "$PROBE/container-after.env" || printf '%s\n' "Container state after collection was unavailable." >> "$PROBE/probe-errors.txt"

set +e
RENDER_HELPER_NAME="nct-diagnostic-render-$HELPER_TOKEN"
render_output=$(docker_helper run --name "$RENDER_HELPER_NAME" --rm --network none --read-only --user "$RUN_UID:$RUN_GID" \
    --cap-drop ALL --security-opt no-new-privileges --security-opt label=disable \
    --pids-limit 64 --memory 256m --cpus 1 --tmpfs /tmp:rw,noexec,nosuid,size=16m \
    --mount "$DATA_MOUNT" \
    --mount "type=bind,src=$SCRIPT_DIR/nct-diagnostic-report.py,dst=/opt/nct-diagnostic-report.py,readonly" \
    --mount "type=bind,src=$PROBE,dst=/probe,readonly" \
    --mount "type=bind,src=$RUN_DIR,dst=/reports" \
    --entrypoint python "$image_id" /opt/nct-diagnostic-report.py \
    --probe-dir /probe --data-root /data --database-input /probe/database.json \
    --output /reports/report.txt --container "$CONTAINER" 2>> "$PROBE/probe-errors.txt")
render_rc=$?
set -e
if remove_and_confirm_helper "$RENDER_HELPER_NAME"; then
    RENDER_HELPER_NAME=""
else
    helper_cleanup_failure "$RENDER_HELPER_NAME"
    exit 1
fi
if [ "$render_rc" -ne 0 ] || [ ! -f "$REPORT" ] || [ ! -f "$JSON_REPORT" ]; then
    partial_report "The exact NCT image could not finish the private report (exit $render_rc). The container and data were not changed."
    exit 1
fi
chmod 600 "$REPORT" "$JSON_REPORT"
checksum_report
completeness=$(printf '%s\n' "$render_output" | sed -n 's/.*"completeness": "\([^"]*\)".*/\1/p' | head -1)
next_step=$(printf '%s\n' "$render_output" | sed -n 's/.*"next_step": "\([^"]*\)".*/\1/p' | head -1)
[ -n "$completeness" ] || completeness="partial"
[ -n "$next_step" ] || next_step="Preserve this report and have the NCT administrator review it before changing the installation."
print_result "$completeness" "$next_step"
