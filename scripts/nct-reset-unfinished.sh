#!/bin/sh
set -eu

NCT_LOCK_SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
. "$NCT_LOCK_SCRIPT_DIR/nct-maintenance-lock.sh"
nct_maintenance_lock "${NCT_PERSIST_ROOT:-/var/lib/nct}/deployment/maintenance.lock"
umask 077

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
CONTAINER="nct"
OUTPUT_ROOT="${NCT_RECOVERY_DIR:-/var/lib/nct/deployment/backups}"
ACTOR="administrator"
APPLY=no
ASSUME_YES=no
HOLD_STOPPED=no
PROBE_TIMEOUT="${NCT_RECOVERY_DOCKER_PROBE_TIMEOUT:-30}"
HELPER_TIMEOUT="${NCT_RECOVERY_DOCKER_HELPER_TIMEOUT:-3600}"

usage() {
    cat <<'EOF'
Create a verified cold backup, preview every unfinished work category, and
optionally apply the evidence-preserving repair.

Usage:
  sh scripts/nct-reset-unfinished.sh [--container NAME] [--output-dir ABSOLUTE_PATH]
      [--actor NAME] [--apply] [--yes]

Preview restores the exact prior runtime state after backup verification. Apply
requires the reviewed plan digest. Completed evidence is never deleted. The
--yes option is reserved for reviewed automation that has already verified and
recorded the plan digest; interactive operators should review and type the
displayed digest prefix.
The installed-build recovery coordinator may add --hold-stopped so an Apply
check remains stable until that same command starts the reviewed container.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --container) [ "$#" -ge 2 ] || exit 2; CONTAINER=$2; shift 2 ;;
        --output-dir) [ "$#" -ge 2 ] || exit 2; OUTPUT_ROOT=$2; shift 2 ;;
        --actor) [ "$#" -ge 2 ] || exit 2; ACTOR=$2; shift 2 ;;
        --apply) APPLY=yes; shift ;;
        --yes) ASSUME_YES=yes; shift ;;
        --hold-stopped) HOLD_STOPPED=yes; shift ;;
        -h|--help) usage; exit 0 ;;
        *) printf '%s\n' "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

case "$CONTAINER" in ''|*[!A-Za-z0-9_.-]*) echo "HALT: invalid container name" >&2; exit 2;; esac
case "$OUTPUT_ROOT" in /*) ;; *) echo "HALT: output directory must be absolute" >&2; exit 2;; esac
case "$OUTPUT_ROOT" in /|*'/../'*|*'/./'*|*/..|*/.) echo "HALT: unsafe output directory" >&2; exit 2;; esac
case "$PROBE_TIMEOUT:$HELPER_TIMEOUT" in *[!0-9:]*|0:*|*:0|:) echo "HALT: recovery timeouts must be positive seconds" >&2; exit 2;; esac
[ -n "$(printf '%s' "$ACTOR" | tr -d '[:space:]')" ] || { echo "HALT: actor is required" >&2; exit 2; }
for tool in docker timeout realpath sha256sum tar cmp; do
    command -v "$tool" >/dev/null 2>&1 || { echo "HALT: $tool is required" >&2; exit 2; }
done

docker_probe() { timeout -k 5 "$PROBE_TIMEOUT" docker "$@"; }
docker_helper() { timeout -k 10 "$HELPER_TIMEOUT" docker "$@"; }
paths_overlap() {
    left=${1%/}; right=${2%/}
    [ "$left" = "$right" ] && return 0
    case "$left/" in "$right/"*) return 0;; esac
    case "$right/" in "$left/"*) return 0;; esac
    return 1
}

docker_probe inspect "$CONTAINER" >/dev/null 2>&1 || { echo "HALT: NCT container not found" >&2; exit 2; }
image=$(docker_probe inspect --format '{{.Image}}' "$CONTAINER")
image_ref=$(docker_probe inspect --format '{{.Config.Image}}' "$CONTAINER")
old_restart=$(docker_probe inspect --format '{{.HostConfig.RestartPolicy.Name}}' "$CONTAINER")
old_restart_max=$(docker_probe inspect --format '{{.HostConfig.RestartPolicy.MaximumRetryCount}}' "$CONTAINER")
old_state=$(docker_probe inspect --format '{{.State.Status}}' "$CONTAINER")
case "$old_state" in running|restarting|exited|created) ;; *) echo "HALT: unsupported container state: $old_state" >&2; exit 2;; esac

mount_lines=$(docker_probe inspect --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Type}}|{{if eq .Type "volume"}}{{.Name}}{{else}}{{.Source}}{{end}}{{"\n"}}{{end}}{{end}}' "$CONTAINER")
[ "$(printf '%s\n' "$mount_lines" | sed '/^$/d' | wc -l | tr -d ' ')" = "1" ] || { echo "HALT: expected exactly one /data mount" >&2; exit 2; }
mount_type=${mount_lines%%|*}
data_source=${mount_lines#*|}
case "$mount_type" in bind|volume) ;; *) echo "HALT: unsupported /data mount type" >&2; exit 2;; esac
if [ "$mount_type" = bind ]; then
    data_path=$(realpath -m -- "$data_source")
else
    data_path=$(docker_probe volume inspect --format '{{.Mountpoint}}' "$data_source")
    [ -n "$data_path" ] || { echo "HALT: named-volume backing path is unavailable" >&2; exit 2; }
    data_path=$(realpath -m -- "$data_path")
fi
output_path=$(realpath -m -- "$OUTPUT_ROOT")
paths_overlap "$data_path" "$output_path" && { echo "HALT: backup output overlaps retained NCT data" >&2; exit 2; }

target_id=$(docker_probe inspect --format '{{.Id}}' "$CONTAINER")
sharing=""
for candidate in $(docker_probe ps -aq); do
    candidate_id=$(docker_probe inspect --format '{{.Id}}' "$candidate")
    [ "$candidate_id" = "$target_id" ] && continue
    candidate_name=$(docker_probe inspect --format '{{.Name}}' "$candidate" | sed 's#^/##')
    candidate_mounts=$(docker_probe inspect --format '{{range .Mounts}}{{.Type}}|{{.Name}}|{{.Source}}|{{.Destination}}{{"\n"}}{{end}}' "$candidate")
    old_ifs=$IFS
    IFS='
'
    for candidate_mount in $candidate_mounts; do
        candidate_type=$(printf '%s' "$candidate_mount" | cut -d'|' -f1)
        candidate_volume=$(printf '%s' "$candidate_mount" | cut -d'|' -f2)
        candidate_source=$(printf '%s' "$candidate_mount" | cut -d'|' -f3)
        [ -n "$candidate_type" ] || continue
        shared=no
        if [ "$mount_type" = volume ] && [ "$candidate_type" = volume ] && [ "$candidate_volume" = "$data_source" ]; then
            shared=yes
        elif [ "$candidate_type" = bind ]; then
            candidate_path=$(realpath -m -- "$candidate_source")
            paths_overlap "$data_path" "$candidate_path" && shared=yes
        elif [ "$candidate_type" = volume ]; then
            candidate_path=$(docker_probe volume inspect --format '{{.Mountpoint}}' "$candidate_volume")
            candidate_path=$(realpath -m -- "$candidate_path")
            paths_overlap "$data_path" "$candidate_path" && shared=yes
        fi
        if [ "$shared" = yes ]; then
            sharing="${sharing}${sharing:+, }$candidate_name"
            break
        fi
    done
    IFS=$old_ifs
done
if [ -n "$sharing" ]; then
    echo "HALT: another container has an overlapping NCT data mount: $sharing" >&2
    echo "Stop or remove that container, then create a new recovery preview." >&2
    exit 2
fi

mkdir -p "$output_path"
OUTPUT_ROOT=$(CDPATH= cd -- "$output_path" && pwd -P)
timestamp=$(date -u +%Y%m%dT%H%M%SZ)
run_dir="$OUTPUT_ROOT/scan-work-recovery-$timestamp"
mkdir -m 0700 "$run_dir"
backup_name="nct-data-before-scan-recovery-$timestamp.tar.gz"
backup="$run_dir/$backup_name"
source_inventory="$run_dir/source-inventory.sha256"
restored_inventory="$run_dir/restored-inventory.sha256"
plan="$run_dir/scan-work-plan.json"
receipt="$run_dir/host-recovery.receipt"
handoff_receipt="$run_dir/coordinator-handoff.receipt"
verify_dir="$run_dir/verified-restore"
helper="nct-scan-recovery-$timestamp-$$"
runtime_restored=no
cleanup_blocked=no

restart_value=$old_restart
if [ "$old_restart" = on-failure ] && [ "${old_restart_max:-0}" -gt 0 ]; then restart_value="on-failure:$old_restart_max"; fi
restore_runtime() {
    [ "$runtime_restored" = no ] || return 0
    docker_probe update --restart="${restart_value:-no}" "$CONTAINER" >/dev/null || { echo "HALT: could not restore the prior restart policy" >&2; return 1; }
    case "$old_state" in
        running|restarting) docker_probe start "$CONTAINER" >/dev/null || { echo "HALT: could not restart NCT" >&2; return 1; } ;;
        exited|created)
            if [ "$(docker_probe inspect --format '{{.State.Running}}' "$CONTAINER")" = true ]; then
                docker_probe stop --time 30 "$CONTAINER" >/dev/null || { echo "HALT: could not restore the stopped state" >&2; return 1; }
            fi ;;
    esac
    actual_policy=$(docker_probe inspect --format '{{.HostConfig.RestartPolicy.Name}}:{{.HostConfig.RestartPolicy.MaximumRetryCount}}' "$CONTAINER")
    [ "$actual_policy" = "$old_restart:$old_restart_max" ] || { echo "HALT: restart policy verification failed" >&2; return 1; }
    if [ "$old_state" = running ] || [ "$old_state" = restarting ]; then
        [ "$(docker_probe inspect --format '{{.State.Running}}' "$CONTAINER")" = true ] || { echo "HALT: NCT running-state verification failed" >&2; return 1; }
    fi
    runtime_restored=yes
}
remove_helper() {
    helper_ids=$(docker_probe ps -aq --no-trunc --filter "name=^/${helper}$") || return 1
    if [ -n "$helper_ids" ]; then
        docker_probe rm -f "$helper" >/dev/null || return 1
    fi
    helper_ids=$(docker_probe ps -aq --no-trunc --filter "name=^/${helper}$") || return 1
    [ -z "$helper_ids" ]
}
hold_nct_stopped() {
    held=yes
    docker_probe update --restart=no "$CONTAINER" >/dev/null || held=no
    running=$(docker_probe inspect --format '{{.State.Running}}' "$CONTAINER") || held=no
    if [ "$running" = true ]; then
        docker_probe stop --time 30 "$CONTAINER" >/dev/null || held=no
    fi
    policy=$(docker_probe inspect --format '{{.HostConfig.RestartPolicy.Name}}:{{.State.Running}}' "$CONTAINER") || held=no
    [ "$policy" = "no:false" ] || held=no
    [ "$held" = yes ]
}
finish_and_restore() {
    if ! remove_helper; then
        cleanup_blocked=yes
        echo "HALT: recovery helper absence could not be proven: $helper" >&2
        echo "NCT will remain stopped with automatic restart disabled. Confirm and remove only that helper, then restart NCT manually." >&2
        hold_nct_stopped || echo "HALT: verify NCT is stopped before taking any further action" >&2
        return 1
    fi
    if [ "$HOLD_STOPPED" = yes ]; then
        hold_nct_stopped || return 1
        runtime_restored=yes
    else
        restore_runtime
    fi
}
cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    [ "$status" -eq 0 ] || HOLD_STOPPED=no
    failed=no
    if [ "$cleanup_blocked" = yes ]; then
        remove_helper || true
        hold_nct_stopped || echo "HALT: verify NCT is stopped before taking any further action" >&2
        failed=yes
    elif ! finish_and_restore; then
        failed=yes
    fi
    [ "$failed" = no ] || [ "$status" -ne 0 ] || status=2
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

{
    printf 'container=%s\nimage_id=%s\nimage_ref=%s\nrestart_policy=%s\nrestart_max_retry=%s\nstate=%s\n' "$CONTAINER" "$image" "$image_ref" "$old_restart" "$old_restart_max" "$old_state"
    docker_probe inspect --format 'network_mode={{.HostConfig.NetworkMode}}{{"\n"}}port_bindings={{json .HostConfig.PortBindings}}{{"\n"}}mounts={{json .Mounts}}{{"\n"}}cap_add={{json .HostConfig.CapAdd}}{{"\n"}}privileged={{.HostConfig.Privileged}}' "$CONTAINER"
} > "$run_dir/container-runtime.txt"
chmod 600 "$run_dir/container-runtime.txt"

docker_probe update --restart=no "$CONTAINER" >/dev/null
if [ "$(docker_probe inspect --format '{{.State.Running}}' "$CONTAINER")" = true ]; then docker_probe stop --time 30 "$CONTAINER" >/dev/null; fi
[ "$(docker_probe inspect --format '{{.State.Running}}' "$CONTAINER")" = false ] || { echo "HALT: NCT did not remain stopped" >&2; exit 2; }

if [ "$mount_type" = bind ]; then data_mount="$data_path:/data:ro"; else data_mount="$data_source:/data:ro"; fi
set -- --network none --read-only --cap-drop ALL --security-opt no-new-privileges --security-opt label=disable --pids-limit 128 --tmpfs /tmp:rw,noexec,nosuid,size=16m
docker_helper run --name "$helper" --rm "$@" -v "$data_mount" "$image" sh -c 'cd /data && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum' > "$source_inventory"
docker_helper run --name "$helper" --rm "$@" -v "$data_mount" -v "$run_dir:/backup" "$image" sh -c "cd /data && tar -czf /backup/$backup_name ."
[ -s "$backup" ] || { echo "HALT: cold backup was not created" >&2; exit 2; }
sha256sum "$backup" > "$backup.sha256"
mkdir -m 0700 "$verify_dir"
tar -C "$verify_dir" -xzf "$backup"
(cd "$verify_dir" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum) > "$restored_inventory"
cmp -s "$source_inventory" "$restored_inventory" || { echo "HALT: independently extracted backup does not match retained data" >&2; exit 2; }

plan_status=0
docker_helper run --name "$helper" --rm "$@" -e PYTHONPATH=/app -v "$verify_dir:/data" -v "$SCRIPT_DIR/nct-reset-unfinished.py:/opt/nct-reset-unfinished.py:ro" -v "$run_dir:/recovery" --entrypoint python "$image" /opt/nct-reset-unfinished.py --data-dir /data --output /recovery/scan-work-plan.json || plan_status=$?
if [ "$plan_status" -ne 0 ]; then
    echo "HALT: the final stopped-container plan refused recovery"
    [ ! -f "$plan" ] || cat "$plan" 2>/dev/null || true
    exit 2
fi
plan_digest=$(docker_helper run --name "$helper" --rm "$@" -v "$run_dir:/recovery:ro" --entrypoint python "$image" -c 'import json;print(json.load(open("/recovery/scan-work-plan.json"))["plan_digest"])')
backup_sha=$(cut -d' ' -f1 "$backup.sha256")
echo "Cold backup verified: $backup"
echo "Final recovery plan: $plan"
echo "Plan digest: $plan_digest"
if [ "$APPLY" != yes ]; then
    echo "Preview only. No saved work record was changed."
    finish_and_restore
    if [ "$HOLD_STOPPED" = yes ]; then
        printf 'contract=nct-stopped-work-handoff:1\nsafe_to_restore=true\ncontainer_id=%s\nplan_digest=%s\n' "$target_id" "$plan_digest" > "$handoff_receipt"
        chmod 600 "$handoff_receipt"
        echo "The exact container is held stopped with automatic restart disabled for the installed-build recovery coordinator."
        echo "Coordinator handoff: $handoff_receipt"
    fi
    exit 0
fi
if [ "$ASSUME_YES" != yes ]; then
    printf '%s' "Type the first 12 characters of the plan digest to apply: "
    read -r answer
    [ "$answer" = "$(printf '%s' "$plan_digest" | cut -c1-12)" ] || { echo "Recovery cancelled. The verified backup and plan were retained."; exit 2; }
fi

if [ "$mount_type" = bind ]; then data_rw="$data_path:/data"; else data_rw="$data_source:/data"; fi
docker_helper run --name "$helper" --rm "$@" -e PYTHONPATH=/app -v "$data_rw" -v "$SCRIPT_DIR/nct-reset-unfinished.py:/opt/nct-reset-unfinished.py:ro" --entrypoint python "$image" /opt/nct-reset-unfinished.py --data-dir /data --apply --plan-digest "$plan_digest" --actor "$ACTOR" --backup-path "$backup" --backup-sha256 "$backup_sha"
printf 'completed=%s\ncontainer=%s\nimage_id=%s\nimage_ref=%s\nplan=%s\nplan_digest=%s\nbackup=%s\nbackup_sha256=%s\nactor=%s\nautomatic_contact=false\n' "$(date -u +%FT%TZ)" "$CONTAINER" "$image" "$image_ref" "$plan" "$plan_digest" "$backup" "$backup_sha" "$ACTOR" > "$receipt"
chmod 600 "$receipt"
finish_and_restore
echo "Recovery applied. NCT restarted with Nmap, Arkime, device contact, local processing, and storage maintenance paused separately for administrator review."
echo "Host receipt: $receipt"
echo "Open Active Scans and review Unfinished work self-check before resuming any category."
