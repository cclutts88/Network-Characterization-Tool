#!/bin/sh
set -eu
umask 077

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
CONTAINER="nct"
OUTPUT_ROOT="${NCT_INSTALLED_RECOVERY_DIR:-/var/lib/nct/deployment/installed-recovery}"
APPLY=no
PROBE_TIMEOUT="${NCT_RECOVERY_DOCKER_PROBE_TIMEOUT:-30}"
HEALTH_TIMEOUT="${NCT_INSTALLED_RECOVERY_HEALTH_TIMEOUT:-90}"

usage() {
    cat <<'EOF'
Inspect and recover the exact installed NCT container without replacing its
image, port, data storage, accounts, evidence, settings, or restart policy.

Usage:
  sh scripts/nct-recover-installed.sh [--container NAME]
      [--output-dir ABSOLUTE_PATH] [--apply]

The first run is a preview. It creates a read-only diagnostic plus a verified
cold backup and stopped-data work plan. If no unfinished work blocks recovery,
run the displayed command with --apply to start and restart-test the exact saved
container. If unfinished work exists, use the separately displayed repair
command. A blank installation is never created by this script.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --container) [ "$#" -ge 2 ] || exit 2; CONTAINER=$2; shift 2 ;;
        --output-dir) [ "$#" -ge 2 ] || exit 2; OUTPUT_ROOT=$2; shift 2 ;;
        --apply) APPLY=yes; shift ;;
        -h|--help) usage; exit 0 ;;
        *) printf '%s\n' "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

case "$CONTAINER" in ''|*[!A-Za-z0-9_.-]*) echo "HALT: invalid container name" >&2; exit 2;; esac
case "$OUTPUT_ROOT" in /*) ;; *) echo "HALT: output directory must be absolute" >&2; exit 2;; esac
case "$OUTPUT_ROOT" in /|*'/../'*|*'/./'*|*/..|*/.) echo "HALT: unsafe output directory" >&2; exit 2;; esac
case "$PROBE_TIMEOUT:$HEALTH_TIMEOUT" in *[!0-9:]*|0:*|*:0|:) echo "HALT: timeouts must be positive seconds" >&2; exit 2;; esac
for tool in docker timeout realpath sha256sum grep; do
    command -v "$tool" >/dev/null 2>&1 || { echo "HALT: $tool is required" >&2; exit 2; }
done
[ "$(id -u)" -eq 0 ] || { echo "HALT: run this recovery as root" >&2; exit 2; }
[ -x "$SCRIPT_DIR/nct-diagnostic-report.sh" ] || { echo "HALT: diagnostic script is missing" >&2; exit 2; }
[ -x "$SCRIPT_DIR/nct-reset-unfinished.sh" ] || { echo "HALT: unfinished-work repair script is missing" >&2; exit 2; }

docker_probe() { timeout -k 5 "$PROBE_TIMEOUT" docker "$@"; }
paths_overlap() {
    left=${1%/}; right=${2%/}
    [ "$left" = "$right" ] && return 0
    case "$left/" in "$right/"*) return 0;; esac
    case "$right/" in "$left/"*) return 0;; esac
    return 1
}
docker_probe info >/dev/null 2>&1 || { echo "HALT: Docker is unavailable" >&2; exit 2; }
docker_probe inspect "$CONTAINER" >/dev/null 2>&1 || { echo "HALT: NCT container not found: $CONTAINER" >&2; exit 2; }

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
paths_overlap "$data_path" "$output_path" && { echo "HALT: recovery output overlaps retained NCT data" >&2; exit 2; }
pre_id=$(docker_probe inspect --format '{{.Id}}' "$CONTAINER")
pre_mounts=$(docker_probe inspect --format '{{json .Mounts}}' "$CONTAINER")

mkdir -p "$output_path"
chmod 700 "$output_path" || { echo "HALT: recovery output permissions could not be restricted" >&2; exit 2; }
OUTPUT_ROOT=$(CDPATH= cd -- "$output_path" && pwd -P)
timestamp=$(date -u +%Y%m%dT%H%M%SZ)
run_dir="$OUTPUT_ROOT/installed-recovery-$timestamp-$$"
mkdir -m 0700 "$run_dir"
diagnostic_root="$run_dir/diagnostic"
work_root="$run_dir/stopped-work-check"
mkdir -m 0700 "$diagnostic_root" "$work_root"

echo "Step 1 of 3: diagnosing the saved installation without starting it."
diagnostic_status=0
"$SCRIPT_DIR/nct-diagnostic-report.sh" --container "$CONTAINER" --output-dir "$diagnostic_root" || diagnostic_status=$?
[ "$diagnostic_status" -eq 0 ] || {
    echo "HALT: the read-only diagnostic did not complete safely." >&2
    echo "Preserve $diagnostic_root and do not reinstall, reset, or bypass the failed check." >&2
    exit 2
}

[ "$(docker_probe inspect --format '{{.Id}}' "$CONTAINER")" = "$pre_id" ] || { echo "HALT: container identity changed during diagnosis" >&2; exit 2; }
[ "$(docker_probe inspect --format '{{json .Mounts}}' "$CONTAINER")" = "$pre_mounts" ] || { echo "HALT: container mounts changed during diagnosis" >&2; exit 2; }

before_inspect="$run_dir/container-before.json"
docker_probe inspect "$CONTAINER" > "$before_inspect"
chmod 600 "$before_inspect"
image_id=$(docker_probe inspect --format '{{.Image}}' "$CONTAINER")
image_ref=$(docker_probe inspect --format '{{.Config.Image}}' "$CONTAINER")
before_id=$(docker_probe inspect --format '{{.Id}}' "$CONTAINER")
before_restart=$(docker_probe inspect --format '{{.HostConfig.RestartPolicy.Name}}' "$CONTAINER")
before_restart_max=$(docker_probe inspect --format '{{.HostConfig.RestartPolicy.MaximumRetryCount}}' "$CONTAINER")
before_ports=$(docker_probe inspect --format '{{json .HostConfig.PortBindings}}' "$CONTAINER")
before_mounts=$(docker_probe inspect --format '{{json .Mounts}}' "$CONTAINER")
before_state=$(docker_probe inspect --format '{{.State.Status}}' "$CONTAINER")
case "$before_state" in running|restarting|exited|created) ;; *) echo "HALT: unsupported container state: $before_state" >&2; exit 2;; esac
docker_probe image inspect "$image_id" >/dev/null 2>&1 || { echo "HALT: exact installed image is not available locally" >&2; exit 2; }
restart_value=$before_restart
if [ "$before_restart" = on-failure ] && [ "${before_restart_max:-0}" -gt 0 ]; then restart_value="on-failure:$before_restart_max"; fi
restore_before_action=no
action_started=no
handoff_active=no
target_held=no
hold_target_stopped() {
    held=yes
    docker_probe update --restart=no "$CONTAINER" >/dev/null || held=no
    running=$(docker_probe inspect --format '{{.State.Running}}' "$CONTAINER") || { held=no; running=unknown; }
    if [ "$running" = true ]; then
        docker_probe stop --time 30 "$CONTAINER" >/dev/null || held=no
    fi
    final_state=$(docker_probe inspect --format '{{.HostConfig.RestartPolicy.Name}}:{{.HostConfig.RestartPolicy.MaximumRetryCount}}:{{.State.Running}}' "$CONTAINER") || { held=no; final_state=unknown; }
    [ "$final_state" = "no:0:false" ] || held=no
    if [ "$held" = yes ]; then target_held=yes; return 0; fi
    target_held=no
    return 1
}
restore_original_runtime() {
    docker_probe update --restart="${restart_value:-no}" "$CONTAINER" >/dev/null || return 1
    case "$before_state" in
        running|restarting) docker_probe start "$CONTAINER" >/dev/null || return 1 ;;
        exited|created)
            if [ "$(docker_probe inspect --format '{{.State.Running}}' "$CONTAINER")" = true ]; then
                docker_probe stop --time 30 "$CONTAINER" >/dev/null || return 1
            fi ;;
    esac
    [ "$(docker_probe inspect --format '{{.HostConfig.RestartPolicy.Name}}:{{.HostConfig.RestartPolicy.MaximumRetryCount}}' "$CONTAINER")" = "$before_restart:$before_restart_max" ]
}

port_lines=$(docker_probe inspect --format '{{range $port,$items := .HostConfig.PortBindings}}{{if or (eq $port "8080/tcp") (eq $port "8445/tcp")}}{{range $items}}{{printf "%s|%s\n" $port .HostPort}}{{end}}{{end}}{{end}}' "$CONTAINER" | tr -d '\r' | sed '/^$/d' | sort -u)
port_count=$(printf '%s\n' "$port_lines" | sed '/^$/d' | wc -l | tr -d ' ')
[ "$port_count" = "1" ] || {
    echo "HALT: expected exactly one distinct saved NCT listener and host port; found $port_count" >&2
    echo "No container or data was changed. Review the diagnostic report in $diagnostic_root." >&2
    exit 2
}
listener_pair=$(printf '%s\n' "$port_lines" | sed -n '1p')
container_listener=${listener_pair%%|*}
container_listener=${container_listener%/tcp}
case "$container_listener" in 8080) health_scheme=http ;; 8445) health_scheme=https ;; *) echo "HALT: unsupported saved NCT listener" >&2; exit 2;; esac

helper=""
cleanup_helper() {
    [ -n "${helper:-}" ] || return 0
    helper_ids=$(docker_probe ps -aq --no-trunc --filter "name=^/${helper}$") || return 1
    if [ -n "$helper_ids" ]; then
        docker_probe rm -f "$helper" >/dev/null || return 1
    fi
    helper_ids=$(docker_probe ps -aq --no-trunc --filter "name=^/${helper}$") || return 1
    [ -z "$helper_ids" ]
}
cleanup_all() {
    status=$?
    trap - EXIT HUP INT TERM
    cleanup_ok=yes
    if ! cleanup_helper; then
        cleanup_ok=no
        echo "HALT: helper absence could not be proven: ${helper:-unknown}" >&2
        status=2
    fi
    if [ "$cleanup_ok" = yes ] && [ "$restore_before_action" = yes ]; then
        if ! restore_original_runtime; then
            echo "HALT: the reviewed runtime could not be restored after the preflight stopped." >&2
            hold_target_stopped || echo "HALT: NCT stopped state could not be proven; inspect Docker before any further action." >&2
            status=2
        fi
    elif { [ "$cleanup_ok" = no ] && [ "$restore_before_action" = yes ]; } || { [ "$status" -ne 0 ] && { [ "$action_started" = yes ] || [ "$handoff_active" = yes ]; }; }; then
        if hold_target_stopped; then
            echo "NCT is held stopped with automatic restart disabled. Preserve $run_dir." >&2
        else
            echo "HALT: NCT stopped state could not be proven; inspect Docker before any further action." >&2
        fi
        status=2
    fi
    exit "$status"
}
trap cleanup_all EXIT
trap 'exit 130' HUP INT TERM

echo "Step 2 of 3: creating a verified cold backup and inspecting stopped data."
work_status=0
if [ "$APPLY" = yes ]; then
    # Until the stopped-work helper produces its explicit safe handoff receipt,
    # interruption or cleanup uncertainty must leave NCT stopped.
    handoff_active=yes
    "$SCRIPT_DIR/nct-reset-unfinished.sh" --container "$CONTAINER" --output-dir "$work_root" --actor "installed-build recovery preview" --hold-stopped || work_status=$?
else
    "$SCRIPT_DIR/nct-reset-unfinished.sh" --container "$CONTAINER" --output-dir "$work_root" --actor "installed-build recovery preview" || work_status=$?
fi
[ "$work_status" -eq 0 ] || {
    echo "HALT: stopped data could not be backed up and inspected safely." >&2
    echo "Preserve $run_dir. Do not start a blank installation or bypass the work check." >&2
    exit 2
}
if [ "$APPLY" = yes ]; then
    handoff=$(find "$work_root" -type f -name coordinator-handoff.receipt -print | sort)
    [ "$(printf '%s\n' "$handoff" | sed '/^$/d' | wc -l | tr -d ' ')" = "1" ] || {
        echo "HALT: the stopped-work helper did not provide one explicit safe handoff receipt." >&2
        echo "NCT will remain stopped with automatic restart disabled until helper cleanup is reviewed." >&2
        exit 2
    }
    grep -Fqx 'contract=nct-stopped-work-handoff:1' "$handoff" || { echo "HALT: invalid stopped-work handoff contract" >&2; exit 2; }
    grep -Fqx 'safe_to_restore=true' "$handoff" || { echo "HALT: stopped-work handoff did not authorize restoration" >&2; exit 2; }
    grep -Fqx "container_id=$before_id" "$handoff" || { echo "HALT: stopped-work handoff names a different container" >&2; exit 2; }
fi
plan=$(find "$work_root" -type f -name scan-work-plan.json -print | sort | tail -1)
[ -n "$plan" ] && [ -f "$plan" ] || { echo "HALT: stopped-data work plan was not produced" >&2; exit 2; }
plan_dir=$(dirname "$plan")
plan_name=$(basename "$plan")
helper="nct-installed-recovery-plan-$timestamp-$$"
plan_values=$(timeout -k 5 "$PROBE_TIMEOUT" docker run --name "$helper" --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --security-opt label=disable --pids-limit 64 --tmpfs /tmp:rw,noexec,nosuid,size=8m -v "$plan_dir:/plan:ro" --entrypoint python "$image_id" -c 'import json; p=json.load(open("/plan/'"$plan_name"'")); print("yes" if p.get("safe_to_apply") else "no"); print(int(p.get("affected_count") or 0)); print(p.get("plan_digest") or "")')
cleanup_helper || { echo "HALT: plan helper absence could not be proven: $helper" >&2; exit 2; }
helper=""
safe_to_apply=$(printf '%s\n' "$plan_values" | sed -n '1p')
affected_count=$(printf '%s\n' "$plan_values" | sed -n '2p')
plan_digest=$(printf '%s\n' "$plan_values" | sed -n '3p')
[ "$safe_to_apply" = yes ] || {
    echo "HALT: the stopped-data plan found an unsafe or unreadable condition." >&2
    echo "Preserve $plan and the verified backup beside it. Do not bypass this result." >&2
    exit 2
}
case "$affected_count" in ''|*[!0-9]*) echo "HALT: invalid stopped-data plan" >&2; exit 2;; esac
[ "$APPLY" != yes ] || grep -Fqx "plan_digest=$plan_digest" "$handoff" || { echo "HALT: stopped-work handoff does not match the reviewed plan" >&2; exit 2; }
if [ "$APPLY" = yes ]; then
    handoff_active=no
    restore_before_action=yes
fi

runtime_record="$run_dir/exact-installed-runtime.txt"
{
    printf 'container=%s\ncontainer_id=%s\nimage_id=%s\nimage_ref=%s\nstate=%s\nrestart_policy=%s\nrestart_max_retry=%s\nport_bindings=%s\nmounts=%s\nplan=%s\nplan_digest=%s\naffected_work=%s\n' \
        "$CONTAINER" "$before_id" "$image_id" "$image_ref" "$before_state" "$before_restart" "$before_restart_max" "$before_ports" "$before_mounts" "$plan" "$plan_digest" "$affected_count"
} > "$runtime_record"
chmod 600 "$runtime_record"

if [ "$affected_count" -gt 0 ]; then
    echo "HALT: $affected_count unfinished work record(s) require evidence-preserving repair before restart." >&2
    echo "Review $plan, then run:" >&2
    echo "  sh scripts/nct-reset-unfinished.sh --container $CONTAINER --output-dir $work_root --apply" >&2
    echo "The installed image, data, ports, accounts, and evidence were not replaced." >&2
    exit 3
fi

if [ "$APPLY" != yes ]; then
    echo "Recovery preview is clear. No work record or installed setting was changed."
    echo "Exact runtime record: $runtime_record"
    echo "Verified stopped-data plan: $plan"
    echo "To recover and restart-test this exact installation, run:"
    echo "  sh scripts/nct-recover-installed.sh --container $CONTAINER --output-dir $OUTPUT_ROOT --apply"
    exit 0
fi

echo "Step 3 of 3: starting and restart-testing the exact saved installation."
echo "NOTICE: starting normal NCT resumes enabled schedules, connector polling, and other saved automation."
echo "Review those saved settings before --apply when automatic network contact is not intended."
restore_before_action=no
action_started=yes
hold_failed_recovery() {
    echo "HALT: $1" >&2
    if hold_target_stopped; then
        echo "NCT is held stopped with automatic restart disabled. Preserve $run_dir and the verified cold backup." >&2
    else
        echo "HALT: NCT stopped state could not be proven; inspect Docker before any further action. Preserve $run_dir." >&2
    fi
    exit 2
}
docker_probe update --restart=no "$CONTAINER" >/dev/null || hold_failed_recovery "automatic restart could not be disabled."
running=$(docker_probe inspect --format '{{.State.Running}}' "$CONTAINER") || hold_failed_recovery "container state could not be read."
if [ "$running" = true ]; then
    docker_probe stop --time 30 "$CONTAINER" >/dev/null || hold_failed_recovery "the container could not be stopped."
fi
docker_probe update --restart="${restart_value:-no}" "$CONTAINER" >/dev/null || hold_failed_recovery "the exact restart policy could not be restored."
docker_probe start "$CONTAINER" >/dev/null || hold_failed_recovery "the exact container could not be started."

wait_for_health() {
    deadline=$(( $(date +%s) + HEALTH_TIMEOUT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if timeout -k 2 8 docker exec "$CONTAINER" python -c 'import json,ssl,sys,urllib.request; scheme,port=sys.argv[1:3]; context=ssl._create_unverified_context() if scheme=="https" else None; data=json.load(urllib.request.urlopen(f"{scheme}://127.0.0.1:{port}/health",timeout=3,context=context)); raise SystemExit(0 if data.get("status")=="ok" else 1)' "$health_scheme" "$container_listener" >/dev/null 2>&1; then
            return 0
        fi
        sleep 2
    done
    return 1
}
if ! wait_for_health; then
    hold_failed_recovery "the exact installed container did not become healthy."
fi

actual_id=$(docker_probe inspect --format '{{.Id}}' "$CONTAINER") || hold_failed_recovery "container identity could not be read."
actual_image=$(docker_probe inspect --format '{{.Image}}' "$CONTAINER") || hold_failed_recovery "image identity could not be read."
actual_ports=$(docker_probe inspect --format '{{json .HostConfig.PortBindings}}' "$CONTAINER") || hold_failed_recovery "saved ports could not be read."
actual_mounts=$(docker_probe inspect --format '{{json .Mounts}}' "$CONTAINER") || hold_failed_recovery "saved mounts could not be read."
actual_restart=$(docker_probe inspect --format '{{.HostConfig.RestartPolicy.Name}}:{{.HostConfig.RestartPolicy.MaximumRetryCount}}' "$CONTAINER") || hold_failed_recovery "restart policy could not be read."
[ "$actual_id" = "$before_id" ] || hold_failed_recovery "container identity changed."
[ "$actual_image" = "$image_id" ] || hold_failed_recovery "image identity changed."
[ "$actual_ports" = "$before_ports" ] || hold_failed_recovery "saved ports changed."
[ "$actual_mounts" = "$before_mounts" ] || hold_failed_recovery "data mounts changed."
[ "$actual_restart" = "$before_restart:$before_restart_max" ] || hold_failed_recovery "restart policy changed."

helper="nct-installed-recovery-build-$timestamp-$$"
expected_build=$(timeout -k 5 "$PROBE_TIMEOUT" docker run --name "$helper" --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --security-opt label=disable --pids-limit 64 --tmpfs /tmp:rw,noexec,nosuid,size=8m --entrypoint python "$image_id" -c 'from app.build_info import BUILD_ID,BUILD_COMMIT; print(BUILD_ID+"|"+BUILD_COMMIT)') || hold_failed_recovery "exact installed-image build identity could not be read."
cleanup_helper || hold_failed_recovery "build helper absence could not be proven: $helper."
helper=""
actual_build=$(timeout -k 5 "$PROBE_TIMEOUT" docker exec "$CONTAINER" python -c 'from app.build_info import BUILD_ID,BUILD_COMMIT; print(BUILD_ID+"|"+BUILD_COMMIT)') || hold_failed_recovery "running build identity could not be read."
[ "$actual_build" = "$expected_build" ] || hold_failed_recovery "running build identity does not match the exact installed image."

docker_probe restart --time 30 "$CONTAINER" >/dev/null || hold_failed_recovery "the exact container could not complete its restart command."
if ! wait_for_health; then
    hold_failed_recovery "NCT failed the restart test."
fi
post_root="$run_dir/post-recovery-diagnostic"
mkdir -m 0700 "$post_root" || hold_failed_recovery "the post-recovery report directory could not be created."
"$SCRIPT_DIR/nct-diagnostic-report.sh" --container "$CONTAINER" --output-dir "$post_root" >/dev/null || hold_failed_recovery "the post-recovery diagnostic did not complete safely."
receipt="$run_dir/installed-recovery.receipt"
if ! {
    printf 'completed=%s\ncontainer=%s\ncontainer_id=%s\nimage_id=%s\nimage_ref=%s\nbuild=%s\nport_bindings=%s\nmounts=%s\nrestart_policy=%s\nrestart_max_retry=%s\nplan=%s\nplan_digest=%s\naffected_work=0\nhealth_verified=true\nrestart_cycle_verified=true\nenabled_automation_resume=normal_runtime\nautomatic_network_contact=possible\ncontroller_sign_in_verified=false\n' \
        "$(date -u +%FT%TZ)" "$CONTAINER" "$before_id" "$image_id" "$image_ref" "$actual_build" "$before_ports" "$before_mounts" "$before_restart" "$before_restart_max" "$plan" "$plan_digest"
} > "$receipt"; then hold_failed_recovery "the recovery receipt could not be written."; fi
chmod 600 "$receipt" || hold_failed_recovery "the recovery receipt permissions could not be restricted."
sha256sum "$receipt" > "$receipt.sha256" || hold_failed_recovery "the recovery receipt checksum could not be written."
echo "The exact installed NCT container is healthy and passed one restart cycle."
echo "No blank installation was created and no saved work record was changed."
echo "Enabled schedules and connectors resumed with normal NCT startup; review their status in the application."
echo "Recovery receipt: $receipt"
echo "Controller acceptance is complete only after an operator signs in and confirms retained history and evidence."
