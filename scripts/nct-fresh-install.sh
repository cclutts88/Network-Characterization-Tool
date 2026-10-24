#!/bin/sh
set -eu
umask 077

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
CONTAINER="nct"
OUTPUT_ROOT="${NCT_FRESH_INSTALL_DIR:-/var/lib/nct/deployment/fresh-installs}"
NEW_DATA_SOURCE=""
SELECTED_IMAGE=""
APPLY=no
CANCEL=no
PLAN=""
CONFIRMATION=""
ADMIN_USER=""
ADMIN_PASSWORD_FILE=""
PROBE_TIMEOUT="${NCT_FRESH_DOCKER_PROBE_TIMEOUT:-30}"
HELPER_TIMEOUT="${NCT_FRESH_DOCKER_HELPER_TIMEOUT:-3600}"
HOST_USER="$(id -u):$(id -g)"

usage() {
    cat <<'EOF'
Create and verify a rollback-safe preview for a genuinely fresh NCT installation.

Preview:
  sh scripts/nct-fresh-install.sh [--container NAME] [--output-dir ABSOLUTE_PATH]
      [--new-data-source ABSOLUTE_PATH_OR_VOLUME] [--image VERSIONED_IMAGE]

Apply the exact reviewed plan:
  sh scripts/nct-fresh-install.sh --apply --plan ABSOLUTE_PLAN_PATH
      --admin-user USER [--confirmation FRESH-XXXXXXXXXXXX]
      [--admin-password-file ABSOLUTE_PATH]

Cancel a reviewed preview and resume the retained installation:
  sh scripts/nct-fresh-install.sh --cancel --plan ABSOLUTE_PLAN_PATH

Preview stops NCT, makes and independently verifies a complete cold backup, and
holds NCT stopped so the reviewed source cannot change before Apply. Apply
retains the old container, image and data as the rollback source and creates the
fresh instance on a different empty data location. Cancel restores the earlier
restart policy and running state. There is no --yes bypass.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --container) [ "$#" -ge 2 ] || exit 2; CONTAINER=$2; shift 2 ;;
        --output-dir) [ "$#" -ge 2 ] || exit 2; OUTPUT_ROOT=$2; shift 2 ;;
        --new-data-source) [ "$#" -ge 2 ] || exit 2; NEW_DATA_SOURCE=$2; shift 2 ;;
        --image) [ "$#" -ge 2 ] || exit 2; SELECTED_IMAGE=$2; shift 2 ;;
        --apply) APPLY=yes; shift ;;
        --cancel) CANCEL=yes; shift ;;
        --plan) [ "$#" -ge 2 ] || exit 2; PLAN=$2; shift 2 ;;
        --confirmation) [ "$#" -ge 2 ] || exit 2; CONFIRMATION=$2; shift 2 ;;
        --admin-user) [ "$#" -ge 2 ] || exit 2; ADMIN_USER=$2; shift 2 ;;
        --admin-password-file) [ "$#" -ge 2 ] || exit 2; ADMIN_PASSWORD_FILE=$2; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) printf '%s\n' "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

die() { printf '%s\n' "HALT: $*" >&2; exit 2; }
[ "$APPLY" = no ] || [ "$CANCEL" = no ] || die "--apply and --cancel cannot be combined"
case "$CONTAINER" in ''|*[!A-Za-z0-9_.-]*) die "invalid container name" ;; esac
case "$PROBE_TIMEOUT:$HELPER_TIMEOUT" in *[!0-9:]*|0:*|*:0|:) die "timeouts must be positive seconds" ;; esac
for tool in docker timeout realpath sha256sum tar cmp awk sed grep cut date df cat find wc tr openssl curl sleep id; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
done
[ -r "$SCRIPT_DIR/nct-fresh-install.py" ] || die "fresh-install support tool is missing"

docker_probe() { timeout -k 5 "$PROBE_TIMEOUT" docker "$@"; }
HELPER_NAME="nct-fresh-helper-$$"
HELPER_BLOCK="${TMPDIR:-/tmp}/nct-fresh-helper-cleanup-block-$$"
rm -f "$HELPER_BLOCK"
hold_named_container_stopped() {
    held_name=$1
    held_ids=$(docker_probe ps -aq --no-trunc --filter "name=^/${held_name}$") || return 1
    [ -n "$held_ids" ] || return 0
    docker_probe update --restart=no "$held_name" >/dev/null 2>&1 || return 1
    if [ "$(docker_probe inspect --format '{{.State.Running}}' "$held_name")" = true ]; then
        docker_probe stop --time 30 "$held_name" >/dev/null 2>&1 || return 1
    fi
    [ "$(docker_probe inspect --format '{{.HostConfig.RestartPolicy.Name}}:{{.State.Running}}' "$held_name")" = "no:false" ]
}
hold_all_nct_stopped() {
    hold_status=0
    hold_named_container_stopped "$CONTAINER" || hold_status=1
    if [ -n "${retained_container:-}" ]; then
        hold_named_container_stopped "$retained_container" || hold_status=1
    fi
    return "$hold_status"
}
remove_helper() {
    helper_ids=$(docker_probe ps -aq --no-trunc --filter "name=^/${HELPER_NAME}$") || return 1
    if [ -n "$helper_ids" ]; then docker_probe rm -f "$HELPER_NAME" >/dev/null || return 1; fi
    helper_ids=$(docker_probe ps -aq --no-trunc --filter "name=^/${HELPER_NAME}$") || return 1
    [ -z "$helper_ids" ]
}
docker_helper() {
    [ "${1:-}" = run ] || die "internal helper invocation must use docker run"
    shift
    remove_helper || {
        : > "$HELPER_BLOCK"
        if hold_all_nct_stopped; then
            die "helper absence could not be proven: $HELPER_NAME; NCT is verified stopped"
        fi
        die "helper absence and NCT stopped state could not be proven; disconnect NCT network access and inspect Docker manually"
    }
    helper_status=0
    timeout -k 10 "$HELPER_TIMEOUT" docker run --name "$HELPER_NAME" "$@" || helper_status=$?
    if ! remove_helper; then
        : > "$HELPER_BLOCK"
        if hold_all_nct_stopped; then
            die "helper cleanup could not be proven: $HELPER_NAME; NCT is verified stopped"
        fi
        die "helper cleanup and NCT stopped state could not be proven; disconnect NCT network access and inspect Docker manually"
    fi
    return "$helper_status"
}
paths_overlap() {
    left=${1%/}; right=${2%/}
    [ "$left" = "$right" ] && return 0
    case "$left/" in "$right/"*) return 0 ;; esac
    case "$right/" in "$left/"*) return 0 ;; esac
    return 1
}
assert_isolated_mounts() {
    all_container_ids=$(docker_probe ps -aq)
    [ -n "$all_container_ids" ] || return 0
    isolation_status=0
    # One bounded Docker snapshot avoids a separate potentially slow inspect for every container.
    # shellcheck disable=SC2086
    docker_probe inspect $all_container_ids | docker_helper run --rm -i --user "$HOST_USER" \
        --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
        --pids-limit 64 --tmpfs /tmp:rw,noexec,nosuid,size=8m \
        -v "$SCRIPT_DIR/nct-fresh-install.py:/opt/nct-fresh-install.py:ro" \
        --entrypoint python "$plan_image" /opt/nct-fresh-install.py check-isolation \
        --target-id "$target_id" --old-type "$mount_type" --old-source "$data_source" \
        --old-path "$data_path" --new-bind-path "${reviewed_new_path:-}" >/dev/null || isolation_status=$?
    if [ "$isolation_status" -ne 0 ]; then
        [ -z "${ISOLATION_BLOCK:-}" ] || : > "$ISOLATION_BLOCK"
        die "container data isolation could not be proven; review the reported overlap or Docker inspection failure"
    fi
}
plan_value() {
    field=$1
    docker_helper run --rm --user "$HOST_USER" --network none --read-only --cap-drop ALL --cap-add DAC_OVERRIDE \
        --security-opt no-new-privileges --pids-limit 64 --tmpfs /tmp:rw,noexec,nosuid,size=8m \
        -v "$PLAN:/reviewed-plan.json:ro" \
        -v "$SCRIPT_DIR/nct-fresh-install.py:/opt/nct-fresh-install.py:ro" \
        --entrypoint python "$plan_image" /opt/nct-fresh-install.py get \
        --plan /reviewed-plan.json --field "$field"
}

if [ "$CANCEL" = yes ]; then
    [ -n "$PLAN" ] || die "--cancel requires --plan"
    case "$PLAN" in /*) ;; *) die "plan path must be absolute" ;; esac
    PLAN=$(realpath -e -- "$PLAN") || die "reviewed plan was not found"
    [ -r "$PLAN" ] || die "reviewed plan is not readable"
    docker_probe inspect "$CONTAINER" >/dev/null 2>&1 || die "reviewed NCT container was not found"
    plan_image=$(docker_probe inspect --format '{{.Image}}' "$CONTAINER")
    [ "$(plan_value container_name)" = "$CONTAINER" ] || die "plan names a different container"
    [ "$(plan_value container_id)" = "$(docker_probe inspect --format '{{.Id}}' "$CONTAINER")" ] ||
        die "container changed after preview; cancellation cannot safely select it"
    [ "$(plan_value image_id)" = "$plan_image" ] || die "container image changed after preview"
    old_restart=$(plan_value runtime.restart_policy.name)
    old_restart_max=$(plan_value runtime.restart_policy.maximum_retry_count)
    prior_state=$(plan_value prior_state)
    mount_type=$(plan_value old_data.type)
    data_source=$(plan_value old_data.source)
    target_id=$(plan_value container_id)
    if [ "$mount_type" = bind ]; then data_path=$(realpath -m -- "$data_source")
    else data_path=$(docker_probe volume inspect --format '{{.Mountpoint}}' "$data_source"); data_path=$(realpath -m -- "$data_path"); fi
    ISOLATION_BLOCK="$(dirname "$PLAN")/apply-isolation-block"
    rm -f "$ISOLATION_BLOCK"
    assert_isolated_mounts
    restart_value=$old_restart
    [ "$old_restart" != on-failure ] || [ "$old_restart_max" -eq 0 ] || restart_value="on-failure:$old_restart_max"
    docker_probe update --restart="$restart_value" "$CONTAINER" >/dev/null
    case "$prior_state" in running|restarting) docker_probe start "$CONTAINER" >/dev/null ;; esac
    [ "$(docker_probe inspect --format '{{.HostConfig.RestartPolicy.Name}}:{{.HostConfig.RestartPolicy.MaximumRetryCount}}' "$CONTAINER")" = "$old_restart:$old_restart_max" ] || die "cancelled preview restart policy could not be verified"
    actual_running=$(docker_probe inspect --format '{{.State.Running}}' "$CONTAINER")
    case "$prior_state" in running|restarting) [ "$actual_running" = true ] || die "cancelled preview running state could not be verified" ;; *) [ "$actual_running" = false ] || die "cancelled preview stopped state could not be verified" ;; esac
    rm -f "$HELPER_BLOCK"
    rm -f "$ISOLATION_BLOCK"
    printf '%s\n' "Fresh-install preview cancelled. The retained NCT installation was resumed with its earlier restart policy."
    exit 0
fi

if [ "$APPLY" = yes ]; then
    [ -n "$PLAN" ] || die "--apply requires --plan"
    case "$PLAN" in /*) ;; *) die "plan path must be absolute" ;; esac
    PLAN=$(realpath -e -- "$PLAN") || die "reviewed plan was not found"
    [ -r "$PLAN" ] || die "reviewed plan is not readable"
    [ -n "$ADMIN_USER" ] || die "--admin-user is required"
    printf '%s' "$ADMIN_USER" | grep -Eq '^[a-z0-9][a-z0-9._-]{1,63}$' ||
        die "Administrator username must be 2-64 lowercase letters, numbers, dots, dashes, or underscores"

    # Use the currently saved target image only to validate and read the signed-by-digest plan.
    docker_probe inspect "$CONTAINER" >/dev/null 2>&1 || die "reviewed NCT container was not found"
    plan_image=$(docker_probe inspect --format '{{.Image}}' "$CONTAINER")
    reviewed_container=$(plan_value container_name) || die "plan validation failed"
    [ "$reviewed_container" = "$CONTAINER" ] || die "plan names a different container"
    reviewed_id=$(plan_value container_id)
    current_id=$(docker_probe inspect --format '{{.Id}}' "$CONTAINER")
    [ "$reviewed_id" = "$current_id" ] || die "container changed after preview; create a new preview"
    image_id=$(plan_value image_id)
    docker_probe image inspect "$image_id" >/dev/null 2>&1 || die "reviewed image is no longer available"
    current_image=$(docker_probe inspect --format '{{.Image}}' "$CONTAINER")
    [ "$current_image" = "$image_id" ] || die "container image changed after preview"
    mount_type=$(plan_value old_data.type)
    data_source=$(plan_value old_data.source)
    current_mount=$(docker_probe inspect --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Type}}|{{if eq .Type "volume"}}{{.Name}}{{else}}{{.Source}}{{end}}{{end}}{{end}}' "$CONTAINER")
    [ "$current_mount" = "$mount_type|$data_source" ] || die "data mount changed after preview"
    backup=$(plan_value backup.path)
    backup_sha=$(plan_value backup.sha256)
    expected_confirmation=$(plan_value confirmation)
    retained_container=$(plan_value retained_old_container_name)
    new_data_source=$(plan_value new_data.source)
    prior_state=$(plan_value prior_state)
    old_restart=$(plan_value runtime.restart_policy.name)
    old_restart_max=$(plan_value runtime.restart_policy.maximum_retry_count)
    health_url=$(plan_value runtime.health_url)
    login_url=$(plan_value runtime.login_url)
    me_url=$(plan_value runtime.me_url)
    tls_cert=$(plan_value runtime.tls_certificate_source)
    tls_key=$(plan_value runtime.tls_key_source)
    tls_cert_sha=$(plan_value runtime.tls_certificate_sha256)
    tls_key_sha=$(plan_value runtime.tls_key_sha256)
    plan_digest=$(plan_value plan_digest)
    pre_switch=yes
    restore_before_switch() {
        status=$?
        trap - EXIT HUP INT TERM
        rm -f "${apply_inspect:-}" 2>/dev/null || true
        if [ -e "$HELPER_BLOCK" ] || [ -e "${ISOLATION_BLOCK:-/nonexistent}" ]; then
            if hold_all_nct_stopped; then
                printf '%s\n' "HALT: helper cleanup or data isolation is unresolved; NCT is verified stopped and runtime restoration was not attempted." >&2
            else
                printf '%s\n' "HALT: helper cleanup or data isolation is unresolved and Docker could not verify NCT is stopped; disconnect network access and inspect Docker manually." >&2
            fi
        elif [ "$pre_switch" = yes ] && docker_probe inspect "$CONTAINER" >/dev/null 2>&1; then
            restart_value=$old_restart
            [ "$old_restart" != on-failure ] || [ "$old_restart_max" -eq 0 ] || restart_value="on-failure:$old_restart_max"
            restore_ok=yes
            docker_probe update --restart="$restart_value" "$CONTAINER" >/dev/null 2>&1 || restore_ok=no
            case "$prior_state" in running|restarting) docker_probe start "$CONTAINER" >/dev/null 2>&1 || restore_ok=no ;; esac
            actual_policy=$(docker_probe inspect --format '{{.HostConfig.RestartPolicy.Name}}:{{.HostConfig.RestartPolicy.MaximumRetryCount}}' "$CONTAINER") || restore_ok=no
            [ "$actual_policy" = "$old_restart:$old_restart_max" ] || restore_ok=no
            actual_running=$(docker_probe inspect --format '{{.State.Running}}' "$CONTAINER") || restore_ok=no
            case "$prior_state" in running|restarting) [ "$actual_running" = true ] || restore_ok=no ;; *) [ "$actual_running" = false ] || restore_ok=no ;; esac
            [ "$restore_ok" = yes ] || printf '%s\n' "HALT: prior NCT runtime could not be verified; keep all retained data and inspect the container before proceeding." >&2
        fi
        exit "$status"
    }
    trap restore_before_switch EXIT HUP INT TERM
    [ -f "$backup" ] || die "reviewed cold backup is missing"
    [ "$(sha256sum "$backup" | awk '{print $1}')" = "$backup_sha" ] || die "reviewed cold backup checksum changed"
    run_dir=$(dirname "$PLAN")
    ISOLATION_BLOCK="$run_dir/apply-isolation-block"
    rm -f "$ISOLATION_BLOCK"
    output_path=$(realpath -m -- "$run_dir")
    if [ "$mount_type" = bind ]; then data_path=$(realpath -m -- "$data_source")
    else data_path=$(docker_probe volume inspect --format '{{.Mountpoint}}' "$data_source"); data_path=$(realpath -m -- "$data_path"); fi
    paths_overlap "$data_path" "$output_path" && die "backup output now overlaps retained NCT data"
    target_id=$reviewed_id
    reviewed_new_path=""
    if [ "$mount_type" = bind ]; then
        reviewed_new_path=$(realpath -m -- "$new_data_source")
        paths_overlap "$data_path" "$reviewed_new_path" && die "fresh data path now overlaps retained NCT data"
        paths_overlap "$output_path" "$reviewed_new_path" && die "fresh data path now overlaps backup output"
    fi
    if [ -n "$tls_cert" ]; then
        tls_ca="$run_dir/reviewed-tls-certificate.pem"
        [ -r "$tls_ca" ] || die "reviewed TLS trust copy is unavailable"
        [ "$(sha256sum "$tls_ca" | awk '{print $1}')" = "$tls_cert_sha" ] || die "reviewed TLS trust copy changed"
        current_cert_sha=$(docker_helper run --rm --network none --read-only --cap-drop ALL --cap-add DAC_OVERRIDE \
            -v "$tls_cert:/source:ro" --entrypoint sha256sum "$image_id" /source | awk '{print $1}')
        current_key_sha=$(docker_helper run --rm --network none --read-only --cap-drop ALL --cap-add DAC_OVERRIDE \
            -v "$tls_key:/source:ro" --entrypoint sha256sum "$image_id" /source | awk '{print $1}')
        [ "$current_cert_sha" = "$tls_cert_sha" ] || die "TLS certificate changed after preview"
        [ "$current_key_sha" = "$tls_key_sha" ] || die "TLS key changed after preview"
        openssl x509 -in "$tls_ca" -noout -checkend 0 >/dev/null 2>&1 || die "TLS certificate is invalid or expired"
    else
        tls_ca=""
    fi
    source_inventory="$run_dir/source-inventory.json"
    restored_inventory="$run_dir/restored-inventory.json"
    [ -f "$source_inventory" ] && [ -f "$restored_inventory" ] || die "reviewed inventory evidence is incomplete"
    cmp -s "$source_inventory" "$restored_inventory" || die "reviewed backup inventory no longer matches"
    docker_probe inspect "$retained_container" >/dev/null 2>&1 && die "retained rollback container name is already in use"
    if [ "$mount_type" = volume ]; then
        docker_probe volume inspect "$new_data_source" >/dev/null 2>&1 && die "reviewed fresh volume already exists"
        data_mount="$data_source:/data:ro"
    else
        [ ! -e "$new_data_source" ] || die "reviewed fresh bind path already exists"
        data_mount="$data_source:/data:ro"
    fi

    docker_probe update --restart=no "$CONTAINER" >/dev/null
    if [ "$(docker_probe inspect --format '{{.State.Running}}' "$CONTAINER")" = true ]; then
        docker_probe stop --time 30 "$CONTAINER" >/dev/null
    fi
    [ "$(docker_probe inspect --format '{{.State.Running}}' "$CONTAINER")" = false ] || die "NCT did not remain stopped"
    apply_inspect="$run_dir/apply-container-inspect.json"
    docker_probe inspect "$CONTAINER" > "$apply_inspect"
    docker_helper run --rm --user "$HOST_USER" --network none --read-only --cap-drop ALL --cap-add DAC_OVERRIDE \
        --security-opt no-new-privileges --pids-limit 64 --tmpfs /tmp:rw,noexec,nosuid,size=8m \
        -v "$PLAN:/reviewed-plan.json:ro" -v "$apply_inspect:/current-inspect.json:ro" \
        -v "$SCRIPT_DIR/nct-fresh-install.py:/opt/nct-fresh-install.py:ro" \
        --entrypoint python "$image_id" /opt/nct-fresh-install.py validate-runtime \
        --plan /reviewed-plan.json --inspect /current-inspect.json >/dev/null
    rm -f "$apply_inspect"
    target_id=$reviewed_id
    assert_isolated_mounts
    current_inventory="$run_dir/apply-source-inventory.json"
    docker_helper run --rm --network none --read-only --cap-drop ALL --cap-add DAC_OVERRIDE \
        --security-opt no-new-privileges --pids-limit 64 --tmpfs /tmp:rw,noexec,nosuid,size=8m \
        -v "$data_mount" \
        -v "$SCRIPT_DIR/nct-fresh-install.py:/opt/nct-fresh-install.py:ro" \
        --entrypoint python "$image_id" /opt/nct-fresh-install.py inventory \
        --root /data > "$current_inventory"
    cmp -s "$source_inventory" "$current_inventory" || {
        die "NCT data changed after preview; the old installation was restored and a new preview is required"
    }

    if [ -z "$CONFIRMATION" ]; then
        [ -t 0 ] || die "interactive confirmation is required unless --confirmation is supplied"
        printf '%s\n' "This creates a blank NCT installation and retains the old one for rollback."
        printf 'Type %s to continue: ' "$expected_confirmation" >&2
        IFS= read -r CONFIRMATION
    fi
    [ "$CONFIRMATION" = "$expected_confirmation" ] || die "confirmation does not match this exact plan"

    final_password=""
    if [ -n "$ADMIN_PASSWORD_FILE" ]; then
        case "$ADMIN_PASSWORD_FILE" in /*) ;; *) die "Administrator password file must be absolute" ;; esac
        ADMIN_PASSWORD_FILE=$(realpath -e -- "$ADMIN_PASSWORD_FILE") || die "Administrator password file was not found"
        paths_overlap "$ADMIN_PASSWORD_FILE" "$data_source" && die "Administrator password file must be outside old NCT data"
        case "$new_data_source" in /*) paths_overlap "$ADMIN_PASSWORD_FILE" "$new_data_source" && die "Administrator password file must be outside fresh NCT data" ;; esac
        final_password=$(cat "$ADMIN_PASSWORD_FILE")
    else
        [ -t 0 ] || die "interactive password entry or --admin-password-file is required"
        terminal_state=$(stty -g)
        trap 'stty "$terminal_state" 2>/dev/null || true; restore_before_switch' HUP INT TERM EXIT
        printf 'New Administrator password (12-256 characters): ' >&2
        stty -echo; IFS= read -r first_password; stty "$terminal_state"; printf '\nConfirm password: ' >&2
        stty -echo; IFS= read -r second_password; stty "$terminal_state"; printf '\n' >&2
        [ "$first_password" = "$second_password" ] || die "passwords do not match"
        final_password=$first_password
        first_password=""; second_password=""
        trap restore_before_switch EXIT HUP INT TERM
    fi
    password_length=$(printf %s "$final_password" | wc -c | tr -d ' ')
    [ "$password_length" -ge 12 ] && [ "$password_length" -le 256 ] || die "Administrator password must be 12-256 characters"

    switched=no
    complete=no
    fresh_candidate_name="$CONTAINER-fresh-failed-$(date -u +%Y%m%dT%H%M%SZ)"
    rollback() {
        status=$?
        trap - EXIT HUP INT TERM
        rm -f "${apply_inspect:-}" 2>/dev/null || true
        if [ "$switched" = yes ] && [ "$complete" != yes ]; then
            if [ -e "$HELPER_BLOCK" ]; then
                if hold_all_nct_stopped; then
                    printf '%s\n' "HALT: helper cleanup is unresolved. Both installations are verified stopped; do not resume either until the named helper is confirmed absent." >&2
                else
                    printf '%s\n' "HALT: helper cleanup is unresolved and Docker could not verify both installations are stopped; disconnect network access and inspect Docker manually." >&2
                fi
                rm -f "$run_dir/fresh-bootstrap-password" 2>/dev/null || true
                final_password=""
                exit "${status:-2}"
            fi
            rollback_ok=yes
            if docker_probe inspect "$CONTAINER" >/dev/null 2>&1; then
                docker_probe update --restart=no "$CONTAINER" >/dev/null 2>&1 || rollback_ok=no
                docker_probe stop --time 20 "$CONTAINER" >/dev/null 2>&1 || rollback_ok=no
                docker_probe rename "$CONTAINER" "$fresh_candidate_name" >/dev/null 2>&1 || rollback_ok=no
            fi
            if docker_probe inspect "$retained_container" >/dev/null 2>&1; then
                docker_probe rename "$retained_container" "$CONTAINER" >/dev/null 2>&1 || rollback_ok=no
                restart_value=$old_restart
                [ "$old_restart" != on-failure ] || [ "$old_restart_max" -eq 0 ] || restart_value="on-failure:$old_restart_max"
                docker_probe update --restart="$restart_value" "$CONTAINER" >/dev/null 2>&1 || rollback_ok=no
                case "$prior_state" in running|restarting) docker_probe start "$CONTAINER" >/dev/null 2>&1 || rollback_ok=no ;; esac
            else rollback_ok=no; fi
            actual_id=$(docker_probe inspect --format '{{.Id}}' "$CONTAINER" 2>/dev/null) || rollback_ok=no
            [ "$actual_id" = "$reviewed_id" ] || rollback_ok=no
            actual_mount=$(docker_probe inspect --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Type}}|{{if eq .Type "volume"}}{{.Name}}{{else}}{{.Source}}{{end}}{{end}}{{end}}' "$CONTAINER" 2>/dev/null) || rollback_ok=no
            [ "$actual_mount" = "$mount_type|$data_source" ] || rollback_ok=no
            actual_policy=$(docker_probe inspect --format '{{.HostConfig.RestartPolicy.Name}}:{{.HostConfig.RestartPolicy.MaximumRetryCount}}' "$CONTAINER" 2>/dev/null) || rollback_ok=no
            [ "$actual_policy" = "$old_restart:$old_restart_max" ] || rollback_ok=no
            actual_running=$(docker_probe inspect --format '{{.State.Running}}' "$CONTAINER" 2>/dev/null) || rollback_ok=no
            case "$prior_state" in running|restarting) [ "$actual_running" = true ] || rollback_ok=no ;; *) [ "$actual_running" = false ] || rollback_ok=no ;; esac
            if docker_probe inspect "$fresh_candidate_name" >/dev/null 2>&1; then
                [ "$(docker_probe inspect --format '{{.HostConfig.RestartPolicy.Name}}:{{.State.Running}}' "$fresh_candidate_name")" = "no:false" ] || rollback_ok=no
            fi
            if [ "$rollback_ok" = yes ]; then
                printf '%s\n' "HALT: fresh initialization failed; the exact old installation was restored and verified. Candidate data was retained for review." >&2
            else
                if hold_all_nct_stopped; then
                    printf '%s\n' "HALT: automatic rollback could not be verified. Both installations are verified stopped. Preserve both containers and data and inspect names, mounts, state, and restart policies before recovery." >&2
                else
                    printf '%s\n' "HALT: automatic rollback and stopped state could not be verified. Disconnect network access, preserve both containers and data, and inspect names, mounts, state, and restart policies before recovery." >&2
                fi
            fi
        fi
        rm -f "$run_dir/fresh-bootstrap-password" 2>/dev/null || true
        final_password=""
        exit "$status"
    }
    pre_switch=no
    trap rollback EXIT HUP INT TERM

    docker_probe rename "$CONTAINER" "$retained_container" >/dev/null
    switched=yes
    if [ "$mount_type" = volume ]; then
        docker_probe volume create --label "nct.fresh.plan=$plan_digest" "$new_data_source" >/dev/null
    else
        mkdir -m 0755 -p "$new_data_source"
        [ -z "$(find "$new_data_source" -mindepth 1 -maxdepth 1 -print -quit)" ] || die "fresh bind path is not empty"
    fi
    bootstrap_secret="$run_dir/fresh-bootstrap-password"
    openssl rand -base64 36 | tr -d '\r\n' > "$bootstrap_secret"
    chmod 600 "$bootstrap_secret"
    bootstrap_create="$run_dir/create-fresh-bootstrap.sh"
    final_create="$run_dir/create-fresh-final.sh"
    docker_helper run --rm --user "$HOST_USER" --network none --read-only --cap-drop ALL --cap-add DAC_OVERRIDE \
        --security-opt no-new-privileges --pids-limit 64 --tmpfs /tmp:rw,noexec,nosuid,size=8m \
        -v "$PLAN:/reviewed-plan.json:ro" \
        -v "$SCRIPT_DIR/nct-fresh-install.py:/opt/nct-fresh-install.py:ro" \
        --entrypoint python "$image_id" /opt/nct-fresh-install.py render-create \
        --plan /reviewed-plan.json --admin "$ADMIN_USER" --secret-path "$bootstrap_secret" --bootstrap --docker-timeout "$PROBE_TIMEOUT" \
        > "$bootstrap_create"
    chmod 700 "$bootstrap_create"
    sh "$bootstrap_create" >/dev/null
    docker_probe start "$CONTAINER" >/dev/null
    attempts=0
    until { if [ -n "$tls_ca" ]; then curl --cacert "$tls_ca" -fsS --connect-timeout 2 --max-time 5 "$health_url"; else curl -fsS --connect-timeout 2 --max-time 5 "$health_url"; fi; } >/dev/null 2>&1; do
        attempts=$((attempts + 1)); [ "$attempts" -lt 45 ] || die "fresh NCT did not become healthy during Administrator initialization"; sleep 1
    done
    printf %s "$final_password" | docker_probe exec -i "$CONTAINER" python -c '
import sys
from pathlib import Path
from app.auth import reset_user_password
reset_user_password(Path("/data/analyzer.db"), username=sys.argv[1], password=sys.stdin.read(), actor="explicit-fresh-install")
' "$ADMIN_USER" >/dev/null
    docker_probe stop --time 30 "$CONTAINER" >/dev/null

    if [ "$mount_type" = volume ]; then fresh_mount="$new_data_source:/data:ro"; else fresh_mount="$new_data_source:/data:ro"; fi
    docker_helper run --rm --network none --read-only --cap-drop ALL --cap-add DAC_OVERRIDE \
        --security-opt no-new-privileges --pids-limit 64 --tmpfs /tmp:rw,noexec,nosuid,size=8m \
        -v "$fresh_mount" \
        -v "$SCRIPT_DIR/nct-fresh-install.py:/opt/nct-fresh-install.py:ro" \
        --entrypoint python "$image_id" /opt/nct-fresh-install.py verify-fresh \
        --root /data --admin "$ADMIN_USER" > "$run_dir/fresh-verification.json"
    docker_probe rm "$CONTAINER" >/dev/null
    docker_helper run --rm --user "$HOST_USER" --network none --read-only --cap-drop ALL --cap-add DAC_OVERRIDE \
        --security-opt no-new-privileges --pids-limit 64 --tmpfs /tmp:rw,noexec,nosuid,size=8m \
        -v "$PLAN:/reviewed-plan.json:ro" \
        -v "$SCRIPT_DIR/nct-fresh-install.py:/opt/nct-fresh-install.py:ro" \
        --entrypoint python "$image_id" /opt/nct-fresh-install.py render-create \
        --plan /reviewed-plan.json --admin "$ADMIN_USER" --secret-path /not-used --docker-timeout "$PROBE_TIMEOUT" \
        > "$final_create"
    chmod 700 "$final_create"
    sh "$final_create" >/dev/null
    docker_probe start "$CONTAINER" >/dev/null
    attempts=0
    until { if [ -n "$tls_ca" ]; then curl --cacert "$tls_ca" -fsS --connect-timeout 2 --max-time 5 "$health_url"; else curl -fsS --connect-timeout 2 --max-time 5 "$health_url"; fi; } >/dev/null 2>&1; do
        attempts=$((attempts + 1)); [ "$attempts" -lt 45 ] || die "fresh NCT did not become healthy after removing bootstrap access"; sleep 1
    done

    cookie="$run_dir/first-sign-in.cookie"
    login_status=$(printf %s "$final_password" | docker_helper run --rm -i --user "$HOST_USER" --network none \
        --read-only --cap-drop ALL --cap-add DAC_OVERRIDE --security-opt no-new-privileges --pids-limit 32 \
        --entrypoint python "$image_id" -c 'import json,sys; print(json.dumps({"username":sys.argv[1],"password":sys.stdin.read()}))' "$ADMIN_USER" |
        { if [ -n "$tls_ca" ]; then curl --cacert "$tls_ca" -sS --connect-timeout 2 --max-time 10 -c "$cookie" -o "$run_dir/first-sign-in.json" -w '%{http_code}' -H 'Content-Type: application/json' --data-binary @- "$login_url"; else curl -sS --connect-timeout 2 --max-time 10 -c "$cookie" -o "$run_dir/first-sign-in.json" -w '%{http_code}' -H 'Content-Type: application/json' --data-binary @- "$login_url"; fi; })
    [ "$login_status" = 200 ] || die "fresh Administrator sign-in failed"
    if [ -n "$tls_ca" ]; then me_status=$(curl --cacert "$tls_ca" -sS --connect-timeout 2 --max-time 10 -b "$cookie" -o "$run_dir/first-session.json" -w '%{http_code}' "$me_url")
    else me_status=$(curl -sS --connect-timeout 2 --max-time 10 -b "$cookie" -o "$run_dir/first-session.json" -w '%{http_code}' "$me_url"); fi
    [ "$me_status" = 200 ] || die "fresh Administrator session verification failed"
    rm -f "$cookie" "$bootstrap_secret"
    restart_value=$old_restart
    [ "$old_restart" != on-failure ] || [ "$old_restart_max" -eq 0 ] || restart_value="on-failure:$old_restart_max"
    docker_probe update --restart="$restart_value" "$CONTAINER" >/dev/null
    [ "$(docker_probe inspect --format '{{.HostConfig.RestartPolicy.Name}}:{{.HostConfig.RestartPolicy.MaximumRetryCount}}' "$CONTAINER")" = "$old_restart:$old_restart_max" ] || die "fresh restart policy verification failed"
    printf 'completed=%s\nplan=%s\nplan_digest=%s\nnew_container=%s\nretained_container=%s\nold_data=%s\nnew_data=%s\nbackup=%s\nbackup_sha256=%s\nadministrator=%s\nhealth_verified=true\nfirst_sign_in_verified=true\nempty_operator_data_verified=true\nautomatic_network_contact=false\n' \
        "$(date -u +%FT%TZ)" "$PLAN" "$plan_digest" "$CONTAINER" "$retained_container" "$data_source" "$new_data_source" "$backup" "$backup_sha" "$ADMIN_USER" > "$run_dir/fresh-install.receipt"
    chmod 600 "$run_dir/fresh-install.receipt"
    complete=yes
    final_password=""
    trap - EXIT HUP INT TERM
    rm -f "$HELPER_BLOCK"
    rm -f "$ISOLATION_BLOCK"
    printf '%s\n' "Fresh NCT is healthy and the new Administrator sign-in was verified."
    printf '%s\n' "Fresh data: $new_data_source"
    printf '%s\n' "Rollback source retained: container $retained_container with data $data_source"
    printf '%s\n' "Verified backup: $backup"
    printf '%s\n' "Receipt: $run_dir/fresh-install.receipt"
    exit 0
fi

[ -z "$PLAN$CONFIRMATION$ADMIN_USER$ADMIN_PASSWORD_FILE" ] || die "apply/cancel-only options were supplied without --apply or --cancel"
case "$OUTPUT_ROOT" in /*) ;; *) die "output directory must be absolute" ;; esac
case "$OUTPUT_ROOT" in /|*'/../'*|*'/./'*|*/..|*/.) die "unsafe output directory" ;; esac
docker_probe inspect "$CONTAINER" >/dev/null 2>&1 || die "NCT container not found"
container_id=$(docker_probe inspect --format '{{.Id}}' "$CONTAINER")
image_ref=$(docker_probe inspect --format '{{.Config.Image}}' "$CONTAINER")
[ -z "$SELECTED_IMAGE" ] || image_ref=$SELECTED_IMAGE
case "$image_ref" in *:latest|latest) die "fresh installation requires a versioned image, not latest" ;; esac
image_id=$(docker_probe image inspect --format '{{.Id}}' "$image_ref") || die "selected image is not available"
[ "$image_id" = "$(docker_probe inspect --format '{{.Image}}' "$CONTAINER")" ] || die "R24 currently requires the exact running image; upgrade separately before fresh installation"
prior_state=$(docker_probe inspect --format '{{.State.Status}}' "$CONTAINER")
case "$prior_state" in running|exited|created|restarting) ;; *) die "unsupported container state: $prior_state" ;; esac
mount_line=$(docker_probe inspect --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Type}}|{{if eq .Type "volume"}}{{.Name}}{{else}}{{.Source}}{{end}}{{"\n"}}{{end}}{{end}}' "$CONTAINER")
[ "$(printf '%s\n' "$mount_line" | sed '/^$/d' | wc -l | tr -d ' ')" = 1 ] || die "expected exactly one /data mount"
mount_type=${mount_line%%|*}; data_source=${mount_line#*|}
case "$mount_type" in bind|volume) ;; *) die "unsupported /data mount type" ;; esac
if [ "$mount_type" = bind ]; then
    data_path=$(realpath -m -- "$data_source")
else
    data_path=$(docker_probe volume inspect --format '{{.Mountpoint}}' "$data_source")
    [ -n "$data_path" ] || die "named-volume backing path is unavailable"
    data_path=$(realpath -m -- "$data_path")
fi
output_path=$(realpath -m -- "$OUTPUT_ROOT")
paths_overlap "$data_path" "$output_path" && die "backup output overlaps retained NCT data"

target_id=$container_id
plan_image=$image_id
reviewed_new_path=""
assert_isolated_mounts

timestamp=$(date -u +%Y%m%dT%H%M%SZ)
if [ -z "$NEW_DATA_SOURCE" ]; then
    if [ "$mount_type" = volume ]; then NEW_DATA_SOURCE="$data_source-fresh-$timestamp"
    else NEW_DATA_SOURCE="$(dirname "$data_path")/nct-fresh-$timestamp"; fi
fi
if [ "$mount_type" = bind ]; then
    case "$NEW_DATA_SOURCE" in /*) ;; *) die "new bind data source must be absolute" ;; esac
    NEW_DATA_SOURCE=$(realpath -m -- "$NEW_DATA_SOURCE")
    paths_overlap "$data_path" "$NEW_DATA_SOURCE" && die "fresh data path overlaps old NCT data"
    paths_overlap "$output_path" "$NEW_DATA_SOURCE" && die "fresh data path overlaps backup output"
    [ ! -e "$NEW_DATA_SOURCE" ] || die "fresh data path already exists"
    reviewed_new_path=$NEW_DATA_SOURCE
    assert_isolated_mounts
else
    case "$NEW_DATA_SOURCE" in ''|*[!A-Za-z0-9_.-]*) die "invalid fresh volume name" ;; esac
    [ "$NEW_DATA_SOURCE" != "$data_source" ] || die "fresh volume must differ from old data volume"
    docker_probe volume inspect "$NEW_DATA_SOURCE" >/dev/null 2>&1 && die "fresh volume already exists"
fi

mkdir -p "$output_path"
OUTPUT_ROOT=$(CDPATH= cd -- "$output_path" && pwd -P)
run_dir="$OUTPUT_ROOT/fresh-install-$timestamp"
mkdir -m 0700 "$run_dir"
inspect_file="$run_dir/container-inspect.json"
source_inventory="$run_dir/source-inventory.json"
restored_inventory="$run_dir/restored-inventory.json"
summary="$run_dir/source-summary.json"
backup="$run_dir/nct-data-before-fresh-install-$timestamp.tar.gz"
verify_dir="$run_dir/verified-restore"
plan="$run_dir/fresh-install-plan.json"
retained_container="$CONTAINER-pre-fresh-$timestamp"
docker_probe inspect "$retained_container" >/dev/null 2>&1 && die "retained rollback container name already exists"
remove_raw_inspect() { rm -f "$inspect_file" "${tls_key_copy:-}" 2>/dev/null || true; }
trap 'remove_raw_inspect' EXIT HUP INT TERM
docker_probe inspect "$CONTAINER" > "$inspect_file"

old_restart=$(docker_probe inspect --format '{{.HostConfig.RestartPolicy.Name}}' "$CONTAINER")
old_restart_max=$(docker_probe inspect --format '{{.HostConfig.RestartPolicy.MaximumRetryCount}}' "$CONTAINER")
restart_value=$old_restart
[ "$old_restart" != on-failure ] || [ "$old_restart_max" -eq 0 ] || restart_value="on-failure:$old_restart_max"
restore_preview() {
    docker_probe update --restart="$restart_value" "$CONTAINER" >/dev/null || return 1
    case "$prior_state" in running|restarting) docker_probe start "$CONTAINER" >/dev/null || return 1 ;; esac
    [ "$(docker_probe inspect --format '{{.HostConfig.RestartPolicy.Name}}:{{.HostConfig.RestartPolicy.MaximumRetryCount}}' "$CONTAINER")" = "$old_restart:$old_restart_max" ] || return 1
    actual_running=$(docker_probe inspect --format '{{.State.Running}}' "$CONTAINER") || return 1
    case "$prior_state" in running|restarting) [ "$actual_running" = true ] || return 1 ;; *) [ "$actual_running" = false ] || return 1 ;; esac
}
preview_complete=no
restore_preview_on_failure() {
    status=$?
    remove_raw_inspect
    if [ -e "$HELPER_BLOCK" ]; then
        if hold_all_nct_stopped; then
            printf '%s\n' "HALT: helper cleanup is unresolved; NCT is verified stopped and preview restoration was not attempted." >&2
        else
            printf '%s\n' "HALT: helper cleanup is unresolved and Docker could not verify NCT is stopped; disconnect network access and inspect Docker manually." >&2
        fi
    elif [ "$preview_complete" != yes ]; then
        if ! restore_preview; then
            if hold_all_nct_stopped; then
                printf '%s\n' "HALT: preview failed and the prior runtime could not be restored; NCT is verified stopped." >&2
            else
                printf '%s\n' "HALT: preview failed and Docker could not verify NCT is stopped; disconnect network access and inspect Docker manually." >&2
            fi
        fi
    fi
    exit "$status"
}
trap restore_preview_on_failure EXIT HUP INT TERM
docker_probe update --restart=no "$CONTAINER" >/dev/null
if [ "$(docker_probe inspect --format '{{.State.Running}}' "$CONTAINER")" = true ]; then docker_probe stop --time 30 "$CONTAINER" >/dev/null; fi
[ "$(docker_probe inspect --format '{{.State.Running}}' "$CONTAINER")" = false ] || die "NCT did not remain stopped"
tls_cert_source=$(docker_probe inspect --format '{{range .Mounts}}{{if eq .Destination "/run/tls/nct-server.crt"}}{{.Source}}{{end}}{{end}}' "$CONTAINER")
tls_key_source=$(docker_probe inspect --format '{{range .Mounts}}{{if eq .Destination "/run/tls/nct-server.key"}}{{.Source}}{{end}}{{end}}' "$CONTAINER")
tls_cert_sha=""; tls_key_sha=""
if [ -n "$tls_cert_source$tls_key_source" ]; then
    [ -n "$tls_cert_source" ] && [ -n "$tls_key_source" ] || die "TLS certificate and key mounts must both exist"
    tls_cert_copy="$run_dir/reviewed-tls-certificate.pem"
    tls_key_copy="$run_dir/reviewed-tls-key.tmp"
    docker_helper run --rm --network none --read-only --cap-drop ALL --cap-add DAC_OVERRIDE \
        -v "$tls_cert_source:/source:ro" --entrypoint cat "$image_id" /source > "$tls_cert_copy"
    docker_helper run --rm --network none --read-only --cap-drop ALL --cap-add DAC_OVERRIDE \
        -v "$tls_key_source:/source:ro" --entrypoint cat "$image_id" /source > "$tls_key_copy"
    chmod 600 "$tls_cert_copy"
    chmod 600 "$tls_key_copy"
    tls_cert_sha=$(sha256sum "$tls_cert_copy" | awk '{print $1}')
    tls_key_sha=$(sha256sum "$tls_key_copy" | awk '{print $1}')
    openssl x509 -in "$tls_cert_copy" -noout -checkend 0 >/dev/null 2>&1 || die "TLS certificate is invalid or expired"
    cert_pub=$(openssl x509 -in "$tls_cert_copy" -pubkey -noout | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
    key_pub=$(openssl pkey -in "$tls_key_copy" -pubout -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
    [ -n "$cert_pub" ] && [ "$cert_pub" = "$key_pub" ] || die "TLS certificate and key do not match"
    rm -f "$tls_key_copy"
    tls_key_copy=""
fi
if [ "$mount_type" = volume ]; then data_mount="$data_source:/data:ro"; else data_mount="$data_path:/data:ro"; fi
helper_base="--rm --network none --read-only --cap-drop ALL --cap-add DAC_OVERRIDE --security-opt no-new-privileges --pids-limit 64 --tmpfs /tmp:rw,noexec,nosuid,size=16m"
# shellcheck disable=SC2086
docker_helper run $helper_base -v "$data_mount" \
    -v "$SCRIPT_DIR/nct-fresh-install.py:/opt/nct-fresh-install.py:ro" --entrypoint python "$image_id" \
    /opt/nct-fresh-install.py inventory --root /data > "$source_inventory"
# shellcheck disable=SC2086
docker_helper run $helper_base -v "$data_mount" \
    -v "$SCRIPT_DIR/nct-fresh-install.py:/opt/nct-fresh-install.py:ro" --entrypoint python "$image_id" \
    /opt/nct-fresh-install.py summary --root /data > "$summary"
source_bytes=$(docker_helper run --rm --user "$HOST_USER" --network none --read-only -v "$run_dir:/fresh:ro" \
    --entrypoint python "$image_id" -c 'import json;print(json.load(open("/fresh/source-summary.json"))["total_file_bytes"])')
available_kb=$(df -Pk "$OUTPUT_ROOT" | awk 'NR == 2 {print $4}')
required_kb=$(( (source_bytes * 2 + 67108864 + 1023) / 1024 ))
[ "$available_kb" -ge "$required_kb" ] || die "backup location lacks space for the archive and independent extraction"
# shellcheck disable=SC2086
docker_helper run $helper_base -v "$data_mount" "$image_id" \
    sh -c "cd /data && find . -mindepth 1 -print0 | tar --null --no-recursion -czf - -T -" > "$backup"
[ -s "$backup" ] || die "cold backup was not created"
sha256sum "$backup" > "$backup.sha256"
mkdir -m 0777 "$verify_dir"
docker_helper run --rm -i --network none --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER --security-opt no-new-privileges \
    --pids-limit 64 -v "$verify_dir:/restore" "$image_id" \
    tar --same-owner --same-permissions --no-overwrite-dir -xzf - -C /restore < "$backup"
chmod 0755 "$verify_dir"
# shellcheck disable=SC2086
docker_helper run $helper_base -v "$verify_dir:/data:ro" \
    -v "$SCRIPT_DIR/nct-fresh-install.py:/opt/nct-fresh-install.py:ro" --entrypoint python "$image_id" \
    /opt/nct-fresh-install.py inventory --root /data > "$restored_inventory"
cmp -s "$source_inventory" "$restored_inventory" || die "independently extracted backup does not match old NCT data"
backup_sha=$(awk '{print $1}' "$backup.sha256")
# shellcheck disable=SC2086
docker_helper run --rm --user "$HOST_USER" --network none --read-only --cap-drop ALL --cap-add DAC_OVERRIDE \
    --security-opt no-new-privileges --pids-limit 64 --tmpfs /tmp:rw,noexec,nosuid,size=16m \
    -v "$run_dir:/fresh:ro" \
    -v "$SCRIPT_DIR/nct-fresh-install.py:/opt/nct-fresh-install.py:ro" --entrypoint python "$image_id" \
    /opt/nct-fresh-install.py plan --inspect /fresh/container-inspect.json \
    --summary /fresh/source-summary.json --inventory /fresh/source-inventory.json \
    --container "$CONTAINER" --container-id "$container_id" --prior-state "$prior_state" \
    --image-ref "$image_ref" --image-id "$image_id" --mount-type "$mount_type" \
    --data-source "$data_source" --new-data-source "$NEW_DATA_SOURCE" \
    --retained-container "$retained_container" --backup "$backup" --backup-sha256 "$backup_sha" \
    --tls-certificate-sha256 "$tls_cert_sha" --tls-key-sha256 "$tls_key_sha" \
    --created-at "$(date -u +%FT%TZ)" > "$plan"
rm -f "$inspect_file"
plan_image=$image_id
PLAN=$plan
confirmation=$(plan_value confirmation)
plan_digest=$(plan_value plan_digest)
preview_complete=yes
trap - EXIT HUP INT TERM
rm -f "$HELPER_BLOCK"
printf '%s\n' "Fresh-install preview complete. NCT is intentionally held stopped so this exact reviewed source cannot change."
printf '%s\n' "Reviewed container: $CONTAINER ($container_id)"
printf '%s\n' "Pinned image: $image_ref ($image_id)"
printf '%s\n' "Old data retained at: $mount_type $data_source"
printf '%s\n' "Fresh data will use: $mount_type $NEW_DATA_SOURCE"
printf '%s\n' "Verified cold backup: $backup"
printf '%s\n' "Plan: $plan"
printf '%s\n' "Plan digest: $plan_digest"
printf '%s\n' "Required confirmation: $confirmation"
printf '%s\n' "TLS and network settings are retained exactly as listed in the plan; old application data is not copied."
printf '%s\n' "Apply only after reviewing the plan:"
printf '%s\n' "  sh scripts/nct-fresh-install.sh --apply --plan '$plan' --admin-user NEW_ADMIN"
printf '%s\n' "Cancel and resume the old installation without replacing it:"
printf '%s\n' "  sh scripts/nct-fresh-install.sh --cancel --plan '$plan'"
