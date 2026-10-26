#!/bin/sh
set -eu

WORKDIR="${NCT_WORKDIR:-/root/NCT-Air-Gapped-Range-Deployment}"
PERSIST_ROOT="${NCT_PERSIST_ROOT:-/var/lib/nct}"
DATA_DIR="$PERSIST_ROOT/data"
CONTAINER="${NCT_CONTAINER:-nct}"
IMAGE="network-characterization-tool:0.16.0-range-test-20261013-phase3-r3"
EXPECTED_BUILD_ID="0.16.0-range-test-20261013-phase3-r3"
EXPECTED_BUILD_COMMIT="f6ba1ad4a754b904511e3d726110d6fc35b9f237"
RANGE_IP="${1:-}"
MODE="${2:-legacy}"
ARCHIVE="$WORKDIR/offline-images/nct-range-images.tar"
ARCHIVE_CHECKSUM="$ARCHIVE.sha256"
MANIFEST="$WORKDIR/PACKAGE-MANIFEST.sha256"
DATA_CHECK="$WORKDIR/scripts/nct-range-data-check.py"
SCHEMA_PREFLIGHT="$WORKDIR/scripts/nct-schema-preflight.py"
STATE_DIR="$PERSIST_ROOT/deployment"
BACKUP_DIR="$STATE_DIR/backups"
PACKAGE_SHA256="${NCT_PACKAGE_SHA256:-}"

say() { printf '%s\n' "[NCT recovery upgrade] $*"; }
die() { printf '%s\n' "[NCT recovery upgrade] HALT: $*" >&2; exit 1; }
valid_sha256() {
    value=$1
    [ "${#value}" -eq 64 ] || return 1
    case "$value" in *[!0-9a-f]*) return 1 ;; esac
}
file_sha256() { sha256sum "$1" | awk 'NR == 1 { print $1; exit }'; }
# SAVED_HTTPS_PORT_FUNCTION_START
saved_https_host_port() {
    container=$1
    port=$(docker inspect --format '{{range index .HostConfig.PortBindings "8445/tcp"}}{{.HostPort}}{{println}}{{end}}' "$container") || return 1
    case "$port" in ''|*[!0-9]*) return 1 ;; esac
    [ "$port" -ge 1 ] 2>/dev/null && [ "$port" -le 65535 ] || return 1
    printf '%s\n' "$port"
}
# SAVED_HTTPS_PORT_FUNCTION_END
wait_for_health() {
    attempt=0
    until health=$(curl --connect-timeout 2 --max-time 5 -ksS "https://$RANGE_IP:$original_host_port/health" 2>/dev/null); do
        attempt=$((attempt + 1))
        [ "$attempt" -lt 30 ] || return 1
        sleep 1
    done
    printf '%s' "$health"
}
snapshot() {
    root=$1
    output=$2
    docker run --rm \
        -v "$root:/data:ro,Z" \
        -v "$DATA_CHECK:/opt/nct-range-data-check.py:ro,Z" \
        "$IMAGE" python /opt/nct-range-data-check.py snapshot --root /data --immutable > "$output"
    chmod 600 "$output"
}
snapshot_running_candidate() {
    output=$1
    docker exec -i "$CONTAINER" python - snapshot --root /data < "$DATA_CHECK" > "$output"
    chmod 600 "$output"
}
active_check() {
    set +e
    docker run --rm \
        -v "$DATA_DIR:/data:ro,Z" \
        -v "$DATA_CHECK:/opt/nct-range-data-check.py:ro,Z" \
        "$IMAGE" python /opt/nct-range-data-check.py active --root /data --immutable
    active_rc=$?
    set -e
    [ "$active_rc" -ne 42 ] || die "Saved data contains active or unresolved work. Preserve the stopped installation for administrator review."
    [ "$active_rc" -eq 0 ] || die "Saved data could not be checked for active work."
}
no_other_writer() {
    for container_id in $(docker ps -q); do
        [ "$container_id" != "$original_container_id" ] || continue
        source_path=$(docker inspect --format '{{range .Mounts}}{{if and (eq .Destination "/data") (eq .Type "bind")}}{{.Source}}{{end}}{{end}}' "$container_id")
        [ "$source_path" != "$DATA_DIR" ] || die "Another running container mounts $DATA_DIR: $container_id"
    done
}
# RECOVERY_ISOLATION_FUNCTION_START
isolate_failed_candidate() {
    if docker inspect "$CONTAINER" >/dev/null 2>&1; then
        docker update --restart=no "$CONTAINER" >/dev/null 2>&1 || return 1
        docker stop "$CONTAINER" >/dev/null 2>&1 || return 1
        [ "$(docker inspect --format '{{.State.Running}}' "$CONTAINER" 2>/dev/null)" = "false" ] || return 1
        docker rename "$CONTAINER" "$failed_container" >/dev/null 2>&1 || return 1
    fi
    [ -d "$DATA_DIR" ] && [ ! -e "$failed_data" ] || return 1
    mv "$DATA_DIR" "$failed_data" || return 1
    [ ! -e "$DATA_DIR" ] || return 1
}
# RECOVERY_ISOLATION_FUNCTION_END

[ "$(id -u)" -eq 0 ] || die "Run this script as root."
[ -n "$RANGE_IP" ] || die "Usage: sh $WORKDIR/scripts/nct-recover-unhealthy-upgrade.sh RANGE_IP [legacy|docker|compose]"
case "$MODE" in legacy|docker|compose) ;; *) die "Mode must be legacy, docker, or compose." ;; esac
for command_name in docker sha256sum tar cmp awk curl grep; do
    command -v "$command_name" >/dev/null 2>&1 || die "$command_name is required."
done
docker info >/dev/null 2>&1 || die "Docker is not reachable."
[ -f "$MANIFEST" ] || die "Missing $MANIFEST"
[ -f "$ARCHIVE" ] && [ -f "$ARCHIVE_CHECKSUM" ] || die "The offline image archive or checksum is missing."
[ -f "$DATA_CHECK" ] && [ -f "$SCHEMA_PREFLIGHT" ] || die "A required read-only recovery checker is missing."
valid_sha256 "$PACKAGE_SHA256" || die "Set NCT_PACKAGE_SHA256 to the verified outer ZIP SHA-256 from the extraction step."
(cd "$WORKDIR" && sha256sum -c PACKAGE-MANIFEST.sha256) || die "The package manifest check failed."
(cd "$(dirname "$ARCHIVE")" && sha256sum -c "$(basename "$ARCHIVE_CHECKSUM")") || die "The offline image archive checksum failed."
manifest_sha256=$(file_sha256 "$MANIFEST")
archive_sha256=$(file_sha256 "$ARCHIVE")

docker inspect "$CONTAINER" >/dev/null 2>&1 || die "Container $CONTAINER was not found."
mount_type=$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Type}}{{end}}{{end}}' "$CONTAINER")
mount_source=$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Source}}{{end}}{{end}}' "$CONTAINER")
[ "$mount_type" = "bind" ] && [ "$mount_source" = "$DATA_DIR" ] || die "$CONTAINER does not store /data at $DATA_DIR."
original_container_id=$(docker inspect --format '{{.Id}}' "$CONTAINER")
original_image_id=$(docker inspect --format '{{.Image}}' "$CONTAINER")
original_restart_policy=$(docker inspect --format '{{.HostConfig.RestartPolicy.Name}}' "$CONTAINER")
original_host_port=$(saved_https_host_port "$CONTAINER") ||
    die "The current HTTPS host port could not be identified from the saved container configuration."

original_build_id=$(docker run --rm "$original_image_id" python -c 'from app.build_info import BUILD_ID; print(BUILD_ID)') || die "The retained source image build ID could not be read."
original_build_commit=$(docker run --rm "$original_image_id" python -c 'from app.build_info import BUILD_COMMIT; print(BUILD_COMMIT)') || die "The retained source image commit could not be read."
[ -n "$original_build_id" ] && [ -n "$original_build_commit" ] || die "The retained source image build identity is incomplete."

say "Disabling the failed restart loop and stopping the old container..."
docker update --restart=no "$CONTAINER" >/dev/null
docker stop "$CONTAINER" >/dev/null 2>&1 || true
[ "$(docker inspect --format '{{.State.Running}}' "$CONTAINER")" = "false" ] || die "The old container did not stop."
no_other_writer

say "Loading the manifest-verified replacement image..."
docker load -i "$ARCHIVE" >/dev/null
docker image inspect "$IMAGE" >/dev/null 2>&1 || die "The expected replacement image was not loaded."
expected_image_id=$(docker image inspect --format '{{.Id}}' "$IMAGE")

say "Checkpointing the stopped database with the retained source image..."
docker run --rm -v "$DATA_DIR:/data:Z" "$original_image_id" python -c '
import pathlib, sqlite3
path = pathlib.Path("/data/analyzer.db")
if path.exists():
    db = sqlite3.connect(path)
    result = db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
    db.close()
    if result is None or int(result[0]) != 0:
        raise SystemExit(f"SQLite WAL checkpoint did not complete: {result}")
' || die "The stopped database checkpoint failed."
no_other_writer
active_check

timestamp=$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "$BACKUP_DIR"
chmod 700 "$PERSIST_ROOT" "$STATE_DIR" "$BACKUP_DIR"
before="$BACKUP_DIR/recovery-pre-upgrade-$timestamp.json"
after="$BACKUP_DIR/recovery-post-upgrade-$timestamp.json"
restored="$BACKUP_DIR/recovery-restored-$timestamp.json"
audit="$BACKUP_DIR/recovery-schema-preflight-$timestamp.json"
backup="$BACKUP_DIR/recovery-nct-data-$timestamp.tar.gz"
backup_checksum="$backup.sha256"
verify_root="$BACKUP_DIR/recovery-backup-verify-$timestamp"
verify_inventory="$BACKUP_DIR/recovery-backup-verify-$timestamp.json"
receipt="$STATE_DIR/recovery-upgrade-$timestamp.receipt"
rollback="nct-recovery-source-$timestamp"
failed_container="nct-failed-recovery-$timestamp"
failed_data="$PERSIST_ROOT/failed-recovery-data-$timestamp"

say "Running the replacement schema audit through a read-only mount..."
docker run --rm \
    -e PYTHONPATH=/app \
    -v "$DATA_DIR:/data:ro,Z" \
    -v "$SCHEMA_PREFLIGHT:/opt/nct-schema-preflight.py:ro,Z" \
    "$IMAGE" python /opt/nct-schema-preflight.py --db /data/analyzer.db \
        --expected-build-id "$original_build_id" \
        --expected-build-commit "$original_build_commit" \
        --required-source-version 6 > "$audit" ||
    die "The saved schema is not an exact supported recovery source."
chmod 600 "$audit"
snapshot "$DATA_DIR" "$before"
preflight_sha256=$(docker run --rm \
    -v "$BACKUP_DIR:/verification:ro,Z" \
    "$IMAGE" python -c '
import hashlib, json, pathlib, sys
root = pathlib.Path("/verification")
report_path = root / sys.argv[1]
inventory_path = root / sys.argv[2]
report = json.loads(report_path.read_text(encoding="utf-8"))
inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
if report.get("status") != "pass":
    raise SystemExit("Schema preflight did not pass")
database = inventory.get("restore_files", {}).get("analyzer.db")
if not database or report.get("database_sha256") != database.get("sha256"):
    raise SystemExit("Schema preflight does not match analyzer.db")
print(hashlib.sha256(report_path.read_bytes()).hexdigest())
' "$(basename "$audit")" "$(basename "$before")") || die "The schema audit does not match the exact saved database inventory."
valid_sha256 "$preflight_sha256" || die "The schema-audit checksum is invalid."
before_sha256=$(file_sha256 "$before")

say "Creating and independently verifying a cold recovery backup..."
tar -C "$PERSIST_ROOT" -czf "$backup" data
chmod 600 "$backup"
sha256sum "$backup" > "$backup_checksum"
chmod 600 "$backup_checksum"
mkdir -m 700 "$verify_root"
tar -C "$verify_root" -xzf "$backup"
snapshot "$verify_root/data" "$verify_inventory"
cmp -s "$before" "$verify_inventory" || die "The extracted cold backup does not match the complete pre-upgrade inventory."
rm -rf "$verify_root"

account_count=$(docker run --rm -v "$DATA_DIR:/data:ro,Z" "$IMAGE" python -c '
import pathlib, sqlite3
p = pathlib.Path("/data/analyzer.db")
print(sqlite3.connect(f"file:{p}?mode=ro&immutable=1", uri=True).execute("SELECT COUNT(*) FROM analyst_users").fetchone()[0])
') || die "Existing NCT accounts could not be counted."
case "$account_count" in ''|*[!0-9]*) die "The saved account count is invalid." ;; esac

candidate_may_have_written=no
recovery_complete=no
restore_on_failure() {
    status=$?
    trap - EXIT HUP INT TERM
    [ "$recovery_complete" = "yes" ] && exit "$status"
    if [ "$candidate_may_have_written" = "yes" ]; then
        say "Candidate validation failed; preserving it and restoring the verified cold backup."
        if ! isolate_failed_candidate; then
            printf '%s\n' "[NCT recovery upgrade] HALT: the failed candidate could not be fully stopped, renamed, and separated from $DATA_DIR. No backup was extracted over the existing data. Preserve $backup and $rollback." >&2
        elif sha256sum -c "$backup_checksum" >/dev/null 2>&1 && tar -C "$PERSIST_ROOT" -xzf "$backup"; then
            if snapshot "$DATA_DIR" "$restored" && cmp -s "$before" "$restored"; then
                printf '%s\n' "[NCT recovery upgrade] The exact pre-upgrade data was restored and verified. The incompatible old image remains stopped as $rollback." >&2
            else
                printf '%s\n' "[NCT recovery upgrade] HALT: restored data did not verify. Preserve $failed_data, $backup, and $rollback." >&2
            fi
        else
            printf '%s\n' "[NCT recovery upgrade] HALT: the cold backup could not be verified or restored. Preserve $failed_data, $backup, and $rollback." >&2
        fi
    else
        printf '%s\n' "[NCT recovery upgrade] The old container remains stopped as $CONTAINER; no candidate was started." >&2
    fi
    exit "$status"
}
trap restore_on_failure EXIT
trap 'exit 130' HUP INT TERM

say "Retaining the incompatible old container and starting the replacement..."
docker rename "$CONTAINER" "$rollback"
candidate_may_have_written=yes
start_script="$WORKDIR/scripts/nct-start-$MODE.sh"
[ -f "$start_script" ] || die "Missing $start_script"
NCT_HTTPS_PORT="$original_host_port" NCT_UPGRADE_ACCOUNT_COUNT="$account_count" sh "$start_script" "$RANGE_IP"

candidate_container_id=$(docker inspect --format '{{.Id}}' "$CONTAINER")
candidate_image_id=$(docker inspect --format '{{.Image}}' "$CONTAINER")
[ "$candidate_image_id" = "$expected_image_id" ] || die "The replacement container image identity is wrong."
candidate_mount=$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Source}}{{end}}{{end}}' "$CONTAINER")
[ "$candidate_mount" = "$DATA_DIR" ] || die "The replacement container data mount is wrong."
candidate_host_port=$(saved_https_host_port "$CONTAINER") ||
    die "The replacement HTTPS host port could not be identified from its saved container configuration."
[ "$candidate_host_port" = "$original_host_port" ] || die "The replacement did not preserve the HTTPS port."
health=$(wait_for_health) || die "The replacement did not become healthy."
printf '%s' "$health" | grep -q '"status":"ok"' || die "The replacement health status is not ok."
printf '%s' "$health" | grep -q "\"build_id\":\"$EXPECTED_BUILD_ID\"" || die "The replacement build ID is wrong."
printf '%s' "$health" | grep -q "\"build_commit\":\"$EXPECTED_BUILD_COMMIT\"" || die "The replacement build commit is wrong."

snapshot_running_candidate "$after"
docker run --rm -v "$BACKUP_DIR:/verification:ro,Z" "$IMAGE" python -c '
import json, pathlib, sys
root = pathlib.Path("/verification")
before = json.loads((root / sys.argv[1]).read_text())
after = json.loads((root / sys.argv[2]).read_text())
for path, identity in before["files"].items():
    if after["files"].get(path) != identity:
        raise SystemExit(f"Retained file changed or disappeared: {path}")
if after["artifact_registry"] != before["artifact_registry"]:
    raise SystemExit("Registered artifact identity changed")
for table, count in before["database"]["tables"].items():
    if after["database"]["tables"].get(table, 0) < count:
        raise SystemExit(f"Stored record count decreased for {table}")
' "$(basename "$before")" "$(basename "$after")" || die "Post-upgrade retained-data comparison failed."

candidate_account_count=$(docker exec "$CONTAINER" python -c '
import sqlite3
print(sqlite3.connect("/data/analyzer.db").execute("SELECT COUNT(*) FROM analyst_users").fetchone()[0])
') || die "The replacement account count could not be read."
[ "$candidate_account_count" = "$account_count" ] || die "The saved account count changed."

say "Restarting the exact replacement once for final verification..."
docker restart "$CONTAINER" >/dev/null
health=$(wait_for_health) || die "The replacement did not become healthy after restart."
printf '%s' "$health" | grep -q '"status":"ok"' || die "The restarted replacement health status is not ok."
printf '%s' "$health" | grep -q "\"build_id\":\"$EXPECTED_BUILD_ID\"" || die "The restarted replacement build ID is wrong."
printf '%s' "$health" | grep -q "\"build_commit\":\"$EXPECTED_BUILD_COMMIT\"" || die "The restarted replacement build commit is wrong."
after_sha256=$(file_sha256 "$after")
backup_sha256=$(file_sha256 "$backup")

{
    printf 'completed=%s\n' "$(date -u +%FT%TZ)"
    printf 'outcome=verified_recovery_upgrade\n'
    printf 'operator_package_sha256=%s\n' "$PACKAGE_SHA256"
    printf 'package_manifest_sha256=%s\n' "$manifest_sha256"
    printf 'image_archive_sha256=%s\n' "$archive_sha256"
    printf 'schema_preflight=%s\n' "$audit"
    printf 'schema_preflight_sha256=%s\n' "$preflight_sha256"
    printf 'pre_upgrade_inventory=%s\n' "$before"
    printf 'pre_upgrade_inventory_sha256=%s\n' "$before_sha256"
    printf 'post_upgrade_inventory=%s\n' "$after"
    printf 'post_upgrade_inventory_sha256=%s\n' "$after_sha256"
    printf 'backup=%s\n' "$backup"
    printf 'backup_sha256=%s\n' "$backup_sha256"
    printf 'source_container=%s\n' "$rollback"
    printf 'source_container_id=%s\n' "$original_container_id"
    printf 'source_image_id=%s\n' "$original_image_id"
    printf 'source_build_id=%s\n' "$original_build_id"
    printf 'source_build_commit=%s\n' "$original_build_commit"
    printf 'source_restart_policy=%s\n' "$original_restart_policy"
    printf 'candidate_container_id=%s\n' "$candidate_container_id"
    printf 'candidate_image_id=%s\n' "$candidate_image_id"
    printf 'candidate_build_id=%s\n' "$EXPECTED_BUILD_ID"
    printf 'candidate_build_commit=%s\n' "$EXPECTED_BUILD_COMMIT"
    printf 'data_mount=%s\n' "$DATA_DIR"
    printf 'https_port=%s\n' "$candidate_host_port"
    printf 'account_count=%s\n' "$candidate_account_count"
    printf 'health=%s\n' "$health"
} > "$receipt"
chmod 600 "$receipt"

recovery_complete=yes
trap - EXIT HUP INT TERM
say "Recovery upgrade verified. NCT is ready at https://$RANGE_IP:$candidate_host_port"
say "Cold backup: $backup"
say "Read-only schema audit: $audit"
say "Incompatible source container retained (stopped): $rollback"
say "Receipt: $receipt"
