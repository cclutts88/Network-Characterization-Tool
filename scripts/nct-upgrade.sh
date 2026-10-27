#!/bin/sh
set -eu

NCT_LOCK_SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
. "$NCT_LOCK_SCRIPT_DIR/nct-maintenance-lock.sh"
nct_maintenance_lock "${NCT_PERSIST_ROOT:-/var/lib/nct}/deployment/maintenance.lock"

WORKDIR="${NCT_WORKDIR:-/root/NCT-Air-Gapped-Range-Deployment}"
PERSIST_ROOT="${NCT_PERSIST_ROOT:-/var/lib/nct}"
DATA_DIR="$PERSIST_ROOT/data"
CONTAINER="${NCT_CONTAINER:-nct}"
IMAGE="network-characterization-tool:0.16.0-range-test-20261013-phase3-r3"
RANGE_IP="${1:-}"
MODE="${2:-auto}"
ARCHIVE="$WORKDIR/offline-images/nct-range-images.tar"
CHECKSUM="$WORKDIR/offline-images/nct-range-images.tar.sha256"
STATE_DIR="$PERSIST_ROOT/deployment"
BACKUP_DIR="$STATE_DIR/backups"
SCHEMA_PREFLIGHT="$WORKDIR/scripts/nct-schema-preflight.py"

say() { printf '%s\n' "[NCT upgrade] $*"; }
die() { printf '%s\n' "[NCT upgrade] ERROR: $*" >&2; exit 1; }
verify_archive_checksum() {
    expected_checksum=$(awk 'NR == 1 { print $1; exit }' "$CHECKSUM")
    actual_checksum=$(sha256sum "$ARCHIVE" | awk '{print $1}')
    [ -n "$expected_checksum" ] && [ "$actual_checksum" = "$expected_checksum" ]
}
api_at_least() {
    awk -v have="$1" -v need="$2" 'BEGIN {
        split(have, h, "."); split(need, n, ".")
        ok = (h[1] + 0 > n[1] + 0) || (h[1] + 0 == n[1] + 0 && h[2] + 0 >= n[2] + 0)
        exit(ok ? 0 : 1)
    }'
}

[ "$(id -u)" -eq 0 ] || die "Run this script as root."
[ -n "$RANGE_IP" ] || die "Usage: sh $WORKDIR/scripts/nct-upgrade.sh RANGE_IP [auto|compose|docker|legacy]"
case "$MODE" in auto|compose|docker|legacy) ;; *) die "Mode must be auto, compose, docker, or legacy." ;; esac
for command_name in docker sha256sum tar cmp curl grep; do
    command -v "$command_name" >/dev/null 2>&1 || die "$command_name is required."
done
docker info >/dev/null 2>&1 || die "Docker is not reachable."
[ -f "$ARCHIVE" ] || die "Missing $ARCHIVE"
[ -f "$CHECKSUM" ] || die "Missing $CHECKSUM"
[ -f "$SCHEMA_PREFLIGHT" ] || die "Missing $SCHEMA_PREFLIGHT"
verify_archive_checksum || die "The offline image archive checksum does not match."
docker inspect "$CONTAINER" >/dev/null 2>&1 ||
    die "Container $CONTAINER was not found. Use a start script for a new installation."

mount_type=$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Type}}{{end}}{{end}}' "$CONTAINER")
mount_source=$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Source}}{{end}}{{end}}' "$CONTAINER")
[ "$mount_type" = "bind" ] && [ "$mount_source" = "$DATA_DIR" ] ||
    die "$CONTAINER does not store /data at $DATA_DIR. Run nct-migrate-data.sh first."
original_container_id=$(docker inspect --format '{{.Id}}' "$CONTAINER")
original_image_id=$(docker inspect --format '{{.Image}}' "$CONTAINER")
original_state=$(docker inspect --format '{{.State.Status}}' "$CONTAINER")
original_health=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}not-configured{{end}}' "$CONTAINER")
original_restart_policy=""
if [ -n "${NCT_PACKAGE_RUNTIME_CLONE:-}" ]; then
    original_restart_policy=$(docker inspect --format '{{.HostConfig.RestartPolicy.Name}}{{if eq .HostConfig.RestartPolicy.Name "on-failure"}}:{{.HostConfig.RestartPolicy.MaximumRetryCount}}{{end}}' "$CONTAINER")
fi
if [ "$original_state" != running ] || [ "$original_health" = unhealthy ]; then
    die "NCT is $original_state/$original_health. Preserve it and run the read-only diagnostic, then preview sh scripts/nct-recover-installed.sh --container $CONTAINER. Ordinary upgrade will not bypass the stopped-data work check."
fi
original_port_lines=$(docker inspect --format '{{range $port,$items := .HostConfig.PortBindings}}{{if or (eq $port "8080/tcp") (eq $port "8445/tcp")}}{{range $items}}{{printf "%s|%s\n" $port .HostPort}}{{end}}{{end}}{{end}}' "$CONTAINER" | tr -d '\r' | sed '/^$/d' | sort -u)
[ "$(printf '%s\n' "$original_port_lines" | sed '/^$/d' | wc -l | tr -d ' ')" = 1 ] ||
    die "The current NCT listener and host port are missing or ambiguous. Run the diagnostic; do not guess."
original_host_port=${original_port_lines#*|}
case "$original_host_port" in ''|*[!0-9]*) die "The current NCT HTTPS host port could not be identified." ;; esac
[ "$original_host_port" -ge 1 ] && [ "$original_host_port" -le 65535 ] || die "The current NCT HTTPS host port is invalid."

active_check_code='
import glob, json, pathlib, sqlite3, sys
active = []
for path in glob.glob("/data/**/manifest.json", recursive=True):
    try:
        item = json.load(open(path, encoding="utf-8"))
        if item.get("status") in {"queued", "dispatching", "running", "waiting_for_password", "awaiting_fallback_approval", "updating", "migrating"}:
            active.append({"source": "manifest", "path": path, "state": item.get("status")})
    except Exception:
        pass
db_path = pathlib.Path("/data/analyzer.db")
if db_path.exists():
    immutable = len(sys.argv) > 1 and sys.argv[1] == "immutable"
    suffix = "&immutable=1" if immutable else ""
    db = sqlite3.connect(f"file:{db_path}?mode=ro{suffix}", uri=True)
    tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type = \"table\"")}
    checks = (
        ("scan_runs", "status", ("queued", "dispatching", "running", "awaiting_fallback_approval")),
        ("pipeline_job_attempts", "state", ("queued", "running")),
        ("scan_foundation_processing_attempts", "status", ("running",)),
        ("device_contact_runs", "state", ("waiting", "preparing", "contact_starting", "contact_active", "needs_attention")),
        ("device_contact_attempts", "state", ("preparing", "contact_starting", "contact_active", "needs_attention")),
        ("scan_schedule_occurrences", "state", ("waiting", "preparing", "active", "needs_attention")),
        ("scan_schedule_chunks", "state", ("waiting", "preparing", "active", "needs_attention")),
        ("work_leases", "state", ("active", "recovery_required")),
        ("artifact_compaction_journal", "state", ("preparing", "prepared", "replaced", "verified", "recovery-required")),
    )
    for table, column, states in checks:
        if table not in tables:
            continue
        placeholders = ",".join("?" for _ in states)
        count = int(db.execute(
            f"SELECT COUNT(*) FROM \"{table}\" WHERE \"{column}\" IN ({placeholders})", states
        ).fetchone()[0])
        if count:
            active.append({"source": "database", "table": table, "count": count})
    if "pipeline_admission_intents" in tables:
        count = int(db.execute(
            "SELECT COUNT(*) FROM pipeline_admission_intents "
            "WHERE state = \"pending\" OR activity_state IN (\"waiting\",\"retrying\",\"paused\")"
        ).fetchone()[0])
        if count:
            active.append({"source": "database", "table": "pipeline_admission_intents", "count": count})
    db.close()
if active:
    print(json.dumps(active, sort_keys=True), file=sys.stderr)
    sys.exit(42)
'

check_active() {
    source=${1:-container}
    set +e
    if [ "$source" = "container" ]; then
        docker exec "$CONTAINER" python -c "$active_check_code"
    else
        docker run --rm -v "$DATA_DIR:/data:ro,Z" "$IMAGE" python -c "$active_check_code" immutable
    fi
    active_rc=$?
    set -e
    [ "$active_rc" -ne 42 ] || die "NCT has active or unresolved work. Finish, cancel, or review it before upgrading."
    [ "$active_rc" -eq 0 ] || die "Current NCT data could not be checked for active work."
}

check_active container

account_count=$(docker exec "$CONTAINER" python -c '
import pathlib, sqlite3
p = pathlib.Path("/data/analyzer.db")
print(0 if not p.exists() else sqlite3.connect(f"file:{p}?mode=ro", uri=True).execute("SELECT COUNT(*) FROM analyst_users").fetchone()[0])
') || die "Existing NCT accounts could not be inspected in the running container."
case "$account_count" in ''|*[!0-9]*) die "The running container returned an invalid NCT account count." ;; esac
original_build_id=$(docker exec "$CONTAINER" python -c 'from app.build_info import BUILD_ID; print(BUILD_ID)') ||
    die "The running NCT build identity could not be read."
original_build_commit=$(docker exec "$CONTAINER" python -c 'from app.build_info import BUILD_COMMIT; print(BUILD_COMMIT)') ||
    die "The running NCT build commit could not be read."
[ -n "$original_build_id" ] && [ -n "$original_build_commit" ] ||
    die "The running NCT build identity is incomplete."

say "Loading the verified release image..."
docker load -i "$ARCHIVE" >/dev/null
docker image inspect "$IMAGE" >/dev/null 2>&1 || die "The expected release image was not loaded."

timestamp=$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "$BACKUP_DIR"
chmod 700 "$PERSIST_ROOT" "$STATE_DIR" "$BACKUP_DIR"
before="$BACKUP_DIR/pre-upgrade-$timestamp.json"
after="$BACKUP_DIR/post-upgrade-$timestamp.json"
backup="$BACKUP_DIR/nct-data-$timestamp.tar.gz"
schema_preflight="$BACKUP_DIR/schema-preflight-$timestamp.json"

preflight_binding_code='
import hashlib, json, pathlib, sys
root = pathlib.Path("/verification")
report_path = root / sys.argv[1]
inventory_path = root / sys.argv[2]
report = json.loads(report_path.read_text(encoding="utf-8"))
inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
if report.get("status") != "pass":
    raise SystemExit("Schema preflight report did not record a passing result")
database = inventory.get("restore_files", {}).get("analyzer.db")
if not database or not database.get("sha256"):
    raise SystemExit("Pre-upgrade inventory does not contain analyzer.db identity")
if report.get("database_sha256") != database["sha256"]:
    raise SystemExit("Schema preflight report does not match the inventoried analyzer.db")
digest = hashlib.sha256(report_path.read_bytes()).hexdigest()
print(digest)
'

snapshot_code='
import hashlib, json, pathlib, sqlite3, sys
root = pathlib.Path("/data")
def hash_file(path):
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
            size += len(block)
    return {"size": size, "sha256": digest.hexdigest()}
files = {}
restore_files = {}
for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
    if path.is_symlink():
        raise SystemExit(f"Saved data contains a symbolic link: {path.relative_to(root)}")
    if not path.is_file() or path.name == ".nct-writer.lock":
        continue
    relative = path.relative_to(root).as_posix()
    identity = hash_file(path)
    restore_files[relative] = identity
    if path.name not in {"analyzer.db", "analyzer.db-wal", "analyzer.db-shm", "analyzer.db-journal"}:
        files[relative] = identity
result = {
    "files": files,
    "restore_files": restore_files,
    "database": {"present": False, "integrity": None, "foreign_key_errors": [], "tables": {}},
    "artifact_registry": [],
}
db_path = root / "analyzer.db"
if db_path.exists():
    immutable = len(sys.argv) > 1 and sys.argv[1] == "immutable"
    suffix = "&immutable=1" if immutable else ""
    db = sqlite3.connect(f"file:{db_path}?mode=ro{suffix}", uri=True)
    result["database"]["present"] = True
    result["database"]["integrity"] = db.execute("PRAGMA integrity_check").fetchone()[0]
    result["database"]["foreign_key_errors"] = [list(row) for row in db.execute("PRAGMA foreign_key_check")]
    existing = sorted(row[0] for row in db.execute(
        "SELECT name FROM sqlite_master WHERE type = \"table\" AND name NOT LIKE \"sqlite_%\""
    ))
    for table in existing:
        escaped = table.replace("\"", "\"\"")
        result["database"]["tables"][table] = int(
            db.execute(f"SELECT COUNT(*) FROM \"{escaped}\"").fetchone()[0]
        )
    if "artifact_registry" in existing:
        for digest, size_bytes, canonical_path in db.execute(
            "SELECT sha256, size_bytes, canonical_path FROM artifact_registry ORDER BY sha256"
        ):
            path = pathlib.Path(canonical_path).resolve()
            try:
                path.relative_to(root.resolve())
            except ValueError as exc:
                raise SystemExit(f"Artifact path escapes /data: {canonical_path}") from exc
            observed = hash_file(path)
            if observed != {"size": int(size_bytes), "sha256": digest}:
                raise SystemExit(f"Registered artifact does not match retained bytes: {digest}")
            result["artifact_registry"].append(observed)
    db.close()
if result["database"]["present"]:
    if result["database"]["integrity"] != "ok" or result["database"]["foreign_key_errors"]:
        raise SystemExit("Saved database integrity or foreign-key validation failed")
print(json.dumps(result, sort_keys=True))
'

snapshot() {
    output=$1
    source=${2:-sidecar}
    if [ "$source" = "container" ]; then
        docker exec "$CONTAINER" python -c "$snapshot_code" > "$output"
    else
        docker run --rm -v "$DATA_DIR:/data:ro,Z" "$IMAGE" python -c "$snapshot_code" immutable > "$output"
    fi
    chmod 600 "$output"
}
verify_rollback_identity() {
    [ -n "$rollback" ] && docker inspect "$rollback" >/dev/null 2>&1 || return 1
    [ "$(docker inspect --format '{{.Id}}' "$rollback")" = "$original_container_id" ] || return 1
    [ "$(docker inspect --format '{{.Image}}' "$rollback")" = "$original_image_id" ] || return 1
    rollback_mount_type=$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Type}}{{end}}{{end}}' "$rollback")
    rollback_mount_source=$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Source}}{{end}}{{end}}' "$rollback")
    [ "$rollback_mount_type" = "$mount_type" ] && [ "$rollback_mount_source" = "$mount_source" ]
}
start_original_if_needed() {
    [ "$was_running" = "true" ] || return 0
    [ -z "$original_restart_policy" ] || docker update --restart="$original_restart_policy" "$CONTAINER" >/dev/null 2>&1 || return 1
    docker start "$CONTAINER" >/dev/null 2>&1 || return 1
    attempt=0
    until health=$(curl --connect-timeout 2 --max-time 5 -ksS "https://$RANGE_IP:$original_host_port/health" 2>/dev/null); do
        attempt=$((attempt + 1))
        if [ "$attempt" -ge 15 ]; then
            docker update --restart=no "$CONTAINER" >/dev/null 2>&1 || true
            docker stop "$CONTAINER" >/dev/null 2>&1 || true
            return 1
        fi
        sleep 1
    done
    if ! printf '%s' "$health" | grep -q '"status":"ok"'; then
        docker update --restart=no "$CONTAINER" >/dev/null 2>&1 || true
        docker stop "$CONTAINER" >/dev/null 2>&1 || true
        return 1
    fi
}

was_running=$(docker inspect --format '{{.State.Running}}' "$CONTAINER")
rollback=""
original_stopped=no
backup_ready=no
candidate_may_have_written=no
upgrade_complete=no
restore_original() {
    original_status=$?
    trap - EXIT HUP INT TERM
    set +e
    restored=no
    restore_ok=yes
    if [ "$upgrade_complete" != "yes" ]; then
        if [ "$candidate_may_have_written" = "yes" ] && [ "$backup_ready" = "yes" ] && [ -n "$rollback" ]; then
            failed_container="nct-failed-upgrade-$timestamp"
            failed_data="$PERSIST_ROOT/failed-upgrade-data-$timestamp"
            if docker inspect "$CONTAINER" >/dev/null 2>&1; then
                docker update --restart=no "$CONTAINER" >/dev/null 2>&1 || restore_ok=no
                [ "$restore_ok" != "yes" ] || docker stop "$CONTAINER" >/dev/null 2>&1 || restore_ok=no
                [ "$restore_ok" != "yes" ] || [ "$(docker inspect --format '{{.State.Running}}' "$CONTAINER" 2>/dev/null)" = "false" ] || restore_ok=no
                [ "$restore_ok" != "yes" ] || docker rename "$CONTAINER" "$failed_container" >/dev/null 2>&1 || restore_ok=no
            fi
            if [ "$restore_ok" = "yes" ] && [ -d "$DATA_DIR" ] && [ ! -e "$failed_data" ]; then
                mv "$DATA_DIR" "$failed_data" || restore_ok=no
                [ "$restore_ok" != "yes" ] || [ ! -e "$DATA_DIR" ] || restore_ok=no
            else
                restore_ok=no
            fi
            sha256sum -c "$backup.sha256" >/dev/null 2>&1 || restore_ok=no
            [ "$restore_ok" != "yes" ] || tar -C "$PERSIST_ROOT" -xzf "$backup" || restore_ok=no
            restored_inventory="$BACKUP_DIR/restored-$timestamp.json"
            [ "$restore_ok" != "yes" ] || snapshot "$restored_inventory" || restore_ok=no
            [ "$restore_ok" != "yes" ] || cmp -s "$before" "$restored_inventory" || restore_ok=no
            if [ "$restore_ok" = "yes" ] && verify_rollback_identity; then
                docker rename "$rollback" "$CONTAINER" >/dev/null 2>&1 || restore_ok=no
                [ "$restore_ok" != "yes" ] || start_original_if_needed || restore_ok=no
                [ "$restore_ok" != "yes" ] || restored=yes
            fi
            if [ "$restored" != "yes" ]; then
                original_status=1
                printf '%s\n' "[NCT upgrade] HALT: automatic restore did not verify. The old application was not started. Preserve $failed_data, $backup, and $rollback for administrator recovery." >&2
            fi
        elif [ -n "$rollback" ] && verify_rollback_identity; then
            docker rename "$rollback" "$CONTAINER" >/dev/null 2>&1 || restore_ok=no
            start_original_if_needed || restore_ok=no
            [ "$restore_ok" != "yes" ] || restored=yes
        elif [ "$original_stopped" = "yes" ]; then
            start_original_if_needed || restore_ok=no
            [ "$restore_ok" != "yes" ] || restored=yes
        fi
        if [ "$restored" = "yes" ]; then
            if [ -f "$backup" ]; then
                printf '%s\n' "[NCT upgrade] The original container and verified pre-upgrade data were restored. Data backup: $backup" >&2
            else
                printf '%s\n' "[NCT upgrade] The original container was restored. No completed data backup was created." >&2
            fi
        fi
    fi
    exit "$original_status"
}
trap restore_original EXIT
trap 'exit 130' HUP INT TERM

if [ "$was_running" = "true" ]; then
    original_stopped=yes
    docker stop "$CONTAINER" >/dev/null
fi
say "Checkpointing the stopped database with the retained original image..."
docker run --rm -v "$DATA_DIR:/data:Z" "$original_image_id" python -c '
import pathlib, sqlite3
path = pathlib.Path("/data/analyzer.db")
if path.exists():
    db = sqlite3.connect(path)
    result = db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
    db.close()
    if result is None or int(result[0]) != 0:
        raise SystemExit(f"SQLite WAL checkpoint did not complete: {result}")
' || die "The stopped database could not be checkpointed with the retained original image. The original NCT container will be restored."
check_active sidecar
say "Auditing the stopped saved database with the replacement image (read-only)..."
docker run --rm \
    -e PYTHONPATH=/app \
    -v "$DATA_DIR:/data:ro,Z" \
    -v "$SCHEMA_PREFLIGHT:/opt/nct-schema-preflight.py:ro,Z" \
    "$IMAGE" python /opt/nct-schema-preflight.py --db /data/analyzer.db \
        --expected-build-id "$original_build_id" \
        --expected-build-commit "$original_build_commit" \
        --required-source-version 6 > "$schema_preflight" ||
    die "The saved schema is not an exact supported upgrade source. The original NCT container will be restored."
chmod 600 "$schema_preflight"
snapshot "$before"
schema_preflight_sha256=$(docker run --rm \
    -v "$BACKUP_DIR:/verification:ro,Z" \
    "$IMAGE" python -c "$preflight_binding_code" \
    "$(basename "$schema_preflight")" "$(basename "$before")") ||
    die "The schema audit does not match the exact database backup inventory. The original NCT container will be restored."
[ "${#schema_preflight_sha256}" -eq 64 ] ||
    die "The schema audit checksum is invalid. The original NCT container will be restored."
case "$schema_preflight_sha256" in
    *[!0-9a-f]*) die "The schema audit checksum is invalid. The original NCT container will be restored." ;;
esac
tar -C "$PERSIST_ROOT" -czf "$backup" data
chmod 600 "$backup"
sha256sum "$backup" > "$backup.sha256"
chmod 600 "$backup.sha256"
if [ -n "${NCT_PACKAGE_RUNTIME_CLONE:-}" ]; then
    verification_root=$(mktemp -d "$BACKUP_DIR/verify-$timestamp-XXXXXX")
    tar -C "$verification_root" -xzf "$backup" || die "Cold backup could not be independently extracted; replacement was not started."
    original_data_directory=$DATA_DIR
    DATA_DIR="$verification_root/data"
    snapshot "$BACKUP_DIR/backup-verification-$timestamp.json" || die "Extracted backup inventory failed; replacement was not started."
    DATA_DIR=$original_data_directory
    cmp -s "$before" "$BACKUP_DIR/backup-verification-$timestamp.json" || die "Extracted backup differs from stopped evidence; replacement was not started."
    case "$verification_root" in "$BACKUP_DIR"/verify-"$timestamp"-*) python3 -c 'import shutil,sys; shutil.rmtree(sys.argv[1])' "$verification_root" ;; *) die "Unexpected verification folder; preserve it for review." ;; esac
fi
backup_ready=yes

rollback="nct-upgrade-rollback-$timestamp"
docker rename "$CONTAINER" "$rollback"

if [ "$MODE" = "auto" ]; then
    server_api=$(docker version --format '{{.Server.APIVersion}}' 2>/dev/null || printf unknown)
    case "$server_api" in unknown|'') die "Docker server API version could not be read." ;; esac
    if api_at_least "$server_api" 1.41; then
        if docker compose version >/dev/null 2>&1; then MODE=compose; else MODE=docker; fi
    elif api_at_least "$server_api" 1.39; then
        MODE=legacy
    else
        die "Docker API $server_api is older than the supported Range floor of 1.39."
    fi
fi
start_script="$WORKDIR/scripts/nct-start-$MODE.sh"
[ -f "$start_script" ] || die "Missing $start_script"
say "Starting the release with the $MODE path..."
candidate_may_have_written=yes
if [ -n "${NCT_PACKAGE_RUNTIME_CLONE:-}" ]; then
    [ "$NCT_PACKAGE_RUNTIME_CLONE" = "$WORKDIR/scripts/nct-clone-release-runtime.py" ] || die "Unrecognized package runtime adapter."
    python3 "$NCT_PACKAGE_RUNTIME_CLONE" --original-id "$original_container_id" --image "$IMAGE" --name "$CONTAINER" --url "https://$RANGE_IP:$original_host_port" --ca-file "${NCT_CA_FILE:-$PERSIST_ROOT/tls-material/certs/nct-lab-root.crt}"
else
    NCT_HTTPS_PORT="$original_host_port" NCT_UPGRADE_ACCOUNT_COUNT="$account_count" sh "$start_script" "$RANGE_IP"
fi
snapshot "$after" container
candidate_port_lines=$(docker inspect --format '{{range $port,$items := .HostConfig.PortBindings}}{{if or (eq $port "8080/tcp") (eq $port "8445/tcp")}}{{range $items}}{{printf "%s|%s\n" $port .HostPort}}{{end}}{{end}}{{end}}' "$CONTAINER" | tr -d '\r' | sed '/^$/d' | sort -u)
[ "$(printf '%s\n' "$candidate_port_lines" | sed '/^$/d' | wc -l | tr -d ' ')" = 1 ] ||
    die "The upgraded NCT listener and host port are missing or ambiguous."
candidate_host_port=${candidate_port_lines#*|}
case "$candidate_host_port" in ''|*[!0-9]*) die "The upgraded NCT HTTPS host port could not be identified." ;; esac
[ "$candidate_host_port" -ge 1 ] && [ "$candidate_host_port" -le 65535 ] || die "The upgraded NCT HTTPS host port is invalid."

docker run --rm -v "$BACKUP_DIR:/verification:ro,Z" "$IMAGE" python -c '
import json, pathlib, sys
before = json.loads(pathlib.Path("/verification", sys.argv[1]).read_text())
after = json.loads(pathlib.Path("/verification", sys.argv[2]).read_text())
for path, identity in before["files"].items():
    if after["files"].get(path) != identity:
        raise SystemExit(f"Retained file changed or disappeared during upgrade: {path}")
if after["artifact_registry"] != before["artifact_registry"]:
    raise SystemExit("Registered artifact identity changed during upgrade")
for table, count in before["database"]["tables"].items():
    if table in {"scan_history_index_dirty", "scan_history_groups", "scan_history_memberships"}:
        continue  # Disposable history metadata; retained scan_runs remain checked.
    if after["database"]["tables"].get(table, 0) < count:
        raise SystemExit(f"Stored record count decreased for {table}")
' "$(basename "$before")" "$(basename "$after")"

receipt="$STATE_DIR/upgrade-$timestamp.receipt"
{
    printf 'completed=%s\n' "$(date -u +%FT%TZ)"
    printf 'image=%s\n' "$IMAGE"
    printf 'data_directory=%s\n' "$DATA_DIR"
    printf 'backup=%s\n' "$backup"
    printf 'backup_checksum=%s\n' "$backup.sha256"
    printf 'schema_preflight=%s\n' "$schema_preflight"
    printf 'schema_preflight_sha256=%s\n' "$schema_preflight_sha256"
    printf 'rollback_container=%s\n' "$rollback"
    printf 'rollback_container_id=%s\n' "$original_container_id"
    printf 'rollback_image_id=%s\n' "$original_image_id"
    printf 'rollback_data_mount_type=%s\n' "$mount_type"
    printf 'rollback_data_mount_source=%s\n' "$mount_source"
    printf 'rollback_host_port=%s\n' "$original_host_port"
    printf 'candidate_host_port=%s\n' "$candidate_host_port"
    printf 'pre_upgrade_inventory=%s\n' "$before"
    printf 'post_upgrade_inventory=%s\n' "$after"
} > "$receipt"
chmod 600 "$receipt"

upgrade_complete=yes
trap - EXIT HUP INT TERM
say "Upgrade verified. NCT is ready at https://$RANGE_IP:$candidate_host_port"
say "Data backup: $backup"
say "Read-only schema audit: $schema_preflight"
say "Rollback container retained (stopped): $rollback"
say "Receipt: $receipt"
