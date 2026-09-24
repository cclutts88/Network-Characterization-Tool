#!/bin/sh
set -eu

WORKDIR="${NCT_WORKDIR:-/root/NCT-Air-Gapped-Range-Deployment}"
PERSIST_ROOT="${NCT_PERSIST_ROOT:-/var/lib/nct}"
DATA_DIR="$PERSIST_ROOT/data"
CONTAINER="${NCT_CONTAINER:-nct}"
IMAGE="network-characterization-tool:0.15.2-range-20260924"
RANGE_IP="${1:-}"
MODE="${2:-auto}"
ARCHIVE="$WORKDIR/offline-images/nct-range-images.tar"
CHECKSUM="$WORKDIR/offline-images/nct-range-images.tar.sha256"
STATE_DIR="$PERSIST_ROOT/deployment"
BACKUP_DIR="$STATE_DIR/backups"

say() { printf '%s\n' "[NCT upgrade] $*"; }
die() { printf '%s\n' "[NCT upgrade] ERROR: $*" >&2; exit 1; }
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
for command_name in docker sha256sum tar; do
    command -v "$command_name" >/dev/null 2>&1 || die "$command_name is required."
done
docker info >/dev/null 2>&1 || die "Docker is not reachable."
[ -f "$ARCHIVE" ] || die "Missing $ARCHIVE"
[ -f "$CHECKSUM" ] || die "Missing $CHECKSUM"
(cd "$WORKDIR/offline-images" && sha256sum -c "$(basename "$CHECKSUM")" >/dev/null) ||
    die "The offline image archive checksum does not match."
docker inspect "$CONTAINER" >/dev/null 2>&1 ||
    die "Container $CONTAINER was not found. Use a start script for a new installation."

mount_type=$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Type}}{{end}}{{end}}' "$CONTAINER")
mount_source=$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Source}}{{end}}{{end}}' "$CONTAINER")
[ "$mount_type" = "bind" ] && [ "$mount_source" = "$DATA_DIR" ] ||
    die "$CONTAINER does not store /data at $DATA_DIR. Run nct-migrate-data.sh first."

set +e
docker exec "$CONTAINER" python -c '
import glob, json, sys
active = []
for path in glob.glob("/data/**/manifest.json", recursive=True):
    try:
        item = json.load(open(path, encoding="utf-8"))
        if item.get("status") in {"queued", "running", "awaiting_fallback_approval", "updating", "migrating"}:
            active.append(path)
    except Exception:
        pass
sys.exit(42 if active else 0)
' >/dev/null 2>&1
active_rc=$?
set -e
[ "$active_rc" -ne 42 ] || die "NCT has active work. Finish or stop it before upgrading."
[ "$active_rc" -eq 0 ] || die "Current NCT data could not be checked for active work."

say "Loading the verified release image..."
docker load -i "$ARCHIVE" >/dev/null
docker image inspect "$IMAGE" >/dev/null 2>&1 || die "The expected release image was not loaded."

timestamp=$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "$BACKUP_DIR"
chmod 700 "$PERSIST_ROOT" "$STATE_DIR" "$BACKUP_DIR"
before="$BACKUP_DIR/pre-upgrade-$timestamp.json"
after="$BACKUP_DIR/post-upgrade-$timestamp.json"
backup="$BACKUP_DIR/nct-data-$timestamp.tar.gz"

snapshot() {
    output=$1
    docker run --rm -v "$DATA_DIR:/data:ro,Z" "$IMAGE" python -c '
import json, pathlib, sqlite3, sys
root = pathlib.Path("/data")
tables = (
    "imports", "scan_runs", "scan_profiles", "scan_schedules", "saved_networks",
    "analyst_users", "analyst_investigation_notes", "analyst_workspace_layouts",
    "analyst_scan_drafts", "analyst_view_preferences", "analyst_filter_presets",
    "host_os_overrides", "host_os_inference_reviews", "analyst_host_identities",
)
result = {
    "file_count": sum(path.is_file() for path in root.rglob("*")),
    "tables": {},
}
db_path = root / "analyzer.db"
if db_path.exists():
    db = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    existing = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type = ?", ("table",))}
    for table in tables:
        if table in existing:
            result["tables"][table] = db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
print(json.dumps(result, sort_keys=True))
' > "$output"
    chmod 600 "$output"
}

was_running=$(docker inspect --format '{{.State.Running}}' "$CONTAINER")
[ "$was_running" != "true" ] || docker stop "$CONTAINER" >/dev/null
snapshot "$before"
tar -C "$PERSIST_ROOT" -czf "$backup" data
chmod 600 "$backup"
sha256sum "$backup" > "$backup.sha256"
chmod 600 "$backup.sha256"

rollback="nct-upgrade-rollback-$timestamp"
docker rename "$CONTAINER" "$rollback"
upgrade_complete=no
restore_original() {
    status=$?
    if [ "$upgrade_complete" != "yes" ]; then
        if docker inspect "$CONTAINER" >/dev/null 2>&1; then
            docker stop "$CONTAINER" >/dev/null 2>&1 || true
            docker rm "$CONTAINER" >/dev/null 2>&1 || true
        fi
        if docker inspect "$rollback" >/dev/null 2>&1; then
            docker rename "$rollback" "$CONTAINER" >/dev/null 2>&1 || true
            [ "$was_running" != "true" ] || docker start "$CONTAINER" >/dev/null 2>&1 || true
        fi
        printf '%s\n' "[NCT upgrade] The original container was restored. Data backup: $backup" >&2
    fi
    exit "$status"
}
trap restore_original EXIT
trap 'exit 130' HUP INT TERM

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
sh "$start_script" "$RANGE_IP"
snapshot "$after"

docker run --rm -v "$BACKUP_DIR:/verification:ro,Z" "$IMAGE" python -c '
import json, pathlib, sys
before = json.loads(pathlib.Path("/verification", sys.argv[1]).read_text())
after = json.loads(pathlib.Path("/verification", sys.argv[2]).read_text())
if after["file_count"] < before["file_count"]:
    raise SystemExit("Stored file count decreased during upgrade")
for table, count in before["tables"].items():
    if after["tables"].get(table, 0) < count:
        raise SystemExit(f"Stored record count decreased for {table}")
' "$(basename "$before")" "$(basename "$after")"

receipt="$STATE_DIR/upgrade-$timestamp.receipt"
{
    printf 'completed=%s\n' "$(date -u +%FT%TZ)"
    printf 'image=%s\n' "$IMAGE"
    printf 'data_directory=%s\n' "$DATA_DIR"
    printf 'backup=%s\n' "$backup"
    printf 'backup_checksum=%s\n' "$backup.sha256"
    printf 'rollback_container=%s\n' "$rollback"
    printf 'pre_upgrade_inventory=%s\n' "$before"
    printf 'post_upgrade_inventory=%s\n' "$after"
} > "$receipt"
chmod 600 "$receipt"

upgrade_complete=yes
trap - EXIT HUP INT TERM
say "Upgrade verified. NCT is ready at https://$RANGE_IP:8445"
say "Data backup: $backup"
say "Rollback container retained (stopped): $rollback"
say "Receipt: $receipt"
