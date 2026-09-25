#!/bin/sh
set -eu

WORKDIR="${NCT_WORKDIR:-/root/NCT-Air-Gapped-Range-Deployment}"
PERSIST_ROOT="${NCT_PERSIST_ROOT:-/var/lib/nct}"
DATA_DIR="$PERSIST_ROOT/data"
SOURCE_VOLUME="${NCT_SOURCE_VOLUME:-nct-data}"
CONTAINER="${NCT_CONTAINER:-nct}"
IMAGE="network-characterization-tool:0.15.3-range-20260924"
ARCHIVE="$WORKDIR/offline-images/nct-range-images.tar"
CHECKSUM="$WORKDIR/offline-images/nct-range-images.tar.sha256"

say() { printf '%s\n' "[NCT data migration] $*"; }
die() { printf '%s\n' "[NCT data migration] ERROR: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Run this script as root."
for command_name in docker sha256sum; do
    command -v "$command_name" >/dev/null 2>&1 || die "$command_name is required."
done
docker info >/dev/null 2>&1 || die "Docker is not reachable."
case "$PERSIST_ROOT" in
    /*) ;;
    *) die "NCT_PERSIST_ROOT must be an absolute host path." ;;
esac
case "$PERSIST_ROOT" in
    /|/var|/var/lib) die "Refusing unsafe persistent root: $PERSIST_ROOT" ;;
esac
[ "$DATA_DIR" != "$PERSIST_ROOT" ] || die "The data directory must be below the persistent root."

[ -f "$ARCHIVE" ] || die "Missing $ARCHIVE"
[ -f "$CHECKSUM" ] || die "Missing $CHECKSUM"
(cd "$WORKDIR/offline-images" && sha256sum -c "$(basename "$CHECKSUM")" >/dev/null) ||
    die "The offline image archive checksum does not match."
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    say "Loading the verified NCT image needed for the migration checks..."
    docker load -i "$ARCHIVE"
fi
docker image inspect "$IMAGE" >/dev/null 2>&1 || die "The expected NCT image is unavailable."
docker volume inspect "$SOURCE_VOLUME" >/dev/null 2>&1 || die "Docker volume $SOURCE_VOLUME was not found."

existing_container="no"
was_running="false"
rollback_name=""
migration_complete="no"
if docker inspect "$CONTAINER" >/dev/null 2>&1; then
    existing_container="yes"
    mount_type=$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Type}}{{end}}{{end}}' "$CONTAINER")
    mount_source=$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Source}}{{end}}{{end}}' "$CONTAINER")
    if [ "$mount_type" = "bind" ] && [ "$mount_source" = "$DATA_DIR" ]; then
        say "$CONTAINER already stores /data at $DATA_DIR. No migration is needed."
        exit 0
    fi
    [ "$mount_type" = "volume" ] || die "$CONTAINER does not use a recognized Docker volume for /data."
    volume_name=$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Name}}{{end}}{{end}}' "$CONTAINER")
    [ "$volume_name" = "$SOURCE_VOLUME" ] || die "$CONTAINER uses volume $volume_name, not expected source $SOURCE_VOLUME. Set NCT_SOURCE_VOLUME only after verifying the correct source."
    was_running=$(docker inspect --format '{{.State.Running}}' "$CONTAINER")
fi

set +e
docker run --rm -v "$SOURCE_VOLUME:/data:ro" "$IMAGE" python -c '
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
[ "$active_rc" -ne 42 ] || die "NCT has active work. Finish or stop it before migrating data."
[ "$active_rc" -eq 0 ] || die "The source volume could not be checked for active work."

mkdir -p "$PERSIST_ROOT"
chmod 700 "$PERSIST_ROOT"
if [ -d "$DATA_DIR" ] && [ -n "$(find "$DATA_DIR" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
    die "$DATA_DIR is not empty. The migration will not merge or overwrite existing data."
fi
mkdir -p "$DATA_DIR" "$PERSIST_ROOT/migration-receipts"
chmod 700 "$DATA_DIR" "$PERSIST_ROOT/migration-receipts"

timestamp=$(date -u +%Y%m%dT%H%M%SZ)
restore_original() {
    status=$?
    if [ "$migration_complete" != "yes" ]; then
        if [ -n "$rollback_name" ] && docker inspect "$rollback_name" >/dev/null 2>&1 && ! docker inspect "$CONTAINER" >/dev/null 2>&1; then
            docker rename "$rollback_name" "$CONTAINER" >/dev/null 2>&1 || true
            [ "$was_running" != "true" ] || docker start "$CONTAINER" >/dev/null 2>&1 || true
        fi
        if [ -d "$DATA_DIR" ] && [ -n "$(find "$DATA_DIR" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]; then
            failed_dir="$PERSIST_ROOT/failed-migration-$timestamp"
            [ -e "$failed_dir" ] || mv "$DATA_DIR" "$failed_dir" 2>/dev/null || true
        fi
    fi
    exit "$status"
}
trap restore_original EXIT
trap 'exit 130' HUP INT TERM

if [ "$existing_container" = "yes" ]; then
    [ "$was_running" != "true" ] || docker stop "$CONTAINER" >/dev/null
    rollback_name="nct-volume-rollback-$timestamp"
    docker rename "$CONTAINER" "$rollback_name"
    say "Retained the stopped original container as $rollback_name."
fi

say "Copying $SOURCE_VOLUME to $DATA_DIR without changing the source volume..."
docker run --rm \
    -v "$SOURCE_VOLUME:/source:ro" \
    -v "$DATA_DIR:/target:Z" \
    "$IMAGE" sh -c 'cp -a /source/. /target/'

verification=$(docker run --rm \
    -v "$SOURCE_VOLUME:/source:ro" \
    -v "$DATA_DIR:/target:ro,Z" \
    "$IMAGE" python -c '
import hashlib
import os
from pathlib import Path

def inventory(root):
    root = Path(root)
    digest = hashlib.sha256()
    file_count = 0
    byte_count = 0
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            digest.update(("L\0" + relative + "\0" + os.readlink(path) + "\0").encode())
        elif path.is_dir():
            digest.update(("D\0" + relative + "\0").encode())
        elif path.is_file():
            content_hash = hashlib.sha256()
            with path.open("rb") as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    content_hash.update(block)
                    byte_count += len(block)
            file_count += 1
            digest.update(("F\0" + relative + "\0" + content_hash.hexdigest() + "\0").encode())
    return file_count, byte_count, digest.hexdigest()

source = inventory("/source")
target = inventory("/target")
if source != target:
    raise SystemExit("Source and target inventories do not match: {} != {}".format(source, target))
print("files={} bytes={} digest={}".format(*target))
') || die "The copied data did not match the source volume. The original container will be restored."

receipt="$PERSIST_ROOT/migration-receipts/volume-to-host-$timestamp.receipt"
{
    printf 'completed=%s\n' "$(date -u +%FT%TZ)"
    printf 'source_volume=%s\n' "$SOURCE_VOLUME"
    printf 'target_directory=%s\n' "$DATA_DIR"
    printf 'verification=%s\n' "$verification"
    printf 'rollback_container=%s\n' "${rollback_name:-none}"
    printf 'source_volume_retained=yes\n'
} > "$receipt"
chmod 600 "$receipt"

migration_complete="yes"
trap - EXIT HUP INT TERM
say "Migration verified: $verification"
say "Persistent NCT data directory: $DATA_DIR"
say "Migration receipt: $receipt"
say "The original Docker volume $SOURCE_VOLUME was retained for rollback."
[ -z "$rollback_name" ] || say "Rollback container retained (stopped): $rollback_name"
say "Run one of the NCT start scripts to start the host-folder deployment."
