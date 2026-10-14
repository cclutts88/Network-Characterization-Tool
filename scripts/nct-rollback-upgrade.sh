#!/bin/sh
set -eu

WORKDIR="${NCT_WORKDIR:-/root/NCT-Air-Gapped-Range-Deployment}"
PERSIST_ROOT="${NCT_PERSIST_ROOT:-/var/lib/nct}"
DATA_DIR="$PERSIST_ROOT/data"
CONTAINER="${NCT_CONTAINER:-nct}"
IMAGE="network-characterization-tool:0.16.0-range-test-20261013-phase3-r2"
STATE_DIR="$PERSIST_ROOT/deployment"
BACKUP_DIR="$STATE_DIR/backups"
DATA_CHECK="$WORKDIR/scripts/nct-range-data-check.py"
RANGE_IP="${1:-}"
RECEIPT="${2:-}"

say() { printf '%s\n' "[NCT rollback] $*"; }
die() { printf '%s\n' "[NCT rollback] HALT: $*" >&2; exit 1; }
receipt_value() {
    awk -F= -v key="$1" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' "$RECEIPT"
}
valid_container_id() {
    value=$1
    case "$value" in *[!0-9a-f]*) return 1 ;; esac
    [ "${#value}" -eq 64 ]
}
check_active() {
    set +e
    docker run --rm \
        -v "$DATA_DIR:/data:ro,Z" \
        -v "$DATA_CHECK:/opt/nct-range-data-check.py:ro,Z" \
        "$IMAGE" python /opt/nct-range-data-check.py active --root /data
    active_rc=$?
    set -e
    [ "$active_rc" -ne 42 ] || die "NCT has active or unresolved work. Finish, cancel, or review it before rollback."
    [ "$active_rc" -eq 0 ] || die "Current NCT data could not be checked for active work."
}
snapshot() {
    output=$1
    docker run --rm \
        -v "$DATA_DIR:/data:ro,Z" \
        -v "$DATA_CHECK:/opt/nct-range-data-check.py:ro,Z" \
        "$IMAGE" python /opt/nct-range-data-check.py snapshot --root /data > "$output"
    chmod 600 "$output"
}
stop_unhealthy_previous() {
    reason=$1
    if ! docker stop "$CONTAINER" >/dev/null 2>&1; then
        die "EMERGENCY: $reason Docker could not stop the previous container; it may still be running. Preserve all recovery sources and contact the Range administrator now."
    fi
    running=$(docker inspect --format '{{.State.Running}}' "$CONTAINER" 2>/dev/null) ||
        die "EMERGENCY: $reason The previous container's stopped state could not be confirmed. Preserve all recovery sources and contact the Range administrator now."
    [ "$running" = "false" ] ||
        die "EMERGENCY: $reason The previous container is still running. Preserve all recovery sources and contact the Range administrator now."
    die "$reason The previous container was stopped. Preserve all recovery sources."
}

[ "$(id -u)" -eq 0 ] || die "Run this script as root."
[ -n "$RANGE_IP" ] && [ -n "$RECEIPT" ] ||
    die "Usage: sh $WORKDIR/scripts/nct-rollback-upgrade.sh RANGE_IP UPGRADE_RECEIPT"
for command_name in docker sha256sum tar cmp awk curl grep; do
    command -v "$command_name" >/dev/null 2>&1 || die "$command_name is required."
done
docker info >/dev/null 2>&1 || die "Docker is not reachable."
[ -f "$DATA_CHECK" ] || die "Missing $DATA_CHECK"
[ -f "$RECEIPT" ] || die "Upgrade receipt was not found: $RECEIPT"
case "$RECEIPT" in "$STATE_DIR"/upgrade-*.receipt) ;; *) die "Use the exact upgrade receipt under $STATE_DIR." ;; esac

backup=$(receipt_value backup)
checksum=$(receipt_value backup_checksum)
rollback=$(receipt_value rollback_container)
rollback_container_id=$(receipt_value rollback_container_id)
rollback_image_id=$(receipt_value rollback_image_id)
rollback_data_mount_type=$(receipt_value rollback_data_mount_type)
rollback_data_mount_source=$(receipt_value rollback_data_mount_source)
rollback_host_port=$(receipt_value rollback_host_port)
before=$(receipt_value pre_upgrade_inventory)
case "$backup" in "$BACKUP_DIR"/nct-data-*.tar.gz) ;; *) die "Receipt backup path is outside $BACKUP_DIR." ;; esac
[ "$checksum" = "$backup.sha256" ] || die "Receipt backup checksum path does not match the backup."
case "$before" in "$BACKUP_DIR"/pre-upgrade-*.json) ;; *) die "Receipt inventory path is outside $BACKUP_DIR." ;; esac
case "$rollback" in nct-upgrade-rollback-*) ;; *) die "Receipt rollback-container name is invalid." ;; esac
valid_container_id "$rollback_container_id" || die "Receipt rollback-container identity is invalid."
case "$rollback_image_id" in sha256:*) ;; *) die "Receipt rollback-image identity is invalid." ;; esac
[ "$rollback_data_mount_type" = "bind" ] || die "Receipt rollback mount type is not the required host-folder bind mount."
[ "$rollback_data_mount_source" = "$DATA_DIR" ] || die "Receipt rollback data path does not match $DATA_DIR."
case "$rollback_host_port" in ''|*[!0-9]*) die "Receipt rollback HTTPS port is invalid." ;; esac
[ "$rollback_host_port" -ge 1 ] && [ "$rollback_host_port" -le 65535 ] || die "Receipt rollback HTTPS port is invalid."
[ -f "$backup" ] && [ -f "$checksum" ] && [ -f "$before" ] ||
    die "The receipt's backup, checksum, or pre-upgrade inventory is missing."
docker image inspect "$IMAGE" >/dev/null 2>&1 || die "The verified release image is not loaded."
docker inspect "$CONTAINER" >/dev/null 2>&1 || die "Current container $CONTAINER was not found."
docker inspect "$rollback" >/dev/null 2>&1 || die "Rollback container $rollback was not found."
[ "$(docker inspect --format '{{.Id}}' "$rollback")" = "$rollback_container_id" ] ||
    die "The retained rollback container does not match the exact container recorded during upgrade."
[ "$(docker inspect --format '{{.Image}}' "$rollback")" = "$rollback_image_id" ] ||
    die "The retained rollback container does not use the exact image recorded during upgrade."
retained_mount_type=$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Type}}{{end}}{{end}}' "$rollback")
retained_mount_source=$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Source}}{{end}}{{end}}' "$rollback")
[ "$retained_mount_type" = "$rollback_data_mount_type" ] && [ "$retained_mount_source" = "$rollback_data_mount_source" ] ||
    die "The retained rollback container's data mount does not match the upgrade receipt."
mount_type=$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Type}}{{end}}{{end}}' "$CONTAINER")
mount_source=$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Source}}{{end}}{{end}}' "$CONTAINER")
[ "$mount_type" = "bind" ] && [ "$mount_source" = "$DATA_DIR" ] ||
    die "$CONTAINER does not store /data at $DATA_DIR."

check_active
timestamp=$(date -u +%Y%m%dT%H%M%SZ)
failed_container="nct-failed-upgrade-$timestamp"
failed_data="$PERSIST_ROOT/failed-upgrade-data-$timestamp"
restored_inventory="$BACKUP_DIR/restored-$timestamp.json"
rollback_receipt="$STATE_DIR/rollback-$timestamp.receipt"
[ ! -e "$failed_data" ] || die "Preservation path already exists: $failed_data"
docker inspect "$failed_container" >/dev/null 2>&1 && die "Preservation container already exists: $failed_container"

say "Stopping the candidate and confirming that no work remains active..."
docker stop "$CONTAINER" >/dev/null
check_active
docker rename "$CONTAINER" "$failed_container"
mv "$DATA_DIR" "$failed_data"

say "Verifying and restoring the cold pre-upgrade backup..."
sha256sum -c "$checksum" >/dev/null || die "The cold-backup checksum failed. The old application was not started."
tar -C "$PERSIST_ROOT" -xzf "$backup" || die "The cold backup could not be restored. The old application was not started."
snapshot "$restored_inventory" || die "The restored data could not be inspected. The old application was not started."
cmp -s "$before" "$restored_inventory" ||
    die "The restored full inventory does not match the pre-upgrade inventory. The old application was not started."

say "Starting the previous container only after the restored inventory matched..."
docker rename "$rollback" "$CONTAINER"
docker start "$CONTAINER" >/dev/null
if ! health=$(curl --connect-timeout 2 --max-time 5 -ksS "https://$RANGE_IP:$rollback_host_port/health"); then
    stop_unhealthy_previous "The previous container's health check failed."
fi
if ! printf '%s' "$health" | grep -q '"status":"ok"'; then
    stop_unhealthy_previous "The previous container reported unhealthy."
fi

{
    printf 'completed=%s\n' "$(date -u +%FT%TZ)"
    printf 'source_upgrade_receipt=%s\n' "$RECEIPT"
    printf 'restored_backup=%s\n' "$backup"
    printf 'restored_inventory=%s\n' "$restored_inventory"
    printf 'failed_container=%s\n' "$failed_container"
    printf 'failed_data=%s\n' "$failed_data"
    printf 'restored_container_id=%s\n' "$rollback_container_id"
    printf 'restored_image_id=%s\n' "$rollback_image_id"
    printf 'restored_data_mount=%s\n' "$rollback_data_mount_source"
    printf 'restored_host_port=%s\n' "$rollback_host_port"
    printf 'health=%s\n' "$health"
} > "$rollback_receipt"
chmod 600 "$rollback_receipt"
say "Rollback verified. The installation returned to the backup time."
say "Failed candidate container: $failed_container"
say "Failed candidate data: $failed_data"
say "Rollback receipt: $rollback_receipt"
