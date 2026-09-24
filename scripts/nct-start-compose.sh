#!/bin/sh
set -eu

# NCT WEB INTERFACE PORT -- change 8445 here if the port check shows a conflict.
HOST_PORT=8445

WORKDIR="${NCT_WORKDIR:-/root/NCT-Air-Gapped-Range-Deployment}"
PERSIST_ROOT="${NCT_PERSIST_ROOT:-/var/lib/nct}"
IMAGE="network-characterization-tool:0.15.2-range-20260924"
CONTAINER="nct"
DATA_DIR="$PERSIST_ROOT/data"
RANGE_IP="${1:-}"
ADMIN_USER="${2:-}"
ARCHIVE="$WORKDIR/offline-images/nct-range-images.tar"
CHECKSUM="$WORKDIR/offline-images/nct-range-images.tar.sha256"
COMPOSE_FILE="$WORKDIR/compose.range.yaml"
STATE_DIR="$PERSIST_ROOT/deployment"
TLS_ROOT="$PERSIST_ROOT/tls-material"
BOOTSTRAP_DIR="$STATE_DIR/bootstrap"
BOOTSTRAP_PASSWORD="$BOOTSTRAP_DIR/initial-password.txt"

die() { printf '%s\n' "$*" >&2; exit 1; }
wait_for_health() {
    attempt=0
    until curl -kfsS "https://$RANGE_IP:$HOST_PORT/health" >/dev/null 2>&1; do
        attempt=$((attempt + 1))
        [ "$attempt" -lt 30 ] || return 1
        sleep 1
    done
}

[ "$(id -u)" -eq 0 ] || die "Run this script as root."
[ -n "$RANGE_IP" ] || die "Usage: sh $WORKDIR/scripts/nct-start-compose.sh RANGE_IP [ADMIN_USERNAME]"

for command_name in docker openssl curl sha256sum ss; do
    command -v "$command_name" >/dev/null 2>&1 || die "$command_name is required."
done
docker info >/dev/null 2>&1 || die "Docker is not reachable."
docker compose version >/dev/null 2>&1 || die "The Docker Compose plugin is not available."
[ -f "$ARCHIVE" ] || die "Missing $ARCHIVE"
[ -f "$CHECKSUM" ] || die "Missing $CHECKSUM"
[ -f "$COMPOSE_FILE" ] || die "Missing $COMPOSE_FILE"
[ -f "$WORKDIR/scripts/setup-lab-https.sh" ] || die "Missing the TLS setup helper."
[ -f "$WORKDIR/scripts/nct-set-admin.sh" ] || die "Missing the Administrator setup helper."
(cd "$WORKDIR/offline-images" && sha256sum -c "$(basename "$CHECKSUM")" >/dev/null) ||
    die "The offline image archive checksum does not match."
docker inspect "$CONTAINER" >/dev/null 2>&1 &&
    die "A container named $CONTAINER already exists. This script will not replace it."
if ss -ltn | awk -v p="$HOST_PORT" 'NR > 1 && $4 ~ (":" p "$") { found=1 } END { exit(found ? 0 : 1) }'; then
    die "TCP port $HOST_PORT is in use. Edit HOST_PORT=8445 near the top of this script."
fi

docker load -i "$ARCHIVE"
docker image inspect "$IMAGE" >/dev/null 2>&1 || die "The expected NCT image was not loaded."
mkdir -p "$DATA_DIR" "$BOOTSTRAP_DIR"
chmod 700 "$PERSIST_ROOT" "$DATA_DIR" "$STATE_DIR" "$BOOTSTRAP_DIR"
if [ ! -f "$TLS_ROOT/tls/nct-server.crt" ] && [ ! -f "$TLS_ROOT/tls/nct-server.key" ]; then
    sh "$WORKDIR/scripts/setup-lab-https.sh" "$RANGE_IP" "$TLS_ROOT"
elif [ ! -f "$TLS_ROOT/tls/nct-server.crt" ] || [ ! -f "$TLS_ROOT/tls/nct-server.key" ]; then
    die "TLS material is incomplete under $TLS_ROOT; restore the missing file before continuing."
fi

account_count=$(docker run --rm -v "$DATA_DIR:/data:ro,Z" "$IMAGE" python -c '
import pathlib, sqlite3
p = pathlib.Path("/data/analyzer.db")
print(0 if not p.exists() else sqlite3.connect(p).execute("SELECT COUNT(*) FROM analyst_users").fetchone()[0])
') || die "Existing NCT accounts could not be inspected under $DATA_DIR."
if [ "$account_count" -eq 0 ]; then
    if [ -z "$ADMIN_USER" ]; then
        [ -t 0 ] || die "A new installation requires ADMIN_USERNAME when running non-interactively."
        printf 'Administrator username: ' >&2
        IFS= read -r ADMIN_USER
    fi
    printf '%s' "$ADMIN_USER" | grep -Eq '^[a-z0-9][a-z0-9._-]{1,63}$' ||
        die "Username must be 2-64 lowercase letters, numbers, dots, dashes, or underscores."
fi

export NCT_IMAGE="$IMAGE"
export NCT_BIND_ADDRESS="$RANGE_IP"
export NCT_HTTPS_PORT="$HOST_PORT"
export NCT_DATA_DIR="$DATA_DIR"
export NCT_TLS_ROOT="$TLS_ROOT"
export NCT_BOOTSTRAP_DIR="$BOOTSTRAP_DIR"

printf '%s\n' "Starting NCT with Docker Compose..."
if [ "$account_count" -eq 0 ]; then
    umask 077
    openssl rand -base64 36 | tr -d '\r\n' > "$BOOTSTRAP_PASSWORD"
    export NCT_BOOTSTRAP_ADMIN="$ADMIN_USER"
    export NCT_BOOTSTRAP_PASSWORD_FILE="/run/nct-bootstrap/initial-password.txt"
    docker compose --project-directory "$WORKDIR" -f "$COMPOSE_FILE" up -d
    wait_for_health || die "NCT did not become healthy. Review: docker logs $CONTAINER"
    if ! sh "$WORKDIR/scripts/nct-set-admin.sh" "$ADMIN_USER"; then
        die "Administrator setup did not finish. NCT is still running; the recovery secret remains at $BOOTSTRAP_PASSWORD."
    fi
    rm -f "$BOOTSTRAP_PASSWORD"
    export NCT_BOOTSTRAP_ADMIN=""
    export NCT_BOOTSTRAP_PASSWORD_FILE=""
    docker compose --project-directory "$WORKDIR" -f "$COMPOSE_FILE" up -d --force-recreate
    wait_for_health || die "NCT did not become healthy after removing the bootstrap secret. Review: docker logs $CONTAINER"
else
    printf '%s\n' "Preserving $account_count existing NCT account(s); no password or username will be changed."
    export NCT_BOOTSTRAP_ADMIN=""
    export NCT_BOOTSTRAP_PASSWORD_FILE=""
    docker compose --project-directory "$WORKDIR" -f "$COMPOSE_FILE" up -d
    wait_for_health || die "NCT did not become healthy. Review: docker logs $CONTAINER"
fi

printf '%s\n' "NCT is ready at https://$RANGE_IP:$HOST_PORT"
printf '%s\n' "Persistent operator data: $DATA_DIR"
printf '%s\n' "The existing nmap-terrain-analyzer deployment was not changed."
