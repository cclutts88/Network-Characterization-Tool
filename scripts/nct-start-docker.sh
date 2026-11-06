#!/bin/sh
set -eu

# NCT WEB INTERFACE PORT -- change 8445 here if the port check shows a conflict.
HOST_PORT="${NCT_HTTPS_PORT:-8445}"

WORKDIR="${NCT_WORKDIR:-/root/NCT-Air-Gapped-Range-Deployment}"
PERSIST_ROOT="${NCT_PERSIST_ROOT:-/var/lib/nct}"
IMAGE="network-characterization-tool:0.16.0-range-test-20261013-phase3-r3"
CONTAINER="${NCT_CONTAINER:-nct}"
APP_BIND_ADDRESS="${NCT_APP_BIND_ADDRESS:-${1:-}}"
CONTAINER_PORT=8445
DATA_DIR="$PERSIST_ROOT/data"
RANGE_IP="${1:-}"
ADMIN_USER="${2:-}"
ARCHIVE="$WORKDIR/offline-images/nct-range-images.tar"
CHECKSUM="$WORKDIR/offline-images/nct-range-images.tar.sha256"
STATE_DIR="$PERSIST_ROOT/deployment"
TLS_ROOT="$PERSIST_ROOT/tls-material"
BOOTSTRAP_PASSWORD="$STATE_DIR/bootstrap/initial-password.txt"
FRESH_RESUME_RECEIPT="$STATE_DIR/bootstrap/fresh-resume.json"
RETIREMENT_GUARD_DIR="$PERSIST_ROOT/retirement-guard"
RETIREMENT_DATA_IDENTITY="bind:$DATA_DIR"

die() { printf '%s\n' "$*" >&2; exit 1; }
verify_archive_checksum() {
    expected_checksum=$(awk 'NR == 1 { print $1; exit }' "$CHECKSUM")
    actual_checksum=$(sha256sum "$ARCHIVE" | awk '{print $1}')
    [ -n "$expected_checksum" ] && [ "$actual_checksum" = "$expected_checksum" ]
}
wait_for_health() {
    attempt=0
    until curl --connect-timeout 2 --max-time 5 -kfsS "https://$RANGE_IP:$HOST_PORT/health" >/dev/null 2>&1; do
        attempt=$((attempt + 1))
        [ "$attempt" -lt 30 ] || return 1
        sleep 1
    done
}

[ "$(id -u)" -eq 0 ] || die "Run this script as root."
[ -n "$RANGE_IP" ] || die "Usage: sh $WORKDIR/scripts/nct-start-docker.sh RANGE_IP [ADMIN_USERNAME]"
case "$CONTAINER" in ''|*[!A-Za-z0-9_.-]*) die "Choose a valid dedicated NCT container name." ;; esac

for command_name in docker openssl curl sha256sum ss; do
    command -v "$command_name" >/dev/null 2>&1 || die "$command_name is required."
done
docker info >/dev/null 2>&1 || die "Docker is not reachable."
[ -f "$ARCHIVE" ] || die "Missing $ARCHIVE"
[ -f "$CHECKSUM" ] || die "Missing $CHECKSUM"
[ -f "$WORKDIR/scripts/setup-lab-https.sh" ] || die "Missing the TLS setup helper."
[ -f "$WORKDIR/scripts/nct-set-admin.sh" ] || die "Missing the Administrator setup helper."
[ -f "$WORKDIR/scripts/nct-fresh-bootstrap-state.py" ] || die "Missing the fresh-install resume verifier."
[ -f "$WORKDIR/scripts/nct-verify-empty-fresh-resume.py" ] || die "Missing the fresh-install empty-state verifier."
. "$WORKDIR/scripts/nct-recovery-python.sh"
NCT_STATE_PYTHON=$(nct_select_recovery_python "$WORKDIR") ||
    die "A supported Python interpreter is required for fresh-install ownership receipts."
verify_archive_checksum || die "The offline image archive checksum does not match."
resume_bootstrap=${NCT_RESUME_BOOTSTRAP:-0}
if docker inspect "$CONTAINER" >/dev/null 2>&1; then
    [ "$resume_bootstrap" = 1 ] || die "A container named $CONTAINER already exists. This script will not replace it."
elif [ "$resume_bootstrap" = 1 ]; then
    die "The interrupted fresh container is missing. No state was changed."
fi
if [ "$resume_bootstrap" != 1 ] && ss -ltn | awk -v p="$HOST_PORT" 'NR > 1 && $4 ~ (":" p "$") { found=1 } END { exit(found ? 0 : 1) }'; then
    die "TCP port $HOST_PORT is in use. Set NCT_HTTPS_PORT to an approved free port."
fi

if [ "${NCT_SKIP_IMAGE_LOAD:-0}" = 1 ]; then
    docker image inspect "$IMAGE" >/dev/null 2>&1 || die "The parent installer did not leave the exact NCT image loaded."
    printf '%s\n' "Using the exact release image already admitted by the parent installer."
else
    docker load -i "$ARCHIVE"
fi
docker image inspect "$IMAGE" >/dev/null 2>&1 || die "The expected NCT image was not loaded."
IMAGE_ID=$(docker image inspect --format '{{.Id}}' "$IMAGE")
mkdir -p "$DATA_DIR" "$STATE_DIR/bootstrap" "$RETIREMENT_GUARD_DIR"
chmod 700 "$PERSIST_ROOT" "$DATA_DIR" "$STATE_DIR" "$STATE_DIR/bootstrap" "$RETIREMENT_GUARD_DIR"
if [ ! -f "$RETIREMENT_GUARD_DIR/provisioning.json" ]; then
    [ -z "$(find "$RETIREMENT_GUARD_DIR" -mindepth 1 -maxdepth 1 -print -quit)" ] ||
        die "Unrecognized retirement guard state blocks startup."
    docker run --rm --read-only --network none \
        -v "$RETIREMENT_GUARD_DIR:/retirement-guard:rw" "$IMAGE" \
        python -m app.retirement_guard_cli provision \
        --guard-dir /retirement-guard --installation-id "$CONTAINER" \
        --data-identity "$RETIREMENT_DATA_IDENTITY" >/dev/null ||
        die "Protected retirement authority could not be provisioned."
fi
if [ ! -f "$TLS_ROOT/tls/nct-server.crt" ] && [ ! -f "$TLS_ROOT/tls/nct-server.key" ]; then
    sh "$WORKDIR/scripts/setup-lab-https.sh" "$RANGE_IP" "$TLS_ROOT"
elif [ ! -f "$TLS_ROOT/tls/nct-server.crt" ] || [ ! -f "$TLS_ROOT/tls/nct-server.key" ]; then
    die "TLS material is incomplete under $TLS_ROOT; restore the missing file before continuing."
fi

fresh_state() {
    "$NCT_STATE_PYTHON" "$WORKDIR/scripts/nct-fresh-bootstrap-state.py" "$@" \
        --receipt "$FRESH_RESUME_RECEIPT" --container "$CONTAINER" \
        --image-reference "$IMAGE" --image-id "$IMAGE_ID" --admin-user "$ADMIN_USER" \
        --range-ip "$RANGE_IP" --bind-address "$APP_BIND_ADDRESS" \
        --host-port "$HOST_PORT" --container-port "$CONTAINER_PORT" \
        --data-dir "$DATA_DIR" --retirement-guard-dir "$RETIREMENT_GUARD_DIR" \
        --cert-file "$TLS_ROOT/tls/nct-server.crt" \
        --key-file "$TLS_ROOT/tls/nct-server.key" --secret-file "$BOOTSTRAP_PASSWORD" \
        --archive "$ARCHIVE"
}

account_count="${NCT_UPGRADE_ACCOUNT_COUNT:-}"
owned_fresh_runtime=0
if [ "$resume_bootstrap" = 1 ]; then
    [ -f "$BOOTSTRAP_PASSWORD" ] || die "The protected bootstrap secret is missing. Refusing to guess or reset this installation."
    fresh_state verify || die "The interrupted container does not match its root-owned fresh-install receipt. Nothing was changed."
    account_state=$(docker exec -i "$CONTAINER" python - /data/analyzer.db /data "$ADMIN_USER" \
        < "$WORKDIR/scripts/nct-verify-empty-fresh-resume.py") ||
        die "The interrupted installation contains operator data or an unexpected account. Refusing fresh resume."
    receipt_phase=$("$NCT_STATE_PYTHON" -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["phase"])' "$FRESH_RESUME_RECEIPT") || die "The fresh-install resume phase could not be read."
    case "$account_state:$receipt_phase" in
        PASSWORD_RESET_COUNT=0:awaiting_password)
            printf '%s\n' "Verified the exact empty installation. Re-enter the intended Administrator password; existing operator data will not be adopted or erased."
            NCT_FRESH_BOOTSTRAP_RECEIPT="$FRESH_RESUME_RECEIPT" NCT_FRESH_CONTAINER_ID=$(docker inspect --format '{{.Id}}' "$CONTAINER") \
                sh "$WORKDIR/scripts/nct-set-admin.sh" "$ADMIN_USER" || die "Administrator setup remains incomplete. The verified bootstrap state is preserved; run resume-fresh again."
            ;;
        PASSWORD_RESET_COUNT=1:awaiting_password)
            "$NCT_STATE_PYTHON" "$WORKDIR/scripts/nct-fresh-bootstrap-state.py" mark-password-committed \
                --receipt "$FRESH_RESUME_RECEIPT" --container-id "$(docker inspect --format '{{.Id}}' "$CONTAINER")" --admin-user "$ADMIN_USER" ||
                die "The committed Administrator state could not be bound to this fresh-install receipt."
            printf '%s\n' "The Administrator password had already committed before interruption. Continuing without asking for it again."
            ;;
        PASSWORD_RESET_COUNT=1:password_committed)
            printf '%s\n' "Verified the previously committed Administrator password step. Continuing without asking for it again."
            ;;
        *) die "The Administrator database state and fresh-install resume receipt disagree. Nothing was changed." ;;
    esac
    docker stop "$CONTAINER" >/dev/null
    docker rm "$CONTAINER" >/dev/null
    rm -f "$BOOTSTRAP_PASSWORD"
    account_count=1
    owned_fresh_runtime=1
fi

if [ -z "$account_count" ]; then
    if [ ! -f "$DATA_DIR/analyzer.db" ]; then
        account_count=0
    else
        account_count=$(docker run --rm -v "$DATA_DIR:/data:ro,z" "$IMAGE" python -c '
import pathlib, sqlite3
p = pathlib.Path("/data/analyzer.db")
print(sqlite3.connect(f"file:{p}?mode=ro&immutable=1", uri=True).execute("SELECT COUNT(*) FROM analyst_users").fetchone()[0])
') || die "Existing NCT accounts could not be inspected under $DATA_DIR."
    fi
fi
case "$account_count" in ''|*[!0-9]*) die "The NCT account count is invalid." ;; esac
if [ "$account_count" -eq 0 ]; then
    owned_fresh_runtime=1
    if [ -z "$ADMIN_USER" ]; then
        [ -t 0 ] || die "A new installation requires ADMIN_USERNAME when running non-interactively."
        printf 'Administrator username: ' >&2
        IFS= read -r ADMIN_USER
    fi
    printf '%s' "$ADMIN_USER" | grep -Eq '^[a-z0-9][a-z0-9._-]{1,63}$' ||
        die "Username must be 2-64 lowercase letters, numbers, dots, dashes, or underscores."
fi

start_container() {
    bootstrap=${1:-no}
    set -- docker run -d --name "$CONTAINER" --restart unless-stopped \
        --cap-add NET_RAW \
        -p "$APP_BIND_ADDRESS:$HOST_PORT:$CONTAINER_PORT" \
        -v "$DATA_DIR:/data:Z" \
        -v "$TLS_ROOT/tls/nct-server.crt:/run/tls/nct-server.crt:ro" \
        -v "$TLS_ROOT/tls/nct-server.key:/run/tls/nct-server.key:ro" \
        -v "$RETIREMENT_GUARD_DIR:/run/nct-retirement-guard:rw" \
        -e NCT_AUTH_MODE=local -e NCT_SESSION_HOURS=12 -e NCT_COOKIE_SECURE=1 \
        -e NCT_RETIREMENT_GUARD_MODE=required \
        -e NCT_RETIREMENT_GUARD_DIR=/run/nct-retirement-guard \
        -e NCT_RETIREMENT_DATA_IDENTITY="$RETIREMENT_DATA_IDENTITY"
    if [ "$bootstrap" = "yes" ]; then
        set -- "$@" \
            -v "$BOOTSTRAP_PASSWORD:/run/secrets/nct_bootstrap_password:ro" \
            -e NCT_BOOTSTRAP_ADMIN="$ADMIN_USER" \
            -e NCT_BOOTSTRAP_PASSWORD_FILE=/run/secrets/nct_bootstrap_password
    fi
    set -- "$@" "$IMAGE" uvicorn app.main:app --host 0.0.0.0 --port "$CONTAINER_PORT" \
        --loop asyncio --http h11 --ssl-certfile /run/tls/nct-server.crt \
        --ssl-keyfile /run/tls/nct-server.key
    "$@" >/dev/null
}

printf '%s\n' "Starting NCT with the current Docker Engine path..."
if [ "$account_count" -eq 0 ]; then
    umask 077
    openssl rand -base64 36 | tr -d '\r\n' > "$BOOTSTRAP_PASSWORD"
    start_container yes
    wait_for_health || die "NCT did not become healthy. Review: docker logs $CONTAINER"
    fresh_state create || die "The bootstrap container started but its exact resume ownership receipt could not be written. Preserve it and stop for review."
    if ! NCT_FRESH_BOOTSTRAP_RECEIPT="$FRESH_RESUME_RECEIPT" NCT_FRESH_CONTAINER_ID=$(docker inspect --format '{{.Id}}' "$CONTAINER") \
        sh "$WORKDIR/scripts/nct-set-admin.sh" "$ADMIN_USER"; then
        die "Administrator setup did not finish. The empty bootstrap container and protected secret were preserved. Rerun nct-install-range.sh with resume-fresh; it will verify this exact empty installation before asking again."
    fi
    docker stop "$CONTAINER" >/dev/null
    docker rm "$CONTAINER" >/dev/null
    rm -f "$BOOTSTRAP_PASSWORD"
    start_container no
    wait_for_health || die "NCT did not become healthy after removing the bootstrap secret. Review: docker logs $CONTAINER"
else
    printf '%s\n' "Preserving $account_count existing NCT account(s); no password or username will be changed."
    start_container no
    wait_for_health || die "NCT did not become healthy. Review: docker logs $CONTAINER"
fi
if [ "$owned_fresh_runtime" -eq 1 ]; then
    "$NCT_STATE_PYTHON" "$WORKDIR/scripts/nct-fresh-bootstrap-state.py" mark-runtime-ready \
        --receipt "$FRESH_RESUME_RECEIPT" --admin-user "$ADMIN_USER" \
        --release "$WORKDIR/release.json" --manifest "$WORKDIR/PACKAGE-MANIFEST.sha256" \
        --archive "$ARCHIVE" || die "The final empty runtime could not be bound to its fresh-install ownership receipt. Preserve it for review."
fi

printf '%s\n' "NCT is ready at https://$RANGE_IP:$HOST_PORT"
printf '%s\n' "Persistent operator data: $DATA_DIR"
