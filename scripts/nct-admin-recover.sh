#!/bin/sh
set -eu

# Host-authorized recovery for an existing local-authentication deployment.
# The password is supplied through a read-only file mount and never appears in
# container metadata, command arguments, deployment logs, or shell output.

container="nct"
admin_user=""
password_file=""
generate_password="no"
assume_yes="no"
state_dir="./nct-deployment"
temporary_password="no"
retained_password="no"
password_file_absolute=""
lock_dir="${TMPDIR:-/tmp}/nct-admin-recover.lock"

say() { printf '%s\n' "[NCT recovery] $*"; }
die() { printf '%s\n' "[NCT recovery] ERROR: $*" >&2; exit 1; }
usage() {
    cat <<'EOF'
Usage: sh scripts/nct-admin-recover.sh [options]

  --container NAME              Existing NCT container name
  --admin-user USER             Administrator account to recover
  --password-file FILE          Read the replacement password from FILE
  --generate-password           Write a strong replacement password to state-dir
  --state-dir DIR               Backup, log, and generated-password location
  --yes                         Approve recovery non-interactively
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --container) container=${2:?missing container}; shift 2 ;;
        --admin-user) admin_user=${2:?missing Administrator username}; shift 2 ;;
        --password-file) password_file=${2:?missing password file}; shift 2 ;;
        --generate-password) generate_password="yes"; shift ;;
        --state-dir) state_dir=${2:?missing directory}; shift 2 ;;
        --yes) assume_yes="yes"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; die "Unknown option: $1" ;;
    esac
done

[ -z "$password_file" ] || [ "$generate_password" = "no" ] || die "Choose either --password-file or --generate-password, not both."
command -v docker >/dev/null 2>&1 || die "Docker is required for account recovery."
docker info >/dev/null 2>&1 || die "Docker is not reachable."
docker inspect "$container" >/dev/null 2>&1 || die "Container $container was not found."

if ! mkdir "$lock_dir" 2>/dev/null; then
    die "Another NCT account recovery appears active at $lock_dir."
fi
cleanup() {
    if [ "$temporary_password" = "yes" ] && [ -n "$password_file_absolute" ]; then
        rm -f "$password_file_absolute"
    fi
    rmdir "$lock_dir" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

image=$(docker inspect --format '{{.Config.Image}}' "$container")
data_volume=$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{if eq .Type "volume"}}{{.Name}}{{end}}{{end}}{{end}}' "$container")
[ -n "$data_volume" ] || die "The container does not use a recognized named /data volume."

set +e
docker run --rm -v "$data_volume:/data:ro" "$image" python -c 'import glob,json,sys
active=[]
for p in glob.glob("/data/**/manifest.json",recursive=True):
 try:
  d=json.load(open(p,encoding="utf-8"))
  if d.get("status") in {"queued","running","awaiting_fallback_approval","updating","migrating"}: active.append(p)
 except Exception: pass
sys.exit(42 if active else 0)' >/dev/null 2>&1
active_rc=$?
set -e
[ "$active_rc" -ne 42 ] || die "NCT has active work. Finish or stop it before account recovery."
[ "$active_rc" -eq 0 ] || die "NCT could not prove that no operation is active."

if [ -z "$admin_user" ]; then
    [ -t 0 ] || die "Non-interactive recovery requires --admin-user."
    printf 'Administrator username to recover: ' >&2
    IFS= read -r admin_user
fi
printf %s "$admin_user" | grep -Eq '^[a-z0-9][a-z0-9._-]{1,63}$' || die "Administrator username format is invalid."

mkdir -p "$state_dir/backups" "$state_dir/logs"
umask 077
if [ -n "$password_file" ]; then
    [ -r "$password_file" ] || die "Replacement password file is not readable."
elif [ "$generate_password" = "yes" ]; then
    password_file="$state_dir/recovered-admin-password-$(date -u +%Y%m%dT%H%M%SZ).txt"
    docker run --rm "$image" python -c 'import secrets; print(secrets.token_urlsafe(24),end="")' > "$password_file"
    chmod 600 "$password_file"
    retained_password="yes"
else
    [ -t 0 ] || die "Non-interactive recovery needs --password-file or --generate-password."
    terminal_state=$(stty -g)
    trap 'stty "$terminal_state" 2>/dev/null || true; exit 130' HUP INT TERM
    printf 'Replacement password (12-256 characters): ' >&2
    stty -echo
    IFS= read -r first_password
    stty "$terminal_state"
    printf '\nConfirm replacement password: ' >&2
    stty -echo
    IFS= read -r second_password
    stty "$terminal_state"
    printf '\n' >&2
    trap 'exit 130' HUP INT TERM
    [ "$first_password" = "$second_password" ] || die "Replacement passwords did not match."
    password_file="$state_dir/.recovery-password.$$"
    printf %s "$first_password" > "$password_file"
    unset first_password second_password
    temporary_password="yes"
fi
password_length=$(wc -c < "$password_file" | tr -d ' ')
[ "$password_length" -ge 12 ] && [ "$password_length" -le 258 ] || die "Replacement password file must contain one 12-256 character password."
password_file=$(cd "$(dirname "$password_file")" && pwd)/$(basename "$password_file")
[ "$temporary_password" = "no" ] || password_file_absolute="$password_file"

if [ "$assume_yes" != "yes" ]; then
    printf 'Stop %s, back up its data, and reset Administrator %s? [y/N] ' "$container" "$admin_user"
    IFS= read -r answer
    case "$answer" in y|Y|yes|YES) ;; *) die "Recovery cancelled before any change." ;; esac
fi

was_running=$(docker inspect --format '{{.State.Running}}' "$container")
[ "$was_running" != "true" ] || docker stop "$container" >/dev/null
restart_original() {
    [ "$was_running" != "true" ] || docker start "$container" >/dev/null 2>&1 || true
}

backup_name="nct-account-recovery-$(date -u +%Y%m%dT%H%M%SZ).tar.gz"
backup_abs=$(cd "$state_dir/backups" && pwd)
if ! docker run --rm -v "$data_volume:/data:ro" -v "$backup_abs:/backup" "$image" sh -c "cd /data && tar -czf /backup/$backup_name ."; then
    restart_original
    die "Recovery backup failed; the original container was returned to its prior state."
fi

if ! docker run --rm -v "$data_volume:/data" -v "$password_file:/run/secrets/nct_recovery_password:ro" "$image" python -c 'import pathlib,sqlite3,sys
from app.auth import reset_user_password,set_user_disabled
db=pathlib.Path("/data/analyzer.db")
username=sys.argv[1]
with sqlite3.connect(db) as connection:
 row=connection.execute("SELECT role,disabled FROM analyst_users WHERE username = ?",(username,)).fetchone()
if row is None: raise SystemExit("Administrator account was not found")
if row[0] != "admin": raise SystemExit("Recovery is restricted to Administrator accounts")
if row[1]: set_user_disabled(db,username=username,disabled=False,actor="host-recovery")
password=pathlib.Path("/run/secrets/nct_recovery_password").read_text(encoding="utf-8").rstrip("\r\n")
reset_user_password(db,username=username,password=password,actor="host-recovery")' "$admin_user"; then
    restart_original
    die "The account was not changed; review the recovery error above."
fi

restart_original
if [ "$was_running" = "true" ]; then
    healthy="no"
    attempt=0
    while [ "$attempt" -lt 30 ]; do
        if docker exec "$container" python -c 'import json,urllib.request; assert json.load(urllib.request.urlopen("http://127.0.0.1:8080/health",timeout=2))["status"]=="ok"' >/dev/null 2>&1; then healthy="yes"; break; fi
        attempt=$((attempt + 1))
        sleep 1
    done
    [ "$healthy" = "yes" ] || die "The password was reset, but NCT did not become healthy after restart."
fi

[ "$temporary_password" = "no" ] || rm -f "$password_file"
[ "$temporary_password" = "no" ] || password_file_absolute=""
log_file="$state_dir/logs/admin-recovery-$(date -u +%Y%m%dT%H%M%SZ).log"
printf 'completed=%s\ncontainer=%s\nadmin_user=%s\naction=password_reset_and_session_revocation\nbackup=%s\n' "$(date -u +%FT%TZ)" "$container" "$admin_user" "$backup_abs/$backup_name" > "$log_file"
say "Administrator $admin_user was recovered, all prior sessions were revoked, and NCT was returned to its prior running state."
say "Backup: $backup_abs/$backup_name"
if [ "$retained_password" = "yes" ]; then
    say "Replacement password file: $password_file (save it securely, sign in, then delete it)."
fi
