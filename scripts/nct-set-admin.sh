#!/bin/sh
set -eu

container="${NCT_CONTAINER:-nct}"
requested_user="${1:-}"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)

die() {
    printf '%s\n' "$*" >&2
    exit 1
}

[ -t 0 ] || die "Run this command from an interactive terminal."
command -v docker >/dev/null 2>&1 || die "Docker is required."
command -v mktemp >/dev/null 2>&1 || die "mktemp is required for protected password entry."
docker inspect "$container" >/dev/null 2>&1 || die "Container $container was not found. Start NCT first."
[ -r "$SCRIPT_DIR/nct-read-admin-secret.py" ] || die "The protected Administrator password reader is missing."
. "$SCRIPT_DIR/nct-recovery-python.sh"
NCT_SECRET_PYTHON=$(nct_select_recovery_python "${NCT_WORKDIR:-$SCRIPT_DIR/..}") ||
    die "A supported Python interpreter is required for protected password entry."

admin_rows=$(docker exec "$container" python -c '
from pathlib import Path
from app.auth import list_users

for user in list_users(Path("/data/analyzer.db")):
    if user["role"] == "admin":
        print("{}\t{}".format(user["username"], "disabled" if user["disabled"] else "active"))
') || die "NCT administrator accounts could not be read."

printf '%s\n' "Current NCT Administrator accounts:"
if [ -n "$admin_rows" ]; then
    printf '%s\n' "$admin_rows" | awk -F '\t' '{ printf "  %s (%s)\n", $1, $2 }'
else
    printf '%s\n' "  none"
fi

active_admins=$(printf '%s\n' "$admin_rows" | awk -F '\t' '$2 == "active" { print $1 }')
active_count=$(printf '%s\n' "$active_admins" | awk 'NF { count += 1 } END { print count + 0 }')
current_admin=""
[ "$active_count" -ne 1 ] || current_admin=$active_admins

new_admin=$requested_user
if [ -z "$new_admin" ]; then
    if [ -n "$current_admin" ]; then
        printf 'Administrator username [%s]: ' "$current_admin" >&2
    else
        printf 'Administrator username: ' >&2
    fi
    IFS= read -r new_admin
    [ -n "$new_admin" ] || new_admin=$current_admin
fi

printf '%s' "$new_admin" | grep -Eq '^[a-z0-9][a-z0-9._-]{1,63}$' ||
    die "Username must be 2-64 lowercase letters, numbers, dots, dashes, or underscores."

disable_previous="no"
if [ -n "$current_admin" ] && [ "$current_admin" != "$new_admin" ]; then
    printf "Replace current Administrator '%s' with '%s'? [Y/n]: " "$current_admin" "$new_admin" >&2
    IFS= read -r answer
    case "$answer" in
        n|N|no|NO) disable_previous="no" ;;
        *) disable_previous="yes" ;;
    esac
fi

secret_dir=${TMPDIR:-/tmp}
secret_file=$(mktemp "$secret_dir/nct-admin-secret.XXXXXX") || die "A protected temporary password file could not be created."
rm -f "$secret_file"
cleanup_secret() { rm -f "$secret_file"; }
trap cleanup_secret EXIT HUP INT TERM
"$NCT_SECRET_PYTHON" "$SCRIPT_DIR/nct-read-admin-secret.py" --output "$secret_file" ||
    die "Administrator password setup was not completed. No selected password was saved."

docker exec -i "$container" python -c '
import sys
from pathlib import Path
from app.auth import create_user, list_users, reset_user_password, set_user_disabled

db_path = Path("/data/analyzer.db")
target = sys.argv[1]
previous = sys.argv[2]
disable_previous = sys.argv[3] == "yes"
password = sys.stdin.read()
users = {user["username"]: user for user in list_users(db_path)}

if target in users:
    if users[target]["role"] != "admin":
        raise ValueError("The requested username already belongs to a non-Administrator account")
    if users[target]["disabled"]:
        set_user_disabled(db_path, username=target, disabled=False, actor="host-administrator-setup")
    reset_user_password(
        db_path,
        username=target,
        password=password,
        actor="host-administrator-setup",
    )
    action = "updated"
else:
    create_user(
        db_path,
        username=target,
        display_name=target,
        role="admin",
        password=password,
        created_by="host-administrator-setup",
    )
    action = "created"

if disable_previous and previous and previous != target:
    set_user_disabled(
        db_path,
        username=previous,
        disabled=True,
        actor="host-administrator-setup",
    )

print("NCT Administrator {}: {}".format(action, target))
if disable_previous and previous and previous != target:
    print("Previous Administrator disabled: {}".format(previous))
' "$new_admin" "$current_admin" "$disable_previous" < "$secret_file"

if [ -n "${NCT_FRESH_BOOTSTRAP_RECEIPT:-}" ]; then
    case "$NCT_FRESH_BOOTSTRAP_RECEIPT" in /*) ;; *) die "Fresh-install receipt path must be absolute." ;; esac
    [ -n "${NCT_FRESH_CONTAINER_ID:-}" ] || die "Fresh-install container identity is missing after the password commit."
    actual_container_id=$(docker inspect --format '{{.Id}}' "$container") || die "Fresh-install container identity could not be reread."
    [ "$actual_container_id" = "$NCT_FRESH_CONTAINER_ID" ] || die "Fresh-install container identity changed after the password commit."
    "$NCT_SECRET_PYTHON" "$SCRIPT_DIR/nct-fresh-bootstrap-state.py" mark-password-committed \
        --receipt "$NCT_FRESH_BOOTSTRAP_RECEIPT" --container-id "$NCT_FRESH_CONTAINER_ID" \
        --admin-user "$new_admin" || die "The password committed, but its fresh-install completion receipt could not be recorded. Preserve the installation and use resume-fresh."
fi

printf '%s\n' "All previous sessions for $new_admin were signed out."

