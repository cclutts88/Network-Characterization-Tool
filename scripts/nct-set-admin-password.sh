#!/bin/sh
set -eu

admin_user="${1:-clutts}"
container="${2:-nct}"

[ -t 0 ] || { printf '%s\n' "Run this command from an interactive terminal." >&2; exit 1; }
docker inspect "$container" >/dev/null 2>&1 || { printf '%s\n' "Container $container was not found." >&2; exit 1; }

terminal_state=$(stty -g)
restore_terminal() {
    stty "$terminal_state" 2>/dev/null || true
}
trap restore_terminal EXIT HUP INT TERM

printf 'New password (12-256 characters): ' >&2
stty -echo
IFS= read -r first_password
stty "$terminal_state"
printf '\nConfirm password: ' >&2
stty -echo
IFS= read -r second_password
stty "$terminal_state"
printf '\n' >&2

[ "$first_password" = "$second_password" ] || {
    printf '%s\n' "Passwords do not match." >&2
    exit 1
}

password_length=$(printf %s "$first_password" | wc -c | tr -d ' ')
[ "$password_length" -ge 12 ] && [ "$password_length" -le 256 ] || {
    printf '%s\n' "Password must be 12-256 characters; received $password_length." >&2
    exit 1
}

printf %s "$first_password" | docker exec -i "$container" python -c '
import sys
from pathlib import Path
from app.auth import reset_user_password
reset_user_password(
    Path("/data/analyzer.db"),
    username=sys.argv[1],
    password=sys.stdin.read(),
    actor="host-recovery",
)
print("Password updated successfully")
' "$admin_user"

first_password=""
second_password=""
