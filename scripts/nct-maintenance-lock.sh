#!/bin/sh
# Shared by trusted terminal recovery and the GUI host broker. Nested trusted
# scripts inherit descriptor 9 and therefore retain the same flock ownership.
nct_maintenance_lock() {
    nct_lock_path=${NCT_MAINTENANCE_LOCK:-$1}
    command -v flock >/dev/null 2>&1 || { echo "HALT: flock is required for exclusive NCT maintenance" >&2; exit 2; }
    mkdir -p "$(dirname -- "$nct_lock_path")"
    if [ "$(readlink "/proc/$$/fd/9" 2>/dev/null || true)" != "$nct_lock_path" ]; then
        exec 9>"$nct_lock_path"
    fi
    flock -n 9 || { echo "HALT: another NCT update or recovery operation is running" >&2; exit 2; }
    export NCT_MAINTENANCE_LOCK="$nct_lock_path"
}
