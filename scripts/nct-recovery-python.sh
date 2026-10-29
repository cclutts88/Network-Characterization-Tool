#!/bin/sh
# Read-only interpreter selection for trusted host recovery installation.
nct_select_recovery_python() {
    nct_python_root=$1
    if [ -n "${NCT_RECOVERY_PYTHON:-}" ]; then
        case "$NCT_RECOVERY_PYTHON" in /*) ;; *) printf '%s\n' 'NCT_RECOVERY_PYTHON must be an absolute executable path.' >&2; return 1 ;; esac
        set -- "$NCT_RECOVERY_PYTHON"
    else
        set -- python3.13 python3.12 python3.11 python3.10 python3.9 python3
    fi
    for nct_python_candidate do
        nct_python_command=$(command -v "$nct_python_candidate" 2>/dev/null) || continue
        nct_python_selected=$(PYTHONDONTWRITEBYTECODE=1 "$nct_python_command" -c '
import os, sys
assert sys.version_info >= (3, 9), "Recovery requires Python 3.9 or newer"
import fcntl, sqlite3, ssl, resource, tarfile
path = os.path.realpath(sys.executable)
assert os.path.isabs(path) and os.access(path, os.X_OK)
assert not any(c.isspace() or c in "%\\\"" for c in path), "Unsupported interpreter path"
assert not path.startswith(("/root/", "/home/", "/run/user/")), "Interpreter is hidden by service ProtectHome"
sys.path.insert(0, sys.argv[1] + "/scripts")
import nct_update_host
print(path)
' "$nct_python_root" 2>/dev/null) || continue
        printf '%s\n' "$nct_python_selected"
        return 0
    done
    printf '%s\n' 'No usable recovery Python was found. Install a separate Python 3.9+ runtime from approved offline media, or set NCT_RECOVERY_PYTHON to its absolute path. System Python and NCT were not changed.' >&2
    return 1
}
