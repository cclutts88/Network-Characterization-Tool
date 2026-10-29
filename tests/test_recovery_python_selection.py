import importlib.util
import os
from pathlib import Path
import subprocess
import shutil
import sys
from unittest.mock import patch

import pytest

ROOT = Path(__file__).parents[1]
SCRIPTS = ROOT / "scripts"


def select(env, package=ROOT):
    return subprocess.run(["/bin/sh", "-c", '. "$1/scripts/nct-recovery-python.sh"; nct_select_recovery_python "$2"', "sh", str(ROOT), str(package)],
                          env={**os.environ, **env}, text=True, capture_output=True)


@pytest.mark.skipif(os.name != "posix", reason="Host POSIX installer")
def test_explicit_valid_interpreter_is_resolved_and_pinned():
    result = select({"NCT_RECOVERY_PYTHON": sys.executable})
    assert result.returncode == 0
    assert result.stdout.strip() == str(Path(sys.executable).resolve())


@pytest.mark.skipif(os.name != "posix", reason="Host POSIX installer")
def test_minimal_host_tree_without_app_or_pythonpath_selects_runtime(tmp_path):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    for name in ("nct-recovery-python.sh", "nct_update_host.py", "nct_update_work.py"):
        shutil.copyfile(SCRIPTS / name, scripts / name)
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    environment["NCT_RECOVERY_PYTHON"] = sys.executable
    result = subprocess.run(["/bin/sh", "-c", '. "$1/scripts/nct-recovery-python.sh"; nct_select_recovery_python "$1"', "sh", str(tmp_path)],
        cwd=tmp_path, env=environment, text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == str(Path(sys.executable).resolve())
    assert not (tmp_path / "app").exists()
    assert not list(scripts.glob("__pycache__"))


@pytest.mark.skipif(os.name != "posix", reason="Host POSIX installer")
@pytest.mark.parametrize("value", ["python3", "/missing/python", "/bin/false"])
def test_invalid_explicit_choice_never_falls_back(value):
    result = select({"NCT_RECOVERY_PYTHON": value})
    assert result.returncode != 0
    assert not result.stdout


@pytest.mark.skipif(os.name != "posix", reason="Host POSIX installer")
def test_old_default_and_available_versioned_runtime(tmp_path):
    for name, body in (("python3", "exit 1"), ("python3.9", 'exec "' + sys.executable + '" "$@"')):
        target = tmp_path / name
        target.write_text("#!/bin/sh\n" + body + "\n")
        target.chmod(0o700)
    result = select({"NCT_RECOVERY_PYTHON": "", "PATH": str(tmp_path)})
    # Use the actual shell path because the isolated PATH deliberately has no sh.
    assert result.returncode == 0
    assert result.stdout.strip() == str(Path(sys.executable).resolve())


def installer():
    sys.path.insert(0, str(SCRIPTS))
    try:
        spec = importlib.util.spec_from_file_location("recovery_installer", SCRIPTS / "install_nct_recovery.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.pop(0)


@pytest.mark.skipif(os.name != "posix", reason="Host POSIX installer")
def test_host_installer_uses_actual_executable_and_refuses_hidden_interpreter():
    module = installer()
    assert module.recovery_python() == str(Path(sys.executable).resolve())
    with patch.object(module.sys, "executable", "/root/private/python"), patch.object(module.os, "access", return_value=True):
        with pytest.raises(ValueError, match="protected host service"):
            module.recovery_python()


def test_bootstrap_and_service_do_not_revert_to_system_python():
    source = (SCRIPTS / "nct-install-range.sh").read_text()
    assert "python3 -c" not in source
    assert '"$NCT_RECOVERY_PYTHON" "$NCT_PACKAGE_ROOT/scripts/install_nct_recovery.py"' in source
    install = (SCRIPTS / "install_nct_recovery.py").read_text()
    assert "service_exec = service_command(interpreter, trusted" in install
    assert 'access_command(interpreter, trusted, config_path)' in install
    assert install.index("interpreter = recovery_python()") < install.index('trusted.mkdir(')


@pytest.mark.skipif(os.name != "posix", reason="Host POSIX installer")
def test_missing_host_modules_refuse_interpreter_without_mutating_package(tmp_path):
    marker = tmp_path / "evidence"
    marker.write_bytes(b"unchanged")
    result = select({"NCT_RECOVERY_PYTHON": sys.executable}, package=tmp_path)
    assert result.returncode != 0 and not result.stdout
    assert marker.read_bytes() == b"unchanged"
    assert not (tmp_path / "scripts").exists()


def test_systemd_command_pins_exact_interpreter_and_escapes_paths():
    module = installer()
    command = module.service_command("/opt/python39/bin/python3.9", Path("/opt/nct recovery"), Path("/var/lib/nct/%config$"))
    assert command.startswith('ExecStart="/opt/python39/bin/python3.9" ')
    assert '"/opt/nct recovery/nct_update_host.py"' in command
    assert '"/var/lib/nct/%%config$$"' in command
    with pytest.raises(ValueError, match="control characters"):
        module.service_command("/opt/python\nbad", Path("/opt/nct"), Path("/config"))


def test_emergency_command_round_trips_exact_paths_and_bootstrap_propagates_python():
    import shlex
    module = installer()
    script_dir = Path("/opt/nct's recovery$")
    config = Path('/var/lib/nct/"config"')
    assert shlex.split(module.access_command("/usr/bin/python3.9", script_dir, config)) == [
        "/usr/bin/python3.9", str(script_dir / "nct_update_host.py"), "--config", str(config), "--access-code"]
    assert 'NCT_UPGRADE_PYTHON="$NCT_RECOVERY_PYTHON"' in (SCRIPTS / "nct-install-range.sh").read_text()
