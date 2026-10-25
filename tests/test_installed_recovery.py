from __future__ import annotations

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"


def _diagnostic_module():
    path = SCRIPTS / "nct-diagnostic-report.py"
    spec = importlib.util.spec_from_file_location("nct_diagnostic_report_r18", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _report(*, state: str, health: str = "unknown", database_status: str = "ok",
            unfinished_work=None, changed: bool = False) -> dict:
    return {
        "container": {"name": "exact-nct", "state": state, "health": health},
        "database": {
            "status": database_status,
            "unfinished_work": [] if unfinished_work is None else unfinished_work,
        },
        "collection": {"state_changed_during_report": changed},
    }


def test_diagnostic_names_exact_terminal_recovery_route_for_unavailable_app():
    module = _diagnostic_module()

    restarting = module.next_step(_report(state="restarting"))
    stopped = module.next_step(_report(state="exited"))
    unhealthy = module.next_step(_report(state="running", health="unhealthy"))

    for message in (restarting, stopped, unhealthy):
        assert "nct-recover-installed.sh --container exact-nct" in message
        assert "reviewed recovery path" not in message


def test_diagnostic_routes_unfinished_work_to_distinct_repair():
    module = _diagnostic_module()
    message = module.next_step(_report(
        state="exited",
        unfinished_work=[{"table": "scan_runs", "state": "running", "count": 1}],
    ))

    assert "nct-reset-unfinished.sh --container exact-nct" in message
    assert "nct-recover-installed.sh" not in message


def test_installed_recovery_is_exact_fail_closed_and_non_destructive():
    content = (SCRIPTS / "nct-recover-installed.sh").read_text(encoding="utf-8")

    assert content.index("nct-diagnostic-report.sh") < content.index("nct-reset-unfinished.sh")
    assert '"$SCRIPT_DIR/nct-diagnostic-report.sh" --container "$CONTAINER"' in content
    assert '"$SCRIPT_DIR/nct-reset-unfinished.sh" --container "$CONTAINER"' in content
    assert 'docker_probe inspect --format \'{{.Image}}\'' in content
    assert "MaximumRetryCount" in content
    assert 'expected exactly one distinct saved NCT listener and host port' in content
    assert 'affected_count' in content
    assert 'docker_probe restart --time 30 "$CONTAINER"' in content
    assert 'running build identity does not match the exact installed image' in content
    assert 'controller_sign_in_verified=false' in content
    assert '--hold-stopped' in content
    assert 'restore_before_action=yes' in content
    assert 'hold_failed_recovery' in content
    assert 'docker rm "$CONTAINER"' not in content
    assert 'docker volume rm' not in content
    assert 'rm -rf' not in content
    assert 'nct-fresh-install.sh' not in content


def test_restart_loop_work_check_and_operator_routes_are_documented():
    repair = (SCRIPTS / "nct-reset-unfinished.sh").read_text(encoding="utf-8")
    script_index = (SCRIPTS / "README.md").read_text(encoding="utf-8")
    package_index = (ROOT / "docs" / "RANGE_PACKAGE_SCRIPTS_README.md").read_text(
        encoding="utf-8"
    )
    quickstart = (ROOT / "docs" / "AIR_GAPPED_RANGE_QUICKSTART.md").read_text(
        encoding="utf-8"
    )
    guide = (ROOT / "app" / "how_nct_works_ui.py").read_text(encoding="utf-8")

    assert "running|restarting|exited|created" in repair
    assert "every unfinished work category" in repair
    for text in (script_index, package_index, quickstart, guide):
        assert "nct-recover-installed.sh --container nct" in text
        assert "nct-reset-unfinished.sh --container nct" in text
        assert "nct-fresh-install.sh --container nct" in text
    assert "If NCT will not open, stay in the terminal" in guide
    assert "Do not substitute one path for another" in quickstart
    assert "do not use upgrade as a startup repair" in quickstart
    assert "historical package-specific" in package_index


def test_ordinary_upgrade_routes_stopped_installation_before_exec_checks():
    content = (SCRIPTS / "nct-upgrade.sh").read_text(encoding="utf-8")

    route = content.index("nct-recover-installed.sh")
    active_exec = content.index("check_active container")
    assert route < active_exec
    assert "docker port" not in content
    assert "Ordinary upgrade will not bypass the stopped-data work check" in content
