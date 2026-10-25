from __future__ import annotations

import json
import os
import shutil
import signal
import stat
import subprocess
import time
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


FAKE_DOCKER = r'''#!/usr/bin/env python3
import json, os, sys, time
from pathlib import Path

args = sys.argv[1:]
state_path = Path(os.environ["FAKE_DOCKER_STATE"])
helper_path = Path(os.environ["FAKE_DOCKER_HELPER"])
scenario = os.environ.get("FAKE_DOCKER_SCENARIO", "normal")
data_path = os.environ["FAKE_DOCKER_DATA"]

def load():
    return json.loads(state_path.read_text())
def save(value):
    state_path.write_text(json.dumps(value))
def value(flag):
    return args[args.index(flag) + 1]

if not args:
    raise SystemExit(2)
command = args[0]
if command == "info":
    raise SystemExit(0)
if command == "image" and args[1:2] == ["inspect"]:
    raise SystemExit(0)
if command == "inspect":
    state = load()
    if "--format" not in args:
        print("{}")
        raise SystemExit(0)
    template = value("--format")
    mounts = json.dumps([{"Type":"bind","Source":data_path,"Destination":"/data"}], separators=(",", ":"))
    if "range .Mounts" in template and 'Destination "/data"' in template:
        print(f"bind|{data_path}")
    elif "json .Mounts" in template:
        print(mounts)
    elif ".Config.Image" in template:
        print("nct:test")
    elif template == "{{.Image}}":
        print("sha256:fake")
    elif template == "{{.Id}}":
        print("fake-container-id")
    elif "PortBindings" in template and "range $port" in template:
        print("8080/tcp|18199")
    elif "json .HostConfig.PortBindings" in template:
        print('{"8080/tcp":[{"HostIp":"127.0.0.1","HostPort":"18199"}]}')
    elif "RestartPolicy.Name" in template and "State.Running" in template:
        print(f"{state['policy']}:{state['max']}:{str(state['running']).lower()}")
    elif "RestartPolicy.Name" in template and "MaximumRetryCount" in template:
        print(f"{state['policy']}:{state['max']}")
    elif template == "{{.HostConfig.RestartPolicy.Name}}":
        print(state["policy"])
    elif template == "{{.HostConfig.RestartPolicy.MaximumRetryCount}}":
        print(state["max"])
    elif template == "{{.State.Status}}":
        print("running" if state["running"] else "exited")
    elif template == "{{.State.Running}}":
        print(str(state["running"]).lower())
    else:
        print("")
    raise SystemExit(0)
if command == "ps":
    if scenario == "inventory_failure":
        raise SystemExit(1)
    if helper_path.exists() and helper_path.read_text().strip():
        print(helper_path.read_text().strip())
    raise SystemExit(0)
if command == "rm":
    if scenario == "helper_removal_failure":
        raise SystemExit(1)
    helper_path.write_text("")
    raise SystemExit(0)
if command == "run":
    name = value("--name") if "--name" in args else ""
    script = " ".join(args)
    if "p=json.load" in script:
        if scenario == "helper_removal_failure":
            helper_path.write_text(name)
        print("yes\n0\nfake-plan-digest")
    elif "BUILD_ID" in script:
        helper_path.write_text(name)
        print("fake-build|fake-commit")
        if scenario != "helper_removal_failure":
            helper_path.write_text("")
    raise SystemExit(0)
if command == "update":
    state = load()
    requested = next((item.split("=", 1)[1] for item in args if item.startswith("--restart=")), "no")
    if requested.startswith("on-failure:"):
        state["policy"], count = requested.split(":", 1)
        state["max"] = int(count)
    else:
        state["policy"], state["max"] = requested, 0
    save(state)
    raise SystemExit(0)
if command == "start":
    if scenario == "start_timeout":
        raise SystemExit(124)
    state = load(); state["running"] = True; save(state)
    if scenario == "automation_due":
        Path(os.environ["FAKE_AUTOMATION_MARKER"]).write_text("due automation resumed")
    raise SystemExit(0)
if command == "stop":
    state = load(); state["running"] = False; save(state)
    raise SystemExit(0)
if command == "restart":
    state = load(); state["running"] = True; save(state)
    raise SystemExit(0)
if command == "exec":
    script = " ".join(args)
    if "BUILD_ID" in script:
        print("fake-build|fake-commit")
        raise SystemExit(0)
    if scenario == "slow_health":
        time.sleep(30)
    raise SystemExit(0)
raise SystemExit(2)
'''


RESET_STUB = r'''#!/bin/sh
set -eu
output=""
hold=no
mode=${FAKE_RESET_MODE:-normal}
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output-dir) output=$2; shift 2 ;;
    --hold-stopped) hold=yes; shift ;;
    *) shift ;;
  esac
done
mkdir -p "$output/stub"
[ "$mode" = missing_plan ] || printf '%s\n' '{"safe_to_apply":true,"affected_count":0,"plan_digest":"fake-plan-digest"}' > "$output/stub/scan-work-plan.json"
if [ "$hold" = yes ]; then
  docker update --restart=no nct >/dev/null
  docker stop nct >/dev/null
fi
[ "$mode" = inner_helper_failure ] && { printf '%s' nct-scan-recovery-inner > "$FAKE_DOCKER_HELPER"; exit 2; }
[ "$mode" = slow_handoff ] && sleep 30
handoff_digest=fake-plan-digest
[ "$mode" = digest_mismatch ] && handoff_digest=wrong-plan-digest
[ "$hold" = yes ] && printf '%s\n' 'contract=nct-stopped-work-handoff:1' 'safe_to_restore=true' 'container_id=fake-container-id' "plan_digest=$handoff_digest" > "$output/stub/coordinator-handoff.receipt"
exit 0
'''


@pytest.fixture()
def recovery_harness(tmp_path: Path):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    recovery = scripts / "nct-recover-installed.sh"
    shutil.copy2(ROOT / "scripts" / "nct-recover-installed.sh", recovery)
    diagnostic = scripts / "nct-diagnostic-report.sh"
    diagnostic.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    reset = scripts / "nct-reset-unfinished.sh"
    reset.write_text(RESET_STUB, encoding="utf-8")
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    docker = fake_bin / "docker"
    docker.write_text(FAKE_DOCKER, encoding="utf-8")
    for path in (recovery, diagnostic, reset, docker):
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"running": False, "policy": "on-failure", "max": 3}))
    helper = tmp_path / "helper.txt"
    helper.write_text("")
    automation = tmp_path / "automation.txt"
    data = tmp_path / "data"
    data.mkdir()
    env = os.environ.copy()
    env.update({
        "PATH": f"{fake_bin}{os.pathsep}{env['PATH']}",
        "FAKE_DOCKER_STATE": str(state),
        "FAKE_DOCKER_HELPER": str(helper),
        "FAKE_DOCKER_DATA": str(data),
        "FAKE_AUTOMATION_MARKER": str(automation),
        "NCT_RECOVERY_DOCKER_PROBE_TIMEOUT": "2",
        "NCT_INSTALLED_RECOVERY_HEALTH_TIMEOUT": "4",
    })
    return recovery, state, helper, data, env


def run_recovery(harness, output: Path, scenario: str, *extra: str, timeout: float = 15):
    recovery, state, helper, data, env = harness
    env["FAKE_DOCKER_SCENARIO"] = scenario
    return subprocess.run(
        [str(recovery), "--container", "nct", "--output-dir", str(output), *extra],
        env=env,
        text=True,
        capture_output=True,
        timeout=timeout,
    )


def read_state(path: Path) -> dict:
    return json.loads(path.read_text())


def test_output_inside_retained_data_is_rejected_before_creation(recovery_harness):
    recovery, state, helper, data, env = recovery_harness
    output = data / "recovery-output"
    result = run_recovery(recovery_harness, output, "normal")

    assert result.returncode == 2
    assert "output overlaps retained NCT data" in result.stderr
    assert not output.exists()


def test_docker_start_timeout_is_contained_and_verified_stopped(recovery_harness):
    recovery, state, helper, data, env = recovery_harness
    result = run_recovery(recovery_harness, data.parent / "start-timeout", "start_timeout", "--apply")

    assert result.returncode == 2
    assert "exact container could not be started" in result.stderr
    assert "held stopped with automatic restart disabled" in result.stderr
    assert read_state(state) == {"running": False, "policy": "no", "max": 0}


def test_failed_helper_removal_halts_and_keeps_apply_target_stopped(recovery_harness):
    recovery, state, helper, data, env = recovery_harness
    result = run_recovery(recovery_harness, data.parent / "helper-failure", "helper_removal_failure", "--apply")

    assert result.returncode == 2
    assert "helper absence could not be proven" in result.stderr
    assert helper.read_text().strip().startswith("nct-installed-recovery-plan-")
    assert read_state(state) == {"running": False, "policy": "no", "max": 0}


def test_missing_plan_after_hold_keeps_target_stopped(recovery_harness):
    recovery, state, helper, data, env = recovery_harness
    state.write_text(json.dumps({"running": True, "policy": "on-failure", "max": 3}))
    env["FAKE_RESET_MODE"] = "missing_plan"
    result = run_recovery(recovery_harness, data.parent / "missing-plan", "normal", "--apply")

    assert result.returncode == 2
    assert "stopped-data work plan was not produced" in result.stderr
    assert read_state(state) == {"running": False, "policy": "no", "max": 0}


def test_signal_during_stopped_work_handoff_keeps_target_stopped(recovery_harness):
    recovery, state, helper, data, env = recovery_harness
    state.write_text(json.dumps({"running": True, "policy": "on-failure", "max": 3}))
    env["FAKE_DOCKER_SCENARIO"] = "normal"
    env["FAKE_RESET_MODE"] = "slow_handoff"
    process = subprocess.Popen(
        [str(recovery), "--container", "nct", "--output-dir", str(data.parent / "handoff-signal"), "--apply"],
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        current = read_state(state)
        if current == {"running": False, "policy": "no", "max": 0}:
            break
        time.sleep(0.05)
    assert read_state(state) == {"running": False, "policy": "no", "max": 0}
    os.killpg(process.pid, signal.SIGTERM)
    process.communicate(timeout=10)

    assert process.returncode != 0
    assert read_state(state) == {"running": False, "policy": "no", "max": 0}


def test_inner_helper_cleanup_failure_never_restarts_target(recovery_harness):
    recovery, state, helper, data, env = recovery_harness
    state.write_text(json.dumps({"running": True, "policy": "on-failure", "max": 3}))
    env["FAKE_RESET_MODE"] = "inner_helper_failure"
    result = run_recovery(recovery_harness, data.parent / "inner-helper-failure", "normal", "--apply")

    assert result.returncode == 2
    assert "stopped data could not be backed up" in result.stderr
    assert helper.read_text() == "nct-scan-recovery-inner"
    assert read_state(state) == {"running": False, "policy": "no", "max": 0}


def test_handoff_plan_digest_mismatch_never_restarts_target(recovery_harness):
    recovery, state, helper, data, env = recovery_harness
    state.write_text(json.dumps({"running": True, "policy": "on-failure", "max": 3}))
    env["FAKE_RESET_MODE"] = "digest_mismatch"
    result = run_recovery(recovery_harness, data.parent / "digest-mismatch", "normal", "--apply")

    assert result.returncode == 2
    assert "handoff does not match the reviewed plan" in result.stderr
    assert read_state(state) == {"running": False, "policy": "no", "max": 0}


def test_signal_after_action_start_holds_target_stopped(recovery_harness):
    recovery, state, helper, data, env = recovery_harness
    env["FAKE_DOCKER_SCENARIO"] = "slow_health"
    process = subprocess.Popen(
        [str(recovery), "--container", "nct", "--output-dir", str(data.parent / "signal"), "--apply"],
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and not read_state(state)["running"]:
        time.sleep(0.05)
    assert read_state(state)["running"] is True
    os.killpg(process.pid, signal.SIGTERM)
    stdout, stderr = process.communicate(timeout=10)

    assert process.returncode != 0
    assert "held stopped with automatic restart disabled" in stderr
    assert read_state(state) == {"running": False, "policy": "no", "max": 0}


def test_due_saved_automation_resume_is_disclosed_in_receipt(recovery_harness):
    recovery, state, helper, data, env = recovery_harness
    result = run_recovery(recovery_harness, data.parent / "automation", "automation_due", "--apply")

    assert result.returncode == 0, result.stderr
    assert Path(env["FAKE_AUTOMATION_MARKER"]).read_text() == "due automation resumed"
    receipts = list((data.parent / "automation").glob("installed-recovery-*/installed-recovery.receipt"))
    assert len(receipts) == 1
    receipt = receipts[0].read_text()
    assert "enabled_automation_resume=normal_runtime" in receipt
    assert "automatic_network_contact=possible" in receipt
    assert "Enabled schedules and connectors resumed" in result.stdout
