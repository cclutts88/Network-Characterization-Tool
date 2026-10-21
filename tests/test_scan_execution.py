from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

import app.poc as poc
from app.poc import (
    NoStrikeUpdate,
    RunControl,
    ScanOptions,
    ScanRunRequest,
    ScanScheduleCreate,
    add_global_no_strike,
    create_scan_schedule,
    execute_scan_run,
    get_scan_run_plan,
    nmap_host_presence_counts,
    prepare_scan_run,
)


DISCOVERY_XML = b'''<?xml version="1.0"?><nmaprun scanner="nmap"><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/></host><runstats><finished time="1"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>'''
TCP_XML = b'''<?xml version="1.0"?><nmaprun scanner="nmap"><scaninfo type="syn" protocol="tcp"/><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/></port></ports></host><runstats><finished time="2"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>'''
UDP_XML = b'''<?xml version="1.0"?><nmaprun scanner="nmap"><scaninfo type="udp" protocol="udp"/><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="udp" portid="53"><state state="open"/></port></ports></host><runstats><finished time="3"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>'''


class FakeProcess:
    def __init__(self, code: int | None):
        self.code = code
        self.terminated = False

    def poll(self):
        return 0 if self.terminated else self.code

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.terminated = True

    def wait(self, timeout=None):
        self.terminated = True
        return 0


def test_queued_run_is_recertified_and_stops_before_contact(tmp_path):
    db_path = tmp_path / "nct.db"
    data_dir = tmp_path / "data"
    request = ScanRunRequest(
        operator="Tester",
        originating_host="test-host",
        interface="eth0",
        targets=["192.0.2.10/32"],
        capture=True,
    )
    manifest = prepare_scan_run(request, db_path, interfaces={"eth0"})
    add_global_no_strike(
        NoStrikeUpdate(entries=["192.0.2.10"], changed_by="safety-officer"),
        db_path,
    )
    launched = []

    execute_scan_run(
        manifest["run_id"],
        RunControl(),
        db_path=db_path,
        data_dir=data_dir,
        popen_factory=lambda *args, **kwargs: launched.append((args, kwargs)),
        sleep_fn=lambda _seconds: None,
    )

    completed = get_scan_run_plan(manifest["run_id"], db_path)
    assert launched == []
    assert completed["status"] == "stopped_no_targets"
    assert completed["no_strike"] == ["192.0.2.10/32"]
    assert completed["no_strike_certifications"][-1]["phase"] == "queue_start"
    assert completed["no_strike_certifications"][-1]["remaining_address_count"] == 0


def test_new_global_exclusion_is_rechecked_between_protocol_phases(tmp_path):
    db_path = tmp_path / "nct.db"
    data_dir = tmp_path / "data"
    request = ScanRunRequest(
        operator="Tester",
        originating_host="test-host",
        interface="eth0",
        profile="Custom",
        scan_options=ScanOptions(
            protocol="tcp_udp", tcp_scope="common", udp_scope="common",
            discovery_mode="nmap",
        ),
        targets=["192.0.2.10/32"],
        capture=True,
    )
    manifest = prepare_scan_run(request, db_path, interfaces={"eth0"})
    launched = []

    def fake_popen(argv, *, cwd: Path, **_kwargs):
        command = " ".join(str(item) for item in argv)
        launched.append(command)
        if command.startswith("tcpdump"):
            return FakeProcess(None)
        if "discovery.xml" in command:
            (cwd / "discovery.xml").write_bytes(DISCOVERY_XML)
        elif "tcp-scan.xml" in command:
            (cwd / "tcp-scan.xml").write_bytes(TCP_XML)
            add_global_no_strike(
                NoStrikeUpdate(entries=["192.0.2.10"], changed_by="safety-officer"),
                db_path,
            )
        return FakeProcess(0)

    execute_scan_run(
        manifest["run_id"], RunControl(), db_path=db_path, data_dir=data_dir,
        popen_factory=fake_popen, sleep_fn=lambda _seconds: None,
    )

    completed = get_scan_run_plan(manifest["run_id"], db_path)
    assert any("tcp-scan.xml" in command for command in launched)
    assert not any("udp-scan.xml" in command for command in launched)
    assert completed["status"] == "stopped_no_targets"
    assert completed["no_strike_certifications"][-1]["phase"] == "udp_scan"


def test_scan_run_default_timeout_is_45_minutes():
    request = ScanRunRequest(
        operator="Tester",
        reason="Verify default timeout",
        originating_host="test-host",
        interface="eth0",
        targets=["192.0.2.10/32"],
        capture=True,
    )

    assert request.timeout_seconds == 45 * 60


def test_scan_run_does_not_require_an_operator_reason_note():
    request = ScanRunRequest(
        operator="Tester",
        originating_host="test-host",
        interface="eth0",
        targets=["192.0.2.10/32"],
        capture=True,
    )
    blank_request = request.model_copy(update={"reason": ""})

    assert request.reason == "NCT network characterization initiated through the operator workspace"
    assert ScanRunRequest.model_validate(blank_request.model_dump()).reason == request.reason


def test_scan_manifest_counts_pn_assumptions_separately_from_confirmed_hosts(tmp_path):
    xml_path = tmp_path / "scan.xml"
    xml_path.write_text(
        '''<?xml version="1.0"?><nmaprun scanner="nmap">
        <host><status state="up" reason="user-set"/><address addr="192.0.2.10" addrtype="ipv4"/></host>
        <host><status state="up" reason="user-set"/><address addr="192.0.2.11" addrtype="ipv4"/>
          <ports><port protocol="tcp" portid="22"><state state="closed" reason="reset"/></port></ports>
        </host>
        <runstats><finished time="2"/><hosts up="2" down="0" total="2"/></runstats></nmaprun>''',
        encoding="utf-8",
    )

    counts = nmap_host_presence_counts(xml_path)

    assert counts == {"reported_up": 2, "confirmed": 1, "assumed": 1}


def test_udp_failure_preserves_tcp_xml_as_analyzable_partial_result(tmp_path):
    db_path = tmp_path / "nct.db"
    data_dir = tmp_path / "data"
    request = ScanRunRequest(
        operator="Tester",
        name="Split protocol test",
        reason="Verify retained TCP evidence",
        originating_host="test-host",
        interface="eth0",
        profile="Custom",
        scan_options=ScanOptions(
            protocol="tcp_udp",
            tcp_scope="common",
            udp_scope="common",
            discovery_mode="nmap",
        ),
        targets=["192.0.2.10/32"],
        capture=True,
        timeout_seconds=30,
    )
    manifest = prepare_scan_run(request, db_path, interfaces={"eth0"})

    def fake_popen(argv, *, cwd: Path, **_kwargs):
        command = " ".join(str(item) for item in argv)
        if command.startswith("tcpdump"):
            return FakeProcess(None)
        if "discovery.xml" in command:
            (cwd / "discovery.xml").write_bytes(DISCOVERY_XML)
            return FakeProcess(0)
        if "tcp-scan.xml" in command:
            (cwd / "tcp-scan.xml").write_bytes(TCP_XML)
            return FakeProcess(0)
        if "udp-scan.xml" in command:
            return FakeProcess(2)
        raise AssertionError(command)

    execute_scan_run(
        manifest["run_id"],
        RunControl(),
        db_path=db_path,
        data_dir=data_dir,
        popen_factory=fake_popen,
        sleep_fn=lambda _seconds: None,
    )

    completed = get_scan_run_plan(manifest["run_id"], db_path)
    assert completed["status"] == "completed"
    assert completed["artifact_registry"]["status"] == "complete"
    assert any(item["filename"] == "scan.xml" for item in completed["artifact_registry"]["files"])
    assert completed["partial_results"] is True
    assert completed["success"] is True
    assert completed["coverage"]["actual_protocols"] == ["TCP"]
    assert completed["execution_phases"][0]["status"] == "completed"
    assert completed["execution_phases"][1]["status"] == "failed"
    assert "TCP results were preserved" in completed["execution_note"]
    canonical = data_dir / "scan-runs" / manifest["run_id"] / "scan.xml"
    assert canonical.is_file()
    assert 'protocol="tcp" portid="443"' in canonical.read_text(encoding="utf-8")


def test_combined_top_ports_success_retains_context_and_publishes_both_protocols(
    tmp_path, monkeypatch
):
    db_path = tmp_path / "nct.db"
    data_dir = tmp_path / "data"
    schedule = create_scan_schedule(
        ScanScheduleCreate(
            name="Combined acceptance schedule",
            created_by="crew.lead",
            profile_id="builtin-standard",
            profile_version=1,
            targets=["192.0.2.10/32"],
            manual_targets=["192.0.2.10/32"],
            interface="eth0",
            cadence="once",
            first_run_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            enabled=True,
        ),
        db_path,
    )
    request = ScanRunRequest(
        operator="analyst.one",
        created_by="analyst.one",
        scheduled=True,
        scheduled_by="crew.lead",
        executed_by="scheduler",
        schedule_id=schedule["schedule_id"],
        schedule_batch_id="2" * 32,
        chunk_number=1,
        chunk_count=1,
        batch_hosts_total=1,
        name="Combined acceptance",
        reason="Verify the complete retained combined scan workflow",
        originating_host="test-host",
        interface="eth0",
        profile="Combined acceptance profile",
        scan_options=ScanOptions(
            protocol="tcp_udp",
            tcp_scope="top_1000",
            udp_scope="top_100",
            discovery_mode="nmap",
        ),
        targets=["192.0.2.10/32"],
        capture=True,
        timeout_seconds=30,
    )
    manifest = prepare_scan_run(request, db_path, interfaces={"eth0"})
    launched: list[str] = []
    phase_publications: list[dict] = []
    original_publish = poc.update_scan_progress_manifest

    def record_progress(current: dict, path: Path):
        phase_publications.append(dict(current["progress"]))
        return original_publish(current, path)

    monkeypatch.setattr(poc, "update_scan_progress_manifest", record_progress)

    def fake_popen(argv, *, cwd: Path, **_kwargs):
        command = " ".join(str(item) for item in argv)
        launched.append(command)
        if command.startswith("tcpdump"):
            return FakeProcess(None)
        if "discovery.xml" in command:
            (cwd / "discovery.xml").write_bytes(DISCOVERY_XML)
        elif "tcp-scan.xml" in command:
            (cwd / "tcp-scan.xml").write_bytes(TCP_XML)
        elif "udp-scan.xml" in command:
            (cwd / "udp-scan.xml").write_bytes(UDP_XML)
        else:
            raise AssertionError(command)
        return FakeProcess(0)

    execute_scan_run(
        manifest["run_id"], RunControl(), db_path=db_path, data_dir=data_dir,
        popen_factory=fake_popen, sleep_fn=lambda _seconds: None,
    )

    completed = get_scan_run_plan(manifest["run_id"], db_path)
    commands = {
        phase["name"]: phase["command_argv"]
        for phase in completed["execution_phases"]
    }
    assert commands["tcp"][commands["tcp"].index("--top-ports") + 1] == "1000"
    assert commands["udp"][commands["udp"].index("--top-ports") + 1] == "100"
    assert [phase["status"] for phase in completed["execution_phases"]] == [
        "completed", "completed"
    ]
    assert any("discovery.xml" in command for command in launched)
    assert any("tcp-scan.xml" in command for command in launched)
    assert any("udp-scan.xml" in command for command in launched)
    assert completed["status"] == "completed"
    assert completed["success"] is True
    assert completed.get("partial_results") is not True
    assert completed["coverage"]["actual_protocols"] == ["TCP", "UDP"]
    assert completed["coverage"]["partial_results"] is False
    assert completed["profile_id"] == "inline-custom"
    assert completed["profile_version"] == 1
    assert completed["created_by"] == "analyst.one"
    assert completed["scheduled_by"] == "crew.lead"
    assert completed["executed_by"] == "scheduler"
    assert completed["targets"] == ["192.0.2.10/32"]
    assert completed["schedule_id"] == schedule["schedule_id"]
    assert completed["schedule_batch_id"] == "2" * 32
    assert any(
        item["phase"] == "udp"
        and item["remaining_seconds"] is None
        and item["phase_percent"] is None
        for item in phase_publications
    )
    run_dir = data_dir / "scan-runs" / manifest["run_id"]
    assert (run_dir / "tcp-scan.xml").is_file()
    assert (run_dir / "udp-scan.xml").is_file()
    merged = (run_dir / "scan.xml").read_text(encoding="utf-8")
    assert 'protocol="tcp" portid="443"' in merged
    assert 'protocol="udp" portid="53"' in merged
    registered = {item["filename"] for item in completed["artifact_registry"]["files"]}
    assert {"tcp-scan.xml", "udp-scan.xml", "scan.xml"}.issubset(registered)


def test_combined_top_ports_fping_fallback_previews_and_runs_both_protocols(tmp_path):
    db_path = tmp_path / "nct.db"
    data_dir = tmp_path / "data"
    request = ScanRunRequest(
        operator="Tester",
        name="Combined FPING fallback",
        reason="Verify split fallback approval and execution",
        originating_host="test-host",
        interface="eth0",
        profile="Custom",
        scan_options=ScanOptions(
            protocol="tcp_udp",
            tcp_scope="top_1000",
            udp_scope="top_100",
            discovery_mode="fping",
            traceroute=True,
        ),
        targets=["192.0.2.10/32"],
        capture=True,
        timeout_seconds=30,
    )
    manifest = prepare_scan_run(request, db_path, interfaces={"eth0"})
    control = RunControl()
    approval_states: list[dict] = []
    launched: list[str] = []

    def fake_popen(argv, *, cwd: Path, **_kwargs):
        command = " ".join(str(item) for item in argv)
        launched.append(command)
        if command.startswith("tcpdump"):
            return FakeProcess(None)
        if command.startswith("fping"):
            return FakeProcess(1)
        if "tcp-scan.xml" in command:
            (cwd / "tcp-scan.xml").write_bytes(TCP_XML)
            return FakeProcess(0)
        if "udp-scan.xml" in command:
            (cwd / "udp-scan.xml").write_bytes(UDP_XML)
            return FakeProcess(0)
        raise AssertionError(command)

    def approve_full_target_fallback(_seconds):
        current = get_scan_run_plan(manifest["run_id"], db_path)
        if current and current["status"] == "awaiting_fallback_approval":
            approval_states.append(current)
            control.fallback_decision = "approve"
            control.fallback_decided_by = "Tester"
            control.fallback_authorization_note = "Approved test-only full-target fallback"
            control.fallback_decision_event.set()

    execute_scan_run(
        manifest["run_id"], control, db_path=db_path, data_dir=data_dir,
        popen_factory=fake_popen, sleep_fn=approve_full_target_fallback,
    )

    completed = get_scan_run_plan(manifest["run_id"], db_path)
    assert approval_states
    preview = approval_states[0]
    assert preview["fallback_trigger"] == "no_responsive_hosts"
    assert [item["name"] for item in preview["fallback_execution_phases"]] == [
        "tcp", "udp"
    ]
    tcp_preview, udp_preview = preview["fallback_execution_phases"]
    assert tcp_preview["command_argv"][
        tcp_preview["command_argv"].index("--top-ports") + 1
    ] == "1000"
    assert udp_preview["command_argv"][
        udp_preview["command_argv"].index("--top-ports") + 1
    ] == "100"
    assert completed["status"] == "completed"
    assert completed["fallback_decision"] == "approve"
    assert completed["coverage"]["actual_protocols"] == ["TCP", "UDP"]
    assert any("tcp-scan.xml" in command for command in launched)
    assert any("udp-scan.xml" in command for command in launched)


@pytest.mark.parametrize(
    ("failure_mode", "expected_reason"),
    [("exit", "exit status 4"), ("startup", "a startup error")],
)
def test_fping_failure_pauses_for_fallback_approval_instead_of_failing_scan(
    tmp_path, failure_mode, expected_reason
):
    db_path = tmp_path / "nct.db"
    data_dir = tmp_path / "data"
    request = ScanRunRequest(
        operator="Tester",
        name="FPING fallback test",
        reason="Verify failed discovery requires approval",
        originating_host="test-host",
        interface="eth0",
        profile="Custom",
        scan_options=ScanOptions(
            protocol="tcp",
            tcp_scope="common",
            discovery_mode="fping",
        ),
        targets=["192.0.2.10/32"],
        capture=True,
        timeout_seconds=30,
    )
    manifest = prepare_scan_run(request, db_path, interfaces={"eth0"})
    control = RunControl()
    approval_states = []

    def fake_popen(argv, *, cwd: Path, **kwargs):
        command = " ".join(str(item) for item in argv)
        if command.startswith("tcpdump"):
            return FakeProcess(None)
        if command.startswith("fping"):
            if failure_mode == "startup":
                raise FileNotFoundError("fping executable unavailable")
            kwargs["stderr"].write(b"fping: cannot create raw socket\n")
            kwargs["stderr"].flush()
            return FakeProcess(4)
        raise AssertionError(command)

    def record_and_decline(_seconds):
        current = get_scan_run_plan(manifest["run_id"], db_path)
        if current and current["status"] == "awaiting_fallback_approval":
            approval_states.append(current)
            control.fallback_decision = "decline"
            control.fallback_decided_by = "Tester"
            control.fallback_authorization_note = "Do not bypass discovery in this test"
            control.fallback_decision_event.set()

    execute_scan_run(
        manifest["run_id"],
        control,
        db_path=db_path,
        data_dir=data_dir,
        popen_factory=fake_popen,
        sleep_fn=record_and_decline,
    )

    completed = get_scan_run_plan(manifest["run_id"], db_path)
    assert approval_states
    assert approval_states[0]["fallback_trigger"] == "fping_failed"
    assert expected_reason in approval_states[0]["fallback_reason"]
    assert approval_states[0]["exact_fallback_command"]
    assert completed["status"] == "completed_without_nmap"
    assert completed["fallback_decision"] == "decline"
    assert completed["fallback_approval_required"] is False
    expected_error = (
        "cannot create raw socket"
        if failure_mode == "exit"
        else "fping executable unavailable"
    )
    assert expected_error in completed["discovery_error"]
