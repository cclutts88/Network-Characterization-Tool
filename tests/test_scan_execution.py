from __future__ import annotations

from pathlib import Path

from app.poc import (
    RunControl,
    ScanOptions,
    ScanRunRequest,
    execute_scan_run,
    get_scan_run_plan,
    prepare_scan_run,
)


DISCOVERY_XML = b'''<?xml version="1.0"?><nmaprun scanner="nmap"><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/></host><runstats><finished time="1"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>'''
TCP_XML = b'''<?xml version="1.0"?><nmaprun scanner="nmap"><scaninfo type="syn" protocol="tcp"/><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/></port></ports></host><runstats><finished time="2"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>'''


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
    assert completed["partial_results"] is True
    assert completed["success"] is True
    assert completed["coverage"]["actual_protocols"] == ["TCP"]
    assert completed["execution_phases"][0]["status"] == "completed"
    assert completed["execution_phases"][1]["status"] == "failed"
    assert "TCP results were preserved" in completed["execution_note"]
    canonical = data_dir / "scan-runs" / manifest["run_id"] / "scan.xml"
    assert canonical.is_file()
    assert 'protocol="tcp" portid="443"' in canonical.read_text(encoding="utf-8")
