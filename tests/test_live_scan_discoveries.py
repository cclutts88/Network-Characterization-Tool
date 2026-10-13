import os
import time
from pathlib import Path

import pytest
from fastapi import HTTPException

from app import poc
from app.live_scan_discoveries import live_scan_discoveries


HOST_ONE = b"""<host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/><hostnames><hostname name="web-10"/></hostnames><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.24"/></port><port protocol="tcp" portid="81"><state state="closed"/></port></ports></host>"""
HOST_TWO = b"""<host><status state="up"/><address addr="192.0.2.11" addrtype="ipv4"/><ports><port protocol="udp" portid="53"><state state="open|filtered"/><service name="domain"/></port></ports></host>"""


def test_live_scan_reader_returns_only_fully_closed_provisional_hosts(tmp_path: Path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "tcp-scan.xml").write_bytes(
        b'<?xml version="1.0"?><nmaprun>' + HOST_ONE + b'<host><address addr="192.0.2.99"'
    )

    result = live_scan_discoveries(run_dir)

    assert result["provisional"] is True
    assert result["host_count"] == 1
    assert result["row_count"] == 1
    assert result["parse_errors"] == 0
    assert result["rows"] == [{
        "address": "192.0.2.10",
        "hostname": "web-10",
        "protocol": "tcp",
        "port": 80,
        "state": "open",
        "service": "http · nginx · 1.24",
        "phase": "tcp",
    }]


def test_live_scan_reader_combines_phases_deduplicates_and_stays_bounded(tmp_path: Path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "tcp-scan.xml").write_bytes(b"<nmaprun>" + HOST_ONE)
    (run_dir / "udp-scan.xml").write_bytes(b"<nmaprun>" + HOST_ONE + HOST_TWO)

    result = live_scan_discoveries(run_dir, max_rows=2)

    assert result["host_count"] == 2
    assert result["row_count"] == 2
    assert result["truncated"] is True
    assert {(row["address"], row["protocol"], row["port"]) for row in result["rows"]} == {
        ("192.0.2.10", "tcp", 80),
        ("192.0.2.11", "udp", 53),
    }


def test_live_scan_reader_sorts_ip_addresses_numerically(tmp_path: Path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    hosts = b"".join(
        HOST_ONE.replace(b"192.0.2.10", address)
        for address in (b"192.0.2.10", b"192.0.2.2", b"192.0.2.1", b"192.0.2.20")
    )
    (run_dir / "tcp-scan.xml").write_bytes(b"<nmaprun>" + hosts)

    result = live_scan_discoveries(run_dir)

    assert [row["address"] for row in result["rows"]] == [
        "192.0.2.1", "192.0.2.2", "192.0.2.10", "192.0.2.20"
    ]


def test_live_scan_reader_does_not_follow_a_phase_file_symlink(tmp_path: Path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    outside = tmp_path / "outside.xml"
    outside.write_bytes(b"<nmaprun>" + HOST_TWO)
    try:
        (run_dir / "tcp-scan.xml").symlink_to(outside)
    except OSError:
        pytest.skip("File symlinks are unavailable on this platform")

    result = live_scan_discoveries(run_dir)

    assert result["rows"] == []
    assert result["host_count"] == 0


def test_live_scan_reader_rejects_a_named_pipe_without_blocking(tmp_path: Path):
    if not hasattr(os, "mkfifo"):
        pytest.skip("Named pipes are unavailable on this platform")
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    os.mkfifo(run_dir / "tcp-scan.xml")

    started = time.monotonic()
    result = live_scan_discoveries(run_dir)

    assert time.monotonic() - started < 0.5
    assert result["rows"] == []
    assert result["host_count"] == 0


def test_live_scan_reader_uses_the_opened_file_when_path_is_replaced(tmp_path: Path, monkeypatch):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    phase_file = run_dir / "tcp-scan.xml"
    phase_file.write_bytes(b"<nmaprun>" + HOST_ONE)
    outside = tmp_path / "outside.xml"
    outside.write_bytes(b"<nmaprun>" + HOST_TWO)
    original_open = os.open
    replaced = False

    def replace_after_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal replaced
        descriptor = original_open(path, flags, mode, dir_fd=dir_fd)
        if path == "tcp-scan.xml" and not replaced:
            replaced = True
            phase_file.unlink()
            phase_file.symlink_to(outside)
        return descriptor

    monkeypatch.setattr("app.live_scan_discoveries.os.open", replace_after_open)

    result = live_scan_discoveries(run_dir)

    assert [row["address"] for row in result["rows"]] == ["192.0.2.10"]


def test_live_scan_endpoint_requires_the_exact_run_to_be_active(tmp_path: Path, monkeypatch):
    run_id = "a" * 32
    data_dir = tmp_path / "data"
    run_dir = data_dir / poc.RUNS_DIR_NAME / run_id
    run_dir.mkdir(parents=True)
    (run_dir / "tcp-scan.xml").write_bytes(b"<nmaprun>" + HOST_ONE)
    monkeypatch.setattr(poc, "DATA_DIR", data_dir)
    monkeypatch.setattr(poc, "get_scan_run_plan", lambda *_args, **_kwargs: {
        "run_id": run_id,
        "status": "running",
        "progress": {"phase": "tcp"},
    })

    result = poc.scan_run_live_discoveries(run_id)

    assert result["run_id"] == run_id
    assert result["status"] == "running"
    assert result["phase"] == "tcp"
    assert result["rows"][0]["address"] == "192.0.2.10"

    monkeypatch.setattr(poc, "get_scan_run_plan", lambda *_args, **_kwargs: {
        "run_id": run_id,
        "status": "completed",
    })
    with pytest.raises(HTTPException) as exc:
        poc.scan_run_live_discoveries(run_id)
    assert exc.value.status_code == 409


def test_live_scan_endpoint_rejects_a_symlinked_run_folder(tmp_path: Path, monkeypatch):
    run_id = "b" * 32
    data_dir = tmp_path / "data"
    root = data_dir / poc.RUNS_DIR_NAME
    outside = tmp_path / "outside"
    root.mkdir(parents=True)
    outside.mkdir()
    try:
        (root / run_id).symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("Directory symlinks are unavailable on this platform")
    monkeypatch.setattr(poc, "DATA_DIR", data_dir)
    monkeypatch.setattr(poc, "get_scan_run_plan", lambda *_args, **_kwargs: {
        "run_id": run_id,
        "status": "running",
        "progress": {"phase": "tcp"},
    })

    with pytest.raises(HTTPException) as exc:
        poc.scan_run_live_discoveries(run_id)
    assert exc.value.status_code == 409
