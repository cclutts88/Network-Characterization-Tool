from __future__ import annotations

import argparse
import fcntl
import json
from pathlib import Path
import subprocess
import sys

import pytest


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import probe_nct_writer_lock as probe  # noqa: E402


def values(tmp_path: Path, **changes) -> argparse.Namespace:
    tmp_path.mkdir(parents=True, exist_ok=True)
    lock = tmp_path / ".analyzer.db.nct-writer.lock"
    lock.touch(exist_ok=True)
    base = {
        "lock_path": lock,
        "expect": "available",
        "scenario_id": "forced-stop-20261012",
        "scenario_kind": "forced-termination",
        "phase": "replacement-writer-released",
        "image": "registry.example/nct@sha256:" + "a" * 64,
        "application_version": "0.14.0-dev",
        "build_id": "build-123",
        "deployment_uid": "11111111-2222-4333-8444-555555555555",
        "deployment_generation": 7,
        "pod_uid": "22222222-2222-4333-8444-555555555555",
        "node_uid": "33333333-2222-4333-8444-555555555555",
        "storage_attachment_identity": "csi-attachment-12345678",
        "pvc_uid": "44444444-2222-4333-8444-555555555555",
        "bound_volume_uid": "55555555-2222-4333-8444-555555555555",
        "qualification_report_digest": "f" * 64,
        "receipt_path": tmp_path / "receipt.json",
    }
    base.update(changes)
    result = argparse.Namespace(**base)
    probe._validate(result)
    return result


def test_available_probe_uses_existing_file_and_writes_bounded_receipt(tmp_path: Path) -> None:
    args = values(tmp_path)
    inode = args.lock_path.stat().st_ino
    result = probe.probe(args)

    assert result["status"] == "pass"
    assert result["writer_lock"] == {
        "path": str(args.lock_path),
        "expected": "available",
        "observed": "available",
        "opened_existing_only": True,
        "sqlite_opened": False,
        "released_if_acquired": True,
        "destination_attachment_hold_seconds": 0,
    }
    assert args.lock_path.stat().st_ino == inode
    assert args.receipt_path.stat().st_size <= probe.MAX_RECEIPT_BYTES
    assert json.loads(args.receipt_path.read_text())["attestation"] == result["attestation"]


def test_contended_probe_observes_live_owner_without_opening_database(tmp_path: Path) -> None:
    args = values(
        tmp_path,
        expect="contended",
        phase="old-writer-active",
    )
    holder = subprocess.Popen(
        [
            sys.executable,
            "-c",
            (
                "import fcntl,sys; f=open(sys.argv[1],'r+b'); "
                "fcntl.lockf(f,fcntl.LOCK_EX,1,0); print('ready',flush=True); sys.stdin.read()"
            ),
            str(args.lock_path),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert holder.stdout is not None
        assert holder.stdout.readline().strip() == "ready"
        result = probe.probe(args)
        assert result["writer_lock"]["observed"] == "contended"
        assert result["writer_lock"]["released_if_acquired"] is False
    finally:
        if holder.stdin:
            holder.stdin.close()
        holder.wait(timeout=5)


def test_missing_or_mismatched_lock_fails_closed(tmp_path: Path) -> None:
    args = values(tmp_path)
    args.lock_path.unlink()
    with pytest.raises(probe.ProbeError, match="will not create"):
        probe.probe(args)
    assert not args.lock_path.exists()

    args = values(tmp_path, expect="contended", phase="old-writer-active")
    with pytest.raises(probe.ProbeError, match="expected contended, observed available"):
        probe.probe(args)


def test_unsafe_lock_and_inconsistent_phase_are_rejected(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_bytes(b"")
    lock = tmp_path / ".analyzer.db.nct-writer.lock"
    lock.symlink_to(target)
    args = values(tmp_path, lock_path=lock)
    with pytest.raises(probe.ProbeError, match="opened safely"):
        probe.probe(args)

    with pytest.raises(probe.ProbeError, match="contended probe"):
        values(tmp_path / "other", expect="contended", phase="replacement-writer-released")


def test_destination_pre_replacement_probe_uses_destination_without_future_pod(tmp_path: Path) -> None:
    args = values(
        tmp_path,
        scenario_id="node-loss-20261012",
        scenario_kind="node-loss",
        phase="destination-pre-replacement",
        pod_uid=None,
        hold_seconds=300,
    )
    result = probe.probe(args)

    assert result["writer_lock"]["observed"] == "available"
    assert result["scenario"]["phase"] == "destination-pre-replacement"
    assert "pod_uid" not in result["deployment"]

    with pytest.raises(probe.ProbeError, match="must not claim"):
        values(
            tmp_path / "bad",
            scenario_id="node-loss-20261012",
            scenario_kind="node-loss",
            phase="destination-pre-replacement",
            hold_seconds=300,
        )
