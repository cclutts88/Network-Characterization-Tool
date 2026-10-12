from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

import pytest


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import qualify_kubernetes_storage as qualifier  # noqa: E402
import render_kubernetes_recovery as renderer  # noqa: E402
import render_kubernetes_single_replica as primary  # noqa: E402


def values(tmp_path: Path, command: str = "backup", **changes) -> argparse.Namespace:
    base = {
        "command": command, "name": "nct-analysis", "namespace": "nct",
        "image": "registry.example/nct@sha256:" + "a" * 64,
        "backup_id": "backup-20261012", "application_version": "0.14.0-dev",
        "build_id": "build-123", "backup_receipt_digest": "f" * 64,
        "max_files": 1000, "max_bytes": 1024**3,
        "max_seconds": 3600, "output": tmp_path / "job.json", "overwrite": False,
    }
    for prefix, marker in (("source", "1"), ("backup", "2"), ("target", "3")):
        base.update({
            f"{prefix}_pvc_name": f"nct-{prefix}",
            f"{prefix}_storage_class": "approved-rwo",
            f"{prefix}_storage_size": "20Gi",
            f"{prefix}_pvc_uid": f"{marker}1111111-2222-4333-8444-555555555555",
            f"{prefix}_bound_volume_uid": f"{marker}aaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            f"{prefix}_storage_report": tmp_path / f"{prefix}.json",
            f"{prefix}_storage_report_digest": "",
        })
    base.update(changes)
    result = argparse.Namespace(**base)
    renderer._validate(result)
    prefixes = ("source", "backup", "target") if command == "restore" else ("source", "backup")
    for prefix in prefixes:
        write_report(result, prefix)
    return result


def write_report(args: argparse.Namespace, prefix: str) -> None:
    storage = argparse.Namespace(
        name=args.name, namespace=args.namespace, image=args.image,
        pvc_name=getattr(args, f"{prefix}_pvc_name"),
        storage_class=getattr(args, f"{prefix}_storage_class"),
        storage_size=getattr(args, f"{prefix}_storage_size"),
        pvc_uid=getattr(args, f"{prefix}_pvc_uid"),
        bound_volume_uid=getattr(args, f"{prefix}_bound_volume_uid"),
        mount_path={"source": "/data", "backup": "/backup", "target": "/restore"}[prefix],
    )
    identity = primary.storage_identity(storage)
    report = {
        "schema_version": qualifier.REPORT_SCHEMA_VERSION,
        "tool": {
            "version": qualifier.TOOL_VERSION,
            "source_sha256": hashlib.sha256((SCRIPTS / "qualify_kubernetes_storage.py").read_bytes()).hexdigest(),
        },
        "declared": {
            "storage_identity": identity,
            "storage_identity_sha256": hashlib.sha256(identity.encode()).hexdigest(),
            "accepted": True,
        },
        "measured": {"executor_uid": primary.RUN_AS_UID, "executor_gid": primary.RUN_AS_GID},
        "checks": [
            {"id": name, "status": "pass", "detail": "passed", "duration_seconds": 0.01}
            for name in sorted(primary.REQUIRED_CHECKS)
        ],
        "cleanup": {"id": "cleanup", "status": "pass", "detail": "removed", "duration_seconds": 0.01},
        "limitations": ["exact test volume only"],
    }
    report = qualifier._finalize(report)
    path = getattr(args, f"{prefix}_storage_report")
    path.write_text(json.dumps(report), encoding="utf-8")
    setattr(args, f"{prefix}_storage_report_digest", report["attestation"]["digest"])


def item(document: dict, kind: str) -> dict:
    return next(value for value in document["items"] if value["kind"] == kind)


def test_backup_job_is_bounded_unprivileged_and_mounts_two_exact_claims(tmp_path: Path) -> None:
    args = values(tmp_path)
    document = renderer._job(args)
    job = item(document, "Job")
    pod = job["spec"]["template"]["spec"]
    container = pod["containers"][0]
    mounts = {value["name"]: value for value in container["volumeMounts"]}
    volumes = {value["name"]: value for value in pod["volumes"]}
    assert job["spec"]["backoffLimit"] == 0
    assert job["spec"]["activeDeadlineSeconds"] == 3660
    assert "ttlSecondsAfterFinished" not in job["spec"]
    assert pod["automountServiceAccountToken"] is False
    assert container["securityContext"]["capabilities"] == {"drop": ["ALL"]}
    assert container["securityContext"]["readOnlyRootFilesystem"] is True
    assert mounts["source"]["mountPath"] == "/data"
    assert mounts["backup"]["mountPath"] == "/backup"
    assert volumes["source"]["persistentVolumeClaim"]["claimName"] == "nct-source"
    assert volumes["backup"]["persistentVolumeClaim"]["claimName"] == "nct-backup"
    assert "target" not in volumes
    assert "--source-identity" in container["args"]
    assert container["args"][container["args"].index("--source-qualification-report-digest") + 1] == args.source_storage_report_digest
    assert container["args"][container["args"].index("--backup-qualification-report-digest") + 1] == args.backup_storage_report_digest
    assert job["metadata"]["annotations"]["nct.openai.com/backup-qualification-digest"] == args.backup_storage_report_digest
    assert item(document, "ServiceAccount")["automountServiceAccountToken"] is False


def test_restore_job_uses_read_only_backup_and_distinct_empty_target_contract(tmp_path: Path) -> None:
    args = values(tmp_path, "restore")
    document = renderer._job(args)
    job = item(document, "Job")
    pod = job["spec"]["template"]["spec"]
    container = pod["containers"][0]
    mounts = {value["name"]: value for value in container["volumeMounts"]}
    volumes = {value["name"]: value for value in pod["volumes"]}
    assert mounts["backup"]["readOnly"] is True
    assert mounts["target"]["mountPath"] == "/restore"
    assert "source" not in volumes
    assert volumes["target"]["persistentVolumeClaim"]["claimName"] == "nct-target"
    assert "--expected-source-identity" in container["args"]
    assert "--expected-receipt-digest" in container["args"]
    assert container["args"][container["args"].index("--receipt-path") + 1] == "/tmp/nct-restore-receipt.json"
    assert container["terminationMessagePath"] == "/tmp/nct-restore-receipt.json"
    assert container["terminationMessagePolicy"] == "File"
    assert container["args"][container["args"].index("--target-qualification-report-digest") + 1] == args.target_storage_report_digest
    assert job["metadata"]["annotations"]["nct.openai.com/target-pvc-uid"] == args.target_pvc_uid
    assert job["metadata"]["annotations"]["nct.openai.com/target-qualification-digest"] == args.target_storage_report_digest


def test_renderer_rejects_reused_storage_identity(tmp_path: Path) -> None:
    args = values(tmp_path, "restore")
    args.target_pvc_uid = args.backup_pvc_uid
    args.target_bound_volume_uid = args.backup_bound_volume_uid
    write_report(args, "target")
    with pytest.raises(renderer.RenderError, match="must differ"):
        renderer._job(args)


def test_renderer_rejects_report_for_changed_claim(tmp_path: Path) -> None:
    args = values(tmp_path)
    args.backup_pvc_uid = "91111111-2222-4333-8444-555555555555"
    with pytest.raises(primary.RenderError, match="exact PVC request"):
        renderer._job(args)


@pytest.mark.parametrize("image", ("registry.example/nct:latest", "nct@sha256:short"))
def test_renderer_requires_exact_image_digest(tmp_path: Path, image: str) -> None:
    with pytest.raises(primary.RenderError, match="exact sha256"):
        values(tmp_path, image=image)
