#!/usr/bin/env python3
"""Render bounded Kubernetes Jobs for NCT cold backup and isolated restore."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

import nct_kubernetes_recovery as recovery
import render_kubernetes_single_replica as primary


MAX_TEXT = 160
TEXT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+/-]{0,159}$")


class RenderError(ValueError):
    pass


def _text(value: str, label: str) -> str:
    if len(value) > MAX_TEXT or not TEXT_RE.fullmatch(value):
        raise RenderError(f"{label} contains unsupported characters or is too long")
    return value


def _storage(args: argparse.Namespace, prefix: str) -> argparse.Namespace:
    value = argparse.Namespace(
        name=args.name,
        namespace=args.namespace,
        image=args.image,
        pvc_name=getattr(args, f"{prefix}_pvc_name"),
        storage_class=getattr(args, f"{prefix}_storage_class"),
        storage_size=getattr(args, f"{prefix}_storage_size"),
        pvc_uid=getattr(args, f"{prefix}_pvc_uid"),
        bound_volume_uid=getattr(args, f"{prefix}_bound_volume_uid"),
        storage_report=getattr(args, f"{prefix}_storage_report"),
        storage_report_digest=getattr(args, f"{prefix}_storage_report_digest"),
        mount_path={"source": "/data", "backup": "/backup", "target": "/restore"}[prefix],
        bootstrap_secret=None,
        output=args.output,
        overwrite=args.overwrite,
    )
    primary._validate_args(value)
    primary.validate_report(value)
    return value


def _security() -> dict:
    return {
        "allowPrivilegeEscalation": False,
        "readOnlyRootFilesystem": True,
        "runAsNonRoot": True,
        "runAsUser": primary.RUN_AS_UID,
        "runAsGroup": primary.RUN_AS_GID,
        "capabilities": {"drop": ["ALL"]},
    }


def _pod_security() -> dict:
    return {
        "runAsNonRoot": True,
        "runAsUser": primary.RUN_AS_UID,
        "runAsGroup": primary.RUN_AS_GID,
        "fsGroup": primary.RUN_AS_GID,
        "fsGroupChangePolicy": "OnRootMismatch",
        "seccompProfile": {"type": "RuntimeDefault"},
    }


def _job(args: argparse.Namespace) -> dict:
    source = _storage(args, "source")
    backup = _storage(args, "backup")
    target = _storage(args, "target") if args.command == "restore" else None
    identities = [primary.storage_identity(source), primary.storage_identity(backup)]
    if target:
        identities.append(primary.storage_identity(target))
    keys = [(value.pvc_uid, value.bound_volume_uid) for value in (source, backup, target) if value]
    if len(set(keys)) != len(keys):
        raise RenderError("source, backup, and restore target storage identities must differ")
    digest = hashlib.sha256("\n".join(identities).encode("utf-8")).hexdigest()
    labels = {
        "app.kubernetes.io/name": args.name,
        "app.kubernetes.io/component": "cold-recovery",
        "nct.openai.com/recovery-operation": args.command,
    }
    annotations = {
        "nct.openai.com/backup-id": args.backup_id,
        "nct.openai.com/recovery-identities-sha256": digest,
        "nct.openai.com/source-pvc-uid": source.pvc_uid,
        "nct.openai.com/source-volume-uid": source.bound_volume_uid,
        "nct.openai.com/backup-pvc-uid": backup.pvc_uid,
        "nct.openai.com/backup-volume-uid": backup.bound_volume_uid,
        "nct.openai.com/source-qualification-digest": source.storage_report_digest,
        "nct.openai.com/backup-qualification-digest": backup.storage_report_digest,
    }
    command = ["python", "/opt/nct/tools/nct_kubernetes_recovery.py", args.command]
    tool_args = [
        "--backup-root", "/backup", "--backup-id", args.backup_id,
        "--backup-identity", identities[1],
        "--max-files", str(args.max_files), "--max-bytes", str(args.max_bytes),
        "--max-seconds", str(args.max_seconds),
    ]
    mounts = [{"name": "backup", "mountPath": "/backup", "readOnly": args.command == "restore"}]
    volumes = [{"name": "backup", "persistentVolumeClaim": {"claimName": backup.pvc_name}}]
    if args.command == "backup":
        tool_args.extend([
            "--source", "/data", "--source-identity", identities[0],
            "--source-qualification-report-digest", source.storage_report_digest,
            "--backup-qualification-report-digest", backup.storage_report_digest,
            "--image", args.image, "--application-version", args.application_version,
            "--build-id", args.build_id,
        ])
        mounts.insert(0, {"name": "source", "mountPath": "/data"})
        volumes.insert(0, {"name": "source", "persistentVolumeClaim": {"claimName": source.pvc_name}})
    else:
        annotations.update({
            "nct.openai.com/target-pvc-uid": target.pvc_uid,
            "nct.openai.com/target-volume-uid": target.bound_volume_uid,
            "nct.openai.com/target-qualification-digest": target.storage_report_digest,
        })
        tool_args.extend([
            "--target", "/restore", "--target-identity", identities[2],
            "--expected-source-identity", identities[0],
            "--expected-receipt-digest", args.backup_receipt_digest,
            "--backup-qualification-report-digest", backup.storage_report_digest,
            "--target-qualification-report-digest", target.storage_report_digest,
            "--receipt-path", "/tmp/nct-restore-receipt.json",
        ])
        mounts.append({"name": "target", "mountPath": "/restore"})
        volumes.append({"name": "target", "persistentVolumeClaim": {"claimName": target.pvc_name}})
    mounts.append({"name": "tmp", "mountPath": "/tmp"})
    volumes.append({"name": "tmp", "emptyDir": {"sizeLimit": "64Mi"}})
    suffix = hashlib.sha256(f"{args.command}:{args.backup_id}:{digest}".encode()).hexdigest()[:12]
    base = f"{args.name}-{args.command}"[:49].rstrip("-")
    job = {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": primary._metadata(f"{base}-{suffix}", args.namespace, labels, annotations),
        "spec": {
            "backoffLimit": 0,
            "activeDeadlineSeconds": args.max_seconds + 60,
            "template": {
                "metadata": {"labels": labels, "annotations": annotations},
                "spec": {
                    "serviceAccountName": f"{args.name}-runtime",
                    "automountServiceAccountToken": False,
                    "restartPolicy": "Never",
                    "terminationGracePeriodSeconds": 30,
                    "securityContext": _pod_security(),
                    "containers": [{
                        "name": args.command,
                        "image": args.image,
                        "imagePullPolicy": "IfNotPresent",
                        "command": command,
                        "args": tool_args,
                        "terminationMessagePath": "/tmp/nct-restore-receipt.json",
                        "terminationMessagePolicy": "File",
                        "securityContext": _security(),
                        "resources": {
                            "requests": {"cpu": "100m", "memory": "128Mi"},
                            "limits": {"cpu": "1", "memory": "1Gi"},
                        },
                        "volumeMounts": mounts,
                    }],
                    "volumes": volumes,
                },
            },
        },
    }
    return primary._resource_list([primary._service_account(args), job])


def _add_storage(parser: argparse.ArgumentParser, prefix: str) -> None:
    parser.add_argument(f"--{prefix}-pvc-name", required=True)
    parser.add_argument(f"--{prefix}-storage-class", required=True)
    parser.add_argument(f"--{prefix}-storage-size", required=True)
    parser.add_argument(f"--{prefix}-pvc-uid", required=True)
    parser.add_argument(f"--{prefix}-bound-volume-uid", required=True)
    parser.add_argument(f"--{prefix}-storage-report", type=Path, required=True)
    parser.add_argument(f"--{prefix}-storage-report-digest", required=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("backup", "restore"):
        item = subparsers.add_parser(command)
        item.add_argument("--name", default="nct-analysis")
        item.add_argument("--namespace", required=True)
        item.add_argument("--image", required=True)
        item.add_argument("--backup-id", required=True)
        item.add_argument("--max-files", type=int, default=recovery.DEFAULT_MAX_FILES)
        item.add_argument("--max-bytes", type=int, default=recovery.DEFAULT_MAX_BYTES)
        item.add_argument("--max-seconds", type=int, default=recovery.DEFAULT_MAX_SECONDS)
        item.add_argument("--output", type=Path, required=True)
        item.add_argument("--overwrite", action="store_true")
        _add_storage(item, "source")
        _add_storage(item, "backup")
        if command == "backup":
            item.add_argument("--application-version", required=True)
            item.add_argument("--build-id", required=True)
        else:
            _add_storage(item, "target")
            item.add_argument("--backup-receipt-digest", required=True)
    return parser


def _validate(args: argparse.Namespace) -> None:
    args.name = primary._name(args.name, "name")
    args.namespace = primary._name(args.namespace, "namespace")
    args.image = primary._image(args.image)
    if not recovery.BACKUP_ID_RE.fullmatch(args.backup_id):
        raise RenderError("backup ID is invalid")
    if args.max_files < 1 or args.max_bytes < 1 or not 60 <= args.max_seconds <= 86_400:
        raise RenderError("recovery limits are invalid")
    if args.command == "backup":
        args.application_version = _text(args.application_version, "application version")
        args.build_id = _text(args.build_id, "build ID")
    elif not recovery.DIGEST_RE.fullmatch(args.backup_receipt_digest):
        raise RenderError("backup receipt digest is invalid")


def main() -> int:
    try:
        args = _parser().parse_args()
        _validate(args)
        primary._write_output(args.output, _job(args), args.overwrite)
    except (RenderError, primary.RenderError, recovery.RecoveryError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
