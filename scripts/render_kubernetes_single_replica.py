#!/usr/bin/env python3
"""Render bounded single-replica Kubernetes resources for NCT."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

import qualify_kubernetes_storage as qualifier


RUN_AS_UID = 10001
RUN_AS_GID = 10001
REPORT_MAX_BYTES = 65_536
MAX_IMAGE_CHARS = 512
MAX_STORAGE_SIZE_CHARS = 16
MAX_IMMUTABLE_ID_CHARS = 128
MAX_OUTPUT_BYTES = 262_144
NAME_RE = re.compile(r"^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$")
DNS_RE = re.compile(
    r"^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?)*$"
)
IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[0-9a-f]{64}$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
SIZE_RE = re.compile(r"^[1-9][0-9]*(?:Mi|Gi|Ti)$")
IMMUTABLE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
REQUIRED_CHECKS = {
    "root",
    "advisory_file_lock",
    "atomic_rename_and_fsync",
    "sqlite_wal",
    "bounded_resources",
}


class RenderError(ValueError):
    pass


def _name(value: str, label: str) -> str:
    if not NAME_RE.fullmatch(value):
        raise RenderError(f"{label} must be a Kubernetes DNS label")
    return value


def _dns(value: str, label: str) -> str:
    if len(value) > 253 or not DNS_RE.fullmatch(value):
        raise RenderError(f"{label} must be a Kubernetes DNS name")
    return value


def _image(value: str) -> str:
    if len(value) > MAX_IMAGE_CHARS or not IMAGE_RE.fullmatch(value):
        raise RenderError("image must use an exact sha256 digest")
    return value


def _size(value: str) -> str:
    if len(value) > MAX_STORAGE_SIZE_CHARS or not SIZE_RE.fullmatch(value):
        raise RenderError("storage size must be a positive Mi, Gi, or Ti quantity")
    return value


def _immutable_id(value: str, label: str) -> str:
    if len(value) > MAX_IMMUTABLE_ID_CHARS or not IMMUTABLE_ID_RE.fullmatch(value):
        raise RenderError(f"{label} must be an immutable Kubernetes object identifier")
    return value


def storage_identity(args: argparse.Namespace) -> str:
    mount_path = getattr(args, "mount_path", "/data")
    value = {
        "access_mode": "ReadWriteOnce",
        "executor_gid": RUN_AS_GID,
        "executor_uid": RUN_AS_UID,
        "mount_path": mount_path,
        "namespace": args.namespace,
        "pvc": args.pvc_name,
        "pvc_uid": args.pvc_uid,
        "bound_volume_uid": args.bound_volume_uid,
        "storage_class": args.storage_class,
        "storage_size": args.storage_size,
        "volume_mode": "Filesystem",
    }
    identity = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if len(identity.encode("utf-8")) > qualifier.MAX_STORAGE_IDENTITY_BYTES:
        raise RenderError("storage identity is too large for qualification")
    return identity


def _identity_sha256(identity: str) -> str:
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _metadata(
    name: str,
    namespace: str,
    labels: dict | None = None,
    annotations: dict | None = None,
) -> dict:
    value = {"name": name, "namespace": namespace}
    if labels:
        value["labels"] = labels
    if annotations:
        value["annotations"] = annotations
    return value


def _service_account(args: argparse.Namespace) -> dict:
    return {
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "metadata": _metadata(f"{args.name}-runtime", args.namespace),
        "automountServiceAccountToken": False,
    }


def _pvc(args: argparse.Namespace) -> dict:
    return {
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": _metadata(args.pvc_name, args.namespace, {"app.kubernetes.io/name": args.name}),
        "spec": {
            "accessModes": ["ReadWriteOnce"],
            "volumeMode": "Filesystem",
            "storageClassName": args.storage_class,
            "resources": {"requests": {"storage": args.storage_size}},
        },
    }


def claim_resources(args: argparse.Namespace) -> dict:
    return _resource_list([_service_account(args), _pvc(args)])


def _pod_security() -> dict:
    return {
        "runAsNonRoot": True,
        "runAsUser": RUN_AS_UID,
        "runAsGroup": RUN_AS_GID,
        "fsGroup": RUN_AS_GID,
        "fsGroupChangePolicy": "OnRootMismatch",
        "seccompProfile": {"type": "RuntimeDefault"},
    }


def _container_security() -> dict:
    return {
        "allowPrivilegeEscalation": False,
        "readOnlyRootFilesystem": True,
        "runAsNonRoot": True,
        "runAsUser": RUN_AS_UID,
        "runAsGroup": RUN_AS_GID,
        "capabilities": {"drop": ["ALL"]},
    }


def qualification_resources(args: argparse.Namespace) -> dict:
    identity = storage_identity(args)
    identity_sha256 = _identity_sha256(identity)
    labels = {"app.kubernetes.io/name": args.name, "app.kubernetes.io/component": "storage-qualification"}
    suffix = f"storage-check-{identity_sha256[:12]}"
    prefix = args.name[: 62 - len(suffix)].rstrip("-")
    job_name = f"{prefix}-{suffix}"
    annotations = {
        "nct.openai.com/pvc-uid": args.pvc_uid,
        "nct.openai.com/bound-volume-uid": args.bound_volume_uid,
        "nct.openai.com/storage-identity-sha256": identity_sha256,
    }
    job = {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": _metadata(job_name, args.namespace, labels, annotations),
        "spec": {
            "backoffLimit": 0,
            "activeDeadlineSeconds": 60,
            "ttlSecondsAfterFinished": 86400,
            "template": {
                "metadata": {"labels": labels, "annotations": annotations},
                "spec": {
                    "serviceAccountName": f"{args.name}-runtime",
                    "automountServiceAccountToken": False,
                    "restartPolicy": "Never",
                    "terminationGracePeriodSeconds": 5,
                    "securityContext": _pod_security(),
                    "containers": [{
                        "name": "qualify-storage",
                        "image": args.image,
                        "imagePullPolicy": "IfNotPresent",
                        "command": ["python", "/opt/nct/tools/qualify_kubernetes_storage.py"],
                        "args": ["--root", args.mount_path, "--storage-identity", identity],
                        "securityContext": _container_security(),
                        "resources": {
                            "requests": {"cpu": "50m", "memory": "64Mi"},
                            "limits": {"cpu": "500m", "memory": "256Mi"},
                        },
                        "volumeMounts": [
                            {"name": "data", "mountPath": args.mount_path},
                            {"name": "tmp", "mountPath": "/tmp"},
                        ],
                    }],
                    "volumes": [
                        {"name": "data", "persistentVolumeClaim": {"claimName": args.pvc_name}},
                        {"name": "tmp", "emptyDir": {"sizeLimit": "64Mi"}},
                    ],
                },
            },
        },
    }
    return _resource_list([_service_account(args), job])


def _read_report(path: Path) -> dict:
    try:
        value = os.lstat(path)
    except OSError as exc:
        raise RenderError("storage qualification report is not readable") from exc
    if stat.S_ISLNK(value.st_mode) or not stat.S_ISREG(value.st_mode):
        raise RenderError("storage qualification report must be a regular file, not a link")
    if value.st_size <= 0 or value.st_size > REPORT_MAX_BYTES:
        raise RenderError("storage qualification report size is invalid")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RenderError("storage qualification report is unreadable JSON") from exc


def validate_report(args: argparse.Namespace) -> tuple[dict, str, str]:
    if not DIGEST_RE.fullmatch(args.storage_report_digest):
        raise RenderError("storage report digest must be 64 lowercase hexadecimal characters")
    report = _read_report(args.storage_report)
    if not qualifier.verify_report_digest(report):
        raise RenderError("storage qualification report digest is invalid")
    attestation = report.get("attestation") or {}
    if attestation.get("digest") != args.storage_report_digest:
        raise RenderError("separately supplied storage report digest does not match")
    source_path = Path(__file__).with_name("qualify_kubernetes_storage.py")
    source_sha256 = hashlib.sha256(source_path.read_bytes()).hexdigest()
    tool = report.get("tool") or {}
    if report.get("schema_version") != qualifier.REPORT_SCHEMA_VERSION:
        raise RenderError("storage qualification report schema is unsupported")
    if tool.get("version") != qualifier.TOOL_VERSION or tool.get("source_sha256") != source_sha256:
        raise RenderError("storage qualification report came from a different tool source")
    identity = storage_identity(args)
    identity_sha256 = _identity_sha256(identity)
    declared = report.get("declared") or {}
    if (
        declared.get("accepted") is not True
        or declared.get("storage_identity") != identity
        or declared.get("storage_identity_sha256") != identity_sha256
    ):
        raise RenderError("storage qualification report does not match this exact PVC request")
    measured = report.get("measured") or {}
    if measured.get("executor_uid") != RUN_AS_UID or measured.get("executor_gid") != RUN_AS_GID:
        raise RenderError("storage qualification did not use the NCT deployment user and group")
    checks = report.get("checks")
    if not isinstance(checks, list):
        raise RenderError("storage qualification checks are missing")
    if any(not isinstance(item, dict) for item in checks):
        raise RenderError("storage qualification checks are malformed")
    check_ids = [item.get("id") for item in checks]
    if (
        len(check_ids) != len(set(check_ids))
        or set(check_ids) != REQUIRED_CHECKS
        or any(item.get("status") != "pass" for item in checks)
    ):
        raise RenderError("storage qualification did not pass every required check")
    cleanup = report.get("cleanup") or {}
    if report.get("overall") != "pass" or cleanup.get("id") != "cleanup" or cleanup.get("status") != "pass":
        raise RenderError("storage qualification or cleanup did not pass")
    return report, identity, identity_sha256


def deployment_resources(args: argparse.Namespace) -> dict:
    _report, identity, identity_sha256 = validate_report(args)
    labels = {"app.kubernetes.io/name": args.name, "app.kubernetes.io/component": "analysis"}
    pod_annotations = {
        "nct.openai.com/storage-evidence-digest": args.storage_report_digest,
        "nct.openai.com/storage-identity-sha256": identity_sha256,
        "nct.openai.com/storage-evidence-authenticated": "false",
        "nct.openai.com/pvc-uid": args.pvc_uid,
        "nct.openai.com/bound-volume-uid": args.bound_volume_uid,
    }
    env = [
        {"name": "ANALYZER_DATA_DIR", "value": "/data"},
        {"name": "HOME", "value": "/tmp"},
        {"name": "NCT_AUTH_MODE", "value": "local"},
        {"name": "NCT_COOKIE_SECURE", "value": "1"},
        {"name": "NCT_SESSION_HOURS", "value": "12"},
        {"name": "NCT_ACTIVE_COLLECTION_MODE", "value": "disabled"},
        {"name": "NCT_DEPLOYMENT_PROFILE", "value": "kubernetes_single_replica_analysis"},
        {"name": "NCT_STORAGE_IDENTITY", "value": identity},
        {"name": "NCT_STORAGE_REPORT_DIGEST", "value": args.storage_report_digest},
    ]
    mounts = [
        {"name": "data", "mountPath": "/data"},
        {"name": "tmp", "mountPath": "/tmp"},
    ]
    volumes = [
        {"name": "data", "persistentVolumeClaim": {"claimName": args.pvc_name}},
        {"name": "tmp", "emptyDir": {"sizeLimit": "256Mi"}},
    ]
    if args.bootstrap_secret:
        env.extend([
            {
                "name": "NCT_BOOTSTRAP_ADMIN",
                "valueFrom": {"secretKeyRef": {"name": args.bootstrap_secret, "key": "username"}},
            },
            {"name": "NCT_BOOTSTRAP_PASSWORD_FILE", "value": "/run/secrets/nct-bootstrap/password"},
        ])
        mounts.append({"name": "bootstrap", "mountPath": "/run/secrets/nct-bootstrap", "readOnly": True})
        volumes.append({
            "name": "bootstrap",
            "secret": {
                "secretName": args.bootstrap_secret,
                "defaultMode": 288,
                "items": [{"key": "password", "path": "password"}],
            },
        })
    container = {
        "name": "nct",
        "image": args.image,
        "imagePullPolicy": "IfNotPresent",
        "ports": [{"name": "http", "containerPort": 8080, "protocol": "TCP"}],
        "env": env,
        "securityContext": _container_security(),
        "resources": {
            "requests": {"cpu": "250m", "memory": "512Mi"},
            "limits": {"cpu": "2", "memory": "2Gi"},
        },
        "startupProbe": {
            "httpGet": {"path": "/health/startup", "port": "http"},
            "periodSeconds": 2,
            "failureThreshold": 60,
            "timeoutSeconds": 1,
        },
        "readinessProbe": {
            "httpGet": {"path": "/health/readiness", "port": "http"},
            "periodSeconds": 5,
            "failureThreshold": 3,
            "timeoutSeconds": 1,
        },
        "livenessProbe": {
            "httpGet": {"path": "/health/liveness", "port": "http"},
            "periodSeconds": 10,
            "failureThreshold": 3,
            "timeoutSeconds": 1,
        },
        "volumeMounts": mounts,
    }
    deployment = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": _metadata(args.name, args.namespace, labels),
        "spec": {
            "replicas": 1,
            "revisionHistoryLimit": 1,
            "progressDeadlineSeconds": 600,
            "strategy": {"type": "Recreate"},
            "selector": {"matchLabels": labels},
            "template": {
                "metadata": {"labels": labels, "annotations": pod_annotations},
                "spec": {
                    "serviceAccountName": f"{args.name}-runtime",
                    "automountServiceAccountToken": False,
                    "terminationGracePeriodSeconds": 120,
                    "securityContext": _pod_security(),
                    "containers": [container],
                    "volumes": volumes,
                },
            },
        },
    }
    service = {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": _metadata(args.name, args.namespace, labels),
        "spec": {
            "type": "ClusterIP",
            "selector": labels,
            "ports": [{"name": "http", "port": 8080, "targetPort": "http", "protocol": "TCP"}],
        },
    }
    return _resource_list([_service_account(args), deployment, service])


def _resource_list(items: list[dict]) -> dict:
    return {"apiVersion": "v1", "kind": "List", "items": items}


def _validate_args(args: argparse.Namespace) -> None:
    args.name = _name(args.name, "name")
    args.namespace = _name(args.namespace, "namespace")
    args.pvc_name = _name(args.pvc_name, "PVC name")
    args.storage_class = _dns(args.storage_class, "storage class")
    args.storage_size = _size(args.storage_size)
    if getattr(args, "image", None) is not None:
        args.image = _image(args.image)
    if getattr(args, "pvc_uid", None) is not None:
        args.pvc_uid = _immutable_id(args.pvc_uid, "PVC UID")
    if getattr(args, "bound_volume_uid", None) is not None:
        args.bound_volume_uid = _immutable_id(args.bound_volume_uid, "bound volume UID")
    if getattr(args, "bootstrap_secret", None):
        args.bootstrap_secret = _name(args.bootstrap_secret, "bootstrap Secret name")
    mount_path = getattr(args, "mount_path", "/data")
    if mount_path not in {"/data", "/backup", "/restore"}:
        raise RenderError("mount path must be /data, /backup, or /restore")
    args.mount_path = mount_path


def _write_output(path: Path, value: dict, overwrite: bool) -> None:
    path = path.absolute()
    if path.is_symlink():
        raise RenderError("output must not be a symbolic link")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        raise RenderError("output already exists; use --overwrite to replace it")
    payload = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    if len(payload.encode("utf-8")) > MAX_OUTPUT_BYTES:
        raise RenderError("rendered Kubernetes document exceeds the safe output limit")
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if path.exists() and not overwrite:
            raise RenderError("output appeared while rendering; refusing to replace it")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_common(target: argparse.ArgumentParser, *, image: bool, identity: bool) -> None:
        target.add_argument("--name", default="nct-analysis")
        target.add_argument("--namespace", required=True)
        if image:
            target.add_argument("--image", required=True)
        target.add_argument("--pvc-name", required=True)
        target.add_argument("--storage-class", required=True)
        target.add_argument("--storage-size", required=True)
        if identity:
            target.add_argument("--pvc-uid", required=True)
            target.add_argument("--bound-volume-uid", required=True)
        target.add_argument("--output", type=Path, required=True)
        target.add_argument("--overwrite", action="store_true")

    claim = subparsers.add_parser("claim")
    add_common(claim, image=False, identity=False)
    qualification = subparsers.add_parser("qualification")
    add_common(qualification, image=True, identity=True)
    qualification.add_argument("--mount-path", choices=("/data", "/backup", "/restore"), default="/data")
    deployment = subparsers.add_parser("deployment")
    add_common(deployment, image=True, identity=True)
    deployment.add_argument("--storage-report", type=Path, required=True)
    deployment.add_argument("--storage-report-digest", required=True)
    deployment.add_argument("--bootstrap-secret")
    return parser


def main() -> int:
    try:
        args = _parser().parse_args()
        _validate_args(args)
        if args.command == "claim":
            value = claim_resources(args)
        elif args.command == "qualification":
            value = qualification_resources(args)
        else:
            value = deployment_resources(args)
        _write_output(args.output, value, args.overwrite)
    except RenderError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
