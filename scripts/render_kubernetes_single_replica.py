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
SCENARIO_RE = re.compile(r"^[a-z0-9][a-z0-9-]{7,79}$")
BACKUP_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{7,63}$")
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


def _suffixed_name(base: str, suffix: str) -> str:
    value = f"{base[: 63 - len(suffix) - 1].rstrip('-')}-{suffix}"
    return _name(value, "generated name")


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


def health_adapter_resources(args: argparse.Namespace) -> dict:
    """Render the isolated, read-only Kubernetes status adapter."""
    adapter_name = _suffixed_name(args.name, "health-adapter")
    account_name = _suffixed_name(args.name, "health-reader")
    role_name = _suffixed_name(args.name, "health-read")
    labels = {
        "app.kubernetes.io/name": args.name,
        "app.kubernetes.io/component": "health-adapter",
    }
    account = {
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "metadata": _metadata(account_name, args.namespace, labels),
        "automountServiceAccountToken": False,
    }
    rules = [
        {
            "apiGroups": ["apps"],
            "resources": ["deployments"],
            "resourceNames": [args.name],
            "verbs": ["get"],
        },
        {
            "apiGroups": ["apps"],
            "resources": ["replicasets"],
            "verbs": ["list"],
        },
        {
            "apiGroups": [""],
            "resources": ["pods"],
            "verbs": ["list"],
        },
    ]
    if args.enable_metrics:
        rules.append({
            "apiGroups": ["metrics.k8s.io"],
            "resources": ["pods"],
            "verbs": ["list"],
        })
    role = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": _metadata(role_name, args.namespace, labels),
        "rules": rules,
    }
    binding = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "RoleBinding",
        "metadata": _metadata(role_name, args.namespace, labels),
        "subjects": [{"kind": "ServiceAccount", "name": account_name, "namespace": args.namespace}],
        "roleRef": {
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "Role",
            "name": role_name,
        },
    }
    token_volume = {
        "name": "kube-api-access",
        "projected": {
            "defaultMode": 288,
            "sources": [
                {"serviceAccountToken": {"path": "token", "expirationSeconds": 3600}},
                {
                    "configMap": {
                        "name": "kube-root-ca.crt",
                        "items": [{"key": "ca.crt", "path": "ca.crt"}],
                    },
                },
                {
                    "downwardAPI": {
                        "items": [{
                            "path": "namespace",
                            "fieldRef": {"apiVersion": "v1", "fieldPath": "metadata.namespace"},
                        }],
                    },
                },
            ],
        },
    }
    adapter = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": _metadata(adapter_name, args.namespace, labels),
        "spec": {
            "replicas": 1,
            "revisionHistoryLimit": 1,
            "strategy": {"type": "Recreate"},
            "selector": {"matchLabels": labels},
            "template": {
                "metadata": {"labels": labels},
                "spec": {
                    "serviceAccountName": account_name,
                    "automountServiceAccountToken": False,
                    "terminationGracePeriodSeconds": 10,
                    "securityContext": _pod_security(),
                    "containers": [{
                        "name": "health-adapter",
                        "image": args.image,
                        "imagePullPolicy": "IfNotPresent",
                        "command": ["python", "/opt/nct/tools/nct_kubernetes_health_adapter.py"],
                        "env": [
                            {"name": "NCT_KUBERNETES_NAME", "value": args.name},
                            {"name": "NCT_KUBERNETES_NAMESPACE", "value": args.namespace},
                            {
                                "name": "NCT_KUBERNETES_METRICS_ENABLED",
                                "value": "1" if args.enable_metrics else "0",
                            },
                        ],
                        "ports": [{"name": "http", "containerPort": 8090, "protocol": "TCP"}],
                        "securityContext": _container_security(),
                        "resources": {
                            "requests": {"cpu": "25m", "memory": "32Mi"},
                            "limits": {"cpu": "250m", "memory": "128Mi"},
                        },
                        "readinessProbe": {
                            "httpGet": {"path": "/healthz", "port": "http"},
                            "periodSeconds": 10,
                            "failureThreshold": 3,
                            "timeoutSeconds": 1,
                        },
                        "livenessProbe": {
                            "httpGet": {"path": "/healthz", "port": "http"},
                            "periodSeconds": 20,
                            "failureThreshold": 3,
                            "timeoutSeconds": 1,
                        },
                        "volumeMounts": [{
                            "name": "kube-api-access",
                            "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount",
                            "readOnly": True,
                        }],
                    }],
                    "volumes": [token_volume],
                },
            },
        },
    }
    service = {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": _metadata(adapter_name, args.namespace, labels),
        "spec": {
            "type": "ClusterIP",
            "selector": labels,
            "ports": [{"name": "http", "port": 8090, "targetPort": "http", "protocol": "TCP"}],
        },
    }
    return _resource_list([account, role, binding, adapter, service])


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


def writer_lock_probe_resources(args: argparse.Namespace) -> dict:
    _report, identity, identity_sha256 = validate_report(args)
    args.hold_seconds = getattr(args, "hold_seconds", 0)
    active_phases = {
        "old-writer-active", "candidate-writer-active", "rollback-writer-active",
    }
    released_phases = {
        "replacement-writer-released", "old-writer-released",
        "candidate-writer-released", "rollback-writer-released",
    }
    if args.expect == "contended" and args.phase not in active_phases:
        raise RenderError("contended probes require an active-writer phase")
    if args.expect == "available" and args.phase not in {
        "destination-pre-replacement", *released_phases,
    }:
        raise RenderError("available probes require a destination or released-writer phase")
    if args.expect == "observe" and args.phase not in {
        "candidate-writer-active", "rollback-writer-active",
    }:
        raise RenderError("observe probes require a guarded-upgrade active phase")
    if args.phase == "destination-pre-replacement":
        if args.expect != "available" or args.scenario_kind not in {"controlled-rescheduling", "node-loss"}:
            raise RenderError("destination pre-replacement probes require available rescheduling or node-loss evidence")
        if args.pod_uid is not None:
            raise RenderError("destination pre-replacement probes must not claim a replacement Pod UID")
        if args.hold_seconds < 60:
            raise RenderError("destination pre-replacement probes must hold the attachment for at least 60 seconds")
    elif not args.pod_uid:
        raise RenderError("active and released-replacement probes require a Pod UID")
    elif args.hold_seconds:
        raise RenderError("only destination pre-replacement probes may hold the attachment")
    labels = {
        "app.kubernetes.io/name": args.name,
        "app.kubernetes.io/component": "writer-lock-probe",
    }
    suffix_seed = json.dumps(
        {
            "scenario": args.scenario_id,
            "phase": args.phase,
            "expect": args.expect,
            "storage": identity_sha256,
            "pod": args.pod_uid or "destination-pre-replacement",
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    suffix = f"writer-lock-{hashlib.sha256(suffix_seed.encode()).hexdigest()[:12]}"
    prefix = args.name[: 62 - len(suffix)].rstrip("-")
    job_name = f"{prefix}-{suffix}"
    annotations = {
        "nct.openai.com/scenario-id": args.scenario_id,
        "nct.openai.com/scenario-kind": args.scenario_kind,
        "nct.openai.com/expected-lock-state": args.expect,
        "nct.openai.com/pvc-uid": args.pvc_uid,
        "nct.openai.com/bound-volume-uid": args.bound_volume_uid,
        "nct.openai.com/storage-evidence-digest": args.storage_report_digest,
        "nct.openai.com/storage-identity-sha256": identity_sha256,
    }
    probe_args = [
        "--expect", args.expect,
        "--scenario-id", args.scenario_id,
        "--scenario-kind", args.scenario_kind,
        "--phase", args.phase,
        "--image", args.image,
        "--application-version", args.application_version,
        "--build-id", args.build_id,
        "--deployment-uid", args.deployment_uid,
        "--deployment-generation", str(args.deployment_generation),
        "--node-uid", args.node_uid,
        "--storage-attachment-identity", args.storage_attachment_identity,
        "--pvc-uid", args.pvc_uid,
        "--bound-volume-uid", args.bound_volume_uid,
        "--qualification-report-digest", args.storage_report_digest,
        "--receipt-path", "/tmp/nct-writer-lock-receipt.json",
    ]
    if args.pod_uid:
        probe_args.extend(["--pod-uid", args.pod_uid])
    if args.hold_seconds:
        probe_args.extend(["--hold-seconds", str(args.hold_seconds)])
    job = {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": _metadata(job_name, args.namespace, labels, annotations),
        "spec": {
            "backoffLimit": 0,
            "activeDeadlineSeconds": args.hold_seconds + 60,
            "ttlSecondsAfterFinished": 86400,
            "template": {
                "metadata": {"labels": labels, "annotations": annotations},
                "spec": {
                    "serviceAccountName": f"{args.name}-runtime",
                    "automountServiceAccountToken": False,
                    "restartPolicy": "Never",
                    "nodeName": args.node_name,
                    "terminationGracePeriodSeconds": 5,
                    "securityContext": _pod_security(),
                    "containers": [{
                        "name": "probe-writer-lock",
                        "image": args.image,
                        "imagePullPolicy": "IfNotPresent",
                        "command": ["python", "/opt/nct/tools/probe_nct_writer_lock.py"],
                        "args": probe_args,
                        "terminationMessagePath": "/tmp/nct-writer-lock-receipt.json",
                        "terminationMessagePolicy": "File",
                        "securityContext": _container_security(),
                        "resources": {
                            "requests": {"cpu": "25m", "memory": "32Mi"},
                            "limits": {"cpu": "250m", "memory": "128Mi"},
                        },
                        "volumeMounts": [
                            {"name": "data", "mountPath": "/data"},
                            {"name": "tmp", "mountPath": "/tmp"},
                        ],
                    }],
                    "volumes": [
                        {"name": "data", "persistentVolumeClaim": {"claimName": args.pvc_name}},
                        {"name": "tmp", "emptyDir": {"sizeLimit": "16Mi"}},
                    ],
                },
            },
        },
    }
    return _resource_list([_service_account(args), job])


def failure_snapshot_resources(args: argparse.Namespace) -> dict:
    _report, _identity, identity_sha256 = validate_report(args)
    restore_receipt = _read_report(args.gate4a_restore_receipt)
    if restore_receipt.get("status") != "restore_verification_passed":
        raise RenderError("Gate 4A restore receipt is not a passing receipt")
    labels = {
        "app.kubernetes.io/name": args.name,
        "app.kubernetes.io/component": "failure-evidence",
    }
    suffix_seed = json.dumps(
        {
            "scenario": args.scenario_id,
            "phase": args.phase,
            "mode": args.mode,
            "pod": args.pod_uid,
            "restart": args.container_restart_count,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    suffix = f"failure-evidence-{hashlib.sha256(suffix_seed.encode()).hexdigest()[:10]}"
    prefix = args.name[: 62 - len(suffix)].rstrip("-")
    job_name = f"{prefix}-{suffix}"
    receipt_name = f"{prefix}-{hashlib.sha256((suffix_seed + '-restore').encode()).hexdigest()[:10]}"
    annotations = {
        "nct.openai.com/scenario-id": args.scenario_id,
        "nct.openai.com/scenario-kind": args.scenario_kind,
        "nct.openai.com/evidence-mode": args.mode,
        "nct.openai.com/evidence-phase": args.phase,
        "nct.openai.com/pvc-uid": args.pvc_uid,
        "nct.openai.com/bound-volume-uid": args.bound_volume_uid,
        "nct.openai.com/storage-evidence-digest": args.storage_report_digest,
        "nct.openai.com/storage-identity-sha256": identity_sha256,
    }
    command_args = [
        "snapshot", "--mode", args.mode, "--phase", args.phase,
        "--data-root", "/data", "--scenario-id", args.scenario_id,
        "--scenario-kind", args.scenario_kind, "--image", args.image,
        "--application-version", args.application_version, "--build-id", args.build_id,
        "--deployment-uid", args.deployment_uid,
        "--deployment-generation", str(args.deployment_generation),
        "--pod-uid", args.pod_uid,
        "--container-restart-count", str(args.container_restart_count),
        "--node-uid", args.node_uid,
        "--storage-attachment-identity", args.storage_attachment_identity,
        "--pvc-uid", args.pvc_uid, "--bound-volume-uid", args.bound_volume_uid,
        "--qualification-report-digest", args.storage_report_digest,
        "--gate4a-restore-receipt", "/run/nct-gate4a/restore.json",
        "--validation-root", "/tmp", "--max-files", str(args.max_files),
        "--max-bytes", str(args.max_bytes), "--max-seconds", str(args.max_seconds),
        "--output", "/tmp/nct-gate4b-snapshot.json",
    ]
    for job_id in args.tracked_job_id:
        command_args.extend(("--tracked-job-id", job_id))
    for intent_id in args.tracked_intent_id:
        command_args.extend(("--tracked-intent-id", intent_id))
    for transition in args.health_transition:
        command_args.extend(("--health-transition", transition))
    job = {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": _metadata(job_name, args.namespace, labels, annotations),
        "spec": {
            "backoffLimit": 0,
            "activeDeadlineSeconds": args.max_seconds + 30,
            "ttlSecondsAfterFinished": 86400,
            "template": {
                "metadata": {"labels": labels, "annotations": annotations},
                "spec": {
                    "serviceAccountName": f"{args.name}-runtime",
                    "automountServiceAccountToken": False,
                    "restartPolicy": "Never",
                    "nodeName": args.node_name,
                    "terminationGracePeriodSeconds": 10,
                    "securityContext": _pod_security(),
                    "containers": [{
                        "name": "record-failure-evidence",
                        "image": args.image,
                        "imagePullPolicy": "IfNotPresent",
                        "command": ["python", "/opt/nct/tools/nct_kubernetes_failure_evidence.py"],
                        "args": command_args,
                        "securityContext": _container_security(),
                        "resources": {
                            "requests": {"cpu": "50m", "memory": "128Mi", "ephemeral-storage": args.validation_copy_size},
                            "limits": {"cpu": "1", "memory": "512Mi", "ephemeral-storage": args.validation_copy_size},
                        },
                        "volumeMounts": [
                            {"name": "data", "mountPath": "/data"},
                            {"name": "tmp", "mountPath": "/tmp"},
                            {"name": "gate4a-restore", "mountPath": "/run/nct-gate4a", "readOnly": True},
                        ],
                    }],
                    "volumes": [
                        {"name": "data", "persistentVolumeClaim": {"claimName": args.pvc_name}},
                        {"name": "tmp", "emptyDir": {"sizeLimit": args.validation_copy_size}},
                        {"name": "gate4a-restore", "configMap": {"name": receipt_name}},
                    ],
                },
            },
        },
    }
    receipt_config = {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": _metadata(receipt_name, args.namespace, labels, annotations),
        "immutable": True,
        "data": {"restore.json": json.dumps(restore_receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=True)},
    }
    return _resource_list([_service_account(args), receipt_config, job])


def upgrade_inspection_resources(args: argparse.Namespace) -> dict:
    _report, _identity, identity_sha256 = validate_report(args)
    if not DIGEST_RE.fullmatch(args.contract_digest):
        raise RenderError("schema contract digest must be 64 lowercase hexadecimal characters")
    labels = {
        "app.kubernetes.io/name": args.name,
        "app.kubernetes.io/component": "upgrade-inspection",
    }
    suffix_seed = json.dumps(
        {
            "scenario": args.scenario_id,
            "phase": args.phase,
            "image": args.image,
            "pvc_uid": args.pvc_uid,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    suffix = f"upgrade-inspect-{hashlib.sha256(suffix_seed.encode()).hexdigest()[:10]}"
    prefix = args.name[: 62 - len(suffix)].rstrip("-")
    job_name = f"{prefix}-{suffix}"
    annotations = {
        "nct.openai.com/scenario-id": args.scenario_id,
        "nct.openai.com/upgrade-phase": args.phase,
        "nct.openai.com/schema-contract-digest": args.contract_digest,
        "nct.openai.com/pvc-uid": args.pvc_uid,
        "nct.openai.com/bound-volume-uid": args.bound_volume_uid,
        "nct.openai.com/storage-evidence-digest": args.storage_report_digest,
        "nct.openai.com/storage-identity-sha256": identity_sha256,
    }
    command_args = [
        "inspect", "--data-root", "/data", "--scenario-id", args.scenario_id,
        "--phase", args.phase, "--image", args.image,
        "--runtime-image-id", args.runtime_image_id,
        "--contract-digest", args.contract_digest,
        "--deployment-uid", args.deployment_uid,
        "--deployment-generation", str(args.deployment_generation),
        "--pod-uid", args.pod_uid, "--node-uid", args.node_uid,
        "--storage-attachment-identity", args.storage_attachment_identity,
        "--pvc-uid", args.pvc_uid, "--bound-volume-uid", args.bound_volume_uid,
        "--qualification-report-digest", args.storage_report_digest,
        "--validation-root", "/validation",
        "--max-validation-bytes", str(args.max_validation_bytes),
        "--max-files", str(args.max_files), "--max-bytes", str(args.max_bytes),
        "--max-seconds", str(args.max_seconds),
        "--output", "/tmp/nct-gate4c-inspection.json",
    ]
    job = {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": _metadata(job_name, args.namespace, labels, annotations),
        "spec": {
            "backoffLimit": 0,
            "activeDeadlineSeconds": args.max_seconds + 30,
            "ttlSecondsAfterFinished": 86400,
            "template": {
                "metadata": {"labels": labels, "annotations": annotations},
                "spec": {
                    "serviceAccountName": f"{args.name}-runtime",
                    "automountServiceAccountToken": False,
                    "restartPolicy": "Never",
                    "nodeName": args.node_name,
                    "terminationGracePeriodSeconds": 10,
                    "securityContext": _pod_security(),
                    "containers": [{
                        "name": "inspect-upgrade-data",
                        "image": args.image,
                        "imagePullPolicy": "IfNotPresent",
                        "command": ["python", "/opt/nct/tools/nct_kubernetes_upgrade.py"],
                        "args": command_args,
                        "terminationMessagePath": "/tmp/nct-gate4c-inspection.json",
                        "terminationMessagePolicy": "File",
                        "securityContext": _container_security(),
                        "resources": {
                            "requests": {"cpu": "50m", "memory": "128Mi", "ephemeral-storage": args.validation_copy_size},
                            "limits": {"cpu": "1", "memory": "512Mi", "ephemeral-storage": args.validation_copy_size},
                        },
                        "volumeMounts": [
                            {"name": "data", "mountPath": "/data"},
                            {"name": "tmp", "mountPath": "/tmp"},
                            {"name": "validation", "mountPath": "/validation"},
                        ],
                    }],
                    "volumes": [
                        {"name": "data", "persistentVolumeClaim": {"claimName": args.pvc_name}},
                        {"name": "tmp", "emptyDir": {"sizeLimit": "16Mi"}},
                        {"name": "validation", "emptyDir": {"sizeLimit": args.validation_copy_size}},
                    ],
                },
            },
        },
    }
    return _resource_list([_service_account(args), job])


def upgrade_contract_resources(args: argparse.Namespace) -> dict:
    labels = {
        "app.kubernetes.io/name": args.name,
        "app.kubernetes.io/component": "upgrade-contract",
    }
    digest = hashlib.sha256(args.image.encode()).hexdigest()[:12]
    suffix = f"image-contract-{digest}"
    prefix = args.name[: 62 - len(suffix)].rstrip("-")
    job_name = f"{prefix}-{suffix}"
    job = {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": _metadata(job_name, args.namespace, labels, {
            "nct.openai.com/image": args.image,
        }),
        "spec": {
            "backoffLimit": 0,
            "activeDeadlineSeconds": 60,
            "ttlSecondsAfterFinished": 86400,
            "template": {
                "metadata": {"labels": labels},
                "spec": {
                    "serviceAccountName": f"{args.name}-runtime",
                    "automountServiceAccountToken": False,
                    "restartPolicy": "Never",
                    "terminationGracePeriodSeconds": 5,
                    "securityContext": _pod_security(),
                    "containers": [{
                        "name": "read-image-contract",
                        "image": args.image,
                        "imagePullPolicy": "IfNotPresent",
                        "command": ["python", "/opt/nct/tools/nct_kubernetes_upgrade.py"],
                        "args": ["contract", "--output", "/tmp/nct-image-contract.json"],
                        "terminationMessagePath": "/tmp/nct-image-contract.json",
                        "terminationMessagePolicy": "File",
                        "securityContext": _container_security(),
                        "resources": {
                            "requests": {"cpu": "25m", "memory": "32Mi"},
                            "limits": {"cpu": "250m", "memory": "128Mi"},
                        },
                        "volumeMounts": [{"name": "tmp", "mountPath": "/tmp"}],
                    }],
                    "volumes": [{"name": "tmp", "emptyDir": {"sizeLimit": "8Mi"}}],
                },
            },
        },
    }
    return _resource_list([_service_account(args), job])


def upgrade_backup_manifest_resources(args: argparse.Namespace) -> dict:
    _report, identity, identity_sha256 = validate_report(args)
    labels = {"app.kubernetes.io/name": args.name, "app.kubernetes.io/component": "upgrade-backup-manifest"}
    job_name = f"{args.name[:40].rstrip('-')}-backup-manifest-{hashlib.sha256(args.backup_id.encode()).hexdigest()[:10]}"
    annotations = {
        "nct.openai.com/storage-evidence-digest": args.storage_report_digest,
        "nct.openai.com/storage-identity-sha256": identity_sha256,
        "nct.openai.com/backup-id": args.backup_id,
    }
    command = (
        "from pathlib import Path; import os,sys; "
        "p=Path('/backup')/sys.argv[1]/'manifest.json'; "
        "d=p.read_bytes(); "
        "(0 < len(d) <= 134217728) or (_ for _ in ()).throw(ValueError('manifest size')); "
        "sys.stdout.buffer.write(d)"
    )
    job = {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": _metadata(job_name, args.namespace, labels, annotations),
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 60, "ttlSecondsAfterFinished": 86400,
                 "template": {"metadata": {"labels": labels, "annotations": annotations},
                              "spec": {"serviceAccountName": f"{args.name}-runtime",
                                       "automountServiceAccountToken": False,
                                       "restartPolicy": "Never", "terminationGracePeriodSeconds": 5,
                                       "securityContext": _pod_security(),
                                       "containers": [{"name": "read-backup-manifest", "image": args.image,
                                                       "imagePullPolicy": "IfNotPresent",
                                                       "command": ["python", "-c", command, args.backup_id],
                                                       "securityContext": _container_security(),
                                                       "resources": {"requests": {"cpu": "25m", "memory": "32Mi"},
                                                                     "limits": {"cpu": "250m", "memory": "128Mi"}},
                                                       "volumeMounts": [{"name": "backup", "mountPath": "/backup", "readOnly": True}]}],
                                       "volumes": [{"name": "backup", "persistentVolumeClaim": {"claimName": args.pvc_name, "readOnly": True}}]}}},
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
    if getattr(args, "enable_kubernetes_health", False):
        env.extend([
            {"name": "NCT_KUBERNETES_HEALTH_ENABLED", "value": "1"},
            {"name": "NCT_KUBERNETES_NAME", "value": args.name},
            {"name": "NCT_KUBERNETES_NAMESPACE", "value": args.namespace},
        ])
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
                    "tolerations": [
                        {
                            "key": "node.kubernetes.io/not-ready",
                            "operator": "Exists",
                            "effect": "NoExecute",
                        },
                        {
                            "key": "node.kubernetes.io/unreachable",
                            "operator": "Exists",
                            "effect": "NoExecute",
                        },
                    ],
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
    if hasattr(args, "pvc_name"):
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
    if getattr(args, "scenario_id", None) is not None:
        if not SCENARIO_RE.fullmatch(args.scenario_id):
            raise RenderError("scenario ID must be 8-80 lowercase letters, digits, or hyphens")
        args.deployment_uid = _immutable_id(args.deployment_uid, "Deployment UID")
        if args.pod_uid is not None:
            args.pod_uid = _immutable_id(args.pod_uid, "Pod UID")
        elif getattr(args, "phase", None) != "destination-pre-replacement":
            raise RenderError("Pod UID is required outside the destination pre-replacement phase")
        args.node_uid = _immutable_id(args.node_uid, "Node UID")
        args.node_name = _dns(args.node_name, "node name")
        if args.deployment_generation < 1:
            raise RenderError("Deployment generation must be positive")
        for attribute, label in (
            ("application_version", "application version"),
            ("build_id", "build ID"),
            ("storage_attachment_identity", "storage attachment identity"),
        ):
            if not hasattr(args, attribute):
                continue
            value = getattr(args, attribute)
            if not value or len(value) > MAX_IMAGE_CHARS or any(ord(char) < 32 for char in value):
                raise RenderError(f"{label} is invalid or too large")
        if getattr(args, "container_restart_count", 0) < 0:
            raise RenderError("container restart count must not be negative")
        for attribute, label in (
            ("tracked_job_id", "tracked job ID"),
            ("tracked_intent_id", "tracked admission intent ID"),
            ("health_transition", "health transition"),
        ):
            values = getattr(args, attribute, [])
            if len(values) > 100 or len(values) != len(set(values)):
                raise RenderError(f"{label} values must be unique and bounded")
            if any(not value or len(value) > MAX_IMAGE_CHARS or any(ord(char) < 32 for char in value) for value in values):
                raise RenderError(f"{label} is invalid or too large")
        restore_receipt = getattr(args, "gate4a_restore_receipt", None)
        if restore_receipt is not None and not isinstance(restore_receipt, Path):
            raise RenderError("Gate 4A restore receipt path is invalid")
        if getattr(args, "max_files", 1) < 1 or getattr(args, "max_files", 1) > 1_000_000:
            raise RenderError("max files is outside the enforced limit")
        if getattr(args, "max_bytes", 1) < 1 or getattr(args, "max_bytes", 1) > 4 * 1024**4:
            raise RenderError("max bytes is outside the enforced limit")
        if getattr(args, "max_validation_bytes", 1) < 1 or getattr(args, "max_validation_bytes", 1) > 4 * 1024**4:
            raise RenderError("validation-copy bytes are outside the enforced limit")
        if getattr(args, "max_seconds", 1) < 1 or getattr(args, "max_seconds", 1) > 1800:
            raise RenderError("max seconds is outside the enforced limit")
        if getattr(args, "validation_copy_size", None) is not None:
            args.validation_copy_size = _size(args.validation_copy_size)
    if getattr(args, "backup_id", None) is not None and not BACKUP_ID_RE.fullmatch(args.backup_id):
        raise RenderError("backup ID must be 8-64 lowercase letters, digits, or hyphens")
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
    deployment.add_argument("--enable-kubernetes-health", action="store_true")
    health_adapter = subparsers.add_parser("health-adapter")
    health_adapter.add_argument("--name", default="nct-analysis")
    health_adapter.add_argument("--namespace", required=True)
    health_adapter.add_argument("--image", required=True)
    health_adapter.add_argument("--enable-metrics", action="store_true")
    health_adapter.add_argument("--output", type=Path, required=True)
    health_adapter.add_argument("--overwrite", action="store_true")
    lock_probe = subparsers.add_parser("writer-lock-probe")
    add_common(lock_probe, image=True, identity=True)
    lock_probe.add_argument("--storage-report", type=Path, required=True)
    lock_probe.add_argument("--storage-report-digest", required=True)
    lock_probe.add_argument("--expect", choices=("contended", "available", "observe"), required=True)
    lock_probe.add_argument("--scenario-id", required=True)
    lock_probe.add_argument(
        "--scenario-kind",
        choices=("forced-termination", "recreate-replacement", "controlled-rescheduling", "node-loss", "guarded-upgrade"),
        required=True,
    )
    lock_probe.add_argument(
        "--phase",
        choices=("old-writer-active", "destination-pre-replacement", "replacement-writer-released", "old-writer-released", "candidate-writer-active", "candidate-writer-released", "rollback-writer-active", "rollback-writer-released"),
        required=True,
    )
    lock_probe.add_argument("--application-version", required=True)
    lock_probe.add_argument("--build-id", required=True)
    lock_probe.add_argument("--deployment-uid", required=True)
    lock_probe.add_argument("--deployment-generation", type=int, required=True)
    lock_probe.add_argument("--pod-uid")
    lock_probe.add_argument("--node-name", required=True)
    lock_probe.add_argument("--node-uid", required=True)
    lock_probe.add_argument("--storage-attachment-identity", required=True)
    lock_probe.add_argument("--hold-seconds", type=int, default=0)
    snapshot = subparsers.add_parser("failure-snapshot")
    add_common(snapshot, image=True, identity=True)
    snapshot.add_argument("--storage-report", type=Path, required=True)
    snapshot.add_argument("--storage-report-digest", required=True)
    snapshot.add_argument("--mode", choices=("runtime", "cold"), required=True)
    snapshot.add_argument("--phase", choices=("before-failure", "after-restart", "after-retry"), required=True)
    snapshot.add_argument("--scenario-id", required=True)
    snapshot.add_argument(
        "--scenario-kind",
        choices=("forced-termination", "recreate-replacement", "controlled-rescheduling", "node-loss"),
        required=True,
    )
    snapshot.add_argument("--application-version", required=True)
    snapshot.add_argument("--build-id", required=True)
    snapshot.add_argument("--deployment-uid", required=True)
    snapshot.add_argument("--deployment-generation", type=int, required=True)
    snapshot.add_argument("--pod-uid", required=True)
    snapshot.add_argument("--container-restart-count", type=int, required=True)
    snapshot.add_argument("--node-name", required=True)
    snapshot.add_argument("--node-uid", required=True)
    snapshot.add_argument("--storage-attachment-identity", required=True)
    snapshot.add_argument("--gate4a-restore-receipt", type=Path, required=True)
    snapshot.add_argument("--validation-copy-size", default="20Gi")
    snapshot.add_argument("--max-files", type=int, default=1_000_000)
    snapshot.add_argument("--max-bytes", type=int, default=4 * 1024**4)
    snapshot.add_argument("--max-seconds", type=int, default=300)
    snapshot.add_argument("--tracked-job-id", action="append", default=[])
    snapshot.add_argument("--tracked-intent-id", action="append", default=[])
    snapshot.add_argument("--health-transition", action="append", default=[])
    inspection = subparsers.add_parser("upgrade-inspection")
    add_common(inspection, image=True, identity=True)
    inspection.add_argument("--storage-report", type=Path, required=True)
    inspection.add_argument("--storage-report-digest", required=True)
    inspection.add_argument("--scenario-id", required=True)
    inspection.add_argument(
        "--phase", choices=("before-upgrade", "after-upgrade", "failed-candidate", "after-rollback"), required=True,
    )
    inspection.add_argument("--runtime-image-id", required=True)
    inspection.add_argument("--contract-digest", required=True)
    inspection.add_argument("--deployment-uid", required=True)
    inspection.add_argument("--deployment-generation", type=int, required=True)
    inspection.add_argument("--pod-uid", required=True)
    inspection.add_argument("--node-name", required=True)
    inspection.add_argument("--node-uid", required=True)
    inspection.add_argument("--storage-attachment-identity", required=True)
    inspection.add_argument("--max-files", type=int, default=1_000_000)
    inspection.add_argument("--max-bytes", type=int, default=4 * 1024**4)
    inspection.add_argument("--validation-copy-size", default="20Gi")
    inspection.add_argument("--max-validation-bytes", type=int, default=20 * 1024**3)
    inspection.add_argument("--max-seconds", type=int, default=300)
    contract = subparsers.add_parser("upgrade-contract")
    contract.add_argument("--name", default="nct-analysis")
    contract.add_argument("--namespace", required=True)
    contract.add_argument("--image", required=True)
    contract.add_argument("--output", type=Path, required=True)
    contract.add_argument("--overwrite", action="store_true")
    manifest = subparsers.add_parser("upgrade-backup-manifest")
    add_common(manifest, image=True, identity=True)
    manifest.add_argument("--storage-report", type=Path, required=True)
    manifest.add_argument("--storage-report-digest", required=True)
    manifest.add_argument("--backup-id", required=True)
    return parser


def main() -> int:
    try:
        args = _parser().parse_args()
        _validate_args(args)
        if args.command == "claim":
            value = claim_resources(args)
        elif args.command == "qualification":
            value = qualification_resources(args)
        elif args.command == "deployment":
            value = deployment_resources(args)
        elif args.command == "health-adapter":
            value = health_adapter_resources(args)
        elif args.command == "writer-lock-probe":
            value = writer_lock_probe_resources(args)
        elif args.command == "upgrade-inspection":
            value = upgrade_inspection_resources(args)
        elif args.command == "upgrade-contract":
            value = upgrade_contract_resources(args)
        elif args.command == "upgrade-backup-manifest":
            value = upgrade_backup_manifest_resources(args)
        else:
            value = failure_snapshot_resources(args)
        _write_output(args.output, value, args.overwrite)
    except RenderError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
