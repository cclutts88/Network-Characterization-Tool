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
import render_kubernetes_single_replica as renderer  # noqa: E402
import nct_kubernetes_recovery as recovery  # noqa: E402


def args(tmp_path: Path, **changes) -> argparse.Namespace:
    values = {
        "name": "nct-analysis",
        "namespace": "nct",
        "image": "registry.example/nct@sha256:" + "a" * 64,
        "pvc_name": "nct-data",
        "storage_class": "approved-rwo",
        "storage_size": "20Gi",
        "pvc_uid": "11111111-2222-4333-8444-555555555555",
        "bound_volume_uid": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        "output": tmp_path / "output.json",
        "overwrite": False,
        "bootstrap_secret": None,
        "storage_report": tmp_path / "report.json",
        "storage_report_digest": "",
    }
    values.update(changes)
    value = argparse.Namespace(**values)
    renderer._validate_args(value)
    return value


def passing_report(value: argparse.Namespace) -> dict:
    identity = renderer.storage_identity(value)
    source = SCRIPTS / "qualify_kubernetes_storage.py"
    report = {
        "schema_version": qualifier.REPORT_SCHEMA_VERSION,
        "tool": {
            "version": qualifier.TOOL_VERSION,
            "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        },
        "declared": {
            "storage_identity": identity,
            "storage_identity_sha256": hashlib.sha256(identity.encode()).hexdigest(),
            "accepted": True,
        },
        "measured": {
            "executor_uid": renderer.RUN_AS_UID,
            "executor_gid": renderer.RUN_AS_GID,
        },
        "checks": [
            {"id": check, "status": "pass", "detail": "passed", "duration_seconds": 0.01}
            for check in sorted(renderer.REQUIRED_CHECKS)
        ],
        "cleanup": {
            "id": "cleanup",
            "status": "pass",
            "detail": "removed",
            "duration_seconds": 0.01,
        },
        "limitations": ["bounded exact-volume evidence only"],
    }
    return qualifier._finalize(report)


def write_report(value: argparse.Namespace, report: dict | None = None) -> dict:
    report = report or passing_report(value)
    value.storage_report.write_text(json.dumps(report), encoding="utf-8")
    value.storage_report_digest = report["attestation"]["digest"]
    return report


def write_restore_receipt(value: argparse.Namespace) -> Path:
    path = value.output.parent / "gate4a-restore-receipt.json"
    body = {
        "schema_version": recovery.SCHEMA_VERSION,
        "status": "restore_verification_passed",
        "backup_id": "backup-20261012",
        "source_image": value.image,
        "source_application_version": "0.14.0-dev",
        "source_build_id": "build-123",
        "manifest_sha256": "1" * 64,
        "backup_receipt_sha256": "4" * 64,
        "archive_sha256": "2" * 64,
        "inventory_root_sha256": "3" * 64,
        "target_qualification_report_digest": value.storage_report_digest,
        "source_qualification_report_digest": "5" * 64,
        "backup_qualification_report_digest": "6" * 64,
        "source_and_backup_preserved": True,
        "source_storage_identity": {"pvc_uid": "source-pvc-12345678", "bound_volume_uid": "source-pv-12345678"},
        "backup_storage_identity": {"pvc_uid": "backup-pvc-12345678", "bound_volume_uid": "backup-pv-12345678"},
        "target_storage_identity": {
            "pvc_uid": value.pvc_uid,
            "bound_volume_uid": value.bound_volume_uid,
        },
    }
    body["receipt_sha256"] = recovery._digest(body)
    path.write_text(json.dumps(body), encoding="utf-8")
    return path


def items_by_kind(document: dict) -> dict[str, dict]:
    return {item["kind"]: item for item in document["items"]}


def test_qualification_job_is_bounded_unprivileged_and_exact(tmp_path: Path) -> None:
    value = args(tmp_path)
    claim_document = renderer.claim_resources(value)
    document = renderer.qualification_resources(value)
    items = items_by_kind(document)
    account = items["ServiceAccount"]
    claim = items_by_kind(claim_document)["PersistentVolumeClaim"]
    job = items["Job"]
    pod = job["spec"]["template"]["spec"]
    container = pod["containers"][0]

    assert account["automountServiceAccountToken"] is False
    assert "PersistentVolumeClaim" not in items
    assert claim["spec"] == {
        "accessModes": ["ReadWriteOnce"],
        "volumeMode": "Filesystem",
        "storageClassName": "approved-rwo",
        "resources": {"requests": {"storage": "20Gi"}},
    }
    assert job["spec"]["backoffLimit"] == 0
    assert job["spec"]["activeDeadlineSeconds"] == 60
    assert pod["restartPolicy"] == "Never"
    assert pod["automountServiceAccountToken"] is False
    assert pod["securityContext"]["runAsUser"] == renderer.RUN_AS_UID
    assert container["securityContext"]["capabilities"] == {"drop": ["ALL"]}
    assert container["securityContext"]["readOnlyRootFilesystem"] is True
    assert container["image"].endswith("@sha256:" + "a" * 64)
    assert container["args"][-1] == renderer.storage_identity(value)
    assert container["resources"]["limits"] == {"cpu": "500m", "memory": "256Mi"}
    assert job["metadata"]["name"].endswith(renderer._identity_sha256(renderer.storage_identity(value))[:12])
    assert job["metadata"]["annotations"]["nct.openai.com/pvc-uid"] == value.pvc_uid
    assert job["metadata"]["annotations"]["nct.openai.com/bound-volume-uid"] == value.bound_volume_uid


def test_deployment_is_one_analysis_only_replica_and_uses_exact_report(tmp_path: Path) -> None:
    value = args(tmp_path, bootstrap_secret="nct-bootstrap")
    report = write_report(value)
    document = renderer.deployment_resources(value)
    items = items_by_kind(document)
    deployment = items["Deployment"]
    pod = deployment["spec"]["template"]
    pod_spec = pod["spec"]
    container = pod_spec["containers"][0]
    env = {item["name"]: item for item in container["env"]}

    assert deployment["spec"]["replicas"] == 1
    assert deployment["spec"]["strategy"] == {"type": "Recreate"}
    assert pod_spec["tolerations"] == [
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
    ]
    assert pod_spec["automountServiceAccountToken"] is False
    assert pod_spec["securityContext"]["runAsUser"] == renderer.RUN_AS_UID
    assert pod_spec["securityContext"]["runAsGroup"] == renderer.RUN_AS_GID
    assert container["securityContext"]["capabilities"] == {"drop": ["ALL"]}
    assert "add" not in container["securityContext"]["capabilities"]
    assert container["securityContext"]["readOnlyRootFilesystem"] is True
    assert env["NCT_AUTH_MODE"]["value"] == "local"
    assert env["NCT_COOKIE_SECURE"]["value"] == "1"
    assert env["NCT_ACTIVE_COLLECTION_MODE"]["value"] == "disabled"
    assert env["NCT_BOOTSTRAP_ADMIN"]["valueFrom"]["secretKeyRef"] == {
        "name": "nct-bootstrap", "key": "username",
    }
    assert env["NCT_BOOTSTRAP_PASSWORD_FILE"]["value"].endswith("/password")
    assert all(item["kind"] != "Secret" for item in document["items"])
    assert all(item["kind"] != "PersistentVolumeClaim" for item in document["items"])
    assert {probe for probe in ("startupProbe", "readinessProbe", "livenessProbe")} <= set(container)
    assert pod["metadata"]["annotations"]["nct.openai.com/storage-evidence-digest"] == report["attestation"]["digest"]
    assert pod["metadata"]["annotations"]["nct.openai.com/pvc-uid"] == value.pvc_uid
    assert pod["metadata"]["annotations"]["nct.openai.com/bound-volume-uid"] == value.bound_volume_uid
    assert items["Service"]["spec"]["type"] == "ClusterIP"


def test_optional_health_adapter_is_isolated_and_least_privilege(tmp_path: Path) -> None:
    value = argparse.Namespace(
        name="nct-analysis",
        namespace="nct",
        image="registry.example/nct@sha256:" + "a" * 64,
        enable_metrics=False,
        output=tmp_path / "health-adapter.json",
        overwrite=False,
    )
    renderer._validate_args(value)
    document = renderer.health_adapter_resources(value)
    items = {item["kind"]: item for item in document["items"] if item["kind"] != "Service"}
    account = items["ServiceAccount"]
    role = items["Role"]
    binding = items["RoleBinding"]
    deployment = items["Deployment"]
    pod = deployment["spec"]["template"]["spec"]
    container = pod["containers"][0]

    assert account["metadata"]["name"] == "nct-analysis-health-reader"
    assert account["automountServiceAccountToken"] is False
    assert binding["roleRef"] == {
        "apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "nct-analysis-health-read",
    }
    assert role["rules"] == [
        {"apiGroups": ["apps"], "resources": ["deployments"], "resourceNames": ["nct-analysis"], "verbs": ["get"]},
        {"apiGroups": ["apps"], "resources": ["replicasets"], "verbs": ["list"]},
        {"apiGroups": [""], "resources": ["pods"], "verbs": ["list"]},
    ]
    assert all(set(rule["verbs"]) <= {"get", "list"} for rule in role["rules"])
    assert all("secrets" not in rule["resources"] and "configmaps" not in rule["resources"] for rule in role["rules"])
    assert pod["serviceAccountName"] == "nct-analysis-health-reader"
    assert pod["automountServiceAccountToken"] is False
    assert container["command"] == ["python", "/opt/nct/tools/nct_kubernetes_health_adapter.py"]
    assert container["securityContext"]["capabilities"] == {"drop": ["ALL"]}
    assert container["volumeMounts"] == [{
        "name": "kube-api-access",
        "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount",
        "readOnly": True,
    }]
    projected = pod["volumes"][0]["projected"]
    assert projected["sources"][0]["serviceAccountToken"]["expirationSeconds"] == 3600
    assert "persistentVolumeClaim" not in json.dumps(deployment)
    assert "ANALYZER_DATA_DIR" not in json.dumps(deployment)


def test_metrics_permission_is_separate_explicit_opt_in(tmp_path: Path) -> None:
    value = argparse.Namespace(
        name="nct-analysis", namespace="nct",
        image="registry.example/nct@sha256:" + "a" * 64,
        enable_metrics=True, output=tmp_path / "health-metrics.json", overwrite=False,
    )
    renderer._validate_args(value)
    document = renderer.health_adapter_resources(value)
    role = next(item for item in document["items"] if item["kind"] == "Role")
    assert role["rules"][-1] == {
        "apiGroups": ["metrics.k8s.io"], "resources": ["pods"], "verbs": ["list"],
    }


def test_nct_deployment_can_use_adapter_without_receiving_api_token(tmp_path: Path) -> None:
    value = args(tmp_path, enable_kubernetes_health=True)
    write_report(value)
    document = renderer.deployment_resources(value)
    pod = items_by_kind(document)["Deployment"]["spec"]["template"]["spec"]
    env = {item["name"]: item.get("value") for item in pod["containers"][0]["env"]}

    assert pod["serviceAccountName"] == "nct-analysis-runtime"
    assert pod["automountServiceAccountToken"] is False
    assert not any(volume["name"] == "kube-api-access" for volume in pod["volumes"])
    assert env["NCT_KUBERNETES_HEALTH_ENABLED"] == "1"
    assert env["NCT_KUBERNETES_NAME"] == "nct-analysis"
    assert env["NCT_KUBERNETES_NAMESPACE"] == "nct"


def test_upgrade_inspection_job_is_bounded_cold_and_has_no_api_access(tmp_path: Path) -> None:
    value = args(
        tmp_path,
        scenario_id="upgrade-check-20261012",
        phase="before-upgrade",
        runtime_image_id="docker-pullable://registry.example/nct@sha256:" + "a" * 64,
        contract_digest="b" * 64,
        deployment_uid="dddddddd-2222-4333-8444-555555555555",
        deployment_generation=9,
        pod_uid="eeeeeeee-2222-4333-8444-555555555555",
        node_name="worker-a.example",
        node_uid="ffffffff-2222-4333-8444-555555555555",
        storage_attachment_identity="csi-attachment-12345678",
        max_files=10_000,
        max_bytes=1024**3,
        validation_copy_size="2Gi",
        max_validation_bytes=1024**3,
        max_seconds=240,
    )
    report = write_report(value)
    document = renderer.upgrade_inspection_resources(value)
    items = items_by_kind(document)
    job = items["Job"]
    pod = job["spec"]["template"]["spec"]
    container = pod["containers"][0]

    assert pod["automountServiceAccountToken"] is False
    assert pod["nodeName"] == "worker-a.example"
    assert container["command"] == ["python", "/opt/nct/tools/nct_kubernetes_upgrade.py"]
    assert container["args"][0] == "inspect"
    assert "--contract-digest" in container["args"]
    assert container["terminationMessagePolicy"] == "File"
    assert container["securityContext"]["capabilities"] == {"drop": ["ALL"]}
    assert job["spec"]["activeDeadlineSeconds"] == 270
    assert job["metadata"]["annotations"]["nct.openai.com/storage-evidence-digest"] == report["attestation"]["digest"]
    assert all(item["kind"] not in {"Role", "RoleBinding", "Secret"} for item in document["items"])


def test_upgrade_contract_job_reads_only_the_exact_image(tmp_path: Path) -> None:
    value = argparse.Namespace(
        name="nct-analysis", namespace="nct",
        image="registry.example/nct@sha256:" + "a" * 64,
        output=tmp_path / "contract-job.json", overwrite=False,
    )
    renderer._validate_args(value)
    document = renderer.upgrade_contract_resources(value)
    items = items_by_kind(document)
    pod = items["Job"]["spec"]["template"]["spec"]
    container = pod["containers"][0]

    assert pod["automountServiceAccountToken"] is False
    assert "persistentVolumeClaim" not in json.dumps(document)
    assert container["image"] == value.image
    assert container["args"] == ["contract", "--output", "/tmp/nct-image-contract.json"]
    assert container["terminationMessagePolicy"] == "File"
    assert container["securityContext"]["capabilities"] == {"drop": ["ALL"]}


def test_upgrade_backup_manifest_job_is_read_only_bounded_and_has_no_api_access(tmp_path: Path) -> None:
    value = args(tmp_path, backup_id="backup-20261012")
    report = write_report(value)
    renderer._validate_args(value)
    document = renderer.upgrade_backup_manifest_resources(value)
    items = items_by_kind(document)
    job = items["Job"]
    pod = job["spec"]["template"]["spec"]
    container = pod["containers"][0]

    assert pod["automountServiceAccountToken"] is False
    assert container["volumeMounts"] == [{"name": "backup", "mountPath": "/backup", "readOnly": True}]
    assert pod["volumes"][0]["persistentVolumeClaim"] == {"claimName": value.pvc_name, "readOnly": True}
    assert container["command"][-1] == value.backup_id
    assert job["metadata"]["annotations"]["nct.openai.com/storage-evidence-digest"] == report["attestation"]["digest"]
    assert all(item["kind"] not in {"Role", "RoleBinding", "Secret"} for item in document["items"])


def test_writer_lock_probe_is_exact_unprivileged_and_has_no_api_access(tmp_path: Path) -> None:
    value = args(
        tmp_path,
        scenario_id="forced-stop-20261012",
        scenario_kind="forced-termination",
        expect="contended",
        phase="old-writer-active",
        application_version="0.14.0-dev",
        build_id="build-123",
        deployment_uid="dddddddd-2222-4333-8444-555555555555",
        deployment_generation=7,
        pod_uid="eeeeeeee-2222-4333-8444-555555555555",
        node_name="worker-a.example",
        node_uid="ffffffff-2222-4333-8444-555555555555",
        storage_attachment_identity="csi-attachment-12345678",
    )
    report = write_report(value)
    document = renderer.writer_lock_probe_resources(value)
    items = items_by_kind(document)
    job = items["Job"]
    pod = job["spec"]["template"]["spec"]
    container = pod["containers"][0]

    assert pod["nodeName"] == "worker-a.example"
    assert pod["automountServiceAccountToken"] is False
    assert container["image"].endswith("@sha256:" + "a" * 64)
    assert container["command"] == ["python", "/opt/nct/tools/probe_nct_writer_lock.py"]
    assert container["terminationMessagePolicy"] == "File"
    assert container["securityContext"]["capabilities"] == {"drop": ["ALL"]}
    assert "--expect" in container["args"] and "contended" in container["args"]
    assert job["metadata"]["annotations"]["nct.openai.com/storage-evidence-digest"] == report["attestation"]["digest"]
    assert all(item["kind"] not in {"Role", "RoleBinding", "Secret"} for item in document["items"])


def test_guarded_upgrade_writer_probe_can_measure_without_guessing(tmp_path: Path) -> None:
    value = args(
        tmp_path,
        scenario_id="upgrade-20261012",
        scenario_kind="guarded-upgrade",
        expect="observe",
        phase="candidate-writer-active",
        application_version="0.14.0-dev",
        build_id="build-123",
        deployment_uid="dddddddd-2222-4333-8444-555555555555",
        deployment_generation=8,
        pod_uid="eeeeeeee-2222-4333-8444-555555555555",
        node_name="worker-a.example",
        node_uid="ffffffff-2222-4333-8444-555555555555",
        storage_attachment_identity="csi-attachment-12345678",
    )
    write_report(value)

    document = renderer.writer_lock_probe_resources(value)
    container = items_by_kind(document)["Job"]["spec"]["template"]["spec"]["containers"][0]

    assert "--expect" in container["args"]
    assert "observe" in container["args"]
    assert "candidate-writer-active" in container["args"]


def test_pre_replacement_lock_probe_targets_destination_without_future_pod(tmp_path: Path) -> None:
    value = args(
        tmp_path,
        scenario_id="node-loss-20261012",
        scenario_kind="node-loss",
        expect="available",
        phase="destination-pre-replacement",
        application_version="0.14.0-dev",
        build_id="build-123",
        deployment_uid="dddddddd-2222-4333-8444-555555555555",
        deployment_generation=8,
        pod_uid=None,
        node_name="worker-b.example",
        node_uid="ffffffff-2222-4333-8444-666666666666",
        storage_attachment_identity="csi-attachment-destination",
        hold_seconds=300,
    )
    write_report(value)
    document = renderer.writer_lock_probe_resources(value)
    job = items_by_kind(document)["Job"]
    pod = job["spec"]["template"]["spec"]
    command_args = pod["containers"][0]["args"]

    assert pod["nodeName"] == "worker-b.example"
    assert "--pod-uid" not in command_args
    assert "destination-pre-replacement" in command_args
    assert "csi-attachment-destination" in command_args
    assert command_args[command_args.index("--hold-seconds") + 1] == "300"
    assert job["spec"]["activeDeadlineSeconds"] == 360


def test_failure_snapshot_is_bounded_to_exact_node_storage_and_image(tmp_path: Path) -> None:
    value = args(
        tmp_path,
        scenario_id="forced-stop-20261012",
        scenario_kind="forced-termination",
        mode="runtime",
        phase="before-failure",
        application_version="0.14.0-dev",
        build_id="build-123",
        deployment_uid="dddddddd-2222-4333-8444-555555555555",
        deployment_generation=7,
        pod_uid="eeeeeeee-2222-4333-8444-555555555555",
        container_restart_count=0,
        node_name="worker-a.example",
        node_uid="ffffffff-2222-4333-8444-555555555555",
        storage_attachment_identity="csi-attachment-12345678",
        gate4a_restore_receipt=tmp_path / "gate4a-restore-receipt.json",
        validation_copy_size="20Gi",
        max_files=1000,
        max_bytes=1024**3,
        max_seconds=300,
        tracked_job_id=["pipeline_job_running", "pipeline_job_queued"],
        tracked_intent_id=["intake_intent_12345678"],
        health_transition=["2026-10-12T00:00:00Z|readiness|ready"],
    )
    report = write_report(value)
    value.gate4a_restore_receipt = write_restore_receipt(value)
    document = renderer.failure_snapshot_resources(value)
    items = items_by_kind(document)
    job = items["Job"]
    pod = job["spec"]["template"]["spec"]
    container = pod["containers"][0]

    assert pod["nodeName"] == "worker-a.example"
    assert pod["automountServiceAccountToken"] is False
    assert container["command"] == [
        "python", "/opt/nct/tools/nct_kubernetes_failure_evidence.py",
    ]
    assert container["securityContext"]["capabilities"] == {"drop": ["ALL"]}
    assert container["args"].count("--tracked-job-id") == 2
    assert container["args"].count("--health-transition") == 1
    assert items["ConfigMap"]["immutable"] is True
    assert container["resources"]["limits"]["ephemeral-storage"] == "20Gi"
    assert any(item["mountPath"] == "/run/nct-gate4a" for item in container["volumeMounts"])
    assert job["metadata"]["annotations"]["nct.openai.com/storage-evidence-digest"] == report["attestation"]["digest"]
    assert all(item["kind"] not in {"Role", "RoleBinding", "Secret"} for item in document["items"])


def test_post_bootstrap_deployment_has_no_secret_reference(tmp_path: Path) -> None:
    value = args(tmp_path)
    write_report(value)
    document = renderer.deployment_resources(value)
    deployment = items_by_kind(document)["Deployment"]
    pod = deployment["spec"]["template"]["spec"]
    env_names = {item["name"] for item in pod["containers"][0]["env"]}
    volume_names = {item["name"] for item in pod["volumes"]}
    assert "NCT_BOOTSTRAP_ADMIN" not in env_names
    assert "NCT_BOOTSTRAP_PASSWORD_FILE" not in env_names
    assert "bootstrap" not in volume_names
    assert "NCT_AUTH_MODE" in env_names


@pytest.mark.parametrize(
    ("change", "message"),
    (
        ({"namespace": "other"}, "exact PVC request"),
        ({"pvc_name": "other-data"}, "exact PVC request"),
        ({"storage_class": "other-rwo"}, "exact PVC request"),
        ({"storage_size": "40Gi"}, "exact PVC request"),
        ({"pvc_uid": "99999999-2222-4333-8444-555555555555"}, "exact PVC request"),
        ({"bound_volume_uid": "ffffffff-bbbb-4ccc-8ddd-eeeeeeeeeeee"}, "exact PVC request"),
    ),
)
def test_deployment_rejects_report_identity_mismatch(tmp_path: Path, change: dict, message: str) -> None:
    original = args(tmp_path)
    report = write_report(original)
    changed = args(tmp_path, **change)
    changed.storage_report.write_text(json.dumps(report), encoding="utf-8")
    changed.storage_report_digest = report["attestation"]["digest"]
    with pytest.raises(renderer.RenderError, match=message):
        renderer.deployment_resources(changed)


@pytest.mark.parametrize("fault", ("cleanup", "uid", "source", "digest", "check"))
def test_deployment_rejects_failed_or_mismatched_evidence(tmp_path: Path, fault: str) -> None:
    value = args(tmp_path)
    report = passing_report(value)
    if fault == "cleanup":
        report["cleanup"]["status"] = "fail"
    elif fault == "uid":
        report["measured"]["executor_uid"] = 0
    elif fault == "source":
        report["tool"]["source_sha256"] = "b" * 64
    elif fault == "check":
        report["checks"][0]["status"] = "unavailable"
    report = qualifier._finalize({key: value for key, value in report.items() if key != "attestation"})
    value.storage_report.write_text(json.dumps(report), encoding="utf-8")
    value.storage_report_digest = "c" * 64 if fault == "digest" else report["attestation"]["digest"]
    with pytest.raises(renderer.RenderError):
        renderer.deployment_resources(value)


def test_renderer_requires_exact_image_and_refuses_overwrite(tmp_path: Path) -> None:
    with pytest.raises(renderer.RenderError, match="exact sha256"):
        args(tmp_path, image="registry.example/nct:latest")
    value = args(tmp_path)
    renderer._write_output(value.output, renderer.qualification_resources(value), False)
    with pytest.raises(renderer.RenderError, match="already exists"):
        renderer._write_output(value.output, renderer.qualification_resources(value), False)


def test_renderer_bounds_inputs_and_final_output(tmp_path: Path) -> None:
    with pytest.raises(renderer.RenderError, match="exact sha256"):
        args(tmp_path, image="r" * 600 + "@sha256:" + "a" * 64)
    with pytest.raises(renderer.RenderError, match="positive Mi"):
        args(tmp_path, storage_size="9" * 40 + "Gi")
    with pytest.raises(renderer.RenderError, match="immutable Kubernetes object identifier"):
        args(tmp_path, pvc_uid="a" * 129)
    oversized = {"value": "x" * renderer.MAX_OUTPUT_BYTES}
    with pytest.raises(renderer.RenderError, match="safe output limit"):
        renderer._write_output(tmp_path / "oversized.json", oversized, False)


def test_runtime_image_contains_exact_qualifier_path() -> None:
    dockerfile = (Path(__file__).resolve().parents[1] / "Dockerfile").read_text(encoding="utf-8")
    assert "COPY scripts/qualify_kubernetes_storage.py /opt/nct/tools/qualify_kubernetes_storage.py" in dockerfile
    assert "COPY scripts/probe_nct_writer_lock.py /opt/nct/tools/probe_nct_writer_lock.py" in dockerfile
    assert "COPY scripts/nct_kubernetes_failure_evidence.py /opt/nct/tools/nct_kubernetes_failure_evidence.py" in dockerfile
    assert "COPY scripts/nct_kubernetes_health_adapter.py /opt/nct/tools/nct_kubernetes_health_adapter.py" in dockerfile
