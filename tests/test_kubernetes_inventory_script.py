import os
from pathlib import Path
import stat
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "nct-kubernetes-inventory.sh"
GUIDE = ROOT / "docs" / "KUBERNETES_RANGE_START_HERE.md"


def test_inventory_script_is_read_only_and_avoids_secrets() -> None:
    content = SCRIPT.read_text(encoding="utf-8")

    assert content.startswith("#!/bin/sh\nset -eu\n")
    assert "kubectl config current-context" in content
    assert "kctl config view --minify" in content
    assert "kctl get storageclass" in content
    assert "kctl get --raw /apis/metrics.k8s.io/v1beta1" in content
    assert "No cluster resources were changed and no Secrets were read." in content
    assert "namespace_exists=blocked" in content
    assert "BLOCKED: access or inventory is incomplete" in content
    assert 'list_names "Deployments" deployments.apps' in content
    assert 'list_names "Persistent-volume claims" persistentvolumeclaims' in content
    assert 'list_names "ServiceAccounts" serviceaccounts' in content
    assert 'list_names "ConfigMaps" configmaps' in content
    assert 'list_names "Roles" roles.rbac.authorization.k8s.io' in content
    assert "kctl get pv" in content
    assert 'grep -Fqx "deployment.apps/$name"' in content
    assert 'kubectl --context "$context" --request-timeout="$request_timeout"' in content

    forbidden = (
        "kubectl apply",
        "kubectl create",
        "kubectl delete",
        "kubectl patch",
        "kubectl replace",
        "kubectl scale",
        "kubectl exec",
        "kubectl cp",
        "kubectl port-forward",
        "get secret",
        "get secrets",
        "kubectl auth can-i",
    )
    lowered = content.lower()
    for command in forbidden:
        assert command not in lowered


def test_start_here_separates_fresh_upgrade_recovery_and_blocked_paths() -> None:
    content = GUIDE.read_text(encoding="utf-8")

    assert "Fresh side-by-side Kubernetes trial" in content
    assert "Existing Kubernetes upgrade" in content
    assert "Recovery" in content
    assert "Blocked" in content
    assert "an in-place Kubernetes upgrade" in content
    assert "host-folder-to-PVC migration procedure" in content
    assert "Leave the current Docker installation running, addressable, and unchanged" in content
    assert "different Kubernetes HTTPS DNS name or port" in content
    assert "Saved read-only inventory" in content
    assert "@sha256:..." in content
    assert "exactly one NCT pod is Ready" in content
    assert "does not by itself prove Range readiness" in content


def _fake_kubectl(tmp_path: Path) -> tuple[Path, Path]:
    log = tmp_path / "kubectl.log"
    executable = tmp_path / "kubectl"
    executable.write_text(
        """#!/bin/sh
set -eu
printf '%s\\n' "$*" >> "$KUBECTL_LOG"
mode="${KUBECTL_TEST_MODE:-empty}"
all="$*"
if [ "$all" = "config current-context" ]; then echo range-context; exit 0; fi
case "$all" in
  *" config view "*) echo 'https://range-controller.example:6443'; exit 0 ;;
  *" version "*) echo 'clientVersion: v1.36.1'; echo 'serverVersion: v1.34.0'; exit 0 ;;
  *" get nodes "*) echo 'range-node-1 True amd64 linux v1.34.0'; exit 0 ;;
  *" get storageclass "*) echo 'range-rwo csi.example true WaitForFirstConsumer Retain'; exit 0 ;;
  *" get ingressclass "*) echo 'range-gateway example/controller'; exit 0 ;;
  *" api-resources "*) echo 'gateways.gateway.networking.k8s.io'; exit 0 ;;
  *" get --raw /apis/metrics.k8s.io/v1beta1"*) echo '{"kind":"APIResourceList"}'; exit 0 ;;
  *" get namespace nct-analysis "*)
    case "$mode" in
      absent|absent_orphan) echo 'Error from server (NotFound): namespaces "nct-analysis" not found' >&2; exit 1 ;;
      denied) echo 'Error from server (Forbidden): namespaces is forbidden' >&2; exit 1 ;;
      timeout) echo 'error: context deadline exceeded' >&2; exit 1 ;;
      *) echo 'nct-analysis Active 11111111-2222-4333-8444-555555555555'; exit 0 ;;
    esac ;;
  *" get pods -o name"*)
    [ "$mode" != partial ] || { echo 'Error from server (Forbidden): pods is forbidden' >&2; exit 1; }
    exit 0 ;;
  *" get deployments.apps -o name"*)
    case "$mode" in
      differently_named) echo 'deployment.apps/other-nct' ;;
      exact) echo 'deployment.apps/nct-analysis' ;;
      prefix) echo 'deployment.apps/nct-analysis-old' ;;
    esac
    exit 0 ;;
  *" get serviceaccounts -o name"*) echo 'serviceaccount/default'; exit 0 ;;
  *" get configmaps -o name"*)
    [ "$mode" != configmap ] || { echo 'configmap/kube-root-ca.crt'; echo 'configmap/nct-recovery-receipt'; exit 0; }
    echo 'configmap/kube-root-ca.crt'; exit 0 ;;
  *" get pv "*)
    [ "$mode" != absent_orphan ] || echo 'pv-old old-pv-uid Bound range-rwo nct-analysis old-data csi.example'
    exit 0 ;;
  *" get "*" -o name"*) exit 0 ;;
  *" get deployment "*) exit 0 ;;
  *" get pvc "*) exit 0 ;;
esac
echo "unexpected fake kubectl command: $all" >&2
exit 1
""",
        encoding="utf-8",
    )
    executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
    return executable, log


def _run_inventory(tmp_path: Path, mode: str) -> subprocess.CompletedProcess[str]:
    _fake_kubectl(tmp_path)
    env = os.environ.copy()
    env["PATH"] = f"{tmp_path}:{env['PATH']}"
    env["KUBECTL_LOG"] = str(tmp_path / "kubectl.log")
    env["KUBECTL_TEST_MODE"] = mode
    return subprocess.run(
        ["sh", str(SCRIPT), "--namespace", "nct-analysis"],
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )


@pytest.mark.parametrize("mode", ["denied", "timeout", "partial"])
def test_inventory_blocks_incomplete_access(tmp_path: Path, mode: str) -> None:
    result = _run_inventory(tmp_path, mode)
    assert result.returncode == 0
    assert "BLOCKED:" in result.stdout
    assert "FRESH CANDIDATE:" not in result.stdout
    assert "POSSIBLE FRESH SIDE-BY-SIDE TRIAL:" not in result.stdout


def test_inventory_accepts_only_confirmed_namespace_absence(tmp_path: Path) -> None:
    result = _run_inventory(tmp_path, "absent")
    assert result.returncode == 0
    assert "FRESH CANDIDATE: the requested namespace is confirmed absent and no retained volume refers to it." in result.stdout
    assert "Cluster server: https://range-controller.example:6443" in result.stdout


@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        ("differently_named", "BLOCKED: the namespace contains existing resources."),
        ("exact", "EXISTING KUBERNETES NCT: do not use the fresh-install path."),
    ],
)
def test_inventory_blocks_existing_workloads(
    tmp_path: Path, mode: str, expected: str
) -> None:
    result = _run_inventory(tmp_path, mode)
    assert result.returncode == 0
    assert expected in result.stdout
    assert "POSSIBLE FRESH SIDE-BY-SIDE TRIAL:" not in result.stdout


@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        ("absent_orphan", "BLOCKED: a retained persistent volume still refers to the requested namespace."),
        ("configmap", "BLOCKED: the namespace contains existing resources."),
        ("prefix", "BLOCKED: the namespace contains existing resources."),
    ],
)
def test_inventory_blocks_orphans_configmaps_and_prefix_collisions(
    tmp_path: Path, mode: str, expected: str
) -> None:
    result = _run_inventory(tmp_path, mode)
    assert result.returncode == 0
    assert expected in result.stdout
    assert "EXISTING KUBERNETES NCT:" not in result.stdout
    assert "FRESH CANDIDATE:" not in result.stdout
    assert "POSSIBLE FRESH SIDE-BY-SIDE TRIAL:" not in result.stdout


def test_inventory_pins_every_cluster_read_to_context_and_timeout(tmp_path: Path) -> None:
    result = _run_inventory(tmp_path, "empty")
    assert result.returncode == 0
    assert "POSSIBLE FRESH SIDE-BY-SIDE TRIAL:" in result.stdout
    calls = (tmp_path / "kubectl.log").read_text(encoding="utf-8").splitlines()
    assert calls[0] == "config current-context"
    assert all(
        call.startswith("--context range-context --request-timeout=10s ")
        for call in calls[1:]
    )

