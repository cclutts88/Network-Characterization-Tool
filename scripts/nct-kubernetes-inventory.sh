#!/bin/sh
set -eu

namespace="nct-analysis"
name="nct-analysis"

usage() {
    cat <<'EOF'
Usage: sh scripts/nct-kubernetes-inventory.sh [--namespace NAME] [--name NAME]

Creates a read-only Kubernetes inventory for planning an NCT single-replica trial.
The script never reads Secrets and never changes cluster resources.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --namespace)
            [ "$#" -ge 2 ] || { echo "--namespace requires a value" >&2; exit 2; }
            namespace="$2"
            shift 2
            ;;
        --name)
            [ "$#" -ge 2 ] || { echo "--name requires a value" >&2; exit 2; }
            name="$2"
            shift 2
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

case "$namespace" in
    ''|*[!a-z0-9-]*|-*|*-) echo "Namespace must be a lowercase Kubernetes name." >&2; exit 2 ;;
esac
case "$name" in
    ''|*[!a-z0-9-]*|-*|*-) echo "NCT name must be a lowercase Kubernetes name." >&2; exit 2 ;;
esac

command -v kubectl >/dev/null 2>&1 || {
    echo "kubectl is required on the administrator workstation." >&2
    exit 1
}

context="$(kubectl config current-context 2>/dev/null || true)"
[ -n "$context" ] || {
    echo "kubectl has no current context. Select the intended Range cluster first." >&2
    exit 1
}
request_timeout="10s"
kctl() {
    kubectl --context "$context" --request-timeout="$request_timeout" "$@"
}
server="$(kctl config view --minify -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null || true)"
inventory_complete=yes
[ -n "$server" ] || inventory_complete=no

section() {
    printf '\n=== %s ===\n' "$1"
}

read_or_unavailable() {
    if ! "$@" 2>/dev/null; then
        echo "Unavailable or access denied"
    fi
}

required_read() {
    if ! "$@" 2>/dev/null; then
        echo "BLOCKED: unavailable, denied, or timed out"
        inventory_complete=no
    fi
}

echo "NCT Kubernetes read-only inventory"
echo "Generated (UTC): $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "Context: $context"
echo "Cluster server: ${server:-Unavailable or access denied}"
echo "Requested namespace: $namespace"
echo "Requested NCT name: $name"

section "Cluster"
required_read kctl version --output=yaml

section "Nodes and architecture"
required_read kctl get nodes \
    -o custom-columns='NAME:.metadata.name,READY:.status.conditions[?(@.type=="Ready")].status,ARCH:.status.nodeInfo.architecture,OS:.status.nodeInfo.operatingSystem,KUBELET:.status.nodeInfo.kubeletVersion' \
    --no-headers

section "Namespace"
namespace_result="$(kctl get namespace "$namespace" \
    -o custom-columns='NAME:.metadata.name,STATUS:.status.phase,UID:.metadata.uid' \
    --no-headers 2>&1)" && namespace_rc=0 || namespace_rc=$?
if [ "$namespace_rc" -eq 0 ]; then
    printf '%s\n' "$namespace_result"
    namespace_exists=yes
else
    case "$namespace_result" in
        *NotFound*|*not\ found*)
            namespace_exists=no
            echo "Confirmed absent"
            ;;
        *)
            namespace_exists=blocked
            echo "BLOCKED: namespace existence could not be confirmed."
            echo "$namespace_result"
            ;;
    esac
fi

section "Storage classes"
required_read kctl get storageclass \
    -o custom-columns='NAME:.metadata.name,PROVISIONER:.provisioner,DEFAULT:.metadata.annotations.storageclass\.kubernetes\.io/is-default-class,VOLUME_BINDING:.volumeBindingMode,RECLAIM_POLICY:.reclaimPolicy' \
    --no-headers

section "Persistent volumes referring to requested namespace"
orphaned_pv=no
pv_details="$(kctl get pv \
    -o custom-columns='NAME:.metadata.name,UID:.metadata.uid,STATUS:.status.phase,CLASS:.spec.storageClassName,CLAIM_NAMESPACE:.spec.claimRef.namespace,CLAIM_NAME:.spec.claimRef.name,DRIVER:.spec.csi.driver' \
    --no-headers 2>&1)" && pv_rc=0 || pv_rc=$?
if [ "$pv_rc" -eq 0 ]; then
    matching_pv="$(printf '%s\n' "$pv_details" | awk -v ns="$namespace" '$5 == ns')"
    if [ -n "$matching_pv" ]; then
        printf '%s\n' "$matching_pv"
        orphaned_pv=yes
    else
        echo "None"
    fi
else
    echo "BLOCKED: unavailable, denied, or timed out"
    echo "$pv_details"
    inventory_complete=no
fi

section "Ingress and Gateway support"
required_read kctl get ingressclass \
    -o custom-columns='NAME:.metadata.name,CONTROLLER:.spec.controller' --no-headers
if kctl api-resources --api-group=gateway.networking.k8s.io -o name 2>/dev/null | grep -q .; then
    echo "Gateway API: available"
else
    echo "Gateway API: unavailable or access denied"
fi

section "Metrics API"
if kctl get --raw /apis/metrics.k8s.io/v1beta1 2>/dev/null | grep -q 'APIResourceList'; then
    echo "Metrics API: available"
else
    echo "Metrics API: unavailable or access denied"
fi

section "Existing NCT resources in requested namespace"
namespace_nonempty=no
exact_nct_deployment=no

list_names() {
    label="$1"
    resource="$2"
    echo "$label:"
    result="$(kctl -n "$namespace" get "$resource" -o name 2>&1)" && result_rc=0 || result_rc=$?
    if [ "$result_rc" -ne 0 ]; then
        echo "BLOCKED: unavailable or access denied"
        echo "$result"
        inventory_complete=no
        return
    fi
    if [ -n "$result" ]; then
        printf '%s\n' "$result"
        if { [ "$resource" != serviceaccounts ] || [ "$result" != "serviceaccount/default" ]; } &&
           { [ "$resource" != configmaps ] || [ "$result" != "configmap/kube-root-ca.crt" ]; }; then
            namespace_nonempty=yes
        fi
        if [ "$resource" = deployments.apps ] &&
           printf '%s\n' "$result" | grep -Fqx "deployment.apps/$name"; then
            exact_nct_deployment=yes
        fi
    else
        echo "None"
    fi
}

if [ "$namespace_exists" = yes ]; then
    list_names "Deployments" deployments.apps
    list_names "StatefulSets" statefulsets.apps
    list_names "DaemonSets" daemonsets.apps
    list_names "ReplicaSets" replicasets.apps
    list_names "Pods" pods
    list_names "Services" services
    list_names "Persistent-volume claims" persistentvolumeclaims
    list_names "Ingresses" ingresses.networking.k8s.io
    list_names "Jobs" jobs.batch
    list_names "CronJobs" cronjobs.batch
    list_names "ServiceAccounts" serviceaccounts
    list_names "ConfigMaps" configmaps
    list_names "Roles" roles.rbac.authorization.k8s.io
    list_names "RoleBindings" rolebindings.rbac.authorization.k8s.io

    echo "Deployment details:"
    read_or_unavailable kctl -n "$namespace" get deployment \
        -o custom-columns='NAME:.metadata.name,UID:.metadata.uid,DESIRED:.spec.replicas,READY:.status.readyReplicas,STRATEGY:.spec.strategy.type,IMAGE:.spec.template.spec.containers[*].image' \
        --no-headers
    echo "Persistent-volume claim details:"
    pvc_details="$(kctl -n "$namespace" get pvc \
        -o custom-columns='NAME:.metadata.name,UID:.metadata.uid,STATUS:.status.phase,CLASS:.spec.storageClassName,CAPACITY:.status.capacity.storage,VOLUME:.spec.volumeName' \
        --no-headers 2>&1)" && pvc_rc=0 || pvc_rc=$?
    if [ "$pvc_rc" -eq 0 ]; then
        [ -n "$pvc_details" ] && printf '%s\n' "$pvc_details" || echo "None"
    else
        echo "BLOCKED: unavailable or access denied"
        echo "$pvc_details"
        inventory_complete=no
    fi
else
    if [ "$namespace_exists" = no ]; then
        echo "Skipped because the namespace is confirmed absent."
    else
        echo "BLOCKED: skipped because namespace access was denied or unavailable."
        inventory_complete=no
    fi
fi

section "Planning result"
if [ "$namespace_exists" = blocked ] || [ "$inventory_complete" != yes ]; then
    echo "BLOCKED: access or inventory is incomplete. Do not create or change resources."
elif [ "$exact_nct_deployment" = yes ]; then
    echo "EXISTING KUBERNETES NCT: do not use the fresh-install path."
    echo "Use the guarded Kubernetes upgrade process after backup and compatibility preflight."
elif [ "$orphaned_pv" = yes ]; then
    echo "BLOCKED: a retained persistent volume still refers to the requested namespace."
    echo "An administrator must identify and preserve it before any fresh installation."
elif [ "$namespace_exists" = no ]; then
    echo "FRESH CANDIDATE: the requested namespace is confirmed absent and no retained volume refers to it."
    echo "An administrator must confirm that a new dedicated namespace is intended."
elif [ "$namespace_nonempty" = yes ]; then
    echo "BLOCKED: the namespace contains existing resources."
    echo "An administrator must identify them before this namespace is used for NCT."
else
    echo "POSSIBLE FRESH SIDE-BY-SIDE TRIAL: the namespace is readable and the checked resource lists are empty."
    echo "An administrator must still approve the namespace, image, storage, HTTPS, and policy values."
fi

echo "No cluster resources were changed and no Secrets were read."

