# Kubernetes single-replica analysis profile

## What this profile is

A replica is one running copy of NCT. This profile permits exactly one NCT copy and
uses one persistent volume for its database and retained evidence. It is deliberately
**analysis only**:

- analysts can sign in, import Nmap XML, upload existing device configurations, review
  retained evidence, run local saved-evidence processing, use Hunt, Reach and Map, and
  create a portable scan package;
- this NCT copy cannot start Nmap, run a saved scan schedule, open SSH to a device, or
  start packet capture;
- the application rejects those collection requests even if a caller bypasses the page;
- the pod receives no Linux capabilities, including no raw-network capability.

The manifest does not create a network policy. If this installation must have no
outbound access at all, the cluster administrator must apply the site's approved egress
policy. Without that policy, local features such as an administrator-requested online
Exploit-DB update may still use ordinary outbound network access. Offline reference
upload remains available.

This is a foundation deployment package. It is not yet Range-ready or mission-ready.

## Files and trust boundary

`scripts/render_kubernetes_single_replica.py` creates Kubernetes JSON that `kubectl`
can apply. It never contacts the cluster, calls `kubectl`, or writes a Secret value.
Every image argument must contain an exact `sha256` digest.

The storage qualification report contains an unauthenticated digest. That digest can
detect alteration when it is compared with a separately retained copy, but it is not a
signature and it does not approve a storage class. Keep the report and its digest on the
administrator workstation or evidence store, outside the candidate NCT volume.

The same numeric user and group, `10001:10001`, run the qualification Job and NCT. The
deployment renderer refuses a report from a different user, group, tool source, volume
claim, immutable claim UID, immutable bound-volume UID, namespace, storage class, size,
access mode, or cleanup outcome. Replacing either Kubernetes object changes that
identity and requires a new qualification.

## Before starting

### Prerequisites

Stop and ask the cluster administrator for help unless all of these are true:

- Python 3 is available on the workstation that contains this repository;
- `kubectl` is installed, points to the intended cluster, and can read namespaces,
  claims, bound volumes, Jobs, Deployments, Services, pods, and logs there;
- the NCT image is already in a registry that every intended cluster node can pull,
  using the exact digest recorded in `IMAGE`;
- the operator may create the namespace resources in this guide, or an administrator
  has agreed to apply the rendered files;
- the site has selected one storage class that can provide the requested size and
  `ReadWriteOnce` access;
- an administrator owns the approved HTTPS Ingress or Gateway work in step 5.

This guide does not create registry credentials. If the registry is private, have the
cluster administrator configure the namespace's approved image-pull credential before
applying the Job or Deployment.

### Terms used below

- **PVC (persistent-volume claim):** NCT's request for durable storage.
- **PV (persistent volume):** the bound storage object that satisfies that request.
- **Storage class:** the cluster's named storage provider and policy.
- **UID:** Kubernetes' immutable identifier for one specific object. A reused name can
  point to a different object, so NCT records both the PVC and PV UIDs.
- **ServiceAccount:** the pod's Kubernetes identity. This profile disables its API
  token and grants it no RBAC permissions.
- **RBAC:** Kubernetes API permissions. This profile grants none.
- **ClusterIP Service:** an internal cluster address for NCT; analysts do not browse it
  directly.
- **Ingress or Gateway:** the administrator-managed HTTPS front door that sends
  approved browser traffic to the ClusterIP Service.
- **ReadWriteOnce:** Kubernetes may mount the claim for writing from one node at a
  time. It does not by itself prove that two NCT writers can never overlap.

### Set the values once

Obtain these reviewed values:

- `NAMESPACE`: the dedicated namespace;
- `IMAGE`: the immutable NCT image reference, such as
  `registry.example/nct@sha256:...`;
- `PVC_NAME`: the one persistent-volume claim for NCT;
- `STORAGE_CLASS`: the exact storage class name;
- `STORAGE_SIZE`: a binary Kubernetes quantity such as `20Gi`;
- `NCT_DNS`: the approved analyst-facing DNS name;
- `TRUSTED_CA`: the public CA file used to verify that HTTPS address.

Set them in the same terminal before copying the later commands:

```bash
export NAMESPACE='nct-analysis'
export IMAGE='registry.example/nct@sha256:REPLACE_WITH_64_HEX_DIGEST'
export PVC_NAME='nct-data'
export STORAGE_CLASS='REPLACE_WITH_APPROVED_STORAGE_CLASS'
export STORAGE_SIZE='20Gi'
export NCT_DNS='nct.example.mil'
export TRUSTED_CA='./approved-public-ca.pem'

printf '%s\n' "$NAMESPACE" "$IMAGE" "$PVC_NAME" "$STORAGE_CLASS" \
  "$STORAGE_SIZE" "$NCT_DNS" "$TRUSTED_CA"
```

Replace every example value before continuing. The image value must contain the exact
digest and no tag-only reference such as `:latest`.

After the claim is bound, the steps below capture `PVC_UID`, `PV_NAME`, and `PV_UID`.
The two UIDs are immutable identities, unlike the reusable object names. The renderer
binds the report and Deployment to both UIDs plus the namespace, claim, class,
requested size, access mode, mount path, and NCT user/group. Retain the storage driver
and all three values beside the report.

## Ordered deployment runbook

### 1. Prepare the namespace

Create or select one dedicated namespace. The generated ServiceAccount receives no API
token and no RBAC permissions.

```bash
kubectl create namespace "$NAMESPACE"
```

### 2. Create the claim, capture its immutable identity, then qualify it

Render and apply only the ServiceAccount and claim first:

```bash
python scripts/render_kubernetes_single_replica.py claim \
  --namespace "$NAMESPACE" \
  --pvc-name "$PVC_NAME" \
  --storage-class "$STORAGE_CLASS" \
  --storage-size "$STORAGE_SIZE" \
  --output nct-storage-claim.json

kubectl apply -f nct-storage-claim.json
kubectl wait --for=jsonpath='{.status.phase}'=Bound --timeout=120s \
  -n "$NAMESPACE" pvc/"$PVC_NAME"
PVC_UID="$(kubectl get pvc -n "$NAMESPACE" "$PVC_NAME" -o jsonpath='{.metadata.uid}')"
PV_NAME="$(kubectl get pvc -n "$NAMESPACE" "$PVC_NAME" -o jsonpath='{.spec.volumeName}')"
PV_UID="$(kubectl get pv "$PV_NAME" -o jsonpath='{.metadata.uid}')"
printf 'PVC_UID=%s\nPV_NAME=%s\nPV_UID=%s\n' "$PVC_UID" "$PV_NAME" "$PV_UID"
```

Save those three displayed values. Then render a Job for that exact claim and bound
volume. Its name includes a hash of the immutable identity, so a replacement claim
cannot silently reuse a completed Job:

```bash
python scripts/render_kubernetes_single_replica.py qualification \
  --namespace "$NAMESPACE" \
  --image "$IMAGE" \
  --pvc-name "$PVC_NAME" \
  --storage-class "$STORAGE_CLASS" \
  --storage-size "$STORAGE_SIZE" \
  --pvc-uid "$PVC_UID" \
  --bound-volume-uid "$PV_UID" \
  --output nct-storage-qualification.json

kubectl apply -f nct-storage-qualification.json
QUALIFICATION_JOB="$(python -c "import json; d=json.load(open('nct-storage-qualification.json')); print(next(x['metadata']['name'] for x in d['items'] if x['kind']=='Job'))")"
kubectl wait --for=condition=complete --timeout=90s \
  -n "$NAMESPACE" job/"$QUALIFICATION_JOB"
kubectl logs -n "$NAMESPACE" job/"$QUALIFICATION_JOB" \
  > nct-storage-report.json
python -c "import json; print(json.load(open('nct-storage-report.json', encoding='utf-8'))['attestation']['digest'])" \
  > nct-storage-report.digest
```

A usable report has `"overall": "pass"`, every check has `"status": "pass"`,
and cleanup has `"status": "pass"`. A failure, timeout, unavailable check, or incomplete
cleanup stops deployment. Inspect and remove only the named private
`.nct-storage-qualification-*` directory after confirming it belongs to that failed
run; never delete the volume root or NCT data recursively.

This check covers bounded file locks, observed replacement, file and directory sync,
and SQLite WAL/SHM behavior for this exact mounted environment. It does not test
capacity, performance, backup and restore, node loss, forced termination, or every
volume made by the storage class.

Before every deployment render, read the live `PVC_UID` and `PV_UID` again using the
commands above. If either value changed, discard the old rendered package for this
purpose and run qualification again. Object names alone are not proof that the same
storage is still present.

### 3. Prepare the first-login Secret

There are no default credentials. Use a temporary password file that contains one
strong password and create a Secret with the chosen Administrator username and password.
Do not place the password in the renderer command or generated JSON.

```bash
kubectl create secret generic nct-bootstrap \
  -n "$NAMESPACE" \
  --from-literal=username=CHOSEN_ADMIN_USERNAME \
  --from-file=password=./nct-bootstrap-password.txt
```

The bootstrap account is created only when the account store on the volume is empty. An
existing volume preserves its accounts and does not recreate or replace them. Local
authentication is forced in this profile; a fresh empty volume without the Secret fails
startup instead of opening NCT without a login.

### 4. Render the bootstrap deployment

```bash
REPORT_DIGEST="$(cat nct-storage-report.digest)"
python scripts/render_kubernetes_single_replica.py deployment \
  --namespace "$NAMESPACE" \
  --image "$IMAGE" \
  --pvc-name "$PVC_NAME" \
  --storage-class "$STORAGE_CLASS" \
  --storage-size "$STORAGE_SIZE" \
  --pvc-uid "$PVC_UID" \
  --bound-volume-uid "$PV_UID" \
  --storage-report nct-storage-report.json \
  --storage-report-digest "$REPORT_DIGEST" \
  --bootstrap-secret nct-bootstrap \
  --output nct-single-replica-bootstrap.json

kubectl apply -f nct-single-replica-bootstrap.json
kubectl rollout status -n "$NAMESPACE" deployment/nct-analysis --timeout=180s
```

The Deployment uses `Recreate`, one replica, no autoscaler, a ClusterIP Service, a
read-only root filesystem, bounded resources, and no Linux capabilities. `Recreate`
means the old NCT copy must fully stop before Kubernetes starts its replacement. The
application writer guard also keeps a new copy stopped if another writer still owns the
volume.

### 5. Put the ClusterIP Service behind the approved HTTPS gateway

Use this single traffic path:

`analyst browser -> approved HTTPS gateway -> nct-analysis ClusterIP port 8080`

Terminate TLS at the cluster's approved Ingress or Gateway. Keep the private key in the
cluster's approved TLS Secret; do not put it in the NCT image or generated JSON. Issue a
certificate for `NCT_DNS` from a CA trusted by analyst workstations. Do not expose the
internal HTTP port directly to analysts.

Verify the final address without skipping certificate checks:

```bash
curl --fail --cacert "$TRUSTED_CA" "https://$NCT_DNS/health/startup"
curl --fail --cacert "$TRUSTED_CA" "https://$NCT_DNS/health/readiness"
curl --fail --cacert "$TRUSTED_CA" "https://$NCT_DNS/health/liveness"
```

This provider-neutral package cannot safely generate a site-specific Ingress or
Gateway. Give the cluster administrator this exact handoff checklist and stop until all
items are returned:

- backend Service: `nct-analysis` in namespace `$NAMESPACE`;
- backend protocol and port: HTTP on Service port `8080`;
- analyst address: `https://$NCT_DNS` only;
- TLS certificate: valid for `$NCT_DNS`, with its private key kept in the site's
  approved cluster Secret;
- trust file: the public CA chain saved at `$TRUSTED_CA` on the verification
  workstation;
- access policy: analyst browsers may reach the HTTPS address, while the ClusterIP and
  pod port are not exposed directly;
- returned result: all three `curl` commands above succeed without `--insecure`, and a
  browser reaches the NCT sign-in page without a certificate warning.

Do not continue to first login when any checklist item is missing.

### 6. Sign in, remove bootstrap access, and replace the pod

Sign in through `https://NCT_DNS` with the selected Administrator. Confirm that the
account exists. Render the same deployment again without `--bootstrap-secret`, apply it,
and wait for the `Recreate` replacement to finish:

```bash
python scripts/render_kubernetes_single_replica.py deployment \
  --namespace "$NAMESPACE" \
  --image "$IMAGE" \
  --pvc-name "$PVC_NAME" \
  --storage-class "$STORAGE_CLASS" \
  --storage-size "$STORAGE_SIZE" \
  --pvc-uid "$PVC_UID" \
  --bound-volume-uid "$PV_UID" \
  --storage-report nct-storage-report.json \
  --storage-report-digest "$REPORT_DIGEST" \
  --output nct-single-replica.json

kubectl apply -f nct-single-replica.json
kubectl rollout status -n "$NAMESPACE" deployment/nct-analysis --timeout=180s
kubectl delete secret -n "$NAMESPACE" nct-bootstrap
```

Delete the local plaintext password file according to site credential-handling policy.
Do not delete the Secret until the rendered deployment no longer references or mounts it.

### 7. Verify the installed profile

Confirm all of the following:

- exactly one NCT pod is Ready and no second NCT pod exists;
- HTTPS login works with certificate verification enabled;
- retained evidence is visible and a selected evidence file can be downloaded;
- Settings / System Health shows **Kubernetes · one replica · analysis only** and
  **Active scanning: Disabled by deployment policy**;
- startup, readiness, and liveness checks return healthy results;
- Nmap Run now, scheduled Run now/Enable, and device Start SSH controls are disabled;
- authenticated direct scan and device-collection requests return `503`;
- the pod drops `ALL` capabilities, uses user/group `10001:10001`, receives no API
  token, and mounts the exact qualified claim;
- deleting the one pod produces one clean replacement that can still sign in and read
  the retained evidence;
- the live claim and bound-volume UIDs match the saved report, renderer arguments, and
  pod annotations.

Do not use a rolling update, set replicas above one, add an autoscaler, or add raw-network
capabilities to this profile.

## Upgrade and rollback boundary

Before an upgrade, record the current image digest, qualified storage identity, report
digest, application/schema compatibility, and a verified database-plus-evidence backup.
Stop the old NCT copy completely before starting the new image. If the new image fails,
start the old image only when its documented schema compatibility permits opening the
current data. Otherwise restore the matching backup before starting that old image.

Forced termination, rescheduling, node loss, backup, restore, upgrade, and rollback are
Kubernetes acceptance gate 4. Until those tests pass, this package must not be described
as Range-ready or mission-ready.

## What a successful gate proves

This profile proves one analysis-only NCT copy on the named cluster and exact tested
volume. It does not prove multiple-copy operation, live collection, general
storage-class approval, Range readiness, mission readiness, or production scale.
