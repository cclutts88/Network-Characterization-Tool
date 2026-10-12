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

## Gate 4A cold backup and isolated restore

Gate 4A is an administrator recovery exercise. It is separate from System Health's
storage dry run, Artifact Registry backfill, exact-content compaction, pod replacement,
and image rollback. The recovery tools never call `kubectl`, never contact a network
target, and never overwrite the live source or an existing restore target.

The exercise requires three separately qualified storage objects:

1. the current NCT data claim as the **source**;
2. a different claim as the **backup target**; and
3. a third, empty claim as the **restore target**.

Names are not sufficient. Immediately before each render and apply, record the
namespace, claim UID, bound-volume UID, storage class, requested size, and passing
qualification report digest for every mounted object. Save the exact image digest,
application version, build ID, generated Jobs, backup receipt, restore receipt, and
command output outside the three claims. Backup data contains analyst accounts,
preferences, reports, and retained evidence; protect it as sensitive operational data.

Start from an administrator workstation that has `kubectl`, Python 3, the NCT source
package, the Gate 3C source qualification report, and access to the intended namespace.
Use a private working directory. Set these values first; do not paste Secret content:

```sh
export NCT_NAMESPACE='nct'
export NCT_NAME='nct-analysis'
export NCT_IMAGE='registry.example/nct@sha256:REPLACE_WITH_EXACT_DIGEST'
export NCT_APP_VERSION='REPLACE_WITH_IMAGE_VERSION'
export NCT_BUILD_ID='REPLACE_WITH_IMAGE_BUILD_ID'
export SOURCE_PVC='nct-data'
export SOURCE_CLASS='REPLACE_WITH_APPROVED_STORAGE_CLASS'
export SOURCE_SIZE='20Gi'
export SOURCE_REPORT='./source-storage-report.json'
export SOURCE_REPORT_DIGEST='REPLACE_WITH_SAVED_REPORT_DIGEST'
export BACKUP_PVC='nct-gate4a-backup'
export BACKUP_CLASS="$SOURCE_CLASS"
export BACKUP_SIZE='50Gi'
export RESTORE_PVC='nct-gate4a-restore'
export RESTORE_CLASS="$SOURCE_CLASS"
export RESTORE_SIZE='20Gi'
export BACKUP_ID="backup-$(date -u +%Y%m%d-%H%M%S)"
```

The examples below intentionally stop after each important proof. Read the displayed
identity and receipt before continuing. A failed command is a stop condition.

The backup claim must have room for the private source snapshot and an uncompressed
archive at the same time, plus manifest, receipt, and filesystem overhead. Plan for more
than twice the retained source bytes; the example uses 50 GiB for a source claim that
may hold 20 GiB. The backup tool performs a bounded free-space preflight and stops before
creating an archive when the measured free space cannot cover that minimum.

### 0. Create and qualify the separate claims

Create the backup claim:

```sh
python scripts/render_kubernetes_single_replica.py claim \
  --name "$NCT_NAME" --namespace "$NCT_NAMESPACE" \
  --pvc-name "$BACKUP_PVC" --storage-class "$BACKUP_CLASS" \
  --storage-size "$BACKUP_SIZE" --output gate4a-backup-claim.json
kubectl apply -f gate4a-backup-claim.json
kubectl -n "$NCT_NAMESPACE" wait --for=jsonpath='{.status.phase}'=Bound \
  "pvc/$BACKUP_PVC" --timeout=180s
export BACKUP_PVC_UID="$(kubectl -n "$NCT_NAMESPACE" get pvc "$BACKUP_PVC" -o jsonpath='{.metadata.uid}')"
export BACKUP_PV="$(kubectl -n "$NCT_NAMESPACE" get pvc "$BACKUP_PVC" -o jsonpath='{.spec.volumeName}')"
export BACKUP_PV_UID="$(kubectl get pv "$BACKUP_PV" -o jsonpath='{.metadata.uid}')"
python scripts/render_kubernetes_single_replica.py qualification \
  --name "$NCT_NAME" --namespace "$NCT_NAMESPACE" --image "$NCT_IMAGE" \
  --pvc-name "$BACKUP_PVC" --storage-class "$BACKUP_CLASS" \
  --storage-size "$BACKUP_SIZE" --pvc-uid "$BACKUP_PVC_UID" \
  --bound-volume-uid "$BACKUP_PV_UID" --mount-path /backup \
  --output gate4a-backup-qualification.json
export BACKUP_QUAL_JOB="$(python -c 'import json; print(next(x["metadata"]["name"] for x in json.load(open("gate4a-backup-qualification.json"))["items"] if x["kind"]=="Job"))')"
kubectl apply -f gate4a-backup-qualification.json
kubectl -n "$NCT_NAMESPACE" wait --for=condition=complete "job/$BACKUP_QUAL_JOB" --timeout=180s
kubectl -n "$NCT_NAMESPACE" logs "job/$BACKUP_QUAL_JOB" > gate4a-backup-storage-report.json
export BACKUP_REPORT='./gate4a-backup-storage-report.json'
export BACKUP_REPORT_DIGEST="$(python -c 'import json; print(json.load(open("gate4a-backup-storage-report.json"))["attestation"]["digest"])')"
```

Create and qualify the restore claim with the same sequence and these substitutions:

```sh
python scripts/render_kubernetes_single_replica.py claim \
  --name "$NCT_NAME" --namespace "$NCT_NAMESPACE" \
  --pvc-name "$RESTORE_PVC" --storage-class "$RESTORE_CLASS" \
  --storage-size "$RESTORE_SIZE" --output gate4a-restore-claim.json
kubectl apply -f gate4a-restore-claim.json
kubectl -n "$NCT_NAMESPACE" wait --for=jsonpath='{.status.phase}'=Bound \
  "pvc/$RESTORE_PVC" --timeout=180s
export RESTORE_PVC_UID="$(kubectl -n "$NCT_NAMESPACE" get pvc "$RESTORE_PVC" -o jsonpath='{.metadata.uid}')"
export RESTORE_PV="$(kubectl -n "$NCT_NAMESPACE" get pvc "$RESTORE_PVC" -o jsonpath='{.spec.volumeName}')"
export RESTORE_PV_UID="$(kubectl get pv "$RESTORE_PV" -o jsonpath='{.metadata.uid}')"
python scripts/render_kubernetes_single_replica.py qualification \
  --name "$NCT_NAME" --namespace "$NCT_NAMESPACE" --image "$NCT_IMAGE" \
  --pvc-name "$RESTORE_PVC" --storage-class "$RESTORE_CLASS" \
  --storage-size "$RESTORE_SIZE" --pvc-uid "$RESTORE_PVC_UID" \
  --bound-volume-uid "$RESTORE_PV_UID" --mount-path /restore \
  --output gate4a-restore-qualification.json
export RESTORE_QUAL_JOB="$(python -c 'import json; print(next(x["metadata"]["name"] for x in json.load(open("gate4a-restore-qualification.json"))["items"] if x["kind"]=="Job"))')"
kubectl apply -f gate4a-restore-qualification.json
kubectl -n "$NCT_NAMESPACE" wait --for=condition=complete "job/$RESTORE_QUAL_JOB" --timeout=180s
kubectl -n "$NCT_NAMESPACE" logs "job/$RESTORE_QUAL_JOB" > gate4a-restore-storage-report.json
export RESTORE_REPORT='./gate4a-restore-storage-report.json'
export RESTORE_REPORT_DIGEST="$(python -c 'import json; print(json.load(open("gate4a-restore-storage-report.json"))["attestation"]["digest"])')"
```

Re-read the source identity immediately before stopping NCT:

```sh
export SOURCE_PVC_UID="$(kubectl -n "$NCT_NAMESPACE" get pvc "$SOURCE_PVC" -o jsonpath='{.metadata.uid}')"
export SOURCE_PV="$(kubectl -n "$NCT_NAMESPACE" get pvc "$SOURCE_PVC" -o jsonpath='{.spec.volumeName}')"
export SOURCE_PV_UID="$(kubectl get pv "$SOURCE_PV" -o jsonpath='{.metadata.uid}')"
printf 'source=%s/%s backup=%s/%s restore=%s/%s\n' \
  "$SOURCE_PVC_UID" "$SOURCE_PV_UID" "$BACKUP_PVC_UID" "$BACKUP_PV_UID" \
  "$RESTORE_PVC_UID" "$RESTORE_PV_UID"
```

### 1. Stop the writer

Resolve queued or running work, scale the NCT Deployment to zero, and wait until no NCT
pod remains. Do not rely on ReadWriteOnce or the displayed replica count alone. The
backup process opens and holds NCT's writer lock for the complete capture and fails if
another process still owns it.

```sh
kubectl -n "$NCT_NAMESPACE" scale "deployment/$NCT_NAME" --replicas=0
kubectl -n "$NCT_NAMESPACE" wait --for=delete pod \
  -l "app.kubernetes.io/name=$NCT_NAME,app.kubernetes.io/component=analysis" --timeout=180s
test -z "$(kubectl -n "$NCT_NAMESPACE" get pod \
  -l "app.kubernetes.io/name=$NCT_NAME,app.kubernetes.io/component=analysis" \
  -o name)" || { printf '%s\n' 'STOP: an NCT pod still exists' >&2; exit 1; }
```

### 2. Render the backup Job

Use `scripts/render_kubernetes_recovery.py backup --help` for the complete argument
list. Supply the exact image digest; source and backup claim details; both qualification
reports and their separately recorded digests; one new lowercase backup ID; the
application version and build ID; and an unused output path. The renderer validates both
reports and creates a bounded Job with no API token, RBAC, Secret, Linux capability, or
automatic cleanup. It does not apply the Job.

The Job mounts the source at `/data` and separate backup storage at `/backup`. It rejects
active work, writer contention, changed storage identities, unsafe links or special
files, path or case collisions, and configured file, byte, time, or report limits. It
captures the complete data tree through protected file handles into a private snapshot,
then validates only that snapshot rather than opening the live SQLite database. It includes
the database, WAL/SHM side files, artifacts,
imports, scan and device evidence, jobs, packages, reports, preferences, and offline
reference data. Only the fixed runtime writer-lock file is excluded. Hard-linked paths
are materialized as separate regular archive members so every pathname remains present.

The completed backup contains a byte and SHA-256 manifest for every pathname, a complete
inventory digest, the archive digest, database, Artifact Registry, supported retained
evidence, and observation baselines, storage identities, both qualification-report
digests, image/build identity, and a detached receipt. The tool rereads the stored
archive before it reports `backup_verified`. These digests detect change but are not
cryptographic signatures; retain the receipt and digests separately.

```sh
python scripts/render_kubernetes_recovery.py backup \
  --name "$NCT_NAME" --namespace "$NCT_NAMESPACE" --image "$NCT_IMAGE" \
  --backup-id "$BACKUP_ID" --application-version "$NCT_APP_VERSION" --build-id "$NCT_BUILD_ID" \
  --source-pvc-name "$SOURCE_PVC" --source-storage-class "$SOURCE_CLASS" \
  --source-storage-size "$SOURCE_SIZE" --source-pvc-uid "$SOURCE_PVC_UID" \
  --source-bound-volume-uid "$SOURCE_PV_UID" --source-storage-report "$SOURCE_REPORT" \
  --source-storage-report-digest "$SOURCE_REPORT_DIGEST" \
  --backup-pvc-name "$BACKUP_PVC" --backup-storage-class "$BACKUP_CLASS" \
  --backup-storage-size "$BACKUP_SIZE" --backup-pvc-uid "$BACKUP_PVC_UID" \
  --backup-bound-volume-uid "$BACKUP_PV_UID" --backup-storage-report "$BACKUP_REPORT" \
  --backup-storage-report-digest "$BACKUP_REPORT_DIGEST" --output gate4a-backup-job.json
export BACKUP_JOB="$(python -c 'import json; print(next(x["metadata"]["name"] for x in json.load(open("gate4a-backup-job.json"))["items"] if x["kind"]=="Job"))')"
kubectl apply -f gate4a-backup-job.json
kubectl -n "$NCT_NAMESPACE" wait --for=condition=complete "job/$BACKUP_JOB" --timeout=14520s
kubectl -n "$NCT_NAMESPACE" logs "job/$BACKUP_JOB" > gate4a-backup-receipt.json
grep -q '"status": "backup_verified"' gate4a-backup-receipt.json
export BACKUP_RECEIPT_DIGEST="$(python -c 'import json; print(json.load(open("gate4a-backup-receipt.json"))["receipt_sha256"])')"
```

**Stop here** unless the receipt says `backup_verified` and its digest has been copied
to protected storage outside all three claims.

### 3. Render the restore Job

Create and qualify a new empty target. Re-read all three storage UIDs, then use
`scripts/render_kubernetes_recovery.py restore --help`. Supply the source, backup, and
target identities and qualification reports plus the same backup ID. The renderer
rejects reused identities. The restore Job mounts backup storage read-only and never
mounts the live source.

Restore fails closed for a nonempty target, changed identity, missing or extra manifest
entry, traversal, link, special file, duplicate, case collision, archive tampering,
truncation, over-limit expansion, interrupted write, database corruption, foreign-key
failure, changed table baseline, or mismatched registered artifact. A failed or
interrupted target is retained for inspection and must not be reused; start again with a
fresh empty qualified target. The live source and backup are never deleted or changed.

```sh
python scripts/render_kubernetes_recovery.py restore \
  --name "$NCT_NAME" --namespace "$NCT_NAMESPACE" --image "$NCT_IMAGE" \
  --backup-id "$BACKUP_ID" --backup-receipt-digest "$BACKUP_RECEIPT_DIGEST" \
  --source-pvc-name "$SOURCE_PVC" --source-storage-class "$SOURCE_CLASS" \
  --source-storage-size "$SOURCE_SIZE" --source-pvc-uid "$SOURCE_PVC_UID" \
  --source-bound-volume-uid "$SOURCE_PV_UID" --source-storage-report "$SOURCE_REPORT" \
  --source-storage-report-digest "$SOURCE_REPORT_DIGEST" \
  --backup-pvc-name "$BACKUP_PVC" --backup-storage-class "$BACKUP_CLASS" \
  --backup-storage-size "$BACKUP_SIZE" --backup-pvc-uid "$BACKUP_PVC_UID" \
  --backup-bound-volume-uid "$BACKUP_PV_UID" --backup-storage-report "$BACKUP_REPORT" \
  --backup-storage-report-digest "$BACKUP_REPORT_DIGEST" \
  --target-pvc-name "$RESTORE_PVC" --target-storage-class "$RESTORE_CLASS" \
  --target-storage-size "$RESTORE_SIZE" --target-pvc-uid "$RESTORE_PVC_UID" \
  --target-bound-volume-uid "$RESTORE_PV_UID" --target-storage-report "$RESTORE_REPORT" \
  --target-storage-report-digest "$RESTORE_REPORT_DIGEST" --output gate4a-restore-job.json
export RESTORE_JOB="$(python -c 'import json; print(next(x["metadata"]["name"] for x in json.load(open("gate4a-restore-job.json"))["items"] if x["kind"]=="Job"))')"
kubectl apply -f gate4a-restore-job.json
kubectl -n "$NCT_NAMESPACE" wait --for=condition=complete "job/$RESTORE_JOB" --timeout=14520s
export RESTORE_POD="$(kubectl -n "$NCT_NAMESPACE" get pod -l "job-name=$RESTORE_JOB" -o jsonpath='{.items[0].metadata.name}')"
kubectl -n "$NCT_NAMESPACE" get pod "$RESTORE_POD" \
  -o jsonpath='{.status.containerStatuses[0].state.terminated.message}' \
  > gate4a-restore-receipt.json
grep -q '"status": "restore_verification_passed"' gate4a-restore-receipt.json
export RESTORE_RECEIPT_DIGEST="$(python -c 'import json; print(json.load(open("gate4a-restore-receipt.json"))["receipt_sha256"])')"
```

The same receipt is also in the Job log, but the terminated-container message is the
Job's durable in-cluster copy while the Job and Pod are retained. Copy the receipt and
its digest to protected storage outside all three claims.

**Stop here** unless the receipt says `restore_verification_passed`. Preserve any failed
target and create a different empty target before retrying.

### 4. Verify the restored application

`restore_verification_passed` proves byte-exact pre-start restoration, database
integrity, baseline equality, and registered artifact hashes. It is not the final Gate
4A result. Render the normal one-replica Deployment against the restore target and use
the **same exact image digest**. Then verify all of the following:

- startup and readiness succeed;
- an existing administrator can sign in;
- the stored database/table baselines remain present;
- retained scans, device collections, reports, jobs, and observations remain visible;
- no incomplete work became complete;
- at least one retained evidence file downloads with its recorded SHA-256; and
- the restore claim and bound-volume UIDs match the saved report, Job, and Deployment.

Stop the restored application after the exercise and preserve the source, backup, target,
Jobs, logs, manifests, and receipts until review is complete. A passing Gate 4A exercise
on one exact cluster and storage set does not prove forced termination, rescheduling,
node loss, upgrade, rollback, Range, mission, or multi-replica readiness.

Render the normal Gate 3C Deployment with the restore claim's identity and qualification
report and the same image. Do **not** supply `--bootstrap-secret`: the administrator
account must be present in the restored data. Creating a new bootstrap account could hide
an incomplete account restore. Apply it only after the offline restore receipt passes,
review the generated document before applying it, and wait for the replacement:

```sh
python scripts/render_kubernetes_single_replica.py deployment \
  --name "$NCT_NAME" --namespace "$NCT_NAMESPACE" --image "$NCT_IMAGE" \
  --pvc-name "$RESTORE_PVC" --storage-class "$RESTORE_CLASS" \
  --storage-size "$RESTORE_SIZE" --pvc-uid "$RESTORE_PVC_UID" \
  --bound-volume-uid "$RESTORE_PV_UID" \
  --storage-report "$RESTORE_REPORT" \
  --storage-report-digest "$RESTORE_REPORT_DIGEST" \
  --output gate4a-restored-deployment.json
python -m json.tool gate4a-restored-deployment.json
kubectl apply -f gate4a-restored-deployment.json
kubectl -n "$NCT_NAMESPACE" rollout status "deployment/$NCT_NAME" --timeout=180s
```

Run the startup, readiness, sign-in, retained-history, and evidence-download checks above.
**Stop and preserve the restored target** if the existing administrator cannot sign in;
do not create or inject a replacement account. After the checks pass, stop the test copy
before returning to the source:

```sh
kubectl -n "$NCT_NAMESPACE" scale "deployment/$NCT_NAME" --replicas=0
kubectl -n "$NCT_NAMESPACE" wait --for=delete pod \
  -l "app.kubernetes.io/name=$NCT_NAME,app.kubernetes.io/component=analysis" --timeout=180s
```

To return to the unchanged source, first re-read its live claim and bound-volume UIDs and
compare them with the identity inside the saved source qualification report. Stop if
either value changed:

```sh
export CURRENT_SOURCE_PVC_UID="$(kubectl -n "$NCT_NAMESPACE" get pvc "$SOURCE_PVC" -o jsonpath='{.metadata.uid}')"
export CURRENT_SOURCE_PV="$(kubectl -n "$NCT_NAMESPACE" get pvc "$SOURCE_PVC" -o jsonpath='{.spec.volumeName}')"
export CURRENT_SOURCE_PV_UID="$(kubectl get pv "$CURRENT_SOURCE_PV" -o jsonpath='{.metadata.uid}')"
export SAVED_SOURCE_PVC_UID="$(python -c 'import json,os; v=json.loads(json.load(open(os.environ["SOURCE_REPORT"]))["declared"]["storage_identity"]); print(v["pvc_uid"])')"
export SAVED_SOURCE_PV_UID="$(python -c 'import json,os; v=json.loads(json.load(open(os.environ["SOURCE_REPORT"]))["declared"]["storage_identity"]); print(v["bound_volume_uid"])')"
test "$CURRENT_SOURCE_PVC_UID" = "$SOURCE_PVC_UID" \
  && test "$CURRENT_SOURCE_PVC_UID" = "$SAVED_SOURCE_PVC_UID" \
  && test "$CURRENT_SOURCE_PV_UID" = "$SOURCE_PV_UID" \
  && test "$CURRENT_SOURCE_PV_UID" = "$SAVED_SOURCE_PV_UID" \
  || { printf '%s\n' 'STOP: source storage identity changed' >&2; exit 1; }
python scripts/render_kubernetes_single_replica.py deployment \
  --name "$NCT_NAME" --namespace "$NCT_NAMESPACE" --image "$NCT_IMAGE" \
  --pvc-name "$SOURCE_PVC" --storage-class "$SOURCE_CLASS" \
  --storage-size "$SOURCE_SIZE" --pvc-uid "$SOURCE_PVC_UID" \
  --bound-volume-uid "$SOURCE_PV_UID" \
  --storage-report "$SOURCE_REPORT" \
  --storage-report-digest "$SOURCE_REPORT_DIGEST" \
  --output gate4a-source-deployment.json
python -m json.tool gate4a-source-deployment.json
kubectl apply -f gate4a-source-deployment.json
kubectl -n "$NCT_NAMESPACE" rollout status "deployment/$NCT_NAME" --timeout=180s
```

Again verify startup, readiness, existing-administrator sign-in, retained history, and
one evidence download. Never mount source and restore claims into two running NCT
Deployments at the same time. Do not delete any claim or Job until the reviewer accepts
the saved receipts and the original source has passed all checks again.

## Upgrade and rollback boundary

Before an upgrade, record the current image digest, qualified storage identity, report
digest, application/schema compatibility, and a verified database-plus-evidence backup.
Stop the old NCT copy completely before starting the new image. If the new image fails,
start the old image only when its documented schema compatibility permits opening the
current data. Otherwise restore the matching backup before starting that old image.

Forced termination, rescheduling, node loss, backup, restore, upgrade, and rollback are
Kubernetes acceptance gate 4. Until those tests pass, this package must not be described
as Range-ready or mission-ready.

## What successful Gate 3C proves

This profile proves one analysis-only NCT copy on the named cluster and exact tested
volume. It does not prove multiple-copy operation, live collection, general
storage-class approval, Range readiness, mission readiness, or production scale.
