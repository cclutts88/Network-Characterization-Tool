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

## Gate 4B forced-stop, replacement, rescheduling, and node-loss acceptance

Gate 4B uses a fresh qualified target restored by Gate 4A. Do not run these destructive
exercises against production or unique evidence. The rendered Deployment carries
indefinite `NoExecute` tolerations for `node.kubernetes.io/not-ready` and
`node.kubernetes.io/unreachable`. During ambiguous node loss, Kubernetes therefore keeps
the old Pod assigned instead of automatically starting another possible writer. This is
intentional: availability waits for independent node fencing and storage-detachment
proof.

ReadWriteOnce, `Recreate`, a missing Pod object, and the NCT file lock are useful controls,
but none proves by itself that a partitioned node stopped writing. NCT receives no
Kubernetes API token, node power control, storage-controller access, Secret access, or
cluster-wide permissions. The administrator operates only the fixed NCT Deployment and
Jobs in its namespace. Existing infrastructure and storage operators must return the old
node UID, exact attachment identity, fencing result, and detachment result. Record any
broader provider action and its operator separately.

Set these values from the saved Gate 4A exercise and the live fixed resources:

```sh
export GATE4B_SCENARIO='forced-stop-20261012-01'
export SCENARIO_KIND='forced-termination'
export GATE4A_RESTORE_RECEIPT='./gate4a-restore-receipt.json'
export DEPLOYMENT_UID="$(kubectl -n "$NCT_NAMESPACE" get deployment "$NCT_NAME" -o jsonpath='{.metadata.uid}')"
export DEPLOYMENT_GENERATION="$(kubectl -n "$NCT_NAMESPACE" get deployment "$NCT_NAME" -o jsonpath='{.metadata.generation}')"
export POD_NAME="$(kubectl -n "$NCT_NAMESPACE" get pod -l "app.kubernetes.io/name=$NCT_NAME,app.kubernetes.io/component=analysis" -o jsonpath='{.items[0].metadata.name}')"
export POD_UID="$(kubectl -n "$NCT_NAMESPACE" get pod "$POD_NAME" -o jsonpath='{.metadata.uid}')"
export RESTART_COUNT="$(kubectl -n "$NCT_NAMESPACE" get pod "$POD_NAME" -o jsonpath='{.status.containerStatuses[0].restartCount}')"
export NODE_NAME="$(kubectl -n "$NCT_NAMESPACE" get pod "$POD_NAME" -o jsonpath='{.spec.nodeName}')"
export NODE_UID='REPLACE_WITH_UID_RETURNED_BY_CLUSTER_OPERATOR'
export STORAGE_ATTACHMENT_ID='REPLACE_WITH_EXACT_ATTACHMENT_RETURNED_BY_STORAGE_OPERATOR'
```

The saved Gate 4A restore receipt is required as a file. The renderer places this
non-secret receipt in an immutable ConfigMap mounted read-only into the snapshot Job.
The recorder verifies the receipt's own digest, passing status, exact image and build,
restored PVC/PV UIDs, qualification digest, manifest, archive, and inventory before it
records Gate 4B evidence. A typed digest by itself is not accepted.

Before the exercise, use the exact administrator identity that will run it. Every
following line must say `yes` for the namespace shown. A site administrator may apply
the generated files instead when this identity is intentionally more limited:

```sh
for check in \
  'get deployments.apps' 'patch deployments.apps' \
  'get pods' 'list pods' 'watch pods' 'delete pods' \
  'get pods/log' 'create jobs.batch' 'get jobs.batch' 'watch jobs.batch' 'delete jobs.batch' \
  'create configmaps' 'get configmaps' 'delete configmaps' \
  'get serviceaccounts' 'create serviceaccounts' 'patch serviceaccounts' \
  'get persistentvolumeclaims'; do
  verb="${check%% *}"
  resource="${check#* }"
  kubectl auth can-i "$verb" "$resource" -n "$NCT_NAMESPACE"
done
```

The NCT Pod and generated Jobs must still have no API token or RBAC grant. Confirm the
application ServiceAccount cannot read Secrets, exec into Pods, or list cluster-wide
nodes:

```sh
kubectl auth can-i get secrets -n "$NCT_NAMESPACE" \
  --as="system:serviceaccount:$NCT_NAMESPACE:$NCT_NAME-runtime"
kubectl auth can-i create pods/exec -n "$NCT_NAMESPACE" \
  --as="system:serviceaccount:$NCT_NAMESPACE:$NCT_NAME-runtime"
kubectl auth can-i list nodes \
  --as="system:serviceaccount:$NCT_NAMESPACE:$NCT_NAME-runtime"
```

All three lines must say `no`. Cordon, node UID lookup, fencing, and CSI attachment
inspection belong to the site's bounded infrastructure and storage operator identities;
do not add those rights to NCT.

Use one of these exact scenario kinds and a new unique scenario ID for each run:

| Exercise | `SCENARIO_KIND` | Example unique `GATE4B_SCENARIO` |
|---|---|---|
| Forced process termination | `forced-termination` | `forced-stop-20261012-01` |
| Recreate replacement | `recreate-replacement` | `recreate-20261012-01` |
| Controlled rescheduling | `controlled-rescheduling` | `reschedule-20261012-01` |
| Fenced node loss | `node-loss` | `node-loss-20261012-01` |

Stop if the exact image, PVC UID, bound-volume UID, qualification report digest, Gate 4A
receipt, Deployment UID, or attachment identity cannot be established. Save every
generated document, Job log, status observation, selected evidence download, and
provider fencing/detachment record outside the test claim.

### Complete one scenario from start to finish

Use a fresh Gate 4A-restored qualified target for each of the four scenarios. This keeps
one failure's work history, Pod identity, or storage state from being mistaken for the
next scenario's evidence. Follow this order without skipping or reusing a receipt:

1. Keep the restored NCT Deployment scaled to zero. Set the new scenario ID and exact
   kind, then refresh the Deployment UID and generation, restored PVC and volume UIDs,
   qualification digest, restored Pod placeholders, node UID, and attachment identity.
2. While NCT is stopped, record `SCENARIO-before-cold.json`. The cold recorder must
   acquire and release the existing writer lock and pass database, Artifact Registry,
   observation, and retained-evidence checks.
3. Start the one-replica restored Deployment. Refresh the real Pod UID, restart count,
   node UID, and attachment identity. Verify readiness, existing-account sign-in, and
   download one retained evidence file as `SCENARIO-evidence-before.bin`.
4. Create one Running and one Queued retained-evidence job plus one pending admission
   intent. Record `SCENARIO-active-lock.json` and `SCENARIO-before-runtime.json`.
5. Perform exactly one failure exercise. Record `SCENARIO-after-runtime.json` after the
   replacement or restart is Ready.
6. For every scenario, explicitly retry the Interrupted attempt, wait for that single
   retry to complete, and record `SCENARIO-after-retry.json`. The retry is required in
   all four exercises so the same verifier command applies.
7. While the recovered copy is still Ready, repeat sign-in and health checks and download
   the same evidence as `SCENARIO-evidence-after.bin`.
8. Scale the restored Deployment to zero and prove no Pod remains. Then record
   `SCENARIO-released-lock.json` and `SCENARIO-after-cold.json`, run the verifier, and
   archive the receipt with the external fencing/detachment record. Controlled
   rescheduling and node loss also require a destination pre-replacement lock receipt
   after the old writer is fenced, the old attachment is detached, and the destination
   attachment exists, but before the replacement NCT Pod is created.
9. Do not start the next exercise on this target. Create a fresh Gate 4A restore, set a
   new unique scenario ID and kind, and repeat from step 1.

Every scenario archive must contain the before/after runtime snapshots, before/after
cold snapshots, active/final-released lock receipts, the required pre-replacement available-lock receipt for rescheduling and node loss, before/after copies of the same selected
evidence, the after-retry snapshot, generated Job documents and logs, health observations,
the live cluster-observation log, the structured orchestration record, and provider
records. A missing file leaves that scenario unaccepted.

Use these limits and the same renderer command for every snapshot. A cold snapshot
copies the complete locked tree through protected file handles into `/tmp`, then runs
SQLite and evidence checks on that private copy. It never opens the mounted source
database for inspection:

```sh
export SNAPSHOT_MAX_FILES='1000000'
export SNAPSHOT_MAX_BYTES='4398046511104'
export SNAPSHOT_MAX_SECONDS='300'

refresh_runtime_identity() {
  POD_NAME="$(kubectl -n "$NCT_NAMESPACE" get pod \
    -l "app.kubernetes.io/name=$NCT_NAME,app.kubernetes.io/component=analysis" \
    -o jsonpath='{.items[0].metadata.name}')"
  POD_UID="$(kubectl -n "$NCT_NAMESPACE" get pod "$POD_NAME" -o jsonpath='{.metadata.uid}')"
  RESTART_COUNT="$(kubectl -n "$NCT_NAMESPACE" get pod "$POD_NAME" -o jsonpath='{.status.containerStatuses[0].restartCount}')"
  NODE_NAME="$(kubectl -n "$NCT_NAMESPACE" get pod "$POD_NAME" -o jsonpath='{.spec.nodeName}')"
  DEPLOYMENT_GENERATION="$(kubectl -n "$NCT_NAMESPACE" get deployment "$NCT_NAME" -o jsonpath='{.metadata.generation}')"
  printf 'POD=%s UID=%s RESTARTS=%s NODE=%s GENERATION=%s\n' \
    "$POD_NAME" "$POD_UID" "$RESTART_COUNT" "$NODE_NAME" "$DEPLOYMENT_GENERATION"
}
```

For every `failure-snapshot` render, include all of these arguments in addition to the
phase-specific values shown below:

```sh
--gate4a-restore-receipt "$GATE4A_RESTORE_RECEIPT" \
--validation-copy-size "$RESTORE_SIZE" \
--max-files "$SNAPSHOT_MAX_FILES" --max-bytes "$SNAPSHOT_MAX_BYTES" \
--max-seconds "$SNAPSHOT_MAX_SECONDS"
```

For every runtime record, include one Running job, one Queued job, and one pending
automatic-admission intent:

```sh
export RUNNING_JOB_ID='REPLACE_RUNNING_JOB_ID'
export QUEUED_JOB_ID='REPLACE_QUEUED_JOB_ID'
export PENDING_INTENT_ID='REPLACE_PENDING_INTENT_ID'
```

The initial and final cold records omit these IDs and all live-health claims. Runtime
`before-failure` requires a Readiness record. Runtime `after-restart` and `after-retry`
require both Startup and Readiness values in
the exact `TIME|probe|result` format. Apply each rendered document, wait for its Job,
and save the Job log under the matching unique scenario filename:

```sh
kubectl apply -f gate4b-SCENARIO-PHASE-job.json
export SNAPSHOT_JOB="$(python -c 'import json,sys; print(next(x["metadata"]["name"] for x in json.load(open(sys.argv[1]))["items"] if x["kind"]=="Job"))' gate4b-SCENARIO-PHASE-job.json)"
kubectl -n "$NCT_NAMESPACE" wait --for=condition=complete "job/$SNAPSHOT_JOB" --timeout=330s
kubectl -n "$NCT_NAMESPACE" logs "job/$SNAPSHOT_JOB" > gate4b-SCENARIO-PHASE.json
```

This helper is the complete snapshot command used by all five phases:

```sh
record_snapshot() {
  mode="$1"; phase="$2"; stem="$3"; shift 3
  python scripts/render_kubernetes_single_replica.py failure-snapshot \
    --name "$NCT_NAME" --namespace "$NCT_NAMESPACE" --image "$NCT_IMAGE" \
    --pvc-name "$RESTORE_PVC" --storage-class "$RESTORE_CLASS" \
    --storage-size "$RESTORE_SIZE" --pvc-uid "$RESTORE_PVC_UID" \
    --bound-volume-uid "$RESTORE_PV_UID" --storage-report "$RESTORE_REPORT" \
    --storage-report-digest "$RESTORE_REPORT_DIGEST" --mode "$mode" --phase "$phase" \
    --scenario-id "$GATE4B_SCENARIO" --scenario-kind "$SCENARIO_KIND" \
    --application-version "$NCT_APP_VERSION" --build-id "$NCT_BUILD_ID" \
    --deployment-uid "$DEPLOYMENT_UID" --deployment-generation "$DEPLOYMENT_GENERATION" \
    --pod-uid "$POD_UID" --container-restart-count "$RESTART_COUNT" \
    --node-name "$NODE_NAME" --node-uid "$NODE_UID" \
    --storage-attachment-identity "$STORAGE_ATTACHMENT_ID" \
    --gate4a-restore-receipt "$GATE4A_RESTORE_RECEIPT" \
    --validation-copy-size "$RESTORE_SIZE" --max-files "$SNAPSHOT_MAX_FILES" \
    --max-bytes "$SNAPSHOT_MAX_BYTES" --max-seconds "$SNAPSHOT_MAX_SECONDS" \
    "$@" --output "gate4b-$stem-job.json"
  kubectl apply -f "gate4b-$stem-job.json"
  snapshot_job="$(python -c 'import json,sys; print(next(x["metadata"]["name"] for x in json.load(open(sys.argv[1]))["items"] if x["kind"]=="Job"))' "gate4b-$stem-job.json")"
  kubectl -n "$NCT_NAMESPACE" wait --for=condition=complete "job/$snapshot_job" --timeout=330s
  kubectl -n "$NCT_NAMESPACE" logs "job/$snapshot_job" > "gate4b-$stem.json"
}

record_snapshot cold before-failure before-cold

export BEFORE_READY_AT='REPLACE_WITH_before_ready_observed_at'
record_snapshot runtime before-failure before-runtime \
  --tracked-job-id "$RUNNING_JOB_ID" --tracked-job-id "$QUEUED_JOB_ID" \
  --tracked-intent-id "$PENDING_INTENT_ID" \
  --health-transition "$BEFORE_READY_AT|readiness|ready"

refresh_runtime_identity
export REPLACEMENT_CREATED_AT='REPLACE_WITH_replacement_created_observed_at'
export AFTER_READY_AT='REPLACE_WITH_after_ready_observed_at'
record_snapshot runtime after-restart after-runtime \
  --tracked-job-id "$RUNNING_JOB_ID" --tracked-job-id "$QUEUED_JOB_ID" \
  --tracked-intent-id "$PENDING_INTENT_ID" \
  --health-transition "$REPLACEMENT_CREATED_AT|startup|started" \
  --health-transition "$AFTER_READY_AT|readiness|ready"

# After the one explicit retry is Complete:
record_snapshot runtime after-retry after-retry \
  --tracked-job-id "$RUNNING_JOB_ID" --tracked-job-id "$QUEUED_JOB_ID" \
  --tracked-intent-id "$PENDING_INTENT_ID" \
  --health-transition "$REPLACEMENT_CREATED_AT|startup|started" \
  --health-transition "$AFTER_READY_AT|readiness|ready"

# Only after scaling to zero and proving no Pod remains:
record_snapshot cold after-retry after-cold
```

For the initial cold record, use the `failure-snapshot` command shown below with
`--mode cold --phase before-failure` while the Deployment is scaled to zero. Use the
stopped target's retained Pod/node fields from the Gate 4A restore record as historical
diagnostic values; after startup replace them with the live values before any runtime
record. Omit `--tracked-job-id` and `--tracked-intent-id` from this first cold record
because the scenario work does not exist yet. Apply the generated Job, wait for
completion, and save its log as the unique `SCENARIO-before-cold.json`. At the end,
repeat it with
`--mode cold --phase after-retry` and save `SCENARIO-after-cold.json`.

Capture each named event time once. Reuse the exact same value in the live cluster
observation, orchestration event and health transition. Do not run `date` separately for
those three records; even a one-second difference correctly fails verification.

### Record the active writer and pre-failure work

Using the normal NCT interface on the restored test copy, queue two eligible retained-
evidence processing jobs. Wait until one attempt says **Running** while the other remains
**Queued**. Also select a pending automatic-admission record. Save their exact job and
intent IDs. Do not enable scans, schedules, device contact, compaction, migration,
backfill, or backup while a Gate 4B scenario is active.

Render the active-writer probe on the same node. It opens only the already existing lock
file, never creates it, and never opens SQLite. The Job passes only when it reports
`contended`:

```sh
python scripts/render_kubernetes_single_replica.py writer-lock-probe \
  --name "$NCT_NAME" --namespace "$NCT_NAMESPACE" --image "$NCT_IMAGE" \
  --pvc-name "$RESTORE_PVC" --storage-class "$RESTORE_CLASS" \
  --storage-size "$RESTORE_SIZE" --pvc-uid "$RESTORE_PVC_UID" \
  --bound-volume-uid "$RESTORE_PV_UID" --storage-report "$RESTORE_REPORT" \
  --storage-report-digest "$RESTORE_REPORT_DIGEST" --expect contended \
  --scenario-id "$GATE4B_SCENARIO" --scenario-kind "$SCENARIO_KIND" \
  --phase old-writer-active --application-version "$NCT_APP_VERSION" \
  --build-id "$NCT_BUILD_ID" --deployment-uid "$DEPLOYMENT_UID" \
  --deployment-generation "$DEPLOYMENT_GENERATION" --pod-uid "$POD_UID" \
  --node-name "$NODE_NAME" --node-uid "$NODE_UID" \
  --storage-attachment-identity "$STORAGE_ATTACHMENT_ID" \
  --output gate4b-active-lock.json
kubectl apply -f gate4b-active-lock.json
export ACTIVE_LOCK_JOB="$(python -c 'import json; print(next(x["metadata"]["name"] for x in json.load(open("gate4b-active-lock.json"))["items"] if x["kind"]=="Job"))')"
kubectl -n "$NCT_NAMESPACE" wait --for=condition=complete "job/$ACTIVE_LOCK_JOB" --timeout=90s
kubectl -n "$NCT_NAMESPACE" logs "job/$ACTIVE_LOCK_JOB" > gate4b-active-lock-receipt.json
grep -q '"observed":"contended"' gate4b-active-lock-receipt.json
```

Render a runtime snapshot on that node with the selected IDs. Repeat
`--tracked-job-id` and `--tracked-intent-id` for every selected record. A health value
contains a UTC time, probe, and result. The Job reads SQLite in query-only mode and writes
nothing to the data claim:

```sh
export BEFORE_READY_AT='REPLACE_WITH_before_ready_observed_at'
python scripts/render_kubernetes_single_replica.py failure-snapshot \
  --name "$NCT_NAME" --namespace "$NCT_NAMESPACE" --image "$NCT_IMAGE" \
  --pvc-name "$RESTORE_PVC" --storage-class "$RESTORE_CLASS" \
  --storage-size "$RESTORE_SIZE" --pvc-uid "$RESTORE_PVC_UID" \
  --bound-volume-uid "$RESTORE_PV_UID" --storage-report "$RESTORE_REPORT" \
  --storage-report-digest "$RESTORE_REPORT_DIGEST" --mode runtime \
  --phase before-failure --scenario-id "$GATE4B_SCENARIO" \
  --scenario-kind "$SCENARIO_KIND" --application-version "$NCT_APP_VERSION" \
  --build-id "$NCT_BUILD_ID" --deployment-uid "$DEPLOYMENT_UID" \
  --deployment-generation "$DEPLOYMENT_GENERATION" --pod-uid "$POD_UID" \
  --container-restart-count "$RESTART_COUNT" --node-name "$NODE_NAME" \
  --node-uid "$NODE_UID" --storage-attachment-identity "$STORAGE_ATTACHMENT_ID" \
  --gate4a-restore-receipt "$GATE4A_RESTORE_RECEIPT" --validation-copy-size "$RESTORE_SIZE" \
  --tracked-job-id REPLACE_RUNNING_JOB_ID --tracked-job-id REPLACE_QUEUED_JOB_ID \
  --tracked-intent-id REPLACE_PENDING_INTENT_ID \
  --health-transition "$BEFORE_READY_AT|readiness|ready" \
  --output gate4b-before-runtime-job.json
kubectl apply -f gate4b-before-runtime-job.json
export BEFORE_RUNTIME_JOB="$(python -c 'import json; print(next(x["metadata"]["name"] for x in json.load(open("gate4b-before-runtime-job.json"))["items"] if x["kind"]=="Job"))')"
kubectl -n "$NCT_NAMESPACE" wait --for=condition=complete "job/$BEFORE_RUNTIME_JOB" --timeout=300s
kubectl -n "$NCT_NAMESPACE" logs "job/$BEFORE_RUNTIME_JOB" > gate4b-before-runtime.json
```

A cold snapshot must acquire the released writer lock, run database integrity and
foreign-key checks, verify the Artifact Registry and supported evidence references, and
record the complete bounded evidence inventory. If the lock remains owned, the Job fails
instead of reading cold state. Never take the initial cold snapshot after NCT starts.

### Exercise 1: forced process termination

Use the site's existing node/container-runtime operator to abruptly terminate only the
NCT container process on the healthy node. Do not grant exec access or host privileges
to NCT and do not delete the Pod. Save the operator's action or ticket and UTC time.
Confirm the same Pod UID returns Ready with a larger container restart count. Capture an
`after-restart` runtime snapshot. The prior running attempt must be **Interrupted** with
no output, the queued attempt must remain queued or complete once, and the admission
intent must remain attributable. Retry the interrupted item through NCT, capture an
`after-retry` snapshot, and require one new completed attempt whose result says created
or reused.

### Exercise 2: Recreate replacement

Record the current Pod UID, apply the reviewed Deployment again with one replica and
`Recreate`, and request a rollout restart. The old Pod must disappear before a new Pod
UID reaches Startup or Ready. Repeat the active-lock, released-lock, runtime, cold,
sign-in, and evidence checks. Any interval with two Ready NCT Pods or two successful
application writer owners fails the gate.
Retry the Interrupted attempt and capture the required `after-retry` snapshot before
stopping this scenario.

### Exercise 3: controlled rescheduling

Cordon the source node using the site's bounded administrator identity. Scale NCT to
zero and wait for the old Pod to disappear. Obtain explicit CSI/provider evidence that
the exact volume attachment is detached from the source node. Have the storage operator
establish the destination attachment on the selected compatible node and return its
distinct identity. Run the `available` lock probe on that destination node and attachment
before creating the replacement NCT Pod. The probe releases the writer lock but remains
Running as a bounded attachment holder while the replacement is created. Scale to one,
wait for the replacement to become Ready on that same node and attachment, and only then
delete the probe Job. The replacement must use that same destination node UID and attachment identity,
plus the same PVC UID, bound-volume UID, qualification digest, image, and Deployment UID.
Preserve both attachment identities and their event times. Repeat startup, sign-in, retained-evidence,
work-state, and cold checks before uncordoning the source node.
Retry the Interrupted attempt and capture the required `after-retry` snapshot before
stopping this scenario.

### Exercise 4: node loss

Use a fresh Gate 4A-restored target. Power off or externally fence the source node while
NCT has one running and one queued retained-evidence job. The old Pod must remain assigned
and no replacement may appear automatically. A timeout or unavailable node is not
fencing proof. First record readiness loss, then externally fence the source node. Only
after fencing may the operator record that the old writer is conclusively stopped and
detach the exact old storage attachment. Establish a distinct destination attachment on
the compatible second node and run the destination `available` lock probe. Only after it
passes may the administrator force-remove the stale Pod object and create the one-replica
replacement on that node. If the site cannot provide a second node, fencing, destination
attachment, or detachment evidence,
record this scenario as **not accepted**; do not simulate a pass.
Before the loss, preserve its name with `export STALE_POD_NAME="$POD_NAME"`; the bounded
replacement sequence below uses that exact stale object only after fencing, writer-stop,
detachment, destination attachment and destination lock proof have all passed.
After the safe replacement is Ready, retry the Interrupted attempt and capture the
required `after-retry` snapshot before stopping this scenario.

### Record replacement order and external controls

Create `gate4b-cluster-observations.json` live as each event occurs. Do not reconstruct it
from memory. Each sample records the full observed NCT Pod set, Deployment identity and
generation, storage attachments reported by the storage operator, and the simultaneous
writer-owner count established by the lock observations. Save the source `kubectl` JSON
and provider output beside it. A sample has this form:

```json
{
  "schema_version": 1,
  "scenario": {"id": "REPLACE", "kind": "node-loss"},
  "samples": [
    {
      "event": "before_ready",
      "observed_at": "2026-10-12T12:00:00Z",
      "deployment_uid": "REPLACE",
      "deployment_generation": 7,
      "pods": [
        {"pod_uid": "REPLACE_OLD", "node_uid": "REPLACE_OLD_NODE", "phase": "Running", "ready": true, "storage_attachment_identity": "REPLACE_OLD_ATTACHMENT"}
      ],
      "attachments": [
        {"identity": "REPLACE_OLD_ATTACHMENT", "node_uid": "REPLACE_OLD_NODE", "state": "attached"}
      ],
      "writer_owners_observed": 1
    }
  ]
}
```

At every named event, save the raw source observations before adding the corresponding
sample. Use a unique event name in each filename:

```sh
export OBSERVED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
export EVENT_NAME='before_ready'
kubectl -n "$NCT_NAMESPACE" get deployment "$NCT_NAME" -o json \
  > "gate4b-$EVENT_NAME-deployment.json"
kubectl -n "$NCT_NAMESPACE" get pods \
  -l "app.kubernetes.io/name=$NCT_NAME,app.kubernetes.io/component=analysis" -o json \
  > "gate4b-$EVENT_NAME-pods.json"
# Save the storage operator's attachment output as gate4b-$EVENT_NAME-attachments.json.
# Immediately append the sample derived from these files to gate4b-cluster-observations.json.
```

The required event names are the same names used below. The verifier derives old/new
identity, maximum simultaneous Ready Pods, maximum writer owners, attachment movement,
and event times from these samples. It rejects an orchestration record that disagrees.
The observation-log digest is bound into the final receipt.

Create `gate4b-orchestration.json` from the same observations and provider records. Use
exact UTC times and UIDs; do not estimate them. The old and new blocks must match the
before/after snapshot receipts. `max_ready_pods` and `max_writer_owners` must equal the
maxima derived from the cluster-observation log:

```json
{
  "schema_version": 1,
  "scenario": {"id": "REPLACE", "kind": "node-loss"},
  "deployment_uid": "REPLACE",
  "generation_before": 7,
  "generation_after": 9,
  "old": {"pod_uid": "REPLACE", "node_uid": "REPLACE", "container_restart_count": 0, "storage_attachment_identity": "REPLACE_OLD"},
  "new": {"pod_uid": "REPLACE", "node_uid": "REPLACE", "container_restart_count": 0, "storage_attachment_identity": "REPLACE_NEW"},
  "max_ready_pods": 1,
  "max_writer_owners": 1,
  "events": [
    {"event": "before_ready", "at": "2026-10-12T12:00:00Z"},
    {"event": "readiness_lost", "at": "2026-10-12T12:01:00Z"},
    {"event": "node_fenced", "at": "2026-10-12T12:02:00Z"},
    {"event": "old_writer_stopped", "at": "2026-10-12T12:02:00Z"},
    {"event": "storage_detached", "at": "2026-10-12T12:03:00Z"},
    {"event": "storage_attached", "at": "2026-10-12T12:04:00Z"},
    {"event": "pre_replacement_lock_passed", "at": "2026-10-12T12:05:00Z"},
    {"event": "replacement_created", "at": "2026-10-12T12:06:00Z"},
    {"event": "after_ready", "at": "2026-10-12T12:07:00Z"}
  ],
  "fencing": {"required": true, "old_node_uid": "REPLACE", "operator": "REPLACE", "completed_at": "2026-10-12T12:02:00Z", "evidence_sha256": "REPLACE"},
  "detachment": {"required": true, "old_attachment_identity": "REPLACE_OLD", "operator": "REPLACE", "completed_at": "2026-10-12T12:03:00Z", "evidence_sha256": "REPLACE"},
  "no_replacement_before_fencing_and_detachment": true
}
```

For forced termination and Recreate replacement, set both `required` values to `false`
and omit the provider-only events. Controlled rescheduling requires detachment but not
fencing. Node loss requires both records and the explicit no-replacement assertion. The
tool binds the exact external-file hashes and checks event order; it does not interpret
or authenticate the provider's statements.

For controlled rescheduling and node loss, save an `available` lock receipt only after
the old writer is stopped, the old attachment is detached, and the distinct destination
attachment is established. Render it on the destination node with phase
`destination-pre-replacement` and omit `--pod-uid` because the replacement Pod must not
exist yet. Its node UID, new attachment identity, Deployment identity/generation, image,
build, and storage identity must match the later recovered runtime receipt. Its receipt
time must exactly match the cluster-observation sample named
`pre_replacement_lock_passed`. If the storage platform cannot establish a destination
attachment for this bounded probe before NCT is created, the scenario is not accepted.

```sh
export NODE_NAME='REPLACE_DESTINATION_NODE'
export NODE_UID='REPLACE_DESTINATION_NODE_UID_FROM_CLUSTER_OPERATOR'
export STORAGE_ATTACHMENT_ID='REPLACE_NEW_ATTACHMENT_FROM_STORAGE_OPERATOR'
export DEPLOYMENT_GENERATION="$(kubectl -n "$NCT_NAMESPACE" get deployment "$NCT_NAME" -o jsonpath='{.metadata.generation}')"
export DESTINATION_NODE_NAME="$NODE_NAME"
export DESTINATION_NODE_UID="$NODE_UID"
export DESTINATION_ATTACHMENT_ID="$STORAGE_ATTACHMENT_ID"
export PRE_REPLACEMENT_GENERATION="$DEPLOYMENT_GENERATION"
python scripts/render_kubernetes_single_replica.py writer-lock-probe \
  --name "$NCT_NAME" --namespace "$NCT_NAMESPACE" --image "$NCT_IMAGE" \
  --pvc-name "$RESTORE_PVC" --storage-class "$RESTORE_CLASS" --storage-size "$RESTORE_SIZE" \
  --pvc-uid "$RESTORE_PVC_UID" --bound-volume-uid "$RESTORE_PV_UID" \
  --storage-report "$RESTORE_REPORT" --storage-report-digest "$RESTORE_REPORT_DIGEST" \
  --expect available --scenario-id "$GATE4B_SCENARIO" --scenario-kind "$SCENARIO_KIND" \
  --phase destination-pre-replacement --application-version "$NCT_APP_VERSION" \
  --build-id "$NCT_BUILD_ID" --deployment-uid "$DEPLOYMENT_UID" \
  --deployment-generation "$DEPLOYMENT_GENERATION" --node-name "$NODE_NAME" \
  --node-uid "$NODE_UID" --storage-attachment-identity "$STORAGE_ATTACHMENT_ID" \
  --hold-seconds 1800 \
  --output gate4b-pre-replacement-lock.json
kubectl apply -f gate4b-pre-replacement-lock.json
export PRE_LOCK_JOB="$(python -c 'import json; print(next(x["metadata"]["name"] for x in json.load(open("gate4b-pre-replacement-lock.json"))["items"] if x["kind"]=="Job"))')"
export PRE_LOCK_POD=''
for attempt in $(seq 1 90); do
  PRE_LOCK_POD="$(kubectl -n "$NCT_NAMESPACE" get pod -l "job-name=$PRE_LOCK_JOB" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
  [ -n "$PRE_LOCK_POD" ] && break
  sleep 1
done
[ -n "$PRE_LOCK_POD" ] || { echo 'Gate 4B rejected: holding probe Pod was not created'; exit 1; }
kubectl -n "$NCT_NAMESPACE" wait --for=condition=Ready "pod/$PRE_LOCK_POD" --timeout=90s
receipt_ready=false
for attempt in $(seq 1 90); do
  holder_phase="$(kubectl -n "$NCT_NAMESPACE" get pod "$PRE_LOCK_POD" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
  [ "$holder_phase" = 'Running' ] || { echo 'Gate 4B rejected: destination holder ended before its receipt was saved'; exit 1; }
  if kubectl -n "$NCT_NAMESPACE" logs "pod/$PRE_LOCK_POD" \
      > gate4b-pre-replacement-lock-receipt.json 2>/dev/null && \
      grep -q '"observed":"available"' gate4b-pre-replacement-lock-receipt.json; then
    receipt_ready=true
    break
  fi
  sleep 1
done
[ "$receipt_ready" = true ] || { echo 'Gate 4B rejected: destination lock receipt was not produced'; exit 1; }
# Record pre_replacement_lock_passed using checked_at from this receipt.
# Keep PRE_LOCK_JOB running while creating the replacement.
case "$SCENARIO_KIND" in
  controlled-rescheduling)
    kubectl -n "$NCT_NAMESPACE" scale "deployment/$NCT_NAME" --replicas=1 ;;
  node-loss)
    kubectl -n "$NCT_NAMESPACE" delete pod "$STALE_POD_NAME" --force --grace-period=0 ;;
  *) echo 'Gate 4B rejected: holding probe is not valid for this scenario'; exit 1 ;;
esac

deadline=$((SECONDS + 600))
while :; do
  holder_phase="$(kubectl -n "$NCT_NAMESPACE" get pod "$PRE_LOCK_POD" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
  [ "$holder_phase" = 'Running' ] || { echo 'Gate 4B rejected: destination holder ended before replacement was Ready'; exit 1; }
  replacement_ready="$(kubectl -n "$NCT_NAMESPACE" get pod \
    -l "app.kubernetes.io/name=$NCT_NAME,app.kubernetes.io/component=analysis" \
    -o jsonpath='{.items[0].status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)"
  [ "$replacement_ready" = 'True' ] && break
  [ "$SECONDS" -lt "$deadline" ] || { echo 'Gate 4B rejected: replacement did not become Ready before timeout'; exit 1; }
  sleep 2
done

refresh_runtime_identity
[ "$NODE_NAME" = "$DESTINATION_NODE_NAME" ] || { echo 'Gate 4B rejected: replacement used a different node'; exit 1; }
case "$SCENARIO_KIND" in
  controlled-rescheduling)
    [ "$DEPLOYMENT_GENERATION" -eq $((PRE_REPLACEMENT_GENERATION + 1)) ] || { echo 'Gate 4B rejected: scale generation transition is invalid'; exit 1; } ;;
  node-loss)
    [ "$DEPLOYMENT_GENERATION" -eq "$PRE_REPLACEMENT_GENERATION" ] || { echo 'Gate 4B rejected: node-loss generation changed'; exit 1; } ;;
esac
export NODE_UID='REPLACE_RECOVERED_NODE_UID_FROM_CLUSTER_OPERATOR'
export STORAGE_ATTACHMENT_ID='REPLACE_RECOVERED_ATTACHMENT_FROM_STORAGE_OPERATOR'
[ "$NODE_UID" = "$DESTINATION_NODE_UID" ] || { echo 'Gate 4B rejected: destination node identity changed'; exit 1; }
[ "$STORAGE_ATTACHMENT_ID" = "$DESTINATION_ATTACHMENT_ID" ] || { echo 'Gate 4B rejected: destination attachment identity changed'; exit 1; }
kubectl -n "$NCT_NAMESPACE" delete "job/$PRE_LOCK_JOB" --wait=true
```

For controlled rescheduling, scaling from zero to one advances Deployment generation by
exactly one. The pre-replacement receipt remains bound to the pre-scale generation; the
verifier requires the recovered runtime generation to be exactly one greater. Node loss
does not scale the Deployment and requires the same generation on both records.

The loop above rejects the scenario immediately if the holder stops before the replacement
is Ready. After the replacement is Ready on the recorded destination, it verifies the
node, attachment and expected generation transition, then deletes the holder. It retains
the refreshed `POD_UID`, `NODE_NAME`, `NODE_UID`, `DEPLOYMENT_GENERATION`, and
`STORAGE_ATTACHMENT_ID` from the recovered Pod, cluster operator, and storage operator.
After retry/evidence checks, scale to zero and create a
separate available receipt with phase `replacement-writer-released` and that recovered
Pod UID. Reusing the pre-replacement receipt, old identity, or stale values fails.

```sh
refresh_runtime_identity
export NODE_UID='REPLACE_RECOVERED_NODE_UID_FROM_CLUSTER_OPERATOR'
export STORAGE_ATTACHMENT_ID='REPLACE_RECOVERED_ATTACHMENT_FROM_STORAGE_OPERATOR'
kubectl -n "$NCT_NAMESPACE" scale "deployment/$NCT_NAME" --replicas=0
kubectl -n "$NCT_NAMESPACE" wait --for=delete \
  pod -l "app.kubernetes.io/name=$NCT_NAME,app.kubernetes.io/component=analysis" --timeout=180s
python scripts/render_kubernetes_single_replica.py writer-lock-probe \
  --name "$NCT_NAME" --namespace "$NCT_NAMESPACE" --image "$NCT_IMAGE" \
  --pvc-name "$RESTORE_PVC" --storage-class "$RESTORE_CLASS" --storage-size "$RESTORE_SIZE" \
  --pvc-uid "$RESTORE_PVC_UID" --bound-volume-uid "$RESTORE_PV_UID" \
  --storage-report "$RESTORE_REPORT" --storage-report-digest "$RESTORE_REPORT_DIGEST" \
  --expect available --scenario-id "$GATE4B_SCENARIO" --scenario-kind "$SCENARIO_KIND" \
  --phase replacement-writer-released --application-version "$NCT_APP_VERSION" \
  --build-id "$NCT_BUILD_ID" --deployment-uid "$DEPLOYMENT_UID" \
  --deployment-generation "$DEPLOYMENT_GENERATION" --pod-uid "$POD_UID" \
  --node-name "$NODE_NAME" --node-uid "$NODE_UID" \
  --storage-attachment-identity "$STORAGE_ATTACHMENT_ID" \
  --output gate4b-released-lock.json
kubectl apply -f gate4b-released-lock.json
export RELEASED_LOCK_JOB="$(python -c 'import json; print(next(x["metadata"]["name"] for x in json.load(open("gate4b-released-lock.json"))["items"] if x["kind"]=="Job"))')"
kubectl -n "$NCT_NAMESPACE" wait --for=condition=complete "job/$RELEASED_LOCK_JOB" --timeout=90s
kubectl -n "$NCT_NAMESPACE" logs "job/$RELEASED_LOCK_JOB" > gate4b-released-lock-receipt.json
grep -q '"observed":"available"' gate4b-released-lock-receipt.json
```

### Finish and verify each scenario

After retry and verification, download the selected evidence while the recovered copy is
still Ready. Use the exact same retained-evidence URL before and after. The following
keeps the password out of command history, stores the secure session only in a private
temporary cookie jar, and verifies that the two downloads match:

```sh
export NCT_BASE_URL="https://$NCT_DNS"
export EVIDENCE_DOWNLOAD_URL='/api/scan-runs/REPLACE_RUN_ID/artifacts/REPLACE_ARTIFACT'
export NCT_LOGIN_USER='REPLACE_EXISTING_ADMIN'
read -r -s -p 'NCT password: ' NCT_LOGIN_PASSWORD; printf '\n'
export NCT_LOGIN_PASSWORD
umask 077
python -c 'import json,os; print(json.dumps({"username":os.environ["NCT_LOGIN_USER"],"password":os.environ["NCT_LOGIN_PASSWORD"]}))' > gate4b-login.json
curl --fail --silent --show-error --cacert "$TRUSTED_CA" \
  -c gate4b-cookie.jar -H 'Content-Type: application/json' \
  --data-binary @gate4b-login.json "$NCT_BASE_URL/api/auth/login" > gate4b-login-result.json
rm -f gate4b-login.json
unset NCT_LOGIN_PASSWORD
curl --fail --silent --show-error --cacert "$TRUSTED_CA" -b gate4b-cookie.jar \
  "$NCT_BASE_URL$EVIDENCE_DOWNLOAD_URL" --output selected-evidence-before.bin
# Repeat the preceding download after recovery as selected-evidence-after.bin.
sha256sum selected-evidence-before.bin selected-evidence-after.bin
rm -f gate4b-cookie.jar gate4b-login-result.json
```

The two SHA-256 values must match; the verifier repeats that check. Refresh all recovered
runtime identities, then scale the application to zero and prove no Pod remains. Render
the lock probe with `--expect available --phase replacement-writer-released` and the
recovered `--pod-uid`; it must acquire and release
the existing lock without creating or replacing it. Record the final cold snapshot and
run the local verifier with the saved runtime, cold, lock, and download records:

```sh
python scripts/nct_kubernetes_failure_evidence.py verify \
  --before-runtime gate4b-before-runtime.json \
  --after-runtime gate4b-after-runtime.json \
  --before-cold gate4b-before-cold.json \
  --after-cold gate4b-after-cold.json \
  --after-retry gate4b-after-retry.json \
  --active-lock-receipt gate4b-active-lock-receipt.json \
  --released-lock-receipt gate4b-released-lock-receipt.json \
  --orchestration-record gate4b-orchestration.json \
  --cluster-observations gate4b-cluster-observations.json \
  --selected-evidence-before selected-evidence-before.bin \
  --selected-evidence-after selected-evidence-after.bin \
  --max-evidence-bytes 1073741824 --max-provider-bytes 16777216 \
  --max-seconds 300 \
  --output gate4b-scenario-receipt.json
```

For controlled rescheduling, also add:

```sh
--pre-replacement-lock-receipt gate4b-pre-replacement-lock-receipt.json \
--detachment-evidence provider-storage-detachment.txt
```

For node loss, add both external records:

```sh
--pre-replacement-lock-receipt gate4b-pre-replacement-lock-receipt.json \
--fencing-evidence provider-node-fencing.txt \
--detachment-evidence provider-storage-detachment.txt
```

The verifier rejects changed installation bindings, missing evidence, reduced observation
counts, changed downloads, false completion of interrupted work, duplicated queued work,
lost attribution, malformed retry history, and invalid receipts. SHA-256 detects changed
records; it is not an authenticated signature. Provider fencing and storage-detachment
records remain human-reviewed external evidence and are never replaced by this receipt.

Stop the gate immediately for a rolling update, more than one replica, an autoscaler,
automatic replacement during ambiguous node loss, a successful `available` lock probe
while NCT is Ready, two overlapping writers, changed storage or image identity, failed
database/evidence/download checks, disappeared or duplicated work, active destructive
maintenance, or a need to grant NCT Kubernetes API access. Keep Gate 4B open until all
four exact-cluster scenarios and independent review pass.

## Gate 4C guarded upgrade and rollback

Gate 4C is an administrator-only acceptance exercise. It does not add an analyst-facing
upgrade control. Use an isolated Gate 4A-restored copy until this complete exercise has
passed. Keep the original source, the cold backup, the candidate claim, and every receipt
until independent review is complete.

An image rollback changes the application. A data rollback restores the complete saved
state. They are separate decisions. The old image may reopen the candidate claim only
when the old image's own machine-readable contract proves that it can read and write the
exact resulting schema, data layout, and completed migration plan. Missing or uncertain
compatibility fails closed:

> Rollback blocked: the old image is not verified for the current data. Nothing was
> opened or changed.

The safe default is restoration of the verified pre-upgrade backup into another empty,
qualified claim. Never restore over the source or failed candidate claim. Restoration
returns NCT to the recorded backup time; later changes are not included.

This package establishes the first **Gate 4C-capable baseline**. Both the old and the
candidate image in a Gate 4C exercise must provide the image-owned contract and schema
ledger described below. A pre-contract release uses the earlier Gate 4A backup/restore
recovery procedure; it is not eligible to pass Gate 4C. Gate 4C remains open until a
future baseline-to-candidate exercise passes on the exact target cluster and storage.

### 1. Record the exact release and cluster identities

Start from the Gate 4A and 4B variables, then record both immutable images and a new
scenario identifier:

```sh
export OLD_IMAGE='registry.example/nct@sha256:REPLACE_OLD_64_HEX_DIGEST'
export NEW_IMAGE='registry.example/nct@sha256:REPLACE_NEW_64_HEX_DIGEST'
export GATE4C_SCENARIO='upgrade-REPLACE_DATE-REPLACE_UNIQUE_SUFFIX'
export DEPLOYMENT_UID="$(kubectl -n "$NCT_NAMESPACE" get deployment "$NCT_NAME" -o jsonpath='{.metadata.uid}')"
export DEPLOYMENT_GENERATION="$(kubectl -n "$NCT_NAMESPACE" get deployment "$NCT_NAME" -o jsonpath='{.metadata.generation}')"
export OLD_POD="$(kubectl -n "$NCT_NAMESPACE" get pod -l "app.kubernetes.io/name=$NCT_NAME,app.kubernetes.io/component=analysis" -o jsonpath='{.items[0].metadata.name}')"
export OLD_POD_UID="$(kubectl -n "$NCT_NAMESPACE" get pod "$OLD_POD" -o jsonpath='{.metadata.uid}')"
export OLD_NODE_NAME="$(kubectl -n "$NCT_NAMESPACE" get pod "$OLD_POD" -o jsonpath='{.spec.nodeName}')"
export OLD_NODE_UID="$(kubectl get node "$OLD_NODE_NAME" -o jsonpath='{.metadata.uid}')"
export OLD_RUNTIME_IMAGE_ID="$(kubectl -n "$NCT_NAMESPACE" get pod "$OLD_POD" -o jsonpath='{.status.containerStatuses[0].imageID}')"
```

Get an infrastructure-operator record of the exact storage attachment identity. Record
the live PVC and PV UIDs again. A name match is insufficient. Stop for more than one NCT
Pod, an autoscaler, a rolling strategy, an unexpected image ID, missing attachment
identity, or changed storage qualification.

### 2. Read the contract owned by each image

The contract Job has no data volume, API token, RBAC, Secret, or network capability. It
starts the exact image only to report that image's application version, build, commit,
readable schema versions, writable target, evidence-layout contract, migration plan, and
contract digest.

```sh
python scripts/render_kubernetes_single_replica.py upgrade-contract \
  --name "$NCT_NAME" --namespace "$NCT_NAMESPACE" --image "$OLD_IMAGE" \
  --output gate4c-old-contract-job.json
kubectl apply -f gate4c-old-contract-job.json
OLD_CONTRACT_JOB="$(python -c 'import json; print(next(x["metadata"]["name"] for x in json.load(open("gate4c-old-contract-job.json"))["items"] if x["kind"]=="Job"))')"
kubectl -n "$NCT_NAMESPACE" wait --for=condition=complete "job/$OLD_CONTRACT_JOB" --timeout=90s
OLD_CONTRACT_POD="$(kubectl -n "$NCT_NAMESPACE" get pod -l "job-name=$OLD_CONTRACT_JOB" -o jsonpath='{.items[0].metadata.name}')"
OLD_CONTRACT_RUNTIME_IMAGE_ID="$(kubectl -n "$NCT_NAMESPACE" get pod "$OLD_CONTRACT_POD" -o jsonpath='{.status.containerStatuses[0].imageID}')"
kubectl -n "$NCT_NAMESPACE" logs "job/$OLD_CONTRACT_JOB" > gate4c-old-contract-raw.json
python scripts/nct_kubernetes_upgrade.py bind-contract \
  --contract gate4c-old-contract-raw.json --requested-image "$OLD_IMAGE" \
  --runtime-image-id "$OLD_CONTRACT_RUNTIME_IMAGE_ID" --output gate4c-old-contract.json

python scripts/render_kubernetes_single_replica.py upgrade-contract \
  --name "$NCT_NAME" --namespace "$NCT_NAMESPACE" --image "$NEW_IMAGE" \
  --output gate4c-new-contract-job.json
kubectl apply -f gate4c-new-contract-job.json
NEW_CONTRACT_JOB="$(python -c 'import json; print(next(x["metadata"]["name"] for x in json.load(open("gate4c-new-contract-job.json"))["items"] if x["kind"]=="Job"))')"
kubectl -n "$NCT_NAMESPACE" wait --for=condition=complete "job/$NEW_CONTRACT_JOB" --timeout=90s
NEW_CONTRACT_POD="$(kubectl -n "$NCT_NAMESPACE" get pod -l "job-name=$NEW_CONTRACT_JOB" -o jsonpath='{.items[0].metadata.name}')"
NEW_CONTRACT_RUNTIME_IMAGE_ID="$(kubectl -n "$NCT_NAMESPACE" get pod "$NEW_CONTRACT_POD" -o jsonpath='{.status.containerStatuses[0].imageID}')"
kubectl -n "$NCT_NAMESPACE" logs "job/$NEW_CONTRACT_JOB" > gate4c-new-contract-raw.json
python scripts/nct_kubernetes_upgrade.py bind-contract \
  --contract gate4c-new-contract-raw.json --requested-image "$NEW_IMAGE" \
  --runtime-image-id "$NEW_CONTRACT_RUNTIME_IMAGE_ID" --output gate4c-new-contract.json
export OLD_CONTRACT_DIGEST="$(python -c 'import json; print(json.load(open("gate4c-old-contract.json"))["contract_digest"])')"
export NEW_CONTRACT_DIGEST="$(python -c 'import json; print(json.load(open("gate4c-new-contract.json"))["contract_digest"])')"
export OLD_APP_VERSION="$(python -c 'import json; print(json.load(open("gate4c-old-contract.json"))["application_version"])')"
export OLD_BUILD_ID="$(python -c 'import json; print(json.load(open("gate4c-old-contract.json"))["build_id"])')"
export NEW_APP_VERSION="$(python -c 'import json; print(json.load(open("gate4c-new-contract.json"))["application_version"])')"
export NEW_BUILD_ID="$(python -c 'import json; print(json.load(open("gate4c-new-contract.json"))["build_id"])')"
```

Stop if either image cannot produce a bound contract or if its observed runtime image
digest differs from the requested image. Do not label a pre-contract release as a
Gate 4C old image.

### 3. Prove the old writer stopped and create the cold backup

Download the selected retained evidence once and save its exact URL and SHA-256. Record
successful existing-account sign-in, `/health/startup`, and `/health/readiness`. Then
scale NCT to zero, wait for the Pod to disappear, and run the existing writer-lock probe.
Do not proceed while active saved work or destructive maintenance is present.

Define this helper and run the first check while the old copy is still Ready. Set
`NCT_LOGIN_USER` to an existing administrator and `EVIDENCE_DOWNLOAD_URL` to the exact
saved evidence link selected before the exercise. The helper prompts privately for the
password for each running phase, creates credential files with owner-only permissions,
then deletes and unsets the credential:

```sh
export NCT_BASE_URL="https://$NCT_DNS"
export NCT_LOGIN_USER='REPLACE_EXISTING_ADMIN_USERNAME'
export EVIDENCE_DOWNLOAD_URL='/REPLACE_WITH_EXACT_SAVED_EVIDENCE_PATH'
gate4c_capture_checks () {
  phase="$1"; stem="$2"; evidence="$3"
  umask 077
  gate4c_cleanup_credentials () {
    rm -f "${stem}-login.json" "${stem}-cookie.jar" "${stem}-login-result.json"
    unset NCT_LOGIN_PASSWORD
  }
  printf 'Password for %s: ' "$NCT_LOGIN_USER" >&2
  read -r -s NCT_LOGIN_PASSWORD || { gate4c_cleanup_credentials; return 1; }
  printf '\n' >&2
  export NCT_LOGIN_PASSWORD
  python -c 'import json,os; print(json.dumps({"username":os.environ["NCT_LOGIN_USER"],"password":os.environ["NCT_LOGIN_PASSWORD"]}))' > "${stem}-login.json" || \
    { gate4c_cleanup_credentials; return 1; }
  login_status="$(curl --silent --show-error --cacert "$TRUSTED_CA" -c "${stem}-cookie.jar" \
    -H 'Content-Type: application/json' --data-binary @"${stem}-login.json" \
    --output "${stem}-login-result.json" --write-out '%{http_code}' \
    "$NCT_BASE_URL/api/auth/login")" || { gate4c_cleanup_credentials; return 1; }
  startup_status="$(curl --silent --show-error --cacert "$TRUSTED_CA" \
    --output "${stem}-startup.json" --write-out '%{http_code}' \
    "$NCT_BASE_URL/health/startup")" || { gate4c_cleanup_credentials; return 1; }
  readiness_status="$(curl --silent --show-error --cacert "$TRUSTED_CA" \
    --output "${stem}-readiness.json" --write-out '%{http_code}' \
    "$NCT_BASE_URL/health/readiness")" || { gate4c_cleanup_credentials; return 1; }
  evidence_status="$(curl --silent --show-error --cacert "$TRUSTED_CA" \
    -b "${stem}-cookie.jar" --output "$evidence" --write-out '%{http_code}' \
    "$NCT_BASE_URL$EVIDENCE_DOWNLOAD_URL")" || { gate4c_cleanup_credentials; return 1; }
  if [ "$login_status" != 200 ] || [ "$startup_status" != 200 ] || \
     [ "$readiness_status" != 200 ] || [ "$evidence_status" != 200 ] || \
     [ ! -s "$evidence" ]; then
    echo "Gate 4C rejected: sign-in, health, or evidence download did not succeed" >&2
    rm -f "${stem}-web.json" "$evidence"
    gate4c_cleanup_credentials
    return 1
  fi
  PHASE="$phase" STARTUP_STATUS="$startup_status" READINESS_STATUS="$readiness_status" \
    OUT="${stem}-web.json" python -c 'import json,os; json.dump({"phase":os.environ["PHASE"],"startup_status":int(os.environ["STARTUP_STATUS"]),"readiness_status":int(os.environ["READINESS_STATUS"]),"existing_account_signin":True},open(os.environ["OUT"],"w"))' || \
    { gate4c_cleanup_credentials; return 1; }
  gate4c_cleanup_credentials
}
gate4c_capture_checks before-upgrade gate4c-before selected-evidence-before.bin
gate4c_observe () {
  phase="$1"; ready="$2"; writer_receipt="$3"; generation="$4"; pod_uid="$5"; node_uid="$6"
  attachment="$7"; pvc_uid="$8"; pv_uid="$9"
  writer_owners="$(WRITER_RECEIPT="$writer_receipt" python -c 'import hashlib,json,os,sys; p=json.load(open(os.environ["WRITER_RECEIPT"])); a=p.get("attestation",{}); b={k:v for k,v in p.items() if k!="attestation"}; d=hashlib.sha256(json.dumps(b,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()).hexdigest(); w=(p.get("writer_lock") or {}).get("observed"); sys.exit(1) if p.get("status")!="pass" or a.get("algorithm")!="sha256" or a.get("digest")!=d or w not in {"available","contended"} else print(1 if w=="contended" else 0)')" || {
    echo 'Gate 4C rejected: writer-lock receipt is missing or invalid' >&2
    return 1
  }
  case "$phase" in
    candidate-ready|rollback-ready) [ "$writer_owners" = 1 ] || return 1 ;;
    old-stopped|candidate-stopped|rollback-stopped) [ "$writer_owners" = 0 ] || return 1 ;;
    candidate-failed) : ;;
  esac
  if [ -f gate4c-cluster-observations.json ]; then
    set -- --previous gate4c-cluster-observations.json --overwrite
  else
    set --
  fi
  python scripts/nct_kubernetes_upgrade.py observe-cluster \
    --scenario-id "$GATE4C_SCENARIO" --phase "$phase" \
    --ready-pods "$ready" --writer-owners "$writer_owners" \
    --writer-receipt "$writer_receipt" \
    --deployment-uid "$DEPLOYMENT_UID" --deployment-generation "$generation" \
    --pod-uid "$pod_uid" --node-uid "$node_uid" \
    --storage-attachment-identity "$attachment" --pvc-uid "$pvc_uid" \
    --bound-volume-uid "$pv_uid" "$@" --output gate4c-cluster-observations.json
}
gate4c_probe_writer () {
  phase="$1"; expected="$2"; image="$3"; app_version="$4"; build_id="$5"
  generation="$6"; pod_uid="$7"; node_name="$8"; node_uid="$9"; shift 9
  attachment="$1"; stem="$2"
  probe_pvc="${GATE4C_PROBE_PVC:-$RESTORE_PVC}"
  probe_class="${GATE4C_PROBE_CLASS:-$RESTORE_CLASS}"
  probe_size="${GATE4C_PROBE_SIZE:-$RESTORE_SIZE}"
  probe_pvc_uid="${GATE4C_PROBE_PVC_UID:-$RESTORE_PVC_UID}"
  probe_pv_uid="${GATE4C_PROBE_PV_UID:-$RESTORE_PV_UID}"
  probe_report="${GATE4C_PROBE_REPORT:-$RESTORE_REPORT}"
  probe_report_digest="${GATE4C_PROBE_REPORT_DIGEST:-$RESTORE_REPORT_DIGEST}"
  python scripts/render_kubernetes_single_replica.py writer-lock-probe \
    --name "$NCT_NAME" --namespace "$NCT_NAMESPACE" --image "$image" \
    --pvc-name "$probe_pvc" --storage-class "$probe_class" --storage-size "$probe_size" \
    --pvc-uid "$probe_pvc_uid" --bound-volume-uid "$probe_pv_uid" \
    --storage-report "$probe_report" --storage-report-digest "$probe_report_digest" \
    --expect "$expected" --scenario-id "$GATE4C_SCENARIO" --scenario-kind guarded-upgrade \
    --phase "$phase" --application-version "$app_version" --build-id "$build_id" \
    --deployment-uid "$DEPLOYMENT_UID" --deployment-generation "$generation" \
    --pod-uid "$pod_uid" --node-name "$node_name" --node-uid "$node_uid" \
    --storage-attachment-identity "$attachment" --output "${stem}-job.json"
  kubectl apply -f "${stem}-job.json"
  writer_job="$(STEM="$stem" python -c 'import json,os; print(next(x["metadata"]["name"] for x in json.load(open(os.environ["STEM"]+"-job.json"))["items"] if x["kind"]=="Job"))')"
  kubectl -n "$NCT_NAMESPACE" wait --for=condition=complete "job/$writer_job" --timeout=90s
  kubectl -n "$NCT_NAMESPACE" logs "job/$writer_job" > "${stem}-receipt.json"
}
```

After the old Pod has disappeared, create the required released-writer receipt and first
cluster observation:

```sh
kubectl -n "$NCT_NAMESPACE" scale "deployment/$NCT_NAME" --replicas=0
kubectl -n "$NCT_NAMESPACE" wait --for=delete pod \
  -l "app.kubernetes.io/name=$NCT_NAME,app.kubernetes.io/component=analysis" --timeout=180s
python scripts/render_kubernetes_single_replica.py writer-lock-probe \
  --name "$NCT_NAME" --namespace "$NCT_NAMESPACE" --image "$OLD_IMAGE" \
  --pvc-name "$RESTORE_PVC" --storage-class "$RESTORE_CLASS" --storage-size "$RESTORE_SIZE" \
  --pvc-uid "$RESTORE_PVC_UID" --bound-volume-uid "$RESTORE_PV_UID" \
  --storage-report "$RESTORE_REPORT" --storage-report-digest "$RESTORE_REPORT_DIGEST" \
  --expect available --scenario-id "$GATE4C_SCENARIO" --scenario-kind guarded-upgrade \
  --phase old-writer-released --application-version "$OLD_APP_VERSION" \
  --build-id "$OLD_BUILD_ID" --deployment-uid "$DEPLOYMENT_UID" \
  --deployment-generation "$DEPLOYMENT_GENERATION" --pod-uid "$OLD_POD_UID" \
  --node-name "$OLD_NODE_NAME" --node-uid "$OLD_NODE_UID" \
  --storage-attachment-identity "$STORAGE_ATTACHMENT_ID" \
  --output gate4c-old-writer-released-job.json
kubectl apply -f gate4c-old-writer-released-job.json
OLD_LOCK_JOB="$(python -c 'import json; print(next(x["metadata"]["name"] for x in json.load(open("gate4c-old-writer-released-job.json"))["items"] if x["kind"]=="Job"))')"
kubectl -n "$NCT_NAMESPACE" wait --for=condition=complete "job/$OLD_LOCK_JOB" --timeout=90s
kubectl -n "$NCT_NAMESPACE" logs "job/$OLD_LOCK_JOB" > gate4c-old-writer-released-receipt.json
gate4c_observe old-stopped 0 gate4c-old-writer-released-receipt.json \
  "$DEPLOYMENT_GENERATION" "$OLD_POD_UID" "$OLD_NODE_UID" \
  "$STORAGE_ATTACHMENT_ID" "$RESTORE_PVC_UID" "$RESTORE_PV_UID"
```

Now run the complete Gate 4A cold-backup procedure with `OLD_IMAGE`. It must create a
fresh `backup_verified` receipt for this exact image, build, source PVC/PV, qualification
report, archive, and inventory root before any candidate write. Keep the backup receipt,
manifest, archive, and their separately recorded digests outside every NCT data claim.

Export the exact stored Gate 4A manifest through a one-purpose read-only Job. This Job
has no API token or writeable volume:

```sh
python scripts/render_kubernetes_single_replica.py upgrade-backup-manifest \
  --name "$NCT_NAME" --namespace "$NCT_NAMESPACE" --image "$NEW_IMAGE" \
  --backup-id "$BACKUP_ID" --pvc-name "$BACKUP_PVC" \
  --storage-class "$BACKUP_CLASS" --storage-size "$BACKUP_SIZE" \
  --pvc-uid "$BACKUP_PVC_UID" --bound-volume-uid "$BACKUP_PV_UID" \
  --storage-report "$BACKUP_REPORT" --storage-report-digest "$BACKUP_REPORT_DIGEST" \
  --output gate4c-backup-manifest-job.json
kubectl apply -f gate4c-backup-manifest-job.json
BACKUP_MANIFEST_JOB="$(python -c 'import json; print(next(x["metadata"]["name"] for x in json.load(open("gate4c-backup-manifest-job.json"))["items"] if x["kind"]=="Job"))')"
kubectl -n "$NCT_NAMESPACE" wait --for=condition=complete "job/$BACKUP_MANIFEST_JOB" --timeout=90s
kubectl -n "$NCT_NAMESPACE" logs "job/$BACKUP_MANIFEST_JOB" > gate4a-backup-manifest.json
```

### 4. Inspect the cold source and run fail-closed preflight

The inspection Job opens no application database for writing. It first acquires the
existing writer lock, hashes the bounded data tree, checks database integrity and the
image-owned schema ledger, verifies every registered artifact, rejects active work, and
records exact Kubernetes and storage identities.

```sh
python scripts/render_kubernetes_single_replica.py upgrade-inspection \
  --name "$NCT_NAME" --namespace "$NCT_NAMESPACE" --image "$OLD_IMAGE" \
  --pvc-name "$RESTORE_PVC" --storage-class "$RESTORE_CLASS" --storage-size "$RESTORE_SIZE" \
  --pvc-uid "$RESTORE_PVC_UID" --bound-volume-uid "$RESTORE_PV_UID" \
  --storage-report "$RESTORE_REPORT" --storage-report-digest "$RESTORE_REPORT_DIGEST" \
  --scenario-id "$GATE4C_SCENARIO" --phase before-upgrade \
  --runtime-image-id "$OLD_RUNTIME_IMAGE_ID" --contract-digest "$OLD_CONTRACT_DIGEST" \
  --deployment-uid "$DEPLOYMENT_UID" --deployment-generation "$DEPLOYMENT_GENERATION" \
  --pod-uid "$OLD_POD_UID" --node-name "$OLD_NODE_NAME" --node-uid "$OLD_NODE_UID" \
  --storage-attachment-identity "$STORAGE_ATTACHMENT_ID" \
  --output gate4c-before-inspection-job.json
kubectl apply -f gate4c-before-inspection-job.json
BEFORE_JOB="$(python -c 'import json; print(next(x["metadata"]["name"] for x in json.load(open("gate4c-before-inspection-job.json"))["items"] if x["kind"]=="Job"))')"
kubectl -n "$NCT_NAMESPACE" wait --for=condition=complete "job/$BEFORE_JOB" --timeout=330s
kubectl -n "$NCT_NAMESPACE" logs "job/$BEFORE_JOB" > gate4c-before-inspection.json

python scripts/nct_kubernetes_upgrade.py plan \
  --scenario-id "$GATE4C_SCENARIO" --old-image "$OLD_IMAGE" --new-image "$NEW_IMAGE" \
  --old-contract gate4c-old-contract.json --new-contract gate4c-new-contract.json \
  --before-inspection gate4c-before-inspection.json \
  --backup-receipt gate4a-backup-receipt.json \
  --backup-manifest gate4a-backup-manifest.json \
  --backup-receipt-digest "$BACKUP_RECEIPT_DIGEST" \
  --expected-candidate-generation "$((DEPLOYMENT_GENERATION + 1))" \
  --expected-rollback-generation "$((DEPLOYMENT_GENERATION + 2))" \
  --output gate4c-plan.json
```

The plan says `direct` only for an exact unchanged schema, data layout, and migration
plan that the old image declares readable and writable. `restore` means the separate
empty-target restore is required. Unknown means blocked; it never means compatible.

If preflight fails, do not start the candidate. Reinspect the complete stopped tree. The
old image may restart on it only after the before/after inventory roots prove that no
candidate mutation occurred.

### 5. Start exactly one candidate and verify it

Record a `preflight-passed` event, render the normal single-replica Deployment with
`NEW_IMAGE`, and apply it only after the old Pod and every inspection Job have ended.
The Deployment remains `Recreate` with one replica. Startup writes a durable migration
ledger before other schema initialization. Readiness stays unavailable until the
migration and recovery sequence completes. An interrupted attempt is resumed through
the same idempotent migration identifier and attempt count.

```sh
export OLD_APP_VERSION="$(python -c 'import json; print(json.load(open("gate4c-old-contract.json"))["application_version"])')"
export OLD_BUILD_ID="$(python -c 'import json; print(json.load(open("gate4c-old-contract.json"))["build_id"])')"
export NEW_APP_VERSION="$(python -c 'import json; print(json.load(open("gate4c-new-contract.json"))["application_version"])')"
export NEW_BUILD_ID="$(python -c 'import json; print(json.load(open("gate4c-new-contract.json"))["build_id"])')"
python scripts/render_kubernetes_single_replica.py deployment \
  --name "$NCT_NAME" --namespace "$NCT_NAMESPACE" --image "$NEW_IMAGE" \
  --pvc-name "$RESTORE_PVC" --storage-class "$RESTORE_CLASS" --storage-size "$RESTORE_SIZE" \
  --pvc-uid "$RESTORE_PVC_UID" --bound-volume-uid "$RESTORE_PV_UID" \
  --storage-report "$RESTORE_REPORT" --storage-report-digest "$RESTORE_REPORT_DIGEST" \
  --output gate4c-candidate-deployment.json
kubectl apply -f gate4c-candidate-deployment.json
kubectl -n "$NCT_NAMESPACE" rollout status "deployment/$NCT_NAME" --timeout=300s

export CANDIDATE_POD="$(kubectl -n "$NCT_NAMESPACE" get pod -l "app.kubernetes.io/name=$NCT_NAME,app.kubernetes.io/component=analysis" -o jsonpath='{.items[0].metadata.name}')"
export CANDIDATE_POD_UID="$(kubectl -n "$NCT_NAMESPACE" get pod "$CANDIDATE_POD" -o jsonpath='{.metadata.uid}')"
export CANDIDATE_NODE_NAME="$(kubectl -n "$NCT_NAMESPACE" get pod "$CANDIDATE_POD" -o jsonpath='{.spec.nodeName}')"
export CANDIDATE_NODE_UID="$(kubectl get node "$CANDIDATE_NODE_NAME" -o jsonpath='{.metadata.uid}')"
export CANDIDATE_RUNTIME_IMAGE_ID="$(kubectl -n "$NCT_NAMESPACE" get pod "$CANDIDATE_POD" -o jsonpath='{.status.containerStatuses[0].imageID}')"
export CANDIDATE_GENERATION="$(kubectl -n "$NCT_NAMESPACE" get deployment "$NCT_NAME" -o jsonpath='{.metadata.generation}')"
export CANDIDATE_ATTACHMENT_ID='REPLACE_WITH_CURRENT_ATTACHMENT_FROM_STORAGE_OPERATOR'
gate4c_capture_checks after-upgrade gate4c-after selected-evidence-after.bin
gate4c_probe_writer candidate-writer-active contended "$NEW_IMAGE" "$NEW_APP_VERSION" \
  "$NEW_BUILD_ID" "$CANDIDATE_GENERATION" "$CANDIDATE_POD_UID" \
  "$CANDIDATE_NODE_NAME" "$CANDIDATE_NODE_UID" "$CANDIDATE_ATTACHMENT_ID" \
  gate4c-candidate-writer-active
gate4c_observe candidate-ready 1 gate4c-candidate-writer-active-receipt.json \
  "$CANDIDATE_GENERATION" "$CANDIDATE_POD_UID" \
  "$CANDIDATE_NODE_UID" "$CANDIDATE_ATTACHMENT_ID" "$RESTORE_PVC_UID" "$RESTORE_PV_UID"
```

After the candidate becomes Ready, record its Pod, node, runtime image ID, Deployment
generation, attachment identity, and the exact PVC/PV identities. Verify the same
existing account, retained history, table counts, and evidence URL. Scale the candidate
to zero, prove its writer released, then render `upgrade-inspection` again using
`--phase after-upgrade`, `NEW_IMAGE`, `NEW_CONTRACT_DIGEST`, and the new runtime
identities. Preserve a failed candidate claim; do not repair it in place for acceptance.

```sh
kubectl -n "$NCT_NAMESPACE" scale "deployment/$NCT_NAME" --replicas=0
kubectl -n "$NCT_NAMESPACE" wait --for=delete \
  pod -l "app.kubernetes.io/name=$NCT_NAME,app.kubernetes.io/component=analysis" --timeout=180s
python scripts/render_kubernetes_single_replica.py writer-lock-probe \
  --name "$NCT_NAME" --namespace "$NCT_NAMESPACE" --image "$NEW_IMAGE" \
  --pvc-name "$RESTORE_PVC" --storage-class "$RESTORE_CLASS" --storage-size "$RESTORE_SIZE" \
  --pvc-uid "$RESTORE_PVC_UID" --bound-volume-uid "$RESTORE_PV_UID" \
  --storage-report "$RESTORE_REPORT" --storage-report-digest "$RESTORE_REPORT_DIGEST" \
  --expect available --scenario-id "$GATE4C_SCENARIO" --scenario-kind guarded-upgrade \
  --phase candidate-writer-released --application-version "$NEW_APP_VERSION" \
  --build-id "$NEW_BUILD_ID" --deployment-uid "$DEPLOYMENT_UID" \
  --deployment-generation "$CANDIDATE_GENERATION" --pod-uid "$CANDIDATE_POD_UID" \
  --node-name "$CANDIDATE_NODE_NAME" --node-uid "$CANDIDATE_NODE_UID" \
  --storage-attachment-identity "$CANDIDATE_ATTACHMENT_ID" \
  --output gate4c-candidate-writer-released.json
kubectl apply -f gate4c-candidate-writer-released.json
CANDIDATE_LOCK_JOB="$(python -c 'import json; print(next(x["metadata"]["name"] for x in json.load(open("gate4c-candidate-writer-released.json"))["items"] if x["kind"]=="Job"))')"
kubectl -n "$NCT_NAMESPACE" wait --for=condition=complete "job/$CANDIDATE_LOCK_JOB" --timeout=90s
kubectl -n "$NCT_NAMESPACE" logs "job/$CANDIDATE_LOCK_JOB" > gate4c-candidate-writer-released-receipt.json
gate4c_observe candidate-stopped 0 gate4c-candidate-writer-released-receipt.json \
  "$CANDIDATE_GENERATION" "$CANDIDATE_POD_UID" \
  "$CANDIDATE_NODE_UID" "$CANDIDATE_ATTACHMENT_ID" "$RESTORE_PVC_UID" "$RESTORE_PV_UID"

python scripts/render_kubernetes_single_replica.py upgrade-inspection \
  --name "$NCT_NAME" --namespace "$NCT_NAMESPACE" --image "$NEW_IMAGE" \
  --pvc-name "$RESTORE_PVC" --storage-class "$RESTORE_CLASS" --storage-size "$RESTORE_SIZE" \
  --pvc-uid "$RESTORE_PVC_UID" --bound-volume-uid "$RESTORE_PV_UID" \
  --storage-report "$RESTORE_REPORT" --storage-report-digest "$RESTORE_REPORT_DIGEST" \
  --scenario-id "$GATE4C_SCENARIO" --phase after-upgrade \
  --runtime-image-id "$CANDIDATE_RUNTIME_IMAGE_ID" --contract-digest "$NEW_CONTRACT_DIGEST" \
  --deployment-uid "$DEPLOYMENT_UID" --deployment-generation "$CANDIDATE_GENERATION" \
  --pod-uid "$CANDIDATE_POD_UID" --node-name "$CANDIDATE_NODE_NAME" \
  --node-uid "$CANDIDATE_NODE_UID" --storage-attachment-identity "$CANDIDATE_ATTACHMENT_ID" \
  --output gate4c-after-inspection-job.json
kubectl apply -f gate4c-after-inspection-job.json
AFTER_JOB="$(python -c 'import json; print(next(x["metadata"]["name"] for x in json.load(open("gate4c-after-inspection-job.json"))["items"] if x["kind"]=="Job"))')"
kubectl -n "$NCT_NAMESPACE" wait --for=condition=complete "job/$AFTER_JOB" --timeout=330s
kubectl -n "$NCT_NAMESPACE" logs "job/$AFTER_JOB" > gate4c-after-inspection.json
```

### 6. Exercise the rollback branch selected by preflight

For `direct`, the old image may reopen the current claim only after the candidate Pod is
gone, its writer is released, and the plan explicitly contains
`"direct_rollback_authorized": true`. Start one old-image Pod, verify it, stop it, and
record an `after-rollback` inspection on the same PVC.

```sh
python -c 'import json,sys; p=json.load(open("gate4c-plan.json")); sys.exit(0 if p.get("direct_rollback_authorized") is True and p.get("rollback_decision")=="direct" else 1)'
python scripts/render_kubernetes_single_replica.py deployment \
  --name "$NCT_NAME" --namespace "$NCT_NAMESPACE" --image "$OLD_IMAGE" \
  --pvc-name "$RESTORE_PVC" --storage-class "$RESTORE_CLASS" --storage-size "$RESTORE_SIZE" \
  --pvc-uid "$RESTORE_PVC_UID" --bound-volume-uid "$RESTORE_PV_UID" \
  --storage-report "$RESTORE_REPORT" --storage-report-digest "$RESTORE_REPORT_DIGEST" \
  --output gate4c-direct-rollback-deployment.json
kubectl apply -f gate4c-direct-rollback-deployment.json
kubectl -n "$NCT_NAMESPACE" rollout status "deployment/$NCT_NAME" --timeout=300s
export ROLLBACK_POD="$(kubectl -n "$NCT_NAMESPACE" get pod -l "app.kubernetes.io/name=$NCT_NAME,app.kubernetes.io/component=analysis" -o jsonpath='{.items[0].metadata.name}')"
export ROLLBACK_POD_UID="$(kubectl -n "$NCT_NAMESPACE" get pod "$ROLLBACK_POD" -o jsonpath='{.metadata.uid}')"
export ROLLBACK_NODE_NAME="$(kubectl -n "$NCT_NAMESPACE" get pod "$ROLLBACK_POD" -o jsonpath='{.spec.nodeName}')"
export ROLLBACK_NODE_UID="$(kubectl get node "$ROLLBACK_NODE_NAME" -o jsonpath='{.metadata.uid}')"
export ROLLBACK_RUNTIME_IMAGE_ID="$(kubectl -n "$NCT_NAMESPACE" get pod "$ROLLBACK_POD" -o jsonpath='{.status.containerStatuses[0].imageID}')"
export ROLLBACK_GENERATION="$(kubectl -n "$NCT_NAMESPACE" get deployment "$NCT_NAME" -o jsonpath='{.metadata.generation}')"
export ROLLBACK_ATTACHMENT_ID='REPLACE_WITH_CURRENT_ATTACHMENT_FROM_STORAGE_OPERATOR'
gate4c_capture_checks after-rollback gate4c-rollback selected-evidence-rollback.bin
gate4c_probe_writer rollback-writer-active contended "$OLD_IMAGE" "$OLD_APP_VERSION" \
  "$OLD_BUILD_ID" "$ROLLBACK_GENERATION" "$ROLLBACK_POD_UID" \
  "$ROLLBACK_NODE_NAME" "$ROLLBACK_NODE_UID" "$ROLLBACK_ATTACHMENT_ID" \
  gate4c-rollback-writer-active
gate4c_observe rollback-ready 1 gate4c-rollback-writer-active-receipt.json \
  "$ROLLBACK_GENERATION" "$ROLLBACK_POD_UID" \
  "$ROLLBACK_NODE_UID" "$ROLLBACK_ATTACHMENT_ID" "$RESTORE_PVC_UID" "$RESTORE_PV_UID"
kubectl -n "$NCT_NAMESPACE" scale "deployment/$NCT_NAME" --replicas=0
kubectl -n "$NCT_NAMESPACE" wait --for=delete pod \
  -l "app.kubernetes.io/name=$NCT_NAME,app.kubernetes.io/component=analysis" --timeout=180s
python scripts/render_kubernetes_single_replica.py writer-lock-probe \
  --name "$NCT_NAME" --namespace "$NCT_NAMESPACE" --image "$OLD_IMAGE" \
  --pvc-name "$RESTORE_PVC" --storage-class "$RESTORE_CLASS" --storage-size "$RESTORE_SIZE" \
  --pvc-uid "$RESTORE_PVC_UID" --bound-volume-uid "$RESTORE_PV_UID" \
  --storage-report "$RESTORE_REPORT" --storage-report-digest "$RESTORE_REPORT_DIGEST" \
  --expect available --scenario-id "$GATE4C_SCENARIO" --scenario-kind guarded-upgrade \
  --phase rollback-writer-released --application-version "$OLD_APP_VERSION" \
  --build-id "$OLD_BUILD_ID" --deployment-uid "$DEPLOYMENT_UID" \
  --deployment-generation "$ROLLBACK_GENERATION" --pod-uid "$ROLLBACK_POD_UID" \
  --node-name "$ROLLBACK_NODE_NAME" --node-uid "$ROLLBACK_NODE_UID" \
  --storage-attachment-identity "$ROLLBACK_ATTACHMENT_ID" \
  --output gate4c-rollback-writer-released-job.json
kubectl apply -f gate4c-rollback-writer-released-job.json
ROLLBACK_LOCK_JOB="$(python -c 'import json; print(next(x["metadata"]["name"] for x in json.load(open("gate4c-rollback-writer-released-job.json"))["items"] if x["kind"]=="Job"))')"
kubectl -n "$NCT_NAMESPACE" wait --for=condition=complete "job/$ROLLBACK_LOCK_JOB" --timeout=90s
kubectl -n "$NCT_NAMESPACE" logs "job/$ROLLBACK_LOCK_JOB" > gate4c-rollback-writer-released-receipt.json
gate4c_observe rollback-stopped 0 gate4c-rollback-writer-released-receipt.json \
  "$ROLLBACK_GENERATION" "$ROLLBACK_POD_UID" \
  "$ROLLBACK_NODE_UID" "$ROLLBACK_ATTACHMENT_ID" "$RESTORE_PVC_UID" "$RESTORE_PV_UID"
python scripts/render_kubernetes_single_replica.py upgrade-inspection \
  --name "$NCT_NAME" --namespace "$NCT_NAMESPACE" --image "$OLD_IMAGE" \
  --pvc-name "$RESTORE_PVC" --storage-class "$RESTORE_CLASS" --storage-size "$RESTORE_SIZE" \
  --pvc-uid "$RESTORE_PVC_UID" --bound-volume-uid "$RESTORE_PV_UID" \
  --storage-report "$RESTORE_REPORT" --storage-report-digest "$RESTORE_REPORT_DIGEST" \
  --scenario-id "$GATE4C_SCENARIO" --phase after-rollback \
  --runtime-image-id "$ROLLBACK_RUNTIME_IMAGE_ID" --contract-digest "$OLD_CONTRACT_DIGEST" \
  --deployment-uid "$DEPLOYMENT_UID" --deployment-generation "$ROLLBACK_GENERATION" \
  --pod-uid "$ROLLBACK_POD_UID" --node-name "$ROLLBACK_NODE_NAME" --node-uid "$ROLLBACK_NODE_UID" \
  --storage-attachment-identity "$ROLLBACK_ATTACHMENT_ID" \
  --output gate4c-rollback-inspection-job.json
kubectl apply -f gate4c-rollback-inspection-job.json
ROLLBACK_INSPECTION_JOB="$(python -c 'import json; print(next(x["metadata"]["name"] for x in json.load(open("gate4c-rollback-inspection-job.json"))["items"] if x["kind"]=="Job"))')"
kubectl -n "$NCT_NAMESPACE" wait --for=condition=complete "job/$ROLLBACK_INSPECTION_JOB" --timeout=330s
kubectl -n "$NCT_NAMESPACE" logs "job/$ROLLBACK_INSPECTION_JOB" > gate4c-rollback-inspection.json
```

For `restore`, keep the failed or successfully upgraded claim unchanged. Create and
qualify a new empty PVC/PV with a new attachment identity. Run the Gate 4A restore from
the pre-upgrade backup into that target and verify its restore receipt. Start the exact
old image on only that restored target. Verify readiness, the existing account, retained
history, and the same evidence download, then stop it and record an `after-rollback`
inspection. The verifier rejects a source, backup, candidate, or restore target with
overlapping immutable identities.

```sh
python -c 'import json,sys; p=json.load(open("gate4c-plan.json")); sys.exit(0 if p.get("rollback_decision")=="restore" else 1)'
export ROLLBACK_PVC='nct-gate4c-rollback-restore'
export ROLLBACK_CLASS="$RESTORE_CLASS"
export ROLLBACK_SIZE="$RESTORE_SIZE"
```

Run Gate 4A steps 2 through 6 exactly as written in this document, substituting
`ROLLBACK_PVC` for the empty restore target. Those steps create and verify the new claim,
set `ROLLBACK_PVC_UID`, `ROLLBACK_PV_UID`, `ROLLBACK_REPORT`, and
`ROLLBACK_REPORT_DIGEST`, and produce `gate4a-restore-receipt.json` plus its separately
retained digest. Stop unless that receipt says `restore_verification_passed`. Then run:

```sh
python scripts/render_kubernetes_single_replica.py deployment \
  --name "$NCT_NAME" --namespace "$NCT_NAMESPACE" --image "$OLD_IMAGE" \
  --pvc-name "$ROLLBACK_PVC" --storage-class "$ROLLBACK_CLASS" --storage-size "$ROLLBACK_SIZE" \
  --pvc-uid "$ROLLBACK_PVC_UID" --bound-volume-uid "$ROLLBACK_PV_UID" \
  --storage-report "$ROLLBACK_REPORT" --storage-report-digest "$ROLLBACK_REPORT_DIGEST" \
  --output gate4c-restored-rollback-deployment.json
kubectl apply -f gate4c-restored-rollback-deployment.json
kubectl -n "$NCT_NAMESPACE" rollout status "deployment/$NCT_NAME" --timeout=300s
export ROLLBACK_POD="$(kubectl -n "$NCT_NAMESPACE" get pod -l "app.kubernetes.io/name=$NCT_NAME,app.kubernetes.io/component=analysis" -o jsonpath='{.items[0].metadata.name}')"
export ROLLBACK_POD_UID="$(kubectl -n "$NCT_NAMESPACE" get pod "$ROLLBACK_POD" -o jsonpath='{.metadata.uid}')"
export ROLLBACK_NODE_NAME="$(kubectl -n "$NCT_NAMESPACE" get pod "$ROLLBACK_POD" -o jsonpath='{.spec.nodeName}')"
export ROLLBACK_NODE_UID="$(kubectl get node "$ROLLBACK_NODE_NAME" -o jsonpath='{.metadata.uid}')"
export ROLLBACK_RUNTIME_IMAGE_ID="$(kubectl -n "$NCT_NAMESPACE" get pod "$ROLLBACK_POD" -o jsonpath='{.status.containerStatuses[0].imageID}')"
export ROLLBACK_GENERATION="$(kubectl -n "$NCT_NAMESPACE" get deployment "$NCT_NAME" -o jsonpath='{.metadata.generation}')"
export ROLLBACK_ATTACHMENT_ID='REPLACE_WITH_CURRENT_ATTACHMENT_FROM_STORAGE_OPERATOR'
gate4c_capture_checks after-rollback gate4c-rollback selected-evidence-rollback.bin
GATE4C_PROBE_PVC="$ROLLBACK_PVC" GATE4C_PROBE_CLASS="$ROLLBACK_CLASS" \
  GATE4C_PROBE_SIZE="$ROLLBACK_SIZE" GATE4C_PROBE_PVC_UID="$ROLLBACK_PVC_UID" \
  GATE4C_PROBE_PV_UID="$ROLLBACK_PV_UID" GATE4C_PROBE_REPORT="$ROLLBACK_REPORT" \
  GATE4C_PROBE_REPORT_DIGEST="$ROLLBACK_REPORT_DIGEST" \
  gate4c_probe_writer rollback-writer-active contended "$OLD_IMAGE" "$OLD_APP_VERSION" \
  "$OLD_BUILD_ID" "$ROLLBACK_GENERATION" "$ROLLBACK_POD_UID" \
  "$ROLLBACK_NODE_NAME" "$ROLLBACK_NODE_UID" "$ROLLBACK_ATTACHMENT_ID" \
  gate4c-rollback-writer-active
gate4c_observe rollback-ready 1 gate4c-rollback-writer-active-receipt.json \
  "$ROLLBACK_GENERATION" "$ROLLBACK_POD_UID" \
  "$ROLLBACK_NODE_UID" "$ROLLBACK_ATTACHMENT_ID" "$ROLLBACK_PVC_UID" "$ROLLBACK_PV_UID"
kubectl -n "$NCT_NAMESPACE" scale "deployment/$NCT_NAME" --replicas=0
kubectl -n "$NCT_NAMESPACE" wait --for=delete pod \
  -l "app.kubernetes.io/name=$NCT_NAME,app.kubernetes.io/component=analysis" --timeout=180s
```

Run the exact `rollback-writer-released` probe and `after-rollback` inspection commands
from the direct branch above, substituting `ROLLBACK_PVC`, `ROLLBACK_CLASS`,
`ROLLBACK_SIZE`, `ROLLBACK_PVC_UID`, `ROLLBACK_PV_UID`, `ROLLBACK_REPORT`, and
`ROLLBACK_REPORT_DIGEST`. The output filenames stay
`gate4c-rollback-writer-released-receipt.json` and
`gate4c-rollback-inspection.json`; the verifier binds both to the fresh restored target.
After the released-writer receipt is saved, record the final stopped observation:

```sh
gate4c_observe rollback-stopped 0 gate4c-rollback-writer-released-receipt.json \
  "$ROLLBACK_GENERATION" "$ROLLBACK_POD_UID" \
  "$ROLLBACK_NODE_UID" "$ROLLBACK_ATTACHMENT_ID" "$ROLLBACK_PVC_UID" "$ROLLBACK_PV_UID"
```

### 7. Create the ordered event and web-check records, then verify

Use UTC timestamps that strictly increase. A restore exercise requires this order:

```json
{
  "scenario_id": "upgrade-REPLACE_DATE-REPLACE_UNIQUE_SUFFIX",
  "events": [
    {"event":"old-writer-released","at":"REPLACE_UTC"},
    {"event":"backup-verified","at":"REPLACE_LATER_UTC"},
    {"event":"preflight-passed","at":"REPLACE_LATER_UTC"},
    {"event":"candidate-started","at":"REPLACE_LATER_UTC"},
    {"event":"candidate-ready","at":"REPLACE_LATER_UTC"},
    {"event":"candidate-writer-released","at":"REPLACE_LATER_UTC"},
    {"event":"failed-claim-preserved","at":"REPLACE_LATER_UTC"},
    {"event":"restore-target-verified","at":"REPLACE_LATER_UTC"},
    {"event":"old-started-on-restored-data","at":"REPLACE_LATER_UTC"},
    {"event":"rollback-ready","at":"REPLACE_LATER_UTC"}
  ]
}
```

A direct rollback uses the same first six events, then these exact final events:

```json
{
  "scenario_id": "upgrade-REPLACE_DATE-REPLACE_UNIQUE_SUFFIX",
  "events": [
    {"event":"old-writer-released","at":"REPLACE_UTC"},
    {"event":"backup-verified","at":"REPLACE_LATER_UTC"},
    {"event":"preflight-passed","at":"REPLACE_LATER_UTC"},
    {"event":"candidate-started","at":"REPLACE_LATER_UTC"},
    {"event":"candidate-ready","at":"REPLACE_LATER_UTC"},
    {"event":"candidate-writer-released","at":"REPLACE_LATER_UTC"},
    {"event":"old-started-on-current-data","at":"REPLACE_LATER_UTC"},
    {"event":"rollback-ready","at":"REPLACE_LATER_UTC"}
  ]
}
```

Each web-check file records its phase, HTTP startup and readiness status, and whether an
existing account signed in, for example:

```json
{"phase":"after-upgrade","startup_status":200,"readiness_status":200,"existing_account_signin":true}
```

The `gate4c_observe` calls create five ordered samples: old stopped, candidate Ready or
failed, candidate stopped, rollback Ready, and rollback stopped. Each sample carries the
exact Deployment generation, Pod, node, attachment, PVC, PV, Ready-Pod count, and writer
count. The helper derives the writer count from the matching attested lock-probe receipt;
it never copies the Ready-Pod count. A failed candidate may have zero or one measured
writer owner, depending on whether its process has exited. The verifier rejects missing
phases, identity changes, reordered timestamps, or any count above one.

For a successful candidate, run the final verifier with the three cold inspection
receipts, both active-writer receipts, all three released-writer receipts, cluster
observations, event record, three web checks, and three downloads. Each observation is
bound to its exact lock receipt rather than a copied readiness count. The restore branch
also supplies the actual Gate 4A
restore receipt and its separately retained digest:

```sh
set --
if python -c 'import json,sys; sys.exit(0 if json.load(open("gate4c-plan.json"))["rollback_decision"]=="restore" else 1)'; then
  set -- --restore-receipt gate4a-restore-receipt.json \
    --restore-receipt-digest "$RESTORE_RECEIPT_DIGEST"
fi
python scripts/nct_kubernetes_upgrade.py verify \
  --plan gate4c-plan.json \
  --before-inspection gate4c-before-inspection.json \
  --after-inspection gate4c-after-inspection.json \
  --rollback-inspection gate4c-rollback-inspection.json \
  --old-lock-receipt gate4c-old-writer-released-receipt.json \
  --candidate-active-lock-receipt gate4c-candidate-writer-active-receipt.json \
  --candidate-lock-receipt gate4c-candidate-writer-released-receipt.json \
  --rollback-active-lock-receipt gate4c-rollback-writer-active-receipt.json \
  --rollback-lock-receipt gate4c-rollback-writer-released-receipt.json \
  --cluster-observations gate4c-cluster-observations.json \
  --events gate4c-events.json \
  --before-web-check gate4c-before-web.json \
  --after-web-check gate4c-after-web.json \
  --rollback-web-check gate4c-rollback-web.json \
  --evidence-before selected-evidence-before.bin \
  --evidence-after selected-evidence-after.bin \
  --evidence-rollback selected-evidence-rollback.bin \
  "$@" \
  --output gate4c-final-receipt.json
```

If the candidate never becomes Ready, do not create a passing after-upgrade inspection.
Use this bounded capture for its last Pod/runtime identities, then scale it to zero, prove
`candidate-writer-released`, and inspect the preserved claim with
`--phase failed-candidate`. Save that output as `gate4c-failed-inspection.json`, then run:

```sh
export CANDIDATE_POD="$(kubectl -n "$NCT_NAMESPACE" get pod -l "app.kubernetes.io/name=$NCT_NAME,app.kubernetes.io/component=analysis" -o jsonpath='{.items[0].metadata.name}')"
test -n "$CANDIDATE_POD" || { echo 'Gate 4C rejected: no candidate Pod identity exists'; exit 1; }
export CANDIDATE_POD_UID="$(kubectl -n "$NCT_NAMESPACE" get pod "$CANDIDATE_POD" -o jsonpath='{.metadata.uid}')"
export CANDIDATE_NODE_NAME="$(kubectl -n "$NCT_NAMESPACE" get pod "$CANDIDATE_POD" -o jsonpath='{.spec.nodeName}')"
export CANDIDATE_RUNTIME_IMAGE_ID="$(kubectl -n "$NCT_NAMESPACE" get pod "$CANDIDATE_POD" -o jsonpath='{.status.containerStatuses[0].imageID}')"
export CANDIDATE_GENERATION="$(kubectl -n "$NCT_NAMESPACE" get deployment "$NCT_NAME" -o jsonpath='{.metadata.generation}')"
test -n "$CANDIDATE_POD_UID" && test -n "$CANDIDATE_NODE_NAME" && test -n "$CANDIDATE_RUNTIME_IMAGE_ID" || \
  { echo 'Gate 4C rejected: candidate runtime identities are incomplete'; exit 1; }
export CANDIDATE_NODE_UID="$(kubectl get node "$CANDIDATE_NODE_NAME" -o jsonpath='{.metadata.uid}')"
export CANDIDATE_ATTACHMENT_ID='REPLACE_WITH_CURRENT_ATTACHMENT_FROM_STORAGE_OPERATOR'
test -n "$CANDIDATE_NODE_UID" && test -n "$CANDIDATE_ATTACHMENT_ID" || \
  { echo 'Gate 4C rejected: node or attachment identity is incomplete'; exit 1; }
kubectl -n "$NCT_NAMESPACE" get pod "$CANDIDATE_POD" -o json > gate4c-candidate-pod-status.json
export FAILURE_OBSERVED_AT="$(date -u +%Y-%m-%dT%H:%M:%S+00:00)"
export STARTUP_STATUS="$(curl --silent --output gate4c-failed-startup-body.txt --write-out '%{http_code}' --cacert "$TRUSTED_CA" "$NCT_BASE_URL/health/startup" || true)"
export READINESS_STATUS="$(curl --silent --output gate4c-failed-readiness-body.txt --write-out '%{http_code}' --cacert "$TRUSTED_CA" "$NCT_BASE_URL/health/readiness" || true)"
python -c 'import json,os; p=json.load(open("gate4c-candidate-pod-status.json")); c=p["status"]["containerStatuses"][0]; t=c.get("state",{}).get("terminated") or c.get("lastState",{}).get("terminated") or {}; json.dump({"scenario_id":os.environ["GATE4C_SCENARIO"],"phase":"candidate-failure","observed_at":os.environ["FAILURE_OBSERVED_AT"],"runtime":{"pod_uid":os.environ["CANDIDATE_POD_UID"],"image_id":os.environ["CANDIDATE_RUNTIME_IMAGE_ID"]},"container":{"terminated":bool(t),"exit_code":int(t.get("exitCode",0)),"reason":t.get("reason") or c.get("state",{}).get("waiting",{}).get("reason","")},"startup_status":int(os.environ["STARTUP_STATUS"] or 0),"readiness_status":int(os.environ["READINESS_STATUS"] or 0)},open("gate4c-candidate-failure-evidence.json","w"))'
gate4c_probe_writer candidate-writer-active observe "$NEW_IMAGE" \
  "$NEW_APP_VERSION" "$NEW_BUILD_ID" "$CANDIDATE_GENERATION" \
  "$CANDIDATE_POD_UID" "$CANDIDATE_NODE_NAME" "$CANDIDATE_NODE_UID" \
  "$CANDIDATE_ATTACHMENT_ID" gate4c-candidate-writer-active
gate4c_observe candidate-failed 0 gate4c-candidate-writer-active-receipt.json \
  "$CANDIDATE_GENERATION" "$CANDIDATE_POD_UID" \
  "$CANDIDATE_NODE_UID" "$CANDIDATE_ATTACHMENT_ID" "$RESTORE_PVC_UID" "$RESTORE_PV_UID"
kubectl -n "$NCT_NAMESPACE" scale "deployment/$NCT_NAME" --replicas=0
kubectl -n "$NCT_NAMESPACE" wait --for=delete pod \
  -l "app.kubernetes.io/name=$NCT_NAME,app.kubernetes.io/component=analysis" --timeout=180s
```

Run the exact `candidate-writer-released` probe shown in step 5, then record the stopped
sample before inspection:

```sh
gate4c_observe candidate-stopped 0 gate4c-candidate-writer-released-receipt.json \
  "$CANDIDATE_GENERATION" "$CANDIDATE_POD_UID" \
  "$CANDIDATE_NODE_UID" "$CANDIDATE_ATTACHMENT_ID" "$RESTORE_PVC_UID" "$RESTORE_PV_UID"
```

Now create the failed inspection and failure receipt:

```sh
python scripts/render_kubernetes_single_replica.py upgrade-inspection \
  --name "$NCT_NAME" --namespace "$NCT_NAMESPACE" --image "$NEW_IMAGE" \
  --pvc-name "$RESTORE_PVC" --storage-class "$RESTORE_CLASS" --storage-size "$RESTORE_SIZE" \
  --pvc-uid "$RESTORE_PVC_UID" --bound-volume-uid "$RESTORE_PV_UID" \
  --storage-report "$RESTORE_REPORT" --storage-report-digest "$RESTORE_REPORT_DIGEST" \
  --scenario-id "$GATE4C_SCENARIO" --phase failed-candidate \
  --runtime-image-id "$CANDIDATE_RUNTIME_IMAGE_ID" --contract-digest "$NEW_CONTRACT_DIGEST" \
  --deployment-uid "$DEPLOYMENT_UID" --deployment-generation "$CANDIDATE_GENERATION" \
  --pod-uid "$CANDIDATE_POD_UID" --node-name "$CANDIDATE_NODE_NAME" \
  --node-uid "$CANDIDATE_NODE_UID" --storage-attachment-identity "$CANDIDATE_ATTACHMENT_ID" \
  --output gate4c-failed-inspection-job.json
kubectl apply -f gate4c-failed-inspection-job.json
FAILED_INSPECTION_JOB="$(python -c 'import json; print(next(x["metadata"]["name"] for x in json.load(open("gate4c-failed-inspection-job.json"))["items"] if x["kind"]=="Job"))')"
kubectl -n "$NCT_NAMESPACE" wait --for=condition=complete "job/$FAILED_INSPECTION_JOB" --timeout=330s
kubectl -n "$NCT_NAMESPACE" logs "job/$FAILED_INSPECTION_JOB" > gate4c-failed-inspection.json
python scripts/nct_kubernetes_upgrade.py record-failure \
  --scenario-id "$GATE4C_SCENARIO" --image "$NEW_IMAGE" \
  --contract gate4c-new-contract.json \
  --failed-inspection gate4c-failed-inspection.json \
  --failure-stage during-migration --failure-evidence gate4c-candidate-failure-evidence.json \
  --output gate4c-candidate-failure.json
```

If no candidate Pod, runtime image ID, node, or attachment identity ever exists, the
failed-candidate acceptance path cannot be proven. Preserve the scheduler and container
events, keep the candidate unapplied or scaled to zero, and record the exercise as
rejected. Do not create a final Gate 4C receipt. The old copy may use the unchanged source
only after a second cold inventory matches the preflight inventory exactly; otherwise use
the verified Gate 4A restore path on a fresh target.

The failed branch always preserves the candidate claim and restores the cold backup to
the fresh qualified target, even when preflight would have allowed direct rollback. Run
the restore rollback commands above, use the restore event template with
`candidate-failed` in place of `candidate-ready`, then verify with:

```sh
python scripts/nct_kubernetes_upgrade.py verify \
  --plan gate4c-plan.json --before-inspection gate4c-before-inspection.json \
  --failed-inspection gate4c-failed-inspection.json \
  --candidate-failure gate4c-candidate-failure.json \
  --rollback-inspection gate4c-rollback-inspection.json \
  --old-lock-receipt gate4c-old-writer-released-receipt.json \
  --candidate-active-lock-receipt gate4c-candidate-writer-active-receipt.json \
  --candidate-lock-receipt gate4c-candidate-writer-released-receipt.json \
  --rollback-active-lock-receipt gate4c-rollback-writer-active-receipt.json \
  --rollback-lock-receipt gate4c-rollback-writer-released-receipt.json \
  --cluster-observations gate4c-cluster-observations.json --events gate4c-events.json \
  --restore-receipt gate4a-restore-receipt.json \
  --restore-receipt-digest "$RESTORE_RECEIPT_DIGEST" \
  --before-web-check gate4c-before-web.json --rollback-web-check gate4c-rollback-web.json \
  --evidence-before selected-evidence-before.bin \
  --evidence-rollback selected-evidence-rollback.bin \
  --output gate4c-final-receipt.json
```

Stop immediately for active work, maintenance, a missing backup proof, insufficient
space, incompatible storage, overlapping Pods or writers, rolling replacement, a
changed identity, incomplete migration ledger, failed database or artifact verification,
reduced retained counts, failed sign-in/readiness, or a changed evidence download. Save
the reports and receipts outside all claims. SHA-256 detects change but is not an
authenticated signature.

Forced termination, rescheduling, node loss, backup, restore, upgrade, and rollback are
Kubernetes acceptance gate 4. Until those tests pass, this package must not be described
as Range-ready or mission-ready.

## Optional read-only Kubernetes status adapter — Gate 5

This gate is optional. Standalone NCT does not need Kubernetes status. The adapter is a
separate workload because the NCT application must never receive a Kubernetes API token
and adapter failure must never make the NCT Pod unready. Use a namespace dedicated to
NCT. Kubernetes Role rules cannot restrict list permission by labels, so a shared
namespace would let the credential technically list other Deployments, ReplicaSets and
Pods even though the adapter requests and accepts only the fixed NCT ownership chain.

The default package reads Deployment, ReplicaSet and Pod status only. Add the metrics
flag only when the cluster Metrics API is installed and the administrator accepts that
separate permission. Missing or denied metrics leave Deployment and Pod status available
and display resource measurements as Unavailable.

Render the adapter without pod resource metrics:

```bash
python scripts/render_kubernetes_single_replica.py health-adapter \
  --name "$NCT_NAME" \
  --namespace "$NCT_NAMESPACE" \
  --image "$NCT_IMAGE" \
  --output nct-kubernetes-health-adapter.json
```

To opt in to current aggregate NCT Pod CPU and memory, add
`--enable-metrics`. Render the NCT Deployment with the fixed internal adapter address by
adding `--enable-kubernetes-health` to the existing `deployment` command. That flag adds
only the adapter name and namespace to NCT; it does not change the NCT ServiceAccount,
mount a token, add RBAC, or make cluster status part of NCT readiness.

Before applying anything, review the rendered resources. The adapter package must contain
one dedicated ServiceAccount, Role, RoleBinding, Deployment and Service. Its Role must
contain only `get` and `list` for Deployments, ReplicaSets and Pods, plus Pods in the
`metrics.k8s.io` API group only when requested. It must contain no wildcard, Secret,
ConfigMap, event, log, exec, attach, port-forward, discovery or cluster-wide permission.

```bash
kubectl -n "$NCT_NAMESPACE" apply -f nct-kubernetes-health-adapter.json
kubectl -n "$NCT_NAMESPACE" auth can-i get "deployment/$NCT_NAME" \
  --as="system:serviceaccount:$NCT_NAMESPACE:${NCT_NAME}-health-reader"
kubectl -n "$NCT_NAMESPACE" auth can-i list replicasets \
  --as="system:serviceaccount:$NCT_NAMESPACE:${NCT_NAME}-health-reader"
kubectl -n "$NCT_NAMESPACE" auth can-i list pods \
  --as="system:serviceaccount:$NCT_NAMESPACE:${NCT_NAME}-health-reader"
kubectl -n "$NCT_NAMESPACE" auth can-i list deployments \
  --as="system:serviceaccount:$NCT_NAMESPACE:${NCT_NAME}-health-reader"
kubectl -n "$NCT_NAMESPACE" auth can-i get secrets \
  --as="system:serviceaccount:$NCT_NAMESPACE:${NCT_NAME}-health-reader"
kubectl -n "$NCT_NAMESPACE" auth can-i get configmaps \
  --as="system:serviceaccount:$NCT_NAMESPACE:${NCT_NAME}-health-reader"
kubectl -n "$NCT_NAMESPACE" auth can-i watch pods \
  --as="system:serviceaccount:$NCT_NAMESPACE:${NCT_NAME}-health-reader"
kubectl -n "$NCT_NAMESPACE" auth can-i get pods --subresource=log \
  --as="system:serviceaccount:$NCT_NAMESPACE:${NCT_NAME}-health-reader"
kubectl -n "$NCT_NAMESPACE" auth can-i create pods --subresource=exec \
  --as="system:serviceaccount:$NCT_NAMESPACE:${NCT_NAME}-health-reader"
kubectl auth can-i list pods --all-namespaces \
  --as="system:serviceaccount:$NCT_NAMESPACE:${NCT_NAME}-health-reader"
```

The exact Deployment, ReplicaSet-list and Pod-list results should be `yes`. Deployment
list, Secret, ConfigMap, watch, log, exec and all-namespace checks must be `no`.
Apply the separately rendered NCT Deployment after those checks. In Settings / System
Health, **Optional Kubernetes status** must show one of these states:

- **Not configured:** no adapter request was attempted; local health remains active.
- **Available:** the current bounded Deployment, Pod and optional metric reads succeeded.
- **Partial:** Deployment and Pod status is available; pod resource measurements are
  unavailable.
- **Unavailable:** access was denied, timed out, malformed, incomplete or could not be
  read. Cluster state is unknown; this never means zero Pods or a failed deployment.

Verify denied access, a stopped adapter, an unavailable Metrics API, more than 32 matching
objects, paginated results and an API response that exceeds the fixed bound. NCT startup,
readiness, liveness, local CPU and memory, saved work, and evidence operations must remain
unchanged in every case. The adapter uses at most four API requests, 32 items per list,
256 KiB per response, 512 KiB in one sample and 2.5 seconds total; it caches samples for
15 seconds and combines simultaneous reads. It returns no Kubernetes object names, UIDs,
node details, images, annotations, logs, commands, environment values or raw responses.

Local package tests cannot prove the target cluster's RBAC enforcement, namespace
isolation, API path, Metrics API or network behavior. Gate 5 remains open until the exact
cluster exercises above pass and the results are retained with the installation record.

## What successful Gate 3C proves

This profile proves one analysis-only NCT copy on the named cluster and exact tested
volume. It does not prove multiple-copy operation, live collection, general
storage-class approval, Range readiness, mission readiness, or production scale.
