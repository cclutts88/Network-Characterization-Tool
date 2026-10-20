# Start here: NCT on the Kubernetes Range

This page chooses the safe path before anyone changes the cluster. The first supported
Kubernetes profile runs **one analysis-only NCT copy**. It can import and analyze saved
evidence, but it cannot start Nmap, SSH device collection, schedules, or packet capture.

## Choose one path

| What exists now | Path | What to do |
|---|---|---|
| NCT currently runs as a standalone Docker container | Fresh side-by-side Kubernetes trial | Preserve the Docker installation. Use a new Kubernetes namespace and a new persistent claim. Import only the evidence you intentionally choose after the trial passes. |
| No NCT installation exists in the selected namespace | Fresh Kubernetes installation | Inventory the cluster, stage the exact image, qualify a new persistent claim, then follow the ordered deployment runbook. |
| One supported Kubernetes NCT Deployment already exists | Existing Kubernetes upgrade | Do not create another claim or bootstrap account. Use the guarded Gate 4C upgrade and rollback process after completing the exact-cluster backup and recovery gates. |
| A verified Kubernetes backup must be recovered | Recovery | Restore into a different empty, qualified claim. Do not restore over the live claim. |
| The current state does not clearly match one row above | Blocked | Stop. Record the inventory report and ask the cluster administrator to identify the installation and retained storage before any change. |

The current Range Docker installation is **not** an in-place Kubernetes upgrade. The
recommended first trial is side by side so the existing service and its data remain
available until the Kubernetes candidate passes acceptance.

## What to bring to the Range

Transfer both `NCT-Kubernetes-Range-Discovery-20261019-r1.zip` and its adjacent
`.zip.sha256` file to the air-gapped administrator workstation through the approved
transfer process. These files are an administrator discovery kit. Do **not** upload them
into NCT, a Kubernetes pod, or an NCT data volume.

From the directory that received both files, verify the transferred ZIP before opening
it, then extract it into a new working directory:

```bash
sha256sum -c NCT-Kubernetes-Range-Discovery-20261019-r1.zip.sha256
unzip NCT-Kubernetes-Range-Discovery-20261019-r1.zip \
  -d NCT-Kubernetes-Range-Discovery-20261019-r1
cd NCT-Kubernetes-Range-Discovery-20261019-r1
sha256sum -c PACKAGE-CONTENTS.sha256
```

The extracted directory contains this start page, the full single-replica guide, and
`scripts/nct-kubernetes-inventory.sh`. Stay in that directory so the command below can
find `scripts/`.

## Step 1: collect the read-only inventory

From a workstation whose `kubectl` already points to the intended Range cluster, run:

```bash
set -e
report="$HOME/nct-kubernetes-inventory-$(date -u +%Y%m%dT%H%M%SZ).txt"
sh scripts/nct-kubernetes-inventory.sh --namespace nct-analysis > "$report"
cat "$report"
printf 'Saved read-only inventory: %s\n' "$report"
```

The script only reads cluster and local context status. It pins every cluster request to
the context shown at the top of the report and applies a ten-second request limit. It
does not submit authorization reviews, create, apply, patch, scale, restart, delete,
copy, or execute anything, and it never reads Secrets. Save the output outside the NCT
data volume.

The final **Planning result** must say `FRESH CANDIDATE` or `POSSIBLE FRESH
SIDE-BY-SIDE TRIAL` before the fresh path can continue. `BLOCKED`, an unreadable
namespace, an incomplete list, or any unexpected resource stops the fresh path.
The inventory cannot select Recovery. Use Recovery only when the cluster administrator
identifies both a verified Kubernetes backup and an approved empty restore target;
otherwise treat retained-volume and unknown states as `BLOCKED`.

The report must establish:

- the intended Kubernetes context and actual cluster server address;
- the target namespace and whether NCT already exists there;
- the Kubernetes version and node architecture;
- available storage classes and the selected CSI-backed class;
- available Ingress or Gateway support;
- whether the Metrics API is available;
- any existing workload, Service, claim, retained volume, nondefault ConfigMap, recovery
  record, or Ingress associated with that namespace.

If the report shows an existing resource, retained volume, or recovery record that
nobody expected, stop. Do not reuse or delete it merely because its name looks familiar.

Review the saved `.txt` report, then send **only that report** to the cluster
administrator through the approved channel. Never send kubeconfig files, Docker data,
Secrets, passwords, private keys, or tokens with it.

## Step 2: obtain the administrator-owned values

The cluster administrator must return all of these before deployment rendering:

| Required value | Why it is needed |
|---|---|
| Dedicated namespace | Keeps the optional health reader from seeing unrelated workloads. |
| Exact image registry reference ending in `@sha256:...` | Proves which immutable NCT image every eligible node will run. |
| Registry/import procedure and pull credential status | Proves the disconnected cluster can actually retrieve the image. |
| Storage class, CSI driver, filesystem, and capacity | Identifies the exact persistent storage that must be qualified for SQLite. |
| Analyst HTTPS DNS name and trusted public CA chain | Provides the approved browser entry point without bypassing certificate checks. |
| Egress policy decision | States whether the analysis pod is fully air-gapped or may reach approved services. |
| Node count and eligible node architecture | Determines which image is usable and whether later two-node recovery testing is possible. |
| Operator permissions | Confirms who may apply the rendered resources and inspect their status. |

Do not put a password, private key, registry token, or Secret contents in the inventory
report, renderer command, generated JSON, or support message.

## Step 3: choose the trial boundary

Before the Kubernetes trial, record the current standalone Docker baseline without
changing it:

| Existing Docker fact | Record |
|---|---|
| Analyst URL and HTTPS port | The address analysts use today. |
| Container and exact image/build | The running container name plus the build shown in NCT. |
| Persistent host data location | The host folder mounted at `/data`. Do not copy or move it. |
| Baseline evidence | Visible scan, device-collection, artifact, and user counts needed to confirm the original installation remains unchanged. |

Leave the current Docker installation running, addressable, and unchanged through the
Kubernetes trial and acceptance. If the Range administrator later requires it to stop,
treat that as a planned service interruption with a recorded return procedure. The
inventory script and fresh
Kubernetes trial do not inspect, stop, upgrade, migrate, or mount that installation.
The administrator must assign a different Kubernetes HTTPS DNS name or port so the trial
cannot silently replace the current analyst address.

For the first Range trial, use a new namespace and new claim. Do not point the
Kubernetes candidate at the Docker host data directory. There is no reviewed
host-folder-to-PVC migration procedure yet.

Once the values above are available, follow the **Ordered deployment runbook** in
[`KUBERNETES_SINGLE_REPLICA.md`](KUBERNETES_SINGLE_REPLICA.md). That runbook creates the
claim, qualifies the exact bound volume, creates temporary first-login credentials,
renders the one-replica Deployment, and hands HTTPS work to the cluster administrator.

## Step 4: know what success means

The Kubernetes candidate is usable for analyst testing only after all of these pass:

- exactly one NCT pod is Ready and replacement strategy is `Recreate`;
- the qualified PVC and PV identities match the saved report and Deployment annotations;
- HTTPS login works without a browser certificate warning;
- the temporary bootstrap Secret is removed after the administrator account is confirmed;
- startup, readiness, and liveness checks are healthy;
- retained evidence can be imported, viewed, and downloaded;
- System Health says **Kubernetes · one replica · analysis only**;
- live scans, enabled schedules, SSH collection, and packet capture are visibly disabled
  and rejected by the server;
- the pod has no Kubernetes API token and no added Linux capabilities;
- the exact image digest shown by the pod matches the approved registry digest.

This proves a functioning trial. It does not by itself prove Range readiness. Range
promotion additionally requires the exact-cluster backup/restore, failure/replacement,
node-loss, upgrade, and rollback exercises described in the full runbook.

