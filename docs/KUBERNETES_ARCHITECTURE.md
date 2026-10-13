# Kubernetes-capable NCT architecture

## Status and intent

This document is the design boundary for building NCT with Kubernetes capabilities in
mind. It does not claim that the current build is Kubernetes-ready or safe to scale to
multiple application replicas.

NCT must preserve two goals at the same time:

1. Core collection, evidence retention, analysis and review continue to work offline in
   one container on constrained Range hardware.
2. New code avoids local-only assumptions that would force a later redesign before NCT
   can run under Kubernetes.

Kubernetes, PostgreSQL, Redis, Elasticsearch and cloud services remain optional. No core
analyst workflow may require them.

## Deployment profiles

### Standalone

One NCT application process owns a local SQLite database and retained evidence root.
This remains the default offline and constrained-hardware profile.

### Kubernetes single replica

The first Kubernetes profile will run exactly one NCT application replica with durable
storage. It may expose read-only deployment and pod health when the cluster grants the
approved namespace-scoped permissions.

ReadWriteOnce storage is not a single-writer guarantee. Kubernetes can attach the same
volume to overlapping pods on one node. This profile therefore requires all of the
following:

- application replicas fixed at one;
- autoscaling disabled;
- a non-overlapping replacement strategy;
- fail-closed startup when the former writer may still be active;
- graceful shutdown and a bounded termination window;
- startup recovery before readiness;
- storage qualified for SQLite locking and durability.

### Kubernetes multiple replicas

This profile is future work. It remains unsupported until NCT has:

- cross-process job leases with expiry and fencing;
- idempotent publication and lost-claim protection across replicas;
- explicit coordination for singleton migrations, compaction, backfill and scans;
- a reviewed shared transactional database design;
- a reviewed shared or partitioned artifact-storage design;
- multi-replica upgrade, rollback, failure and load tests.

A Kubernetes manifest or successful pod start does not satisfy this gate.

SQLite remains embedded in the NCT application for standalone and approved
single-replica deployments. NCT must not put SQLite behind a custom network service or
database sidecar. Gate 7 selects PostgreSQL as the future multiple-replica transactional
authority and an S3-compatible immutable content-addressed object API as its artifact
authority. That decision does not enable multiple replicas: the adapters, migration,
service qualification and Gate 8 concurrency/failure testing remain unfinished. The
full decision and rollback boundary are recorded in
`docs/SHARED_STORAGE_ARCHITECTURE.md`.

## Runtime and mission identity

Pod names, pod IPs, container names, node names and process IDs are temporary runtime
labels. They may appear in health diagnostics but may not become durable identity for a
mission, site, analyst, artifact, observation, job, device, host or finding.

Durable work must retain globally stable identifiers, exact inputs, processing contract,
attempt history and evidence provenance. A replacement pod must be able to decide from
saved state whether work is queued, running under a valid lease, safely recoverable,
complete or blocked for review.

## Health and observability

NCT health uses a provider-neutral model. The local provider works without Kubernetes.
An optional Kubernetes adapter may add deployment context.

Health meanings stay separate:

- **Startup:** migrations and required recovery have finished.
- **Readiness:** this instance may accept new requests or work.
- **Liveness:** the process is responsive and should not be restarted merely because an
  optional dependency is unavailable.
- **Workload health:** queues, workers, failures, retries and retained results.
- **Resource health:** current and peak CPU, memory, disk and database use.

Health reads must be bounded, side-effect-free and inexpensive. Opening System Health
must not initialize schema, hash evidence, start a benchmark, enqueue work or contact a
network target.

The application exposes three fixed, unauthenticated orchestration probes. They bypass
session lookup and return `Cache-Control: no-store`:

- `/health/startup` reports success after required initialization and the recovery
  safety check finish. An unresolved compaction condition may remain safely fenced so
  an administrator can inspect and recover it; a fatal initialization or recovery
  exception prevents startup.
- `/health/readiness` reports success only while the HTTP instance may safely accept
  requests. Optional dependency loss, absent SearchSploit data, failed saved work and a
  safely fenced recovery condition belong to workload or storage health rather than
  making the administrative service unavailable.
- `/health/liveness` reports only that the process can answer. It does not query SQLite,
  inspect disk, check workers or contact a network target.

The legacy `/health` response remains available for existing deployment tooling.
Readiness is cleared before local shutdown cleanup begins, but that ordering alone does
not prove Kubernetes Service removal or traffic draining; those remain deployment-gate
tests.

The Kubernetes adapter must:

- use a dedicated read-only ServiceAccount;
- be limited to one configured namespace and fixed NCT labels;
- read only approved Deployment, ReplicaSet and Pod status fields;
- never read Secrets, logs, exec endpoints or unrelated objects, and never inspect, use,
  or return arbitrary annotations present in bounded Kubernetes responses;
- enforce strict item, response-size and time limits;
- return coarse non-secret status to the browser;
- report denied, missing or timed-out access as **Unavailable**, not zero;
- remain optional so local health continues when the cluster API is absent.

Per-pod CPU and memory require an explicitly configured Metrics API or equivalent
provider. Pod counts and readiness must not imply that resource metrics exist.

## Storage qualification

A Kubernetes storage class is not approved for SQLite merely because it mounts. Before
use, the exact driver, access mode and filesystem must prove:

- reliable advisory file locks;
- atomic rename within the database and evidence boundaries;
- durable `fsync` behavior;
- correct SQLite WAL and SHM behavior;
- stable ownership and permissions after pod replacement;
- backup and restore with the database in a consistent state.

Unsupported network filesystems fail closed. The approved layout must name the database,
WAL/SHM side files, artifacts, job state, generated reports, backups and restore target.
Evidence and database backups must retain compatible provenance and recovery order.

The explicit `scripts/qualify_kubernetes_storage.py` check covers only the exact mounted
environment supplied to it. It works in a new private disposable directory and does not
open the NCT database or retained evidence. A controller enforces the complete run's time
limit. Workers stay bound to the already-open directory and an orchestrator-only marker,
so replacing a path cannot redirect a check. Synchronized and continuous independent
observers cover each replacement result and the replacement interval. A passing report
demonstrates the bounded lock, observed repeated replacement, sync and SQLite WAL checks
recorded in that run; its SHA-256 digest is an
unauthenticated integrity value, not a signature or storage-class approval. Driver and
volume identity must be declared by the operator and retained with the measured report.
Replacement stability, backup/restore, node loss, forced termination and upgrade or
rollback behavior still require later acceptance gates.

## Upgrades and rollback

Image rollback and data rollback are different operations. A previous image must never
silently open a newer incompatible schema.

Every Kubernetes upgrade design must define:

- preflight version and schema compatibility;
- migration ownership and single-execution protection;
- verified backup/checkpoint requirements;
- forward-compatible image rollback or a tested data-restore procedure;
- readiness only after migration and recovery complete;
- failure behavior that leaves evidence and prior valid analysis available.

Ordinary rolling replacement is prohibited while SQLite is the application database.

## Jobs, scans and graceful termination

New long-running work must be durable and idempotent. A pod receiving termination must
stop claiming work, finish or checkpoint only within its reviewed contract, preserve the
attempt record and release or allow expiry of its claim. Restart recovery must distinguish
an interrupted attempt from completed output and must never publish partial results.

Network scanning and device collection are placement-sensitive. A future scheduler must
bind work to approved network reachability, interface, node labels and minimum Linux
capabilities. Web replicas must not automatically inherit raw-network privileges. The
deployment must not assume every Kubernetes node or pod can reach every mission network.

## Configuration and secrets

Images are immutable. Runtime configuration, TLS material and credentials stay outside
the image. Secret values are never returned by System Health, logs or the Kubernetes
adapter. Configuration identity may be recorded as a safe digest or version without
recording its secret content.

## Acceptance sequence

Kubernetes capability advances only through reviewed gates:

1. Provider-neutral local live-health measurements and bounded System Health display.
2. Side-effect-free startup, readiness and liveness endpoints.
3. Single-replica Kubernetes manifests with least-privilege permissions and qualified
   durable storage.
4. Failure and recovery acceptance, split into reviewed sub-gates while aggregate Gate 4
   remains open:
   - **4A:** cold backup, isolated restore, and retained-evidence verification;
   - **4B:** forced termination, replacement, rescheduling, and node loss;
   - **4C:** upgrade, schema compatibility, image rollback, and data rollback.
5. Optional Kubernetes health adapter with denied-access, timeout, truncation and
   no-Metrics-API tests.
6. Cross-process worker leases, fencing and singleton-operation coordination.
7. Shared database and artifact-storage decision with migration and rollback design.
8. Multi-replica concurrency and failure testing.
9. Representative disconnected Range validation.

Gate 6 is implemented in work-family packages. Its common contract uses the
authoritative transactional database, database time, opaque leases and monotonically
increasing fencing epochs. Kubernetes Lease objects, Pod names, process IDs, RWO storage
and filesystem locks may support diagnostics or placement but never authorize result
publication. Retained-evidence analysis may be reclaimed only after expiry and must
start a new attempt from immutable inputs. Network contact is never reassigned from an
expiry alone. Compaction, backfill and migrations require reviewed recovery after
uncertain ownership. Scheduler work requires unique durable occurrences and chunk
claims in addition to any leader election. The completed Gate 6 packages cover the
common contract, saved-analysis workers, storage-maintenance exclusion, active Nmap,
durable scheduled occurrences and interactive device contact. Network-contact work
never transfers from lease expiry alone. A restart before device contact closes the
original attempt and requires a new operator-started collection; a restart after
possible contact requires attributed administrator review. The initial Kubernetes web
profile remains analysis only because collection placement and privileges are a
separate deployment decision.

Acceptance status: gates 1 and 2 are implemented on `foundation/evidence-engine-v2`.
Gate 1 provides the local provider and bounded administrator System Health display.
Gate 2 provides side-effect-free lifecycle probes with explicit recovery and shutdown
semantics. Application-side gate 3A now adds a process-lifetime writer guard acquired
before SQLite opens, atomic shutdown admission fences for local writer families, and
fail-closed retention when shutdown cannot prove every writer stopped. Gate 3B provides
the bounded exact-mount qualification tool. Gate 3C is complete on the foundation
branch: claim creation is separate from qualification, and the report, Job, and
Deployment bind both the immutable claim UID and bound-volume UID. The generated web
profile is one analysis-only replica with `Recreate`, forced local authentication, no
API token or RBAC, no Linux capabilities, and exact qualification-report binding. Active
Nmap, schedules and device contact are disabled in both the interface and server routes;
a future collection worker requires its own reviewed placement and privilege profile.
Gate 3C's final image and exact mounted-storage exercise passed its package acceptance
checks. This completes the foundation package, but exact-cluster apply, HTTPS, and
exact-volume deployment acceptance remain open. Gate 4 remains open for cold backup and
isolated restore proof, forced termination, rescheduling, node loss, upgrade, and
compatible rollback. Gates 5 through 9 also remain open. Completing the foundation
packages for gates 1 through 3 does not make this build Kubernetes-ready, Range-ready,
or mission-ready. See
`docs/KUBERNETES_SINGLE_REPLICA.md`.

The foundation package for Gate 4A now provides the reviewed cold-backup and isolated-
restore Jobs, validation tool, receipts, capacity boundary and complete administrator
runbook. Its independent quality gate is **CLEAR — DOCUMENTED DEVIATION**: hard-linked
paths restore as separate byte-identical regular files, and SHA-256 receipts detect
change without providing authenticated signatures. Gate 4A acceptance remains open until
the complete runbook succeeds against the exact cluster, image and three qualified
volumes, including restored startup, existing-account sign-in and retained-evidence
download. This package status does not change the open Gate 4 aggregate or later gates.

Gate 4B deliberately fails closed during ambiguous node loss. The one-replica Deployment
tolerates not-ready and unreachable node taints indefinitely so Kubernetes cannot evict
the old Pod and automatically create a possible second writer. An external operator must
prove node fencing and storage detachment before removing the stale Pod and permitting a
replacement. The foundation package includes an existing-file-only writer-lock probe,
bounded runtime snapshots, cold inspection of a complete protected private copy,
Gate 4A restore-receipt verification, durable-work transition verification, and four
administrator exercises for forced process termination, Recreate replacement,
controlled rescheduling, and fenced node loss. NCT and those Jobs receive no Kubernetes
API token or RBAC. The verifier binds a structured single-writer event sequence to the
old and new Pod, node, Deployment generation, PVC/PV and distinct old/new attachment
identities. Controlled rescheduling and node loss require the old attachment to be
detached before a replacement is created; node loss also requires a retained provider
fencing record. The verifier checks the external records' hashes and event order but
does not authenticate or interpret the provider statements. This is a documented
availability tradeoff: evidence safety takes priority over automatic failover. Local
package validation cannot prove CSI detachment, scheduler behavior, a node's power
state, or two-node recovery; Gate 4B remains open
until all four exercises pass on the exact qualified cluster and restored data target.

The foundation package for Gate 4C adds an image-owned schema contract and a durable
migration ledger to application startup. The contract binds the application version,
build, commit, readable and writable schema versions, evidence-layout contract and
migration-plan digest. Startup records a migration attempt before other schema writers
run, retains failed or interrupted state, and does not become Ready until the same
idempotent migration plan completes with before/after schema fingerprints. A bounded
administrator tool creates cold inspection, preflight and final upgrade/rollback
receipts tied to exact old/new images, runtime image IDs, Deployment generation, Pod,
node, storage attachment, PVC/PV and qualification report. It verifies database
integrity, registered artifacts, retained counts, ordered events, existing-account
sign-in, lifecycle checks and the same evidence download. Direct rollback is permitted
only when the old image itself declares the exact current schema writable and readable
with the same layout and completed migration plan. Every changed or unknown contract
requires restoring the verified pre-upgrade Gate 4A backup to a separate empty qualified
target while preserving the failed upgraded claim. Local receipts can detect changed
inputs but cannot prove cluster scheduling, CSI attachment behavior or an exact-cluster
upgrade; Gate 4C remains open until both compatible and restore-required branches pass on
the intended cluster.

This package establishes the first Gate 4C-capable baseline. A participating old image
must already provide its own bound contract and completed schema ledger; a pre-contract
release is recoverable through Gate 4A but cannot be represented as a Gate 4C-compatible
old image. The final verifier also requires the real Gate 4A restore receipt for restore
branches, phase-bound released-writer receipts, and ordered cluster samples with at most
one Ready Pod and one writer owner.

Gate 5 uses a separate optional adapter workload. The NCT application Pod retains its
token-free runtime ServiceAccount and never calls the Kubernetes API. The adapter has a
dedicated ServiceAccount, one namespace Role, a projected short-lived token and no NCT
data volume. It may only get or list Deployments, ReplicaSets and Pods; Metrics API Pod
access is a second explicit opt-in. The adapter requests the fixed NCT labels, then
requires the exact configured Deployment UID to own every accepted ReplicaSet and an
accepted ReplicaSet UID to own every accepted Pod. A matching label without that owner
chain fails closed. It returns only coarse counts and current aggregate resource use.

Kubernetes RBAC cannot restrict list access by labels. This first profile therefore
requires an NCT-only namespace. In a shared namespace the adapter credential could
technically list unrelated objects even though its client supplies the fixed selector,
rejects unrelated ownership and never returns names, UIDs, nodes, images, annotations,
logs, commands, environment values or raw responses. The adapter disables redirects and
environment proxies, verifies the mounted cluster CA, uses a fixed API destination, and
enforces four requests, 32 items per list, 256 KiB per response, 512 KiB total response
data and a 2.5-second total budget. Pagination, excess data, malformed ownership,
denial, timeout and API loss become **Unavailable**, never zero. A 15-second cache and
single-flight sampling prevent browser refreshes from multiplying API requests.
Adapter delay or failure does not affect NCT startup, readiness, liveness, local health,
work admission or evidence handling.

Only the completed profile may be claimed. Single-replica Kubernetes success does not
establish multi-replica, Range or mission readiness.

The Gate 5 foundation package is complete and independently reviewed on
`foundation/evidence-engine-v2`. That package supplies the bounded adapter, rendered
RBAC and Service, application-side cached reader, System Health presentation, Operator
Guide topics, denial/timeout/truncation tests and exact-cluster acceptance procedure.
Gate 5 acceptance remains open until those procedures pass on the named NCT-only
namespace and exact cluster; package completion does not establish cluster, Range,
mission, multi-replica or stable-`main` readiness.

Gate 6 is complete and independently reviewed on
`foundation/evidence-engine-v2`. It provides the common database-time lease and
fencing contract, protected recovery for retained-evidence analysis, strict
recovery-required handling for storage maintenance, durable scheduled occurrences,
and dedicated active-Nmap and interactive-device-contact packages. None of those
network activities transfer merely because ownership expires. Gate 7 may now define
the shared database and artifact-storage boundary; multiple application replicas remain
unsupported until that decision is implemented and Gate 8 concurrency and failure
testing passes.
