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
database sidecar. A future multiple-replica profile requires a separately reviewed,
real shared transactional database; PostgreSQL is one possible candidate, not a selected
dependency or approved design.

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
- never read Secrets, arbitrary annotations, logs, exec endpoints or unrelated objects;
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
4. Forced termination, rescheduling, node-loss, backup, restore, upgrade and rollback
   tests with retained evidence verification.
5. Optional Kubernetes health adapter with denied-access, timeout, truncation and
   no-Metrics-API tests.
6. Cross-process worker leases, fencing and singleton-operation coordination.
7. Shared database and artifact-storage decision with migration and rollback design.
8. Multi-replica concurrency and failure testing.
9. Representative disconnected Range validation.

Acceptance status: gates 1 and 2 are implemented on `foundation/evidence-engine-v2`.
Gate 1 provides the local provider and bounded administrator System Health display.
Gate 2 provides side-effect-free lifecycle probes with explicit recovery and shutdown
semantics. Application-side gate 3A now adds a process-lifetime writer guard acquired
before SQLite opens, atomic shutdown admission fences for local writer families, and
fail-closed retention when shutdown cannot prove every writer stopped. Gate 3 remains
open until single-replica manifests, least-privilege permissions and the exact durable
storage class pass lock, rename, `fsync`, WAL and SHM qualification. Gates 4 through 9
also remain open. Completing gates 1, 2 and 3A does not make this build Kubernetes-ready.

Only the completed profile may be claimed. Single-replica Kubernetes success does not
establish multi-replica, Range or mission readiness.
