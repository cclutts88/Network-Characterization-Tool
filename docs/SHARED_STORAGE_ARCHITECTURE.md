# NCT Shared Storage Architecture

Status: Gate 7 decision package. This document selects the storage boundary required
for a future multiple-application-replica profile. It does not enable that profile.

## Profiles

NCT retains two explicit deployment profiles.

### Standalone and single-replica profile

- SQLite remains embedded in the NCT application.
- Exact artifact bytes remain in the local content-addressed artifact directory.
- The application and its data remain portable as one offline package.
- SQLite is never placed behind a custom network service or database sidecar.
- This remains the normal disconnected-Range and constrained-hardware profile.

### Future multiple-replica profile

- PostgreSQL is the selected authoritative transactional database.
- Artifact bytes use a shared S3-compatible immutable content-addressed object store.
- The database stores the artifact SHA-256 identity, byte length, media type, backend
  identity and opaque storage key. It does not store a host filesystem path as shared
  identity.
- Database records remain the authority for observations, provenance, work claims,
  fencing epochs, maintenance state and publication receipts.
- The artifact store never decides whether an observation or job is complete.

PostgreSQL and shared artifacts are optional deployment dependencies. They are not
added to the standalone image or required for core offline operation.

## Shared artifact contract

The selected shared backend contract is an S3-compatible object service that can also
be deployed in a disconnected Range. A shared writable filesystem is not selected as
multi-replica artifact authority. The object backend must provide this behavior:

1. Address an object by `sha256/<first two hex characters>/<64 hex characters>`.
2. Create only when absent. A concurrent create of the same bytes converges on one
   object. Existing bytes are never overwritten in place.
3. Verify SHA-256 and byte length before database publication and again on requested
   integrity checks.
4. Return bytes by exact storage key. Listing is diagnostic only and is never evidence
   authority.
5. Reject links, traversal, redirects to an unapproved endpoint and mutable aliases.
6. Keep incomplete uploads private until verification succeeds.
7. Delete only through the fenced storage-maintenance workflow after a dry run proves
   the object is unreferenced. Ordinary application work never silently deletes it.
8. Expose a stable non-secret backend identity. Credentials remain outside receipts,
   logs, browser responses and migration plans.

The object backend must separately pass conditional create, read-after-write,
exact-byte, multipart-abort and deletion-fence tests. Passing the existing SQLite
volume qualification does not qualify the object service.

## Transaction and publication boundary

One PostgreSQL transaction must own each consequential state transition. All Gate 6
rules remain in force:

- leases use database time and monotonically increasing fencing epochs;
- a worker rechecks its exact claim in the publication transaction;
- object verification finishes before the transaction records it as available;
- an abandoned object upload has no observation and can be cleaned only by fenced
  maintenance;
- a committed observation points only to a verified immutable object;
- network contact never transfers from expiry alone;
- migration, backfill and compaction remain singleton maintenance work.

PostgreSQL advisory locks may help an implementation, but they do not replace durable
lease rows, fencing epochs or retained attempt history.

## Offline migration and cutover

Migration is an offline, versioned operation. Dual writing SQLite and PostgreSQL is
prohibited because the two stores cannot provide one atomic commit.

1. Stop admission and prove all writers and network-contact processes are stopped.
2. Create a verified Gate 4A cold backup. Preserve the source data directory.
3. Record the source schema contract and fingerprint, database integrity result,
   artifact and observation counts, exact artifact inventory digest and total bytes.
4. Create empty target PostgreSQL schema and an empty target artifact namespace.
5. Copy exact artifacts with conditional create and verify every SHA-256 and byte
   length. Existing matching objects may be reused; a mismatch fails closed.
6. Import structured state in dependency order while retaining globally stable IDs,
   timestamps, analyst provenance, observation history, attempt history and tombstones.
7. Recalculate database-generated constraints and indexes without changing mission
   identity or evidence meaning.
8. Verify row counts by table, foreign-key closure, immutable request digests, artifact
   references, observation counts, work states and a bounded sample plus full digest
   inventory of artifact bytes.
9. Write a cutover receipt binding the source backup, source contract, target database
   identity, target artifact backend identity, application image and verification
   report. Credentials are excluded.
10. Start exactly one application instance against the target. Complete lifecycle,
    sign-in, evidence download and read-only analyst workflow checks before any writer
    is admitted.

Migration tooling must be restart-safe by staging into a fresh target generation.
Rerunning the same source and plan is idempotent. A changed source, target identity,
schema contract or artifact inventory creates a new plan rather than modifying the old
receipt.

## Rollback

Before the shared target admits a write, rollback means stopping the target and
restarting the unchanged SQLite source after its backup and writer lock are verified.

After the target admits any write, direct image or database rollback to the old SQLite
source is prohibited. The old source would omit new observations, analyst actions and
work history. Recovery then requires:

- preserving the failed shared target and its receipts;
- exporting any recoverable post-cutover mission events and artifacts;
- restoring the verified pre-cutover backup to a separate target generation;
- explicitly reconciling post-cutover events through the later portable mission-bundle
  contract; and
- recording the data-loss or reconciliation decision.

NCT does not claim that reverse PostgreSQL-to-SQLite migration exists at Gate 7.

## Implementation sequence after this decision

Gate 7 selects the architecture and freezes its machine-readable contract. The profile
remains blocked until later work provides:

1. a database portability layer and PostgreSQL schema/migrations;
2. a shared artifact adapter and backend-specific qualification;
3. offline migration, verification and cutover receipts;
4. deployment configuration that never exposes secrets;
5. Gate 8 multi-replica concurrency, failure, upgrade and load tests; and
6. Gate 9 representative disconnected-Range validation.

Until those items pass, System Health and deployment tooling must report multiple
application replicas as unsupported.
