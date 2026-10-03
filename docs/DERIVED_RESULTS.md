# Derived Result Foundation Contract

NCT has an internal store for completed, reusable computations. Production Nmap views
now use its verified file-reading result. Device-analysis and SearchSploit retain their
existing result paths.

## Identity and reuse

A computation identity includes:

- result family
- analysis version
- payload schema version
- canonical parameters
- role-labelled input identities and input metadata

The first adapter accepts one registered Nmap XML artifact. It verifies the retained
bytes against the Artifact Registry SHA-256 and size before reading or publishing a
result. Its reusable payload contains only the output of `parse_xml()` for those exact
bytes. It does not contain a run, Network Scope, assignment, analyst, observation time,
group merge, identity override, topology enrichment, or current-state decision.
The adapter is bound to that declared parser. A different calculation must use a
different declared family or version rather than populate this result identity.

Identical bytes may reuse one computation. Every artifact observation remains separately
linked so shared computation never collapses provenance. Changed bytes cannot reuse a
result even when file size and modification time are identical.

## Publication and integrity

Payload serialization and parsing occur before the short publication transaction. The
result row, immutable input manifest, and observation association commit together.
Publishing the same identity and payload is idempotent. Publishing different content
under the same identity is a conflict and leaves the retained result unchanged.

Stored payloads are canonical JSON with a retained SHA-256. Reads verify the hash,
identity and input rows, then reject unreadable or noncanonical content without changing
source evidence. Publication recomputes supplied identities and payload hashes before
writing. Later observation links are checked against the retained input manifest inside
the same transaction instead of trusting caller-supplied identity fields.

Derived results are disposable computation. They may be deleted and rebuilt without
deleting source evidence. Observation links disappear if the corresponding observation
is removed, while the reusable result may remain. A missing observation cannot authorize
a new link or result publication.

## Production Nmap use

Analyze, Hunt, Reach and scan-comparison paths use the shared Nmap file reading for
terminal scans that have exactly one registered `nmap_scan` observation for the run's
aggregate `scan.xml`. NCT verifies the run-local file and canonical retained file against
the same exact-content identity on every read. A warm result with its encounter already
linked uses one consistent read-only database snapshot and performs no database write.

The Map topology loader and device-analysis topology enrichment retain their existing
specialized Nmap parser in this milestone. They do not yet use this shared reading.
Nonterminal runs may still be read directly from a stable run-local XML snapshot, but
their analysis is neither published nor reused. If a run stops being terminal while a
new reusable result is being calculated, publication is rejected.

Run grouping, partial-result warnings, Network Scope, source links, analyst overrides,
topology enrichment and presentation remain outside the reusable result. Reusing the
file reading never starts, skips or changes a network scan and never combines separate
evidence encounters.

Historical scan XML without a registered observation remains readable by directly
parsing its current bytes on each request. Page reads do not register it or perform
backfill. After explicit storage backfill creates the exact observation, later reads may
use verified reuse. Ambiguous observations, missing registered evidence, changed
run-local copies, corrupt canonical bytes and deleted runs fail explicitly.

The old size-and-modification-time `scan_analysis_cache` contained disposable calculated
data and is removed by an idempotent startup migration. Historical scan XML, manifests,
audit records and artifact observations are not removed. Older rollback code can create
an empty legacy cache and rebuild it from the retained XML. All application processes
sharing a database must be restarted together for this migration; mixed old and new
processes are not supported during the transition.

## Current limits

An exact identity match means only that the same declared calculation was already
completed for the same verified bytes. It does not mean the result is current, latest,
fresh, or still true on the network.

Device summaries, exposure reports, SearchSploit results, coverage comparisons and other
analysis families retain their existing storage. Their full dependency and retention
contracts must be defined before migration.

Dirty-state propagation, dependency scheduling, global analysis versioning, persistent
jobs, workers and operator-facing saved-result controls remain later milestones.
