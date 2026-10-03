# Derived Result Foundation Contract

NCT now has an internal store for completed, reusable computations. This first slice is
foundation infrastructure. Existing Analyze, Hunt, Reach, Map, device-analysis and
SearchSploit cache paths are unchanged.

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

## Current limits

An exact identity match means only that the same declared calculation was already
completed for the same verified bytes. It does not mean the result is current, latest,
fresh, or still true on the network.

Production scan-analysis reads still use the existing cache. Migrating that path requires
a separate quality gate. Device summaries, exposure reports, SearchSploit results,
coverage comparisons and other analysis families retain their existing storage. Their
full dependency and retention contracts must be defined before migration.

Dirty-state propagation, dependency scheduling, global analysis versioning, persistent
jobs, workers and operator-facing saved-result controls remain later milestones.
