# Manual Arkime Sessions JSON intake

For aggregate Tier A traffic counts, use the separate
[`ARKIME_SUMMARY_CSV.md`](ARKIME_SUMMARY_CSV.md) workflow. The summary adapter retains
grouped counts without presenting them as individual sessions or open services.

This is the manual bounded Arkime evidence path in NCT. It accepts a saved result from
Arkime's Sessions API when the JSON root contains a `data` array. It does not contact
Arkime, copy packet captures, accept an OpenSearch `hits.hits` export, or claim that a
passively observed destination port is open now.

## What the analyst records

The analyst chooses one active Network Scope and records the observation-point label,
query start and end, Arkime packet-time bounding mode, optional query expression,
their assessment of whether the query result is complete, and their separate
assessment of sensor capture coverage. A complete returned query does not prove that
the sensor captured every packet, so these two assessments remain separate.

NCT accepts `first`, `last`, `both`, and `either` packet-time bounds. It rejects
database-time searches because their index-time boundary cannot be verified using the
packet timestamps in each retained session. Epoch timestamp units are detected and
recorded; one file cannot mix seconds, milliseconds, and ISO-8601 packet times.

## Validation and retained evidence

NCT validates the complete file before publishing any database record. The initial
limit is 10 MiB and 10,000 session rows. Duplicate JSON keys, non-finite numbers,
conflicting flat and nested values, conflicting supported aliases, contradictory
result counts, invalid addresses, invalid ports, rows outside the declared time bound,
and unsupported document shapes fail closed. Missing protocol or ports remain
unknown.

Each accepted upload retains:

- the exact JSON bytes by SHA-256 content identity;
- a separate evidence observation for every upload, even when the bytes match;
- the source filename, analyst, import time, scope snapshot, operator sensor label,
  query boundary, completeness declarations, and parser version; and
- immutable per-row receipts with source ordinal, Arkime session ID when present,
  source node, addresses, ports when present, packet times, packet and byte counts,
  application fields, VLAN fields, and limited source context.

The operator sensor label adds deployment context. It never replaces the source node
stored in a session row. Overlapping imports remain separate and their counts are not
added together.

## Publication and failure behavior

The artifact observation, import record, and every session receipt commit in one
SQLite transaction. NCT rechecks that the selected Network Scope is active after the
write transaction begins. A database failure leaves none of those database records
published.

The filesystem and SQLite cannot share one transaction. NCT writes and verifies the
exact-content file before committing the database graph. A crash or forced database
failure can therefore leave an unreferenced canonical file. Ordinary NCT work never
silently deletes such a file. Storage inspection and a later reviewed maintenance
process may identify it; automatic pruning remains disabled.

All history and detail reads use read-only database connections with bounded pages and
a revision check for paging. Each history response reads its count, revision and rows
from one database snapshot. Raw-source downloads open only the exact canonical storage
components without following file or directory links, then verify the saved size and
SHA-256 before returning any bytes. The application authentication boundary protects
these routes when sign-in mode is enabled.

## Current boundary

The retained sessions are passive source receipts for analyst inspection. They do not
currently create canonical hosts or services, update Current Network or Last Seen,
feed Hunt, Reach, or Map conclusions, or establish physical-device identity. Automatic
bounded Sessions API intake is documented in
[`ARKIME_API_CONNECTOR.md`](ARKIME_API_CONNECTOR.md). Tier A connection records,
PCAP-backed workflows, timeline
correlation, and validation against the actual retained Range export remain later
Phase 6 work.
