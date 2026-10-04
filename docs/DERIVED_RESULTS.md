# Derived Result Foundation Contract

NCT has an internal store for completed, reusable computations. Production Nmap views
and every supported new device collection use verified reusable results. SearchSploit
retains its existing result path.

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

Map and Network Devices use a separate `nmap_topology_hosts` family because their
established topology interpretation intentionally differs from the base Analyze
payload. It preserves the existing host order and duplicates, assumed, down and
status-missing host records, open or state-missing ports, service defaults, MAC/vendor,
operating-system label and traceroute details. It shares the same exact scan selection,
terminal-state, run-local and canonical-content checks, atomic publication, and
per-observation provenance links as the base family. Reusing the base family here would
silently remove information that Map and device correlations already show.

Map continues to consider its current newest 200 scan records, while device correlation
continues to consider only completed scans from that same bounded set. Nonterminal Map
runs may still be read directly from a stable run-local XML snapshot, but their topology
reading is neither published nor reused. If a run stops being terminal while a new
reusable result is being calculated, publication is rejected. A registered scan that
cannot be verified is omitted and produces a visible Map warning or Network Devices
review item instead of being silently trusted.

Run grouping, partial-result warnings, Network Scope, source links, analyst overrides,
Map graph assembly, device-interface correlation, imports and presentation remain
outside the reusable results. Reusing a file reading never starts, skips or changes a
network scan and never combines separate evidence encounters.

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

## Calculation compatibility status

System Health shows a read-only, paged status for the three reusable result families
currently governed by this contract: Nmap analysis, Nmap topology and device summaries.
The status is calculated from each retained result every time it is requested; NCT does
not store or update a mutable status flag.

- **Current** means the saved calculation version, output format and declared settings
  exactly match the rules supported by the running build.
- **Stale** means NCT recognizes the result family, but one or more of those calculation
  rules differ. The retained result and its evidence are not deleted.
- **Unknown** means this build cannot safely interpret the saved family or its contract
  metadata. Unknown results never default to Current.

This status describes calculation compatibility only. It does not prove that the source
evidence is recent or intact, that the result is still true on the network, or that it
applies to a different collection. Existing source-byte, authority and provenance checks
remain mandatory whenever a result is consumed. Rolling back to a build whose exact
contract matches a retained result makes that result Current again without rewriting it.

## Direct inputs and source records

The first dependency view is a read-only drill-down from one saved result. A result is
the calculation node. Every declared input role is a separate direct edge into that
calculation, even when two roles use identical bytes. An Artifact Registry observation
linked to a role is a source encounter that supplied those exact bytes; it is provenance
for that role, not another calculation dependency.

NCT derives this view from each immutable saved input manifest, its retained input rows
and exact observation links. It verifies that the computation identity, manifest and
rows agree before showing them as trustworthy. Input roles and source encounters are
paged separately, and the interface summarizes descriptor metadata rather than dumping
full semantic manifests or command text. Missing command history, an embedded history
section and a dedicated empty history file remain different recorded input types. If an
observation was deleted, the input remains but the view says that no retained source
record is linked; NCT does not invent provenance.

This relationship check does not rehash or inspect source files, verify result payload
bytes, determine freshness, mark anything dirty or schedule rebuilding. The first view
supports only exact reviewed family, version, output-format and settings combinations;
unknown or changed contracts are shown as unsupported rather than inferred from familiar
names or roles. No graph table or data migration is needed,
so rollback uses the same retained immutable records.

## Saved calculations using an input

The reverse lookup starts from one verified result and input role. NCT resolves that
role's input kind and exact identity on the server, then pages saved input rows that
record the same pair. Matching only an identity is insufficient because an artifact
digest and a calculation descriptor can use the same text while representing different
input types. Separate roles remain separate recorded relationships even when they use
the same bytes.

For a calculation contract supported by the running build, NCT verifies the saved
computation identity, manifest, complete input rows and provenance links before calling
the candidate a verified direct relationship. Older, changed or unknown contracts stay
visible as unsupported saved-record candidates; their input-row relationship is not
interpreted as trusted. A conflicting supported record fails visibly. Candidate totals
and verified relationships on the current page are reported separately, so an empty or
partly unsupported page is not presented as a database-wide integrity audit.

An additive startup index on input kind, exact identity, result and role keeps the
bounded lookup deterministic without writing during requests. The lookup reads retained
relationships only. It does not inspect source files, multiply relationships for
duplicate observations, determine evidence freshness, predict invalidation, mark results
stale, traverse indirect dependencies or rerun analysis.

## Saved calculation version inventory

System Health groups retained reusable calculations by their exact saved family, rule
version, output schema and settings. Settings that differ remain separate groups even
when their family and version match. Each group reports its compatibility with the
running build, number of saved calculation results, and earliest and latest calculation
creation time. An operator can open a separately paged list of the exact results in the
group.

The group and result pages use read-only database snapshots. Unfamiliar families and
malformed contract metadata remain visible as Unknown rather than being dropped or
merged. Counts come from calculation rows only, so multiple evidence encounters linked
to one shared result do not inflate them. Page status counts describe only the displayed
groups; NCT does not claim database-wide compatibility totals without evaluating every
group.

This is a saved-version inventory. A Stale group may already have a Current replacement,
and its result count is not a count of jobs required. The inventory does not inspect
source bytes, determine evidence freshness, mark results stale, invalidate dependents,
schedule work or rebuild analysis.

## Operator-requested saved analysis jobs

From Scan History, an analyst can explicitly choose **Prepare saved analysis** for one
finalized scan that has exactly one authoritative registered aggregate `scan.xml` and
an intact run-local copy. The first job type runs only the current Nmap base-analysis
contract. It reads retained files and never starts Nmap or contacts the network.

The durable request freezes the scan encounter, artifact observation, digest, size,
calculation family, rule version, output schema, settings and expected computation
identity. A request token makes browser retries idempotent without merging separate
scan encounters. Identical bytes from separate encounters may reuse one verified result,
while both jobs and both provenance links remain visible.

Queued work survives a restart and resumes automatically. A restart does not attempt to
continue halfway through parsing: any attempt that was running is marked Interrupted.
The analyst can explicitly retry it from Scan History, which adds another attributed
attempt and starts the local calculation again from the verified retained file. Missing,
changed or ambiguous evidence fails visibly and does not recommend or start a rescan.

Workers claim queued attempts in short database transactions. File verification and
parsing happen outside the writer transaction. Before publication, NCT rechecks the
authoritative scan observation, finalized run state and worker claim. The result, input
rows, observation link and successful attempt outcome commit together. Losing the claim
or encountering a corrupt retained result rolls back publication. Job-status reads are
bounded and read-only.

This first runner assumes one NCT application process for a database. It has no bulk
requests, cancellation, automatic retries, automatic stale scheduling, cross-process
leases, progress checkpoints, topology jobs or device-summary jobs.

### Pipeline queue cutover and rollback boundary

The supported-ingestion work moves saved-analysis requests into additive pipeline job,
request and attempt tables before adding more stage types. At startup, before any worker
starts, NCT copies any retained legacy job history in one transaction. Job IDs, request
tokens, attempts, attribution, timing, errors, result links and the frozen calculation
contract remain exact. Counts, relationships and deterministic content fingerprints must
match before a migration marker is written. A partial schema, orphan, missing request,
missing attempt, interrupted copy or mismatched retry chain blocks startup and leaves no
completed migration.

After a successful copy, database triggers freeze all retained legacy queue tables against
inserts, updates and deletes. This prevents an old worker claim from publishing a result
and then marking obsolete queue state complete. Queued replacement attempts remain queued;
replacement attempts left running are marked Interrupted by normal startup recovery and
must be explicitly retried. All current routes, claims, retries, status reads and completion
writes use only the pipeline tables. There are no dual writes or fallback reads.

This cutover is not compatible with an ordinary rollback to older application code. Older
code cannot see post-cutover requests and its retained queue is deliberately read-only.
All NCT processes using the database must be stopped and upgraded together. Preserve the
database, stop every worker, and roll forward if recovery is needed. A future rollback tool
would have to reconcile post-cutover history explicitly before older code could run; none
is currently provided.

## Current limits

An exact identity match means only that the same declared calculation was already
completed for the same verified bytes. It does not mean the result is current, latest,
fresh, or still true on the network.

New manual uploads and new completed, untruncated SSH collections use the verified device
summary result path. Their exact configuration, raw output and command-history roles,
selection order, parser limits, semantic manifest fields and artifact observations are
frozen before activation. Failed, incomplete and truncated collections keep their files
but cannot publish analysis. Historical device collections remain reviewable and
downloadable; they require a separate adoption migration before verified analysis is
available. Legacy device-cache tables and rows remain only for rollback safety and are
not read or written by new production analysis.

Exposure reports, SearchSploit results, coverage comparisons and other analysis families
retain their existing production storage and do not appear in calculation compatibility
status yet.

Input freshness, dirty-state propagation across dependencies, transitive scheduling,
automatic rebuilding, global analysis versioning and broader job families remain later
milestones. Calculation compatibility status itself does not schedule or perform work.
