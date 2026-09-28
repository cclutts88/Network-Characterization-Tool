# Evidence scope assignment and correction

This internal foundation records an operator's explicit network context for one
Artifact Registry observation. Manual Nmap uploads now have an explicit operator
workflow that records or corrects the assignment and separately asks the coordinator
to verify the retained artifact and save all scoped assessment records as one
operation. Existing Analyze, Hunt, Reach and Map results continue to use their current
read paths while this foundation is expanded.

## Identity and assignment

- Assignment attaches to `artifact_observation_id`, not a content hash. Separate
  encounters of identical bytes remain separately attributable.
- The only supported mode is `whole_artifact`. The operator must confirm that every
  address in the observation belongs to one selected network context.
- Scope is never inferred from a CIDR, Saved Network, command target, filename,
  artifact hash or address. Mixed-scope artifacts remain blocked pending a separately
  reviewed partition model.
- Initial assignment requires an active scope and creates no endpoint, service,
  assessment or receipt. An observation with an unlinked legacy assessment is blocked
  until a deliberate migration reconciliation exists.

## Correction and retention

- A correction appends one successor to the current assignment. The caller supplies
  the assignment it reviewed, so simultaneous corrections cannot create branches.
- A correction must choose a different active destination. Its source scope may have
  been archived; prior assignment rows and all prior evidence remain immutable.
- Assignment-to-assessment links are append-only and require an exact observation and
  scope match. The many-to-many link permits multiple parser versions and later reuse
  of an identical assessment when a correction returns to a previously used scope.
- Database triggers and constraints reject updates, deletion, duplicate roots,
  branches, cross-observation successors, wrong revisions, same-scope successors,
  inactive destinations, legacy-root bypasses, mismatched links and incomplete audit
  provenance. Endpoint entities, service entities, assessments and receipts are also
  immutable at the database layer.

## Internal assigned Nmap processing

- Processing accepts the exact assignment identity and processor identity. The
  observation and scope are resolved from the retained assignment; callers cannot
  supply a separate scope.
- Canonical bytes are verified and parsed before the short writer transaction. Inside
  that transaction, the coordinator rechecks that the assignment is still the current
  leaf and the destination scope remains active.
- Assessment, endpoint, service, receipt and assignment-link records commit together.
  A failure leaves none of those new records behind.
- An exact completed replay performs no writes even after a later correction or scope
  archive. A stale or archived assignment that never completed is rejected.
- A correction back to a previously used scope reuses the identical assessment for
  the same parser version and adds the new immutable assignment link. Separate
  observations and parser versions remain separate assessments.
- Database enforcement also blocks direct insertion of a new link for a superseded
  assignment or archived destination.

## Manual upload operator workflow

- The workflow is limited to exact observations created by manual Nmap XML imports.
  Upload and legacy analysis still complete first. Assignment and foundation processing
  are deliberate follow-up actions in the same Import Nmap Evidence workspace, so a
  refresh or lost response can be recovered.
- Recent observation status and immutable assignment history are read-only queries.
  They do not reparse the XML or initialize storage on the request path.
- A scope is never preselected. The operator must choose an active scope, record a
  reason and confirm that every address in the file belongs to that context. Several
  subnets may belong to one scope; mixed isolated contexts remain unsupported.
- Analysts and administrators may assign, correct and process. Viewers may review the
  status and history. Network Scope creation and archival remain administrator actions.
  Authentication-disabled installations attribute actions to the local operator.
- Processing failure retains the assignment and reports that it can be retried. A
  correction is a separate append-only decision and must then be processed explicitly.
- The workflow does not contact the network, grant scan authority, require an analyst
  to be tasked or change the current Analyze, Hunt, Reach or Map results.

## Remaining gate

Automated scan artifacts, device evidence and other imports do not enter this workflow.
Saved Network or CIDR inference, mixed-scope and per-host partitioning, migration of old
records, job processing, current-state/Last Seen views and a general read-model switch
remain separately reviewed roadmap work.
