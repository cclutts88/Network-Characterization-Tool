# Evidence scope assignment and correction

This internal foundation records an operator's explicit network context for one
Artifact Registry observation. It does not ingest, parse, move or rewrite evidence.
No application route or user interface calls it yet.

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

## Remaining gate

Production ingestion must accept the reviewed assignment ID rather than a caller
supplied scope. It must resolve the observation and scope server-side, verify the
assignment is still the current leaf and the destination scope is active, then commit
the assessment, receipts and assignment link in one write transaction. Exact replay,
correction-versus-ingestion races, archived-scope behavior, role authorization and the
operator workflow require their own review before any route is enabled.
