# Network scope registry

The network scope registry provides stable context for address and service identity.
Its reviewed administrator Settings page and API support scope creation, metadata,
history and archive; they do not assign evidence or run ingestion.

## Identity and lifecycle

- NCT generates an opaque `scope_<uuid>` ID. The ID never comes from a label, CIDR,
  Saved Network, scan target, filename or artifact hash.
- Labels and descriptions are display metadata. Labels use Unicode normalization and
  case folding to prevent confusing duplicate active names. An archived label may be
  reused, but it creates a new ID and never joins the two histories.
- Every edit requires the version the operator saw. Competing edits serialize, so one
  advances the version and the other receives a conflict instead of overwriting it.
- Scope creation, edits and archive write a complete before/after audit record in the
  same transaction. Database triggers prevent scope deletion, ID changes, and audit
  update/deletion. An audit failure rolls the scope change back.
- Archive is permanent in this slice and blocks new evidence. It does not remove or
  change existing endpoints, assessments, receipts, IDs, labels or audit records.

## Evidence enforcement

New assessments require an active registered scope. The active check and evidence
write share one immediate transaction, so an archive racing an assessment produces
one of two complete outcomes: evidence commits before archive, or archive wins and no
evidence rows are created. Database triggers also reject direct assessment/endpoint
inserts for missing or archived scopes.

An exact replay of an assessment already committed remains an idempotent no-op after
archive. A new artifact observation, parser version or assessment in that scope is
rejected. Scope IDs on endpoints and assessments cannot be changed in place.

## Compatibility and remaining gates

Pre-registry scope IDs are retained byte-for-byte as inactive legacy records with an
immutable migration event. The migration does not rebuild or modify entity/receipt
tables and is idempotent. Legacy scopes cannot silently accept new evidence.

The internal [evidence assignment contract](EVIDENCE_SCOPE_ASSIGNMENTS.md) now records
whole-artifact observation assignments and immutable correction chains. It retains
the original assignment and provides immutable links for original and replacement
assessments. Route and ingestion wiring remain disabled until assessment, receipt and
assignment-link creation can commit atomically under a rechecked current assignment.
Mixed-scope artifacts still require a separately reviewed partition model; host-by-host
scope must never be inferred from CIDRs or Saved Networks.

Remaining work includes assignment/correction routes and UI with their own reviewed
role authorization, atomic ingestion linking, mixed-scope partitioning, read models
and production migration. Existing scope-management routes already enforce the
reviewed administrator/local-operator policy.
