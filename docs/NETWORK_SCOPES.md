# Network scope registry

The internal network scope registry provides stable context for address and service
identity. It is foundation storage only and is not exposed through NCT routes or UI.

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

This slice deliberately omits evidence reassignment. A later correction model must
retain the original assessment, create or reuse evidence under the active destination
scope, and link both through an immutable correction/supersession event with actor,
reason and time. Mixed-scope artifacts require a separately reviewed partition model;
host-by-host scope must never be inferred from CIDRs or Saved Networks.

Remaining work includes operator routes/UI, role authorization, scope assignment,
correction/supersession, mixed-scope partitioning, read models and production migration.
