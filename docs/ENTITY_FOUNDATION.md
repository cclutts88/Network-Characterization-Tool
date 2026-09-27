# Scoped endpoint and evidence storage

This is an additive internal foundation, not a replacement for current NCT analysis.
The initial `app/entities.py` contract stores address endpoints, transport endpoints,
and immutable assessment receipts. It is not yet called by application routes.

## Identity

- `scope_id` is an explicit, persistent network-context identifier owned by the
  caller. No default global scope exists. Scope assignment is still to be built.
- Saved Networks are editable target selections and may overlap. Their names,
  CIDRs, filenames and artifact hashes must not be inferred as routing-domain identity.
- An address endpoint is `(scope_id, normalized IP address)`. It does not establish
  physical Host/Device identity. MACs and hostnames are evidence, not automatic merge keys.
- A service endpoint is `(address endpoint, transport protocol, port)`. It is not
  a claim that a service is open or that its software identity is established.
- IPv4 and IPv6 are accepted; IPv6 zone IDs require explicit adapter mapping and
  are rejected here. Supported transports initially are TCP, UDP and SCTP.

## Evidence and replay

Each assessment references an existing Artifact Registry observation. That link
retains its canonical artifact hash, original source, encounter timestamp and actor.
Foreign keys prevent deleting linked artifact observations, including cascading
artifact deletion. Future retention must preserve receipt metadata explicitly.

An assessment is unique per scope, artifact observation and parser version. Adapters
must namespace the version, for example `nmap-endpoints:1`, and pass source facts
before analyst overrides or enrichment. Identical replays are no-ops; changed facts
under the same identity are rejected. A new parser version retains its own receipts.
Different encounters of identical bytes retain separate assessments while reusing
the same scoped endpoint identities. Parsed-result caching by hash is a later layer.

Assessment time is optional, timezone-aware and UTC-normalized, with a required
source basis when known. It must never default to upload/encounter/processing time.
The separate recorded timestamp describes processing only. Adapter facts must
retain source time windows, raw timestamps, extraction locators, state/reason and
coverage at the correct host/service granularity; a scan end is not a precise
per-host observation time. Invalid or conflicting source times must remain unknown.

All entity and receipt writes for one assessment commit together. A failed write
rolls back the entire assessment. Initial schema setup is guarded once per database.
Facts are preserved without promoting assumed host presence, filtered ports or
missing observations into positive presence/absence claims. There is deliberately
no latest/current-state selection or Last Seen calculation in this layer.

## Remaining gates

- Verified source adapters, including safe Nmap time/coverage extraction.
- Explicit scope assignment for new and legacy evidence; no automatic cross-network merge.
- Physical Host/Device reconciliation and normalized network/interface entities.
- Typed evidence read models, evidence locators and lifecycle calculations.
- Parser-result caching, processing jobs, failure status and source-change validation.
- Production integration, migration and operator-facing inspection/acceptance.

The storage contract alone does not complete canonical entities, evidence receipts,
Last Seen, delta detection or the broader roadmap.
