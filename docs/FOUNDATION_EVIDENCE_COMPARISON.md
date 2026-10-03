# Scoped source-record service comparison

This first delta-detection slice compares what two retained Nmap source records
reported for one address in one exact Network Scope. It is a read-only evidence
comparison. It does not select current truth or decide that either record represents
the live network.

## Selection contract

The analyst explicitly selects **Record A** and **Record B** from saved source records
for one scoped address. NCT does not choose an automatic baseline or order the records
by upload, processing, or assignment time.

Both selections must:

- belong to the same Network Scope and address endpoint;
- identify distinct assignment/assessment pairs;
- use the supported Nmap endpoint parser; and
- remain linked to current, unsuperseded assignments when the comparison is read.

NCT validates both records together in one read-only database snapshot. A correction
that supersedes either selection makes the comparison stale and the analyst must select
again. Archived scopes remain reviewable. Identical file bytes encountered separately
remain separate source records.

## Comparison rules

The comparison uses the union of explicit transport receipts, keyed by protocol and
port. TCP and UDP on the same port remain different services. Only the source-reported
state participates in equality; timestamps, file locations, assignment reasons,
receipt identifiers, software identity and script output do not.

Each row receives one neutral evidence label:

- **Same reported state** — both records explicitly report the same state.
- **Different reported state** — both explicitly report a state and the values differ.
- **Recorded only in A** — only Record A contains that protocol and port.
- **Recorded only in B** — only Record B contains that protocol and port.
- **Comparison unavailable** — both service receipts exist but an explicit comparable
  state is missing or unreadable.

Recorded only in B does not mean a service is newly present. Recorded only in A does
not mean it disappeared or was no longer observed. An omitted port, aggregate closed
port count, absent host, successful scan status, or scan-information entry is not proof
that the other record assessed that service. Coverage-backed lifecycle categories stay
open until NCT can establish target, protocol, port and completion coverage.

## Output and bounds

The result shows Record A and Record B provenance, file-reported collection windows and
coverage uncertainty before the service rows. The service union is ordered and paged;
the API never loads an entire assessment payload, reparses XML, hashes files, writes to
storage, contacts a network, or changes existing scan-comparison behavior.

Current-state selection, Last Seen, disappearance detection, automatic baselines,
cross-parser comparisons, software/version deltas and persistent comparison caching
remain separate gates.
