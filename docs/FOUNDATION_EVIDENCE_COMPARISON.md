# Scoped source-record service comparison

This first delta-detection slice compares what two retained Nmap source records
reported for one address in one exact Network Scope. It is a read-only evidence
comparison. It does not select current truth or decide that either record represents
the live network.

## Coverage receipt gate

Lifecycle wording is gated by the versioned `nmap-coverage:1` receipt produced by
`nmap-endpoints:2`. Existing `nmap-endpoints:1` assessments remain readable history;
they do not acquire coverage claims during an application upgrade. An operator must
explicitly reprocess a current assignment to create the new assessment and receipt.

A requested `scaninfo` port is not by itself proof that the probe completed. Coverage
receipts separately retain successful source completion, exact protocol port ranges,
confirmed host response, host collection intervals, explicit port counts, aggregate
omitted-port counts and multi-phase provenance. Missing, incomplete, mismatched, mixed,
or ambiguously timed evidence carries specific ineligibility reasons. A per-record
coverage result proves only that coverage evidence is complete enough to interpret an
omission. It does not establish chronological order. Ordering is evaluated separately
only when two valid host collection intervals do not overlap.

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

The neutral evidence label remains visible even when lifecycle classification is not
available.

## Coverage-aware lifecycle rules

NCT orders records only from valid host collection intervals. Record A is earlier only
when its host interval ends strictly before Record B begins; the reverse rule identifies
Record B as earlier. Equal, touching, overlapping, missing, invalid and multi-phase
ambiguous intervals leave order unresolved. Upload, assignment and processing times do
not establish order. Both sources must also record successful completion.

After order is established, each protocol and port receives one lifecycle label:

| Earlier evidence | Later evidence | Required coverage | Label |
|---|---|---|---|
| Supported state | Same supported state | Each side is explicit or an attributable aggregate `open`/`closed` state | **Unchanged** |
| `closed` | `open` | Each side is explicit or an attributable aggregate state | **Newly observed** |
| `open` | `closed` | Each side is explicit or an attributable aggregate state | **No longer observed** |
| Other different supported states | Other different supported states | Both states are exact and coverage-qualified | **Changed** |
| Aggregate state other than `open` or `closed` | Any state | Aggregate state is ambiguous for one exact service | **Not assessed** |
| Any other combination | Any other combination | Missing, incomplete, contradictory or ineligible evidence | **Not assessed** |

An `open` to `closed` transition is **No longer observed**, and `closed` to `open` is
**Newly observed**, whether the supported state came from an explicit row or an
attributable aggregate. Other different exact states are **Changed**. Identical states
are **Unchanged**. A missing or unreadable explicit state is **Not assessed**.
Assumed host presence, unsuccessful completion, undeclared protocols, malformed port
ranges, contradictory aggregate counts and ambiguous merged phases are ineligible.
Changing between an explicit port row and a matching aggregate state does not create a
change by itself. An attributable aggregate `open` or `closed` state uses the same
transition rules as its explicit equivalent. Other aggregate states, including
`filtered` and `open|filtered`, are too ambiguous for an exact lifecycle label.

For example, if an earlier common-ports scan reports TCP/443 and a later top-100 scan
does not include TCP/443, the result is **Not assessed**. If the later scan explicitly
included TCP/443, completed successfully, confirmed the host and fully accounted for
the omitted port, the result may be **No longer observed**. That phrase means only that
the later saved scan did not observe the service; it does not prove the service is gone
now. The mirror rule applies to **Newly observed**.

## Output and bounds

The result shows Record A and Record B provenance, the evidence-backed earlier/later
decision, file-reported collection windows, coverage receipts and per-row reasons. The
service union is ordered and paged;
the API never loads an entire assessment payload, reparses XML, hashes files, writes to
storage, contacts a network, or changes existing scan-comparison behavior.

Current-state selection, Last Seen, proof of disappearance, automatic baselines,
cross-parser comparisons, software/version deltas and persistent comparison caching
remain separate gates.
