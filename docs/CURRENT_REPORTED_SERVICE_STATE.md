# Current reported service state

This view answers a narrow question: **what did the latest defensible saved Nmap
evidence report for each protocol and port on one IP address in one Network Scope?**
It does not state what is live on the network now.

## Selection contract

The `current-reported-service-state:1` selector uses only saved database receipts from
current, unsuperseded scope assignments produced by `nmap-endpoints:2`. A record can
participate only when its retained coverage receipt says the source completed
successfully. TCP, UDP and SCTP on the same port remain separate services.

NCT orders source records only from valid host collection windows written in the
evidence. One record is later only when every record in the latest group is separated
by a strict non-overlap. Equal, touching, overlapping, transitively overlapping and
unknown-time windows remain unresolved. Upload time, assignment time, processing time
and scan run identifiers never select state.

For each protocol and port that was explicitly reported in at least one eligible saved
record, NCT evaluates the latest defensible record:

- An eligible explicit service receipt reports its exact saved state.
- An eligible aggregate `open` or `closed` coverage result can report the saved state
  when the completed source accounts for that exact protocol and port.
- A later record that did not assess the port returns **Not assessed**. NCT does not
  carry the older state forward.
- An ambiguous aggregate state such as `filtered` or `open|filtered` returns **Not
  assessed** for an omitted individual port.
- Competing latest or unknown-time records return **Unresolved**, even when their saved
  states happen to agree.

Every determination retains the exact source observation, assignment, assessment,
collection window, coverage reason and retained-source link used to explain it.
Identical bytes encountered twice remain two source observations.

## Safety and bounds

The selector opens the database read-only and uses saved receipts only. It does not
open artifact files, hash content, parse XML, run backfill, create jobs, contact a
network or change data. The source-record ceiling is checked before stored receipt JSON
is decoded. Service keys and competing latest records have separate reviewed ceilings.
Cross-page requests carry an assignment-set revision; a scope correction invalidates
the page and requires a refresh. Limit failures produce no partial result.

## Claims this view does not make

“Current” here means the latest defensible **source-reported** state. It is not:

- live network truth;
- proof that an address is online now;
- physical-device identity;
- an exact Last Seen timestamp;
- proof that a service or device disappeared; or
- proof that the same IP at different times belongs to the same physical device.

The broader current-state model, physical-device reconciliation, exact Last Seen and
disappearance claims remain later roadmap gates.
