# Scoped device interface observations

This contract adds traceable interface and address receipts for verified device
configuration evidence. It is an additive ingestion stage after the reusable,
scope-free device summary. It does not create physical-device identity or change the
existing Network Devices analysis.

## Scope assignment

A device collection receives a Network Scope only through an explicit operator
decision. The assignment is attached to the exact collection authority and is
append-only. A correction creates a successor and preserves the earlier decision and
its receipts. NCT never derives scope from a management address, hostname, interface
address, CIDR, filename, Saved Network, or artifact hash.

Whole-collection assignment is allowed only when the operator has established that the
selected configuration belongs to one routing context represented by that Network
Scope. Evidence containing isolated contexts that cannot be represented safely must
remain unassigned. Publication fails closed when supported statements identify more
than one routing context or when routing-context syntax is unresolved. The completed
scope-free summary and source evidence remain available for review. Missing scope is
**Needs scope**, not an inferred default.

## Versioned extraction

`device-interface-addresses:1` reads the exact configuration artifact selected by the
active collection authority. It verifies the retained local file and canonical
Artifact Registry bytes before parsing. It does not use the bounded `interfaces` list
stored in the reusable device-summary payload.

Each receipt retains:

- collection ID and authority revision;
- current assignment and exact Network Scope;
- selected configuration artifact observation, digest, size and filename;
- extractor version;
- interface name, normalized address, prefix length and address family;
- routing context or an explicit unresolved value;
- exact source line, line number and extraction syntax.

The first extractor recognizes explicit interface-address statements from the supported
Cisco-style, Juniper set-style and VyOS set-style configurations. Other syntax remains
visible in bounded coverage metadata as unsupported rather than being guessed. Multiple
addresses, secondary addresses, IPv4 and IPv6 are separate immutable receipts.

## Evidence meaning and time

A receipt means **the retained configuration reported this address on this interface**.
It is not proof that the address responded, was active at collection time, or belongs to
a reconciled physical device. Upload time is never source time. An eligible NCT SSH
collection may retain its collection start/end window as context, but that window does
not establish when a configured address became active.

Later collections append receipts. Missing interfaces or addresses mean not reported or
not assessed. They do not establish removal or disappearance. Scoped Nmap positive
observations remain separate and are never strengthened by device configuration facts.

## Durable processing

Only evidence marked for the supported ingestion policy is admitted automatically.
The scope decision commits a durable intake intent. The worker waits for the verified
reusable summary, then freezes the exact authority, selected configuration source,
summary result, assignment and extractor contract. Before publication it rechecks the
source bytes, authority, active scope, current assignment and worker ownership.

The immutable assessment, all receipts and successful job outcome commit together.
Normalization failure preserves the completed reusable summary and retained source.
Failed or interrupted normalization requires an explicit local retry and never contacts
the device. Historical evidence is adopted only through an explicit reviewed action.

## Deliberate boundary

This is a documented Phase 1 deviation from implementing a broad current-device model
in one step. Collection-specific receipts come first because the existing reusable
summary is a presentation-bounded calculation and because physical identity, mixed
routing contexts, address lifetimes and exact Last Seen need separate evidence rules.
Steps 13 and 14 remain partial, and Phase 0 dataset benchmarking remains open.

## Development validation

The completed slice was exercised through the live isolated Device History and Device
Overview workflow. The operator can record a reviewed scope decision, watch local
normalization complete, open the configuration-reported address receipts and their
retained source, and see the same scope and readiness in Device Overview. Browser
console checks were clean.

A disposable synthetic benchmark used 1,000 explicit interfaces in a 58,458-byte
configuration. It extracted 1,000 receipts in 0.103 seconds, published them atomically
in 0.170 seconds, and returned the first and last 100-row pages in 0.003 seconds each
(rounded). This is a reproducible development measurement, not production-scale or
concurrent-workload acceptance. The script is retained at
`scripts/benchmark_device_observations.py`.
