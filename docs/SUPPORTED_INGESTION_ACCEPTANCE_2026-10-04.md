# Currently Supported Ingestion: Development Acceptance

Date: 2026-10-04  
Implementation revision: `9e5b1f5`  
Branch: `foundation/evidence-engine-v2`

## Accepted boundary

This milestone covers the evidence sources that currently participate in NCT's reviewed
foundation pipeline:

- manual Nmap XML uploads;
- eligible completed Nmap scans;
- manual device-configuration uploads; and
- eligible completed device collections.

Each participating encounter retains its own identity and source trail. The pipeline then
records any required Network Scope decision, runs local durable work, and verifies the
exact saved output before showing the encounter as Ready. Device summaries remain reusable
scope-free calculations; scoped device-address receipts remain a separate later stage.

System Health exposes one paged **Evidence intake status** view. It tells an operator what
arrived, which stage is complete or waiting, what action is needed, and where to open the
retained source or history. The visible outcomes are Ready, Processing, Needs scope and
Needs attention. Older records stay in their original history and are not included in this
processing view.

## Safety and evidence meaning

The status request reads one saved SQLite metadata snapshot. Loading it does not open or
hash evidence files, initialize storage, start or retry work, parse source content, contact
a network, or publish results.

Ready means the exact saved output and its required provenance are present for that
encounter. It does not mean a host is online now or that saved evidence remains current on
the live network. Duplicate bytes may reuse one verified calculation, while each encounter
keeps its own provenance links. A failed later stage does not erase an earlier completed
stage or its source evidence.

The view fails closed when saved records are missing, malformed, linked to another
encounter, changed from their immutable input description, interrupted, or terminally
failed. One malformed encounter becomes a visible integrity issue for that row and does
not prevent the rest of the page from loading.

## Verification

- Complete Docker suite: **1,003 passed, 4 expected skips**.
- Focused ingestion-integrity suite: **15 passed**.
- UI, page-contract and delayed-response suite: **62 passed, 1 expected skip**.
- Actual browser-side delayed-response regression: passed under Node.
- Independent reviewer: **CLEAR - DOCUMENTED DEVIATION**, with **59 independent tests
  passed** after adversarial review.
- Novice operator: **CLEAR**. The operator understood what arrived, the present Ready
  stages, exact encounter/source/history links, the local-only processing boundary, and
  the tested Needs scope, Processing and Needs attention guidance.
- Live isolated browser preview: all present supported examples displayed as Ready with
  exact source/history links, an expandable encounter identity, the historical-record
  boundary, and contextual Operator Guide guidance.

The live preview contained Ready examples. Waiting, Needs scope, failed, interrupted,
missing-output, wrong-encounter, malformed-metadata, shared-result and changed-descriptor
states were verified deterministically in tests.

## Exact-revision benchmark

The retained raw report is
[`supported_ingestion_benchmark_2026-10-04.json`](supported_ingestion_benchmark_2026-10-04.json).
It ran three times against implementation revision `9e5b1f5` with disposable synthetic
data.

| Measurement | Result across 3 runs |
| --- | --- |
| Large Nmap input | 400 hosts, 89,994 bytes |
| Large Nmap cold processing | 0.349-0.390 s, 0.365 s median |
| Large device input | 600 interfaces, 35,592 bytes |
| Large device cold processing | 0.586-1.957 s, 0.595 s median |
| Repeated identical device content | 0.187-0.199 s, 0.195 s median; same summary reused |
| Status first page | 0.0037-0.0047 s, 0.0043 s median |
| Status last page | 0.0028-0.0029 s, 0.0028 s median |
| Receipt first and last pages | about 0.0037-0.0039 s |
| Concurrent status reads during large write | 36-38 per run; no errors |
| Peak Python memory | about 105 MB |
| Disposable database | about 3.6 MB |

Every run retained two separate encounters for the repeated device content, reused the
same verified calculation, recorded 600 device receipts, verified the first and last
100-row receipt pages, and returned the final 3 of 53 repeated status encounters.

## Remaining roadmap work

This is development acceptance on the foundation branch. It is not Range, mission,
production-scale or stable-main acceptance. Representative Phase 0 production datasets
remain unavailable, so the roadmap's full comparison benchmark remains open.

The milestone does not complete historical bulk adoption, general dependency rebuilding,
multi-process worker leases or checkpoints, passive collectors, physical-device identity,
broad current truth, exact device Last Seen or disappearance claims. Steps 10-14 retain
their documented partial status, and Step 15 remains open.
