# Phase 0 eight-client, single-worker concurrency benchmark — 2026-10-09

## Result

**PASS for the declared local development workload.** Three fresh repeats used
eight separate simulated analyst clients against one normal NCT container with
exactly one application worker. All 1,182 recorded workload operations and 30
run-time login requests completed. Reads continued while saves were active,
every final synthetic record and audit entry
matched the expected result, and the retained evidence files did not change.
There were no unexpected responses, timeouts, lost updates, database lock/busy
messages, unhandled application errors, cross-owner records, or integrity
failures.

The test used foundation revision
`b5ee87c9cd0ec3482d3183bc48ab73f33148c2c0`, Docker image
`sha256:1b573eed7a2e0311ee21e3be7c212ef02a288c2cfc1c16516b7bec43ddc15a85`,
and canonical synthetic corpus manifest
`355b89e8dc8b3c38b0bf97ed41cc3c62cb3504493cfeefb71e85a894604e16d8`.
The runs occurred on the same Windows Docker Desktop development host. The test
started no scans, contacted no devices, and used no operator, Range, mission, or
production data.

## What each repeat did

Eight independent operating-system client processes each signed in with its own
analyst account and session. Every client completed four cycles containing:

- Current Network, Hunt, Map, and Reach reads;
- private note, layout, view, and filter-preset reads;
- private note, layout, view, and filter-preset saves; and
- one attempt to update another analyst's layout, which NCT correctly refused
  without revealing that analyst's layout.

That produced 49 recorded workload operations per analyst client: 48 operations
across four cycles and one ownership-isolation check. Two additional synchronized
clients then tried to save version 2 of the same note. Exactly one save succeeded
and the other received the expected version conflict. Each repeat therefore
recorded 394 workload operations: 256 reads, 128 independent saves, eight
isolation checks, and two collision saves. Ten login requests also occurred inside
each repeat's wall time, but they are not part of the 394-operation latency and
throughput calculations. Account creation and synthetic record setup occurred
before the timed workload and are not part of either count.

Each repeat began with a fresh data directory, application container, client
container, and internal-only Docker network. Afterward, the controller verified
the complete logical database, every expected owner and audit sequence, unchanged
evidence bytes, SQLite integrity, the exact single application process, and full
cleanup.

## Measurements

Latency is how long an individual response took. The 95th percentile means 95%
of responses completed at or below that time. Throughput is the average number
of requests completed each second. Wall time is the elapsed time for one complete
repeat. CPU time is total processor work. Median is the middle value from the
three repeats. Reads overlapping saves counts reads that completed while at least
one save was active; it shows that reads continued during writing. Peak memory is
the highest container memory observed during its complete measured lifetime. NCT
peak memory includes application startup, data setup, and the workload. Client
peak memory covers the load-generating client's complete container lifetime.
Client resources belong to the load-generating client container; application
resources belong to NCT.

| Measurement | Repeat 1 | Repeat 2 | Repeat 3 | Median | Declared limit |
| --- | ---: | ---: | ---: | ---: | ---: |
| Recorded workload operations | 394 | 394 | 394 | 394 | all must complete |
| Wall time | 66.10 s | 67.04 s | 67.26 s | 67.04 s | 240 s |
| Throughput | 5.960/s | 5.877/s | 5.858/s | 5.877/s | recorded only |
| Read p95 | 5.027 s | 5.537 s | 5.187 s | 5.187 s | 30 s |
| Write p95 | 0.281 s | 0.277 s | 0.347 s | 0.281 s | 10 s |
| Reads overlapping saves | 110 | 87 | 92 | 92 | at least 8 |
| NCT CPU | 67.62 s | 68.41 s | 68.67 s | 68.41 s | 240 s |
| NCT peak memory, including startup and setup | 858,128,384 B | 933,421,056 B | 935,755,776 B | 933,421,056 B | 2,147,483,648 B |
| Client CPU | 16.72 s | 16.86 s | 17.18 s | 16.86 s | 240 s |
| Client peak memory, full client lifetime | 1,846,652,928 B | 1,863,012,352 B | 1,902,428,160 B | 1,863,012,352 B | 2,147,483,648 B |

## Retained evidence

`summary.json` is the strict machine-checked three-repeat summary. Each
`repeat-*` directory contains the prepared identity, raw client records, exact
state snapshots, application log, process list, container inspection, resource
measurements, source/fresh-data attestation, final result, hashes for all raw
artifacts, and cleanup proof. The summarizer recalculates request correctness,
latencies, read/write overlap, result bindings, fixed limits, identities, hashes,
state changes, resource values, and cleanup from those files.

## Limits of this result

This result applies only to the stated synthetic workload on the named local
development environment. It does not test multiple NCT server workers, multiple
application containers, distributed deployment, browser rendering, human
workflow, live scan contention, network latency, long-duration use, larger
analyst counts, Range hardware, production-scale retained history, or mission
performance. It is not a live System Health check and does not establish Range
or mission readiness.
