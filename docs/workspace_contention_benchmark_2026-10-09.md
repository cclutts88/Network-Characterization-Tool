# Workspace contention benchmark — 2026-10-09

## Result

**PASS** for the declared local development workload. All three serial runs and all
three concurrent runs completed without a SQLite locked/busy/timeout error,
optimistic conflict, unexpected error, missing read, state mismatch, audit gap, or
database integrity failure.

In plain language: on one development computer, eight simulated analysts repeatedly
saved separate notes, Map layouts, Hunt views, and Analyze filters while NCT also
read the workspace and changed a folder containing 1,000 items. Every requested
action finished, reads kept working, saved records and change histories matched the
expected result, and the final database check passed.

This result applies to commit
`970f25c350ddf29ad7ea8c61f0b6c828fe447205` in the
`nct-foundation-tests:local` Linux test image on the Windows Docker Desktop
development host.

## Workload

Each repeat used a fresh disposable test database configured like NCT. Setup and one
warm-up save per record were excluded from measurements.

- 8 analysts, each owning separate records
- 50 cycles per analyst
- 400 measured saves per family per run: nested investigation note, Map layout,
  Hunt working view, and Analyze filter preset
- 4 KiB payload per saved record
- One 1,000-item note folder shared, unshared, and moved while ordinary saves ran
- 2 bounded readers making 50 full workspace reads each
- 3 serial repeats and 3 concurrent repeats with repeatable operation ordering
- Nearest-rank percentiles: `sorted[ceil(p * n) - 1]`

The concurrent pass limits were declared before the retained run: no errors or
conflicts; every read completes; reads and every ordinary save family make progress
during concurrent writing; every measured ordinary save remains below 5 seconds; and each
family's concurrent p95 remains at or below the greater of 1 second and ten times
its serial p95.

## Measured ordinary saves

The table uses the worst value observed across the three repeats for each mode.
Serial means one save at a time. Concurrent means saves ran while other workspace
work was active. p95 is the time within which at least 95% of saves finished; max is
the single slowest save. A row passes when its p95 stays within the Concurrent limit
and every measured ordinary save stays below the separate five-second limit. This is why a
max above 1,000 ms can still be a PASS. ms means thousandths of a second.

| Save family | Serial p95 | Concurrent p95 | Concurrent limit | Concurrent max | Result |
| --- | ---: | ---: | ---: | ---: | --- |
| Investigation note | 3.547 ms | 15.468 ms | 1,000 ms | 1,832.282 ms | PASS |
| Map layout | 3.276 ms | 9.681 ms | 1,000 ms | 1,434.660 ms | PASS |
| Hunt working view | 3.059 ms | 11.607 ms | 1,000 ms | 1,435.306 ms | PASS |
| Analyze filter preset | 3.185 ms | 12.412 ms | 1,000 ms | 2,436.065 ms | PASS |

All concurrent repeats completed 100 of 100 requested reads while writers were
active. Each repeat also recorded ordinary operations from all four families during
the recursive folder workload; per-family overlap ranged from 23 to 207 operations.

The 1,000-item recursive operations measured:

| Operation | Serial range | Concurrent range |
| --- | ---: | ---: |
| Share | 78.886–81.107 ms | 95.794–200.975 ms |
| Unshare | 79.040–80.762 ms | 81.159–100.570 ms |
| Move | 6.885–8.058 ms | 6.818–935.988 ms |

Each run verified exact final versions and payload markers, exact ownership and row
counts, contiguous note and layout audit histories, every recursive descendant's
parent/version/sharing state, the recursive root's full audit history, WAL mode,
30-second busy timeout, and `PRAGMA integrity_check = ok`.

## Reproduce

From the repository root, with the exact test image available:

```text
docker run --rm -e PYTHONPATH=/app -v "<repository>:/app" -w /app \
  nct-foundation-tests:local python scripts/benchmark_workspace_contention.py \
  --workers 8 --cycles 50 --recursive-items 1000 --reader-workers 2 \
  --reads-per-worker 50 --repeats 3 --payload-bytes 4096 \
  --runtime-label nct-foundation-tests:local \
  --host-label "Windows Docker Desktop development host" \
  --source-commit 970f25c350ddf29ad7ea8c61f0b6c828fe447205 \
  --output docs/workspace_contention_benchmark_2026-10-09.json
```

The complete machine-readable measurements are retained in
`docs/workspace_contention_benchmark_2026-10-09.json`.

## What this result does not prove

This proves only that the stated storage workload passed on the named local
development setup. It is a direct, single-process storage benchmark. It does not
establish HTTP or rendered-page performance, network latency, multi-process
contention, cold-cache startup, large retained-installation performance, Range
readiness, or mission readiness. CPU measurements in the JSON are whole-process
`process_time`, not per-thread attribution.
