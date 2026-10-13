# Active scan progress contention benchmark — 2026-10-12

This disposable local development check ran active-scan progress saves at the
same time as analyst workspace saves, background-work lease heartbeats, and
read traffic against one SQLite database.

The run completed 100 progress saves, 100 workspace saves, 100 lease renewals,
and 200 reads with no locked, busy, timeout, conflict, or unexpected errors.
The final scan progress, workspace version and content, lease history, and Scan
History membership were exact, and SQLite's integrity check passed.

| Lane | Operations | 95th percentile | Slowest operation |
|---|---:|---:|---:|
| Active-scan progress | 100 | 3.598 ms | 333.293 ms |
| Analyst workspace save | 100 | 3.607 ms | 181.295 ms |
| Background-work heartbeat | 100 | 3.879 ms | 331.541 ms |
| Read traffic | 200 | 1.475 ms | 3.648 ms |

The predeclared limits were a 95th percentile below one second and every
operation below five seconds. The complete run took 0.782 seconds and passed
both limits. A start barrier made all three writer lanes overlap for 0.524178
seconds, with all three active concurrently. The synthetic scan passed through
the normal saved contact-start transition before progress publication. Progress
updates were protected by database triggers that would have failed the run if
they rebuilt Scan History membership rows.

This is a repeatable, local, single-process SQLite development result. It does
not establish cold-cache, multi-process, production-scale, Range, mission, or
future PostgreSQL performance. Reproduce it with
`scripts/benchmark_scan_progress_contention.py`; the complete machine-readable
result is retained in `docs/scan_progress_contention_benchmark_2026-10-12.json`.
