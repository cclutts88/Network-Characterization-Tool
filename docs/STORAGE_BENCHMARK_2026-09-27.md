# Foundation storage measurements — 2026-09-27

Measured in local Docker Desktop / WSL2 Linux, Python 3.12.14, using the
`nct-foundation-tests:local` image (`sha256:1b573eed7a2e0311ee21e3be7c212ef02a288c2cfc1c16516b7bec43ddc15a85`).
Application code: foundation commit `34dcc10`; benchmark script added with this report.
All input was generated in an isolated temporary directory. No operator data was used.

Each collection contained one 64 KiB file. Ten distinct contents were distributed
across 100 or 1,000 finalized device collections, with separate manifests and
observations. This intentionally exercises a duplicate-heavy historical dataset.

| Collections | Operation | Elapsed seconds | CPU seconds | Peak process memory (KiB) |
|---:|---|---:|---:|---:|
| 100 | Dry run | 0.0876 | 0.0876 | 52,304 |
| 100 | Initial backfill + report | 0.7787 | 0.3176 | 52,952 |
| 100 | Repeated backfill + report | 0.2094 | 0.2058 | 52,952 |
| 1,000 | Dry run | 0.9138 | 0.9135 | 53,288 |
| 1,000 | Initial backfill + report | 7.5017 | 3.1163 | 53,692 |
| 1,000 | Repeated backfill + report | 2.0196 | 2.0175 | 54,460 |

| Collections | Initial used bytes | After backfill bytes | Potentially reclaimable bytes | Observations |
|---:|---:|---:|---:|---:|
| 100 | 6,570,100 | 7,377,012 | 6,553,600 | 100 |
| 1,000 | 65,701,000 | 67,224,712 | 65,536,000 | 1,000 |

Both runs verified exact duplicate counts, all expected references, zero reported
issues, ten unique registered artifacts, one observation per collection, unchanged
original files/manifests, and zero new registrations on repeated backfill. Reclaimable
space is only an estimate: no compaction or deletion was performed.

Reproduce from the repository root in the Linux test environment:

```sh
python scripts/benchmark_storage_health.py --collections 100 --unique 10
python scripts/benchmark_storage_health.py --collections 1000 --unique 10
```

The script prints JSON and automatically removes only its temporary synthetic data.
Module imports are warmed before timing; filesystem caches are not flushed. Peak
memory is the process lifetime high-water mark, including imports and data creation,
not incremental memory per operation. File-length accounting excludes filesystem
overhead/compression. Results are single runs, not a statistical latency distribution.

These are foundation measurements, not a before/after comparison with main. They do
not establish cold-cache performance, concurrent scan behavior, large note-tree
contention, page latency, enrichment latency, or Range/mission acceptance. Those
Phase 0 and Phase 1 measurements remain open.
