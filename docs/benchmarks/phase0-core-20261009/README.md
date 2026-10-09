# Phase 0 Core Comparison — 2026-10-09

**Result: PASS**

This retained development benchmark compares stable `main` at
`fc979133634fe068c7dd13b5aa6b0cb873305c0e` with the foundation branch at
`aca02905ca29256ff58cca701a74968b1da2bf99`. Both used the same canonical
synthetic corpus, runner and Linux image.

## What was verified

- Three fresh runs per revision, each in a unique container with networking
  disabled and the source and corpus mounted read-only.
- Nine Nmap inputs, four device inputs, one known historical comparison and the
  frozen offline enrichment workload all matched their exact expected results.
- Stable `main` repeated 24 offline enrichment searches on the warm pass.
- Foundation made 24 cold searches, then served all 24 warm queries from its
  persistent cache without another search.
- Every workload and the whole run stayed within the limits declared before the
  comparison.

## Median whole-run results

| Measure | Stable main | Foundation | Result |
| --- | ---: | ---: | --- |
| Wall time | 3.839 s | 3.689 s | PASS |
| CPU time | 5.498 s | 4.028 s | PASS |
| Peak memory | 173,367,296 bytes | 177,496,064 bytes | PASS |
| Retained data | 123,105 bytes | 159,969 bytes | PASS |

Wall time is the elapsed time to finish the complete workload. CPU time is total
processor work and can be higher than wall time when work overlaps. Peak memory
is the highest memory use observed. Retained data is the data left in the
disposable NCT data area after the run.

The additional 36,864 retained bytes on foundation are its persistent
enrichment cache. In practical terms, foundation saved the exact enrichment
results and reused them when the same questions were repeated, avoiding 24
duplicate searches. The extra retained space is the cost of that reuse.

## Retained evidence

`main-1.json` through `main-3.json` and `foundation-1.json` through
`foundation-3.json` are the raw reports. `phase0-core-summary.json` is the
machine-checked median comparison. Each raw report contains its exact Git,
source, image, container, isolation, corpus, runner, correctness, timing, memory
and retained-storage evidence.

## Boundary

This result covers the core Nmap parser, historical comparison, device summary
and offline enrichment path on local development hardware. It does not measure
HTTP endpoints, saved foundation views, rendered browser behavior, multiple
simultaneous processes, Range hardware, production history or mission data.
This is a development benchmark, not a live System Health check. It does not
measure the current installation or establish Range or mission readiness.
