# Phase 0 HTTP and Persistent-View Comparison — 2026-10-09

**Result: PASS**

This retained development benchmark compares stable `main` at
`fc979133634fe068c7dd13b5aa6b0cb873305c0e` with the foundation branch at
`611854cc737a57857da648574bae19144e424426`. Both used the same canonical
synthetic corpus, runner and Linux image.

## What was verified

- Three fresh runs per revision, each in a unique container with networking
  disabled and the target source and corpus mounted read-only.
- Every run returned the same 4,188 unique Current Network addresses in the
  required order and 6,125 Hunt findings.
- The foundation filtered `10.20.0.0/24` inventory produced a 100-row first
  page and a non-overlapping 20-row final page. Its full IP export and LFA both
  covered all 120 filtered addresses.
- The foundation Processed Evidence view returned 120 strict entities as a
  100-row first page and a non-overlapping 20-row final page. Its bounded
  endpoint, latest-observation and service-receipt requests also succeeded.
- Foundation HTTP reads did not change retained evidence or any database table.
  Stable `main` changed only its three declared legacy read caches.
- Every request and the whole run stayed within the limits declared before the
  comparison.

## Median common-request results

| Request | Stable main | Foundation | Result |
| --- | ---: | ---: | --- |
| Current Network first build | 3.719 s | 5.289 s | PASS |
| Current Network shared reuse | 2.627 s | 1.033 s | PASS |
| Hunt shared reuse | 2.688 s | 1.205 s | PASS |
| Map shared reuse | 0.726 s | 0.426 s | PASS |
| Reach shared reuse | 3.514 s | 1.041 s | PASS |

Median is the middle result from the three runs. First build is the initial
request that prepares the shared network view; shared reuse is a later request
that reuses that prepared work. Wall time is elapsed time, CPU time is processor
work, peak memory is the highest memory used, and retained data is what remained
in the disposable test data area.

The first foundation Current Network build is slower and returns a richer
response, but it remains below the predeclared comparison ceiling. Repeated
Current Network, Hunt, Map and Reach requests are all faster in this local
three-run comparison.

Map does materially different work on the two revisions. Stable `main` reports
1 device, 1 gateway, 2 interfaces, 2 subnets and 47 relationships. Foundation
reports 1 device, 0 gateways, 1,000 interfaces, 0 synthetic subnets and 1,041
relationships under its newer exact topology rules. Both exact results repeat
three times and are required by the machine summary. Map timing therefore
compares the two revision-specific results; it is not an identical-output
microbenchmark.

The synthetic corpus deliberately gives four different configuration samples the
same device address. Stable's older Map keeps the router sample's two addressed
interfaces and derives its gateway and two connected subnets. Foundation's newer
merge keeps all 1,000 switch-interface records under that shared synthetic device
identity, so it does not emit those router-derived gateway/subnet objects in this
artificial case. The source files remain retained; this difference is in the Map
projection produced by each revision, not lost evidence.

## Median whole-run results

| Measure | Stable main | Foundation | Result |
| --- | ---: | ---: | --- |
| Wall time | 14.091 s | 13.245 s | PASS |
| CPU time | 8.066 s | 6.624 s | PASS |
| Peak memory | 475,942,912 bytes | 570,290,176 bytes | PASS |
| Retained data | 9,604,019 bytes | 5,283,414 bytes | PASS |

Peak memory increased by about 94 MB and remained below the predeclared
951,885,824-byte foundation ceiling. Foundation retained less disposable data
in this test even though it added canonical processed evidence, because stable
`main` populated its larger legacy read caches.

## Retained evidence

`main-1.json` through `main-3.json` and `foundation-1.json` through
`foundation-3.json` are the raw reports. `phase0-http-summary.json` is the
machine-checked comparison. Each raw report contains exact Git, source, image,
container, isolation, corpus, runner, correctness, timing, memory, response-size,
database and retained-storage evidence.

## Boundary

This is an ordered in-process FastAPI TestClient comparison on local development
hardware. Later requests share process-local work created by earlier requests;
they are labeled shared reuse rather than independent cold starts. This result
does not measure rendered-browser behavior, simultaneous processes, Range
hardware, production history, physical devices or mission data. It is not a
live System Health check and does not establish Range or mission readiness.
