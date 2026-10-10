# Phase 0 rendered-browser benchmark — 2026-10-09

## Result

The retained comparison passed. Stable main and the foundation build were each
measured three times from fresh, independently prepared data. Every run passed
its page-content checks, declared resource limits, retained-data check, and
cleanup check. The strict summary also confirmed that the three starting
databases for each version were identical.

- Stable main: `fc979133634fe068c7dd13b5aa6b0cb873305c0e`
- Foundation: `3a42d6c3cdeb2538b7e2e5baef6c47bb23320833`
- Corpus manifest SHA-256: `355b89e8dc8b3c38b0bf97ed41cc3c62cb3504493cfeefb71e85a894604e16d8`
- Chrome: `155.0.8059.39`
- Chrome executable SHA-256: `d3784ffbf1f6109348416064b3e4cd739b06fa61d89a81b262c780df9f32270c`
- Playwright: `1.62.1`
- Node.js: `v24.19.0`

## Median measurements

Cold is the first page load in a fresh browser. Reload repeats the page in the
same run. Action-to-ready is the time from opening or reloading a page until its
expected final content is visible and stable. Lower times are faster; `ms`
means thousandths of a second.

Peak memory is the highest memory use observed during the complete run.
Browser memory is Chrome; application memory is NCT. CPU time is the total
processor work during the complete run, not page-loading time.

| Page | Stable cold | Foundation cold | Stable reload | Foundation reload |
| --- | ---: | ---: | ---: | ---: |
| Analysis | 3,184 ms | 5,233 ms | 2,975 ms | 974 ms |
| Hunt | 4,115 ms | 1,618 ms | 4,065 ms | 1,428 ms |
| Reach | 2,964 ms | 1,356 ms | 2,740 ms | 1,320 ms |
| Map | 1,094 ms | 804 ms | 1,016 ms | 740 ms |

| Complete-run resource | Stable | Foundation | Declared limit |
| --- | ---: | ---: | ---: |
| Browser peak memory | 1,787,838,464 bytes | 1,741,778,944 bytes | 2,684,354,560 bytes |
| Application peak memory | 263,340,032 bytes | 406,986,752 bytes | 1,073,741,824 bytes |
| Browser CPU | 36.83 seconds | 37.48 seconds | 180 seconds |
| Application CPU | 20.68 seconds | 11.85 seconds | 180 seconds |

Hunt rendered 139,168 document nodes on stable main and 2,096 on the
foundation build while retaining the same 4,188 hosts and 6,125 findings.
Document nodes are the page elements Chrome must keep in memory. The foundation
build displayed far fewer elements at once through paging; evidence was not
removed. The foundation action checks also exercised both current and processed
evidence at the first and last pages, using page sizes of 100 and 20.

These are absolute acceptance limits. Relative differences between revisions
are descriptive and were not used as a pass/fail gate.

## Retained evidence

`summary.json` is the machine-checked six-run summary. Each `main-*` and
`foundation-*` directory contains the exact run result, controller identity,
preparation report, resource sample, cleanup proof, and screenshots of
Analysis, Hunt, Reach, and Map. Foundation directories also include the
pagination and filter action screenshot.

The benchmark used fresh Chrome processes and profiles on the same Windows
host. External browser requests were blocked. The application ran in a fresh
container with an internal-only network and a disposable loopback relay. The
source checkout and benchmark harness were mounted read-only; each run received
a fresh writable data directory that was removed afterward.

## Limits of this result

This is a same-host Windows Chrome comparison. It is not evidence for a Linux
browser, browser container, GPU behavior, human interaction, multiple
simultaneous analysts, Range deployment, production scale, or mission
performance. Those require their own reviewed acceptance runs.
