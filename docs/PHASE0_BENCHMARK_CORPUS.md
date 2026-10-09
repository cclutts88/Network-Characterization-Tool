# Phase 0 Development Benchmark Corpus

This corpus gives NCT one repeatable set of synthetic evidence for comparing the
stable `main` build with `foundation/evidence-engine-v2`. It exists so both builds
are measured against the same inputs and expected results.

The corpus contains:

- a small TCP-only Nmap scan;
- a medium UDP-only Nmap scan;
- two time-separated TCP/UDP scans with known additions, changes, omissions and
  an exact duplicate source file;
- four large Nmap files with 1,000 synthetic hosts each across separate subnets;
- router, firewall and switch evidence, plus a 1,000-interface boundary case; and
- a frozen offline enrichment workload with repeated product/version queries,
  its deterministic command and configuration, and exact expected cache behavior.

Every generated file is listed in a versioned manifest with its SHA-256 digest,
size and expected result counts. Generation is deterministic, refuses to overwrite
an existing directory and requires no network access. Verification rejects missing,
changed, linked or unsafe files.

Generate a fresh disposable copy from the repository root:

```text
python scripts/generate_phase0_benchmark_corpus.py --generate /tmp/nct-phase0-corpus
```

Verify a retained copy without running NCT:

```text
python scripts/generate_phase0_benchmark_corpus.py --verify /tmp/nct-phase0-corpus
```

The corpus uses reserved documentation address ranges and fabricated products,
names and identifiers. It contains no operator, Range, mission or production data.
This is a developer test-data set, not a System Health check. It does not report
the condition or performance of a running NCT installation. It does not by itself
measure performance or prove Range or mission readiness. The roadmap benchmark
remains open until the exact stable and foundation revisions run the retained
benchmark procedure and pass the declared correctness and resource limits.

## Core comparison runner

`scripts/benchmark_phase0_core.py` runs one isolated repeat. Use a new Linux
container and a nonexistent data directory for every repeat. The container must
have networking disabled, with the target checkout and corpus mounted read-only.
Before starting it, the controller records two JSON attestations:

- Git evidence from the target checkout's exact revision, clean-status check and
  source digest; and
- Docker evidence from inspection of the exact image and newly created container,
  including its unique container ID, disabled network and read-only mounts.

The worker validates those attestations against the source it can read. It also
regenerates the canonical corpus in memory, so editing an input and its manifest
together cannot create a valid run. One retained report covers all parser,
historical-comparison, device-summary and frozen enrichment workloads and accounts
for every retained file in its disposable data directory.

After three stable-main reports and three foundation reports exist, run:

```text
python scripts/summarize_phase0_core_benchmark.py \
  --main-run MAIN-1.json --main-run MAIN-2.json --main-run MAIN-3.json \
  --foundation-run FOUNDATION-1.json \
  --foundation-run FOUNDATION-2.json \
  --foundation-run FOUNDATION-3.json \
  --output phase0-core-summary.json
```

The summary requires repeats 1, 2 and 3, six unique fresh containers, identical
runner/corpus/image identities, exact results, the full workload list and the
predeclared median limits. A passing result applies only to this core development
comparison; it does not establish HTTP, browser, Range or mission performance.
