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
