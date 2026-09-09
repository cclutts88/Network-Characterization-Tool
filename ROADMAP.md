# Net Characterization Tool Roadmap

## Phase 1 — Usability and history

- [x] Reopen previous scans through the complete analysis renderer.
- [x] Add human-friendly manual and scheduled scan names.
- [x] Retain creator, scheduler, executor, and execution-method metadata.
- [x] Show explicit scan coverage in history.
- [x] Preserve host-summary CSV and add normalized port-level CSV.
- [x] Parse and surface MAC addresses and Nmap-reported vendors.

## Phase 2 — Scan profiles

- [x] Consolidate all Nmap scan construction on one page.
- [x] Save, clone, reuse, and version profiles.
- [x] Add TCP, UDP, and TCP + UDP modes.
- [x] Add common, full, custom, and ICS-focused port scopes.
- [x] Enforce `-n` in the shared command builder.
- [x] Persist schedule definitions against an immutable profile version.

## Phase 3 — Scheduling and discovery

- [ ] Execute recurring daily, weekly, monthly, and custom schedules.
- [ ] Retain schedule owner, modification history, next run, and last run.
- [ ] Show live scan progress using the effective target total after no-strike
  exclusions, including hosts scanned/total, percentage, elapsed time, current
  chunk when applicable, and a clear indeterminate state when exact per-host
  progress is unavailable.
- [x] Add optional FPING pre-discovery with retained responsive-host evidence
  and an explicit warning that ICMP-blocking hosts can be omitted.
- [x] Collect and retain Nmap traceroute hop paths and map observed hop
  relationships.
- [ ] Offer automatic compare-to-previous for scheduled scans.

## Phase 4 — Comparison

- [ ] Expand deltas across hosts, ports, protocols, service states, products,
  versions, OS identity, hostnames, MACs, and routes.
- [ ] Warn when targets, protocols, port coverage, or profile versions differ.
- [ ] Show affected hosts and evidence behind each change.

## Phase 5 — Terrain enrichment

- [ ] Ingest router ARP tables while excluding unresolved/incomplete entries.
- [ ] Correlate MAC observations from PCAP Ethernet, ARP, LLDP, CDP, and IPv6
  neighbor discovery with source, segment, timestamps, and confidence.
- [ ] Add offline OUI/vendor lookup.
- [ ] Add local SearchSploit/ExploitDB references with careful
  “potentially relevant” wording.
- [ ] Evaluate the suggested GitLab Nmap parser and identify the analyst's
  “Redline / Red…” network-mapping tool before integration.
- [ ] Enrich topology with IP/MAC/interface/route/segment relationships.

## Phase 6 — Device configuration collection

- [ ] Redesign zero-touch collection around secure session-only credentials,
  SSH-agent use, NETCONF, RESTCONF, vendor APIs, and platform constraints.
- [ ] Keep manual configuration retrieval and upload as the supported workflow
  until the automated design is proven safe and reliable.

## Phase 7 — Operator feedback

- [ ] Add an **Operator Feedback** page as the final navigation tab.
- [ ] Let operators classify feedback as a feature to add, change, or remove,
  or as a problem encountered while using the tool.
- [ ] Capture the affected page/feature, operator comments, submission time,
  application version, and optional scan/run reference for troubleshooting.
- [ ] Provide a simple review queue with status such as New, Under Review,
  Planned, Completed, or Declined while preserving the original submission.
- [ ] Add a safe export path for sharing selected feedback with the project
  backlog without including scan evidence, credentials, or sensitive network
  details by default.

