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

- [x] Show live Nmap host completion progress, including whole-batch progress
  for sequential scheduled chunks.
- [x] Execute recurring daily, weekly, monthly, and custom schedules.
- [x] Retain schedule owner, modification history, next run, and last run.
- [x] Add optional FPING pre-discovery with retained responsive-host evidence
  and an explicit warning that ICMP-blocking hosts can be omitted.
- [x] Collect and retain Nmap traceroute hop paths and map observed hop
  relationships.
- [x] Offer automatic compare-to-previous for scheduled scans.

## Phase 4 — Comparison

- [x] Expand deltas across hosts, ports, protocols, service states, products,
  versions, OS identity, hostnames, MACs, and routes.
- [x] Warn when targets, protocols, port coverage, or profile versions differ.
- [x] Show affected hosts and evidence behind each change.

## Phase 5 — Terrain enrichment

- [x] Ingest router ARP tables while excluding unresolved/incomplete entries.
- [x] Correlate MAC observations from Nmap and router/firewall ARP tables with
  source, interface, segment, timestamps, and confidence.
- [ ] Evaluate PCAP MAC correlation only for future deployments with collectors
  on target Layer-2 segments; do not infer endpoint MACs from routed traffic.
- [x] Add offline OUI/vendor lookup using the locally installed Nmap database.
- [ ] Extend the packet parser for PCAPNG when a future deployment includes
  collectors on useful Layer-2 segments.
- [x] Collect and parse LLDP/CDP chassis, device, local-interface, and remote-port
  identity into confirmed network-map links.
- [ ] Add local SearchSploit/ExploitDB references with careful
  “potentially relevant” wording.
- [ ] Evaluate the suggested GitLab Nmap parser and identify the analyst's
  “Redline / Red…” network-mapping tool before integration.
- [x] Enrich topology with IP/MAC/interface/route/segment relationships.

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
