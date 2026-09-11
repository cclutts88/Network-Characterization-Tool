# Network Characterization Tool — Revised Release Roadmap

The application direction is:

**Nmap → Net Devices → Analysis → Hunt → Map → Reachability / Hardening**

Nmap and Net Devices are collection sources. Analysis interprets and correlates
their results. Hunt focuses analyst attention, Map visualizes selected results,
and Reachability evaluates possible communication paths. Hardening Validation is
an optional future mode within Reachability.

## Release status

### Release 1 — Saved Network / Target Foundation — Complete

- [x] Persistent Saved Networks with standardized name, CIDR, description,
  category, and tags.
- [x] Saved-only, manual-only, and combined scan scopes.
- [x] Multiple Saved Networks in a combined scan.
- [x] Copy a manual target into the Saved Networks editor.
- [x] Add reviewed subnet candidates derived from device configurations.
- [x] Reject invalid or duplicate names and CIDRs; warn on overlaps and normalize
  host-bit CIDRs.
- [x] Retain an immutable Saved Network snapshot with scan history.
- [x] Preserve existing data across the local Docker development workflow.

### Release 2 — Subnet-Grouped Scan History — Complete

- [x] Group runs by their retained Saved Network snapshot.
- [x] Keep multi-network runs in a distinct group without duplicating scans.
- [x] Keep scans without a Saved Network snapshot under Ad Hoc / Manual Scans.
- [x] Show scan count, latest scan, latest run time, and latest host count.
- [x] Nest status, date, profile, actual targets, host count, ownership, evidence,
  Analyze, Compare, and Delete actions under collapsible groups.
- [x] Complete browser validation against migrated scan history and package the
  release for rollback-safe deployment.

### Release 3 — Global No-Strike Redesign — Complete, absorbed early

- [x] Store a persistent global exclusion list.
- [x] Apply global and scan-specific exclusions before FPING and Nmap.
- [x] Keep the editor in a compact collapsible panel.
- [x] Require confirmation before removing excluded entries.
- [x] Preserve No-Strike settings after restart through persistent storage.
- [x] Add a concise pre-launch breakdown of requested addresses, global
  exclusions, scan-specific exclusions, and effective addresses.
- [x] Expand regression coverage for overlapping global and scan-specific ranges.

### Release 4 — Network Device Collection Usability — Complete

- [x] Group collection history by device.
- [x] Keep collection runs and raw evidence collapsible.
- [x] Derive review-only Saved Network candidates from collected configurations.
- [x] Add confirmed deletion of individual device collection results.
- [x] Add structured collapsible summaries for interfaces, routes, neighbors,
    VLANs, firewall/ACL, NAT, commands, configuration, and raw output.
- [x] Add route counts, search, filtering, and large-table handling.

### Release 5 — Scan Execution Engine Upgrade — Complete

- [x] FPING pre-discovery with retained evidence and explicit fallback approval.
- [x] Live Nmap percentage, elapsed time, ETA, heartbeat, and host completion when
  Nmap provides reliable values.
- [x] Chunk and scheduled-batch progress.
- [x] Split combined work into Discovery → TCP → UDP → Merge → Analysis.
- [x] Preserve successful TCP results when UDP fails or times out.
- [x] Tune UDP ports, retries, timing, service detection, host timeouts, and
  recovery behavior.

### Release 6 — Unified Analysis Framework — Complete

- [x] Nmap host, port, service, OS, coverage, outlier, and change analysis.
- [x] Retained evidence and scan-quality warnings.
- [x] Initial device interface, route, neighbor, MAC, LLDP/CDP, and topology
  parsing.
- [x] Add a dedicated Network Device Analysis view.
- [x] Add route protocol/default/next-hop/multipath summaries and review items.
- [x] Add device collection comparison for routes, interfaces, firewall/ACL,
  NAT, and network objects.
- [x] Correlate Saved Networks, Nmap hosts, device interfaces, routes, and policy
  with confidence and provenance.

### Release 7 — Dedicated Hunting View — Planned

- [ ] Service-aware categories such as Remote Access, File Transfer, File
  Sharing, Web, Identity, Databases, Email, and Network Management.
- [ ] Support nonstandard ports and multiple categories per host.
- [ ] Distinguish exposed, inferred, observed, and correlated capability.
- [ ] Add combined filters and scan-to-scan hunting changes.

### Release 8 — SearchSploit Enrichment — Planned

- [ ] Normalize product/version evidence and query a staged local Exploit-DB
  dataset.
- [ ] Show candidate references, match counts, platform, and type.
- [ ] Clearly label results as potential matches requiring analyst validation.
- [ ] Do not execute exploit code.

### Release 9 — Network Map Core Redesign — Planned as an independent release

- [ ] Pan-and-zoom canvas with cursor-centered zoom, node drag, selection, and
  Fit.
- [ ] Saved-network grouping and collapsible subnet groups.
- [ ] Compact nodes with full detail in a side panel.
- [ ] Consolidate router/firewall interfaces into one device identity.

### Release 10 — Advanced Map Usability — Planned

- [ ] Search by IP, hostname, MAC, OS, service, port, and Saved Network.
- [ ] Pan, zoom, and highlight search results.
- [ ] Add zoom-dependent detail and optional analytical overlays.
- [ ] Evaluate saved layouts, minimap, reset layout, and alternate layouts.

### Future major capability — Reachability Analysis

- [ ] Evaluate source, destination, and service using open ports, routes,
  interfaces, firewall/ACL policy, NAT, Saved Networks, and device identity.
- [ ] Support host, subnet, WAN/Internet, external IP, and external CIDR sources.
- [ ] Report Local, Routed, Expected Allowed, Expected Blocked, Unknown, and Not
  Exposed without claiming unsupported certainty.
- [ ] Group source-exposure reports by Saved Network and preserve policy objects
  and evidence.
- [ ] Send saved reachability results to the map for focused visualization.

### Future extension — Hardening Validation

- [ ] Simulate proposed firewall, ACL, or routing controls without changing
  production devices.
- [ ] Compare current and proposed paths, alternate paths, and collateral impact.
- [ ] Export evidence-backed hardening reports and map comparisons.

## Release discipline

Every release should be built and tested locally, checked against existing and
new data, packaged with offline dependencies where required, deployed by a short
final swap, smoke-tested, and kept independently rollbackable. Scan-engine,
device-analysis, map, and reachability redesigns must remain separate releases.

Regression checks include scan creation, Saved Networks, manual targets,
No-Strike behavior, FPING, TCP, UDP, storage, history, analysis, deletion, device
collection/history, migration, and map loading.
