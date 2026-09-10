# Changelog

## 0.6.3 — Cleaner topology labels

- Removed interface MAC addresses from network-map connection labels to reduce
  visual clutter while retaining them on device cards, in search, and in the
  Device Details interface list.
- Prevented pfSense and other device self-ARP entries from recreating known
  router/firewall interface IPs as separate endpoint blocks or neighbor links.

## 0.6.2 — pfSense collection repair

- Replaced the nonexistent `pfSsh.php playback config` command with the
  documented read-only `cat /cf/conf/config.xml` collection method.
- Applied the corrected configuration collection to both pfSense router and
  firewall profiles while retaining `ifconfig` interface-MAC evidence.
- Added regression coverage preventing the invalid playback command from
  returning to either pfSense template.

## 0.6.1 — Interface hardware identity

- Added detailed interface collection commands for Cisco and Juniper routers
  and firewalls while continuing to use VyOS configuration `hw-id` and pfSense
  `ifconfig` evidence.
- Parsed Cisco dotted MACs, Juniper current/hardware addresses, VyOS `hw-id`,
  and Linux/FreeBSD `ether` or `link/ether` output into individual interfaces.
- Displayed each interface MAC directly beside its interface name and IP on
  router/firewall map cards, connection evidence, search, and device details.
- Retained the existing device-level MAC as a primary/observed summary instead
  of using it as a substitute for every interface's hardware address.

## 0.6.0 — Confirmed neighbor topology

- Constrained the Previous Scans panel to a compact fixed height with its own
  scrollbar and sticky table headings so older automated scans and uploads
  remain available without making the whole page excessively long.
- Added detailed LLDP collection for VyOS, Cisco, and Juniper device profiles
  plus detailed CDP collection for Cisco profiles.
- Parsed LLDP/CDP local interfaces, remote ports, neighbor names, management
  addresses, chassis identifiers/MACs, platforms, and capabilities from retained
  configuration evidence.
- Correlated discovered neighbors to existing device/IP/MAC nodes and added
  confirmed, labeled interface-to-interface links to the network map.
- Included password-prompt interactive configuration collections in network-map
  evidence processing as well as key-based collections and manual uploads.
- Added an LLDP/CDP link count, map legend, searchable neighbor identity, and
  neighbor details while retaining the source configuration as evidence.
- Applied the operator-provided Device Name to configuration-derived map nodes.

## 0.5.0 — Evidence-backed scan comparison

- Added direct selection and comparison of any two completed automated scan
  occurrences, including scheduled scans split across multiple chunks.
- Standardized automated comparison labels around the readable scan name,
  scheduled/manual status, completion time, effective scope, and pinned profile
  version; legacy per-chunk names are collapsed into one scan occurrence.
- Kept chunk numbers as structured progress metadata instead of embedding them in
  future scheduled scan names.
- Expanded comparison details across host presence, ports, port states, services,
  products, versions, hostnames, MAC/vendor identity, OS identity, and traceroute
  paths.
- Added explicit coverage cautions for target, protocol, exact port, discovery,
  timing, DNS, traceroute, profile/version, and analyzer-interface differences.
- Linked every affected host back to the retained before/after XML evidence.
- Made uploaded XML and automated runs use the same rich comparison renderer.
- Preserved full host, OS-group, outlier, coverage, and export analysis when a
  chunked scheduled occurrence is opened as one logical scan.

## 0.4.2 — Active recurring scheduling

- Completed recurring hourly, daily, weekly, monthly, and custom-hour schedule
  execution while keeping every schedule pinned to an immutable profile version.
- Added schedule owner and modification history for creation, enable/pause, and
  profile-version changes.
- Added occurrence-level start, completion, status, run IDs, and completed-chunk
  tracking alongside next-run and last-run information.
- Kept conflicting schedules queued behind the single scanner and retained the
  analyst warning after more than three delayed occurrences.
- Added restart recovery that marks orphaned runs as interrupted and resumes the
  affected occurrence after its last completed chunk without repeating successful
  chunks.
- Fixed subnet characterization counts when Nmap discovers router or firewall
  interface addresses already represented by infrastructure nodes; the map now
  reports endpoint and scanned-device observations separately.
- Collapsed infrastructure-only transit subnets into labeled links between their
  connected devices and changed the map to a deterministic spider-web layout.
- Added collision spacing plus draggable map boxes with live connection updates
  and a reset control for restoring the automatic layout.
- Added topology-aware radial placement around the most-connected network device
  and configuration-derived zone labels for Cisco, VyOS, Juniper, and pfSense
  interface evidence while always retaining each zone's subnet CIDR.
- Added map zoom-out, zoom-in, 100%, and fit-to-view controls that remain
  compatible with draggable node positioning.
- Moved map scaling controls into a persistent map overlay and enlarged network
  device cards to list every correlated interface/IP address. Connections now
  terminate at device-card borders and retain the matching interface evidence.

## 0.4.1 — Scan builder usability and path discovery

- Kept the shared page navigation visible while long content scrolls.
- Made TCP + UDP selection automatically choose compatible independent Common
  port scopes when Top-N defaults were active.
- Added live port-scope details showing fixed/custom ports, Nmap-selected Top-N
  behavior, and why each scope exists, including ICS/OT protocol context.
- Added optional FPING host discovery to profiles, automated runs, and portable
  packages so Nmap can focus on responsive hosts.
- Added optional Nmap traceroute collection, retained hop parsing, and observed
  hop relationships for the network map.
- Added clearer validation when a selected custom TCP or UDP scope is empty.

## 0.4.0 — Phase 1 and 2

- Consolidated scan construction, saved-profile selection, run-now execution,
  and package generation on one Nmap Scans page.
- Added TCP, UDP, and combined TCP + UDP scan modes with independent common,
  full, custom, and ICS/OT port scopes.
- Added protected built-in profiles plus save, clone, reuse, and immutable
  version creation.
- Added profile-version-pinned schedule definitions without enabling recurring
  execution yet.
- Added `Name_Date_Time` names, `(S)` scheduled markers, and creator/scheduler/
  executor metadata.
- Added explicit scan coverage to manifests and history.
- Routed historical and automated XML through the same full analysis renderer.
- Added Nmap MAC/vendor and hostname parsing.
- Added separate host-summary and normalized port-level CSV exports.
- Added raw XML as a secondary history action.
- Added GitHub Actions tests and a GitHub Pages project site.
