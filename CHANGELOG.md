# Changelog

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
