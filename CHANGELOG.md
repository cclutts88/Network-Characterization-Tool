# Changelog

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
