# Changelog

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
