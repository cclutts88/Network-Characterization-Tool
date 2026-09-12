# Changelog

## 0.14.0-dev — Advanced Map Usability

- Added an expanded map workspace that uses the available browser window and
  returns to the standard workspace with its button or Escape.
- Kept subnet endpoints collapsed by default and added individual-line and
  organized grouped-box presentation modes.
- Added per-subnet and map-wide endpoint sorting and breakdowns by IP address,
  hostname, or operating system, with grouped host rows opening the retained
  host evidence in the details panel.
- Kept each endpoint breakdown as one logical pool when it flows into multiple
  columns, with one centered heading and one total spanning the entire group.
- Added lower-right resize handles to grouped endpoint boxes; widening a box
  reflows its host pool into additional columns, and Reset layout restores the
  automatic size.
- Changed IP presentation to one numerically sorted host pool instead of
  arbitrary address-range subgroups; hostname and OS headings now appear only
  when the selected field contains multiple meaningful values.
- Moved individual-versus-grouped and expand-versus-collapse controls into each
  subnet box, and simplified the map toolbar to Expand all and Collapse all.
- Color-coded grouped host rows by observed OS family, with exact OS text and a
  legend so a mixed Windows, Linux, macOS, network, other, or unknown pool is
  immediately distinguishable.
- Kept expanded-workspace details available as an optional floating panel while
  anchoring it inside the map canvas border. Expanded mode starts with the panel
  hidden and provides Show details / Hide details without letting it escape the
  map area at narrower browser widths.
- Moved the expanded-workspace details toggle to the map's upper-right control
  area and made the SVG coordinate space follow the expanded canvas aspect ratio,
  allowing the full map width to be used for layout, dragging, and panning.
- Replaced the expanded map's fixed height estimate with a flexible canvas that
  consumes all remaining space down to the workspace's bottom border.
- Expanded the SVG coordinate boundary itself to match the entire visible canvas
  at its current aspect ratio, eliminating inactive space to the right and below
  the former fixed 1120-by-720 map boundary.
- Made expanded workspace the topology's 1:1 working surface and retained that
  coordinate extent when returning to the standard form, where the same layout
  is scaled down as an overview instead of being rebuilt or rearranged.
- Kept Show details / Hide details independent of map scale so opening the
  floating panel never changes an expanded 100% workspace into a fitted view.
- Added a Large network workspace option providing four times the screen area
  (twice the width and twice the height) at 100%, while standard mode retains a
  fitted overview of the selected mission workspace.
- Changed Fit to Fit devices, calculating the visible node boundary so a sparse
  topology fills the viewport without sacrificing unused mission workspace.
- Added edge-triggered auto-pan during node dragging. Holding a node near any map
  edge now scrolls the mission workspace in that direction, allowing placement
  throughout 1× and 4× areas without repeatedly zooming out.
- Added Shift-click multi-object selection and group dragging. Selected boxes
  retain their relative positions while moving, relationship lines update live,
  and edge-triggered auto-pan continues to work for the complete selection.
- Made Shift-click on an expanded subnet in Individual view select or deselect
  that subnet and every dependent host node, allowing the complete branch to be
  repositioned together.
- Added automatic zoom-dependent detail levels: Overview, Summary, Full detail,
  and Evidence detail. The active level is visible beside the map scale, and
  labels, endpoint rows, controls, and evidence summaries adapt to the scale.
- Added a live minimap to the expanded workspace with topology and selection
  markers, a current-viewport frame, and click-drag navigation across 1× and 4×
  mission areas.
- Added Small, Medium, Large, and hidden minimap controls.
- Added a 50-step presentation Undo / Redo history covering map moves, grouped
  box resizing, endpoint presentation changes, sorting, workspace size, layout
  reset, layout presets, locking, and selection arrangement.
- Added object locking plus a contextual selection bar for fitting, locking,
  row or column alignment, even distribution, and compact arrangement.
- Added box selection, right-click node actions, and keyboard controls for
  Undo / Redo, fit, lock, box select, zoom, selection clearing, and coarse or
  precise arrow-key movement. Shift+R aligns an unlocked multi-selection into a
  row, Shift+C aligns it into a column, Shift+F fits a selection, and Shift+L
  locks or unlocks it. F remains the whole-map Fit Devices shortcut.
- Added Spider web, Hierarchy, and Grid automatic layout presets.
- Added an analyst-selectable WAN anchor. Device details suggest interfaces
  named WAN, outside, internet, uplink, or external, permit any interface to be
  chosen when evidence is ambiguous, and place, label, and lock that device at
  the map's top center. An external WAN marker now sits above the map border and
  connects directly to the anchored device with a visible uplink. The marker
  follows the uplink during movement, zoom, and pan and disappears when its
  anchored device is outside the visible map or removed by an isolated search.
- Reworked interface connection labels into stacked interface, IP, and zone
  lines. Lower zoom levels suppress extra detail, while hover text preserves the
  complete relationship and evidence.
- Expanded map search with result counts, previous/next navigation, automatic
  focus on the active match, and an isolate-matches presentation mode.
- Added named private browser layouts that save and restore manual placement,
  group sizes and modes, locks, WAN anchor, map preset, workspace size, zoom,
  minimap presentation, sorting, and analytical overlay selection.
- Added optional OS-family, service-exposure, and identity-gap overlays with a
  concise legend. Service exposure is presented as port-density context rather
  than a vulnerability finding, while identity gaps distinguish missing
  OS/MAC/evidence from conflicting observations.
- Added zoom-safe network-diagram symbols for routers, firewalls, switches,
  wireless devices, and unknown infrastructure. Device borders remain solid
  when identity is confirmed by configuration evidence and dashed when the
  type is inferred, leaving color available for analytical overlays.
- Added explanatory hover text to the Map search navigation arrows and Isolate
  control.
- Standardized host and network presentation on numeric IP ordering across scan
  analysis, Hunt, comparisons, device candidates, and Map collections, including
  IPv4, IPv6, CIDR, and canonical host identifiers.
- Kept map presentation state local to each analyst browser so display changes
  do not modify shared evidence or another analyst's view.

## 0.13.0-dev — Network Map Core

- Added cursor-centered wheel zoom and click-drag canvas panning while retaining
  toolbar zoom, Fit, node dragging, and centered layout reset behavior.
- Replaced oversized interface-expanded device boxes with compact device nodes;
  complete addresses, interfaces, routes, services, MACs, and provenance remain
  available in the sticky details panel.

## 0.12.1-dev — Network-wide hunting workflow

- Made Hunt a top-level page in the Nmap, Device, Analyze, Hunt, Map workflow.
- Made Hunt load a network-wide view by default using the newest completed
  evidence for each retained network scope.
- Added a complete host/device inventory alongside capability findings, keeping
  hosts even when no matching service capability is present.
- Added operating-system, subnet, and device-type filters and expanded the
  capability-evidence explanations.
- Cross-referenced Nmap IPs with retained router/firewall neighbor-table MAC
  evidence in Hunt and Nmap Analysis, with direct-versus-correlated source
  labels, hover detail, timestamps, and links to the supplying collection.
- Added a future audited analyst OS-override capability to the rollout roadmap.
- Kept the capability evidence guide pinned below the Hunt navigation while
  scrolling through host and finding tables.
- Renamed Hunt's analyst-facing capability categories to datasets throughout
  the summary, filter, findings table, and comparison language.
- Expanded Hunt to a 26-dataset classification catalog including authentication,
  identity, name resolution, VPN, monitoring, virtualization, storage, OT, IoT,
  routing, and policy domains while keeping only active datasets in the summary
  and filter dropdown.
- Made the Host and device inventory collapsible and kept its current host count
  visible in the collapsed heading.
- Added offline SearchSploit enrichment with CVE categorization, candidate-title
  filtering, network-wide filters, database provenance, connected updates,
  air-gapped archive uploads, and retained-version rollback.
- Validated the official Exploit-DB archive on an empty NCT data volume through
  upload, activation, restart persistence, second-version staging, and rollback.
- Made the major Hunt panels collapsible, added clear open/closed chevrons, and
  kept active Network and SearchSploit filters visible in collapsed headings.
- Replaced the separate visible page-title blocks with a centered NCT wordmark
  and active Nmap, Device, Analyze, Hunt, and Map navigation state.
- Enlarged and spaced the NCT wordmark, highlighted the N/C/T initials in its
  full-name underline, and shortened the shared navigation buttons.
- Removed the originating-host banner and operator-entered host field from the
  Nmap page while continuing to record the analyzer hostname automatically.
- Added a slim origin notice beneath the sticky navigation on Nmap, Device, and
  Hunt so outbound scan, collection, and connected-update traffic is attributed
  to the current NCT host without an operator-entered field.

## 0.12.0-dev — Dedicated service hunting

- Added a dedicated Hunt Services view for completed automated Nmap scans.
- Classified exposed services into Remote Access, File Transfer, File Sharing,
  Web, Identity, Databases, Email, Network Management, and uncategorized
  exposure without hiding unknown services.
- Distinguished exposed, port-inferred, fingerprint-observed, and correlated
  capability evidence, including fingerprint matches on nonstandard ports.
- Added combined host, category, protocol, evidence-level, and nonstandard-port
  filters while allowing multiple capability categories per host.
- Added scan-to-scan hunting comparisons with added, removed, and changed
  findings, host category changes, coverage warnings, and retained XML links.
- Added direct Hunt actions to completed scan history and analysis history.

## 0.11.0-dev — Unified network-device analysis

- Added a dedicated Network Device Analysis view under Analyze Results, plus a
  direct Analyze action on each retained device collection.
- Added route protocol, default-route, next-hop, multipath, interface-role, and
  review-item summaries derived from retained configuration evidence.
- Added collection-to-collection comparison for interfaces, routes,
  firewall/ACL rules, NAT statements, and network objects.
- Correlated Saved Networks and retained Nmap hosts with parsed interfaces,
  routes, policy, NAT, and network objects, including confidence labels and
  links back to source evidence.
- Added network-object extraction to the structured device-configuration view.

## 0.10.0-dev — Split scan execution engine

- Split local scan execution into visible Discovery, TCP, UDP, Merge, and
  Analysis preparation phases with separate retained evidence for each stage.
- Added a dedicated Nmap host-discovery pass; responsive targets are certified
  once and passed to protocol scans without repeating discovery.
- Preserved successful TCP XML as the canonical analyzable result when the UDP
  phase fails or reaches its time limit, while clearly marking the run partial.
- Bounded UDP work with profile-aware retry limits and per-host timeouts, used
  light service detection, and kept OS detection in the TCP phase.
- Added phase-aware progress labels and command accountability to the scan page.
- Added regression coverage for phase commands, TCP/UDP XML merging, and the
  TCP-success/UDP-failure recovery path.

## 0.9.0-dev — Network-device collection usability

- Added structured, collapsible review sections for interfaces, routes,
  neighbors, VLANs, firewall/ACL evidence, NAT evidence, executed commands,
  configuration text, and raw output.
- Added route-type filtering, result search, route counts, and bounded table
  rendering for large collection results.
- Added confirmation-protected deletion of one device collection result with
  strict run-directory validation and active-session protection.
- Removed duplicate artifact links when an uploaded file also matches the
  normal collected-configuration filename pattern.
- Kept Open, Analyze, Compare, and Delete scan-history actions on one row so
  the Delete control no longer wraps onto a line by itself.
- Shortened host and port CSV export filenames to a compact NCT label and
  eight-character result identifier for reliable opening on Windows.

## 0.8.0-dev — Subnet-grouped scan history

- Replaced the flat Nmap run table with collapsible groups based on the immutable
  Saved Network snapshots retained with each scan.
- Kept scans spanning several Saved Networks in a dedicated multi-network group
  and legacy/manual scans in an Ad Hoc / Manual group without duplicating runs.
- Added group summaries for scan count, latest scan, completion time, and latest
  host count while preserving per-run scope, profile, ownership, evidence, and
  deletion controls.
- Added direct Analyze and Compare actions from grouped history; Compare opens
  Analysis with the selected run preselected for a second-run comparison.
- Added a live pre-launch scope and safety summary showing requested, globally
  excluded, scan-specific excluded, and effective scan address counts.
- Standardized the No-Strike interface on “excluded” wording and prevented
  overlapping global and scan-specific exclusions from being double-counted.
- Reconciled the repository roadmap with the revised Nmap → Net Devices →
  Analysis → Hunt → Map → Reachability / Hardening release sequence.

## 0.7.1-dev — Scan workspace layout

- Added expandable Saved Networks and No-Strikes panels directly below the
  primary page navigation.
- Consolidated manual Saved Network management and review-only subnet
  suggestions from device configurations into the Saved Networks panel.
- Added an explicit scan-scope selector for a Saved Network, manual IPv4 host
  or CIDR entry, or a combination of both sources.
- Kept global No-Strikes separate from per-scan exclusions while placing all
  global safety-list management in one expandable panel.

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
