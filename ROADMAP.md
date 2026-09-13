# Network Characterization Tool — Revised Release Roadmap

The application direction is:

**Device → Nmap → Analyze → Hunt → Map → Reachability / Hardening**

Device configuration establishes the network core and candidate subnets before
Nmap scanning. Analyze interprets retained scan and device evidence, Hunt focuses
analyst attention, Map visualizes selected results, and Reachability evaluates
possible communication paths. Hardening Validation is an optional future mode
within Reachability.

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

### Release 7 — Dedicated Hunting View — Complete

- [x] Service-aware categories such as Remote Access, File Transfer, File
  Sharing, Web, Identity, Databases, Email, and Network Management.
- [x] Support nonstandard ports and multiple categories per host.
- [x] Distinguish exposed, inferred, observed, and correlated capability.
- [x] Add combined filters and scan-to-scan hunting changes.

### Release 8 — SearchSploit Enrichment — Complete

- [x] Normalize product/version evidence and query a staged local Exploit-DB
  dataset.
- [x] Show candidate references, match counts, platform, and type.
- [x] Clearly label results as potential matches requiring analyst validation.
- [x] Do not execute exploit code.
- [x] Package and validate the official offline Exploit-DB archive against an
  empty persistent NCT data volume, including restart persistence, a second
  staged version, and rollback to the prior version.
- [x] Add a connected **Update from internet** workflow that stages, validates,
  and atomically activates official Exploit-DB data.
- [x] Add an air-gapped **Upload offline update** workflow with archive safety
  checks, database validation, atomic replacement, and rollback retention.
- [x] Display database source, version/update time, and previous-version rollback
  controls in the NCT interface.
- [x] Complete the pre-map interface cleanup with a shared centered NCT brand,
  emphasized acronym letters, compact navigation, and active-button page identity.
- [x] Show the automatic NCT host in a slim sticky origin banner on pages that
  can initiate scans, device collection, or connected database updates.

### Release 9 — Network Map Core Redesign — Complete

- [x] Pan-and-zoom canvas with cursor-centered zoom, node drag, selection, and
  Fit.
- [x] Saved-network grouping and collapsible subnet groups.
- [x] Compact nodes with full detail in a sticky side panel.
- [x] Consolidate router/firewall interfaces into one device identity while
  retaining their addresses and evidence in device details.

### Release 10 — Advanced Map Usability — In progress

- [x] Reorder the primary workflow as Device, Nmap, Analyze, Hunt, and Map and
  make Device the default NCT landing page so subnet evidence can guide scans.
- [x] Compact the Map inventory counts, remove Relationships and Evidence
  records from the visual summary, and make the complete summary collapsible.
- [x] Move Expand workspace into a sticky top-center control that remains in the
  same predictable position for entering and exiting the mission workspace.
- [x] Make Analyze open directly on the selected scan results without jumping
  into comparison output; replace the large Previous scans panel with a compact
  top comparison selector that stays collapsed until requested.
- [x] Present original operator scan scopes and exclusion counts in Analyze
  instead of exposing fragmented post-exclusion CIDRs as the main title.
- [x] Replace Device's disconnected command blocks with one ordered,
  vendor-specific execution plan that distinguishes NCT host commands, device
  commands, and local evidence writes; show SCP, remote-file creation, and
  cleanup only for the VyOS and pfSense password workflows that actually use
  them, while identifying Cisco, Juniper, and key-based collection as direct
  SSH streaming.
- [x] Add UniFi OS gateways as Router and Firewall collection targets using a
  guarded read-only Linux evidence set for platform, interfaces, routes,
  neighbors, VLANs, listening services, firewall rules, and LLDP. Stream results
  directly through SSH, tolerate unavailable version-specific utilities while
  retaining their status, parse Linux interface and route evidence into Device
  Analysis and Map, and keep EdgeRouter on the existing VyOS path.
- [x] Add **Switch** as a first-class Device collection type instead of relying
  on router profiles. Provide vendor/platform capability choices so unsupported
  combinations are disabled rather than sending inappropriate commands.
- [x] Add guarded read-only switch profiles for Cisco IOS / IOS-XE / NX-OS,
  Juniper EX, and UniFi switches. Collect version and configuration plus VLANs,
  access/trunk mode, interface status and descriptions, MAC address tables,
  spanning tree, link aggregation, PoE status where supported, and LLDP/CDP.
- [x] Parse switch evidence into Device Analysis and Map so learned MACs,
  VLAN membership, uplinks, port channels, and neighbor relationships can refine
  endpoint placement. Retain per-command success/failure because model and
  software-version command support varies.
- [x] Search by IP, hostname, MAC, OS, service, port, and Saved Network.
- [x] Highlight search results, step forward and backward through matches, fit
  the active match, and optionally isolate matching topology branches.
- [x] Keep the fixed-height map as the default workspace, with an operator option
  to expand it into a full-width workspace and show or hide a floating details
  panel anchored inside the map canvas border.
- [x] Let the expanded map use its complete visible width for node placement and
  keep the details toggle with the map controls instead of the page toolbar.
- [x] Reclaim the details area whenever no map object is selected, open details
  automatically on selection, and let the analyst suppress the pane without
  clearing that selection in either the standard or expanded workspace.
- [x] Size the expanded canvas from the actual remaining vertical space so its
  full width and height remain usable across browser window sizes.
- [x] Expand the SVG coordinate boundary with the visible canvas so every part of
  the expanded workspace supports node placement, dragging, and panning.
- [x] Treat expanded Map as the canonical 1:1 topology workspace and preserve its
  layout as a scaled overview when returning to the smaller standard viewport.
- [x] Offer a four-times-area large-network workspace for missions requiring more
  topology construction room while preserving 100% scale and pan navigation.
- [x] Fit the viewport to the actual device and subnet boundary instead of empty
  mission-workspace borders when the topology is sparse.
- [x] Auto-pan the mission workspace when an analyst drags a node near any edge.
- [x] Add Shift-click multi-object selection and group dragging that preserves
  relative placement, updates relationship lines, and supports edge auto-pan.
- [x] In an expanded Individual endpoint view, let Shift-clicking the parent
  subnet select or deselect the subnet and all of its dependent host nodes as
  one movable branch.
- [x] Add zoom-dependent detail levels that move automatically between overview,
  summary, full, and evidence views while showing the active level.
- [x] Add a live minimap in the expanded workspace with selected-node markers, a
  viewport frame, and click-drag navigation across large mission areas.
- [x] Add Small, Medium, Large, and hidden minimap presentation controls.
- [x] Add a reversible 50-step map-presentation history with toolbar and
  keyboard Undo / Redo controls.
- [x] Let analysts lock selected objects against accidental dragging or group
  layout changes while retaining them in the visible selection.
- [x] Add a selection action bar for fit, lock, row/column alignment,
  distribution, and compact arrangement.
- [x] Add drag-box selection, contextual right-click actions, keyboard fit,
  lock, box-select, zoom, row/column alignment, Escape, and precise/coarse
  arrow-key movement.
- [x] Add Spider web, Hierarchy, and Grid layout presets while continuing to
  honor explicitly positioned objects.
- [x] Let an analyst choose a device interface as the WAN / outside path, place
  that device at the top center, and lock and label it as the visual topology
  anchor. Suggest explicitly named WAN, outside, internet, uplink, or external
  interfaces while allowing a manual choice when the source is ambiguous. Show
  the selected path as a WAN marker outside the map border with a visible uplink
  to the anchored device. Keep the marker aligned with that uplink during device
  movement, zoom, and pan, and hide the WAN presentation when its device is not
  visible.
- [x] Let an analyst designate a discovered device or host as the External WAN
  gateway, promote it into a single top-boundary WAN object instead of leaving
  a duplicate node on the canvas, connect that boundary to the nearest visible
  internal device, and retain the private presentation choice with saved
  layouts.
- [x] Let analysts hide one or several Map objects without deleting evidence,
  list them in a collapsible Hidden objects section, and restore objects
  individually or all at once.
- [x] Present interface connection details as stacked, zoom-aware labels with a
  concise interface and IP summary plus the complete relationship and evidence
  in hover text.
- [x] Add per-subnet endpoint display modes: collapsed by default, individual
  endpoint lines, or an organized endpoint-group box.
- [x] In the grouped endpoint view, let the analyst sort and divide hosts by IP
  address, hostname, or operating system, with useful counts and breakdowns for
  the selected investigation view; IP is one sorted pool, while subgroup
  headings appear only for actual hostname or OS differences.
- [x] Use numeric IP-address ordering across scan analysis, Hunt, comparisons,
  device candidates, and Map host collections instead of lexical text order.
- [x] Let analysts resize grouped endpoint boxes and reflow their host pools
  across the available columns without changing shared evidence.
- [x] Put grouped-versus-individual and expand-versus-collapse toggles on each
  subnet box, with map-wide Expand all and Collapse all controls.
- [x] Color-code grouped host rows by observed operating-system family while
  retaining exact OS text and an Unknown OS treatment.
- [x] Add optional OS-family, service-exposure, and identity-gap analytical
  overlays with an explicit map legend and neutral default view.
- [x] Distinguish routers, firewalls, switches, wireless devices, and unknown
  infrastructure with compact network-diagram symbols, including a clearly
  separated crossed-arrow router mark. Keep analytical color available for
  overlays and use solid versus dashed borders for confirmed versus inferred
  device identity.
- [x] Add named private layouts that persist in the current analyst's browser,
  restore the complete presentation, and can be replaced or deleted.
- [x] Save every visible object's coordinates in a named layout and stabilize
  all visible objects on entering Edit mode so an untouched auto-layout node
  cannot reflow independently while the analyst is building the map. Expand
  the logical map boundary to contain saved edge positions instead of clamping
  an outlying object into a new location during redraw.
- [x] Let each analyst mark exactly one personal or shared layout as the default
  with a hollow/filled star; automatically open that layout on future Map visits.
- [x] Add Direct and Right-angle trunks connection styles so analysts can switch
  between compact web lines and conventional vertical-drop/horizontal-backbone
  diagram presentation without changing topology evidence.
- [x] Add a Hybrid backbone default that keeps infrastructure links structured
  and endpoint membership direct, plus per-connection style and direction
  overrides with draggable, grid-aware bend handles.
- [x] Add optional 20- and 40-pixel object grids and visual line magnets for
  aligning compatible nearby trunks without creating or merging topology
  evidence.
- [x] Add an analyst-local Map markup layer with colored rectangles and ellipses
  that can contain text, be moved, resized, edited, deleted from their controls
  or the keyboard, and be retained in private layouts.
- [x] Add an optional joined gateway presentation that visually groups a routed
  next-hop device with the subnet containing its address, moves both parts as
  one, and keeps their separate evidence records and outgoing routes intact.
- [x] Add an explicit Map Edit mode and keep line routing, object movement,
  layout construction, alignment, locking, markup, and destructive presentation
  controls out of the normal investigation view.
- [x] Add a type-organized Map parking lot for blank-slate construction. Keep
  endpoints bundled inside subnet objects, preserve all topology evidence while
  objects are parked, restore lines automatically when both ends are placed, and
  queue parked upstream, downstream, and peer dependencies for the active item.
- [x] Preserve parked objects in private named layouts and let analysts park or
  place joined gateway/subnet pairs as one visual construction unit.
- [x] Exclude the Docker runtime's private bridge gateway from mission topology
  and layout calculations while retaining it as tool-local raw traceroute path
  evidence. Fit the standard viewer to placed content instead of empty expanded
  workspace borders so locked objects do not appear to jump toward the corner.
- [x] Keep viewport navigation separate from object geometry so navigating never
  rewrites or snaps object and line coordinates. Use click-and-drag to pan and
  ordinary wheel movement for pointer-centered zoom.
- [x] Preserve each subnet's Grouped or Individual endpoint presentation while
  entering Edit mode. Show individual host objects when their subnet is placed,
  and keep those dependent hosts off-canvas while the subnet is parked.
- [x] Prefer analyst-assigned Saved Network names for matching subnet titles on
  the Map while retaining each CIDR as the stable technical identifier.
- [x] Add authenticated deliberately shared layouts with owner protection,
  explicit Administrator publishing, and analyst-local default selection.

### Future release — Rapid Deployment and Upgrade Automation

- [x] Provide an operator-friendly rapid deployment launcher that performs a
  complete preflight, deployment or upgrade, health check, and final access
  handoff without requiring the operator to assemble Docker commands manually.
  - [x] Add a guided Test/Range installer with built-in prompts, a final review,
    a non-mutating plan mode, automatic preflight before deployment, private-lab
    TLS generation, initial Administrator setup, and a reusable non-sensitive
    Range preset for frequently reset VMs.
- [x] Give the launcher explicit **Test**, **Range**, and **Mission** deployment
  profiles with different acceptance rules rather than treating every host as
  equivalent:
  - **Test** keeps the current developer workflow local, permits alternate
    ports, and prioritizes fast rebuild, reset, and rollback.
  - **Range** assumes older or inconsistent host software, limited or absent
    internet access, occupied ports, and disposable training infrastructure. It
    prioritizes compatibility and useful diagnostics without silently upgrading
    or reconfiguring the range host.
  - **Mission** requires the supported modern Docker baseline, stable hostname
    and ports, trusted HTTPS, authenticated access, backups, monitoring, and a
    fail-closed readiness check. Required prerequisites may be installed only
    through an explicitly approved and logged administrator workflow.
- [x] Use one immutable, versioned, checksummed NCT application image across all
  three profiles. Keep configuration, credentials, ports, certificates, and
  data volumes environment-specific, and never promote test or range data into
  a mission environment implicitly.
- [x] Define promotion gates from local testing to range evaluation and then to
  mission readiness. Preserve the exact NCT image digest, build version,
  deployment profile, test results, compatibility findings, known limitations,
  and rollback proof so a successful lab launch alone cannot be reported as
  mission-ready.
  - [x] Record the content-addressed local image ID, registry digest when
    available, declared version/build, and exact running build in every Test or
    Range deployment receipt; reject `:latest` and missing build identity for
    Range.
- [x] Detect whether Docker Engine or Docker Desktop is installed, running, and
  reachable; compare its server/API version with NCT's documented minimum and
  tested versions, and explain the exact supported workaround when the local
  version is too old or exposes an incompatible API.
- [x] Detect and validate both the modern `docker compose` plugin and legacy
  `docker-compose`. Prefer the supported Compose path, fall back to a compatible
  direct-Docker deployment when Compose is absent or too old, and stop with a
  clear corrective action only when no safe path is available.
- [x] Implement a documented Range compatibility ladder: modern Compose v2,
  legacy `docker-compose`, direct Docker Engine, and finally a self-contained
  offline NCT VM/appliance when the installed Docker API, kernel, image format,
  networking, or security model is too old to support safely. Do not disguise
  an unsupported Docker host with fragile command-line workarounds.
- [ ] Package the range fallback so it can be transferred without internet
  access and booted with a known-compatible runtime while still requiring the
  operator to choose its network attachment, address, ports, and authorized
  target ranges. Treat the VM/appliance as a separately versioned artifact with
  its own checksum, resource minimums, upgrade path, and rollback instructions.
- [ ] Maintain a repeatable Range compatibility test matrix covering Compose v2,
  legacy Compose v1, Docker Engine without Compose, the oldest supported Docker
  API and Linux kernel, supported CPU architectures, offline image loading,
  occupied ports and container names, bridge/VPN subnet overlap, existing older
  NCT deployments, preserved data, `NET_RAW`, packet capture, and scan
  reachability. Record pass, degraded, workaround, and unsupported outcomes.
  - [x] Add an executable non-destructive baseline covering Compose v2, legacy
    Compose, direct Engine, API/architecture rejection, verified offline
    archives, occupied ports, existing/active NCT instances, data-volume
    retention, and promotion receipt identity. Emit a timestamped report and
    optionally include the real host/image `--check-only` result.
  - [x] Add Docker bridge overlap cases for host LAN/VPN routes and retained
    Saved Networks, with a Test warning and a Range/Mission hard stop.
  - [x] Convert the previously successful recurring Range VM recovery into a
    sanitized API 1.39 fixture and an explicit Range-only compatibility path.
    Bypass incompatible Compose, probe Python 3.12 threading, scope the seccomp
    workaround to the analyzer only when proven necessary, force the stable
    asyncio/h11 transport, and prevent Mission promotion of the workaround.
  - [ ] Capture reports on representative older Range hosts before closing the
    matrix.
- [ ] Make the launcher idempotent: identify an existing NCT container, image,
  persistent data volume, configured ports, and running version before making
  changes. Distinguish an upgrade from a new installation, preserve evidence
  and databases, run migration checks, keep the previous container/image as a
  rollback target, and avoid creating duplicate active instances.
  - [x] Treat an already-running healthy direct deployment with the exact image
    ID, bind address, port, and data volume as already current without taking a
    backup or replacing its container.
- [ ] Detect host-port conflicts before startup, including conflicts caused by
  an older NCT instance versus an unrelated application. Reuse the existing NCT
  ports during an upgrade when safe; otherwise choose or request available HTTP,
  HTTPS, and application ports without stopping or reconfiguring unrelated
  services. Test and Range modes may retain an approved alternate port; Mission
  mode must preserve its declared stable URL or stop for an explicit operator
  decision. Save the selected ports so restarts use the same addresses.
  - [x] Detect other Docker publishers plus host listeners reported by `ss` or
    `netstat`, reuse a recognized existing NCT binding, and atomically retain
    successful Test/Range port selections for the next launcher run.
- [x] Make access mode explicit before deployment: **Local only** binds to
  loopback, while **LAN accessible** binds only to the operator-selected host
  interface or approved addresses. Never advertise a LAN URL when Docker is
  listening only on `127.0.0.1`, and never expose NCT on every interface merely
  because a port is available.
- [ ] Include a firewall preflight for the selected address and port. On Windows,
  distinguish Domain, Private, and Public profiles; detect an existing matching
  rule; and explain why traffic is blocked. Offer to create a narrowly named NCT
  inbound rule only with explicit operator approval and required elevation,
  defaulting to Domain/Private and approved source subnets rather than Public or
  Any. Record rules created by NCT and remove or restore them during rollback.
  - [x] On Linux Range hosts, distinguish active firewalld/UFW from installed
    but inactive or unmanaged state, detect and reuse a matching rule, require
    an approved source CIDR for changes, verify a newly created rule, and remove
    only the NCT-created rule during rollback. Windows profile-aware handling
    remains open.
- [ ] Validate the complete HTTPS path, not just the container port: reverse
  proxy health, certificate/key availability, certificate expiration and host/IP
  names, system time, and client trust requirements. Connected and air-gapped
  deployments must each have a documented certificate path, and failed TLS
  validation must not be reported as a successful LAN deployment.
- [ ] Check that Docker is using Linux containers on a supported CPU architecture
  and that virtualization/WSL prerequisites, daemon context, disk space, memory,
  persistent-volume permissions, and host-path sharing are usable before pulling,
  importing, or replacing an image.
- [ ] Detect Docker bridge-subnet overlap with the mission LAN, VPN, and Saved
  Networks before creating the deployment network. Choose a non-conflicting
  private bridge range and verify container DNS, gateway reachability, and the
  operator-selected host interface without modifying the host's routes or VPN.
  - [x] Inventory existing Docker CIDRs, non-Docker host IPv4 routes, and active
    Saved Networks before deployment; warn in Test and stop Range/Mission when
    any retained scope overlaps.
- [ ] Verify NCT's required container capabilities and runtime behavior,
  including `NET_RAW`, Nmap, FPING, tcpdump, SSH, the accountability capture
  interface, outbound target reachability, and the host IP that devices will
  actually observe. A web health check alone is not sufficient proof that scan
  and capture workflows can operate.
  - [x] Before reporting success, verify Nmap, FPING, tcpdump, SSH,
    packet-capture interface enumeration, the `NET_RAW` grant, and raw-socket
    creation inside the deployed application container.
- [ ] Refuse an upgrade while a scan, scheduled batch, device collection,
  database update, or schema migration is active unless the operator explicitly
  stops or defers it. Use a deployment lock so two launcher instances cannot
  change containers or ports concurrently.
- [ ] Validate free space and create a restorable data/database backup before a
  schema-changing upgrade. Check forward and rollback schema compatibility,
  preserve file ownership and permissions, and never treat an older image as a
  valid rollback target when it cannot safely read the upgraded data.
- [ ] Handle cancellation, terminal closure, reboot, or power loss at every
  transition. Use staged files and atomic state changes, label temporary and
  rollback resources, resume or clean up an incomplete attempt on the next run,
  and leave the last known-good NCT instance available whenever possible.
- [ ] Account for connected-environment DNS, proxy, and `NO_PROXY` settings while
  keeping air-gapped mode free of mandatory network calls. Verify downloaded or
  imported checksums and available disk space before unpacking large images or
  offline SearchSploit data.
- [ ] After deployment, test local access and, when LAN mode was selected, test
  the bound LAN address separately. Recheck after a container restart, report
  whether automatic restart is enabled, and provide a diagnostic summary when
  Docker, firewall, TLS, routing, or application readiness fails.
- [x] Support connected and air-gapped deployment packages. Use a validated
  local NCT image/archive when supplied, pull only when permitted and necessary,
  and verify the image version and integrity before the final swap.
- [x] Perform the container swap only after preflight succeeds, retain the
  existing data volume, wait for the NCT health endpoint, verify the reported
  build/version, and automatically restore the prior known-good container when
  startup or migration validation fails.
- [ ] Discover the actual bound host address and selected HTTPS port after a
  successful health check. Print a copyable final message such as
  `NCT is available at https://x.x.x.x:443`; when several addresses are valid,
  clearly distinguish local-only and LAN-accessible URLs rather than guessing.
- [x] Write a concise deployment log containing the preflight decisions,
  versions, selected ports, upgrade/rollback outcome, and final URL without
  recording credentials or sensitive application evidence.
- [x] Show a concise, terminal-safe NCT success summary only after the deployed
  health check passes, followed by the verified access URL and build details.

```text
NCT - Network Characterization Tool
Deployment verified.
Available at https://x.x.x.x:443
```

### Future extension — Analyst Identity Overrides

- [x] Allow an analyst to append or correct a host operating system when it is
  known from trusted local knowledge.
- [x] Preserve the scanner-detected OS beside the analyst value instead of
  overwriting evidence.
- [x] Record who made the change, when it changed, and the reason, and flag a
  later scan when its fingerprint disagrees with the analyst override.

### Future extension — Evidence-Based OS Inference

- [x] Infer possible Windows, Linux, network-appliance, and other operating
  system families from service fingerprints, banners, protocols, and retained
  device evidence when an authoritative OS identification is unavailable.
- [x] Mark inferred operating systems with distinct text styling, an explicit
  `inferred` label, confidence, and the evidence that contributed to the result.
- [x] Keep Nmap-detected operating systems authoritative; inferred values never
  silently overwrite direct scanner evidence.
- [x] When analyst identity overrides are implemented, keep analyst-confirmed
  operating systems authoritative over inferred values as well.
- [x] Let analysts confirm, dismiss, or investigate an inference while retaining
  its original evidence and audit history.

### Future foundation — Multi-Analyst Workspaces — In progress

- [x] Add authenticated analyst identities and role-based permissions for shared
  collection, safety, evidence, and administrative actions.
  - [x] Add opt-in local analyst authentication with PBKDF2 password hashes,
    expiring HttpOnly sessions, same-origin mutation checks, fail-closed first
    startup, and Admin / Analyst / Viewer enforcement. Keep authentication
    disabled by default while this remains a single-user Test build.
  - [x] Bind authenticated OS corrections and inference reviews to the signed-in
    server session instead of trusting a client-supplied analyst label.
  - [x] Show the signed-in identity and role on every primary page, provide
    sign-out, and give Administrators a focused account creation/listing screen.
  - [x] Bind authenticated scan, profile, schedule, safety, Saved Network, and
    device-collection actor fields to the server session while preserving the
    existing typed-operator workflow when authentication is disabled.
  - [x] Add Administrator account enable/disable and password reset with session
    revocation, last-active-Administrator protection, and visible account audit
    history.
  - [x] Add deployment-aware first-run Administrator creation with no fixed
    credentials, one-time read-only secret mounting and removal, existing-account
    preservation, and an admin-only host recovery path with backup and session
    revocation.
- [x] Give each analyst a persistent personal workspace for saved map layouts,
  filters, investigation notes, scan drafts, and interface preferences.
  - [x] Move named Map layouts to owner-scoped server storage when authentication
    is enabled, while retaining browser-local layouts in disabled Test mode.
    Reject stale replacements and prevent one analyst from deleting another's
    personal layout.
  - [x] Store one default Map layout preference per analyst, permit either a
    personal or currently shared layout, and expose it as a hollow/filled star.
  - [x] Autosave one owner-scoped Nmap builder draft per analyst, including the
    selected interface, scope, profile, timeout, and scan options. Reject stale
    browser writes instead of silently replacing a newer draft.
  - [x] Preserve each analyst's Hunt and Analyze filters, collapsible-card state,
    natural IP/hostname sorting, and paginated row preference on
    the server. Keep the working view isolated by account and reject stale writes.
  - [x] Add private named Hunt and Analyze filter presets that analysts can load,
    update, and delete without affecting another operator's view.
- [ ] Add optional per-analyst themes for visual individuality. Themes must remain
  presentation-only and must not change evidence meaning, shared data, exports,
  or the visibility of warnings and status indicators.
- [ ] Keep shared evidence authoritative while requiring an explicit publish or
  share action to move personal layouts and investigations into a team workspace.
  - [x] Allow only an Administrator to deliberately publish or unpublish a
    versioned personal Map layout; other analysts can load shared layouts but do
    not overwrite the owner's copy.
  - [x] Add a CherryTree-style investigation notebook with personal notes on the
    left, page-specific shared notes on the right, nested folders, retained page
    context, version-conflict protection, owner-controlled branch sharing, and
    portable Markdown export.
- [x] Add version checks, conflict handling, scan ownership and queuing, live
  status updates, and an audit trail for every shared change.
  - [x] Replace concurrent-scan rejection with a persistent first-in/first-out
    analyzer queue. Show the active owner and waiting positions, automatically
    dispatch the next run, preserve unstarted manual requests across restart,
    let owners cancel their runs, and let Administrators reassign queued work.
  - [x] Retain and display queued, started, reassigned, cancellation, fallback,
    interruption, and terminal events with the responsible server identity.

### Future major capability — Reachability Analysis

- [ ] Evaluate source, destination, and service using open ports, routes,
  interfaces, firewall/ACL policy, NAT, Saved Networks, and device identity.
  - [x] Add the first read-only Reach page and API using the current
    network-wide host/service inventory, Saved Networks, newest per-device
    collections, retained routes, and narrowly supported explicit ACL evidence.
  - [x] Build the likely path only from source-attached router/firewall evidence,
    show that path visually, and exclude ordinary switch management default
    routes unless Layer-3 forwarding is explicitly established.
  - [x] Select the newest completed or uploaded collection per device for Reach;
    failed newer attempts no longer displace the last usable retained evidence.
  - [x] Parse retained UniFi `iptables-save` filter and NAT tables by table,
    chain, rule order, action, protocol, and basic address/port selectors instead
    of discarding bare saved-rule lines.
  - [x] Collect and retain UniFi `ipset` definitions for future address-group
    resolution. Existing collections remain useful but require a new pull to add
    object membership that was not captured previously.
  - [x] Parse complete retained UniFi IP-set definitions and memberships into
    compact policy objects, report the full evidence count beside a bounded UI
    preview, and resolve IP/network/port sets while walking ordered `FORWARD` and
    user chains. Stop at Unknown for unsupported DPI, GeoIP, missing membership,
    or truncated policy evidence rather than inferring a verdict.
    - [x] Match host and subnet Reach inputs against retained network objects,
      select a usable WAN route when metadata-only defaults have no interface,
      and carry drop-or-continue prechecks forward when every possible branch
      converges on the same explicit deny. Unsupported criteria remain Unknown
      whenever they could change the final verdict.
  - [x] Walk retained UniFi NAT `PREROUTING` and nested chains before firewall
    evaluation. Resolve supported DNAT address/port changes and local redirects,
    show the original and effective destination in Reach, and use the translated
    target for route, service, and ordered `FORWARD` evidence.
  - [x] Add attachment-aware ordered policy evaluation for Cisco IOS/IOS-XE/ASA
    ACLs, VyOS interface policies, active pfSense `pfctl` rules, and Juniper
    zone policies with directly resolvable addresses and built-in applications.
    A rule that is merely present but not demonstrably applied is not treated as
    an allow or deny decision.
  - [x] Expand vendor-aware ordered policy, object, zone, NAT, and stateful-flow
    evaluation before treating complex configurations as allow or deny evidence.
    - [x] Resolve static Cisco address and service objects/groups, VyOS address,
      network, port, and interface groups, pfSense static and nested aliases,
      and Juniper zone address books/sets and custom applications/application
      sets. Expose the retained object inventory in Device views and keep
      missing, incomplete, cyclic, or unsupported definitions at Unknown.
    - [x] Walk supported Linux/UniFi `POSTROUTING` chains and nested chains for
      exact source NAT and masquerade. Show the original and effective source,
      outgoing interface, retained rule, and chain path in Reach; keep address
      ranges and conflicting multi-device translations at Unknown.
    - [x] Resolve dynamic and DNS-backed objects, vendor policy-based NAT,
      established-flow state, and multi-device translation paths; keep
      unsupported criteria at Unknown.
      - [x] Let analysts evaluate either a new connection or an
        established/related flow. Match retained iptables and VyOS state rules
        against the selected state, include that basis in the evidence, and
        warn that configuration evidence does not prove a live state-table
        entry exists.
      - [x] Capture pfSense runtime alias tables and use their retained IPv4
        membership to resolve DNS-backed aliases at the collection timestamp.
        Identify dynamic Cisco, VyOS, pfSense, and Juniper objects in the
        object inventory, and keep them unresolved when no retained runtime
        membership is available.
      - [x] Normalize and evaluate exact Cisco static and object NAT, VyOS
        source/destination NAT, and retained active pfSense `rdr`/NAT rules.
        Keep policy/route-map NAT and unresolved translations at Unknown.
      - [x] Carry unique source and destination translations sequentially
        across multiple retained devices, preserve every device and evidence
        step in the Reach path, and stop at ambiguous or looping paths.
- [x] Support host, subnet, WAN/Internet, external IP, and external CIDR sources.
  - [x] Accept IPv4 hosts, IPv4 CIDRs, and WAN/Internet as either endpoint.
  - [x] Let an analyst explicitly designate an exact source IPv4 host or CIDR as
    external. Preserve the address for rule matching while binding the path to
    the retained WAN-facing interface; never guess external status from an
    unsaved address alone.
- [ ] Report Local, Routed, Expected Allowed, Expected Blocked, Unknown, and Not
  Exposed without claiming unsupported certainty.
  - [x] Report Local, Routed, exact-policy Expected Allowed/Blocked, and Unknown
    with confidence, evidence, and prominent caveats.
  - [x] Report Not Exposed only when retained scan coverage proves that the
    requested service was actually assessed and not exposed.
  - [x] Correlate Hunt SearchSploit candidates with retained Reach evidence.
    Show and filter conservative external, internal-only, local-segment,
    externally-blocked, not-exposed, and unknown classifications per matched
    service while keeping exploitability explicitly unconfirmed.
- [x] Group on-demand source-exposure reports by Internet and Saved Network,
  deduplicate Hunt dataset rows into unique observed services, preserve complete
  route, ordered-policy, and NAT objects plus rendered evidence, correlate local
  SearchSploit candidates, filter by source/outcome/candidate presence, and
  export the complete evidence report as JSON without generating network traffic.
- [x] Send individual Reach evaluations and source-exposure report paths to a
  temporary Map investigation overlay that highlights mapped endpoints and
  retained transit evidence, dims unrelated topology, fits the focused path,
  preserves saved layouts, and provides an explicit exit back to the normal map.

### Device-role and switch evidence follow-up

- [x] Allow Router and Firewall to be selected together in one device collection,
  merge their read-only templates without duplicate commands, retain both roles,
  and label the analyzed device and map object as `Router + Firewall` when the
  collected evidence supports both functions.
- [x] Run UniFi command sets through the guarded per-command wrapper so one
  unavailable command no longer discards usable output from the rest of a pull.
- [x] Add guarded UniFi switch fallbacks for platform, switch-control, forwarding,
  VLAN, and spanning-tree evidence on firmware where standard Linux utilities are
  absent.
- [x] Parse retained UniFi `swctrl` physical-port state and learned MAC/VLAN
  tables into structured switch ports, forwarding state, VLAN observations, and
  endpoint-to-port evidence.
- [x] Raise the bounded streamed configuration retention limit to 5 MB, report
  truncation explicitly, and collect firewall tables before large address sets
  so missing late evidence cannot masquerade as an empty policy.
- [x] Mark failed device pulls as partial evidence in Device Analysis and warn
  separately when a switch pull contains no structured port, learned-MAC,
  aggregation, or spanning-tree records.
- [x] Deduplicate repeated config-derived Saved Network suggestions by current
  device/interface path while retaining the newest supporting source.
- [ ] Rerun the revised profile against representative UniFi switch models and add
  parser fixtures for their actual retained `mca-cli-op`, `swctrl`, and `stp`
  formats. Do not infer missing Layer-2 relationships from the older partial pulls.

### Future extension — Hardening Validation

- [x] Simulate proposed firewall, ACL, or routing controls without changing
  production devices.
  - [x] Add a read-only exact-flow policy projection for retained routers and
    firewalls. Compare the current outcome with a proposed permit or deny on a
    selected device, show source attachment and address-pair scope, preserve
    evidence and caveats, and export the complete comparison as JSON.
  - [x] Add proposed route insertion, removal, and metric/preference changes.
    - [x] Add read-only retained-device route insertion/removal comparison with
      exact destination coverage, retained-interface validation, broader-route
      fallback visibility, evidence/caveats, and JSON export.
    - [x] Add metric/preference changes and vendor-neutral path-choice modeling
      for equally specific routes with complete comparable retained values.
- [x] Compare current and proposed paths, retained alternate routes, and bounded
  collateral scope. State when only one representative flow was evaluated and
  never extrapolate a route prefix into untested service/policy conclusions.
- [x] Export evidence-backed hardening reports and open current-to-projected
  results as temporary Map focus comparisons. Keep the overlay browser-local
  and leave saved map layouts unchanged.

### End-of-roadmap fringe-vendor validation

- [ ] Return to Juniper only after the primary mission vendor work and all other
  planned capabilities are complete. Validate zone-default policy, collection,
  parsing, and Reach behavior against representative retained Juniper evidence;
  do not let this fringe case block UniFi, Cisco, VyOS, or pfSense delivery.

## Release discipline

Every release should be built and tested locally, checked against existing and
new data, packaged with offline dependencies where required, deployed by a short
final swap, smoke-tested, and kept independently rollbackable. Scan-engine,
device-analysis, map, and reachability redesigns must remain separate releases.

Local completion means development-ready only. Range-ready requires the pinned
artifact to pass the documented compatibility matrix on representative older
hosts and real network equipment, with limitations and workarounds recorded.
Mission-ready requires that same artifact to pass the modern server baseline,
security, authentication, TLS, backup/restore, monitoring, restart, and rollback
gates; no successful local or range run may waive those controls.

Regression checks include scan creation, Saved Networks, manual targets,
No-Strike behavior, FPING, TCP, UDP, storage, history, analysis, deletion, device
collection/history, migration, and map loading.
