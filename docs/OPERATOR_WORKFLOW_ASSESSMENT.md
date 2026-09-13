# NCT Operator Workflow Assessment

Assessment date: 2026-09-13

## Scope and method

This review followed the normal authenticated operator path through **Device →
Nmap → Analyze → Hunt → Reach → Map** using retained test evidence. It did not
start a scan, contact a network device, change evidence, or inspect mission
data. The live pages and their source were reviewed together so delayed data
loading, collapsed states, and page-to-page handoffs were included.

Recommendations in this document began as observations only. The approved
mechanical consistency and low-risk handoff rollout is recorded below; the
larger Analyze workspace redesign remains a separate decision.

## Current flow

| Page | Primary operator job | Useful entry | Current exit / handoff |
| --- | --- | --- | --- |
| Device | Build and run a read-only configuration collection; import an existing result; promote identified networks to Saved Networks | Default landing page | Successful collections can open Network Device Analysis or continue to Nmap; accepted Saved Networks offer a Nmap handoff |
| Nmap | Manage authorized scope and exclusions, build or schedule a scan, monitor the analyzer, and reopen retained scans | Saved Network created from Device or an existing Saved Network | Per-run Open, Analyze, Hunt, and Compare actions |
| Analyze | Inspect one Nmap result, compare two scans, or import XML; separately analyze retained device collections | Per-run Analyze action from Nmap | “Hunt this scan” for an opened Nmap run |
| Hunt | Correlate newest evidence across network scopes, hosts, devices, datasets, and SearchSploit candidates | Network-wide view by default or a run-specific link | Host, service, and SearchSploit rows can open Reach with destination/protocol/port loaded while leaving Source unchanged |
| Reach | Evaluate a source, destination, protocol, port, and flow state using retained evidence; model policy or route changes | Manual query entry | “Show on Map” after a completed result or projection |
| Map | Review and arrange the final evidence-backed topology and focused Reach paths | Normal Map navigation or Reach focus | Final visualization; evidence links return to retained files |

## Workflow findings to review before changing

### High-value flow improvements

1. **The main Analyze button opens an empty work surface even when retained
   scans exist.** The page exposes comparison and XML import, but opening a
   normal retained result requires returning to Nmap and selecting Analyze on a
   run. A better landing behavior would offer the newest completed scan or a
   short retained-result picker without recreating the full Scan History table.

2. **Hunt cannot hand a selected finding to Reach.** An analyst who identifies
   a host, service, or candidate in Hunt must manually re-enter its address,
   protocol, and port in Reach. A contextual “Evaluate in Reach” action should
   carry only those selected values and leave the operator in control of the
   source and external/internal context.

3. **Device has no contextual completion handoff to Nmap.** The navigation is
   always available, but a successfully retained collection or newly accepted
   Saved Network could offer a clear “Continue to Nmap” action. It should not
   start a scan or silently select an unapproved scope.

### Redundancy or avoidable backtracking

1. **Device collection review and Network Device Analysis overlap.** Device
   currently supports deep structured review inside collection history, while
   Analyze has a separate device-analysis view with comparisons and interpreted
   findings. The cleaner boundary is: Device for collection status, commands,
   raw evidence, and reuse; Analyze for interpreted structures and comparison.
   Before removing anything, confirm that every current Device detail has an
   equivalent Analyze destination and add an explicit “Analyze collection”
   link.

2. **Hunt always shows both Refresh network view and Reset to network-wide
   view.** Reset is useful only when a run-specific or comparison context is
   active. In the default network-wide state it is visually redundant and
   should be hidden or disabled with an explanatory state label.

3. **Nmap combines the core scan builder with profile lifecycle, analyzer
   queue, scheduling, and long-term history.** All are valid functions, but the
   first-run path is longer than necessary. A future workflow revision should
   preserve Build Scan as the dominant section and place profile maintenance
   and scheduling in clearly named advanced drawers. Queue and Current Run
   should remain visible when work exists.

4. **The Map toolbar includes stored-file browsing alongside map navigation and
   layout controls.** File access is useful evidence provenance, but it is not
   part of the frequent map-editing path. Consider a collapsed Evidence Files
   drawer so search, view, layout, and edit controls stay visually distinct.

### Consistency gaps

- Expandable sections use four different visual languages: no visible marker
  in Device history, plus/minus in Nmap management and history, a right-side
  arrow in Analyze comparison, and left-side chevrons elsewhere.
- Reach does not currently show the personal/shared investigation-note rails
  used on Device, Nmap, Analyze, Hunt, and Map. This is documented for a later
  workflow decision because adding a page-specific shared workspace is more
  than a mechanical styling fix.
- Device Analysis is a child of Analyze but its shared notes are labeled for
  Device. Decide whether shared notes follow the evidence type or the current
  page before changing that scope.
- Asynchronous evidence pages briefly show their import or empty state before
  retained results arrive. Loading text is present on Hunt and Map, but Analyze
  can look complete before its requested run renders. A later workflow release
  should use one explicit loading state on every evidence page.

## Mechanical consistency rollout

The following changes are safe to apply together without changing evidence,
defaults, navigation, or operator decisions:

- Use one accent right-facing chevron for a collapsed disclosure and rotate it
  downward when open.
- Keep the chevron on the left edge of the disclosure label on Device, Nmap,
  Analyze, Hunt, Network Device Analysis, Reach, and Map.
- Preserve every existing default open/closed state, count, summary, and
  keyboard-accessible native `details` behavior.
- Add a UI contract test so new top-level disclosures cannot silently return to
  plus/minus, an unmarked header, or a conflicting right-side indicator.

## Decisions applied after review

- Mandatory reason/authorization text was removed from the pre-run workflow.
  Nmap records a neutral system context without asking the operator, Device
  accepts an optional collection note, and a note remains required only at an
  explicit fallback authorization decision.
- Manual creator/operator identity entry was removed from scan, Saved Network,
  No-Strike, fallback, and Device forms. Authenticated actions use the signed-in
  analyst automatically; historical attribution remains available for audit.
- Reach now participates in personal and page-specific shared notes. Its source
  links open the relevant retained Analyze section expanded in a new tab so the
  active Reach/Hunt context is not discarded.
- Hunt now hides its network-wide reset action until the operator enters a
  focused scan or comparison context.
- Nmap keeps scan construction, queue state, and current-run status prominent
  while profile lifecycle controls and scheduling are collapsed as advanced
  operations.
- Map keeps stored evidence available in a collapsed Evidence Files drawer
  instead of mixing file browsing with the frequent map controls.
- Hunt now opens Reach in a new tab with the selected destination and, when
  available, protocol and port. Source and external/internal context remain
  deliberate analyst choices, and the active Hunt filters remain intact.
- Device now ends successful collections with **Analyze collection** and
  **Continue to Nmap** actions. Accepted config-derived Saved Networks also
  expose the Nmap handoff without starting a scan or selecting scope.
- Device history is now limited to collection status, commands, raw/saved
  files, reuse, and deletion. Interpreted routes, interfaces, neighbor, VLAN,
  switching, policy, NAT, and comparison views remain in Network Device
  Analysis.
- Analyze, Network Device Analysis, Hunt, Reach, and Map now show explicit
  retained-evidence loading states instead of temporarily resembling empty
  completed views. Search inputs use one consistent clear control, including
  filters rendered after a retained result loads.
- Export is available throughout the workflow: retained collection files on
  Device, artifacts on Nmap, host/port CSV on Analyze, structured JSON on
  Network Device Analysis, filtered CSV plus full JSON on Hunt, result and
  simulation JSON on Reach, and both portable SVG and topology/layout JSON on
  Map. These browser-local downloads do not send network traffic or change
  evidence.

## Remaining workflow release candidate

The low-risk Hunt → Reach transfer, Device completion handoffs, Device versus
Device Analysis boundary, loading convention, and search clear controls are
complete. Analyze now opens on the newest retained evidence from every network
scope plus current device configuration evidence, consolidates correlated
identity, services, capability datasets, provenance, and collection time into
one paginated inventory, and includes a compact specific-result picker without
recreating Nmap Scan History. The inventory now expands in place for capability
basis, source provenance, coverage, and observation history; a bulk view
compares the newest two complete Nmap observations per exact scope; and a
separate retained routes/policy drawer keeps possible forwarding distinct from
explicit authorization evidence. Analyze also recalculates uncommon ports by
OS peer group across the current network or the operator-selected subnet.
Remaining Analyze work is device-collection
bulk change comparison and safely attaching retained SearchSploit enrichment.

A separate Export Studio candidate is now recorded in the roadmap. It keeps
one-click downloads for routine use, while a preview-first customized path can
choose complete versus filtered data, format, columns, ordering, grouping,
section layout, and report notes with provenance carried into every output.
