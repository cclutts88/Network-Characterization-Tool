# NCT — Network Correlation & Triage
## Foundational Redesign and Governing Roadmap

**Roadmap status:** Approved governing direction  
**Working product expansion:** **NCT = Network Correlation & Triage**  
**Foundation branch:** `foundation/evidence-engine-v2`  
**Stable baseline:** `main` remains the known-working baseline until phased acceptance gates are met.

> This roadmap governs future NCT development. Completed legacy release history is preserved in
> [docs/ROADMAP_LEGACY_PRE_EVIDENCE_ENGINE.md](docs/ROADMAP_LEGACY_PRE_EVIDENCE_ENGINE.md).

---

# 0. Roadmap Governance — Project Source of Truth

`ROADMAP.md` is the governing project-control document for NCT.

All future development on this redesign must keep this file current.

## 0.1 Required updates

Update the roadmap whenever any of the following occurs:

- A roadmap step is started.
- A roadmap step is completed.
- A planned capability changes materially.
- Implementation reveals a new dependency or prerequisite.
- A feature is deferred, split, absorbed, or reordered.
- The implementation deviates from the planned architecture.
- A previously unknown limitation is discovered.
- A design decision materially changes storage, workflow, evidence meaning,
  permissions, deployment, or analyst experience.

## 0.2 Status notation

Use these status markers consistently:

- `[ ]` — Planned
- `[~]` — In progress
- `[x]` — Complete
- `[!]` — Blocked / requires decision
- `[-]` — Deferred / intentionally removed from the current phase

Completed work should not be removed from the roadmap simply because it shipped.

## 0.3 Deviation log

Any meaningful deviation must be recorded in the **Architecture / Roadmap Deviation
Log** with:

- Date
- Phase / capability
- Planned approach
- Implemented or revised approach
- Reason
- Expected impact
- Follow-up, if any

A deviation is not automatically a problem. The purpose of the log is to preserve
engineering rationale so future work does not accidentally undo intentional
decisions.

## 0.4 Completion discipline

A roadmap item should only be marked complete when:

1. The implementation exists on the foundation branch.
2. Relevant automated tests pass.
3. Existing behavior has not regressed within the tested scope.
4. The roadmap is updated to reflect what actually shipped.
5. Any deviation from the original plan has been documented.

## 0.5 Architecture / Roadmap Deviation Log

## Scheduled scan incident repair — started 2026-10-23

- [x] Reproduce and repair the Teams-reported startup failure converting older
  schedules, including native durable occurrences, repeated restarts and mixed
  legacy/native data. Preserve frozen plans, completed chunks and evidence; never
  resume uncertain network contact automatically.
  Seven new regressions reproduced the fault before the fix; 34 focused Docker
  checks then passed, with independent reviewer CLEAR. The controller's stopped
  phase4-r5 container log confirms the same migration stack; no live repair made.
- [x] Repair independently reproduced queue starvation using isolated
  regressions and additional controller evidence where needed. Seven isolated
  regressions reproduced head-of-queue starvation and unhandled changed-scope
  errors. Dispatch now considers later eligible schedules while retaining blockers
  and enforcing one successful dispatch per check. Real changed-scope validation
  and repeated checks preserve the review barrier; independent reviewer CLEAR,
  51 focused Docker tests passed. This is not proof of the controller queue cause.
- [x] Repair new scheduled scan Saved Network selection/name snapshots and scope retention,
  automatic analysis without changing historical evidence or guessing scope.
  Reproduced dropped selection on scheduled chunks; atomic run admission now
  copies the reviewed schedule selection only after frozen definition validation.
  Execution targets remain bounded to the chunk. Actual contact-boundary tests
  retain scope/name and block a changed association; automatic local-processing
  regression now covers scheduled completion. Independent reviewer CLEAR. A literal
  Saved Network record rename and older missing-context records remain separate
  handoff items; no historical evidence was relabelled.
- [x] Browser verification found and repaired a separate missing automatic step: scoped
  foundation processing could finish while reusable local Nmap analysis still
  required Prepare from saved scan. Extend the existing background calculation
  worker to admit one completed, explicitly marked scan with an existing finalized
  intake receipt and one registered aggregate XML. This local-only calculation
  does not require or assign scope. Existing jobs in any state prevent automatic
  retries/recalculation. Startup and worker-exit checks recover missed admission;
  unmarked historical scans retain explicit preparation.
  **Documented deviation:** browser verification required this additional local
  base-analysis step beyond scoped foundation admission. The explicit missing-scope
  handoff correction now excludes only scope-independent base-analysis jobs from
  its existing processing-history prohibition; scoped and unknown jobs still block
  correction. This preserves the repair after automatic local preparation without
  altering either result's provenance. Independent reviewer CLEAR — DOCUMENTED
  DEVIATION; 53 focused checks passed. Combined full suite: 1,923 passed, 18 skipped,
  one existing dependency warning. Rebuilt isolated preview verified automatic saved
  analysis in History with original Saved Network/scope and no preparation click.
- [-] Troubleshooting, unfinished-work reset and fresh-install implementation handed
  to the Primary NCT Roadmap Builder at the user's explicit direction. No scripts
  implemented and no controller reset/reinstall performed. Requirements, recommended
  options and acceptance checks are in
  `docs/NCT_SCHEDULE_INCIDENT_AND_FIX_HANDOFF_2026-10-23.md` (R22–R24).
- Controller read-only inspection: 19 completed scans, one queued scheduled scan,
  a native preparing occurrence and another waiting occurrence; foreign-key check
  returns no violations. Startup's failed transaction did not leave broken database
  relationships. Existing evidence and deployment remain untouched.
- The user requested implementation stop after this incident repair and a complete
  requested-fix report for the Primary NCT Roadmap Builder. All other requests are
  recorded in that handoff, not silently accepted as completed. Development stays on the
  foundation branch; no controller repair, deployment package change, main
  promotion, Range acceptance or mission readiness is claimed.
- Final completion gate: **CLEAR — DOCUMENTED DEVIATION**. Independent reviewer
  checked the exact final diff, 24-item handoff and rebuilt preview; two restarts
  retained one completed scan, one waiting native occurrence, one base-analysis
  job and the unchanged sample XML hash. Browser opened verified saved analysis
  without preparation, with no browser error logs. Implementation stops here.

## Teams requested-fix integration — resumed 2026-10-23

- [x] **R22 diagnostic-first recovery report complete.** Add one administrator command
  that can inspect a running, stopped or restarting NCT container without opening the
  saved database for writes. Save a private report containing the exact image/build,
  container state, saved port and mount configuration, host and data-storage capacity,
  bounded recent logs, database integrity and read-only unfinished-work summaries. Do
  not include passwords, environment secret values or raw retained evidence by default.
  The command must explain where the report was saved and give next steps tied to the
  observed state. Test stopped-container data, restart loops, missing or restricted
  runtime access and both bind-folder and named-volume storage.
  **Documented safety deviation:** the initial design proposed sanitized recent-log
  excerpts. The report instead retains only bounded signal counts because arbitrary log
  text can contain unlabeled credentials that no redaction pattern can safely guarantee
  to remove. Before any report path is created, the wrapper identifies the exact
  container and proves that the requested report root does not overlap retained data.
  Preflight failures therefore print a partial result and next step to the terminal;
  once separation is proved, every complete or partial saved result contains a private
  text report, JSON companion and checksum in a new owner-only child directory. Docker
  probes and image helpers have deadlines, and all database summaries share one explicit
  read transaction so they describe a coherent saved snapshot.
  **Completion evidence (2026-10-23):** the focused diagnostic, Guide and UI suite passes
  **104 tests**; the clean full suite passes **1,950 tests with 18 skipped** and one
  dependency warning. Real isolated Docker checks covered stopped named-volume storage,
  an exact-image report, a refused retained-data overlap, forced helper timeouts, valid
  text/JSON/checksum output, private file modes, unchanged database hashes and zero
  remaining diagnostic helpers. A failed helper removal keeps the exact helper identity
  and private probe path; a final cleanup retry may remove that helper, but the recorded
  workspace remains until the administrator follows the report. The rebuilt browser
  Guide was checked with a clean console. Independent gate: **CLEAR — DOCUMENTED
  DEVIATION** for bounded log-signal summaries in place of unsafe arbitrary log excerpts
  and for terminal-only results before storage separation is proved. Novice gate:
  **CLEAR**. This is committed development work only; it does not reset unfinished work,
  change the installed Range, or claim mission readiness.
- [x] **R23 evidence-preserving reset unfinished work — completed 2026-10-23.** R22 captures
  the pre-reset state. Keep this separate from fresh installation; require a verified cold
  backup, preserve completed evidence and refuse unfamiliar work or unresolved migration.
  Add scan-work self-diagnosis that automatically detects impossible or stranded active,
  queued, and scheduled states, preserves a diagnostic record, and blocks additional scan
  dispatch while the condition is unresolved. On Active Scans, show the exact affected
  work and reasons, then offer an administrator-confirmed reset of only the proven
  unfinished records. Reconcile only strictly provable stale bookkeeping automatically;
  uncertain network contact remains interrupted for human review. Keep the host-side
  recovery path available when the application cannot start, because an in-tool control
  cannot repair an unavailable UI. Recover all eligible affected scans together: retain
  each frozen target, profile, scope, ownership, queue order, schedule occurrence, and
  completed target-batch history; queue only work that remains. Recheck current No-Strike,
  mission authorization, scope, and analyzer availability before contact. Preserve any
  possibly active attempt as Interrupted and create a separately traceable retry only
  after review rather than treating partial output as a clean completion. The preview must
  identify every salvageable and excluded item with its reason so operators do not have
  to rebuild a large queue manually.
  **First scan/schedule recovery slice implemented and independently cleared on 2026-10-23.** Active
  Scans now provides a read-only queue self-check for every signed-in operator. Startup
  records a durable pause when it finds stranded or contradictory scan/schedule work;
  automatic scan dispatch and automatic Arkime pull contact remain paused until review.
  The host command stops the exact container, refuses shared data, creates and
  independently restores and verifies a complete cold backup, recalculates the exact
  plan from that restored copy, and applies only the confirmed plan to the original
  data. It keeps untouched queued scans in order, removes only proven stale pre-contact
  ownership, interrupts uncertain-contact scans, preserves completed target batches and
  evidence, holds affected schedules for review, and releases only the primary scan
  capacity lease. NCT restarts paused; an administrator must separately type the exact
  resume confirmation before preserved waiting scans can again compete for capacity and
  repeat the current scope, Mission Environment and No-Strike checks.
  **Documented deviation:** this first slice deliberately covers Nmap scans and durable
  scheduled occurrences only. It pauses automatic Arkime pull contact during the scan
  recovery boundary but does not rewrite Arkime pull, device-contact, pipeline-job,
  storage-maintenance or other work records. Those work types require their own proven
  state contracts before R23 can be marked complete. The first slice therefore remains
  `[~]`; it must not be described as a universal unfinished-work reset. Focused automated
  checks and disposable stopped-container tests pass, including a complete backup and
  restore comparison, named-volume preview, exact-plan apply, preserved evidence,
  repeated-apply refusal, shared-volume refusal and restoration of the prior running and
  restart-policy state. Review authorization is split deliberately: **Resume preserved
  scans** authorizes only Nmap queue contact, while **Resume passive pulls** separately
  authorizes automatic Arkime connector contact; failure to start either path restores
  its durable pause. The exact plan now covers the full scan manifest, complete affected
  schedule and immutable definition records, frozen occurrence and target records, every
  active-lease ownership field, and every unfinished sibling in an affected occurrence.
  A schedule or lease change after preview invalidates the reviewed digest. Apply records
  the original and resulting database rows with the complete
  plan and receipt in the existing scan audit ledger inside the same transaction, so a
  later portable-receipt write failure remains diagnosable. The host helper checks every
  mount destination for named-volume or parent/child bind overlap, proves backup-output
  separation before creating it, isolates helpers from the network with a read-only root
  and dropped capabilities, bounds Docker calls, and requires a successful inventory to
  prove the helper is absent before restarting NCT. If absence cannot be proved, NCT stays
  stopped with automatic restart disabled and reports the manual recovery boundary. A
  final full Docker regression run passed **1,997 tests with 18 environment-dependent
  skips**. Recovery-focused, documentation and UI coverage passed **137 tests** after the
  cleanup and approval-fingerprint corrections. Disposable stopped-container tests passed
  for named-volume preview, exact-plan apply, transaction receipt, repeat-apply refusal,
  same-volume alternate-destination refusal, verified helper absence, and exact
  `on-failure:4` runtime restoration. The Independent Reviewer / Quality-Gate returned
  **CLEAR — DOCUMENTED DEVIATION** after **58 independent checks**. The novice operator
  returned **CLEAR** at normal and narrow widths with no visible or console errors.
  **Remaining-work completion independently cleared 2026-10-23.**
  The versioned recovery plan now includes Arkime pulls, device-contact attempts and
  publication state, local pipeline attempts and pending intake, device VLAN intake,
  storage maintenance, shared leases and the retained storage-status record. It preserves
  queued work and completed evidence, interrupts a running Arkime pull without changing
  its saved time window, closes only provably pre-contact device work, holds possibly
  contacted or published device work for explicit review, and replaces an interrupted
  local attempt with exactly one traceable queued retry. A former storage owner becomes
  a safety stop; storage can resume only after a new read-only retained-evidence analysis
  reports no issue or unfinished collection. Unresolved exact-content compaction,
  migration, unknown leases and mismatched ownership still refuse recovery. Startup now
  creates and honors one durable five-category hold before it admits any network contact,
  local processing or storage maintenance. Administrators resume Nmap, Arkime, device
  contact, local processing and storage maintenance separately, and a failed local-worker
  restart restores its hold. The Active Scans panel and Operator Guide name every category,
  preserve review-required device and storage items on screen, and explain the complete
  cold backup and separate authorization boundary.
  **Documented deviation:** all recovery changes and the exact before/after rows are kept
  transactionally in the existing append-only scan audit ledger instead of introducing a
  second recovery-only database ledger. A portable receipt is also written after commit;
  failure of that copy cannot erase the transactional receipt or silently resume work.
  This reuses an already protected audit path while retaining a distinct v2 contract and
  recovery identifier. The final focused recovery, storage, connector, worker,
  host-script, documentation and UI suite passed **264 tests**; the complete Docker
  regression suite passed **2,012 tests with 18 environment-dependent skips**. A
  disposable Docker image starts with the recovered volume, reports all five holds,
  renders the recovery panel at normal and narrow widths without horizontal overflow,
  and has a clean browser console. Review identified and the implementation corrected
  two material safety boundaries before completion: unreadable, unknown or malformed
  pause contracts now keep every work category paused, and a rejected storage-resume
  request cannot release or alter the retained lease. The final Independent Reviewer /
  Quality-Gate returned **CLEAR — DOCUMENTED DEVIATION** after **39 independent recovery
  and ownership checks**. The novice operator returned **NOVICE CLEAR** after confirming
  the five separate resume decisions, review-required work, host command containment and
  normal/narrow-screen guidance. R23 is committed development readiness on the foundation
  branch only; it is not Range-ready, mission-ready or available on `main`.
- [x] **Map-to-scan preparation complete on the foundation branch — started and
  completed 2026-10-23.** A selected retained subnet or network device with no Nmap
  observation now offers a bounded Map-details action that prepares the existing Nmap
  scan builder for analyst review. The Map never starts or queues a scan. It uses only an
  explicit IPv4 address or exact CIDR, requires an address choice for multi-address
  devices, and excludes synthetic groups and presentation-only objects. An exact active
  Saved Network is carried only when its retained ID and CIDR still match; stale,
  archived, mismatched and device targets remain visibly manual and unscoped. Mission
  Environment, Global and scan-specific No-Strike, authorization, interface, profile,
  recovery-pause and server-side pre-contact checks remain authoritative. Map placement,
  labels and address containment do not grant permission or assign a Network Scope, and
  the existing unsaved-layout navigation warning remains in force. The Operator Guide and
  built-in How NCT Works guide explain the boundary. Independent architecture gate:
  **CLEAR — DOCUMENTED DEVIATION** for preparing the existing builder rather than
  executing network contact from Map. Verification: the complete Docker suite passed
  **2,014 tests with 19 expected skips**; focused Map, scan-builder and UI checks passed
  **111 tests with 1 expected skip**; both executable browser regressions passed on the
  host; and isolated browser checks confirmed desktop and 900-pixel layouts, readable
  controls, exact and stale handoff behavior, useful contextual guidance, a clean console
  and an unchanged empty scan queue. The novice operator returned **NOVICE CLEAR** after
  independently repeating the workflow. The final Independent Reviewer / Quality-Gate
  returned **CLEAR — DOCUMENTED DEVIATION**. This is committed and verified development
  readiness on the foundation branch only; it is not Range-ready, mission-ready or
  available on `main`.
- [x] **No-Strike broad-CIDR operator clarity absorbed into Scope & Safety Setup.** The retained safety model already
  accepts normalized IPv4 hosts and CIDR networks, including a broad exclusion such as
  `10.0.0.0/8`, for both the shared Global No-Strike list and scan/schedule additions.
  Make that supported input explicit in the one authoritative Scope & Safety Setup page
  and in the Operator Guide. Remove shared-list management from Nmap Scan Details; keep
  only optional run-specific exclusions and the pre-launch impact summary in the scan
  builder. This work now belongs to the shared collection-safety milestone below.
- [x] **Scope & Safety Setup and shared active-collection gate complete on the foundation branch.** Add the first
  Collect destination, `Scope & Safety Setup`, where an administrator selects the active
  installation Network Scope and records the reviewed Global No-Strike decision before
  NCT permits any Nmap traffic or live network-device contact. An empty shared exclusion
  list is valid only after an explicit `none currently required` decision with actor,
  reason, time, scope revision and safety revision. Read-only review, retained-file
  imports and local analysis remain available while setup is incomplete. Setup means
  `Ready for collection planning`; it never grants authorization to scan or connect.
  Enforce the gate server-side for direct API calls, immediate and queued scans,
  schedules, restart/retry dispatch, fallback paths, interactive SSH, key-based preflight
  and device execution. Revalidate immediately before contact and preserve blocked work
  without changing its target, scope or queue order. Global No-Strike also protects live
  device contact: resolve hostnames without connecting, reject unresolved or excluded
  destinations, and bind contact to the validated address. A later safety change must
  stop affected active scan or device contact when possible and retain the reason. New
  portable packages retain the reviewed setup decision; already distributed packages
  cannot receive later server changes and keep that visible limitation. Existing
  evidence is never rewritten or retroactively scoped. Independent architecture gate:
  **CLEAR — DOCUMENTED DEVIATION** from scan-only No-Strike management to a shared,
  audited active-collection prerequisite. Novice workflow gate: **CLEAR** for the first
  Collect destination, explicit empty-list review, plain readiness wording and direct
  return links from blocked collection pages.
  **Completion and deviation record (2026-10-23):** the authoritative page now appears
  first under Collect. Nmap Scan Details contains only Saved Networks and Scan Profiles;
  the scan builder retains optional one-run/one-schedule exclusions and its impact
  preview. Reviews are append-only settings records bound to the exact active scope and
  Global No-Strike revisions, avoiding a new database migration while preserving actor,
  reason and time. Manual targets and unscoped new collection plans inherit only the
  administrator-selected, currently reviewed setup scope; an explicitly differently
  scoped Saved Network is rejected. This is not the later selector-hiding single-scope
  mode and does not rewrite historical evidence. Device hostnames are resolved before
  contact, every returned IPv4 address is checked, and SSH is bound to one recorded safe
  address. A new intersecting Global No-Strike revision durably cancels waiting device
  work and requests cancellation of active work. IPv6 device contact and live updates to
  already downloaded portable packages remain outside this milestone. The clean full
  Docker suite passes **1,955 tests with 18 skipped** and one existing dependency warning.
  Focused safety, scan, schedule, device and UI checks pass, and a rebuilt isolated browser verified the
  review flow, navigation, removed duplicate panel, device return link and a clean
  console/network log. This is development-ready foundation work only; it is not on
  `main`, installed on the Range or mission-ready.
- [~] **Unified Mission Environment workflow — started 2026-10-23.** Replace the
  separate Scope & Safety destination with one top-level Mission Environment entry
  before Collect. Present the page in the operator's working order: active Network
  Scope, installation-wide Global No-Strike review, available tools and access, then
  the environment picture supported by retained evidence. Keep reviewed declarations
  separate from automatic observations so evidence never grants collection authority.
  The automatic table remains network-level: one row per scoped Saved Network or
  device-identified network, with the Saved Network name, CIDR, unique observed-host
  count, retained network-device names, Nmap/device/Arkime visibility, blind spots and
  latest retained evidence times. Individual addresses may contribute to counts but
  never become rows; addresses outside every saved or device-identified network are
  reported as omitted rather than guessed into `/32` networks. Calculation is read-only,
  bounded and makes no network contact. The current independent architecture review is
  **CLEAR — DOCUMENTED DEVIATION** from the earlier separate first-under-Collect page;
  final safety, browser and novice gates remain in progress.
  Add a separate **Special Device Roles** register immediately after the automatic
  network-level table. Keep the role-creation form separate from a sectioned comparison
  table. The table presents the role and exact scope, **Mission Partner Identified**
  addresses, declared ports/services and their retained assessment first, then any
  other same-scope **Possible Matches Shown By Evidence**, their observed ports/services
  and the exact reason each match is shown. Possible matches remain investigation leads
  and never become recommendations, Map markers or automatic role assignments. An administrator may record
  multiple IPv4 or IPv6 addresses for one role (including primary, alternate and
  backup services), and one address may hold several roles. A **Specific Special
  Identifier** option records a required operator-supplied role name for mission systems
  outside the standard DNS, directory, DHCP, gateway, time and proxy list. Creation
  may also retain known `port/protocol` pairs and mission-partner service names for
  each address. Those declared details support bounded comparison with retained Nmap
  and Arkime evidence but do not prove the role. Each address remains an
  independently versioned, scope-bound declaration with actor, reason, time, revision
  and retirement history so reused addresses in different scopes are never merged.
  Retained Nmap services, device configurations and Arkime session receipts may assess
  whether available evidence is consistent with a standard declaration, partially supports it,
  conflicts with it, is insufficient, is stale or has not been assessed. These labels
  describe retained evidence only: they do not validate live operation, recommend a
  replacement, grant authorization, change No-Strike, alter Reach or collection, or
  silently assign a role. Missing or partial observations never establish a conflict.
  Specific Special Identifiers remain declared identifications and are not automatically
  inferred or recommended. Map may visibly identify declared special-device addresses and show the exact scope,
  declaration and supporting evidence status; it must not promote evidence-shown
  alternatives into recommendations or declarations. The independent reviewer cleared
  this architecture as a **DOCUMENTED DEVIATION** provided declarations and assessments
  remain separate, assessment rules and source receipts are versioned, and all other
  authorization and evidence boundaries remain intact.
  Special-device Map legend clarity started 2026-10-23: every visible
  Mission Partner Identified marker must have a matching legend key, and its
  object details must name the declared special-device role without implying
  that an evidence-only possible match was identified or recommended.
  Novice review found that the full-screen Map could cover the Operator Guide;
  that layering defect and the associated full-details control are included in
  this gate so the Guide stays usable while an analyst inspects the marked
  object in the expanded workspace. The final novice pass then found that opening
  those details could move the unpinned Guide to a nearby search-result count. The
  full-details action must instead focus the declared-role explanation and keep its
  scope, partner-provided fields, provenance and non-recommendation limits visible.
  Special-device Map legend clarity implementation completed 2026-10-23: collapsed
  groups, grouped endpoint rows, individual hosts and WAN Portal presentation now use
  the same **MP ID** marker only when a Mission Partner Identified declaration exists;
  the conditional legend defines that marker, and selected-object details show the
  exact declared role, scope, address, declared ports/services, actor, time and source
  link. Evidence-only possible matches remain unmarked and are not promoted into Map
  recommendations or declarations. Expanded Map keeps the Guide above the canvas,
  places **Open full details** on a usable narrow-screen row, supports native pointer
  and keyboard activation, and focuses the declared-role Guide explanation after it
  opens. The executable Map runtime regression passed, the full Docker suite passed
  **2,014 tests with 19 skips and one dependency warning**, and live normal plus
  980×900 browser checks confirmed the Guide/details workflow, no page-width overflow
  and no browser warnings or errors. The novice operator returned **CLEAR** and the
  independent quality gate returned **CLEAR — DOCUMENTED DEVIATION** after separately
  verifying 75 focused tests, one skip, the executable Map runtime and whitespace.
  This remains development work on the foundation branch, not Range-ready,
  mission-ready or available on `main`.
  Operator Guide data-flow refinement started 2026-10-23: replace the ambiguous
  **Why this matters** block throughout the shared guide with three consistent parts.
  **How to use this** explains the highlighted page, section or control; **How NCT
  uses this** explains the context it creates and the next supported pipeline use;
  **Limits** preserves the evidence, authorization and live-state boundaries. The
  guide's own help must explain this reading order, and the data-use wording must
  remain specific to the active NCT workflow rather than promising unsupported future
  capability. Focused tests, live browser review, novice review and the independent
  quality gate are required before this refinement is marked complete. The first
  cumulative re-review **HALTED FOR REVIEW** because the Arkime guide copy described
  aggregate summaries too broadly, Arkime receipts from separate imports without a
  session identifier could be collapsed, and the collection-safety regression suite
  lacked hostile ambient SSH-configuration and live fence-invalidation exercises.
  The correction now limits cross-source role evidence to individual retained session
  receipts, preserves every retained receipt in role assessment while leaving verified
  exact-stream deduplication to Communication History where dataset, source-node and
  session identity are available together, proves OpenSSH ignores ambient config, and proves a running
  fenced child is terminated when the reviewed scope becomes stale. Focused Docker
  verification passes **101 tests** with one existing dependency warning. The shared
  guide now renders **How to use this**, **How NCT uses this**, and **Limits** for page
  overviews and focused controls. Live browser checks passed, the novice operator gate
  is **CLEAR**, the independent gate is **CLEAR — DOCUMENTED DEVIATION** after **133
  independent tests**, and the then-current full Docker suite passed **1,972 tests with
  18 skipped** and one existing dependency warning. This guide refinement is complete
  on the foundation branch only; it is not on `main` or installed on the Range.
  Common network and server role catalog refinement started 2026-10-23: expose
  the existing scope-bound role declarations as a collapsible, novice-readable
  catalog instead of hiding the basic choices in a dropdown. The selected Network
  Scope is shared with the declaration form. Each catalog entry must distinguish
  mission-partner declared addresses from bounded, same-scope retained-evidence
  matches; choosing an entry starts a draft only and cannot save a declaration,
  select an address, authorize collection, or promote a possible match. Typical
  ports are examples and are never copied into partner-supplied fields. The saved
  seven-column declaration/evidence table remains authoritative, custom roles remain
  available, and the catalog is collapsible. Added role rules are versioned and weak
  common-port signals remain investigation leads rather than device identification.
  Independent architecture gate: **CLEAR — DOCUMENTED DEVIATION** with exact-scope,
  stale-result, bounded-match, optional-detail and no-write selection regressions
  required. Novice review requires explicit draft-only wording, one synchronized
  scope selector, a clear Use this role action, and separate saved-table labeling.
  Implementation completed 2026-10-23 with 17 common and mission-specific role cards,
  one scope selector, collapsible layout, draft-only selection, optional partner-supplied
  ports/services, distinct declaration counts, and bounded same-scope evidence matches.
  Every possible match keeps its exact retained Nmap, Arkime, or device-configuration
  sources and source times. Source selection occurs before the separate display limit,
  so a supporting receipt beyond the first 25 visible signals is not lost. Ordinary
  SNMP agent ports no longer identify a network-management server; that role stays
  declaration-only until directional evidence can distinguish the manager. The novice
  gate initially halted because an unsaved catalog selection said Cancel edit; catalog
  drafts now say **Clear draft**, while saved records retain **Cancel edit**. The
  independent reviewer halted generic source links, SNMP overclassification and the
  pre-selection source limit; all were corrected and the final gate is **CLEAR —
  DOCUMENTED DEVIATION** after **135 independent tests**. Focused Docker validation
  passes **103 tests** and the cumulative full Docker suite passes **1,974 tests with 18
  skipped** and one existing dependency warning. Final novice browser checks are
  **CLEAR** at desktop and 980×900 with the Guide open: keyboard use, collapse state,
  draft clearing, table headings, contained scrolling and the console all passed. This
  refinement is development-ready on the foundation branch only; it is not on `main`,
  installed on the Range or mission-ready.
- [ ] **R24 explicit fresh installation.** Begin only after the diagnostic and reset
  boundaries are complete. Preview the exact NCT data that will be isolated, verify a
  separately stored backup and require explicit destructive confirmation. Preserve
  unrelated installations and document TLS/network-setting treatment and restoration.
- The remaining R01–R21 requests stay tracked in
  `docs/NCT_SCHEDULE_INCIDENT_AND_FIX_HANDOFF_2026-10-23.md`. After R22–R24, implement
  reliability and evidence-correctness items before navigation/presentation work, then
  plan STIG, reviewed neighbor collection and image-integrity capabilities as separately
  gated milestones. No handoff item is accepted as fixed without current-code reproduction
  or evidence that an existing implementation already satisfies it.
- [ ] **Later operator library navigation.** Add a hamburger **Evidence Library** that
  puts retained Nmap scans and device-pull evidence in one searchable, filterable catalog
  while preserving each record's provenance and read-only source access. Add a separate
  administrator **NCT Configuration & Source** area (the clarified form of the requested
  “Configurations & Code” entry) for read-only inspection of NCT's own approved
  configuration examples and application source. Bind displayed files to the installed
  build with a packaged hash manifest and use an explicit file allowlist; exclude secrets,
  credentials, runtime environment values and arbitrary host filesystem browsing. Keep
  its access separate from analyst Evidence Library access. Each listed file must show
  its exact, copyable packaged/container path and build identity so an authorized analyst
  can locate the same file directly without the page becoming a filesystem browser. This
  is recorded for later and does not interrupt R22–R24 reliability work.
- [ ] **Later single-scope operating mode.** Add an explicit administrator opt-in for
  installations with exactly one Network Scope available for new evidence and no reused
  or overlapping address space across sites, tenants, labs, missions, VPN contexts or
  disconnected ranges. Record the administrator, acknowledgment, exact scope revision,
  effective time and later changes. Eligible new scans, imports and device evidence may
  then freeze that authorized default at intake and label the resulting assignment as
  automatic; this is a durable operator decision, not scope inference. Hide redundant
  selectors and filters but always show `Network Scope: NAME · assigned automatically`
  with a Settings path on collection, evidence, analysis, comparison and export views.
  Never rewrite historical, unscoped, differently scoped, mixed-context or unresolved
  evidence. Creating or reactivating another scope, archiving the selected scope or
  invalidating its authority must stop automatic assignment atomically without changing
  earlier records; returning to one scope requires a new opt-in. Preserve No-Strike,
  authorization, target, capture-coverage and physical-identity boundaries. Require
  concurrency, restart, queued-work, second-scope, archived-scope, mixed-context and
  historical-preservation tests. Independent architecture gate: **CLEAR — DOCUMENTED
  DEVIATION** from per-intake selection to an audited administrator-authorized default;
  novice design gate: **CLEAR** with a persistent scope indicator and explicit plain-
  language acknowledgment. This remains later work and does not interrupt R22–R24.

## Arkime next-forward recommendation without historical repair or deduplication — 2026-10-21

- **Planned approach:** Phase 6.8 would generate the smallest useful next collection
  window with overlap and deduplicate the repeated portion.
- **Revised approach:** this slice recommends only the next forward UTC window for one
  exact API stream. It starts at the latest complete retained end minus a bounded
  safety overlap and ends at an explicit UTC cutoff or one frozen server time minus a
  disclosed collection delay. It retains every contributing source reference and does
  not combine or remove traffic observations.
- **Reason and expected impact:** a time overlap is not a traffic-observation identity.
  Removing records without a separately proven identity contract could silently lose
  evidence. The recommendation also cannot determine the smallest historical repair
  because earlier gaps may require separate operator decisions and API bounding rules.
- **Follow-up:** automatic collection, historical-gap repair and traffic-observation
  deduplication remain open. A recommended interval may still exceed the connector's
  returned-row limit and therefore cannot guarantee a complete API result.

## Arkime retained-window continuity without traffic deduplication — 2026-10-21

- **Planned approach:** Phase 6.7 would track retained Arkime coverage windows and
  gaps, followed by Phase 6.8 choosing the next useful window and deduplicating
  overlap.
- **Revised approach:** Phase 6.7 compares only complete, unambiguous publications
  from one exact API stream and merges touching or overlapping query intervals only
  for continuity calculation. Every retained source receipt remains separate, and no
  session, packet or byte counts are combined or deduplicated. Manual Sessions JSON,
  communication summaries, incomplete declarations and malformed or ambiguous API
  provenance remain visible but cannot bridge a gap.
- **Reason and expected impact:** matching query intervals does not establish that two
  exports contain the same traffic observations. Treating interval overlap as traffic
  identity could silently remove evidence or undercount communication. The narrower
  rule gives operators a defensible view of NCT's retained query-window history while
  preserving every source encounter.
- **Follow-up:** traffic-observation deduplication remains deferred to Phase 6.8 and
  requires a separately reviewed identity contract. Phase 6.7 does not claim sensor
  uptime, continuous packet capture, absent traffic or deduplicated passive evidence.

## Arkime durable history as deduplicated retained records — 2026-10-21

- **Planned approach:** Phase 6.10 would collapse repetitive sessions into durable
  communication summaries across retained Arkime windows.
- **Revised approach:** build immutable, versioned history generations only from a
  frozen set of complete automatic API pulls in one exact stream. Repeated records are
  recognized only by the exact declared Arkime dataset, Network Scope/version, profile
  authority, source node and session ID. Matching repeated records must agree on every
  normalized retained field before one counted record can represent their encounters.
  Manual Sessions imports, communication-summary CSVs, incomplete retained API results,
  noncomparable streams, records without both identity fields and conflicting copies stay
  excluded with visible reasons and preserved evidence. Eligibility requires a complete
  retained API result; its separate capture declaration remains Complete, Partial or
  Unknown and does not decide eligibility. `rootId` is retained as context and is never
  substituted for the exact record ID.
- **Reason and expected impact:** Arkime addresses a saved record by node and session ID
  and can separately link multiple segments. That supports overlap handling for repeated
  retained records, but it does not prove a unique real-world connection or deduplicated
  packets. A declared dataset identity also prevents a replacement Arkime backend at the
  same URL and username from silently sharing the earlier record namespace.
- **Follow-up:** reuse the immutable derived-result identity and publication model, add
  normalized Arkime-specific generation, source, record-membership and path tables for
  bounded reads, and define a real multi-source work contract before using the shared
  background queue. Cross-stream aggregation, packet deduplication, linked-segment
  collapse and claims of unique connections remain deferred.
  This narrower retained-history rule does not relax Phase 6.7 continuity eligibility or
  Phase 6.8 recommendation rules and cannot support sensor-uptime, absence, whole-network
  visibility or complete-capture claims.

## Separate exact-source Arkime context in Hunt — 2026-10-21

- **Planned approach:** extend the network-wide Hunt request with an optional Arkime
  import so one selected passive source could appear beside the existing Hunt evidence.
- **Revised approach:** Hunt now loads the selected retained Sessions JSON/API source
  through a separate `/api/hunting/passive-context` request and renders it in a clearly
  labeled passive-context panel. The ordinary network-wide Hunt request, cache,
  inventory, CVE candidates, filters and exports remain unchanged. The selected import
  identifier survives normal network-view refreshes, while focused-scan selection and
  the explicit Remove action clear it. Independent request ownership prevents a delayed
  earlier selection from replacing a later source.
- **Reason and expected impact:** coupling passive-source failure, timing and caching to
  the existing Hunt request could hide otherwise usable evidence or accidentally make
  the selected Arkime source part of current inventory. The separate request preserves
  the user's exact-source investigation workflow while keeping both failure and evidence
  meaning isolated.
- **Remaining boundary:** this is Hunt access to one exact retained passive source, not
  a unified Timeline selection or a current-network assertion. Aggregate summary CSV
  imports are rejected because their groups can overlap. Passive context does not add
  hosts, services, CVEs, Last Seen, Reach or Map claims, does not alter filters or
  exports, and does not combine Arkime and Nmap collection windows.

## NCT-defined Arkime communication-summary contract — 2026-10-21

- **Planned approach:** begin passive Tier A intake with the lowest-cost summary
  export available from Arkime, retaining grouped communication counts before adding
  higher-volume session correlation.
- **Revised approach:** the first Tier A slice accepts one explicitly NCT-defined
  `NCT Arkime Summary CSV v1` contract because a stable native Arkime summary-export
  shape has not yet been verified in the isolated Range. The exact ordered fields,
  grouping rule, 10 MiB and 10,000-row limits, Network Scope, observation point,
  query window, bounding mode, query expression and operator declarations are frozen
  before immutable receipts are published. Count values remain exact decimal text at
  the API and browser boundary.
- **Reason and expected impact:** silently interpreting an unverified native export or
  deriving completeness from a small aggregate file could misstate traffic coverage.
  The bounded contract provides a reviewable offline path now while preserving a
  separate compatibility gate for future native exports.
- **Remaining boundary:** recorded completeness comes only from the operator's grouping,
  export and capture declarations; NCT cannot prove completeness or group membership
  from this CSV. Repeated or overlapping files remain separate observations and their
  counts are never added. These receipts do not create current hosts or services,
  establish Last Seen, prove an open listener, contact Arkime, or complete downstream
  Timeline, Hunt, Reach, Map or active/passive correlation.

## Default-VLAN operator access for the isolated trial — 2026-10-21

- **Planned approach:** operators would reach the side-by-side NCT trial through its
  assigned HTTPS address after installing the private NCT web certificate authority.
- **Revised approach:** the existing home resolver now provides the stable local name
  `nct.home.arpa`, and the existing NCT leaf certificate was reissued by the same
  private NCT authority with both the stable name and the retained IP address in its
  approved names. The original leaf certificate and extension file remain as local
  rollback copies on the NCT guest.
- **Reason and expected impact:** a stable name removes the need for operators to
  memorize a Range address and avoids a certificate-name mismatch when the name is
  used. The Default VLAN already had a working route to the isolated trial, so this
  change did not add or broaden a firewall rule. Existing access to other Range
  management endpoints is a separate network-hardening decision and was not changed
  implicitly.
- **Remaining boundary:** the name, route, certificate chain and NCT health response
  are verified. Each operator workstation must still trust the approved public NCT web
  authority before normal browser use; bypassing a browser warning is not an accepted
  setup step. This is a trial-environment access improvement, not Range, mission,
  stable-`main` or multi-replica acceptance.
- **Installer completion:** the guided HTTPS setup now accepts an optional operator DNS
  name and generates one certificate that approves both the stable server IP and that
  name. The original IP-only workflow remains supported, and certificate generation
  remains separate from container deployment.

## Bounded Arkime Sessions API connector — 2026-10-20

- **Planned approach:** progress from manual Arkime evidence intake to direct API
  collection, then continue toward passive connection summaries and correlation.
- **Revised approach:** the first direct connector is an intentionally bounded Tier E
  Sessions API window collector. It uses one deployment-configured read-only Digest
  account over verified HTTPS, freezes scope and query authority before contact,
  requests no more than 1,000 ordered sessions and 10 MiB, retains the exact returned
  entity, and reuses the reviewed manual whole-file validator and atomic receipt path.
  It does not page silently. Missing or larger result counts are retained as Unknown
  or Partial and stop that definition for explicit review. One restart-aware worker
  runs one window at a time; interruptions never resume automatically and a retry
  preserves the original window and its scheduling purpose. The connector freezes its
  parser and request contract with each attempt, enforces a whole-request deadline and
  validates the actual returned row ceiling independently from the byte ceiling. Profile
  definitions are immutable and paged in this slice;
  changing one means creating a replacement and pausing the earlier definition.
- **Reason and expected impact:** unbounded paging, automatic catch-up after downtime,
  mutable queued queries, or treating a capped response as complete could lose or
  misstate evidence. The bounded slice makes network contact and completeness visible,
  preserves exact provenance and keeps repeated or overlapping responses as separate
  observations while still removing routine manual export work.
- **Remaining boundary:** Tier A summaries, PCAP retrieval, current-state or Last Seen
  claims, Timeline/Hunt/Reach/Map correlation, and compatibility with the live Range
  Arkime endpoint remain separate gates. The foundation implementation and isolated
  browser validation do not make this Range-ready, mission-ready, or available on
  `main`.

## Field-correction and first-class VLAN program — 2026-10-19

- [~] A staged correction program is proceeding from the post-2026-10-14 operator
  reports.
- [x] First evidence gate completed: traceroute compares only canonical ordered hop
  identity, keeps absent or incomplete requested paths Not assessed, omits path rows
  when neither source collected traceroute, and applies the reviewed interactive host
  limit to those rows. Detailed and network-wide views carry the same unassessed-path
  count, affected addresses, evidence links, and warning language. Recognized services
  on nonstandard ports retain that status across duplicate capability rows without
  guessing unknown ports. Proposed route/policy results now become unusable after any
  input change until reassessed, retain the exact tested inputs and source receipts,
  and remain readable with the Operator Guide open. Focused Docker regression:
  **237 passed**; final full Docker suite: **1,664 passed, 17 skipped**; executable
  Reach and Network Changes browser-handler regressions passed. The rebuilt browser
  preview had no console warnings or errors. Independent gate:
  **CLEAR — DOCUMENTED DEVIATION**; novice-operator gate: **CLEAR**.
- [x] Shared presentation correction complete. Explicit shared page, contained and static table
  modes now replace the broad page-specific sticky-header rules, Map detail tables gain
  the same contained contract at render time, and Live Discoveries uses the active
  theme. The responsive contained-table boundary was widened after browser review
  found that a tablet-width page could overflow when the Operator Guide was closed.
  Focused Docker interface regression: **67 passed**; complete Docker suite: **1,664
  passed, 17 skipped**; six executable browser-handler regressions passed. The isolated
  browser matrix covered table-bearing workspaces, Graphite and Halloween palettes,
  tablet and full widths, and the Operator Guide open and closed; no page-level
  horizontal overflow or browser console warnings/errors remained. Populated dynamic
  table handlers are covered by the executable regressions while the isolated browser
  preview intentionally used empty temporary evidence storage. The first independent
  closeout halted because an assignment-history table with an extra CSS class had
  escaped the original audit pattern. The table now declares the shared static mode,
  and the regression tokenizes every wrapper's complete class list so additional
  classes cannot conceal an unclassified table. Exact-diff rerun: **67 focused passed**
  and **1,664 passed, 17 skipped** in the complete suite. Independent quality gate:
  **CLEAR**; novice-operator gate: **CLEAR**.
- [x] Post-presentation operator correction gate complete after commit `dd632df`.
  Hunt now keeps eight cells under eight headings, groups host-level CVE summaries only
  by canonical `host_key`, preserves separate unkeyed rows and distinct same-port
  fingerprints, and repeats each transport beside its service/product/version so
  wrapping cannot imply a false pairing. Reach now reads in operator order from traffic
  and path through evidence and limits to the supported outcome, and plainly separates
  Unknown from Not assessed. Device History separately shows the immutable
  collection-plan scope suggestion and the analyst-confirmed Network Scope; copying a
  prior collection may prefill a new suggestion but does not silently confirm it.
  Hostname collection now gives an ordered authorized workflow, enumerates all readable
  Windows IPv4 DHCP scopes and forward DNS zones, reports partial and zero-row results,
  and refuses false success when modern or legacy collectors fail. The dedicated Guide
  topic is reachable from both the Windows collector heading and Copy control. Existing
  saved-analysis guidance was revalidated: preparing a saved scan reads its retained
  XML locally, Scan History remains metadata-first, and no refresh or selection starts
  network contact or silently queues preparation. Focused Docker regression: **272
  passed, 2 skipped**; Hunt and Device History executable browser-handler regressions
  passed. The first complete-suite run had one background job miss its three-second
  test deadline under load; that exact test passed immediately in isolation and the
  clean complete rerun passed **1,664 tests with 17 skipped**. The rebuilt isolated
  browser preview confirmed the dedicated hostname guidance from both controls with no
  console warnings or errors. Independent quality gate: **CLEAR**; novice-operator
  gate: **CLEAR**. No evidence model or network-contact boundary was changed.
- **Planned approach:** add VLAN presentation primarily as a Map overlay after the
  current ingestion pipeline work.
- **Revised approach:** make VLAN observations a scoped, provenance-backed evidence
  capability across Device Analysis, Current Network, Hunt, Reach, Map, Changes Over
  Time, retained source/history views, exports, and the Operator Guide. Audit and,
  where required, version the bounded read-only vendor collection command sets before
  expanding projections. Existing retained collections may be reprocessed locally
  only when their exact saved content and command coverage support the new contract;
  otherwise they remain visibly Not collected, Unsupported, or Unknown.
- **Reason and expected impact:** operator review showed that VLAN context is needed
  while interpreting inventory, investigations, path assessment, and change, not only
  while drawing topology. Cisco, Juniper, Linux/UniFi switching evidence already
  provides a partial source foundation, but no shared scoped VLAN observation model
  currently supplies every view. VLAN identity therefore remains local to the exact
  Network Scope, device/bridge observation, collection, and VLAN ID until a later
  reviewed physical-device and Layer-2 segment reconciliation capability exists.
- **Evidence limits:** configuration proves what a retained source reported; it does
  not prove that a VLAN, trunk, route, service, or device is live now. Matching VLAN
  numbers, names, subnets, or MAC addresses do not merge observations across devices.
  No new vendor command may be admitted without read-only behavior, bounded output,
  visible failure coverage, parser fixtures, and independent review.
- Independent start gate: **CLEAR — DOCUMENTED DEVIATION**. Material evidence,
  provenance, migration, collection-profile, and comparison changes remain subject to
  separate reviewer gates before downstream work continues.
- [~] Scoped VLAN evidence milestone started after commit `de80d16`. First establish
  one provenance-backed observation contract from exact retained device configuration
  lines, with explicit Network Scope, device/bridge context, VLAN ID, optional name,
  interface membership and source receipt. Then project only supported fields into
  Device Analysis, Current Network, Hunt, Reach, Map, Changes Over Time, retained
  history/source views, exports, and the Operator Guide. Existing evidence that lacks
  required collection coverage remains visibly Not collected, Unsupported, or Unknown;
  no view may infer live state, physical-device identity, cross-device Layer-2 segment
  identity, or equivalence from a matching VLAN number or name.
- [x] Schema version 6 safety gate completed. Independent review halted the first
  draft because it could accept mixed version-5/version-6 lineage and could not safely
  distinguish expected VLAN tables from unrelated changes after interruption. The
  revised guard now authenticates an exact completed version-5 contract, plan digest,
  five-row ledger and fingerprint; accepts only the exact reviewed version-6 VLAN schema
  after a failed or hard-interrupted attempt; rejects premature completed rows and all
  unrelated schema drift; and proves that a version-5 image rejects completed version-6
  data before workers start. A second independent review halted downstream projection
  work until four additional boundaries were explicit. Version 6 now includes a
  separate durable VLAN-admission request for every newly confirmed device-scope
  assignment, so interface normalization and VLAN extraction cannot overwrite each
  other's job identity. Immutable assessments retain older extractor versions while
  selecting only the current supported extractor and collection contract. Linux PVID
  and generic declared-membership evidence retain their source meaning instead of being
  relabeled as access, native, tagged, or untagged. Interrupted ledger rows now require
  the exact valid started or failed shape, including their fingerprint, completion, and
  error fields. A fully initialized version-5 device and intake schema is covered by an
  exact version-6 upgrade test. VLAN admission now accepts only a real pipeline job that
  exactly matches the frozen assignment, scope, source, hash, run, extractor, family,
  payload, parameters, and job definition; superseded assignments are rejected and a
  retained non-null job binding is immutable. The immutable request also freezes the
  exact completed reusable-analysis result, full reviewed assignment/authority contract,
  collection contract, and source coverage. Admission re-derives those records under one
  immediate write lock, rejecting newer summaries, archived scopes, changed authority,
  or scope-correction races. The first complete-suite run exposed ten stale upgrade
  fixture/shared-connection checks; all ten causes were corrected. Final focused Docker
  regression passed **138 tests**. The complete Docker suite passed **1,690 tests with
  17 expected skips** and the existing dependency warning. Independent quality gate:
  **CLEAR — DOCUMENTED DEVIATION** after verifying the exact retained contract,
  concurrency fence, fail-closed admission, migration boundary, and source vocabulary.
- **Documented migration-boundary deviation:** version 6 supports a fresh installation
  and an exact version-5-to-version-6 upgrade. Saved versions 1 through 4 must first be
  upgraded and sealed by the reviewed version-5 package. This staged boundary replaces
  the first draft's direct older-version-to-version-6 shortcut, which would have created
  a false version-5 ledger entry before the version-5 schema had actually been applied.
  The existing read-only version-4 audit remains available to qualify the staged first
  upgrade; version 6 will fail closed rather than synthesize skipped migration history.
  This gate is now clear. Downstream VLAN extraction, worker execution, receipt
  publication, and cross-view projections are the next implementation work; none is
  implied complete by this schema and admission checkpoint.
- [x] Scoped VLAN extraction and publication completed after commit `d0d4954`.
  This bounded slice consumes only the exact retained device configuration already
  named by the reviewed VLAN admission contract. It adds no command, subprocess, or
  network contact. Supported syntax will produce immutable source-line receipts under
  the exact device assignment and Network Scope; unsupported syntax, missing command
  coverage, decoding loss, and safety limits remain explicit and cannot be interpreted
  as proof that a VLAN is absent. Admission and lease acquisition are earlier durable,
  fenced steps. Final assignment, authority, source and lease checks then commit the
  assessment, receipts, lease release, and terminal output together or publish nothing.
  Cross-view presentation, comparison, historical adoption, and collection-profile
  expansion remain separate reviewed gates. Independent architecture start gate:
  **CLEAR**.
  - The retained-source worker now recognizes bounded Cisco configuration and `show vlan`
    evidence, Juniper set syntax, and Linux `bridge vlan show` output, including common
    wrapped Cisco port rows and indented Linux VLAN ranges. It publishes immutable,
    source-line receipts only after rechecking the exact assignment, authority, source,
    scope, and worker lease.
  - Coverage distinguishes supported, partial, unsupported, and unknown. Empty or
    incomplete evidence never means no VLAN exists, and every status carries explicit
    retained-evidence, no-live-state, no-absence, and no-device-identity limits.
  - The first independent completion review halted for a blocking-safe source-open race,
    incomplete wrapped-row handling, a multibyte related-line bound, and overstated
    atomicity wording. The worker now opens the exact file relative to a verified parent
    directory with no-follow and nonblocking safeguards, rechecks file and directory
    identity, and has named-pipe and parent-replacement regressions. The parser and this
    roadmap wording were corrected. Final independent quality gate: **CLEAR**. Novice
    wording gate: **CLEAR**.
  - Verification: **45 focused tests passed**, **211 device/pipeline/schema tests passed**,
    and the complete required Linux suite passed with **1710 passed, 17 skipped**. The
    only warning is the existing Starlette test-client deprecation. This capability is
    committed for the foundation branch only; it is not on `main` and does not yet make
    VLAN evidence visible throughout the operator views.
- [~] Scoped VLAN cross-view presentation started after commit `d07ed1a`. This slice
  will build one bounded read-only projection from the current exact scoped VLAN
  assessment, then carry its retained-source state, Network Scope, device/bridge and
  receipt links through Device Analysis, Current Network, Hunt, Reach, Map, Changes Over
  Time, retained history/source views, exports, and the Operator Guide. Missing or older
  unsupported evidence remains visibly unknown; a matching number or name cannot merge
  VLANs across devices or scopes. No collection command, live-state claim, automatic
  historical adoption, or Layer-2 identity inference is authorized by this slice.
  Independent architecture start gate: **CLEAR — DOCUMENTED DEVIATION**. Projection
  begins from every current device-scope assignment, including those without a current
  assessment, so missing, obsolete, unsupported, or unprocessed VLAN evidence remains
  visible as Unknown. Context may attach only to its exact configuration-source record;
  matching IP addresses cannot bind it to an Nmap host. Existing heuristic switching
  fields stay separate. Current-only evidence may appear as context in Changes Over Time,
  but VLAN added/removed/changed claims require a later reviewed comparable-coverage and
  device-continuity contract. This slice must use deterministic bounded paging and a
  source revision, invalidate affected view caches, and preserve all evidence limits.
  - [x] **2026-10-19 — scoped VLAN context is available across the analyst workflow.**
    One read-only, revisioned projection now enumerates every current device-scope
    assignment, including Unknown records with no usable current assessment. It accepts
    only the current assignment, active scope, exact current collection authority,
    extractor and collection contract, and retains the scope, collection, reporting
    device, bridge, interface, VLAN, source hash, receipt and source-line provenance.
    Equal VLAN IDs remain separate across scopes, collections, devices and bridges;
    declarations and memberships for the same VLAN inside one exact device/bridge context
    are summarized together without discarding their individual receipts. Device Analysis
    links to the existing bounded receipt pages for full source-line detail. Device
    Collections, Current Network, Hunt, Reach, Map
    and Changes Over Time show bounded context with scope/state/search filters, deterministic
    paging, a visible source revision, manual refresh, retained-source links, and standalone
    revision-bound JSON and CSV exports. The Operator Guide and How NCT Works explain the
    retained-evidence meaning and the no-live, no-absence, no-cross-device and no-identity
    limits. A reusable device profile continues to remember a preferred scope only as the
    next collection's visible suggestion; completed evidence keeps the analyst-confirmed
    scope for that exact collection.
    **Documented presentation deviation:** rather than injecting VLAN records into each
    page's older cached model and native export, every affected page reads the same direct
    projection panel. This bypasses stale page caches and keeps the new standalone exports
    tied to one VLAN revision. Existing Analyze, Hunt, Reach and Map exports remain unchanged
    because those models do not yet contain VLAN conclusions; no mixed-revision combined
    export is produced. Changes Over Time labels this as current context only, and no VLAN
    change detection, Reach outcome, routing conclusion, CVE/capability, physical identity,
    topology segment or Map link is created. Browser validation used isolated retained
    Cisco evidence at 1265 px with the Operator Guide open: headings stayed above and aligned
    with cells, the 940 px table used an internal 525 px viewport, VLAN 110 and 120 retained
    their names and source links, every requested page showed the correct limitation, and an
    archived scope remained visible as Unknown instead of implying disappearance.
    **Independent-review correction:** the first completion candidate was halted because its
    state filter could be overwritten by an assessment state, it expanded receipts before
    paging, exports checked size after expansion, and separate queries were not held in one
    SQLite snapshot. The corrected projection keeps the requested filter separate, begins one
    read transaction before candidate selection, builds its revision from bounded assignment
    and assessment metadata, filters and pages assignments before loading detail, caps each
    visible assignment at 200 VLAN summaries, and sends full source lines through the existing
    100-row receipt endpoint. Export preflight rejects more than 20,000 receipt rows or a
    conservative 10 MiB byte estimate before expansion, including multibyte UTF-8 evidence;
    JSON and CSV encoding also enforce the
    10 MiB limit incrementally. Regression coverage now includes mixed evidence states,
    revision-bound filtered export, the 20,000-receipt ceiling, aggregate assignment limits,
    multibyte oversized-export rejection before expansion, later receipt insertion changing
    the source revision, and a concurrent scope archive proving one coherent first page followed
    by a stale-revision `409` on the next request. Final Linux/Docker validation: focused
    VLAN/UI suite `123 passed`; broader device/evidence/route/UI suite `213 passed`; full suite
    `1721 passed, 17 skipped`. The only warning is the existing Starlette test-client
    deprecation warning; no new warning or failure was introduced. Novice operator re-review:
    **CLEAR** after Unknown/Unsupported, retained-not-live, Saved Network scope-context and
    bounded-detail wording corrections. Independent architecture completion gate:
    **CLEAR — DOCUMENTED DEVIATION**. The intentional deviation remains the shared direct
    projection panel and standalone revision-bound exports instead of modifying each older
    page model and its native export.

## Kubernetes Range trial preparation — 2026-10-19

- [x] Prepare a non-destructive, single-replica Kubernetes trial path for the Range.
  The first step must inventory the selected cluster context, namespace, storage classes,
  ingress support, Metrics API, and any existing NCT resources without creating, changing,
  deleting, or reading Secrets. The operator guide must make the choice between a fresh
  side-by-side Kubernetes trial, an existing supported Kubernetes upgrade, recovery, and
  an unsupported/blocked path before any mutation. A standalone Docker installation is
  not to be treated as an in-place Kubernetes upgrade; the safe trial uses a new namespace
  and new persistent claim while preserving the current installation until acceptance.
  Exact image registry/digest, namespace, storage class, requested capacity, HTTPS gateway,
  and target-cluster qualification evidence remain required before application.
  Completed with a fail-closed read-only inventory script, a novice-oriented start page,
  and the `NCT-Kubernetes-Range-Discovery-20261019-r1.zip` administrator handoff package.
  The inventory pins the selected context, bounds each request, does not read Secrets,
  and detects existing workloads, nondefault configuration records, claims, and retained
  volumes even when the namespace is absent. The fresh, existing-upgrade, recovery, and
  blocked paths are explained without treating the current Docker installation as a
  Kubernetes upgrade. Focused Docker validation passed 39 tests. The independent reviewer
  and novice operator both returned `CLEAR`. This completes discovery preparation only;
  no Range cluster resource was changed, and exact-cluster storage, registry, HTTPS,
  backup/restore, replacement, node-loss, upgrade, and rollback evidence remain required
  before Range-ready status. The complete Docker regression suite also passed
  1,733 tests with 17 skipped checks after this package work.

## Range transfer candidate — 2026-10-19

- [x] Prepare one complete air-gapped Docker package from the latest reviewed
  foundation branch for the next Range test. The package must use a new immutable
  image and build identity, carry its own file and image checksums, keep the existing
  host-folder data and rollback safeguards, and clearly identify itself as a transfer
  candidate pending Range installation and acceptance. This work started after the
  Kubernetes discovery kit and full 1,733-test Docker regression suite passed.
  The first `phase4-r1` draft was withdrawn at the independent quality gate: its
  packaged script reference pointed to development-only files that were not delivered,
  and its outer checksum path did not fail closed when the companion checksum was
  absent. `phase4-r2` replaces that draft with the self-contained Range script guide
  and requires the matching adjacent ZIP checksum before extraction.
  Completed as `NCT-Air-Gapped-Range-Deployment-0.16.0-20261019-phase4-r2.zip`
  with adjacent checksum. The extracted 23-file manifest and nested offline-image
  checksum passed on Linux; the outer ZIP checksum is
  `6be272983dfe7385333b5e9ea2078706ccced87305cb9e23ac94a5a77641cd26`.
  The exact archive loaded into an empty Docker engine and preserved the NCT and
  Caddy identities, application version, build, commit, required tools, raw-network
  capability, healthy startup, and healthy restart. Disposable health, five main
  pages, System Health rendering, and browser-console checks passed. A missing
  checksum was separately proven to stop before extraction, while the supplied
  checksum passed. The independent reviewer and novice operator both returned
  `CLEAR`. This is a locally verified transfer candidate; Range installation,
  HTTPS, sign-in, retained-data, offline-reference, device-field, and analyst
  workflow acceptance remain pending. It is not Range-accepted, mission-ready, or
  available on `main`.

- [x] **2026-10-20 — correct the retained version-5 Range upgrade gate.** The
  `phase4-r2` package was transferred, its outer and internal manifests passed, and
  its replacement image loaded. The stopped-database read-only preflight then rejected
  the healthy retained `phase3-r3` database because the packaged gate admitted only
  the earlier version-4 lineage. The upgrade stopped before backup or migration and
  restored the original `phase3-r3` container; the retained database reports schema
  version 5 with all five expected completed migrations. This is a release-path
  compatibility defect, not evidence corruption. Correct the gate to admit only the
  exact reviewed version-4 sources or the exact `phase3-r3` version-5 source, preserving
  integrity, foreign-key, plan-digest, fingerprint, build-origin and complete-ledger
  checks. Add direct rejection tests for altered version-5 state, rebuild under a new
  immutable package identity, and repeat independent and Range validation. `phase4-r2`
  remains rejected for retained-data upgrade and is not Range-accepted.
  - [x] The source gate now accepts only the exact reviewed version-4 lineages or
    `0.16.0-range-test-20261013-phase3-r3` at commit
    `f6ba1ad4a754b904511e3d726110d6fc35b9f237` as a version-5 source. Version 5 must
    match its exact plan digest, live and recorded fingerprint, five completed ledger
    rows, final migration origin, retained running build, integrity check and foreign-key
    check; every other version-5 source fails closed. Version-4 late-maintenance handling
    remains unchanged. The primary operator guide now explains the exact accepted source
    and requires a corrected full ZIP and adjacent checksum in a new staging directory
    after a safely restored preflight stop; it forbids database, manifest, checksum and
    single-script edits. Focused Linux/Docker validation passed **95 tests** and the
    complete suite passed **1,739 tests with 17 skipped**. Novice review: **CLEAR**.
    Independent quality gate: **CLEAR — DOCUMENTED DEVIATION**. The source correction
    is complete on the foundation branch; corrected immutable package sealing and live
    Range retained-data acceptance remain in progress.
  - [x] The corrected immutable transfer package is sealed as
    `NCT-Air-Gapped-Range-Deployment-0.16.0-20261019-phase4-r5.zip` at **97,499,852
    bytes** with outer SHA-256
    `fcfdbd179fb81c11b6b7aeea482927c1ea3a3ff6f3880e674c17947b0357502f` and a
    required adjacent checksum. `phase4-r3` was withdrawn before transfer because its
    packaged script reference was the repository developer guide and named files that
    were not delivered. `phase4-r4` was withdrawn locally because its receipt called an
    archive configuration digest an archive-loaded image ID. `phase4-r5` contains the
    exact package-specific script guide, distinguishes Docker image IDs from archive
    configuration digests, and retains no missing Kubernetes or development-only
    references. A fresh extraction has one safe root, **24** unique entries, **23**
    manifest-bound files, LF-only checksum records, and a **98,220,544-byte** image
    archive with SHA-256
    `d8b8e7d2bee57ecc8b8827b31e82d6df2717a1f6d8fd8868c58699ffde6e069a`.
    All checksums, **15** shell helpers and both Python helpers passed from the fresh
    extraction. The exact archive reloaded as build
    `0.16.0-range-test-20261019-phase4-r5` from commit
    `b908834cb60327a640e9987fddff036c4df9fb75`. Its read-only preflight accepted a
    fresh database created by the exact `phase3-r3` image; an isolated copy then
    upgraded to schema version 6 with all six migrations complete, SQLite integrity
    `ok`, no foreign-key errors, healthy startup, and successful Analyze, Hunt, Reach,
    Map and System Health responses. Novice package gate: **CLEAR**. Independent exact
    package gate: **CLEAR — DOCUMENTED DEVIATION**. This is a locally verified transfer
    candidate. Installation, HTTPS, sign-in, retained-data, account, offline-reference,
    device-field and operator-workflow checks on the work Range remain pending; it is
    not yet Range-accepted, mission-ready or available on `main`.
  - [x] **Live retained-data upgrade completed on the work Range.** The uploaded
    `phase4-r5` ZIP matched the sealed outer SHA-256 exactly, and its complete
    23-file manifest and nested image checksum passed in a fresh staging directory.
    The adjacent sidecar checksum was not transferred; for this installation only,
    the operator compared the uploaded ZIP directly with the exact sealed digest
    recorded above before extraction. This preserved the checksum guarantee but is
    a documented operator-path deviation; future transfers still require the adjacent
    sidecar and must not edit package checksums or scripts. The guarded legacy upgrade
    accepted the exact `phase3-r3` version-5 source, preserved both analyst accounts,
    created `/var/lib/nct/deployment/backups/nct-data-20261020T023003Z.tar.gz`, and
    retained stopped rollback container
    `nct-upgrade-rollback-20261020T023003Z`. Receipt
    `/var/lib/nct/deployment/upgrade-20261020T023003Z.receipt` records completion at
    `2026-10-20T02:32:35Z`. The live container now reports build
    `0.16.0-range-test-20261019-phase4-r5` and commit
    `b908834cb60327a640e9987fddff036c4df9fb75` from the unchanged bind-mounted
    `/var/lib/nct/data`. The database is schema version 6 with all six migrations
    complete, integrity `ok`, and no foreign-key errors. Pre/post inventory showed no
    changes to existing evidence-table counts; the only table-count changes were the
    three new empty scoped-VLAN tables and the migration ledger advancing from five to
    six rows. The backup-created restore-file inventory changed as expected, while the
    retained non-database files and Artifact Registry inventory remained unchanged.
    HTTPS health passed at `10.101.35.15:8445`; root, Scans, Analyze, Hunt, System
    Health and Map all enforced sign-in, and their redirects returned the NCT sign-in
    page successfully. This closes the retained-data upgrade gate, with the backup and
    rollback materials preserved. Rollback was not exercised in this run; it requires
    restoring the matching pre-upgrade data before starting the retained old container.
    Authenticated analyst workflow, offline-reference and device-field acceptance remain
    separate hands-on checks, so this is not yet Range-accepted, mission-ready or
    available on `main`.

## Independent quality gate — 2026-09-27

- Reviewer operating rules are preserved in [docs/NCT_PROJECT_OPERATING_RULES.md](docs/NCT_PROJECT_OPERATING_RULES.md).
- [x] Independent review of foundation commit `dbadae3` and corrective changes completed. Green tests alone
  are not acceptance; review includes evidence semantics, missing references,
  migration checkpoints, storage accounting, and compatibility with stable main.
- **QUALITY GATE: CLEAR — DOCUMENTED DEVIATION** — corrected manual device-upload manifests use
  `source_filename` / `artifact_sha256`, but storage inspection did not validate
  these references. Missing or changed upload content now blocks verification.
  Missing directories, unsafe paths, timed-out scans and upload attribution are also
  corrected. Independent reproduction passed; full Docker suite: **530 passed**.
- Docker access restored after the user enabled permission requests. Focused Linux
  regression testing and independent re-review passed.
- [x] Fixes completed for upload provenance, observation-backed missing references,
  path containment, timed-out scans, and signed-in Nmap upload attribution.
- Accepted deviation: resumed backfills skip copying and duplicate observations,
  but still hash content for integrity verification. Large-dataset performance has
  not been measured. Historical deletion has no observation tombstones: unresolved
  retained sources conservatively block reclaim estimates even if deletion was
  intentional. No evidence deletion or compaction execution is enabled.
- Recovery limitation: if an observation row itself was lost, backfill recreates a
  deterministic replacement ID. A legacy manifest's old ID is not rewritten; current
  evidence downloads use retained file paths. Existing observation IDs are preserved.
- [x] Storage category presentation completed: database size and evidence-folder
  usage exposed from the existing read-only inventory. Reviewer CLEAR; 57 focused
  route/storage tests passed. Browser dry run, backfill, repeated backfill and report
  persistence after preview restart verified; no browser console warnings/errors.
- Preview acceptance checklist: [docs/STORAGE_PREVIEW_CHECKLIST.md](docs/STORAGE_PREVIEW_CHECKLIST.md).
- [x] User-requested Operator Guide implementation: backfill purpose/process on hover
  or focus, dry-run comparison, and free corner resizing across the shared shell.
  Size persists across pages and refreshes, with viewport limits, Reset size, keyboard
  resizing, and existing top/bottom docking. Guide tab stays at the pane's vertical
  midpoint. Fixed Expand/Compact and standalone tooltip superseded by user direction.
  Reviewer cleared resize logic, including pointer ownership and capture-loss handling;
  66 focused tests passed. Browser verified keyboard resizing, cross-page persistence,
  top/bottom docking, centered tab, and narrow-screen bounds. Automated native drag
  interaction could not be confirmed; direct user corner-drag acceptance remains pending.
- User acceptance: provide a disposable running preview with scenarios and expected
  results; development verification does not imply user, Range, or main acceptance.

## Phase 2 scan workflow closeout — 2026-10-12

- [x] Phase 2 Steps 3–6 acceptance completed. Existing profile, identity, scheduling,
  progress, timeout, split-protocol, retained-evidence and partial-result behavior is
  closed with one deterministic successful combined-run regression covering
  discovery, top-1,000 TCP, top-100 UDP, merge and terminal publication. The check also
  verifies retained profile/version/operator/target/schedule context and that a new
  phase cannot display the preceding phase's ETA.
- **Planned approach:** list FPING and traceroute as separate saved-profile classes,
  retain creator/callsign together as scan authority, and require the full live
  top-1,000 TCP plus top-100 UDP run for foundation completion.
- **Implemented/revised approach:** FPING discovery and traceroute remain immutable
  options within versioned TCP, UDP, TCP+UDP, ICS-oriented and custom profiles;
  canonical usernames remain the audit authority while the optional display callsign
  remains Phase 8 presentation work; deterministic combined execution is the
  foundation gate and the full live port-count run remains a Range acceptance test.
- **Reason and impact:** profile options preserve one exact versioned command context
  without creating misleading duplicate profile kinds, audit identity cannot depend on
  a mutable display alias, and a deterministic regression can validate failure-prone
  phase handoffs without making normal development contact a live network. No schema
  migration is required. The analyst capability is unchanged; Range acceptance still
  must prove the complete live workload in its authorized environment.
- **Independent gate at start:** **CLEAR — DOCUMENTED DEVIATION**. At that gate,
  completion remained open until the success-path regression, focused/full tests,
  visible guidance check and final independent review passed.
- **Completion:** the deterministic success path now proves discovery → top-1,000 TCP
  → top-100 UDP → merge → terminal publication, both protocol evidence files, the
  analysis-ready aggregate, exact non-partial protocol coverage, and retained profile,
  version, operator, target and schedule context. Every phase clears the prior phase's
  activity and ETA while retaining elapsed time and the complete-run timeout. Active
  Scan guidance distinguishes those timers. Evidence downloads use plain labels and
  correctly distinguish TCP-only, UDP-only, complete combined and partial combined
  runs. Docker focused gate: **94 passed, 1 Node-only skip**; complete Docker suite:
  **1,513 passed, 16 skipped**; host Node rendering regression, isolated browser
  guidance/layout and console checks, and diff validation passed. Novice operator:
  **CLEAR** after two wording corrections. Independent quality gate: **CLEAR —
  DOCUMENTED DEVIATION** after correcting single-protocol artifact wording. This is
  foundation-only capability; it is not on `main`, is not Range-ready proof, and does
  not implement optional callsign display.

## Phase 2 historical analysis and comparison closeout — 2026-10-12

- [x] Phase 2 Step 7 started from commit `c908e80`. Opening a completed
  historical scan restores its retained analysis without contacting the network or
  silently substituting another scan, and makes the boundary between retained source
  analysis and current analyst presentation decisions clear to the operator.
- [x] Phase 2 Step 8 started in parallel because it consumes the same retained scan
  records. Two-scan comparison now covers hosts, ports, protocols, service/product
  fingerprints, versions, OS, MAC and identity, including source links, coverage
  limits, same-scope selection and plain-language interpretation. Completion requires
  focused and full tests, browser checks, novice-operator review, independent quality
  gate, and an exact commit reference here.
- These steps remain foundation-only while in progress. They do not change `main`,
  contact a live network, or establish Range readiness.
- Start-gate review halted the first implementation because opening and comparison
  could still parse or publish during a read, prepared groups were discovered through
  a newest-5,000-run window, current analyst decisions could be mistaken for immutable
  scanner facts, and omitted ports could be mislabeled as removed. The corrected path
  now requires already-completed versioned base-analysis results, verifies every exact
  group chunk and both retained copies, composes those child results deterministically
  with `nmap-group-composition:1`, and returns explicit saved-result provenance. Missing,
  stale, changed, incomplete, or unprepared evidence fails closed with a Prepare,
  Retry, or Backfill action instead of being recalculated by a GET request.
- Historical comparison uses exact-address source-reported attributes. Hostname, MAC,
  vendor and OS changes do not claim that the same physical device changed because
  DHCP and address reuse can produce the same pattern. Current analyst decisions remain
  a separate annotation layer, explicit protocol coverage is reported, and a missing
  individual port row remains Not assessed unless exact retained evidence proves a
  later state. Physical-device reconciliation and automatic historical conversion stay
  later roadmap work. Manual imported XML remains available through processed evidence;
  automated Scan History reopen and compare use the durable prepared-results path.
- Independent closeout review halted the first corrected build again because a saved
  database row could name another run inside its manifest, stale jobs could control the
  recovery message, live offset paging was not bound to one history selection, added and
  removed host ports bypassed the response limit, and the metadata selector still made
  per-run database queries. The closeout correction now binds every database row ID to
  its embedded manifest ID (including grouped chunks), derives recovery state only from
  the unique authoritative observation and current calculation contract, and stops host
  and port detail while the comparison is being built. Network-wide changes load five
  Network Scopes at a time under a selection revision; changed history rejects the next
  page and tells the operator to rebuild. The selector uses one joined indexed metadata
  query, then revalidates current computation identity without opening result payloads or
  evidence files. This bounded interactive contract does not remove evidence; an
  oversized comparison asks the analyst to narrow the Network Scope or choose smaller
  saved scans.
- A second closeout review accepted the source binding, stale-job isolation and
  construction-time comparison limits, then halted paging and scale completion because
  a caller could omit the selection revision after page one and the earlier benchmark
  measured mostly unprepared history below the declared ceiling. Later pages now require
  the exact 64-character selection revision and fail with rebuild guidance when it is
  missing or changed. The reviewed ceiling is now 5,000 retained runs and 5,000 prepared
  groups. A production-selector test builds 5,000 fully prepared, authority-bound groups,
  validates every current calculation identity, and materializes all metadata in **2.21
  seconds** while enforcing a **less-than-5-second** request bound and a **less-than-64
  MiB traced Python-allocation** bound. History beyond that ceiling fails closed with an
  explicit limit message instead of creating an unbounded request.
- **Completion:** implementation commit `a6f4561` reopens only exact, verified,
  current-version prepared results; keeps current analyst annotations separate; and
  compares same-scope saved scan groups with coverage-aware host, port, protocol,
  service/product, version, OS, MAC, identity and traceroute explanations. Network-wide
  comparison loads five scopes at a time under one required history revision, and all
  interactive host/port detail and retained-history work has tested fail-closed bounds.
  Docker focused gate: **155 passed**. Complete Docker suite: **1,537 passed, 16
  skipped**. The exact committed image identified as `a6f4561` passed an isolated
  browser build/load check, the Network Changes empty-state workflow, updated contextual
  Guide wording, and a zero-warning/zero-error browser-console check. Novice operator:
  **CLEAR** after the paging and Guide corrections. Independent quality gate: **CLEAR —
  DOCUMENTED DEVIATION** after three halt-and-correct cycles. This checkpoint is
  committed and suitable for controlled Range testing after packaging; it remains on
  `foundation/evidence-engine-v2`, is not on `main`, and is not yet Range-validated or
  mission-ready.
- **2026-10-12 controlled Range transfer-package start:** Freeze the completed Phase 2
  checkpoint for a manual air-gapped transfer. Build one immutable NCT image from exact
  source commit `99191b49b5bbc0e79e7d20dce1975d7073a6d2c6`, retain the Caddy image,
  include checksums and operator receipts, and require clean archive import, exact-image
  health/browser checks, deployment-script tests, novice review and an independent
  package gate before transfer. Packaging does not establish target-Range, mission or
  `main` readiness.
- **2026-10-13 controlled Range transfer-package completion:** Deployment-safety commit
  `fe7cd83` adds fail-closed active-work checks for current database state and legacy
  manifests, complete cold-backup inventories, verified automatic and manual rollback,
  exact earlier-container/image/mount/port binding, custom-port preservation, and bounded
  health probes. This deliberately follows the immutable application image source commit
  `99191b49b5bbc0e79e7d20dce1975d7073a6d2c6`; the split identity is recorded in the
  package receipt because no application bytes were rebuilt. Range deployment and
  launcher validation passed **52 tests**; all **14** source and packaged shell scripts
  passed syntax checks; the legacy password-wait blocking path and complete retained-data
  snapshot ran against isolated data. The offline archive loaded in an isolated empty
  engine and the archive-loaded image reported its expected health identity. Novice
  operator: **CLEAR**. Independent quality gate: **CLEAR — DOCUMENTED DEVIATION**. The
  final 22-file ZIP was extracted and reverified against its internal manifest; ZIP
  SHA-256 `ebda09dd743740e8d51733649f4f4e4ea88f4fd1c245b006156d9fda8c8c97b1` is supplied
  beside it. This is a verified transfer candidate on `foundation/evidence-engine-v2`,
  not target-Range accepted, mission-ready, or available on `main`; installation,
  sign-in, and any administrator-approved live Cisco collection remain target acceptance
  checks.
- **2026-10-13 Range candidate withdrawal and Host Inventory correction start:** The
  hands-on preview exposed a retained-data-only failure after one normal combined TCP/UDP
  scan: the exact-source selector treated every registered companion artifact for the
  run as a competing `scan.xml`, then an uncacheable-snapshot context-shape mismatch
  turned that verification refusal into a raw HTTP 500/JSON parsing message. Withdraw
  ZIP SHA-256 `ebda09dd743740e8d51733649f4f4e4ea88f4fd1c245b006156d9fda8c8c97b1`;
  it must not be installed on the Range. Correct the selector to identify only the merged
  `scan.xml`, preserve one builder-context shape on every uncacheable path, return an
  explicit conflict when exact-source paging/LFA/export cannot establish a revision,
  validate against the operator's existing saved scan without new network contact, run
  the broader novice workflow sweep, rebuild the immutable image and package under a new
  identity, and repeat the complete transfer gate.
- **2026-10-13 retained combined-scan correction complete:** The exact-source selector
  now uses the run's merged `scan.xml` as the authoritative current-network input while
  preserving TCP, UDP, discovery, packet-capture, console and target companion artifacts
  as evidence. Every unavailable snapshot retains one documented context shape, and
  exact-source Host Inventory paging, LFA and IP export now return an explicit conflict
  instead of a raw server/JSON error when a revision cannot be verified. Validation used
  an isolated copy of the operator's one saved combined scan and made no network contact:
  Host Inventory returned 16 hosts from 1 scan, LFA returned 5 outliers across 2 eligible
  groups, IP export returned 16 addresses, Hunt returned 16 hosts and 54 findings, Reach
  returned 16 hosts, Map returned 21 nodes, and Scan History retained 1 grouped run.
  Scan History now disables Analyze until the exact saved result has completed Prepare,
  Hunt remains readable at narrower widths with the Operator Guide open, and the affected
  guide topics explain their specific controls. Focused validation passed 111 tests, the
  Scan History browser-runtime regression passed, and the full suite passed 1,548 tests
  with 16 skipped. Browser console and novice-operator checks were clear. A replacement
  immutable image and transfer archive remain required before Range transfer; the
  withdrawn archive remains prohibited.
- **2026-10-13 replacement Range image and package gate:** Immutable image
  `network-characterization-tool:0.16.0-range-test-20261013-phase2-r2` is bound to
  correction commit `aab6e6f603df18ba568808cdf26f18ad4384c9a2`. Its health endpoint reports
  version `0.16.0`, the expected build ID and that exact commit. The image passed the
  operator's isolated one-scan API checks, and offline archive SHA-256
  `029862f812ca5e09397026a49e418a33aa26521f0dad94cfd705ae321d65a8b5`
  loaded with `caddy:2-alpine` into a separate empty Docker engine; the archive-loaded
  NCT image then started and passed health and Analyze page checks. Range launch scripts
  and the quickstart now identify the replacement image/archive, 52 deployment checks
  pass, and all 14 source plus 14 packaged shell scripts pass syntax validation. The
  final outer ZIP checksum and independent package gate are recorded after archive
  sealing. This remains a foundation transfer candidate pending target-Range acceptance,
  not mission-ready or available on `main`.
- **2026-10-13 package documentation gate correction:** The first replacement archive
  (`phase2-r2`, outer SHA-256
  `6ba9bc54eeab8a6baa949630fc641d1166998eaea281867bdafe17fc5ff193d5`)
  is withdrawn. Its application image and manifest were valid, but the packaged script
  README was copied from the source checkout and pointed a novice operator to one wrong
  relative Quickstart path and Kubernetes files that were not delivered in the air-gapped
  bundle. A separate package-safe README template now names only delivered operator
  material, has a regression check, and is used for `phase2-r3`. The immutable application
  image remains `0.16.0-range-test-20261013-phase2-r2`; no application bytes or retained
  evidence changed for this documentation-only package correction.
- **2026-10-13 replacement transfer candidate sealed:**
  `NCT-Air-Gapped-Range-Deployment-0.16.0-20261013-phase2-r3.zip` is the only current
  transfer candidate from this correction cycle. Its outer SHA-256 is
  `40761f189e1ef5412c5a7de9b8231cf2d8089c5a347db32c207adae41068333d`;
  its 21-entry package manifest and inner image SHA-256
  `029862f812ca5e09397026a49e418a33aa26521f0dad94cfd705ae321d65a8b5`
  were reverified after a fresh extraction. The complete suite passes 1,549 tests with
  16 skipped; 53 Range launcher/operator tests pass; all 14 packaged shell scripts pass
  syntax validation. The novice operator gate is CLEAR after confirming the contextual
  Host Inventory and LFA Guide topics on their visible controls. The independent package
  gate is CLEAR after separately checking ZIP path safety and uniqueness, all manifest
  hashes, both checksums, the package-only README, image identity, receipt bindings, 17
  package tests, and packaged script syntax. This is committed and development/transfer
  ready on `foundation/evidence-engine-v2`; target installation, HTTPS/sign-in, and
  administrator-approved acceptance checks are still required before calling it
  Range-accepted or mission-ready. It is not available on `main`.
- **2026-10-13 target Range acceptance started:** The novice operator is exercising the
  sealed `phase2-r3` package against the existing Range installation at `10.101.35.15`
  using Docker API 1.39 and the `legacy` upgrade path. Preflight confirmed that the
  running NCT container uses `/var/lib/nct/data -> /data`, HTTPS port 8445, and image
  `network-characterization-tool:0.16.0-range-20261004-r2`. The default package folder
  already contains the earlier release, so the reviewer cleared the Quickstart's
  documented `NCT_WORKDIR` alternate-path mechanism with a new empty root-owned staging
  folder; the earlier package folder remains untouched and releases cannot mix. The
  live container and retained evidence were not changed during preflight. Acceptance
  remains in progress until upgrade receipts, before/after inventories, existing-data
  views, HTTPS/sign-in, health identity, logs, and rollback readiness are independently
  verified.
- **2026-10-13 historical CVE compatibility follow-up started:** The upgraded Range
  preserved the active offline Exploit-DB and legacy query cache, but its seven retained
  scan scopes predate immutable per-scan candidate assessments. Hunt therefore reports
  them as `historical_unassessed` instead of displaying the candidate CVEs that the old
  page could calculate from the shared cache. The current Range remains unchanged. A
  future transfer will add an explicit administrator-confirmed bulk adoption workflow:
  a read-only preview lists eligible, ineligible and already-complete scans, then a
  separately attributed bounded request verifies and freezes each exact retained Nmap
  artifact, unsuperseded scope assignment and active Exploit-DB identity before queueing
  the existing scan-specific processing stages. It will never publish legacy cache rows
  directly, contact the network, run from page reads/startup/upgrade, or silently switch
  source, scope or dataset. Requests and items must be idempotent, restart-safe and
  individually reviewable/retryable. This is a documented supersession of the earlier
  one-run-at-a-time operator burden while preserving explicit consent and evidence
  provenance; automatic historical adoption remains prohibited.
- **2026-10-13 live scan discovery workspace completed in foundation:** The Active Scan
  workspace now places a bounded **Live discoveries** panel beside the active-run card.
  Its read-only endpoint opens the active run folder and known Nmap phase files with
  directory-bound, no-follow, nonblocking handles, verifies regular files after opening,
  reads at most 8 MiB per file, parses only fully closed host elements, and caps the view at 512 hosts
  or 2,000 rows. It presents provisional host,
  port, protocol, scanner-reported state and service fingerprints without starting a
  command, writing evidence, or publishing CVE/correlation claims. The panel is locked
  to the Active Scan card's current height; its table scrolls independently with sticky
  aligned headings and stacks at narrow widths under the same height bound. Read/parse
  failures remain isolated from scan control and visibly retry. A terminal run closes the
  provisional view and links to finalized retained evidence when available. Addresses
  sort as numeric IPv4/IPv6 values instead of text, and each active run permits only one
  in-flight live read; switching or finishing a run cancels the prior display request.
- **2026-10-13 active-scan progress clarification completed in foundation:** Nmap's
  finalized-host count remains separate from phase progress and provisional discoveries.
  The active view reports responsive hosts selected for the phase, hosts Nmap has
  finalized, phase percentage, active targets and the separate provisional-discovery
  count. It does not infer completed hosts from Nmap's percentage or present a
  provisional row as retained evidence. The visible and accessible progress label now
  states active targets and finalized records separately. Operators may therefore see
  the phase bar move while the finalized-host count remains zero; the Guide explains
  that boundary.
- **2026-10-13 whole-tool loading feedback started:** Add one shared activity bar below
  the fixed header on every page so slower page loads, evidence reads and saves do not
  look frozen or blank. It will track concurrent same-page requests and ordinary
  navigation without inventing a percentage or completion time, delay briefly to avoid
  flashing for fast work, expose plain Loading page/data or Saving change text, and
  remain accessible with reduced motion. Background heartbeat polling may opt out, but
  user-requested work may not. Rejected, aborted and overlapping requests must always
  release their own activity state.
- **2026-10-13 scoped automated-scan handoff defect found:** Target-Range validation of
  run `2ad584f784884255b2da4467d0ab39a4` proved that the A51-ADM Saved Network,
  association, Network Scope and immutable run snapshot were all retained correctly,
  while the finalized aggregate `scan.xml` observation received no corresponding scope
  context. The final-file registrar recognized legacy Nmap source labels but omitted the
  active `nmap_scan` label. Automatic admission therefore failed closed as
  `needs_scope`; ingestion and CVE candidate assessment did not start, and no evidence
  was lost or reassigned. The forward correction now carries the exact retained run
  scope into finalized `nmap_scan` observations and has a completion-path regression
  test. Focused ingestion, scope and storage validation passes **84 tests**. This fix is
  foundation-only and is not present in the installed Range image. The existing failed
  handoff remains unchanged pending an independently reviewed, append-only and
  idempotent reconciliation that preserves its original decision and will never infer a
  different scope or adopt unrelated historical scans.
- **2026-10-13 scoped automated-scan handoff correction implemented:** The correction
  is a separate administrator-confirmed action for one selected affected run; it never
  rewrites or deletes the original `needs_scope` admission. In one protected
  transaction it requires completed database and manifest agreement, no manual targets,
  one exact aggregate observation, matching immutable run context and frozen Saved
  Network source, an active scope, the exact known failed-intake contract, verified
  canonical and run-local SHA-256/size, and no earlier context, assignment, processing
  job or correction. It then appends the missing context, inherited assignment, durable
  job request and correction receipt together. The same attributed request is
  idempotent and wakes the durable worker again after a post-commit startup interruption;
  a different replay, malformed or traversing run identity, symlinked retained run path,
  authority drift, content drift or queue failure stops or rolls back the entire action.
  The completion-path regression proves that the queued local job reaches foundation
  completion, retains the original failed admission unchanged and creates candidate work
  from the exact observation and scope without starting a scan or other network process.
  Scan History and the Operator Guide explain that no scope changes, scan, network
  contact or historical bulk adoption occurs. Combined ingestion, storage, UI and
  Range-operator validation passes **183 tests** with one dependency warning; the Scan
  History Node runtime regression passes; the complete suite passes **1,562 tests** with
  **16 skipped** and the same dependency warning. The novice-operator re-gate and
  independent quality gate are both **CLEAR**. This is foundation-only and is not present
  in the installed Range image or on `main`.
- **2026-10-13 corrected full-package Range upgrade started:** Build a new immutable NCT
  image and complete air-gapped package from the cleared scope-handoff checkpoint. Use
  the existing package upgrade path rather than an in-container edit or clean install so
  the Range retains `/var/lib/nct/data`, users, scans, Network Scopes, offline Exploit-DB,
  HTTPS binding and an exact rollback image. Re-run image identity, archive load, package
  manifest/checksum, preserved-data upgrade, browser/API, novice-operator and independent
  package gates before transfer.
- **2026-10-13 corrected package acceptance-guide revision:** The sealed `phase2-r4`
  package is withdrawn before transfer. Its files, image archive, checksums and
  independent package review were clear, but the novice gate found that the Quickstart
  did not require the two release-specific Network Scope handoff checks from the receipt.
  The replacement `phase2-r5` guide now directs the operator to the release receipt,
  explains why the package revision is newer than the unchanged `phase2-r3` application
  build, and makes the acceptance boundary explicit: repairing one affected retained
  scan is local-only, while a new forward-handoff scan requires administrator approval
  of the exact Saved Network, Network Scope, profile, timing and No-Strike controls.
  Missing authorization records the live check as not yet validated; it does not invite
  an improvised scan. The new package must be resealed and independently rechecked before
  it becomes the current transfer candidate. The currently installed Range remains unchanged until
  the newly sealed package is manually transferred and run.
- **2026-10-13 Range container-resource compatibility correction started:** The installed
  Range reports NCT process measurements but shows container CPU and memory as Unavailable.
  On its older Docker stack this is consistent with the older Linux control-group counter
  layout, while the current reader supports only the newer layout. Preserve the safe
  Unavailable behavior for missing or malformed counters, add bounded read-only support
  for both layouts (including
  kernel-reported nested container paths and unlimited-resource sentinels), and test that
  the newer layout remains preferred when both appear. This changes application bytes, so
  the unsealed `phase2-r5` staging candidate is superseded. Rebuild the application as
  `phase2-r4` and seal the complete corrected package as `phase2-r6`; do not patch the
  installed Range container in place.
- **2026-10-13 Range container-resource compatibility correction implemented:** System
  Health now reads both newer and older Linux container counter layouts. Older-layout
  readings require an explicit safe process-to-controller path from the kernel; missing,
  unreadable, absent or unsafe identity stays Unavailable. Current, peak and limit memory
  values remain bound to one exact directory, CPU quota and period remain together, root
  counters require an explicit `/` record, and the newer layout retains priority. This
  prevents host-wide or cross-container numbers from being presented as NCT container
  use. The Operator Guide explains the expanded compatibility and preserves that
  Unavailable never means zero. Focused application, UI, scope-handoff and Range checks
  pass **140 tests**; the runtime browser regression and all source-script syntax checks
  pass; the complete suite passes **1,570 tests** with **16 skipped** and one existing
  dependency warning. The novice gate and independent quality gate are **CLEAR**. The
  correction remains foundation-only and awaits the exact `phase2-r4` image and
  `phase2-r6` archive checks; it is not yet installed on the Range or available on `main`.
- **2026-10-13 Range resource-acceptance guide correction:** The sealed `phase2-r6`
  package is withdrawn before transfer. Its application image, archive, manifest and
  checksums passed, but the novice package gate found that the Quickstart did not turn the
  receipt's pending Range CPU/memory confirmation into an executable acceptance check.
  The `phase2-r7` guide now directs the operator to System Health, waits through the CPU
  warm-up sample, checks aligned process/container rows, CPU current/average/maximum and
  basis, memory current/average/maximum, plausible values and raw errors, and explains
  that zero seconds near maximum is valid. Unavailable remains an honest unknown but now
  explicitly stops this release's Range acceptance without inviting permission or host
  mount workarounds. The unchanged `phase2-r4` application image must be resealed with the
  corrected guide and pass fresh novice and independent package gates.
- **2026-10-13 corrected full Range package sealed:**
  `NCT-Air-Gapped-Range-Deployment-0.16.0-20261013-phase2-r7.zip` is the transfer
  candidate. It is **97,224,297 bytes** with SHA-256
  `84c0b059b9dcafde08b4b04954cdff10a63c8655081ed7d09f37deff65ef619f`.
  The package binds guide checkpoint `6eaa30323d56a4b7a312da638066c2540cbbe6ba`
  to the unchanged tested `phase2-r4` application image from
  `99d8e03b826c05a719d541923a66cf3f5b597224`. A fresh extraction verified all
  **21** manifest-bound files, all **18** source-to-package mappings, all **14**
  delivered shell scripts, and the **97,955,840-byte** offline image archive with
  SHA-256 `8c24bbf6691ad1b6881fc8bc6b60c46549e23e6e43aea3d24662aafa86fd366d`.
  The archive declares only the tested NCT image and `caddy:2-alpine`. The novice
  operator and independent exact-package gates are **CLEAR**. This package is
  transfer-ready, but remains pending installation, sign-in, preserved-data checks,
  Range container CPU/memory confirmation, approved scope-handoff validation, device
  history retest and rollback readiness. It is not yet Range-accepted, mission-ready or
  available on `main`.
- **2026-10-13 live Range package-line-ending correction:** The `phase2-r7`
  transfer candidate is withdrawn after its pre-upgrade check failed safely on the
  recurring Range's older `sha256sum`. The ZIP and payload hashes were correct, but
  Windows CRLF endings in the two checksum-list files were interpreted as part of each
  filename. Removing carriage returns in a read-only pipeline proved all **21** package
  files and the offline image archive still matched; no application image was loaded,
  no upgrade ran, and `/var/lib/nct/data -> /data` remained untouched. The replacement
  `phase2-r8` package must use LF-only internal checksum files, receive a new outer ZIP
  checksum, pass local exact-package gates, and pass the unmodified
  `sha256sum -c` checks on the API 1.39 Range before upgrade. Operators are explicitly
  told to stop and obtain a corrected release rather than edit checksum files in place.
- **2026-10-13 expedited Range deployment — documented packaging deviation:** The user
  explicitly directed that the verified build be deployed now and the packaging be made
  perfect later. This superseded the preceding r7 stop only for this one Range event. The
  original **97,224,297-byte** r7 ZIP remained unchanged at SHA-256
  `84c0b059b9dcafde08b4b04954cdff10a63c8655081ed7d09f37deff65ef619f`.
  In the isolated extraction at
  `/root/nct-package-20261013T193725Z/NCT-Air-Gapped-Range-Deployment`, exactly two
  metadata files were normalized: `PACKAGE-MANIFEST.sha256` and
  `offline-images/nct-range-images.tar.sha256`. Their originals were preserved beside
  them as `.original` files with SHA-256
  `6655e614d9a730044da61eb364acdb291648faff719dea09dc42294db3828fb` and
  `f9681304db65a9750b899b2acbd34f640b972ca27e544374946a406a32496802`.
  The LF versions were
  `9a70427a7ae4cb37cfc2c2dbab89e1bb86e0b8104cc41aa30bcce88cbac676e321`
  and `0aac69776004f944037fbcc6408d8c0dee286be5f112ccc95378b4ebcbcb742792`;
  the manifest entry for the changed inner sidecar was refreshed. All **21** payload
  hashes and the unchanged image archive then passed `sha256sum -c` before Docker.
  The legacy upgrade completed successfully on API 1.39 with application build
  `phase2-r4` from `99d8e03`, `/var/lib/nct/data -> /data`, HTTPS at
  `10.101.35.15:8445`, backup
  `/var/lib/nct/deployment/backups/nct-data-20261013T194204Z.tar.gz`, stopped rollback
  container `nct-upgrade-rollback-20261013T194204Z`, and receipt
  `/var/lib/nct/deployment/upgrade-20261013T194204Z.receipt`. Health and normal saved-data
  requests pass. Process CPU and memory render, but container CPU and memory remain
  **Unavailable**. The cgroup capability and full Range acceptance therefore did not
  pass; no permission change or host-mount workaround is authorized. This is an installed,
  acceptance-incomplete testing state, not mission-ready. The LF-only `phase2-r8` package
  and unmodified Range preflight remain mandatory future cleanup.
- **2026-10-13 corrected portable Range package sealed and independently cleared:**
  `NCT-Air-Gapped-Range-Deployment-0.16.0-20261013-phase2-r8.zip` is the clean
  replacement transfer artifact. It is **97,224,500 bytes** with SHA-256
  `a177b5b788a52601cd4ce8a883439ff84dfc8eb796a62716c58e479c6e86ce19`.
  The package binds guide checkpoint `0572c1e83a6212c0aaee1f43bfceec82acd5660c`
  to the unchanged tested `phase2-r4` application image from
  `99d8e03b826c05a719d541923a66cf3f5b597224`. A fresh extraction verified one
  safe package root, **22** unique archive entries, all **21** manifest-bound files,
  all **18** source-to-package mappings, all **14** delivered shell scripts, and the
  unchanged **97,955,840-byte** offline image archive with SHA-256
  `8c24bbf6691ad1b6881fc8bc6b60c46549e23e6e43aea3d24662aafa86fd366d`.
  The outer sidecar, package manifest and inner image sidecar contain no carriage
  returns, end with a line feed, and pass unmodified GNU `sha256sum -c`. The novice
  operator and independent exact-package gates are **CLEAR**. This package corrects
  future transfer media only; the running Range remains the successfully installed
  identical application image from the documented one-time r7 normalization event.
  Container CPU and memory acceptance on that Range remains unresolved, so neither the
  installed system nor this package is mission-ready or available on `main`.
- **2026-10-13 phase3 Range schema-compatibility correction implemented locally:** The verified
  `phase3-r1` package passed its outer and internal checks on the API 1.39 Range, loaded
  the intended image, and then stopped safely before migration because the saved v4
  schema fingerprint did not match the live database. The guarded upgrade restored the
  original `phase2-r4` container and its verified pre-upgrade data. Local reproduction
  with that exact prior image proves that normal phase2 SearchSploit caching, Artifact
  Registry backfill, and exact-content compaction can create their supported tables
  after v4 sealed its fingerprint. The correction must admit only complete, exact known
  phase2 late-schema groups when removing an allowed subset reproduces the recorded v4
  fingerprint; altered, incomplete, or unrelated schema changes must still fail closed.
  Version 5 startup now initializes these supported schemas before sealing its new
  fingerprint. No Range database marker is rewritten and no retained maintenance state
  is deleted. The seven possible supported late-schema combinations, altered and
  incomplete schemas, unrelated drift, data preservation, v1-through-v5 ledger, and
  clean restart are covered by **29 passing focused tests**. The final Linux/Docker suite,
  including the replacement package's stopped-database audit, passes with **1,629 passed
  and 16 skipped**. An isolated upgrade from the exact
  `phase2-r4` image with rows in all three late-schema groups completed v5, retained all
  rows, passed SQLite integrity and foreign-key checks, and restarted cleanly. The exact
  corrected image also rendered System Health without visible or browser-console errors.
  The replacement upgrade helper now stops the old writer, completes a WAL checkpoint
  through the retained original image, and then uses the replacement image to record an
  immutable read-only audit of database integrity, foreign keys, schema fingerprints,
  the exact v1-through-v4 migration-plan digest and ledger, the separately retained
  running-build and schema-origin identities against the explicit supported phase2-r3
  through phase2-r5 lineage, and exact known late-schema objects. A later supported v4
  image may therefore open an unchanged schema created by an earlier supported v4 image,
  while the v4 state and ledger must still agree on the actual schema origin. Before the candidate can start, the
  helper binds that report to the exact SHA-256 of `analyzer.db` in the complete
  pre-upgrade inventory and retains the report SHA-256 in the upgrade receipt. Deliberate
  changes to the state origin, v4 ledger origin, migration-plan digest, unknown schema,
  incomplete ledger, or report/database binding all stop the upgrade. The final
  Linux/Docker suite passes with **1,636 passed and 16 skipped**; **61 focused tests**
  and Linux shell syntax validation also pass after this reviewer-led correction. One
  initial full-suite run had a single background-job timing miss at its three-second
  deadline; that test passed immediately in isolation and the complete suite then passed
  cleanly on repeat. An exact-image exercise created v4 with `phase2-r3`, opened it
  unchanged with `phase2-r4`, added retained rows in all three supported late-schema
  groups, checkpointed through the retained r4 image, and passed the replacement's
  immutable read-only audit with the r3 schema origin and r4 running identity recorded
  separately. A direct r2-created database is not this same exact v4 schema and fails
  closed. It requires a separate reviewed compatibility or migration path; merely
  starting it with a later phase2 image does not reseal or make it eligible for this
  replacement. The exact replacement `phase3-r2` image was rebuilt from application
  commit `fd4577e`, completed the verified r3-origin/r4-running v4-to-v5 exercise,
  preserved all three late-schema record groups, restarted cleanly, and rendered System
  Health with live process and container measurements and no browser-console errors.
  Package qualification remains in progress. The failed `phase3-r1` package is
  withdrawn. The schema correction quality gate is **CLEAR — DOCUMENTED DEVIATION** at
  commit `17a182f`; the reviewer confirmed that phase2-r2 requires a separate reviewed
  compatibility or migration path and that an ordinary later phase2 start does not make
  it eligible. The Range launch, upgrade, rollback, migration, direct-deploy, test, and
  operator-guide identifiers now consistently select `phase3-r2`; their focused suite
  passes with **24 tests** and every packaged shell helper passes Linux syntax validation.
  The exact `phase3-r2` replacement package was then sealed at package checkpoint
  `978dd52`. Its 97,424,734-byte ZIP has SHA-256
  `903b01076b94c804948bad219748865b7c48237669886cd5cd8651da466558e4`;
  its image archive has SHA-256
  `0af3a23e4072b064b2e99ab3dfd6e4cfe71035b89eb67d40322f3f63f6aa22a3`.
  A fresh extraction passed every one of its 22 manifest-bound file checks, the
  separately bound schema helper was present, all packaged shell helpers passed syntax
  validation, and both images loaded into an empty Docker engine. The archive-loaded NCT
  image reported the exact expected build and application commit, exposed the required
  network tools and capability, and started cleanly after a restart. The novice operator
  gate is **PASS** and the final independent package gate is
  **CLEAR — DOCUMENTED DEVIATION**. Range acceptance still requires the new guarded
  retry and preserved-data/browser checks on the Range host.
  The first `phase3-r2` Range retry exposed a separate recovery gap before that retry
  could load its replacement image: the retained `phase2-r4` container had already been
  restored to data that its own startup fingerprint gate cannot reopen, so it entered a
  restart loop and the ordinary helper could not execute its in-container active-work or
  build-identity checks. No `phase3-r2` image or new schema-audit record was present on
  the Range. The `phase3-r3` recovery-package correction is implemented and undergoing
  final package qualification. It stops the failed loop without deleting it, verifies
  package and image checksums, proves exclusive access to the data folder, checkpoints
  SQLite, runs the active-work and schema gates offline, binds the audit to a complete
  inventory, independently extracts and verifies a cold backup, and retains the
  incompatible source container. Any failure after candidate write
  access must preserve candidate data, restore and verify the cold backup, and leave the
  old incompatible image stopped. Success compares retained files, Artifact Registry
  identities and record and account counts, verifies exact image, mount, port, build, health,
  and restart, then retains a complete recovery receipt. The ordinary upgrade rollback
  now requires old-application health before describing a restore as successful.
  A disposable Docker-in-Docker exercise reproduced the exact old-container restart loop,
  performed the recovery into the exact `phase3-r3` image, retained the existing account
  and schema records, passed health and build-identity checks, and restarted cleanly. A
  separate forced failure after the candidate-write boundary preserved the failed
  candidate, restored the cold backup, independently verified the restored inventory,
  and left the incompatible old image stopped. This exercise also exposed and corrected
  a stopped-WAL read-only compatibility issue: offline SQLite checks now use immutable
  read-only access so they do not attempt to create shared-memory files on a read-only
  mount. The first recovery quality gate was **HALTED FOR REVIEW** because immutable
  reads were also being used against live WAL data, candidate-isolation failures could
  still reach backup extraction, and final restart validation did not recheck the exact
  healthy build commit. Those paths are corrected: live checks use ordinary read-only
  SQLite access inside the running container; immutable access is limited to stopped,
  checkpointed databases; failed candidates must be confirmed stopped, renamed, and
  moved aside before restoration; and the final restart rechecks status, build ID, and
  build commit. A second review halt found that the ordinary upgrade's stopped
  active-work check still preceded its WAL checkpoint. The helper now checkpoints
  immediately after stopping the writer and only then performs the immutable stopped
  check, closing the shutdown admission window. Tests retain active work only in WAL,
  prove an immutable pre-checkpoint read cannot see it, then prove the checkpointed
  stopped check does. Tests also inject stop, rename, and move failures and prove that
  none can extract a backup over the existing tree. A repeat end-to-end recovery passed, and a
  forced candidate-health failure preserved both containers, restored the exact cold
  inventory, account, and healthy database, and left the incompatible source stopped.
  The combined recovery, package, and schema suite passes with **66 tests**; every shell
  helper passes Linux syntax validation; and the complete Linux/Docker suite passes with
  **1,641 passed and 16 skipped**. Range acceptance remains pending until the sealed
  `phase3-r3` package is transferred and this recovery path succeeds against the preserved
  Range data.
  The final independent recovery gate is **CLEAR** and the novice operator instruction
  gate is **PASS**. The exact `phase3-r3` transfer candidate was sealed from package
  checkpoint `1c5ba5e`. Its 95,790,043-byte ZIP has SHA-256
  `9e587dc15173e07688aeea547c928a84499f0295924ae7adddce370784d86bee`;
  its image archive has SHA-256
  `39070f1d4659a12b147bab9853544d591db3d28d42d1e1d535d7f087c2a3c7f5`.
  A fresh extraction passed all **23** manifest-bound file checks, every delivered shell
  helper passed Linux syntax validation, both Python recovery checkers compiled, and the
  guide and receipt identify the exact package revision. The archive loaded into an empty
  Docker engine; the NCT image reported the exact build and source commit, exposed the
  required network tools, started healthy, and restarted healthy. `phase3-r2` remains
  withdrawn. This package is a verified transfer candidate; Range acceptance and mission
  readiness remain pending the preserved-data recovery and hands-on Range checks.

- [x] **Phase 3 R3 clean-state Range acceptance and stopped-container recovery correction — 2026-10-13.**
  The first Range recovery attempt exposed a deployment-helper defect before any package
  load or candidate data write: `docker port` does not report a saved binding for a
  stopped container. The recovery helper now reads the retained `8445/tcp` binding from
  the container's saved configuration and rejects missing, multiple, nonnumeric, zero,
  and out-of-range values before it disables the failed loop, loads an image, or touches
  retained data. Focused regression coverage and a disposable stopped-container exercise
  verify that behavior.
  The exact read-only Range preflight also established that the retained version 4 database
  originated on `phase2-r2`, outside the supported preserved-data recovery boundary that
  begins with the reviewed late-phase2 maintenance layouts. The gate correctly failed
  closed and no candidate migration began. Because the retained evidence and accounts
  were explicitly declared nonessential, the operator authorized a clean NCT-only reset
  instead of weakening the migration guard. The reset removed only NCT containers, NCT
  data and deployment records, failed-upgrade copies, migration receipts, and obsolete NCT
  images. It preserved the VM operating system, Docker, network configuration, unrelated
  files, and retained TLS material.
  A fresh `phase3-r3` installation then passed live Range checks at
  `10.101.35.15:8445`: the container remained running, `/health` returned `status: ok`,
  build ID `0.16.0-range-test-20261013-phase3-r3` and build commit
  `f6ba1ad4a754b904511e3d726110d6fc35b9f237` matched the sealed candidate, one enabled
  administrator account remained, the bootstrap secret was absent, the sign-in page
  loaded, and only the `phase3-r3` NCT image remained. This is **clean-state Range
  acceptance** for the Phase 3 R3 package. Preserved-data migration from `phase2-r2`,
  mission readiness, and availability on `main` remain unclaimed. The recovery-helper
  correction is foundation source for the next transfer package; it does not alter the
  application bytes already running on the Range. The independent recovery closeout gate
  is **CLEAR — DOCUMENTED DEVIATION**.

## Field feedback correction cycle — 2026-10-08

- [x] Captured the complete Teams operator-feedback window from 2026-09-28 12:23
  through 2026-10-05 16:09, including the supporting screenshots, in
  [docs/FIELD_FEEDBACK_2026-09-28_TO_2026-10-05.md](docs/FIELD_FEEDBACK_2026-09-28_TO_2026-10-05.md).
- [~] Reconcile each report against the current foundation build before changing
  behavior. Reports already corrected after the Range build remain regression checks;
  confirmed defects are grouped into small evidence/reliability and operator-workflow
  changes with focused tests and browser validation.
- [~] Three-role review is active: the primary agent implements; the novice operator
  evaluates discoverability and linear workflow; the independent reviewer verifies
  evidence meaning, compatibility, regression risk, tests, and roadmap accuracy.
- [x] First verified correction batch: preserve the initiating analyst through new
  manual and collected device authority, give `Needs scope` a direct assignment path,
  include retained addresses in Proposed Route interface choices, remove the duplicate
  Exposure Report regeneration action, and prevent stale catalog/load/generation
  responses from replacing the selected network. Existing LFA heading order, complete
  subnet-grouped Scan History, and `/8` No-Strike support were retained with regression
  coverage. Disposable browser acceptance confirmed the System Health actor and scope
  path. Focused Docker suite: **135 passed, 1 skipped**; strict host Node runtime check
  passed. Independent quality gate: **CLEAR**.
- [x] Second operator-clarity batch: make Reach results follow a stated reading order,
  explain Nmap `-Pn` as assumed reachability without a direct response while retaining
  the raw source reason, rename the manual Nmap workspace to Import & investigate and
  keep the imported result visible, and rename historical local preparation to Prepare
  from saved scan with explicit no-rescan wording. Disposable browser checks confirmed
  the Import & investigate and completed Reach flows; the primary focused Docker suite
  passed **101 tests**, the complete Docker suite passed **1,010 tests with 7 skipped**,
  and the independent reviewer passed **169 tests**. Independent quality gate:
  **CLEAR**. This item remains foundation-only.
- [x] Third Reach correction batch covers the combined Proposed Change guidance,
  retained-policy request ownership, a specific source-interface evidence error, and
  desktop/narrow result alignment for field reports #3, #4, and #7. The valid browser
  scenario passed all five checks; the missing-interface case gave a specific recovery
  message; desktop and 700-pixel layouts had no horizontal overflow. The focused Docker
  suite passed **131 tests with 1 Node-only skip**, the host runtime race suite passed,
  the complete Docker suite passed **1,011 tests with 8 skips**, and the reviewer passed
  **136 tests with 1 Node-only skip**. Novice workflow: **CLEAR**; independent quality
  gate: **CLEAR**. Evidence semantics were not relaxed and this item remains
  foundation-only.
- [x] Fourth Map correction batch completed reports #2, #8, #12, #15, #16,
  and #26. Inventory counts now remain in normal page flow; automated scan sources use
  retained human labels with scan identity; selected-object evidence and shared
  WAN/Reach role actions begin collapsed; and hiding full details leaves a compact IP,
  hostname, ports, and operating-system summary with a direct full-details action.
  The WAN presentation control now says that it changes drawing only and points to WAN
  Designation for the role used by Reach. Existing evidence links, timestamps, source
  downloads, and shared role meaning remain unchanged. Desktop and 700-pixel browser
  checks found no content overlap or horizontal overflow. Repeated expanded-workspace
  recalculation kept the summary and canvas at stable positions. Novice workflow:
  **CLEAR**; independent quality gate: **CLEAR** with **117 tests passed** and one
  container Node-only skip covered by a passing host runtime regression. Primary
  focused Docker suite: **97 passed, 1 skipped**; complete Docker suite: **1,012
  passed, 9 skipped**. This item remains foundation-only.
- [x] Fifth correction batch completed Map editing and save reliability from reports
  #19, #20, and the save/markup/hidden-object portion of #22. Map text now opens its
  editor by direct double-click; the current layout shows an explicit unsaved state;
  and leaving or replacing it offers overwrite, save-as-new, discard, and stay choices.
  Failed or stale saves retain the edits, a save in progress blocks competing layout
  ownership changes, edits made during the save remain dirty, and deleting the active
  saved copy no longer marks its remaining visible edits clean. Expanded workspace now
  keeps save, markup, and hidden-object review actions available. Evidence-derived
  device identity and shared WAN/Reach roles remain unchanged; device-icon presentation
  override is retained for a separate reviewed decision. Disposable browser checks
  covered direct editing, save-as-new, save-before-leaving, stay-without-loss, expanded
  controls, 900-by-700 layout, and browser console. Novice workflow: **CLEAR**;
  independent quality gate: **CLEAR** after two corrected race/loss findings. Focused
  Docker suite: **77 passed, 1 skipped**; complete Docker suite: **1,013 passed, 9
  skipped**; host runtime regression and diff checks passed. This item remains
  foundation-only.
- [x] Sixth correction batch completed Hunt evidence reports #27, #31, and #38.
  Retained device history now pages beyond the newest 100 collections, direct links
  search older pages within a safe bound, and loading more history preserves the
  analyst's selected and displayed collection. Guidance treats unmatched commands as
  leads rather than proof. New supported scan ingestion saves immutable, versioned
  offline candidate assessments identified by exact Nmap content, Exploit-DB dataset,
  and SearchSploit executable. Every live query confirms the frozen database path;
  failures publish nothing and remain retryable. Exact duplicate evidence reuses one
  result while preserving every encounter link. Hunt reads the saved result without
  page-load calculation and distinguishes queued, failed, historical-unassessed,
  no-fingerprint, no-match, limited-coverage, and matched states. Query-cache execution
  statistics are excluded from immutable content. Exposure remains a separate
  current-context classification because routes and policy can change after ingestion.
  Historical/manual candidate adoption, failed work after a dataset replacement, and
  reassessment against a newer dataset remain separate explicit actions. Novice
  workflow: **CLEAR**; independent quality gate: **CLEAR — DOCUMENTED DEVIATION** after
  five reproduced integrity/state findings were corrected. Reviewer suite: **126
  passed, 1 Node-only skip**; primary broader Docker suite: **200 passed, 1 Node-only
  skip**; complete Docker suite: **1,022 passed, 10 skipped**; host Hunt and Device
  History runtime suites and diff checks passed; disposable browser checks confirmed
  current wording and clean responses. This item remains foundation-only.
- [x] Seventh correction audit completed for Hunt presentation reports #5, #9, #10,
  #13, #14, and #37. Focused evidence identity remains visible without covering
  results; Dataset badges preview the exact matching services and ports for that host;
  MAC provenance remains linked to its retained source; nonstandard-port labels and
  supporting ports share one visual marker; headings precede data; guidance and dataset
  catalogs begin collapsed; and Exposure Reports group retained paths by source,
  destination address, then numeric port/protocol without merging TCP and UDP or
  implying a confirmed vulnerability. Report #14 is deliberately bounded to Hunt;
  density on other large-data pages remains subject to their own audits. Novice
  workflow: **CLEAR**; independent quality gate: **CLEAR** after two preview-fixture
  integrity findings were corrected. Focused Docker suite: **86 passed, 2 skipped**;
  complete Docker suite: **1,022 passed, 10 skipped**; both host runtime suites, browser
  rendering and console checks, and diff validation passed. The changes remain
  foundation-only; they are not on `main` and do not replace the installed Range image.
- [x] Eighth correction audit completed for device-collection reports #23, #24, and
  #33. Validated optional commands now remain visible as their own preview and inside
  the complete device command set. The ordered execution preview identifies every
  external command, local evidence action, cleanup step, and whether it runs on the NCT
  host, the network device, or local evidence storage. Named device collection profiles
  now preserve immutable versions of approved non-secret connection fields, ordered
  roles, validated optional commands, and an optional suggested Network Scope. The
  storage layer itself enforces the allowlist and read-only commands; database guards
  protect immutable versions, root identity, forward-only current-version movement, and
  one-way archival. Passwords, key paths, per-run notes, originating host, capture
  interface, assignment reason, and confirmation are never profile fields. Editing an
  applied profile detaches the working settings until the analyst saves a new immutable
  version or separate profile. Historical **Copy collection settings** creates a draft,
  not a profile. A changed or archived profile requires a fresh preview, and archiving
  clears any already-rendered preview. A suggested Network Scope is accepted only while
  active; if it is later archived, the historical ID and label remain visible while the
  assignment selector defaults to no selection. Every new collection still requires a
  reason and whole-collection confirmation after reusable analysis; no address, prior
  collection, or profile silently assigns evidence. The built-in README and Operator
  Guide describe profile storage, versioning, roles, preview locations, drafts, and scope
  limits. Complete Docker suite: **1,030 passed, 10 skipped**; host Device History
  runtime and diff validation passed; browser create/apply/version/preview/archive and
  guide checks passed without console errors. Novice workflow: **CLEAR**; independent
  quality gate: **CLEAR** after five adversarial findings were corrected. The capability
  is foundation-only and is not yet available on `main` or the installed Range image.
- [~] Ninth correction audit started for whole-network performance report #30 and the
  remaining cross-page density concern in report #14. Measure the current foundation
  build with representative retained-data volume before changing behavior; identify
  which reads, calculations, and initial render paths dominate Analyze, Hunt, Reach,
  Map, Scan History, and System Health. Preserve evidence completeness, provenance,
  exact-content identity, and operator-visible status while reducing unnecessary work.
  The novice-operator pass will assess whether progressive disclosure and load states
  keep the workflow understandable, and the independent reviewer will gate query,
  caching, persistence, and evidence-semantics changes. This work is foundation-only.
  - [x] First bounded correction: replace Scan History's per-request full manifest
    decode/regroup with a transaction-maintained membership and group index. Existing
    rows receive a one-time startup index backfill; source evidence and manifests are
    unchanged. Current writes synchronize the index atomically. Pure-SQL dirty markers
    let an older rollback build continue saving scans, and startup repairs its changes
    when the foundation build returns. Catalog pages now read indexed group rows, and
    one open group reads only its stable-cursor page plus other exact memberships for
    those visible runs. Direct update/delete, rollback-write repair, legacy-cursor, and
    2,000-row migration tests verify maintenance and page behavior. Hunt now starts with
    the overview and advanced filters collapsed while a quick host/service search remains
    visible above results. Focused suite: **84 passed**; complete Docker suite: **1,034 passed, 10
    skipped**; browser layout and console checks passed. Novice workflow: **CLEAR**;
    independent quality gate: **CLEAR** after rollback, repair, migration retry, raw
    delete, and legacy paging probes. Report #30 remains partially complete while shared
    Analyze/Hunt/Reach reconstruction, device evidence selection, Map reconstruction,
    and server-side detail paging remain open.
  - [x] Second bounded correction: keep the shared current-network evidence
    model as the input to Analyze, Hunt, and Reach, but load saved SearchSploit candidate
    assessments only for Hunt and the exposure-report actions that use them. Ordinary
    Reach context, path evaluation, saved-report freshness checks, and proposed-change
    simulations must not perform Hunt-only enrichment. Add an actionable empty state to
    Reach and clarify the difference between the Current Network roster and Hunt's
    investigation view. Preserve the same retained hosts, services, provenance, routes,
    policies, and conservative outcomes. Focused Reach/Hunt/UI suite: **119 passed**;
    complete Docker suite: **1,037 passed, 10 skipped**. Live browser checks confirmed
    the empty-state actions, correct new-scan and manual-import destinations, and a clean
    console. Novice workflow: **CLEAR** after the scan/import actions were separated;
    independent quality gate: **CLEAR**. Shared evidence is still rebuilt independently
    per request; a reviewed descriptor-bound process cache remains a separate later
    correction. This work is foundation-only.
  - [x] Third bounded correction: reuse one serialized shared current-network
    base model inside a running NCT process only when a canonical descriptor proves the
    exact scan selection, Nmap bytes and registration, topology imports, device
    manifests and selected evidence, analyst identity/OS choices, Saved Network labels,
    offline OUI data, calculation contracts, and database identity are unchanged. An
    identical concurrent request shares one build; every caller receives a private copy.
    Recheck the descriptor after each cold build, discard results built across a source
    change, and bypass reuse for unverifiable legacy or unstable inputs. Hunt enrichment, Reach
    results, exposure reports, and comparisons remain outside this cache. Adversarial
    tests cover concurrent callers, source changes during a build, nested caller
    mutation, direct database changes and replacement, same-size/same-time filesystem
    changes, calculation-contract changes, fallback OUI files, scan-selection races,
    symlinked device evidence, failure recovery, and uncacheable legacy evidence. An
    isolated empty-data measurement improved from 47.64 ms cold to 3.05 ms warm; this is
    proof of reuse rather than a representative large-installation benchmark. The live
    Analyze, Hunt, and Reach pages loaded their final states with successful API responses
    and no server errors. Cache-specific tests: **15 passed**; combined
    Analyze/Hunt/Reach/UI regressions: **168 passed**; complete Docker suite:
    **1,052 passed, 10 skipped**; independent quality gate: **CLEAR** after reproducing
    and clearing three initially halted descriptor gaps. Device-evidence selection, Map
    rebuilding, and server-side detail paging remain open under report #30. This work is
    foundation-only.
  - [x] Fourth bounded correction: replace the shared network view's use
    of the fully enriched Device History reader as its newest-device selector. Measure
    and isolate the minimum exact selection contract needed by Analyze, Hunt, and Reach
    without changing Device History, evidence authority, deletion and integrity rules,
    or the verified device-summary calculation. The current fixed 100-record window must
    not hide an older device merely because newer collections belong to other devices.
    Any reusable selection or analysis boundary must return private results, invalidate
    on the exact authority, manifest, selected evidence, gateway-role, or calculation
    change it consumes, remain rollback-compatible, and perform no page-time evidence
    writes. Sub-gate 4a is complete: a disposable transaction-maintained
    selector catalog replaces the global newest-100 history window. One indexed SQL
    selection finds the latest eligible verified summary for every distinct device and
    only those selected manifests and immutable result dependencies are read. The
    selector fingerprints canonical parsed-manifest content, so formatting-only JSON
    rewrites do not change meaning. Selection uses retained completion/creation time
    plus the run identifier as a deterministic tie-breaker. A semantic change or corrupt
    selected record is an actionable integrity
    conflict; NCT does not silently fall back to an older record. The previous weak
    mutable device-analysis cache is disabled until sub-gate 4b can bind a serialized,
    private-copy cache to exact evidence, scope, WAN, calculation, and database inputs.
    Activation and deletion update the disposable selector in their authority
    transactions, older rollback writes leave pure-SQL dirty markers for startup repair,
    and a selection change during calculation is retried once before returning a visible
    conflict. Focused selector/Reach tests pass **82** and the broader device ingestion,
    authority, observation, analysis, and Reach suite passes **146** with one existing
    warning. The independent quality gate returned **CLEAR — DOCUMENTED DEVIATION**
    after separately probing scale, unrelated records, exact semantic change detection,
    rollback, deletion, catalog tampering, read-only behavior, and the visible conflict
    policy. The complete Docker suite passed **1,065 with 10 skipped** and one existing
    warning. The restarted preview served System Health and the Current Network, Hunt,
    and Reach APIs successfully; the novice empty-state smoke pass returned **CLEAR**.
    Sub-gate 4b now reuses one serialized current-device analysis entry inside the
    running NCT process only after a read-only snapshot binds the exact selected
    authority, durable admission decision, immutable saved result and provenance links,
    run-local and canonical evidence bytes, raw manifest bytes, candidate-file shape,
    scope assignments and observation work, WAN roles, calculation contracts, and
    database identity. Every caller receives a private copy. A cold build cannot create
    or repair evidence, and a missing or inconsistent intent, result, link, file, or
    database state returns a visible conflict instead of publishing or falling back.
    Identical concurrent requests share one build; a source change discards the stale
    result and retries once. Warm entries invalidate automatically after database
    replacement, authority deletion, scope-observation completion, WAN changes, and
    calculation changes. Tests pass **14** focused cache cases, including 101 distinct
    devices through the cached builder and a real manifest change during a cold build;
    the broader device/Reach suite passes **175**. The independent quality gate returned
    **CLEAR — DOCUMENTED DEVIATION** after first halting completion for five missing
    integration proofs. The existing 2026-10-08 Whole-network current device selection
    deviation row covers both selector and exact-cache sub-gates; no duplicate row is
    needed. The
    complete Docker suite passes **1,079 with 10 skipped** and one existing dependency
    warning. The restarted preview served System Health and the Current Network, Hunt,
    and Reach APIs successfully, and direct browser checks confirmed all four views
    render their expected empty states. The novice final pass returned **CLEAR** with no
    visible error or navigation regression; its isolated data set did not contain
    populated device evidence. Map rebuilding and server-side detail paging remain open
    under report #30. This work is foundation-only.
  - [x] Fifth bounded correction complete: Current Network correlation and the Map page
    now share one serialized process-local Map topology calculation while its exact
    retained database, newest 200 Nmap scan records, newest 200 manual imports, newest
    300 configuration records, selected retained files, identity/OS review decisions,
    Saved Networks, OUI sources, and calculation contracts are unchanged. Every caller
    receives a private copy. A changed input discards an in-progress mixed result and
    retries once; unverifiable inputs bypass reuse; failures do not leave a blocked
    calculation. Map's response shape and specialized topology semantics are unchanged.
    The selection order has explicit record and exact-filename tie-breakers, including
    case-only uploaded filenames. The cache descriptor uses the exact Map selections, so
    an older unselected 201st scan does not cause needless rebuilding while a selected
    scan change does. The first verified Map view may still publish a missing reusable
    topology-derived result under the existing evidence-pipeline contract; the Operator
    Guide explains this local calculation and the meaning of its generated time.
    Validation passed **22 focused cache tests**, **52 broader Map, Current Network, and
    Hunt tests with 2 skipped**, and the complete Docker suite with **1,086 passed and 10
    skipped** plus one existing dependency warning. Live API checks confirmed healthy
    Current Network and Map responses and a stable reused Map build time; direct browser
    checks confirmed both empty-state pages rendered with no browser warnings or errors.
    The novice final pass returned **CLEAR** after confirming navigation, both empty
    states, and the guide's explanation of the local calculation and generated time.
    The independent quality gate returned **CLEAR — DOCUMENTED DEVIATION** after first
    halting completion for exact selection and case-only ordering gaps, then verifying
    both fixes independently. The existing 2026-10-08 Whole-network current-view
    performance deviation covers this cache; no duplicate deviation is needed.
    Server-side detail paging remains the next separate sub-gate. This work is
    foundation-only.
  - [x] Sixth bounded correction complete: Current Network now applies search, subnet,
    and all seven sort choices to the complete exact-source inventory before returning
    a page of at most 100 hosts and only those hosts' capability findings. An opaque
    source revision rejects later-page, LFA, and export requests with a visible refresh
    when retained inputs change, so one session cannot silently mix evidence versions.
    LFA still evaluates the complete selected subnet, and filtered IP export includes
    every matching address rather than only the visible page. Hunt, Reach, Map, and the
    existing complete-model endpoint keep their prior response and evidence semantics.
    The backend still assembles the complete reusable model before projecting a page;
    this correction bounds response size and browser work without claiming that the
    initial model build is constant-time. Validation passed **106 focused tests with 1
    skipped**, **166 broader tests with 2 skipped**, the host browser-runtime test, and
    the complete Docker suite with **1,101 passed and 11 skipped** plus one existing
    dependency warning. Live API checks covered the paged roster, whole-subnet LFA,
    full filtered export, Hunt, Reach, and Map. Direct browser checks confirmed both
    Current Network sections and a clean console. The novice pass returned **CLEAR WITH
    MINOR FEEDBACK**; its one location-wording concern was corrected and rechecked. The
    independent quality gate returned **CLEAR** after three findings involving stale LFA
    refresh, unstable-source error handling, and built-in guidance were corrected. This
    work is foundation-only and is not available on `main` or the installed Range image.
  - [x] Seventh bounded correction completed after the installed Range build
    `0.16.0-range-test-20261013-phase2-r4` timed out while opening Hunt / Network
    Evidence. The page stopped waiting after 90 seconds and incorrectly described the
    timeout as unavailable verified evidence. A candidate-rich isolated reproduction
    with 1,000 service endpoints, one Saved Network, and 1,001 retained routes required
    51.92 seconds for exposure classification alone. Profiling traced the dominant work
    to reparsing and rescanning every retained route for every candidate/source pair;
    the earlier 4,188-host browser benchmark did not contain this retained-candidate
    and route workload. Correct the repeated calculation with request-local indexes and
    unique-endpoint reuse while preserving exact saved candidate assessments, all
    retained route/policy conclusions, complete response content, and read-only/no-network
    behavior. The implemented correction now builds request-local host, service, route,
    policy, and unique-endpoint indexes, while retaining a conservative visible conflict
    when malformed saved service evidence prevents a definite answer. Raw and indexed
    results are required to remain exactly equal across destination/source translation,
    vendor policy, equal-prefix route priority, chained next hops, and malformed service
    and route inputs. The same isolated workload now completes exposure classification
    in 0.572 seconds, approximately 90 times faster than the 51.92-second baseline.
    Hunt now shows elapsed read-only loading feedback, aborts superseded requests,
    distinguishes timeouts from missing evidence, and retains the exact kind and time of
    the last successfully loaded view. Its constrained tables scroll internally with
    sticky headings at narrow widths whether the Guide is open or closed. The retained
    scan selector accepts both the current paged response and the legacy list response;
    selector failures stay beside that control and cannot replace the network-wide load
    status. This directly corrects the Range `items.map is not a function` startup error.
    The focused regression set passes **166 tests with 1 skipped**, and a populated
    browser check has confirmed network-wide results, clean console output, horizontal
    and vertical table scrolling, and sticky headings. The direct focused-scan startup
    path is covered by a browser-runtime regression proving that a failed later refresh
    identifies the exact retained view and its load time. The complete Docker suite
    passes **1,589 tests with 16 skipped** plus one existing dependency warning; the
    host browser-runtime regression passes separately. The novice acceptance pass and
    independent quality gate both returned **CLEAR**. Specialized revision-bound Hunt
    server paging and bounded exports remain a later sub-gate. Replacement-package
    qualification remains separate from this implementation completion. This work is
    foundation-only and is not yet installed on the Range.
  - [x] Eighth bounded correction packaging completed for replacement transfer candidate
    `phase2-r9`, carrying exact application image
    `0.16.0-range-test-20261013-phase2-r5` from reviewed source commit `46fbf1d`.
    Update every packaged operator script and the air-gapped guide to the exact image and
    package identities, preserve the existing host-folder upgrade and rollback workflow,
    export NCT with the required Caddy image, and verify the immutable archive, Linux
    checksums, shell syntax, exact-image health/build identity, Hunt automatic loading,
    browser console, and package extraction before offering it for Range transfer. The
    exact image and its archive-loaded copy both report version `0.16.0`, build ID
    `0.16.0-range-test-20261013-phase2-r5`, source commit `46fbf1d`, and immutable image
    ID `sha256:24e5b47e425aa219febf32169ce973fed1e251713ec1888a6b573bfe5335c84c`.
    The exact-image Hunt page completed its automatic empty-data network-wide load with
    no console warning or error. **89** focused Range-script/operator-guide tests pass;
    every delivered shell script passes syntax validation. A fresh ZIP extraction passes
    its 22-file manifest, embedded image checksum, Linux line-ending, current-identity,
    and outer checksum checks. The final ZIP SHA-256 is
    `253b889b59c2c3bcc3a382fc45450a248b9eeebc057d66e4f9e35f149b1c3e37`.
    This remains a transfer candidate until it passes installation, sign-in,
    preserved-data, Range-host Hunt performance, rollback-readiness, and operator
    acceptance checks; it is not Range-accepted, mission-ready, or available on `main`.

### Deviation history

| Date | Phase | Planned | Revised / Implemented | Reason | Impact / Follow-up |
|---|---|---|---|---|---|
| 2026-10-21 | Phase 6.1 Tier A summary export | Ingest the lowest-cost native Arkime summary export before higher-volume session correlation | Accept one bounded, explicitly NCT-defined Summary CSV v1 with a fixed ordered header, explicit Network Scope, observation point, query window, bounding and query context, declared grouping/export/capture coverage, exact source bytes and separate immutable grouped receipts. Preserve counts as exact decimal text at the API/browser boundary and never add counts across files | No stable native Tier A Arkime export contract has yet been verified in the isolated Range. Guessing a native format or calculating completeness from aggregate rows would turn operator-provided context into an unsupported evidence claim | Native-format compatibility remains a separate gate. Recorded completeness is declaration-based and cannot be independently verified from the CSV. These rows do not create current hosts or services, prove an open listener, establish Last Seen, contact Arkime or feed downstream correlation yet, so Phase 6 remains partial |
| 2026-10-20 | Phase 6 initial passive intake | Begin Arkime support with the lowest-cost Tier A summary export | Begin with a bounded manual Tier D Sessions JSON intake using an exact retained source, explicit Network Scope, sensor, query window and completeness declaration. Retain exact bytes in the Artifact Registry and publish immutable normalized session receipts only after whole-file validation. Do not ingest PCAP, contact Arkime, infer coverage, merge observations across imports or treat passive traffic as proof of an open listener | The isolated range validation produced a structured Arkime export, while no verified Tier A export is yet available. The retained Range file is not available on the development workstation, so the first adapter is checked against the documented Sessions API shape and representative fixtures without resuming the unstable range host | Tier A remains required and Phase 6 remains incomplete. This first slice is capped for interactive use, reports partial and unknown coverage explicitly, preserves overlapping observations separately and requires the retained Range export to pass a separate compatibility check before Range readiness or any high-volume, live API, correlation or timeline work |
| 2026-10-13 | Phase 3 Range recovery and clean-state acceptance | Recover preserved data through the guarded Phase 3 R3 path after identifying the stopped source container's HTTPS binding | Read the binding from the stopped container's saved configuration and fail closed for missing, multiple, or invalid values. Preserve the exact schema-origin guard: the retained `phase2-r2` database remains ineligible for the supported late-phase2 recovery path. After the operator declared the retained NCT evidence and accounts nonessential, perform an explicitly authorized NCT-only reset and validate a fresh Phase 3 R3 install | `docker port` cannot report the binding of a stopped container, and the retained database came from a different schema origin than the reviewed preserved-data migration boundary | Clean-state Phase 3 R3 Range acceptance passed. Preserved-data migration from `phase2-r2` remains unclaimed. The running Range image is unchanged; the recovery-helper correction must be included in a future transfer package |
| 2026-10-13 | Phase 3 Range schema compatibility | Require unconditional equality between the recorded schema fingerprint and the live database before every version 4 to version 5 upgrade | For version 4 to version 5 only, permit a mismatch solely when every present late phase2 maintenance group is complete and exactly matches the known SearchSploit cache, Artifact Registry backfill, or exact-content compaction definitions, and removing an allowed subset reproduces the recorded version 4 fingerprint. All altered, incomplete, unrelated, later-version, and otherwise unexplained drift still fails closed | The `phase2-r4` build legitimately created these maintenance tables after sealing its version 4 fingerprint. The first `phase3-r1` Range attempt therefore rejected supported phase2 state even though the migration guard correctly protected the saved database | `phase3-r1` is withdrawn. Version 5 now initializes all supported maintenance schemas before sealing its fingerprint. No Range fingerprint is rewritten and no retained maintenance state is deleted. The replacement requires a read-only stopped-database audit, a new exact package, guarded retry, preserved-data checks, and independent review before Range acceptance |
| 2026-10-13 | Phase 3.6 adaptive collection | Let Mission Environment guide collection and show relevant pivots | Enforce the first adaptive gate only where the operator selected exact Saved Network records and reviewed their current Network Scope associations and Mission Environment declaration versions. Any reviewed Nmap-prohibited scope blocks preview, portable package generation, active-run admission, enabled schedule creation, schedule enabling, manual occurrence creation and final waiting-occurrence dispatch. Manual targets and unassociated Saved Networks remain Unknown even when their CIDRs overlap a scope. Arkime/Kibana guidance appears only when the tool is declared available and that exact scope declares available or partial coverage | Addresses, CIDRs, names, previous evidence and tool installation cannot safely establish mission authorization. Exact Saved Network leaves plus optimistic versions provide a reviewable boundary that can be rechecked in the same transaction before accepted work is retained or contact can begin | This supersedes only the non-enforcement portion of the declaration-first deviation below. Authorized remains descriptive and does not grant permission; existing operator authorization and No-Strike controls remain authoritative. Multi-scope selections are reviewed separately and one prohibited scope blocks the complete request. Actual Arkime/Kibana queries, evidence ingestion and broader analysis adaptation remain open, so Phase 3 is still incomplete |
| 2026-10-13 | Phase 3 Mission Environment authorization | Use Mission Environment declarations to guide collection and analysis | The first slice stores and displays administrator-reviewed availability, coverage, authorization and blind-spot declarations. It does not grant permission, block scans, or change analysis. Existing authorization procedures and No-Strike controls remain authoritative | A durable, reviewable declaration layer must exist before it can safely affect network contact. Inferring permission from installed tools, addresses, names, targets or old evidence could authorize activity that an operator did not approve | Unknown is the default; Nmap-prohibited is derived into the blind-spot view; later reviewed gates must add scope-aware warnings/enforcement, adaptive pivots and Arkime/Kibana use. This is an accepted declaration-first deviation and Phase 3 remains incomplete until those gates pass |
| 2026-10-12 | Gate 7 shared storage | Make PostgreSQL or object storage a dependency for ordinary standalone NCT, or place SQLite behind a sidecar/network service | Preserve embedded SQLite plus local content-addressed files for standalone and single-replica operation. Select PostgreSQL as the future multi-replica transactional authority and an S3-compatible immutable content-addressed object API as its artifact authority. Keep the profile disabled until implementation plus Gate 8 concurrency/failure testing passes | The approved offline package must remain portable and efficient. SQLite cannot safely provide multi-replica transactional authority through a sidecar, while a shared writable filesystem would leave artifact behavior tied to path and mount semantics. PostgreSQL supplies shared transactions and database time; the object contract supplies immutable conditional creation without making listing authoritative | Migration is offline into an empty target with a verified cold backup, exact artifact inventory, stable-ID preservation, a cutover receipt and no dual writes. Before the target admits a write, cut back to the unchanged source is allowed. After any target write, preserve the target and restore/reconcile through a separate reviewed generation; automatic reverse migration is not claimed. See `docs/SHARED_STORAGE_ARCHITECTURE.md`. |
| 2026-10-12 | Gate 6 scheduled occurrence controls | Treat pausing a schedule as a stop request for any occurrence that has not started its next chunk | Define Pause future occurrences as a cadence control only. An already-created occurrence retains its complete frozen chunk plan and may continue; stopping that occurrence uses the scan cancellation path. Protect the cadence control with a monotonic control revision so worker progress cannot overwrite a concurrent pause. If ownership is lost after contact, later chunks remain blocked until an administrator verifies the former scanner stopped and records a reviewed closure; the ambiguous chunk never reopens | A durable occurrence is one authorized execution with one immutable plan. Silently changing or partly discarding that plan when the reusable cadence is paused would make the occurrence record disagree with what was authorized. Operators also need separate, explicit meaning for pausing future work and stopping contact already assigned | Schedule actions and the Operator Guide state the boundary. Reviewed closure records actor, reason and confirmation, cancels only unstarted chunks, clears exact recovery blocks and leaves future cadence paused. Tests must retain pause-race, recovery-closure and later-chunk blocking coverage. |
| 2026-10-12 | Kubernetes acceptance gate 5 | Let the NCT application use a namespace-scoped read-only Kubernetes client | Keep all Kubernetes credentials out of the NCT application. Run the optional reader as a separate bounded workload with a dedicated projected short-lived token, namespace Role and ServiceAccount; NCT consumes only its coarse sanitized status over a fixed internal service name | A token in the NCT web container would unnecessarily expand the consequence of an application compromise, and a sidecar could couple adapter failure to NCT Pod readiness. Kubernetes RBAC also cannot restrict list permission by labels, so application filtering alone cannot make a shared namespace least privilege | The first profile requires an NCT-only namespace. In a shared namespace the credential can technically list other Deployments, ReplicaSets and Pods even though the adapter requests fixed labels, validates the exact Deployment ownership chain and returns no identifiers or raw objects. Metrics permission is a separate opt-in. Local tests cannot prove target-cluster authorization, namespace isolation, API networking or Metrics API behavior; exact-cluster denied, timeout, truncation and no-metrics exercises remain required. |
| 2026-10-12 | Kubernetes acceptance gate 4C | Permit an ordinary image rollback after testing a candidate image | Default to restore-based rollback. Direct rollback is machine-authorized only when the old image's own contract proves that it can both read and write the exact current schema version, uses the same evidence-layout contract, and shares the completed migration-plan digest. Changed or unknown compatibility preserves the candidate claim and restores the verified pre-upgrade backup into a separate empty qualified target | Commit `cb7453e` had no authoritative global schema-compatibility contract. SQLite `user_version` and a schema fingerprint can detect a difference but cannot prove semantic read/write compatibility, and the existing startup schema work spans multiple module-owned transactions. A new image cannot safely declare an old image compatible on its behalf | Application startup now owns a versioned schema contract and durable migration ledger, remains unready until migration completion, and fails closed on unreadable saved state. The Gate 4C administrator package binds exact images, builds, runtime identities, storage, backup, schema, registered evidence, counts, access checks and downloads. The foundation package cannot prove Kubernetes scheduling or CSI behavior; compatible and restore-required branches still require exact-cluster exercises. See `docs/KUBERNETES_SINGLE_REPLICA.md` |
| 2026-10-10 | Kubernetes acceptance gate 3C | Let the first single-replica web Deployment retain active scan and device-collection capability | Make the first Kubernetes web profile analysis only: exactly one `Recreate` replica, forced local authentication, no API token or RBAC, all Linux capabilities dropped, and server/UI enforcement that disables Nmap, scheduled execution, SSH device contact and packet capture. Keep import, upload, saved-evidence processing, analysis and portable scan-package creation available. A later collection worker must receive a separately reviewed placement and minimum-privilege profile | Web replicas cannot assume mission-network reachability and must not automatically inherit raw-network privileges. Combining the first SQLite/PVC acceptance gate with active collection would hide a materially different security and placement boundary | The renderer requires one exact image digest and a matching passing exact-PVC qualification report from the same numeric user/group. The built-in guide, System Health, scan and device pages expose the analysis-only boundary. This does not block the standalone profile and does not establish live collection, Range, mission or multi-replica readiness. See `docs/KUBERNETES_SINGLE_REPLICA.md` |
| 2026-10-10 | Deployment architecture | Keep Kubernetes, external databases and server infrastructure outside the requirements for core offline use | Preserve the standalone single-container profile while requiring new runtime, job, storage, identity, health and deployment designs to remain compatible with a future Kubernetes profile. The initial Kubernetes profile remains exactly one NCT application replica; multi-replica operation is blocked until cross-process leases, singleton-operation coordination and a reviewed shared database/artifact design exist | The user wants the full platform developed with Kubernetes capabilities in mind without losing disconnected-Range operation or forcing a cluster onto small deployments | Provider-neutral local health comes first, followed by an optional namespace-scoped Kubernetes adapter. SQLite volumes must pass lock, atomic-rename, `fsync` and WAL/SHM qualification; RWO alone is insufficient. Upgrades must prevent an older image from opening an incompatible newer schema. See `docs/KUBERNETES_ARCHITECTURE.md` |
| 2026-10-09 | Phase 0 rendered-browser benchmark | Run the same Chromium build inside isolated Linux benchmark containers | Use one SHA-256-identified local Windows Chrome/Playwright build for every repeat. Keep each NCT app on a unique internal-only Docker network and reach it only through a disposable dual-network relay published on `127.0.0.1`; block every non-loopback browser request and record the app, relay, network, browser process tree and cleanup identities | No compatible browser image is installed locally and the NCT Linux test image contains no browser executable; Docker Desktop does not publish a host port directly from an internal-only network | Preserves isolated app/data/source execution and equal browser settings across revisions while clearly limiting the result to same-host Windows Chrome. The relay is not part of NCT or a deployment package. No Linux-browser, Range, GPU, human-workflow, production-scale or mission-performance claim is made; those remain separate gates |
| 2026-10-08 | Whole-network current device selection | Reuse Device History's newest records and its existing device-analysis cache | Maintain a rebuildable SQL selector for every active supported device collection, rank only eligible verified summaries per device by retained completion/creation time and run identifier, surface selected integrity conflicts, then reuse one serialized private current-device analysis only when a read-only snapshot proves its exact admission, result, provenance, retained bytes, scope-observation, WAN, contract, and database inputs are unchanged | Device History's global 100-record window could hide an older distinct device, manifest filesystem time is not a stable evidence ordering contract, and the old cache returned a shared mutable object while omitting exact evidence, scope, and WAN inputs | Source authority and retained evidence remain unchanged. Formatting-only parsed-manifest changes do not affect selection, while raw manifest bytes still invalidate analysis reuse. Rollback writes are detected and repaired on startup. A damaged newest eligible record is visible rather than hidden by an older record. Cold cache builds are read-only, warm entries invalidate on every captured dependency and database replacement, and changing inputs retry once before a visible conflict |
| 2026-10-08 | Whole-network current-view performance | Persist the assembled network model as another reusable derived-result family | Use one-entry, process-local serialized caches keyed by exact canonical descriptors, with per-descriptor single-flight builds and pre/post-build source validation. The current evidence view, current device analysis, and Map topology each retain their own exact dependency boundary while shared consumers reuse private serialized copies. Project Current Network host/detail pages from the complete exact-source model with revision-bound server paging | The assembled views combine immutable evidence with mutable analyst identity/OS choices, Saved Network labels, offline OUI data, and filesystem-backed legacy inputs. Persisting those mixed presentation models would create invalidation and migration authority that the evidence pipeline does not yet define | Evidence remains authoritative; unverifiable or changing inputs bypass reuse; restart, rollback, database replacement, selected evidence changes, OUI changes, and calculation-contract changes rebuild. Map and Current Network share one exact topology calculation. Current Network responses and browser work are bounded to 100 hosts while LFA and export retain complete-filter semantics. The backend still assembles the complete reusable model, and specialized Hunt, Reach, and Map payload paging plus representative large-installation benchmarking remain future scale work |
| 2026-09-27 | Phase 1 | Add SQLite WAL/busy-timeout reliability controls | Existing code already had WAL + 30s busy timeout; foundation work is focusing on eliminating repeated schema initialization and long/redundant write paths instead of re-adding WAL | Repository inspection showed WAL was already enabled at startup | Continue auditing storage modules for request-path DDL and lock-heavy patterns |
| 2026-09-27 | Phase 1 | Cache Searchsploit enrichment by normalized service fingerprint | First implementation caches the sanitized Searchsploit query keyed to the active Exploit-DB dataset identity | Current enrichment already deduplicates findings into normalized queries; persisting that boundary provides the same reuse benefit with less invasive change | Later canonical Service entities can reference this cache rather than replacing it |
| 2026-10-08 | Phase 1 candidate evidence | Use the dataset-scoped SearchSploit query cache as the reusable Hunt enrichment boundary | Keep the query cache as an execution aid, but publish an immutable candidate assessment during new supported scan ingestion. The saved identity binds exact Nmap bytes, offline dataset metadata, and the SearchSploit executable digest; each uncached query must report the frozen database path. Hunt reads that saved result, while route/policy exposure is calculated separately from current retained context | Field report #38 required page reads to stop recalculating candidates, and review showed that cache warmth, failed commands, executable changes, or a mismatched configuration file could otherwise change or mislabel the same evidence | Existing cache entries use a new executable-bound namespace. Failed queries publish no result. Historical/manual adoption and reassessment against a newer dataset require future explicit operator actions and do not occur on Hunt reads |
| 2026-09-27 | Phase 1 entities | Establish canonical Host, Service, Network, and Device entities with normalized ingestion and correlation | The initial internal slice implements explicit-scope IPv4/IPv6 address endpoints, TCP/UDP/SCTP transport endpoints, and immutable artifact-backed assessments. These are scoped endpoint identities and observations; they do not claim physical Host or Device reconciliation | Addresses can overlap across network contexts, and retained evidence does not yet provide a reviewed stable identifier and assignment rule for safely merging endpoints into physical systems. Existing Saved Networks are editable target selections, so they cannot provide canonical identity or automatic scope inference | Automatic scope inference and physical Host/Device reconciliation remain deferred. Whole-artifact assignment and correction semantics are reviewed and append-only. Manual imports and eligible finalized scans now use the server-side coordinator to atomically commit assessments, receipts, and immutable assignment links. The first read-only scoped evidence explorer is tracked under Phase 1 steps 3 and 13; it does not select current truth or infer device identity. |
| 2026-09-27 | Phase 1 ingestion wiring | Replace current import consumers with normalized scoped ingestion | First expose an explicit, post-import, observation-level foundation workflow for manual Nmap uploads beside the unchanged legacy analysis path. Assignment creation, correction and retry remain separate recoverable operations. Administrators manage scope identities; analysts and administrators apply reviewed evidence context; viewers are read-only; authentication-disabled mode attributes changes to the local operator | Replacing current Analyze, Hunt, Reach and Map consumers in the same step would combine evidence-model migration with a new operator audit workflow and risk stable behavior. Exact observations also cannot be represented safely by the current hash-grouped import history | Temporary dual processing and storage are expected. Assigning a scope does not change current views. Automated scan artifacts, inference, mixed-scope partitioning, bulk migration and read-model replacement remain separate gates. The observation-level status/history API and UI must make incomplete processing recoverable without creating another observation or assignment root |
| 2026-09-27 | Phase 1 | Nmap imports remain readable through the existing `/data/imports` path model while Artifact Registry is introduced | New imports are stored in the canonical content-addressed artifact store; the raw-download guard was revised to trust either a verified legacy import path or the exact path registered for that SHA-256 | CI exposed that the legacy download endpoint intentionally rejected paths outside `/data/imports` | Preserves existing download behavior while enabling deduplicated storage; legacy imports remain supported during migration |

| 2026-09-27 | Phase 1 | Introduce Artifact Registry without changing existing import behavior | Artifact Registry integration initially caused the existing raw Nmap download test to reject canonical artifact paths; compatibility validation was updated and the subsequent full CI run passed | Legacy endpoint assumed all imported XML lived directly under `/data/imports` | Treat legacy file-layout assumptions as migration compatibility requirements; no Phase 1 item marked complete until green CI |
| 2026-10-03 | Phase 1 delta detection | Classify evidence as `new`, `changed`, `unchanged`, `no longer observed`, or `not assessed` | Begin with an explicit Record A / Record B comparison of reported service states for one scoped address; label one-sided receipts `recorded only in A/B` | Current Nmap receipts preserve reported protocol/port states, but target and port coverage may be unknown or incomplete and processing order does not establish observation chronology | Keep Phase 1 delta detection incomplete. One-sided receipts remain missing evidence, not disappearance or a newly present service. Current-state selection, Last Seen, automatic baselines and coverage-backed lifecycle labels remain separate gates |
| 2026-10-03 | Phase 1 delta coverage | Add lifecycle labels directly from existing Nmap assessment receipts | Add a versioned coverage-receipt contract first; keep lifecycle labels blocked until records prove successful completion, non-overlapping collection order, confirmed host response, exact protocol/port inclusion and complete omitted-port accounting | Review found that requested `scaninfo` ports alone do not prove probe completion, host-level `extraports` were not retained, and multi-phase aggregate XML can mix host timing from one phase with completion time from another | Existing `nmap-endpoints:1` assessments remain readable as historical evidence and do not silently gain stronger claims. Reprocess a current assignment with `nmap-endpoints:2` to create coverage receipts. Ambiguous, incomplete and combined-phase evidence must explain why it is ineligible and resolve to `not assessed` when lifecycle classification is added |
| 2026-10-03 | Phase 1 persistent derived results | Introduce the common derived-result model after persisting additional analysis families | Establish a minimal immutable result store and one verified Nmap base-analysis adapter before replacing any production cache read | Existing scan analysis reuse is keyed by file size, modification time and a local integer version. Device summaries and exposure reports have broader dependency and retention contracts that are not yet safe to generalize. Exact computation identity and atomic publication must be proved before migration | This deliberately introduces family/version identity and immutable input manifests ahead of the broader dependency-graph and analysis-versioning milestones. The first adapter contains only `parse_xml()` output for one verified artifact; run grouping, scope, provenance, overrides, enrichment and current-state claims remain outside. Existing production cache paths remain unchanged pending a separate quality gate |
| 2026-10-03 | Phase 1 production Nmap result migration | Replace the legacy size/modified-time scan-analysis cache in one step | Migrate only authoritative finalized `nmap_scan` observations for each run's exact `scan.xml`; parse unregistered historical scan XML directly without caching until explicit backfill registers it | Finalized run-local XML may be a separate copy from canonical artifact storage, historical scans may have no registry observation, and page reads must not create evidence or perform implicit backfill | Every registered terminal-run analysis verifies both run-local and canonical bytes. Ambiguous, missing, changed or corrupt registered evidence fails explicitly. Per the user's direction that the verified store is the new supported method, disposable legacy cache rows and their table are removed during storage initialization; rollback code can recreate an empty table. Historical scan XML and provenance are not deleted. Unregistered historical files remain usable at the temporary cost of repeated full parsing and verification. Run grouping, scope, overrides, enrichment, provenance, current-state claims and foundation explorer reads remain outside this migration |
| 2026-10-03 | Phase 1 topology result migration | Reuse the production Nmap base-analysis payload in Map and device correlations | Preserve the existing topology reader as a separate immutable result family while sharing exact scan-source verification and publication safeguards | The topology reader intentionally differs from Analyze presence semantics: directly substituting the base payload would remove assumed, down, or otherwise legacy-visible host records and change missing-value handling, ordering, and service defaults | Migrate only automated Map and device-correlation XML reads. Keep graph assembly, source context, device correlation, imports and existing record limits outside the reusable payload. Correcting legacy topology interpretation requires a separate evidence-semantics gate. Device-summary caching remains deferred until its multi-file and command-history dependency contract is defined |
| 2026-10-03 | Phase 1 device-summary result migration | Replace the device summary cache as one production change | Stage the work: first extract a frozen snapshot calculation and internal verified adapter, then gate production reuse for finalized manual uploads before broader collected-device migration | Device summaries select among multiple ordered files, distinguish missing from empty history, consume semantic manifest fields, preserve full routes, normalize command history, and can race collection deletion. Manual uploads and active collections also use different Artifact Registry identities | Per the user's direction, every new manual upload now uses the verified method and cannot fall back to the old cache. A durable lifecycle authority moves from preparing to active only after the file, observation and atomic manifest are verified; deletion leaves a permanent marker before file cleanup. Existing historical, partial and multi-file device collections remain readable through their established path until an explicit adoption gate. Page reads do not create authority or backfill evidence. Full legacy cache retirement remains a later startup migration after those dependent paths move |
| 2026-10-03 | Phase 1 finalized SSH device-summary migration | Keep the old summary path available for completed multi-file collections until historical adoption is designed | Make verified authority the only supported analysis path for every new completed, untruncated key-based or interactive SSH collection. Freeze configuration, raw-output and command-history roles with exact observations, ordered candidates, content identity and semantic inputs. Failed, timed-out, cancelled, expired or truncated collections retain their files but do not publish analysis. Historical collections retain history and downloads but return an explicit conversion-required status instead of running the old summary path | The user explicitly selected the verified method as the new way to operate and authorized retiring the old processing route. Silent fallback would allow a new collection with missing authority or changed bytes to bypass the evidence safeguards | Collection outcome and verification outcome remain separate. A completed collection whose local verification is interrupted stays completed, shows a verification conflict, and can retry locally without contacting the device or creating duplicate observations. The lifecycle row's single artifact fields remain a compatibility pointer to the selected configuration; immutable per-role child inputs are the complete authority for configuration, raw output and command history. Existing legacy cache tables and rows are preserved for rollback and future reviewed migration, but production reads and new collections no longer use or write them. Historical adoption and any later cache-table deletion require a separate non-destructive migration gate |
| 2026-10-03 | Phase 1 dirty-state tracking | Persist a mutable current/stale flag and propagate invalidation before dependency tracking exists | Begin with a read-only calculation-contract status for the three reusable families already in production. Compare retained analysis version, output schema and declared settings to the running build's shared trusted contracts; label exact matches current, known mismatches stale and unknown or unreadable contracts unknown | A mutable flag can drift from immutable result metadata, and there is no reviewed dependency graph or worker capable of safely propagating or rebuilding dependent work yet | This is a partial Step 7 implementation and an early limited Step 9 dependency. Current means only that the calculation contract matches this build; it does not claim that evidence is recent, intact or current on the network. Dependency propagation, input freshness, scheduling and stale-only recomputation remain open |
| 2026-10-03 | Phase 1 dependency graph | Add graph tables and invalidation propagation before a worker and rebuild contract exist | Begin with a read-only Inputs and source records drill-down derived from the existing immutable result manifest, input rows and exact artifact-observation links | The three production reusable families already retain direct input edges and provenance links. Copying them into a second graph can drift, while propagation has no reviewed scheduling or failure behavior yet | Treat a declared input as a direct calculation dependency and an observation link as provenance for that exact role, not another dependency. Verify the saved identity and rows before display; page roles and source encounters separately. Do not infer deleted provenance, inspect source bytes, mark results dirty or schedule rebuilding. This is partial Step 8; reverse impact, result-to-result edges, propagation and scheduling remain open |
| 2026-10-03 | Phase 1 reverse dependency lookup | Predict invalidation impact and propagate dirty state | Add a read-only, indexed lookup from one verified input role to saved calculation records that declare the same input kind and exact identity | Automatic invalidation has no reviewed result-to-result graph, scheduling or rebuild behavior. Existing immutable input rows can safely expose recorded direct relationships without creating mutable graph state | Show verified direct relationships separately from unsupported saved-record candidates. Preserve repeated roles, page candidates deterministically, and validate each supported relationship against its saved computation identity and manifest. This does not predict that a changed file would invalidate an immutable result, inspect source bytes, traverse indirect dependencies, mark work stale or schedule rebuilding. Step 8 remains partial |
| 2026-10-03 | Phase 1 analysis versioning | Add global invalidation and selective rebuild behavior | Add a read-only saved-calculation version inventory for the three migrated reusable families before defining durable rebuild jobs | Exact family, rule version, output schema and settings are already retained and classified, but no reviewed persistent-job contract can safely turn compatibility differences into scheduled work | Group exact retained contracts without merging differing settings, show Current/Stale/Unknown and bounded result drill-down, and keep malformed or unfamiliar groups visible. Counts describe saved calculations, not scans, observations, evidence freshness or jobs required. Other analysis families, invalidation, upgrade handling and selective rebuilding remain open, so Step 9 is partial |
| 2026-10-03 | Phase 1 persistent analysis jobs | Begin with bulk rebuilding from saved-version groups and automatic stale scheduling | Begin with one explicitly requested durable job for the current Nmap base analysis of one authoritative finalized scan encounter | A version group can contain several encounters, an old result does not by itself authorize current processing, and bulk/automatic rebuilding needs dependency selection, batching, cancellation and partial-success rules that are not yet reviewed | Resolve the exact run, observation, digest, size and current calculation contract on the server; keep request identity separate from calculation reuse and encounter provenance; use durable attempt history, restart recovery, short atomic claims, source/authority rechecks and atomic job-result completion. Initially exclude topology, device summaries, historical unregistered files, bulk requests, cancellation, automatic retries and automatic stale scheduling. This is a bounded Step 10 implementation and an early limited Step 11 runner |
| 2026-10-03 | Scan History subnet grouping | Keep the global newest-25 record window and page older records outside subnet dropdowns | Build a read-only catalog across retained scan metadata, group by each exact recorded canonical CIDR, and page scan rows inside that subnet's dropdown | Operators could not find older scans after global history paging, and Saved Network IDs could split the same subnet after rename, archive or recreation | This is a user-directed presentation and pagination correction, not canonical identity merging. Different prefixes stay distinct; scope, Saved Network snapshots, attribution, provenance and exact run actions remain per scan. Multi-subnet scans may appear under each exact recorded subnet with an explicit cross-target note. Host lists and invalid or missing legacy targets remain honestly labelled fallback groups. Catalog and row requests stay bounded and never open XML or artifact files |
| 2026-10-08 | Scan History large-data paging | Rebuild the subnet catalog and filter every group page from all retained manifest metadata | Maintain a disposable normalized membership index and compact group summary in the scan database; synchronize current writes in their transaction, use pure-SQL dirty markers for writes made by rollback builds, repair those markers at foundation startup, and backfill existing manifests once | Field report #30 and code review showed that response pagination still performed O(total history) JSON decoding and grouping for every request. Persistent triggers that require a new application-defined SQL function would break older builds after rollback, so the derived index must remain backward-compatible | The index is derived and can be rebuilt; it never replaces or edits evidence. Exact CIDR, manual-host, legacy, missing-target, multi-group, provenance, and stable-cursor semantics remain unchanged. Tests cover migration, current updates, plain-SQL rollback writes and repair, deletes without foreign-key enforcement, legacy cursor paging, bounded routes, and fallback prevention. Other whole-network scale paths remain open |
| 2026-09-27 | Phase 1 storage | Replace historical duplicate files during migration | Backfill creates verified canonical copies and checkpoints but retains every historical original; new finalized collections use atomic hard-link replacement with a copy fallback | Existing consumers still depend on run-local paths; deleting historical evidence requires a separate rollback and reference-recheck gate | Backfill can temporarily increase used space. Optional compaction remains unimplemented and disabled |
| 2026-10-04 | Phase 1 supported ingestion completion | Treat separate completed foundation features as a complete ingestion pipeline | Finish one durable staged pipeline for currently supported Nmap and device evidence; keep scope-free calculations separate from scoped observations and require explicit scope where needed | Existing operator actions use different persistence, retry and status models, and planned passive collectors or physical-device reconciliation would expand this gate without a safe identity contract | Missing scope is Needs scope, never inferred. Preserve every completed stage when another fails. Generalize the existing single-process worker through additive, preservation-tested pipeline tables, then connect intake, current-state/Last Seen receipts and acceptance benchmarks. The copied legacy queue becomes a trigger-enforced read-only audit archive. All processes must cut over together; ordinary rollback is unsafe because older code cannot see post-cutover work and cannot write the frozen queue. Historical adoption stays explicit and passive collectors remain later phases. See `docs/DERIVED_RESULTS.md` |
| 2026-10-04 | Phase 1 automatic Nmap admission | Find new eligible work by scanning timestamps or all retained evidence after startup | Mark only new participating manual Nmap observations and scan runs, then commit a frozen admission intent with the authoritative assignment or eligible scan finalization before the durable worker creates a job | Timestamp selection can silently adopt historical evidence, miss work across clock changes, or switch a retry to a corrected assignment or newer parser. Making immediate job creation part of evidence retention would also make a successful import, assignment or scan depend on queue availability | Admission intents preserve the exact source, scope decision, actor and processing contract while allowing queue admission after the source transaction. Startup and worker recovery examine only pending intents from explicitly marked sources. Historical rows keep the explicit Queue action; missing scope remains Needs scope; corrections create new intents and cannot redirect older work. This gate covers new manual and automated Nmap evidence only. Device intake, processing retries, current-state selection and Last Seen remain separate gates. |
| 2026-10-04 | Phase 1 automatic device-summary admission | Calculate verified device summaries while opening a page or silently adopt every active authority after upgrade | Mark only new participating manual uploads and eligible SSH collections, freeze an admission intent when exact device authority activates, then calculate through the shared durable worker | Page-time calculation can race authority changes and makes navigation perform expensive work. Broad startup adoption would silently change historical processing behavior | Device summaries are scope-free reusable calculations. Their intents retain the authority revision, selection contract, semantic manifest and ordered exact inputs. Historical unmarked authorities keep their established on-demand behavior until a separate adoption gate. At this admission gate, failed or interrupted calculation required explicit local retry and never contacted the device; Gate 6 later supersedes that retry limit with one fenced recovery attempt from retained evidence. Normalized device observations, Network Scope assignment, physical-device identity, current-state selection and Last Seen remain later gates. |
| 2026-10-04 | Phase 1 latest supported observations / Last Seen foundation | Build a broad current-state model and exact Last Seen behavior after canonical entity storage | First add a versioned, read-only selector for one scoped Nmap address that separately reports the latest supported source window and the last confirmed positive source window | Existing immutable receipts can safely order scoped Nmap observations by validated source collection windows, but they cannot yet prove physical-device identity, live state, exact per-service time, device-configuration scope, or disappearance | Identity remains Network Scope plus IP address. Only current unsuperseded assignments, the supported parser, successful completion and valid source windows may participate. Equal or transitively overlapping windows remain grouped; successful unknown-time records remain visible and block an unqualified latest claim. Every displayed observation links to its retained evidence. A later assumed or incomplete record cannot erase earlier confirmation. This completes only a nested Steps 13-14 slice; broader current state, physical-device reconciliation, device observations, service absence and exact Last Seen remain open. See `docs/ENTITY_FOUNDATION.md` |
| 2026-10-10 | Phase 1 current reported service state | Treat a selected latest record, upload time, processing time, or scan run ID as current network truth | Add a versioned, read-only selector for one exact IP address in one Network Scope that determines the latest defensible source-reported state independently for each protocol and port | Current immutable Nmap receipts can prove source collection order and exact port coverage for a bounded set of successful records, but they cannot prove live status, physical-device identity, exact Last Seen, or disappearance. A later narrower scan must not silently inherit an older service state | “Current” in this view means latest defensible source-reported state only. Only current unsuperseded assignments, `nmap-endpoints:2`, successful completion, strict non-overlapping host collection windows and `nmap-coverage:1` may participate. Unknown, equal, touching or transitively overlapping windows remain unresolved. A latest record that did not assess a port produces **Not assessed**; it does not carry the older state forward. TCP, UDP and SCTP remain separate. Results use saved database receipts only: they perform no artifact reads, artifact-content hashing, XML parsing, backfill, job creation or writes. The candidate ceiling is enforced before stored JSON payloads are decoded. A hash of assignment identity metadata may bind paging to the same read-only selection revision; it never reads or verifies evidence bytes. Results are paged, revision-bound, candidate-capped and source-linked. Upload, processing and run order are display-only. Physical-device reconciliation, live truth, exact Last Seen and disappearance remain open. See `docs/CURRENT_REPORTED_SERVICE_STATE.md` |
| 2026-10-04 | Phase 1 scoped device observations | Normalize verified device configuration directly into a broad current-device model | Add a collection-specific, explicitly scoped receipt stage after the reusable scope-free summary; reject mixed or unresolved routing contexts and retain configuration assertions separately from Nmap confirmations | The reusable summary is presentation-bounded, device configuration does not establish live presence or address time, and physical-device reconciliation does not yet have a reviewed stable-identity contract | Exact selected configuration bytes are verified before extraction. Append-only scope decisions, immutable interface/address receipts, atomic job publication, exact replay comparison and explicit coverage preserve evidence meaning. Missing or failed normalization preserves the completed summary. This completes a bounded nested Step 13 slice; physical identity, live status, broad current truth and exact Last Seen remain open. See `docs/DEVICE_OBSERVATIONS.md` |
| 2026-10-04 | Phase 1 storage | Enable optional exact-content compaction after verified backfill | Add a separate administrator-confirmed action that replaces only reviewed exact copies with hard links to canonical content while preserving every logical evidence path and record | Independent adversarial review reproduced unsafe crash, journal, queue, path-substitution, recovery-integrity and confirmation-ownership cases during implementation; each case was corrected and retained as a regression | This is single-process maintenance. No second NCT process or external evidence edit may use the data directory during inspection, compaction or recovery. Files must share a filesystem and compatible security metadata; shared paths use canonical filesystem timestamps while recorded evidence timestamps remain. A durable recovery block stops all guarded evidence changes when safe repair cannot be proved. Estimated and measured savings are reported separately; automatic pruning stays disabled. See `docs/EXACT_CONTENT_COMPACTION.md` |
| 2026-09-27 | Phase 1 jobs | Use the future generic persistent worker | Storage inspection uses one explicit background operation per application process, a persisted status/report and per-file backfill checkpoints | The generic worker is a later Phase 1 item; Settings must not hash evidence during page reads | Interrupted jobs are shown as interrupted and can be explicitly rerun; deploy with the existing single application worker until cross-process scheduling is implemented |
| 2026-09-27 | Phase 1 reliability | Read-only storage inventory connection | Extended the shared database helper with read-only mode | Full regression testing caught the initial inventory bypassing the shared lock policy | Inventory now retains the common timeout and connection handling; no inventory-time schema writes |
---

# 1. Mission

NCT began as a network characterization platform. Its next generation expands that
mission into a persistent CPT-oriented network evidence, correlation, investigation,
triage, hardening, and reporting platform.

NCT should help an analyst answer:

- What exists?
- What is reachable?
- What is configured?
- What is actually communicating?
- What changed?
- What stopped being observed?
- What does not match expectations?
- What evidence supports the conclusion?
- Where should the analyst pivot next?
- What blind spots remain?
- What hardening action should be considered?
- What should be elevated to the Crew Lead or leadership?

NCT is **not** intended to replace Arkime, Kibana/Elastic, Nmap, packet capture,
SIEM, IDS/IPS, or device-management platforms.

Its role is:

> **Collect useful facts, normalize them, correlate them once, retain what has
> already been learned, identify what changed, expose uncertainty and blind spots,
> and make that knowledge immediately usable across the analyst workflow.**

---

# 2. Foundational Design Principles

## 2.1 Ingest once, enrich once, correlate once, query many times

```text
Collect
  ↓
Normalize
  ↓
Enrich
  ↓
Correlate
  ↓
Persist
  ↓
Query repeatedly
```

Expensive work happens because evidence is new or changed—not because an analyst
opened another page.

## 2.2 Pages do not own analysis

Analyze, Hunt, Reach, Map, Dashboard, Harden, and Report Composer should read shared
persistent results. They should not independently reparse source artifacts or rerun
the same enrichment.

## 2.3 New evidence creates a delta, not a rebuild

New or changed facts proceed downstream. Unchanged facts reuse existing results.

## 2.4 Evidence sources are peers

Nmap is important but not required. NCT must support characterization from any
combination of:

- Active scan evidence
- Arkime passive traffic evidence
- Kibana/Elastic evidence
- Network-device configuration evidence
- Routing/policy evidence
- Analyst-supplied/manual evidence
- Historical retained evidence

## 2.5 Absence is not the same as negative evidence

The system must distinguish:

- **Current / confirmed**
- **Not observed**
- **Closed**
- **Filtered**
- **Historical**
- **Not assessed**
- **Unavailable**
- **Prohibited**
- **Analyst asserted**
- **Stale / insufficient coverage**

## 2.6 Preserve provenance

Every important conclusion must be traceable to its source, collection time,
analysis version, confidence, and analyst additions.

## 2.7 Constrained-resource operation is a requirement

NCT must remain usable on limited range hardware. Avoid architecture that requires
Kubernetes, Elasticsearch, Redis, or an external database cluster just to use core
features.

## 2.8 Mission data must be portable and merge-safe across disconnected sites

NCT must support geographically separated, fully offline kits that independently
collect and analyze the same mission and later exchange mission state by removable
media.

This requirement applies to new persistent mission entities immediately, even before
the synchronization engine itself is implemented.

New mission-state designs must therefore prefer:

- Globally stable identifiers rather than installation-local identity.
- Append-only revision/event history for consequential analyst and mission changes.
- Explicit provenance for site, analyst, source evidence, revision, and processing.
- Merge-safe semantics that do not rely on wall-clock timestamps alone.
- Archive/tombstone behavior where absence from an export cannot be mistaken for
  deletion.
- Idempotent replay so the same bundle can be imported more than once safely.
- Exact artifact identity through the Artifact Registry.
- Separation of mission truth from machine-local configuration, credentials, and
  presentation state.

Do not introduce new persistent mission objects that can only be reconciled by
copying/replacing the SQLite database or by applying last-writer-wins semantics.

## 2.9 Kubernetes-compatible without requiring Kubernetes

Core NCT must continue to run offline as one container on constrained Range hardware.
At the same time, new work must avoid assumptions that prevent a future Kubernetes
deployment. Runtime identity, work ownership, health, storage, configuration and
mission identity may not depend on a container name, pod name, pod IP, local process
ID or installation-local row number.

The first supported Kubernetes profile is one NCT application replica. A ReadWriteOnce
volume is not proof of one writer because more than one pod can mount it on the same
node. The profile must also enforce one replica, no autoscaling, non-overlapping
replacement and fail-closed startup when a former writer may still exist. Multi-replica
application service remains blocked until the worker, database and artifact-storage
contracts explicitly support it.

Kubernetes awareness is optional and least-privilege. A denied or absent cluster API is
reported as unavailable rather than zero. See `docs/KUBERNETES_ARCHITECTURE.md` for the
design and acceptance gates.

---

# 3. Performance Budgets

Interactive responsiveness is a design gate, not an afterthought.

| Operation | Target |
|---|---:|
| Normal page load | < 500 ms |
| Cached Analyze results | < 1 sec |
| Normal filter/pivot | < 1 sec |
| Dashboard cross-filter | < 2 sec |
| Timeline filter | < 2 sec |
| Complex telemetry query | < 3–5 sec |
| Opening previously processed evidence | Near-immediate |

Long-running ingestion/enrichment may exceed these limits, but existing completed
analysis must remain usable while background work continues.

---

# 4. Entity Lifecycle and “Going Dark”

Hosts, ports, services, routes, and communication relationships are **not deleted**
simply because they are no longer seen.

Each entity should retain:

- First seen
- Last seen
- Last actively assessed
- Last passively observed
- Last positively confirmed state
- Current evidence state
- Historical states
- Evidence sources
- Confidence
- Link to supporting evidence

Example:

```text
10.20.4.17 TCP/8443

First seen:            18 Sep 2026 14:12
Last seen:             27 Sep 2026 09:42
Last active scan:      26 Sep 2026 08:31
Last passive evidence: 27 Sep 2026 09:42

Active state:          Not assessed since 26 Sep
Passive state:         Not observed after 09:42
Overall:               Historical / previously observed

[ View Last Evidence ]
```

## 4.1 Last Seen must always lead to evidence

A Last Seen timestamp should link to the evidence record that established it.

If detailed telemetry has expired under retention policy, NCT retains a lightweight
**evidence receipt** with:

- Entity/relationship
- Timestamp/window
- Evidence source
- Import ID
- Count represented
- Original artifact provenance
- Retention status

Pinned evidence attached to an Investigation Lens, Finding, Recommendation, or
Report is protected from automatic pruning.

---

# 5. Core Data Architecture

NCT will separate data into four layers.

## 5.1 Source Artifacts

Examples:

- Nmap XML
- Arkime exports
- Kibana/Elastic exports
- Router/firewall/switch configuration
- CLI command output
- Analyst imports

Each artifact receives:

- Artifact ID
- Cryptographic content hash
- Source type
- Owner/analyst
- First imported
- Last encountered
- Parser version
- Processing status

Identical artifacts are not fully reprocessed.

## 5.2 Normalized Facts

Canonical entities include:

- Host
- IP
- MAC
- Subnet
- Port
- Protocol
- Service
- Device
- Interface
- Route
- Policy
- NAT relationship
- Communication relationship
- Observation

The application works from normalized facts rather than reparsing source files.

## 5.3 Derived Knowledge

Persist results such as:

- Searchsploit enrichment
- Service identity
- Scan comparison
- Active/passive correlation
- Reachability
- Network paths
- Timeline events
- Findings
- Hardening recommendations
- Coverage/blind-spot assessments

Each result records its inputs, dependencies, analysis version, generation time,
and current/stale state.

## 5.4 Analyst-Ready Read Models

Prepared views should support fast reads for:

- Current hosts
- Current services
- Current routes
- Current findings
- Current passive relationships
- Active/passive mismatches
- Historical changes
- Timeline events
- Evidence coverage
- Crew Lead summaries

---

# 6. Storage Strategy

## 6.1 SQLite

Continue using SQLite for structured application state:

- Users/roles
- Settings
- Saved networks
- Artifacts
- Hosts/services
- Devices/routes
- Findings/recommendations
- Enrichment cache
- Jobs
- Lenses
- Dashboards
- Tasks
- Comments
- Report definitions
- Audit/provenance

Required reliability work:

- WAL mode
- Busy timeout
- Short transactions
- Controlled write paths
- Reduced repeated initialization
- Removal of unnecessary storage initialization from normal read/API paths

## 6.2 Parquet for higher-volume telemetry

Arkime/session-style telemetry may be stored in columnar files rather than inflated
SQLite tables.

## 6.3 DuckDB evaluation

Evaluate embedded DuckDB queries over Parquet for fast local analytics without
adding another server.

No core requirement for PostgreSQL, Elasticsearch, Redis, or Kubernetes. Designs must
still preserve the future Kubernetes boundaries in `docs/KUBERNETES_ARCHITECTURE.md`.

---

# 7. Searchsploit and Enrichment Strategy

Searchsploit must not rerun per host when the same service fingerprint repeats.

Example:

```text
143 hosts → OpenSSH 9.2 → one enrichment record
 78 hosts → nginx 1.24   → one enrichment record
```

Enrichment keys should use normalized service fingerprints such as product,
version, CPE, and relevant protocol identity.

Re-enrich only when:

- Fingerprint changes
- Searchsploit dataset changes
- Enrichment logic version changes
- Analyst explicitly requests refresh

Previously valid results remain available while an update is processing.

---

# 8. Processing and Dependency Model

## 8.1 Persistent jobs

Long-running work uses a persistent job model:

- Queued
- Processing
- Complete
- Partial
- Failed
- Cancelled

One failed item should not invalidate all useful completed work.

## 8.2 Worker model

Conceptually:

```text
Web/API
  ├─ Read persisted results
  └─ Queue work
        ↓
      Worker
        ↓
     Persist
```

Keep implementation lightweight.

## 8.3 Dirty-state tracking

Example:

```text
Service analysis      CURRENT
Searchsploit           CURRENT
Arkime correlation     STALE
Route analysis         CURRENT
Hardening              STALE
```

Only stale dependent analysis reruns.

## 8.4 Analysis versioning

Persist parser/engine versions so an upgrade only invalidates results affected by
changed logic.

---

# PHASE 0 — Protect, Inventory, and Benchmark

**Purpose:** Preserve the stable system and establish objective baselines before
foundational changes.

## Steps

1. [x] Keep `main` untouched as the stable baseline.
2. [x] Perform foundational development on `foundation/evidence-engine-v2`.
3. [~] Inventory current:
   - schema
   - data locations
   - scan pipeline
   - Searchsploit pipeline
   - Analyze/Hunt/Reach/Map behavior
   - device parsing
   - exports
   - background work
4. [~] Build repeatable test datasets:
   - small network
   - medium network
   - large/range network
   - TCP
   - UDP
   - combined
   - historical scans
   - device configurations
   - enrichment-heavy cases
5. [~] Record baseline:
   - CPU
   - RAM
   - disk
   - DB size
   - page load
   - query duration
   - enrichment duration
   - [x] Initial synthetic foundation storage measurements recorded in
     [docs/STORAGE_BENCHMARK_2026-09-27.md](docs/STORAGE_BENCHMARK_2026-09-27.md).
     This is not a stable-main comparison or complete Phase 0 baseline.
6. [~] Preserve old-range Docker compatibility and offline operation.

## Exit criteria

- Stable rollback exists.
- Baseline metrics exist.
- Representative regression datasets exist.
- Current architecture is documented.

---

# PHASE 1 — Persistent Data & Analysis Engine v2

**Purpose:** Stop repeated analysis and create the foundation for all later features.

2026-10-04 supported-ingestion completion start: finish one durable, operator-visible
pipeline for the evidence sources NCT currently supports: manual and automated Nmap
evidence, manual device uploads, and eligible completed device collections. Completion
means each supported source has a clear retained-source status, any required explicit
Network Scope decision, durable processing with restart-safe pending/failed/retry
states, verified normalized or reusable outputs, and direct evidence receipts in the UI.
Scope-free calculations and scoped observations remain separate processing stages.
Missing scope must remain **Needs scope** and must never be inferred. Historical adoption
remains explicit and non-destructive. Passive collectors and physical-device identity are
later roadmap phases and are outside this Phase 1 completion boundary. The first gate is
to generalize the reviewed saved-analysis worker without weakening its existing authority,
claim, publication, or restart safeguards; subsequent gates connect intake, normalized
device evidence, current-state/Last Seen views, automatic affected-work selection, and
acceptance benchmarks.

**2026-10-04 supported-ingestion acceptance view start:** add one paged System
Health view derived from authoritative intake markers, scope decisions, queue attempts
and exact saved outputs in a single read-only SQLite snapshot. It must keep separate
encounters separate even when their bytes match, expose missing scope, waiting, queued,
running, failed, interrupted, blocked and completed stages, retain historical unadopted
evidence as an explicit count, and link back to the source workflow. Page loads must not
open or hash evidence files, initialize schema, enqueue work, parse source content or
publish results. Completion requires all four supported intake paths through the real
coordinator and worker, delayed-response pagination tests, restart/partial-failure and
missing-output checks, a disposable end-to-end benchmark, independent review and novice
operator browser acceptance. This gate is development acceptance for the foundation
branch; it is not Range, mission, stable-main or production-scale acceptance.

**2026-10-04 currently supported ingestion development acceptance complete:** the
four participating source paths now meet the bounded completion contract: manual Nmap
uploads, eligible completed Nmap scans, manual device uploads and eligible completed
device collections. System Health follows each separate encounter through retained
authority, explicit Network Scope where required, local durable processing and its exact
saved output. Ready, Processing, Needs scope and Needs attention stay distinct; failed,
interrupted, missing, malformed, mismatched and partially completed records remain visible
without weakening an earlier completed stage. Duplicate content may reuse one verified
calculation while every encounter keeps its own provenance. Older records stay in their
original history and are not included in this processing view. The status request is a
single read-only saved-metadata snapshot and does not open or hash files, initialize
storage, enqueue work, parse evidence, contact a network or publish results.

The independent gate is **CLEAR - DOCUMENTED DEVIATION** after two halts corrected
cross-encounter result borrowing, incomplete device provenance, terminal scan-state
presentation, malformed-record isolation, legitimate shared-result handling and changed
descriptor detection. Independent validation passed **59 tests**; the focused integrity
suite passed **15 tests**; UI and delayed-response checks passed **62 tests** plus the
actual Node handler; and the complete Docker suite passed **1,003 tests with 4 expected
skips**. The isolated live preview displayed all three present supported examples as
Ready with exact source/history links, the plainer historical-record boundary, expandable
encounter identity and contextual Operator Guide. The novice operator gate is **CLEAR**;
the operator understood the present Ready examples and the tested Needs scope, Processing
and Needs attention guidance without mistaking saved evidence for live network truth. The
three-repeat disposable benchmark
for exact revision `9e5b1f5` preserved separate duplicate encounters, reused their shared
device calculation, recorded 600 receipts and verified the first and last 100-row pages,
completed concurrent status reads
without errors, and kept median first/last status pages near 0.0043/0.0028 seconds. See
[the acceptance record](docs/SUPPORTED_INGESTION_ACCEPTANCE_2026-10-04.md) and
[raw benchmark](docs/supported_ingestion_benchmark_2026-10-04.json).

This completes the **currently supported ingestion development-acceptance milestone** on
the foundation branch. Steps 10-14 remain partial at their documented broader boundaries;
Step 15's representative Phase 0 comparison remains open. Historical bulk adoption,
general dependency rebuilding, multi-process leases/checkpoints, passive collectors,
physical-device reconciliation, broad current truth, exact device Last Seen, production
scale, Range, mission and stable-main acceptance remain later reviewed gates.

## Steps

1. [~] Artifact hashing and deduplication.
   - [x] Content-addressed Artifact Registry schema and canonical SHA-256 store.
   - [x] Artifact observation history.
   - [x] Nmap manual imports routed through canonical artifact storage.
   - [x] Manual device-config uploads registered and deduplicated.
   - [x] Legacy raw-import download compatibility preserved.
   - [x] Register automated Nmap run artifacts after execution writers close.
   - [x] Register collected device artifacts beyond manual uploads, including completed/failed SSH, preflight, command history and accountability files.
   - [x] Existing-data backfill for retained imports and finalized scan/device evidence (upload provenance corrected; independently reviewed; 530 Linux tests passing).
   - [x] Dry-run duplicate/storage analysis and Settings / System Health storage view.
   - [x] Dry-run verification of known historical paths and registered content hashes (upload integrity and observation-backed references corrected and independently reviewed).
   - [x] Optional exact-content compaction.
   - [x] Restart-safe/resumable backfill checkpoints and persistent storage-job reports.

   2026-09-27 start: extend registration to finalized collection evidence; add
   explicit read-only storage inspection and resumable, non-destructive backfill.
   Report physical duplicate bytes separately from already-shared hard links.
   Preserve run-local paths and all existing history. Compaction execution stays
   disabled until a separate deletion/rollback acceptance gate is implemented.

   2026-09-27 completion: registry coverage, non-destructive backfill and the
   administrator Settings / System Health page are implemented. Ordinary status
   reads load the last report, while explicit dry-run/backfill actions run in the
   background. Used space counts file lengths once per device/inode; it excludes
   filesystem overhead/compression. Duplicate/reclaimable bytes exclude already
   shared hard links. Unsupported passive telemetry/pin accounting is labelled
   not implemented rather than reported as zero. Automatic pruning is disabled.

   Validation: full Docker regression suite (519 tests), focused registration and
   safety checks, and browser dry-run/backfill/repeat-run checks with duplicate
   sample evidence. Production mission data was not migrated. Optional compaction,
   pin/retention enforcement, cross-process jobs and formal scale benchmarks remain
   future gates; this does not mark Phase 1 as a whole complete.

   2026-10-03 exact-content compaction start: implement the user-requested,
   administrator-controlled storage action in Settings / System Health. The action
   must run a fresh reference and content verification, refuse all changes while
   evidence is active or any verification issue remains, and replace only a verified
   historical copy with an atomic hard link to the exact SHA-256 canonical artifact.
   Every retained path, evidence reference, filename, observation, attribution and
   logical timestamp must remain available. Non-identical content, unsafe paths,
   unsupported filesystems and changed evidence remain untouched. Interruption,
   idempotent retry, rollback-on-validation-failure, operator confirmation, guide
   wording and isolated browser proof are part of this gate. Architecture review was
   CLEAR — DOCUMENTED DEVIATION for optional single-process maintenance, with the
   operating boundary recorded in
   [the compaction contract](docs/EXACT_CONTENT_COMPACTION.md). During implementation,
   independent adversarial review halted the gate after reproducing four unsafe
   interruption cases: post-verification content changes, journal write failure,
   queued-scan dispatch during a recovery block, and substituted symbolic-link paths.
   The corrections now have exact regression coverage and passed the final gate.

   2026-10-04 exact-content compaction completion: System Health now exposes the
   confirmed **Remove verified duplicate copies** action after a fresh clean dry run.
   Only exact SHA-256 matches on the same filesystem with compatible ownership,
   permissions and security attributes qualify. Paths, filenames, scan/collection
   history, observations, attribution and recorded timestamps remain; the eligible
   paths share the canonical physical file and its filesystem timestamps. The UI
   freezes the displayed plan through confirmation and reports estimated file-length
   savings separately from measured free-space change. Durable per-file recovery,
   startup recovery, mutation exclusion, queued-scan deferral, strict journal-owned
   paths, symlink rejection and hash checks for every recovery state keep uncertain
   cases blocked. Automatic pruning remains disabled.

   Validation: independent reviewer **CLEAR — DOCUMENTED DEVIATION** after replaying
   the adversarial interruption cases; novice operator **PASS** before and after the
   action; full Docker suite **907 passed, 2 skipped** (the container lacks Node.js);
   host Node actual-handler confirmation regression passed. The isolated browser
   demonstration compacted two 2 MiB copies, estimated 4.0 MiB, measured 3.9 MiB,
   preserved two observations and both collection paths/manifests, and left no
   eligible duplicates. This is committed development readiness on the foundation
   branch only; it is not available on `main`, Range-ready or mission-ready. See the
   [exact-content compaction operating contract](docs/EXACT_CONTENT_COMPACTION.md).
2. [~] Canonical host/service/network/device entities.
   2026-09-27 start: implement the internal host/service storage contract with
   explicit network scope and immutable artifact-backed receipts. Address endpoints
   are not physical-device identity; overlapping networks must remain separate.
   Production ingestion, network/device normalization and presentation remain open.
   Internal storage slice completed: scope-separated IPv4/IPv6 address endpoints,
   TCP/UDP/SCTP endpoints and atomic immutable assessments linked to Artifact Registry
   observations. Replay conflicts are rejected; source time stays separate from
   processing time; missing evidence does not delete history. Reviewer CLEAR —
   DOCUMENTED DEVIATION; full Docker suite **570 passed**. Review also corrected
   Artifact Registry initialization after database-file replacement and froze caller
   facts before writes. See [storage contract](docs/ENTITY_FOUNDATION.md).
   Deviation: this slice models address/transport endpoints rather than claiming
   physical Host/Device reconciliation. Existing Saved Networks are editable target
   selections, so automatic scope inference and production ingestion remain deferred.
   2026-09-27 adapter start: add verified Nmap XML translation behind an explicit,
   whole-artifact `scope_id`. The adapter must validate canonical bytes, preserve
   all reported transport states and source timing/coverage, and remain off request
   paths until operator scope assignment is designed and reviewed.
   Adapter completion: canonical path, actual size and SHA-256 are verified with a
   bounded read before parsing; unsafe XML is rejected. Source scan/host epochs,
   coverage, extraction locators, `-Pn` presence and every TCP/UDP/SCTP state are
   retained. Reversed/out-of-window times, ambiguous command targets and missing
   host status remain unknown instead of being promoted. Identical bytes retain
   distinct encounter receipts without advancing source time. The initial review
   halted on time conflicts, unsafe target inference and missing-status promotion;
   re-review halted on an unbounded corrupted-file read. All findings were corrected.
   **QUALITY GATE: CLEAR**; full Docker suite **589 passed**, independent focused
   suite **81 passed**. Adapter remains internal/unwired; operator scopes, mixed-scope
   artifacts, original phase-file selection and production migration remain open.
   2026-09-27 scope-registry start: add stable operator-created network contexts
   with editable labels, optimistic versioning, immutable audit history and archive
   semantics. Scope identity must not be derived from Saved Networks, CIDRs or names;
   no ingestion route will be enabled until assignment/correction semantics are reviewed.
   Scope-registry completion: generated opaque IDs, Unicode-safe active-label
   uniqueness, transactional version checks, complete ordered audit snapshots and
   archive-only retention are implemented. Database triggers block scope deletion,
   ID/scope mutation, audit mutation and evidence inserts for missing/archived scopes.
   Exact archived replays remain idempotent; new work is rejected. Pre-registry IDs
   migrate byte-for-byte as inactive legacy contexts without rebuilding entity or
   receipt tables. Reassignment remains explicitly deferred: future correction must
   preserve the original and link a replacement rather than moving evidence in place.
   **QUALITY GATE: CLEAR**; full Docker suite **601 passed**, independent focused
   suite **45 passed**. See [network scope contract](docs/NETWORK_SCOPES.md).
   2026-09-27 operator-workflow start: expose the registry through an
   administrator-only Settings page and API so operators can create, describe,
   rename, inspect and archive scopes before evidence assignment is enabled.
   The page must state that it does not scan, contact devices, change Saved
   Networks or assign evidence; every mutation must keep version and audit checks.
   Operator-workflow completion: the administrator Settings page and same-origin
   API now support create, edit, inspect, archive and complete ordered history while
   retaining version checks, operator attribution and immutable scope identity.
   Local single-operator deployments retain access without weakening authenticated
   roles. Novice testing exposed missing create/reuse guidance, assignment limits and
   guide discoverability; the page now explains those decisions before the form and
   the Operator Guide opens by default for a first-time browser while respecting an
   explicit disable preference. Contextual help covers every scope control and the
   guide itself. Alt+P pins the active explanation without leaving its field; clear
   borders identify both the locked guide and exact field, and controls with declared
   shortcuts show them in the guide. The reviewer halted earlier revisions for stale
   archived editor state and an authenticated first-run preference gap; both were
   corrected and independently rechecked. **QUALITY GATE: CLEAR**; full Docker suite
   **609 passed**, final independent focused suite **96 passed**, and live browser
   create/edit/archive, pin/follow, border, resize/dock/scroll and shortcut behavior
   passed. Evidence assignment and correction remain the next separate foundation step.
   2026-09-27 assignment-contract start: add a storage-first, observation-level
   whole-artifact assignment chain before any route or production-ingestion wiring.
   Corrections must append an immutable successor, retain the original assessment and
   link replacement assessments without changing scope in place. No CIDR, Saved
   Network, target, filename or content-hash scope inference is allowed. Database
   immutability for endpoint entities, assessments and receipts is a prerequisite;
   route/UI and adapter wiring remain halted until those invariants pass review.
   Assignment-contract completion: one append-only whole-artifact assignment chain
   now attaches each decision to an Artifact Registry observation rather than shared
   bytes. Corrections require the exact current assignment, append one successor and
   preserve the prior scope and evidence. Immutable many-to-many assessment links
   support multiple parser versions and safe future reuse. Database constraints block
   duplicate roots, branches, cross-observation and same-scope successors, archived
   destinations, legacy-assessment bypass, mismatched links, malformed provenance and
   all entity/receipt/assessment/assignment/link mutation or deletion. The first review
   halted on a direct legacy-root bypass and incomplete audit fields; both were fixed
   and adversarially rechecked. **QUALITY GATE: CLEAR**; full Docker suite **617 passed**
   and independent focused suite **53 passed**. Route/UI and Nmap adapter wiring remain
   deliberately disabled until current-assignment recheck, assessment/receipt creation
   and assignment linking can commit atomically. See
   [assignment contract](docs/EVIDENCE_SCOPE_ASSIGNMENTS.md).
   2026-09-27 operator-guidance refinement start: clarify the operator-facing hierarchy
   between a stable network scope, its named subnets, their CIDRs and individual IPs,
   including that one scope can contain multiple subnets and this page creates only
   the scope identity. Repair the shared top header so it remains anchored while the
   Network Scopes page scrolls. Make the exact Operator Guide heading reveal the
   Using this guide instructions on pointer hover or keyboard focus. Keep the closed
   disclosure completely hidden and show the instructions as a temporary overlay so
   they do not take space from the current topic.
   Operator-guidance refinement completion: the page and contextual guide now show
   scope → named subnet → CIDR → IP with a familiar AFB development example
   spanning multiple named subnets. The shared header remains anchored while
   content scrolls at desktop and narrow widths. Hovering or focusing the exact
   Operator Guide heading reveals an absolute-positioned instruction overlay; closed
   help has no visual or accessibility-tree footprint and the active topic never
   shifts. **QUALITY GATE: CLEAR**;
   full Docker suite **617 passed**, focused UI/scope suite **61 passed**, and live
   browser hover/focus/dismiss, no-layout-shift, sticky-header and console checks passed.
   2026-09-27 built-in system-guide start: add a read-only How NCT Works README
   to the hamburger menu for all signed-in roles. Explain, in operator language,
   how evidence is collected, retained, registered, observed, scoped, verified,
   parsed, correlated, analyzed and presented; distinguish current capability from
   foundation work and planned behavior. Document storage locations, evidence
   safeguards and the relationship between original evidence, metadata, derived
   results and browser-only preferences. Add a maintenance rule requiring future
   data-flow changes to update the built-in guide and its contract checks.
   Built-in system-guide completion: the hamburger menu now exposes a read-only
   **How NCT Works** README to local mode and every authenticated role. The guide
   explains active collection versus file upload, the ingestion pipeline, current
   Artifact Registry coverage, storage boundaries, Saved Networks versus Network
   Scopes, analysis interpretation, operator workflow, role boundaries, evidence
   safeguards and plain-language terms. Available, partly available, foundation and
   planned behavior are labeled separately. Review halted the first draft because
   exact-byte retention and processing-version visibility were described too broadly;
   the final guide correctly limits Artifact Registry coverage to registered Nmap and
   device evidence, documents the current hostname-import exception and states that
   common analysis versioning remains planned. The project operating rules now require
   future data-flow and role changes to update this operator contract and its checks.
   **QUALITY GATE: CLEAR**; full Docker suite **622 passed**, final focused guide,
   authentication, storage, scope and UI suite **101 passed**, novice acceptance was
   clear after two wording refinements, and live browser hamburger, responsive layout,
   shared shell, contextual guide and console checks passed. No architecture deviation.
   2026-09-27 assigned-Nmap coordinator start: add an internal, unwired coordinator
   that accepts only the reviewed assignment identity, resolves its observation and
   scope server-side, verifies and parses canonical Nmap bytes before the write lock,
   then rechecks the current assignment and active scope while assessment, endpoint,
   receipt and assignment-link records commit together. Exact completed replay must
   remain a no-op after later correction or scope archive; stale or archived unlinked
   work must fail without partial rows. Correction and archive races, parser-version
   separation, identical bytes in separate observations, correction back to a prior
   scope, artifact corruption and injected write failure require adversarial tests.
   Production imports, routes and operator screens remain disconnected pending this
   implementation, independent review and a later authorization/workflow gate.
   Assigned-Nmap coordinator completion: canonical verification and parsing now occur
   before a short writer transaction that rechecks the exact current assignment and
   active scope, then creates or reuses the assessment and commits endpoint, service,
   receipt and immutable assignment-link records together. Exact linked replay is a
   no-op after later correction or archive; unlinked stale/archived work is rejected.
   Database enforcement blocks direct stale/inactive linking. Tests cover injected
   rollback, corrupt/missing/changed evidence, changed-facts conflict, both orderings
   of correction/archive races, correction back to a prior scope, parser versions,
   database replacement and separate observations of identical bytes. The built-in
   guide labels this internal behavior and states that normal imports and operator
   screens do not use it. **QUALITY GATE: CLEAR**; full Docker suite **641 passed**,
   independent reviewer suite **77 passed**, novice wording review clear after the
   all-or-nothing explanation was simplified, live guide reload and browser-console
   checks passed, and no route imports the coordinator. No architecture deviation.
   Production wiring remains a separate gate.
   2026-09-27 manual-Nmap assignment workflow start: expose the reviewed foundation
   path only for exact manual-upload observations while preserving `/api/import` and
   every current analysis consumer. Add observation-level status/history that performs
   no parsing or writes; explicit initial assignment, append-only correction and
   separately retryable coordinator processing; and active-scope choices that do not
   widen administrator-only scope management. Analysts and administrators may mutate,
   viewers may inspect, and local mode uses `local-operator`; actor, parser version and
   processing scope are server-owned. Require a reason and whole-artifact confirmation,
   never preselect or infer scope, and explain that one scope may contain several
   subnets while mixed network contexts remain unsupported. The UI must recover after
   refresh or response loss, distinguish assigned-but-unprocessed from complete, retain
   immutable correction history and state clearly that current Analyze, Hunt, Reach and
   Map results do not change. Automated runs, bulk legacy migration, background jobs,
   mixed-scope partitioning and read-model replacement remain deferred. This is a
   documented temporary dual-path architecture; see the Phase 1 deviation entry above.
   2026-09-27 manual-Nmap assignment workflow completion: exact manual-upload
   observations now expose read-only durable status and history, explicit initial
   assignment, append-only correction and separately retryable atomic processing.
   The operator flow is embedded directly beneath upload in the single Import Nmap
   Evidence workspace rather than appearing as a separate navigation task. It keeps
   current Analyze, Hunt, Reach and Map results unchanged; explains whole-file scope,
   mixed-context limits, processing outputs and failure recovery; and gives viewers a
   read-only view while analysts/administrators may act. A live disposable flow covered
   import, assignment, processing, correction and reload recovery. Reviewer findings
   about permanent scope archive and planned tasking wording were corrected, novice
   feedback added the in-place processing explanation, and a live checkbox-label defect
   was corrected. **QUALITY GATE: CLEAR**; full Docker suite **654 passed**, independent
   reviewer focused suite **106 passed**, primary focused gate **99 passed**, and
   `git diff --check` found no whitespace errors. The next scan-path integration is the
   explicit Saved Network-to-Network Scope association recorded under Phase 2; it is
   not CIDR/name inference and does not rewrite prior evidence.
3. [~] Separate observations from entities.
   First slice retains source observation, parser version and source-assessment time
   separately from import encounter time; no inferred current state or disappearance.
   2026-10-03 typed evidence read-model start: add a read-only Processed Evidence
   explorer inside Analyze / Changes Over Time. Operators will select one exact Network
   Scope, load bounded address/transport summaries, and expand one endpoint to inspect
   assignment, assessment, source-observation, parser, locator, presence/state and
   collection-window receipts. Primary results include only the current unsuperseded
   assignment processed by the supported Nmap parser; superseded assignments, other
   parser versions and pending corrections remain visible as separately labeled history.
   Reads must use one SQLite snapshot, perform no schema setup, hashing, parsing, cache
   writes or network contact, and preserve separate encounters of identical bytes and
   overlapping addresses in different scopes. This milestone does not select a latest
   truth, merge physical devices, calculate Last Seen, or claim disappearance.
   2026-10-03 typed evidence read-model completion: Analyze / Changes Over Time now
   provides a bounded, read-only Processed Evidence explorer by exact Network Scope.
   Operators can page through current and historical addresses, pending records and
   separate assignment/parser history, then open retained source receipts and reported
   services without loading entire evidence files into the page. The explorer labels
   source-reported presence, scan timing and coverage limits; exposes the retained source,
   assignment reason and processing details; and explicitly avoids current-truth, device,
   Last Seen and disappearance claims. Aggregate database queries replaced the original
   cross-product summary, and every expandable result is independently paged. A live
   disposable browser check covered mouse and keyboard use, specific Operator Guide help,
   small-screen layout, source/service drill-down and a clean browser console. The novice
   operator found the completed flow understandable and requested wording refinements that
   are included. **QUALITY GATE: CLEAR**; the full Docker suite passed **707 tests**, the
   independent reviewer passed **72 focused tests**, and `git diff --check` passed. Current
   state inference, Last Seen, disappearance detection and Range deployment remain later
   gates.
4. [~] Delta detection:
   - [x] Versioned coverage receipts and lifecycle eligibility reasons. Work started
     2026-10-03 after independent review halted direct lifecycle classification because
     existing receipts did not retain completion and omitted-port evidence. The new
     contract must preserve exact requested port ranges, successful completion,
     host response, host timing, aggregate omitted-port accounting and NCT multi-phase
     provenance without changing older assessment claims.
     2026-10-03 completion: `nmap-endpoints:2` now records versioned coverage receipts
     without strengthening older assessments. Receipts retain successful completion,
     exact requested protocol/port intervals, confirmed host response, host collection
     time, complete omitted-port accounting and multi-phase provenance. Missing,
     contradictory, malformed, unsuccessful, undeclared-protocol and ambiguous merged
     evidence fails closed with an operator-readable reason.
   - [x] Explicit source-record comparison: compare reported transport state for
     one address in two analyst-selected, current unsuperseded assessments within one
     exact Network Scope. Use neutral Record A / Record B labels and never infer order
     from processing time. Compare only explicit protocol, port and reported state;
     separately show source, collection-window and coverage uncertainty. Results are
     `same reported state`, `different reported state`, `recorded only in A`, `recorded
     only in B`, or `comparison unavailable`. One-sided records are missing evidence,
     not lifecycle `new`, `no longer observed`, or proof of disappearance. Validate both
     selections together in one read-only snapshot, reject stale corrections and page
     the service union. See `docs/FOUNDATION_EVIDENCE_COMPARISON.md`.
     2026-10-03 completion: Processed Evidence now lets an operator open one address,
     choose two distinct current source records as neutral Record A and Record B, review
     each file's collection window, coverage and provenance, and compare the bounded
     protocol/port union. Results are evidence-only and never convert one-sided records
     into appearance or disappearance. The implementation rejects cross-scope, stale,
     superseded and unsupported-parser selections; retains identical-byte encounters;
     keeps TCP and UDP distinct; remains viewer-readable and read-only; and pages large
     comparisons without repeated rows. Live browser checks covered two-record selection,
     same-state and one-sided results, contextual Operator Guide help and a clean final
     browser console. They also caught and corrected historical-card shared selection and
     second-selection status lookup defects before completion. The novice operator passed
     the workflow after one plain-language warning refinement. **QUALITY GATE: CLEAR —
     DOCUMENTED DEVIATION**; the full Docker suite passed **711 tests**, the independent
     reviewer passed **76 focused tests**, and `git diff --check` passed. Coverage-backed
     lifecycle categories were left unfinished by that milestone and are completed by
     the coverage-aware milestone below. Current truth, Last Seen and proof of
     disappearance remain unfinished.
   - [x] new
   - [x] changed
   - [x] unchanged
   - [x] no longer observed
   - [x] not assessed
     2026-10-03 completion: the saved-record comparison now orders evidence only from
     successful, strictly non-overlapping host collection intervals and then applies one
     state-transition table independent of whether Nmap printed a port individually or
     summarized it. Closed to open is Newly observed; open to closed is No longer
     observed; equal supported states are Unchanged; other exact differences are Changed;
     and uncertain time or coverage is Not assessed. A common-ports scan followed by a
     top-100 scan therefore marks a previously reported port outside the later top 100 as
     Not assessed, with a plain explanation that its later state is unknown. The UI also
     distinguishes an individual service row from a complete scan summary and repeats
     that these are historical labels, not live truth. Disposable browser validation
     exercised all five labels, record selection, the common-ports/top-100 case, guide
     wording and a clean browser console. **QUALITY GATE: CLEAR - DOCUMENTED DEVIATION**;
     the full Docker suite passed **753 tests**, the post-wording focused suite passed
     **95 tests**, and the independent reviewer passed **137 focused plus 24 additional
     transition/order checks**. The novice operator independently passed the final live
     workflow after the scan-summary explanation was added. Current truth, Last Seen,
     automatic baselines, physical-device reconciliation and proof of disappearance
     remain later gates.
5. [x] Searchsploit cache redesign.
6. [~] Persistent derived results.
   - [x] Searchsploit query results are now persisted and reused across requests.
   - [x] Cache identity changes with the active Exploit-DB dataset.
   - [x] Common immutable derived-result store and verified Nmap base-analysis adapter.
     Completed 2026-10-03 as an internal foundation boundary. The first family is
     content-addressed by verified XML bytes, declared parameters, family version and
     payload schema version. Identical bytes may reuse computation while every artifact
     observation keeps separate provenance. Publication is short, atomic and idempotent;
     corrupt payloads, forged identities, mismatched observations and unverifiable inputs
     fail closed without changing source evidence. The built-in README explains that
     this adds no new button or operator action yet. At that foundation gate,
     `scan_analysis_cache` reads remained unchanged; the production migration below now
     retires them. **QUALITY GATE: CLEAR - DOCUMENTED
     DEVIATION**; the full Docker suite passed **769 tests**, the final focused suite
     passed **72 tests**, the browser showed the updated guide in the restarted local
     preview, the novice operator passed the wording, and the independent reviewer
     reproduced and verified rejection of both alternate-parser and forged-provenance
     attempts.
   - [x] Migrate production Nmap scan analysis to verified reusable file readings.
     Work started 2026-10-03 with an explicit compatibility boundary: only the unique
     finalized `nmap_scan` observation for a run's `scan.xml` may reuse a result. The
     run-local file must still match the registered canonical bytes. Unregistered legacy
     scans parse their current XML without using the old size/time cache; page reads do
     not register or backfill evidence. The user designated the verified store as the new
     supported method, so the disposable legacy cache table is removed during storage
     initialization while historical scan XML and provenance remain intact. Older code
     can recreate an empty cache after rollback. Grouping, warnings, overrides,
     enrichment and operator-facing evidence links remain outside the reusable reading.
     Completed 2026-10-03. Analyze, Hunt, Reach and scan-comparison paths now reuse only
     exact verified terminal-run evidence. A nonterminal run can still be read from a
     stable run-local XML snapshot, but it cannot publish or reuse a result; a status
     change during calculation also blocks publication. Every registered terminal-run
     analysis verifies both the run-local and canonical copies. Changed bytes, missing or
     ambiguous observations, deleted runs and corrupt retained results fail explicitly. Warm reads
     use a consistent read-only snapshot and make no database write. The old disposable
     table is removed once at startup in an atomic, retryable migration; interruption
     rolls back the removal, historical scans and provenance remain untouched, and an
     older rollback can rebuild an empty cache from retained XML. Map and device-topology
     processing retained their specialized reader at this gate; the topology migration
     immediately below now connects that compatible interpretation to verified reuse. An
     isolated 4-file, 1,000-host-per-file benchmark measured 0.4517 seconds cold and
     0.1606 seconds warm while retaining exact-file checks. The restarted preview showed
     the final built-in guide and the preview database retained its artifact observations
     with no legacy cache table. The novice operator passed the wording. **QUALITY GATE:
     CLEAR - DOCUMENTED DEVIATION**; the full Docker suite passed **785 tests**, the
     final focused suite passed **82 tests**, the reviewer independently passed **95
     tests**, and Python compilation plus `git diff --check` passed.
   - [~] Persist remaining analysis families under the common derived-result model.
     - [x] Migrate the automated Map and device-correlation Nmap topology reader.
       Work started 2026-10-03 under a documented compatibility boundary. The existing
       bytes-to-topology-host calculation will keep its current host, port, trace,
       missing-value and ordering behavior in a separate versioned result family while
       reusing the verified scan-source selection, terminal-state, integrity,
       provenance-link and publication safeguards. Map graph assembly, device interface
       matching, source labels and times, imports and the existing 200-record limits stay
       outside. Device summaries remain deferred until ordered multi-file selection,
       explicit missing inputs, semantic manifest fields, truncation parameters and
       command-history retention have a reviewed dependency contract.
       Completed 2026-10-03. Map and Network Devices now share the same registered-scan
       authority, exact run-local and canonical-content verification, immutable result
       publication and separate observation links as the base Nmap reader, while the
       topology payload remains independently versioned to preserve existing behavior.
       Older unregistered files remain directly readable until explicit backfill. After
       backfill, actual registry authority is checked even when a legacy manifest has no
       registry marker, so missing or changed retained evidence produces a visible Map
       warning or Network Devices review item instead of being silently skipped. The
       operator guide explains the distinct purposes and warning meaning. The isolated
       preview displayed the registered sample host and traceroute gateway; a second Map
       load kept one topology result and one evidence link. **QUALITY GATE: CLEAR -
       DOCUMENTED DEVIATION**; the full Docker suite passed **792 tests**, the final
       focused suite passed **44 tests**, the reviewer independently passed **49 tests**,
       the novice operator passed the revised wording, and Python compilation plus
       `git diff --check` passed.
     - [~] Define and migrate the retained device-summary calculation.
       Work started 2026-10-03 with the dependency contract as the first gate. **QUALITY
       GATE: CLEAR - DOCUMENTED DEVIATION.** The reviewed migration is intentionally
       staged: extract a pure calculation from one frozen, ordered source snapshot and
       prove an internal verified adapter first; separately gate production reuse for
       finalized manual uploads; then migrate broader collected-device evidence. The
       contract preserves sorted `uploaded-*`, then sorted `*-config.txt`, then
       `stdout.txt` configuration priority; `stdout.txt`-first raw-output priority; empty
       versus missing inputs; dedicated command history versus configuration-section
       fallback; complete routes; current bounded presentation sections and UTF-8
       replacement decoding. Semantic inputs include vendor, ordered commands, history
       command/attempt status and the exact `output_complete is False` rule. Run identity,
       filenames and collection provenance stay outside shared calculation content.
       Registered bytes must be verified before and after calculation; page reads do not
       register or backfill legacy evidence. The existing cache and normalized command
       observations remain until every dependent path and a durable deletion/publication
       authority guard pass separate cold, warm, corruption, replacement, concurrency and
       rollback review.
       - [x] Frozen calculation and internal verified manual-upload adapter.
         Completed 2026-10-03 without changing production Network Devices reads. One
         calculation now receives a frozen text/metadata snapshot rather than reopening
         evidence during parsing. The internal adapter verifies the registered run-local
         and canonical upload, identifies semantic manifest and selection-shape inputs,
         excludes run identity and retained filenames from shared content, reattaches
         those details on return, preserves command-history line numbers, and links every
         separate upload encounter. Exact bytes reuse one immutable result; same-size/time
         changes, unreviewed extra files and mid-calculation manifest changes fail closed.
         Existing cache tables and normalized command observations are unchanged. The
         built-in guide labels this as internal groundwork with no page or operator-action
         change. **QUALITY GATE: CLEAR - DOCUMENTED DEVIATION**; the full Docker suite
         passed **798 tests**, the focused suite passed **78 tests**, the reviewer passed
         **65 regressions plus 20 independent wrapper/adapter comparisons**, and the
         novice operator passed the revised wording.
       - [x] Add durable collection authority and gate production reuse for finalized
         manual uploads before expanding to multi-file device collections.
         Completed 2026-10-03. Every new manual
         upload now creates a permanent preparing/active/deleted lifecycle record, atomically
         publishes its completed manifest, and returns success only after activation. Network
         Devices and the summary endpoint use the verified immutable result for active uploads;
         they do not write the old cache. Exact duplicate bytes reuse one result while each
         upload keeps separate authority and provenance. Semantic manifest changes, byte
         changes, missing authority and unsupported selection changes fail explicitly;
         presentation-only changes retain the calculation identity. Deletion records a
         permanent marker and removes disposable cache rows before local file cleanup, allows
         cleanup retry, blocks history/file access, and prevents a concurrent historical-cache
         writer from recreating deleted metadata. Upload failures after preparation are marked
         deleted and cannot silently become legacy records. Existing historical, partial and
         multi-file collections remain readable until their separate adoption gate. The first
         independent review halted the milestone after reproducing partial-cleanup retry,
         summary-text parity, misleading integrity-error and authority-transition defects; all
         four were corrected and independently reproduced as passing. **QUALITY GATE: CLEAR -
         DOCUMENTED DEVIATION**; the full Docker suite passed **809 tests**, the final focused
         suite passed **68 tests**, the reviewer independently passed **60 tests**, Python
         compilation and `git diff --check` passed, and the novice operator passed the revised
         guide. An isolated live upload reached active authority, rendered in Network Devices
         on cold and warm loads without console warnings, retained one reusable result with two
         provenance links, and created no legacy-cache row.
       - [x] Expand verified authority and reusable summaries to eligible finalized
         multi-file device collections.
         Work started 2026-10-03 after commit `6a89238`. This gate reviewed the
         standard and interactive SSH finalization paths, per-file Artifact Registry
         observations, ordered configuration/raw/history selection, completed versus
         partial collection meaning, restart recovery, and compatibility with retained
         historical collections. Completed 2026-10-03. New completed, untruncated
         key-based and interactive SSH collections now activate only after NCT freezes
         the exact retained file set, role choices, content identity, analysis semantics
         and provenance, then verifies the registered result again before publication.
         File replacement before registration, during activation, after activation or on
         local retry fails closed. Successful collection and analysis readiness remain
         separate; a verification conflict can retry from retained files without device
         contact or another observation. Failed and truncated collections keep their
         evidence but are ineligible for analysis. Historical collections keep history
         and downloads and clearly state that no conversion action exists yet. Production
         reads and new collections no longer use or write the old summary cache; its rows
         and tables remain for rollback and a future reviewed migration. **QUALITY GATE:
         CLEAR - DOCUMENTED DEVIATION**; the full Docker suite passed **818 tests**, the
         expanded focused suite passed **170 tests**, and the reviewer independently
         passed **144 tests**, including the activation-race reproduction. The isolated
         preview showed `Verified and ready`, loaded exact configuration/raw/history
         evidence, opened the reusable Network Devices analysis, and produced no browser
         console warnings or errors.
7. [~] Dirty-state tracking.
   - [x] Calculation-contract status for existing reusable result families.
     Completed 2026-10-03. System Health now classifies retained Nmap base analysis,
     Nmap topology and device-summary results from shared trusted versions, output
     schemas and declared settings. Exact matches are Current, known mismatches are
     Stale, and unknown, ambiguous or unreadable contracts are Unknown. The bounded,
     paged read uses no initialization or status writes, stays available alongside a
     pending database writer, rejects conflicting duplicate settings and excessive
     nesting, and ignores older page responses that arrive after newer navigation.
     Current explicitly does not claim that evidence is recent, intact or still true
     on the network. The built-in guide and derived-result contract document the same
     boundary. **QUALITY GATE: CLEAR - DOCUMENTED DEVIATION**; the full Docker suite
     passed **826 tests**, the final focused suite passed **96 tests**, and the reviewer
     independently passed **136 tests**, including reordered page responses and
     malformed contract metadata. The isolated browser preview displayed all three
     supported result families, retained correct page controls, and produced no console
     warnings or errors. Source freshness, dependency propagation, queued rebuilding
     and stale-only recomputation remain open.
8. [~] Dependency graph.
   - [x] Read-only calculation inputs and source-record drill-down.
     Completed 2026-10-03 after calculation-contract status. System Health now shows
     each saved calculation's declared input roles and separately paged retained source
     encounters. The reader verifies the exact reviewed calculation contract, saved
     computation identity, manifest, immutable input rows and artifact-observation
     digests before display. Missing history, embedded history and a dedicated empty
     history file retain different meanings. Reads are administrator-only, bounded,
     do not write status, and discard older responses after an operator changes the
     selected result or role. The built-in guide and contextual Operator Guide explain
     the dependency/provenance boundary and that the view does not inspect source files,
     determine freshness or rerun analysis. **QUALITY GATE: CLEAR - DOCUMENTED
     DEVIATION**; the full Docker suite passed **839 tests**, the reviewer independently
     passed **125 tests**, and the novice operator passed the live workflow. Browser
     checks covered five-role device inputs, one-role Nmap inputs, linked source details,
     result switching, contextual help and a clean console. This remains a partial
     Step 8 implementation: the direct reverse lookup is completed immediately below;
     source-byte checks, result-to-result edges, invalidation propagation, scheduling
     and rebuilding remain open.
   - [x] Indexed reverse lookup for recorded direct input relationships.
     Completed 2026-10-03 after the forward input drill-down. System Health now lets an
     administrator start from one verified input role and inspect every saved input-row
     candidate with the same input kind and exact identity. Separate roles remain
     separate relationships; repeated source observations do not multiply them. Exact
     supported contracts must pass computation-identity, manifest, full input-row and
     provenance verification. Older or unknown contracts remain visible as unsupported
     saved-record candidates, while conflicting or dangling records fail visibly. The
     bounded deterministic query uses an additive startup index and performs no request
     writes. Plain labels, contextual guidance and the built-in guide state that this
     reports direct recorded relationships only; it does not inspect source bytes,
     predict invalidation, mark work stale, traverse indirect dependencies, schedule
     jobs or rebuild analysis. The independent review initially **HALTED FOR REVIEW**
     after reproducing a dangling-row pagination mismatch; counts and pages now share
     the same candidate population and the corruption fails before paging. **QUALITY
     GATE: CLEAR - DOCUMENTED DEVIATION**; the full Docker suite passed **845 tests**,
     the final focused dependency/storage/interface suite passed **124 tests**, the
     post-wording interface suite passed **63 tests**, and the reviewer independently
     passed **131 tests**. The novice operator passed the live workflow after internal
     role names were replaced with plain display labels. Browser checks covered artifact
     and descriptor inputs, result/role switching, opening result inputs, contextual
     help, direct-relationship counts and a clean console. Result-to-result dependencies,
     invalidation, scheduling and rebuilding remain open.
9. [~] Analysis versioning.
   - [x] Saved-calculation version inventory for migrated reusable families.
     Completed 2026-10-03 after the read-only direct dependency views. System Health now
     groups exact retained family, rule version, output format and settings; keeps
     malformed and unfamiliar contracts visible as Unknown; shows saved-result counts
     and earliest/latest calculation times; and pages the exact results in a selected
     group. Group and result reads use bounded read-only snapshots, differing settings
     never merge, and page counts describe only the displayed groups. A settings
     fingerprint is explicitly identified as an internal exact-match identifier rather
     than a readable settings summary. Live testing found and fixed a misleading stale
     input panel when switching groups. **QUALITY GATE: CLEAR - DOCUMENTED DEVIATION**;
     the full Docker suite passed **853 tests**, the final focused inventory, storage,
     interface and guide suite passed **97 tests**, and the reviewer independently passed
     **97 checks** before separately clearing the final expandable-guide delta. Those
     checks included malformed values, exact group selection and delayed-response
     replacement. A 20,000-result/200-group disposable check returned the first group
     page in about **37 ms** and an exact result page in about **7 ms**; this is a
     synthetic development check, not a production benchmark. The novice operator
     passed the live workflow after the settings-fingerprint wording was clarified.
     Browser checks covered exact group/result switching, opening inputs, automatic
     closure of old inputs, contextual help, layout and a clean console. This remains an
     inventory, not an invalidation forecast or rebuild queue; it writes no status and
     does not inspect evidence freshness. Other analysis families, upgrade handling,
     selective rebuilding and durable jobs remain open, so Step 9 remains partial.
10. [~] Persistent jobs and partial failure.
    - [x] Durable operator-requested Nmap base-analysis job for one finalized scan.
      Started 2026-10-03 after the saved-version inventory and the documented
      architecture gate. The request freezes one authoritative scan encounter, exact
      artifact identity and current calculation contract; request tokens are separate
      from shared calculation identity and encounter provenance. Attempts retain queued,
      running, completed, failed and interrupted history. Result publication, inputs,
      source link and successful outcome commit together. The operator action reads
      retained files only and never starts a scan. Queued work resumes after restart;
      at this earlier single-process gate, work interrupted while running required an explicit local retry from the beginning, without a rescan when retained evidence remained intact. Gate 6 cross-process coordination below supersedes that limit with one fenced automatic recovery attempt. Bulk requests,
      cancellation, automatic retries, automatic stale scheduling, topology jobs,
      device-summary jobs and dependency-driven rebuilds remain separate gates.
      Completed 2026-10-03. Scan History now offers Prepare saved analysis for one
      eligible finalized scan and shows queued, running, completed, failed and
      interrupted outcomes without implying collection success. System Health shows a
      bounded read-only request and attempt history. Queued work resumes after restart;
      an abandoned running attempt is retained as Interrupted. At this earlier gate an explicit retry added a new attributed attempt; Gate 6 below now permits one fenced system-recovery attempt from retained evidence. The runner rejects changed, missing, ambiguous or
      symlinked sources, frozen-contract changes, lost source authority and lost worker
      claims. Exact result/input/provenance publication and successful job completion
      are atomic; verified results may be reused across separate encounters without
      merging their jobs or source links. The independent review initially **HALTED FOR
      REVIEW** on publication races, false warm-reuse failures, request-path writes,
      inconsistent status snapshots and symlink traversal. All findings were corrected
      with deterministic regressions. **QUALITY GATE: CLEAR - DOCUMENTED DEVIATION**;
      the reviewer independently passed **139 tests**, the complete Docker suite passed
      **874 tests**, and the final job/storage/interface/guide suite passed **126 tests**.
      Live isolated-preview checks covered the operator action, local-only wording,
      successful verified-result reuse, System Health history and a clean console. Live
      testing also found that a fast completion could remain visually Running until a
      manual refresh; active jobs now refresh the complete history window already loaded
      by the analyst, while preserving older records and open scan groups. This capability
      is development-ready on the foundation branch only. The novice operator passed the
      completed/reused workflow and restart/retry guidance. Queued, interrupted and failed
      transitions are covered by deterministic tests but were not staged as live examples.


   2026-10-04 additive pipeline-queue migration completion: saved Nmap base-analysis
   jobs now run entirely from additive pipeline job, request and attempt tables. Startup
   copies any legacy queue in one transaction before workers start, preserving exact IDs,
   request tokens, attempts, attribution, timing, errors, output links and frozen contracts.
   Deterministic fingerprints, relationship and per-job history validation reject partial
   schemas, orphaned rows, missing initial requests or attempts, broken attempt sequences,
   mismatched retries and interrupted copies without writing a completion marker. Nine
   database triggers freeze retained legacy tables against inserts, updates and deletes;
   a stale old-worker publication therefore rolls back with its obsolete completion write.
   Current routes, status reads, claims, retries and completion writes use only the new
   tables. This is a partial Steps 10-11 migration and adds no new operator action yet.
   **QUALITY GATE: CLEAR - DOCUMENTED DEVIATION**; the reviewer independently passed
   **75 tests**, the focused migration suite passed **27 tests**, the broader startup,
   status, interface and guide gate passed **138 tests**, and the complete Docker suite
   passed **918 tests with 2 expected skips**. All NCT processes sharing a database must
   cut over together. Ordinary rollback is unsafe because older code cannot see
   post-cutover work and cannot write the frozen queue; preserve the database and roll
   forward. See [the derived-result and queue contract](docs/DERIVED_RESULTS.md).

   2026-10-04 durable scoped-Nmap stage start and implementation completion: manual
   Nmap assignments and eligible completed automated scans now enter the shared pipeline
   queue instead of parsing inside the browser request. Each request freezes the exact
   encounter, artifact identity, assignment, Network Scope, parser rules and authenticated
   requester. The worker rechecks source bytes, assignment authority, active scope,
   automated run context, parser compatibility and claim ownership. Scoped entities,
   assessment, receipts, assignment link, output reference and successful attempt state
   commit together. The Analyze and Scan History interfaces show queued, running, failed,
   interrupted and completed work, refresh while work is active, and explain that local
   retry does not start a scan or contact the network. Historical automated-processing
   attempts had no trustworthy request/job identity, so startup marks any old Running row
   Interrupted once and trigger-locks that table as a read-only audit record instead of
   inventing modern jobs. New work uses only the pipeline tables. Duplicate request,
   separate encounter, stale correction, archived scope, parser-change, corrupt evidence,
   publication rollback, restart/retry, access-control and legacy-history checks pass in
   the focused Docker suites. Live acceptance exposed and corrected one cross-job status
   lookup that briefly displayed completed scoped processing as the separate saved-analysis
   result; base-analysis status now filters by its exact job type, and the interface states
   plainly when scoped evidence is ready while saved analysis is unavailable. **QUALITY
   GATE: CLEAR - DOCUMENTED DEVIATION**. The reviewer independently passed the original
   **79-test** gate and the final **48-test** status-separation gate. The complete Docker
   suite passed **925 tests with 2 expected skips**, the final focused suite passed **81
   tests**, and the actual Scan History browser-handler regression passed under Node. An
   isolated live preview completed manual upload assignment and queued processing plus the
   completed-scan Scan History flow without network contact or browser warnings/errors.
   The novice operator returned **CLEAR WITH NON-BLOCKING FEEDBACK**; its wording request
   was incorporated and rechecked live. This scoped-Nmap stage is development-ready on the
   foundation branch only.

   2026-10-04 automatic supported-Nmap admission start: connect new manual Nmap
   observations and new scan runs to the durable worker without scanning timestamps or
   adopting historical evidence. New sources receive an explicit ingestion-policy marker.
   A scope assignment/correction or eligible completed-scan finalization commits a frozen
   admission intent with the authoritative source change; job creation happens afterward
   and can recover after restart. Historical unmarked evidence keeps the explicit Queue
   action. Missing scope remains Needs scope, corrections create new immutable intents,
   and an older intent may not switch to a corrected assignment or newer parser. This gate
   does not add device intake, automatic processing retries, current-state selection or
   Last Seen behavior.

   Automatic supported-Nmap admission completed 2026-10-04. New manual upload
   observations and reviewed scan runs receive an immutable policy marker, and their
   authoritative scope decision or eligible completion commits a frozen handoff before
   job creation. Startup and later worker starts recover only those marked handoffs;
   historical evidence retains its explicit Queue action, missing scope stays Needs
   scope, corrections cannot redirect older work. At this earlier admission gate failed or interrupted attempts were never retried automatically; Gate 6 below now permits a single fenced system-recovery attempt after ownership expiry while preserving the earlier attempt. A retained activity state distinguishes Waiting,
   Retrying and Paused, allowing Analyze and Scan History to refresh through bounded
   temporary storage retries and stop after a true pause. The reviewer halted the gate
   for an automatic retry collision, a hot worker-respawn loop, and two polling gaps;
   each reproduced case was corrected and retained as a regression. **QUALITY GATE:
   CLEAR - DOCUMENTED DEVIATION**. The complete Docker suite passed **944 tests with 2
   expected skips**, the final focused suite passed **78 tests**, the reviewer passed
   **126 independent tests**, and actual browser-handler regressions passed under Node.
   Isolated live acceptance proved a new scoped manual upload processed without Queue,
   a newly completed scan recovered its pending handoff after restart, the existing
   database gained the activity-state migration, and Scan History showed Scoped evidence
   ready with a clean browser console. The novice operator returned **CLEAR**. This
   automatic Nmap stage is development-ready on the foundation branch only; device
   intake, current-state selection and Last Seen remain separate gates.

   2026-10-04 automatic device-summary admission start: move new verified manual
   device uploads and eligible completed SSH collections from page-time calculation into
   the shared durable worker. Only authorities explicitly marked under the new policy
   participate. Authority activation freezes the revision, selection contract, semantic
   manifest and ordered exact inputs in a recoverable admission intent before job
   creation. The worker must atomically publish the reusable summary, provenance and
   successful attempt. At this earlier device-admission gate failed or interrupted calculations required an explicit local retry; Gate 6 below now permits one fenced system-recovery attempt from retained files. Neither path contacts the device. Device History must distinguish local source
   verification from summary processing and show waiting, retrying, paused, queued,
   running, completed, failed and interrupted states. Historical unmarked authorities
   retain their established on-demand behavior until a separate adoption gate. This
   scope-free calculation does not infer Network Scope or physical-device identity and
   does not yet create current-state or Last Seen observations.

   Automatic device-summary admission completed 2026-10-04. Every new participating
   manual upload and eligible completed SSH collection records an immutable policy
   marker, freezes its exact active authority and ordered inputs in a durable handoff,
   and is processed by the shared background worker without waiting for an analyst to
   open a page. Result publication, input records, encounter provenance and successful
   completion commit together. Duplicate content reuses one calculation while retaining
   separate encounter links. Page reads cannot calculate or attach an unrelated duplicate
   result; failed or interrupted work requires the separate local retry and never contacts
   the device. Device History reports local verification separately from background
   processing, preserves older loaded records while polling, and carries open history
   panels through refresh. The reviewer halted the gate after reproducing a pending
   duplicate that could borrow an earlier encounter's result and polling that dropped a
   26th active record; both paths were corrected and retained as actual-handler and
   end-to-end regressions. **QUALITY GATE: CLEAR - DOCUMENTED DEVIATION**. The complete
   Docker suite passed **957 tests with 3 expected skips**, the final focused suite passed
   **24 tests**, the reviewer independently passed **93 tests** plus the actual Device
   History handler regression, the host Node regression passed, and the novice operator
   returned **CLEAR**. An isolated live
   upload reached Reusable analysis complete, opened its retained Device Overview with
   two interfaces and one route, and produced no browser warnings or errors. This stage is
   development-ready on the foundation branch only. Historical adoption, Network Scope
   assignment for device evidence, normalized device observations, physical-device
   reconciliation, current-state selection and Last Seen remain separate reviewed gates.

   Scan History presentation correction completed 2026-10-03. Every retained scan is
   now catalogued under each exact recorded canonical CIDR instead of allowing older
   scans to move into a separate global history page. Opening a subnet loads its newest
   25 scans and loads older scans inside the same dropdown. Saved Network rename,
   archive or recreation does not split the same CIDR; different prefixes remain
   distinct. Multi-subnet scans appear under each exact recorded subnet with a clear
   cross-target note, while host lists and unusable legacy targets remain labelled
   fallback groups. Every row retains its original scope, snapshot, attribution and
   evidence actions. Refresh preserves the complete catalog and scan windows already
   loaded by the operator, including more than 100 subnet groups, while removing stale
   memberships and retaining concurrently loaded rows. History reads no longer create
   missing storage. **QUALITY GATE: CLEAR - DOCUMENTED DEVIATION** after two reviewer
   halts exposed delayed-refresh, stale-membership and 101-group pagination races. The
   actual browser-handler regressions pass, the focused Docker suite passed **95 tests**
   with the Node-only handler wrapper skipped in the Python-only image, and the complete
   Docker suite passed **882 tests** with the same expected skip. The novice operator
   passed the live 30-scan grouped workflow, older loading and expanded-group refresh.
   This correction is development-ready on the foundation branch only.
11. [~] Lightweight worker.
    - [x] Single-process saved-analysis runner with short atomic claims, startup recovery,
      read-only bounded status and lost-claim publication protection. This first runner
      intentionally has no cross-process lease or mid-calculation checkpoint. Broader
      multi-family scheduling, cross-process leases, progress checkpoints, cancellation,
      dependency ordering and automatic retries remain open, so Step 11 stays partial.

    **2026-10-10 Kubernetes-capable architecture start:** Treat Kubernetes compatibility
    as a standing design constraint without making Kubernetes a core dependency. Define
    standalone, single-replica Kubernetes and future multi-replica profiles; storage and
    rollback safety; stable runtime identity; graceful drain and restart behavior;
    provider-neutral health; least-privilege cluster visibility; scan-worker placement;
    and explicit acceptance gates before adding live resource telemetry or orchestration
    integration. The independent start review halted the first proposal until it made
    single-writer enforcement, SQLite filesystem qualification, schema-aware rollback
    and Kubernetes API allowlists explicit.

    **2026-10-10 Kubernetes-capable architecture baseline completion:** The roadmap,
    project operating rules and `docs/KUBERNETES_ARCHITECTURE.md` now make Kubernetes
    compatibility a standing design gate while preserving the offline single-container
    profile. They define the initial one-replica profile, SQLite storage qualification,
    non-overlapping replacement, schema-aware rollback, stable identity, graceful drain,
    provider-neutral health, least-privilege optional cluster visibility, scan-worker
    placement and the separate multi-replica acceptance sequence. Independent architecture
    gate: **CLEAR** after all four start-gate safeguards were made explicit. Novice wording
    review: **PASS**. This is an architecture baseline only; Kubernetes manifests, live
    resource telemetry, cluster status and multi-replica execution remain unimplemented.

    **2026-10-10 provider-neutral live health start:** Implement the first Kubernetes
    acceptance gate as an administrator-only, read-only System Health view. The local
    provider will report separately identified process and container CPU/memory,
    data-filesystem capacity, fixed database/WAL/SHM file size and bounded saved-work
    counts, with measurement source, unit, sample time and explicit Warming up or
    Unavailable states. CPU uses monotonic two-sample deltas. Health reads use fixed
    paths and a time-bounded read-only database query; they do not walk evidence,
    initialize schema, write storage, start work, benchmark the system or contact a
    network target. The browser will keep at most one request active, poll only while
    the page and panel are visible and discard delayed responses. This slice does not
    add Kubernetes API access, historical telemetry, alerts, autoscaling or a
    Kubernetes-readiness claim. Independent architecture start gate: **CLEAR**.

    **2026-10-10 provider-neutral live health completion:** Settings / System Health now
    begins with a live Performance and Reliability panel for administrators. It reports
    separate NCT-process and available Linux-container CPU/memory, data-filesystem used,
    available and total capacity, fixed SQLite/WAL/SHM file size, and queued, running,
    waiting and retrying saved work. Every measurement names its scope, source and unit;
    the first CPU sample says Warming up and unsupported or over-budget reads say
    Unavailable rather than zero. The API omits paths, environment values and runtime
    identifiers. It uses fixed file metadata, filesystem statistics and a 50 ms bounded
    read-only aggregate through NCT's shared SQLite connection policy; it never walks
    evidence or initializes schema. The browser keeps one four-second-bounded request in
    flight, polls at five-second intervals only while the page and panel are visible,
    and discards delayed responses. The page, Operator Guide and built-in How NCT Works
    guide explain that these are restart-local current samples, not retained history,
    a benchmark, an alert or network truth, and that reading them starts no scan or
    network contact. The novice operator's first pass found three wording gaps; all were
    corrected, then the normal and narrow layouts passed with the Guide open and no
    browser warning or error. The independent final gate then halted a stale-status edge
    case where a visible refresh timeout looked like an intentional off-screen cancel.
    NCT now marks prior values as the last successful sample after a failed or timed-out
    visible refresh, while hiding the panel cancels silently; an executable browser-logic
    regression proves both paths and the CPU warm-up banner separately. Final independent
    gate: **CLEAR**. Focused System Health/storage/guide validation passed **132 tests
    with 1 expected container-Node skip**, and the same browser-logic regression passed
    directly with Node. The complete network-disabled Docker suite passed **1,220 tests
    with 15 skips**. The first complete run also exposed the new module bypassing the shared
    SQLite connection helper and an unrelated timing-sensitive scope-correction test;
    the connection use was corrected, the scope test passed independently, and the clean
    complete rerun produced the reported result. Kubernetes API access, historical
    telemetry, alert thresholds and multi-replica execution remain unimplemented.

    **2026-10-10 lifecycle probes start:** Implement Kubernetes acceptance gate 2 with
    separate side-effect-free startup, readiness and liveness endpoints while keeping
    the existing `/health` deployment contract unchanged. Startup means required
    initialization and the compaction-recovery safety check completed; an unresolved
    compaction condition may remain safely fenced for administrator review without
    causing a restart loop, while fatal initialization or recovery exceptions still
    prevent startup. Readiness means the HTTP service can safely accept requests, not
    that every optional dependency or workload is healthy. Liveness proves only that
    the process can answer the request and performs no database, disk, worker or network
    check. The endpoints will bypass authentication-session lookup, use fixed non-secret
    response fields, return meaningful 200/503 states with no-store caching, reset state
    across failed or repeated lifespans and mark readiness false before shutdown cleanup.
    This slice does not yet prove Kubernetes traffic draining or deployment readiness.
    Independent revised architecture start gate: **CLEAR** after distinguishing safely
    fenced recovery from fatal startup failure.

    **2026-10-10 lifecycle probes completion:** Kubernetes acceptance gate 2 now exposes
    independent `/health/startup`, `/health/readiness` and `/health/liveness` checks.
    They return fixed non-secret JSON, useful 200/503 states and `Cache-Control: no-store`
    without authentication-session, database, filesystem, worker or network-target
    reads. The existing `/health` response is unchanged for current deployment tooling.
    Lifecycle state resets at each startup, fatal initialization remains failed, safely
    fenced compaction recovery preserves HTTP access while workers stay stopped, and
    readiness becomes false before shutdown cleanup. Focused authentication, route,
    recovery, shutdown-order and deployment compatibility validation passed **86 tests**;
    direct isolated HTTP checks passed for all four health contracts. The complete suite
    passed **1,226 tests with 15 skips** in a fresh network-disabled disposable container.
    A prior run in the long-lived preview exceeded the one-GiB phase-0 cgroup peak by
    about 4 MiB because that kernel counter retained earlier container activity; the
    exact benchmark and complete suite both passed from a fresh container. This is
    foundation-only development readiness. Kubernetes manifests, traffic draining,
    durable-storage qualification and Range validation remain open under gates 3 and 4.
    The first final review halted synchronous probe handlers because an exhausted shared
    request thread pool could otherwise delay liveness and provoke a false restart. All
    three handlers now execute directly on the application event loop, with a regression
    assertion that preserves that contract. The focused **86 tests** and complete fresh,
    network-disabled Docker suite of **1,226 tests with 15 skips** passed again after the
    correction. Final independent gate: **CLEAR**.

    **2026-10-10 System Health unit-label follow-up:** The first live-health display uses
    IEC binary units (`MiB`, `GiB`, `TiB`) because process, container and filesystem
    values originate as exact bytes and binary labels avoid the decimal/binary ambiguity
    of `MB`, `GB` and `TB`. This precision is less familiar to novice operators. Review
    whether the primary cards should use familiar decimal `GB`/`TB` presentation while
    the Operator Guide retains the exact byte or IEC value, and keep memory and storage
    comparisons explicit so a friendlier label does not silently change the quantity.
    Novice wording review is pending; no unit semantics have been changed yet.

    **2026-10-10 bounded CPU and memory trends start:** Extend live System Health with
    restart-local CPU and memory averages, highest sampled values and longest consecutive
    near-peak stretches for both the NCT process and its Linux container. A dedicated
    sampler will run every five seconds while NCT is running and keep at most 720 attempts
    per metric, representing the last hour or time since restart. Near peak means at least
    95% of the current bounded-window maximum; one qualifying sample represents zero
    elapsed seconds, unavailable or late samples break a stretch, and the threshold is
    recalculated when samples enter or leave the window. Container CPU starts a new trend
    segment whenever its allowance or measurement basis changes. The sampler reads only
    fixed process and cgroup counters, keeps its own CPU baselines, writes no history and
    performs no database, evidence or network access. This is a documented bounded
    in-memory operational-context extension to the earlier no-history limit, not retained
    telemetry, continuous recording, an alert or a benchmark. Independent start gate:
    **CLEAR** with fixed-size, lifecycle, unavailable-sample and wording safeguards.
    A user-directed presentation refinement replaces the earlier paragraph-style CPU
    and memory details with two compact tables limited to Current, Average, Maximum,
    and Time near max. Kernel lifetime peaks and container memory limits remain in the
    bounded administrator API response but are intentionally not added as extra table
    fields. This keeps the operational display aligned with the operator's requested
    four-value comparison rather than mixing lifetime counters into the rolling window.
    **Completed and development-verified:** the five-second restart-local sampler, fixed
    one-hour/720-attempt bounds, process/container CPU and memory series, allowance-basis
    resets, unavailable-gap handling, and compact four-column tables are implemented.
    Current, Average, Maximum, and Time near max now come from the same completed series,
    so Current cannot be newer than the displayed Maximum. Failed CPU, memory, or sampler
    measurements say Unavailable; only a valid first CPU counter awaiting its next reading
    says Warming up. Focused validation passed 122 tests, the isolated network-disabled
    full suite passed 1,235 tests with 15 skipped, the UI runtime regression passed, and
    live browser checks passed at normal size and 1,400 by 1,000 with the Operator Guide
    open and no console warnings, overlap, table scrolling, or page overflow. The novice
    operator returned **PASS**. Independent quality gate: **CLEAR — DOCUMENTED
    DEVIATION** for the user-directed four-column display while lifetime peaks and the
    container memory limit remain available in the bounded administrator API. This is
    committed foundation behavior only; Range, mission, Kubernetes adapter, and stable
    `main` acceptance remain later reviewed gates.
    **2026-10-10 process-lifetime SQLite writer guard start:** Begin Kubernetes
    acceptance gate 3A by preventing overlapping NCT application processes from opening
    the same SQLite data area. The fixed guard will live beside `analyzer.db`, use a
    nonblocking byte-range filesystem lock acquired before database configuration or
    migrations, remain held through worker and scheduler shutdown, and never be unlinked
    or replaced. Startup contention must fail closed without changing database bytes.
    Unsafe links or non-regular guard objects must fail closed; the descriptor must not
    pass to child processes. Normal shutdown, failed startup and process exit release the
    guard, while uncertain worker shutdown deliberately retains it until process exit.
    Separate-process tests are required. This does not qualify a Kubernetes storage class,
    solve older-image rollback, or establish multi-replica support. Independent start
    gate: **CLEAR** with these exact safeguards.
    **2026-10-10 process-lifetime SQLite writer guard completion:** NCT now acquires the
    fixed application writer guard before opening or configuring SQLite. Contention,
    unsafe links and non-regular guard objects fail closed without changing database
    bytes; the descriptor is close-on-exec and the guard file remains stable rather than
    being removed or replaced. Storage maintenance, scheduled-batch producers, scan
    workers and saved-analysis workers now fence admission and register their thread under
    the same lock used by shutdown. Shutdown stops the scheduler and scheduled-batch
    producers before scan children, proves each writer family stopped, and retains the
    guard until process exit whenever that proof fails. Separate-process contention,
    release, crash recovery, failed startup, repeated lifespan, start/shutdown barrier and
    producer-before-child tests passed. The clean network-disabled suite passed **1,253
    tests with 15 skipped**; live preview readiness succeeded and a second process was
    rejected while the preview owned its isolated data directory. Independent quality
    gate: **CLEAR**. This completes application-side gate 3A only. Kubernetes manifests,
    exact storage-class lock/rename/fsync/WAL qualification, forced-termination testing,
    older-image schema protection, Range validation and multi-replica operation remain
    open. The change is foundation-only and does not alter stable `main`.
    **2026-10-10 mounted-storage qualification start:** Begin Kubernetes acceptance gate
    3B with an explicit administrator-run check for one candidate mounted data root. The
    check must work only inside a newly and privately created disposable directory, never
    open `analyzer.db` or retained evidence, refuse links and ambiguous or pre-existing
    workspaces, and clean up by verified directory identity without recursively inspecting
    the supplied root. It will test separate-process advisory locks, same-directory atomic
    rename plus file/directory sync, and SQLite WAL/SHM creation, separate-process writer
    contention, checkpoint, child termination, reopen and integrity. Strict time, process,
    file, workspace, child-output and report limits apply; stuck child process groups must
    be terminated and reaped. Failed, unavailable, timed-out or incomplete cleanup makes
    the result fail. The bounded JSON report will separate operator-declared storage
    identity from measured ownership, permission and filesystem facts and bind both to the
    exact tool source with a canonical SHA-256 digest explicitly labeled unauthenticated.
    A pass applies only to the exact mounted environment tested and does not approve a
    storage class or establish Kubernetes readiness. Replacement stability,
    backup/restore, node loss and forced termination remain later gates. Independent start
    gate: **CLEAR** with these safeguards.
    **2026-10-10 mounted-storage qualification complete:** Added the explicit Linux
    administrator tool and operator instructions for testing one exact candidate mount.
    The complete run is controller-bounded and fail-closed. Workers remain bound to open
    root/workspace descriptors plus a private marker, child process groups terminate if
    their orchestrator exits, and cleanup refuses changed identities or unexpected
    objects. Separate processes verify advisory-lock contention and release, acknowledge
    the preexisting value and every one of 64 same-directory replacements, continuously
    watch the replacement interval for missing, partial or unexpected bytes, and verify
    WAL/SHM creation, rejected concurrent SQLite writing, a non-busy truncated checkpoint,
    exact reopened rows and integrity. Reports bind the declared storage identity,
    measured ownership/permission/filesystem facts, exact schema/tool source, outcome and
    exit code to an explicitly unauthenticated canonical digest. Negative tests cover
    links, pre-existing or escaped workspaces, lock failure, timeouts including repeated
    shutdown timeout, changed worker markers, path replacement, altered/self-consistent
    reports, cleanup refusal, bad checkpoint facts and a deliberate unlink-pause-rename
    fault. Focused isolated Linux validation passed **22 tests**; a live disposable
    container run passed with 65 synchronized replacement observations, more than 20,000
    continuous observations, exact SQLite reopen/integrity, and confirmed cleanup. Final
    isolated Linux regression validation passed **1,275 tests with 15 skipped** and one
    existing dependency deprecation warning.
    Independent completion gate: **CLEAR**. This is foundation-only acceptance evidence
    for gate 3B; it does not qualify a Kubernetes storage class or establish Range,
    mission, multi-replica or stable-`main` readiness.
    **2026-10-10 single-replica analysis package start:** Begin Kubernetes acceptance
    gate 3C with a three-package, provider-neutral renderer. The first package creates
    the exact ReadWriteOnce claim. The second creates a one-shot qualification Job
    bound to the immutable claim and bound-volume UIDs. The third requires the
    separately supplied unauthenticated report digest and rejects any mismatch in report
    schema, tool source, namespace, claim, immutable claim UID, immutable bound-volume
    UID, storage class, requested size, access mode,
    numeric user/group, checks, cleanup or outcome before rendering NCT. The web profile
    uses one `Recreate` replica, forced local authentication, a temporary password-file
    bootstrap Secret reference, secure cookies, bounded resources, lifecycle probes, no
    API token or RBAC, a read-only root filesystem and no Linux capabilities. Per the
    independent start review, this first web profile is analysis only: Nmap, scheduled
    execution, SSH device contact and packet capture are disabled in the pages, direct
    routes and startup scheduler/scan-worker recovery. Import, upload, local processing,
    evidence review and portable package creation remain available. The renderer never
    calls `kubectl` or accepts Secret values; it rejects oversized inputs and output.
    Enabled schedule creation and schedule activation are rejected server-side in the
    analysis-only profile while pause, edit, and delete remain available. Ordered
    HTTPS, bootstrap-removal, storage,
    upgrade and acceptance instructions must pass novice review. This is a start record;
    gate 3C remains open pending focused, full-suite, live browser, container-image and
    independent completion validation.
    **2026-10-10 novice completion correction:** The first live novice pass found four
    operator contradictions after the security review cleared: System Health made the
    optional cluster-health adapter look like the deployment itself was unconfigured;
    scan status still called the analyzer available; the runbook did not define its
    Kubernetes prerequisites and terms; and the HTTPS step lacked an explicit handoff.
    Rename the adapter status, make analysis-only active-scan and paused-schedule text
    explicit, and add copyable variables, definitions, prerequisites, registry notes,
    and a concrete HTTPS administrator handoff before repeating the completion gate.
    **2026-10-10 single-replica analysis package complete:** Gate 3C now provides three
    bounded packages: claim creation, a one-shot qualification Job tied to the immutable
    claim and bound-volume UIDs, and a one-replica analysis-only Deployment that accepts
    only the matching passing report. Replacing either storage object requires a new
    qualification. Enabled schedule creation, schedule activation, Nmap, SSH collection,
    packet capture, scan-worker recovery and scheduler startup are refused while import,
    upload, retained-evidence processing, analysis and portable package creation remain
    available. The final image ran the qualifier as user/group `10001:10001` with every
    check and cleanup passing; the renderer produced the expected UID-bound resources;
    the post-bootstrap read-only-root preview restarted without bootstrap credentials;
    and live System Health, scan, schedule and device pages showed the deployment limits
    without layout or console faults. Final isolated Linux validation passed **1,296
    tests with 15 skipped** and one existing dependency warning. Independent quality
    gate: **CLEAR**. Novice-operator gate: **CLEAR**. This completes the foundation-only
    gate 3C package; it does not claim a cluster apply, HTTPS installation, backup or
    restore proof, Range readiness, mission readiness, multi-replica safety or availability
    on `main`. Those remain later Kubernetes acceptance gates.
    **2026-10-12 Kubernetes recovery gate 4A start:** Reconcile the Kubernetes
    architecture status with completed Gate 3C, then begin the first bounded Gate 4
    slice: cold backup plus isolated restore verification. This administrator workflow
    must prove the NCT writer is stopped, retain the exact qualified source identity,
    store the backup outside the live data claim, reject unsafe files and nonempty restore
    targets, create a hash-backed manifest, restore into a separate empty target, and
    verify database integrity and retained evidence without changing the live source or
    backup. System Health may report readable readiness and recorded verification
    results, but it must not expose a novice-facing restore action. Forced termination,
    rescheduling, node loss, upgrade, and compatible rollback remain separate Gate 4
    slices. Independent start review and novice-operator review are required before this
    slice can be called complete.
    **2026-10-12 Kubernetes recovery gate 4A foundation-package completion:** The
    administrator package now renders bounded non-root cold-backup and isolated-restore
    Jobs for three separately qualified storage identities. Backup requires the existing
    stopped-writer lock, rejects saved active work, captures the source through protected
    file handles, creates and verifies the archive before SQLite validation can change
    the private validation copy, checks free capacity for the temporary snapshot plus
    uncompressed archive, and durably commits the manifest and detached receipt. Restore
    requires the separately retained receipt digest, read-only backup storage and a
    different empty qualified target; it validates bounded paths, types, modes, hashes,
    database integrity, table/schema baselines, registered artifacts, observations and
    supported retained-evidence references, then writes a Kubernetes termination receipt.
    The runbook now includes exact stop, identity, capacity, backup, restore, same-image
    startup, existing-account sign-in, evidence-download, shutdown and safe source-return
    steps. System Health and How NCT Works explain the boundary without exposing a restore
    button. Hard-linked source paths are deliberately restored as separate byte-identical
    regular files, and SHA-256 digests provide integrity evidence rather than authenticated
    signatures. Focused primary validation passed **119 tests**; the full isolated Docker
    suite passed **1,321 tests with 15 skips** and one existing dependency warning; a real
    non-root UID/GID 10001 container wrote the bounded termination receipt; independent
    reviewer validation passed **158 tests** and returned **CLEAR — DOCUMENTED DEVIATION**;
    novice-operator review returned **CLEAR**. This is a foundation-only implementation
    package. Gate 4A remains started until the exact-cluster backup, isolated restore,
    application startup, sign-in and retained-evidence exercise succeeds. It does not
    claim Kubernetes, Range, mission, upgrade, node-loss, rollback or `main` readiness.
    **2026-10-12 Kubernetes failure/replacement gate 4B start:** Begin the bounded
    single-replica failure-acceptance package on an isolated Gate 4A-restored target.
    The package must prevent automatic replacement while node loss is ambiguous, prove
    writer-lock contention and release without opening SQLite, retain queued and running
    processing truth across abrupt termination, compare cold database and retained-
    evidence baselines, and bind each scenario to the exact image, deployment, storage
    identities and qualification evidence. The four acceptance exercises are forced
    process termination, Recreate replacement, controlled two-node rescheduling and
    externally fenced node loss. Ambiguous node loss deliberately requires independent
    administrator fencing and storage-detachment proof before replacement; automatic
    failover is not accepted because ReadWriteOnce, Recreate, a missing Pod object and
    the application lock do not independently prove the old node stopped writing.
    Local development can complete and test the package, but only exact-cluster exercises
    can complete Gate 4B. Independent start review: **CLEAR — DOCUMENTED DEVIATION**.
    **Gate 4B quality-gate correction in progress:** The first completion review halted
    the package because its receipt did not yet prove replacement ordering, externally
    fenced node loss, old-attachment detachment, mandatory retry and intake attribution,
    private-copy cold inspection, the actual Gate 4A restore receipt, full lock/runtime
    identity, bounded durable recording, or the complete operator command and permission
    sequence. The corrected package now requires a verified Gate 4A restore receipt,
    copies the locked tree into bounded temporary storage before opening SQLite, binds
    structured single-writer events to old/new Pod, node, generation and distinct
    attachment identities, hashes retained provider fencing/detachment records, requires
    one Running job, one Queued job, one pending intake intent and exactly one completed
    retry, and requires pre-replacement lock release for rescheduling and node loss.
    The runbook now includes namespace permission preflight, explicit denied application
    permissions, identity refresh, every snapshot phase, retained-evidence download,
    orchestration schema and final verifier inputs. The novice review confirmed the
    corrected runbook order but halted on generic disclosure guidance; dedicated cold-
    recovery and failure-instruction Guide entries now explain that opening help performs
    no action and that node loss requires independent fencing and detachment. A second
    independent review then halted on the physical handoff sequence, fence-before-stop
    ordering, retained cluster observations and impossible pre-replacement Pod binding.
    The package now establishes and identifies the destination attachment before an
    isolated destination lock probe, explicitly omits a future Pod identity from that
    receipt, starts the replacement only after the probe passes, and records node loss as
    readiness loss, external fencing, confirmed writer stop, old detachment, destination
    attachment, lock proof and replacement in that order. A mandatory hashed live
    cluster-observation log now backs event times, Pod identities, Ready/writer maxima,
    attachment movement and health evidence; the operator steps include both lock probes,
    identity refresh, observation capture and bounded verifier inputs. A third review
    then halted on the controlled-reschedule generation change, loss of the destination
    attachment when a one-shot probe exits, contradictory stale attachment/Pod states,
    independently generated health timestamps, and limits checked only after hashing.
    The destination probe now holds the mounted volume for a bounded period after
    releasing the writer lock, remains present until the same-node replacement is Ready,
    and is then removed. The verifier binds its pre-scale generation and requires the
    exact controlled scale transition, rejects active old or extra attachments and a
    retained old Pod, requires one captured time per event across health and observation
    records, and rejects oversized or cumulatively excessive files before streaming past
    the allowed boundary. Adversarial tests cover those states. Focused isolated
    validation currently passes **117 tests**. Independent quality gate:
    **CLEAR — DOCUMENTED DEVIATION**. Novice-operator gate: **CLEAR**. The retained
    cluster/provider records and SHA-256 bindings detect changes but are not authenticated
    signatures and still require human review; local tests cannot prove physical fencing,
    CSI detachment, scheduler behavior or node recovery. The full isolated Docker suite
    passed **1,337 tests with 15 skips** and one existing dependency warning. This
    completes the foundation-only Gate 4B package; Gate 4B itself remains started until
    all four exercises pass on the exact qualified cluster. It does not claim Kubernetes,
    Range, mission, multi-replica or `main` readiness.
    **2026-10-12 Kubernetes guarded upgrade/rollback gate 4C start:** Add the missing
    image-owned schema compatibility contract and persistent migration ledger before
    testing any candidate image. The old Pod must be gone and its writer released; a
    verified Gate 4A backup tied to the exact old image and build must exist before the
    candidate can write. Preflight must bind exact old/new image and runtime identities,
    build contracts, Deployment generation, Pod, node, attachment, PVC/PV and storage
    qualification, then reject active work, incomplete migration, changed evidence or
    ambiguous compatibility. Direct rollback is fail-closed and may occur only when the
    old image itself proves it can read and write the exact resulting schema, layout and
    migration plan. Otherwise preserve the upgraded claim, restore the backup into a
    different empty qualified target, and make the backup-time data boundary explicit.
    System Health and the Operator Guide explain status and next steps without exposing
    upgrade or rollback controls. Independent architecture start gate: **CLEAR —
    DOCUMENTED DEVIATION**. Novice start gate: **HALTED FOR REVIEW** until the direct
    versus restore decision, administrator-only boundary, exact order and data-loss
    warning are explicit; those findings are required completion criteria.
    **2026-10-12 Kubernetes guarded upgrade/rollback gate 4C administrator package
    complete:** Application startup now publishes an image-owned schema contract,
    records resumable migration attempts, and remains unready until its exact migration
    plan completes. The preflight and final verifier bind immutable old/new images and
    runtime IDs, builds, schema and data-layout contracts, Deployment generations,
    Pod/node/attachment identities, source and backup PVC/PV identities, storage
    qualification, cold inventories, retained evidence, record counts, access checks,
    downloads, restore receipts, and a strictly ordered lock/cluster/event timeline.
    Compatible direct rollback is permitted only when the old image's own contract
    authorizes the exact resulting schema and migration plan. Every other path preserves
    the candidate claim and verifies a Gate 4A restore into a distinct empty qualified
    target. A failed candidate requires measured Pod/runtime/health evidence and cannot
    relabel a healthy completed migration. Ready, failed, and stopped observations derive
    writer ownership from attested lock probes independently of Pod readiness; the web
    check records measured HTTP results and fails before writing a success receipt when
    sign-in, health, or evidence download fails. The package is the first Gate 4C-capable
    baseline; earlier images remain Gate 4A restore-only. Focused isolated validation
    passes **183 Kubernetes, schema, writer-lock, health, and UI tests**. The complete
    isolated Docker suite passes **1,379 tests with 15 skips** and one existing
    dependency warning.
    Independent quality gate: **CLEAR — DOCUMENTED DEVIATION**. Novice-operator gate:
    **CLEAR** after fail-closed web-check, independent writer measurement, accepted active
    probe phases, and copyable recovery steps were verified. The administrator package
    is complete on the foundation branch; Gate 4C itself remains started until compatible,
    restore-required, and failed-candidate exercises pass on the exact qualified cluster.
    Local tests cannot prove Kubernetes scheduling, CSI behavior, or authenticate
    administrator-collected external records. This does not claim Range, mission,
    multi-replica, `main`, or exact-cluster readiness.
    **2026-10-12 Kubernetes health-adapter gate 5 start:** Add an optional,
    namespace-scoped, read-only cluster-health provider without making Kubernetes a
    core dependency. The adapter must query only the configured NCT Deployment,
    ReplicaSet, and Pod labels; return only coarse non-secret counts and readiness;
    enforce strict request-time, response-size, and item-count limits; and show denied,
    missing, malformed, oversized, or timed-out access as Unavailable rather than zero.
    Metrics API access is a second explicit opt-in and must remain separately
    unavailable when absent. The standalone local provider remains authoritative and
    unchanged when the adapter is disabled or unavailable. The generated deployment
    may receive only a dedicated namespace Role and ServiceAccount for the selected
    opt-in; it must not read Secrets, ConfigMaps, logs, exec endpoints, unrelated
    objects, or other namespaces, and it must not inspect, use, or return arbitrary
    annotations received in bounded Kubernetes objects. System Health and the
    Operator Guide must explain the distinction between application health, Kubernetes
    workload status, and optional resource metrics. Independent security/architecture
    review and novice-operator review are required before completion.
    **2026-10-12 Kubernetes health-adapter gate 5 foundation-package completion:**
    NCT now keeps its application Pod token-free and reads only the adapter's bounded,
    sanitized status over a fixed internal service name. The separately rendered
    adapter follows the exact Deployment-to-ReplicaSet-to-Pod ownership chain, rejects
    mismatched or excess objects, disables redirects and environment proxies, verifies
    the mounted cluster CA, and enforces a 2.5-second total deadline plus request,
    response-byte and item-count ceilings. Concurrent refreshes share one sample;
    expired waiters fail Unavailable rather than receiving stale status as current.
    Ready counts require both a Running Pod and Ready=True. Metrics remain a separate
    opt-in and incomplete Pod coverage withholds CPU and memory values instead of
    displaying zero. System Health distinguishes Not configured, Available, Partial and
    Unavailable, retains the last successful application-session sample, and provides
    dedicated hover/focus guidance for Deployment counts, resource measurements and
    terminology. The generated administrator runbook verifies required exact-object and
    list permissions as well as denied Deployment-list, Secret, ConfigMap, watch, logs,
    exec and all-namespace access. Focused validation passes **128 tests with 1 skip**;
    the complete isolated Docker suite passes **1,406 tests with 15 skips** and one
    existing dependency warning. The disposable standalone preview passed readiness,
    table-order, horizontal-overflow, contextual-guide, polling and browser-console
    checks. Independent quality gate: **CLEAR — DOCUMENTED DEVIATION**. Novice-operator
    gate: **CLEAR**. The completed foundation package is available only on
    `foundation/evidence-engine-v2`; exact-cluster RBAC, namespace isolation, API path,
    Metrics API, timeout and truncation exercises remain required before Gate 5 itself
    can close. This does not claim Kubernetes, Range, mission, multi-replica or `main`
    readiness.
    **2026-10-12 cross-process coordination gate 6 start:** Add database-authoritative
    expiring ownership, database-time renewal and monotonically increasing fencing for
    saved background work without weakening the existing one-process application writer
    guard or enabling multiple web replicas. A final state change or visible result may
    publish only when the same transaction proves the exact operation, opaque lease,
    runtime owner and fencing epoch are still current. A superseded worker may calculate
    only in private staging and may not publish, replace shared files, remove another
    owner's files, or mark work complete. Replace blanket startup interruption with
    lease-aware recovery: an unexpired owner remains Processing; expired pure analysis
    may start a new protected attempt from immutable retained evidence; the interrupted
    attempt stays in history. Nmap scans and device contact never move automatically
    because expiry does not prove the former network activity stopped. Compaction,
    backfill and migrations enter recovery-required after uncertain ownership and never
    auto-take over. Scheduler work requires durable unique occurrences and chunk claims,
    not only a leader lock. The first package will implement and separately test the
    common lease/fencing contract, derived-analysis recovery and storage-maintenance
    exclusion while retaining the analysis-only Kubernetes collection boundary; scan,
    schedule and interactive collection coordination remain fail-closed until their
    dedicated work-family package is complete. Default analyst views use Waiting,
    Processing, Recovering after restart, Ready, Needs attention and Stopped for safety;
    lease details stay in an administrator disclosure. Independent architecture start
    gate: **CLEAR — DOCUMENTED DEVIATION** because Gate 6 can prove coordination
    semantics with separate processes but Gate 7 must still select and validate shared
    database and artifact storage before any multi-replica deployment. Novice start
    gate: **CLEAR** with the plain-language status and no-force-unlock requirements.
    **2026-10-12 cross-process coordination gate 6 implementation/review correction:**
    The common database lease now binds one opaque operation identity, runtime owner,
    database-time expiry and monotonically increasing fencing epoch. Derived-analysis
    claims publish their result and release that exact lease in one transaction. Startup
    preserves a current owner, retains an expired attempt as Interrupted, and creates one
    separately attributed system-recovery attempt from immutable retained evidence. A
    mismatched current lease is an integrity conflict: the attempt becomes Needs
    attention without releasing or replacing the different live owner. Storage
    maintenance uses the stricter recovery-required policy. Every shared compaction
    replace, recovery cleanup, recovery-block clear and terminal status publication now
    holds the SQLite writer lock and the exact lease fence for the whole filesystem
    mutation; a stale worker leaves recovery material intact and publishes no terminal
    status. Separate-process races and loss immediately before replace, cleanup and
    status publication are deterministic regressions. Gate 4B failure evidence advances
    to schema version 2 so a recovery claim must contain the exact lease key, opaque
    identity, owner, epoch and chronological acquired, expired and released events;
    missing, mismatched, duplicate and stale evidence is rejected. This evidence-format
    revision is a documented deviation from the earlier attempt-row-only receipt because
    those rows could not prove fencing. System Health remains fail-closed when safety
    status is unavailable, uses Waiting, Processing, Recovering after restart, Needs
    attention and Stopped for safety, and keeps collection-lifecycle wording distinct.
    The final focused storage, work, recovery-evidence and interface suite passes
    **189 tests**. A real saved-work lifecycle regression additionally proves that one
    database clock orders claim, expiry, recovery, release and terminal publication.
    Exact-content backfill now stages privately and publishes canonical bytes,
    observations and checkpoints under one still-current fence. An uncertain commit
    stops the whole maintenance run, retains a recovery-required marker and does not
    continue to a later file. Normal compaction may report Processing while its exact
    owner remains current; the same marker becomes Stopped for safety after ownership
    is lost. The intake table now gives one plain-language overall status and a separate
    next action without hiding its detailed processing stages.
    **2026-10-12 Gate 6 benchmark-harness deviation:** The Phase 0 command-line
    integration tests run late inside one long-lived pytest container, so that
    container's cumulative cgroup memory high-water mark includes unrelated earlier
    tests. Those integration tests now explicitly record runner-process-lifetime peak
    memory. Such reports are marked ineligible for formal Phase 0 acceptance. The real
    benchmark default remains fresh-container cgroup-v2 `memory.peak`, and both formal
    summarizers reject any process-lifetime report and bind the accepted memory scope
    and method into comparison identity. The correction is verified by **26 focused
    benchmark tests**.
    **2026-10-12 cross-process coordination gate 6 first-package completion:** The
    complete isolated Docker suite passes **1,430 tests with 15 skips** and one existing
    dependency warning. The disposable preview completed a storage dry run without
    removing evidence; System Health displayed current resource tables, distinct saved
    work states, the background-work safety guide target and corrected intake status,
    with no browser warning or error. Independent quality gate: **CLEAR — DOCUMENTED
    DEVIATION**. Novice-operator gate: **CLEAR**. The common contract,
    retained-evidence analysis and storage-maintenance package is complete on
    `foundation/evidence-engine-v2`. Overall Gate 6 remains open: active Nmap,
    scheduled scans and interactive device contact still require dedicated
    work-family coordination before the gate can close. Gate 7 must then select and
    qualify shared database and artifact storage before any multi-replica deployment.
    No Range, mission, `main`, multi-replica, scan-transfer, schedule-transfer or
    device-contact-transfer readiness is claimed.
    **2026-10-12 cross-process coordination gate 6 network-contact package start:**
    Extend the common database-time lease and fencing contract to active Nmap,
    scheduled occurrences and interactive device contact. Every attempt requires one
    durable identity, opaque owner and fencing epoch. Unstarted work may move after
    expiry; once Nmap, FPING, tcpdump, SSH, SCP or another network-contact phase starts,
    expiry becomes Needs attention and never authorizes automatic resume or transfer.
    Cancellation remains requested until the owning worker proves every child process
    stopped. Final status, evidence registration, authority activation and lease release
    must publish together under the current fence; a stale worker may retain partial
    files but cannot label them complete. Scheduled occurrences must freeze exact scope,
    profile, exclusions, chunks, actor and due time under a unique durable key, prevent
    duplicate dispatch, bound missed occurrences and pause later work after an ambiguous
    active chunk. Interactive passwords remain memory-only and owner-bound. Kubernetes
    active collection remains disabled until placement, privileges and credential
    routing are separately proven. Start quality gate: **CLEAR — DOCUMENTED DEVIATION**.
    The first correction removes legacy automatic scheduled-batch resume: restart now
    pauses the occurrence for review and requires an explicit new occurrence.
    **2026-10-12 Gate 6 network-contact restart/operator correction:** The novice
    walkthrough halted this subgate because waiting scans did not disclose their
    post-restart behavior, interrupted scan and schedule states exposed internal labels,
    active cancellation did not show its pending state, device password/contact records
    could remain falsely active after restart, and the Schedules table could force
    page-wide overflow. Waiting scans now state that they remain saved and may contact
    the network automatically when capacity returns. Cancellation intent is retained in
    a separate database control row that an older progress-manifest write cannot erase,
    is visible as Cancelling, is polled by the owning worker even when the request came
    through another process, and a Global No-Strike change writes the same durable stop
    signal before notifying a local worker. Interrupted scans and schedule
    occurrences show Needs attention and explicitly never resume; enabling or running a
    recovered schedule starts a new occurrence. Startup converts saved device records in
    Running or Waiting for password to Interrupted, removes any unexpected credential
    fields, and leaves partial files unregistered until an administrator proves the old
    SSH/capture process stopped and the files are stable. Recovery rejects mismatched,
    escaping or symlinked collection paths before writing. Device contact stays separate
    from retained-file analysis in Collection History. Every restart-interrupted
    schedule enters review-required, even when it was already paused; re-enabling closes
    the old occurrence and prepares a new one instead of resuming old chunks. The
    schedule table now owns its horizontal scroller. A Global No-Strike addition and
    every affected active-run cancellation now commit in one transaction; a fault on
    the second cancellation write rolls the exclusion, every control row and every
    audit event back before any local worker is signalled. Scan History no longer
    claims that an old scanner or capture process stopped during restart. Its page and
    contextual Guide both require administrator verification before partial files are
    trusted. The Active Scans, Schedules and Device Collection Guides now carry the
    same restart and network-contact boundaries shown on their pages. Focused
    Linux/Docker validation passes **119 tests with 2 skips**; the final interface
    subset passes **83 tests with 1 skip**. The complete isolated suite passes **1,437
    tests with 15 skips** and one existing dependency warning. The fresh disposable
    preview rendered Scans, Schedules and Device History with the Guide open, no
    page-wide overflow or header displacement, and no browser warning or error.
    Independent quality gate: **CLEAR**. Novice-operator gate: **CLEAR**. This
    correction does not close Gate 6: durable occurrence/chunk claims and fenced
    active scan/device publication remain in progress.
    **2026-10-12 Gate 6 durable scheduled-occurrence package start:** Replace the
    mutable schedule-batch counters and process-local singleton with immutable
    schedule-definition identity, one idempotent occurrence per definition/due time,
    and ordered durable chunk records. Occurrence creation must freeze the exact
    resolved targets, scope decision, profile, schedule/global exclusions, interface,
    timeout, fallback/capture policy, actor, due time and chunk plan; atomically
    advance recurring cadence; converge across competing processes; and coalesce
    downtime into at most one bounded catch-up while retaining its missed-time count.
    Completed chunks never reopen. Ambiguous or post-contact work becomes Needs
    attention and blocks later work; enabling a schedule creates future occurrences
    and never resumes an interrupted one. Operators see Schedule, Occurrence and Chunk
    as separate concepts, plain states and explicit future-contact effects. Schema
    compatibility advances so an older image rejects the new tables. Quality gate:
    **CLEAR — DOCUMENTED DEVIATION** for implementation start. This package may
    establish and test durable preparation, claiming and recovery, but cannot claim
    transferable scheduled network execution until the active-Nmap subpackage binds
    one scan run, records contact start and publishes terminal evidence under the same
    current fence. Kubernetes active collection remains disabled through that gate.
    **2026-10-12 Gate 6 durable scheduled-occurrence and active-Nmap completion:**
    Immutable definition versions, idempotent occurrences and ordered chunk records now
    replace mutable batch resume. Each occurrence freezes the exact resolved targets,
    Network Scope decision, pinned profile, global and schedule exclusions, interface,
    contact policy, actor and due-time plan in one guarded transaction; a changed scope
    or Global No-Strike revision aborts preparation. Competing processes converge on one
    occurrence, one chunk claim and one scanner-capacity claim. The selected run enters
    a saved Getting ready to scan state before process launch. Network-contact start,
    progress, artifact registration, scan history, occurrence/chunk completion and both
    fence releases publish only under the current database lease. Pre-contact failure or
    restart reuses the same saved run under a new fence; post-contact ownership loss
    becomes Needs attention, blocks later chunks and requires an attributed administrator
    review that confirms the former scanner is stopped. Pausing controls future
    occurrences and cannot silently stop or reopen already-created work. This is the
    formal documented cadence-control deviation from treating pause as active-work
    cancellation; active work retains its separate stop control. Schema contract v3
    rejects older images and can resume only the exact recorded partial v2-to-v3 schema
    checkpoint; later schema drift fails closed. Pre-contact restart now safely reuses
    only the same run's known planning files, refuses unknown output, and retains one
    bounded retry under replacement fences. Operator and Global No-Strike cancellation
    are checked inside the atomic contact-start transaction: no process starts, no false
    `started_at` is retained, the chunk remains explicitly not-started, and both fences
    close together. The complete isolated Docker suite passes **1,462 tests with 15
    skips** and one existing dependency warning. A further **125 focused scheduling,
    schema, queue, execution, artifact and UI tests** and the JavaScript queue runtime
    pass. The network-disabled disposable preview showed all retained
    occurrences and chunks, plain status text, the analysis-only contact boundary and
    Operator Guide with no browser warning or error. Independent quality gate: **CLEAR
    — DOCUMENTED DEVIATION**. Novice-operator gate: **CLEAR**. Overall Gate 6 remains
    open for interactive device-contact fencing. Gate 7 shared database/artifact
    storage qualification and any multi-replica claim remain later work.
    **2026-10-12 Gate 6 interactive device-contact fencing start:** Apply the
    reviewed database-time ownership and fencing contract to password-prompt SSH,
    key-based configuration pulls and SSH preflight accountability. Each retained
    contact attempt must carry one durable run identity and exact lease claim while
    passwords remain only in the owning process memory. Starting tcpdump, SSH or SCP
    moves the attempt across the no-automatic-takeover boundary. A lost owner may not
    register files, activate verified device authority or publish completion; restart
    leaves post-contact work Needs attention until an administrator verifies every
    former process stopped and the retained files are stable. Final publication must
    recheck the current fence at every database mutation and release only that exact
    claim. Key and interactive paths must retain the same evidence meaning and plain
    operator guidance. This package does not enable Kubernetes active collection or
    make a multi-replica claim; Gate 7 shared storage qualification remains next.
    **2026-10-12 Gate 6 interactive device-contact fencing implementation
    correction:** Schema contract v4 now retains immutable device-contact runs,
    exact attempts, durable cancellation controls and attributed administrator
    reviews. Password-prompt SSH, key-based pulls and SSH preflight share one
    device-contact capacity lease plus one run lease, renew both while owned, and
    commit the no-takeover contact boundary before tcpdump or SSH begins. Output is
    written to an attempt-private directory and only stable, regular files are
    promoted after child processes are stopped. Artifact observations, eligible
    device authority and intake activation, terminal attempt state, cancellation
    acknowledgement and both lease releases now share one terminal database
    transaction. Startup may release one definitely pre-contact attempt, but any
    attempt that reached contact becomes Interrupted — Needs attention and requires
    an administrator to confirm former processes stopped and retained files are
    stable. The Device Collection page keeps its active stop control available after
    password submission and distinguishes Getting ready, Waiting for password,
    Contact active, Cancelling, Interrupted — Needs attention and Closed after
    administrator review from Saved analysis. Focused integration validation is in
    progress; Gate 6 remains open until the complete suite, rendered browser,
    independent reviewer and novice-operator checks pass.
    **2026-10-12 Gate 6 device-contact quality-gate halt:** The first complete
    integration pass found one outdated interactive-finalization regression test
    (**1 failed, 1,468 passed, 15 skipped**) and the independent reviewer returned
    **HALTED FOR REVIEW**. Database schema v4, dual leases, password ownership and
    terminal transaction guards passed review, but live contact publication is not
    yet safe to complete. Corrections in progress cover realistic capture-file
    promotion, interactive output after promotion, immediate cancellation and lease-
    loss process shutdown, fenced/recoverable filesystem publication, database-first
    restart recovery, review of attempt-private partial evidence, and end-to-end
    contact-path tests. The novice review also found unclear collapsed status text,
    password-stage wording and administrator-review visibility; those operator-facing
    corrections are being applied in the same gate. No downstream Gate 7 work begins
    until these findings are independently cleared.
    **2026-10-12 Gate 6 device-contact halt correction progress:** Live publication
    now accepts the capture diagnostic produced by every real tcpdump start, reads
    interactive output before private files move, and records an exact durable file
    inventory before any retained-path rename. Promotion runs under the exact live
    dual claim; terminal database publication marks that receipt committed, while the
    presentation manifest is written only after the database transaction succeeds.
    Blocking SSH, SCP and Cisco-shell children are supervised with bounded ownership
    and cancellation checks, and cancellation or lease loss terminates and reaps the
    processes before any later contact or remote cleanup step. Restart reconciliation
    enumerates durable work first, so missing, corrupt or unsafe presentation files
    cannot hide a contact record. Administrator closure binds to the exact interrupted
    attempt and hashes retained plus attempt-private files twice across a time interval
    with symlink, count and size limits. The novice wording/status/role findings are
    corrected. Expanded focused validation is **69 passed, 1 skipped** with one existing
    dependency warning; independent reviewer and novice rechecks remain in progress.
    **2026-10-12 Gate 6 device-contact final halt corrections in progress:** The
    reviewer recheck confirmed the process fencing, cancellation, promotion,
    database-first recovery and exact-file review corrections, then retained the halt
    for three narrower restart cases. A restart before contact now closes the original
    attempt as Stopped before contact and directs the analyst to start a new collection
    with fresh settings and credentials; NCT never reconstructs credentials or starts
    network contact automatically. Terminal database publication now retains the exact
    final presentation receipt and startup repairs an interrupted manifest write from
    that committed receipt. Missing, unreadable or unsafe evidence trees remain
    untrusted, but an administrator can record two stable filesystem observations and
    close the exact safety block without adopting any file as evidence. Regression
    coverage for these cases and complete password, key-preflight and key-collection
    endpoint lifecycles now passes **75 tests with 1 skipped** and one existing
    dependency warning. The HTTP checks also verified that the one-time password is
    absent from responses, durable records, retained files and SQLite files, corrected
    local-session ownership continuity, and confirmed terminal contact state in both
    the database and retained presentation. Novice-operator recheck: **CLEAR**. The
    independent final quality-gate recheck is in progress.
    **2026-10-12 Gate 6 interrupted-upgrade correction:** The final reviewer pass
    found that an interrupted v3-to-v4 database could retain the first partial
    device-contact table without the two terminal-presentation repair fields. The v4
    initializer now completes those missing fields idempotently before the migration
    fingerprint is finalized. Its restart regression proves the fields exist, then
    performs terminal publication and the unsynced-presentation repair cycle on the
    recovered database. The first complete-suite rerun also exposed four older Cisco
    test doubles that used the unfenced two-argument helper shape; the compatibility
    path now retains that call shape when no contact fence is supplied. Focused schema
    and Cisco validation passes **11 tests**. Complete-suite rerun and independent
    reviewer clearance remain required before Gate 6 closes.
    **2026-10-12 Gate 6 interactive device-contact fencing complete:** Password-
    prompt SSH, key preflight and key collection now use the same durable dual-lease
    boundary, supervise and stop owned child processes, journal exact file promotion,
    publish verified evidence and terminal state together, and repair post-commit
    presentation failures after restart. Passwords remain process-only. Post-contact
    ownership loss retains partial files privately and blocks further device contact
    until an attributed administrator review; missing and unsafe evidence trees can be
    closed without trusting or adopting them. A pre-contact restart closes the original
    attempt and requires a new operator-started collection rather than reconstructing
    credentials or contacting the device automatically. This is the accepted safety
    deviation. The complete isolated Docker suite passes **1,481 tests with 15
    skips** and one existing dependency warning. Focused contact/recovery/schema/UI
    validation passes **75 tests with 1 skip**; recovered-schema/Cisco compatibility
    passes **11 tests**. The disposable final image starts cleanly, the Device
    Collections page and Operator Guide render correctly, and no server error appears
    during the browser check. Independent quality gate: **CLEAR — DOCUMENTED
    DEVIATION**. Novice-operator gate: **CLEAR**. The work remains foundation-only;
    it is committed development capability, not Range-ready or available on `main`.
    Gate 7 shared database and artifact-storage qualification is next.
    **2026-10-12 Gate 7 shared-storage architecture start:** Define and validate the
    storage boundary required before NCT can make any multi-replica claim while
    preserving the approved standalone single-container SQLite profile. This gate
    must select a shared database and artifact-store contract, state which evidence
    remains exact bytes, define migration and rollback without silent deletion, and
    prove that durable work fencing, observations, receipts and presentation repair
    retain the same meaning across the boundary. It does not enable replicas merely
    because a storage service exists, and it does not require Kubernetes for normal
    disconnected use. The independent reviewer must clear the architecture and its
    executable validation before downstream multi-replica or Arkime work relies on it.
    **2026-10-12 Gate 7 architecture package in review:** The formal decision keeps
    embedded SQLite and local content-addressed evidence for standalone and approved
    single-replica operation. PostgreSQL is selected for future multi-replica
    transactional authority, paired with an S3-compatible immutable object contract
    keyed by SHA-256. The machine-readable contract keeps multiple replicas disabled,
    forbids dual writing, defines offline empty-target cutover and separates pre-write
    cutback from post-write restore/reconciliation. System Health explains the current
    and selected future profiles with contextual Operator Guide detail. A storage audit
    also corrected the guarded-upgrade inspector's obsolete Artifact Registry column;
    a populated-registry regression now verifies exact bytes and observations instead
    of exercising only an empty registry. Initial focused validation passes **7 tests**
    with one existing dependency warning. Real disposable PostgreSQL and S3-compatible
    service qualification, backend adapters, migration tooling and Gate 8 remain open;
    this decision package makes no multi-replica readiness claim.
    **2026-10-12 Gate 7 shared-storage decision package complete:** The reviewer
    initially halted the gate because the Kubernetes architecture still described
    PostgreSQL as only a candidate and the machine contract did not enumerate every
    post-write rollback obligation. The documents now consistently point to the
    selected Gate 7 design, and the contract requires export of post-cutover events,
    preservation of the shared target, separate source restoration, later
    reconciliation and an attributed decision receipt. Removing any of those
    requirements invalidates the contract in tests. Focused storage, upgrade,
    System Health and UI validation passes **136 tests** with one existing dependency
    warning; the browser-side runtime-health regression also passes. An isolated
    Docker preview renders the architecture panel and contextual Guide without browser
    console errors. Independent quality gate: **CLEAR** after corrections.
    Novice-operator gate: **CLEAR**. This completes the architecture decision only:
    shared-service adapters, the offline migration command, disposable service
    qualification and Gate 8 concurrency/failure/load testing remain open. Multiple
    replicas remain disabled, and the capability remains foundation-only rather than
    Range-ready or available on `main`.
12. [x] SQLite WAL/busy-timeout/transaction remediation.
   - [x] Confirmed WAL mode at application startup.
   - [x] Confirmed 30-second SQLite busy timeout.
   - [x] Removed repeated Saved Network schema/index DDL from normal access.
   - [x] Removed repeated scan-collaboration schema DDL from normal access.
   - [x] Audit remaining storage modules for repeated request-path initialization/DDL.
     [x] Workspace layouts now initialize once per database file rather than on
     every list/save/default operation. Reviewer CLEAR; 533 full Linux tests passed.
     Independently verified concurrent writer/read, simultaneous initialization,
     replacement database, and initialization retry. Additional corrected modules:
     achievements, exposure reports, host identities, OS overrides, investigation
     notes, network semantics, and preference storage.
     [x] Shared once-per-database initialization completed for those eight modules.
     Existing migrations and compatibility triggers remain intact; failed setup
     retries, file replacement invalidates the cache, and startup runs migrations.
     In-place database restoration requires an application restart.
     Achievements now initializes at startup; lazy initialization remains supported
     for standalone module callers. Reviewer CLEAR; 551 full Linux tests and 40
     final startup/route tests passed. Auth/import schema setup is startup-only;
     existing collection/cache guards remain; backfill setup occurs only on explicit
     jobs. This does not claim all concurrent-write hazards or lock contention solved.
   - [x] Review long write transactions and high-contention write paths. Started
     deterministic simultaneous-edit checks for layouts, notes, and view preferences;
     inspect whether version validation and mutation form one protected operation.
     **QUALITY GATE: CLEAR:** all four simultaneous-edit reproductions (layout, note,
     personal view, filter preset) accepted both writes to version 1 as version 2,
     silently overwriting one change before this fix. Corrected with write transactions that
     protect version/ownership/parent validation and mutation together; reads remain
     read-only and existing conflict responses are retained.
     Full suite: 555 passed; five focused concurrency/rollback tests passed after
     stronger durable-state checks. Independent default/delete, share/delete, audit
     rollback and lock-release checks passed. Recursive note-folder mutations still
     hold a writer slot proportional to branch size; large-data contention remains open.
     - [x] Recursive investigation-note folder gate completed 2026-10-09. A reproduced
       branch-version gap allowed an unchanged folder version to delete a newer edited
       child or overwrite a newer child sharing decision. Recursive share, unshare, and
       delete now require a read-only exact branch preview and opaque descendant revision,
       stage the branch before taking the writer slot, revalidate every staged item and
       new child after the lock, and apply one atomic set-based mutation plus audit record.
       Chunked commits are prohibited. The UI locks the notes workspace before preview,
       shows the full Personal notes path, exact folder/note counts, current shared-page
       impact, and exact completion results. If the server changes data but refresh fails,
       stale editing remains disabled until Refresh succeeds. Rollback, stale-descendant,
       moved/added-child, unrelated-branch, post-staging race, and 1,201-item branch tests
       passed. Final validation after the path wording correction: 1,110 full Linux tests
       passed with 12 expected skips; 75 focused tests and the host-browser runtime
       regression also passed. Live browser delete/share previews were canceled without
       changing data and reported no browser errors. Independent reviewer: CLEAR; novice
       operator gate: CLEAR after the full-path correction. The unavoidable row mutation
       remains inside one write transaction; deeper parent-walk and broader representative
       concurrent-workload benchmarks remain separate follow-up work.
     - [x] Investigation-note parent ancestry gate completed 2026-10-09. Reproductions
       showed that save/move accepted an existing ancestor cycle, missing or cross-owner
       ancestry, and a non-folder ancestor; a non-empty folder could be converted into a
       note, and a 1,500-level target performed 1,500 ancestry reads while holding the
       SQLite writer slot. Save/move now performs one finite, fail-closed structural
       ancestor preflight before the lock, supports at most 128 parent folders, and
       revalidates exact identifier/owner/parent/kind tuples after locking. Moving a folder
       also stages its exact subtree, applies the depth limit to the deepest descendant,
       and is capped at 1,000 total moved items so lock-time work has a finite bound.
       Larger moves are refused without changing the folder. Target version, mutation,
       and audit remain one transaction; non-empty folder conversion is rejected and
       metadata-only ancestor changes do not create false conflicts. A parent-leading
       index and forced existence-only lookup prevent new-child checks from scanning the
       notes table; the same correction now protects recursive share/delete revalidation.
       Corrupt-tree, inverse-move, post-staging drift/addition, exact depth and item-count
       boundaries, audit rollback, query-plan, unrelated-writer/branch, 50,000-unrelated-
       row, and 50,000-post-stage-child checks passed. Final validation: 1,130 full Linux
       tests passed with 12 expected skips and one dependency deprecation warning; 20
       focused ancestry tests passed. The live built-in guide showed the limits and
       all-or-nothing behavior without browser errors. Independent reviewer: CLEAR;
       novice operator guide: CLEAR. The representative local benchmark below closes
       the next reliability subgate; production-scale and Range validation remain open,
       so Step 12 stays partial.
     - [x] Representative workspace contention benchmark completed 2026-10-09. Use a
       disposable database and public storage functions to run simultaneous investigation-
       note, Map-layout, working-view, and filter-preset updates for multiple isolated
       analysts while bounded reads continue. Record per-family latency, wall/CPU time,
       SQLite locked/busy failures, other errors, and exact final version/audit counts.
       Retain the reproducible script and dated results. This establishes a local
       development baseline only; it must not be described as Range-scale or mission-ready
       performance. The retained run uses three identical serial and eight-analyst
       concurrent repeats, 50 cycles per analyst and operation family, 4 KiB payloads,
       a 1,000-item recursive share/unshare/move lane, and bounded readers. It must fail
       on any lock error, conflict, unexpected error, incomplete read progress, missing
       per-family recursive overlap, incorrect payload/version/audit/folder state,
       integrity failure, five-second measured ordinary save, or concurrent p95 above the greater of one
       second and ten times serial p95. Independent start-gate review: CLEAR after
       deterministic recursive overlap and complete descendant/audit checks were added.
       Plain-language result: eight simulated analysts could save separate workspace
       records while reads and a 1,000-item folder change continued; all requested work
       completed and the final saved data and change history were correct.
       Commit `970f25c350ddf29ad7ea8c61f0b6c828fe447205` passed all three
       serial and three concurrent repeats: 400 measured saves per family per run,
       100/100 reads in each concurrent run while writers were active, nonzero recursive
       overlap for every family, zero lock/busy/timeout errors, zero optimistic conflicts,
       zero unexpected errors, exact final payload/version/ownership/audit/folder state,
       and `PRAGMA integrity_check = ok`. Worst concurrent p95 was 15.468 ms and
       worst measured ordinary save was 2,436.065 ms, within the predeclared 1,000 ms
       p95 and five-second ordinary-save limits. Ownership fault tests now prove that
       incorrect primary-row or audit ownership fails the benchmark. Final Linux
       validation: 1,136 passed, 12 expected skips, and one existing dependency
       deprecation warning. Novice documentation gate: CLEAR. Independent completion
       gate: CLEAR. Reproducible script, complete JSON, and plain-language
       report are retained in `scripts/benchmark_workspace_contention.py` and
       `docs/workspace_contention_benchmark_2026-10-09.{json,md}`. This is a local,
       direct, single-process storage baseline only; HTTP/page, network, multi-process,
       cold-cache, large-installation, Range, and mission performance remain unclaimed.
   - [x] Initial disposable synthetic storage measurements executed for 100 and 1,000
     collections: first dry run, initial backfill, repeated backfill, wall time,
     CPU, peak process memory and bytes. Original-file and observation-count checks
     passed. Reviewer CLEAR; report and reproducible script retained. Production-scale,
     cold-cache, multi-process and Range acceptance remain open; the later local
     concurrent-workspace and note-tree subgates are complete above.

   WAL and a 30-second busy timeout were already present before this redesign; the
   remaining reliability work is focused on eliminating unnecessary writes and
   contention.
   **2026-10-12 Step 12 closeout audit start:** Reconcile the remaining partial marker
   against the completed request-path initialization audit, optimistic-write fixes,
   bounded note-tree mutations and retained representative contention benchmark.
   Reinspect explicit writer transactions for network contact, artifact reads, hashing,
   subprocess waits or other unbounded work; require deterministic concurrency and
   rollback coverage for any correction. Close only the foundation development gate
   that is actually supported by evidence. Cold-cache, multi-process, production-scale,
   Range and mission acceptance remain separately labeled and may not be inferred from
   the local benchmark.
   **2026-10-12 active-scan contention correction and Step 12 foundation closeout:**
   The one-second process-supervision loop still checks durable cancellation,
   timeout and ownership on every pass, while clock-only/Nmap display progress is now
   published at most once every five seconds through an explicit fenced progress-only
   path. That path updates the run manifest without deleting and recreating Scan History
   membership rows. Contact start, operator-visible phase changes, cancellation, timeout,
   failure, completion, evidence registration, scheduled-chunk state and lease release
   retain immediate authoritative publication. A failed progress-only write keeps the
   newest in-memory value and retries later; the separate cancellation control row and
   execution fence remain authoritative. A crash can therefore omit only the last few
   seconds of display progress. It cannot erase contact state, a saved stop request,
   evidence, the terminal result or fencing history, and a contacted run becomes
   **Interrupted — Needs attention** without automatically resuming contact.

   Focused scan, queue/history, cancellation, scheduling, writer-shutdown,
   collaboration and UI validation passed **170 tests** with one expected skip
   and one existing dependency warning. Deterministic tests prove bounded progress
   commits, retry after a simulated busy write, no Scan History membership rewrite,
   exact terminal grouping/time/name/host count, immediate stop and timeout behavior,
   durable cross-process cancellation and restart-safe contact recovery. The retained
   disposable contention run executed 100 active-progress saves, 100 analyst-workspace
   saves, 100 background-work lease renewals and 200 reads with zero lock/busy/timeout,
   conflict or unexpected errors; exact final state and SQLite integrity passed. Worst
   lane p95 was 3.879 ms and the slowest operation was 333.293 ms, within the declared
   one-second p95 and five-second maximum limits. A deterministic start barrier proved
   that the three writer lanes were active together and overlapped for 0.524178 seconds;
   the synthetic scan published the normal contact-start state before progress. After
   the first independent review, progress-only writes were also changed to require the
   exact active execution fence, retry only positively identified SQLite busy/locked
   errors, and surface every other database or manifest-file failure through terminal
   handling. Missing, stale, released and replaced fence tests now fail closed.
   Reproduction and full results are in
   `scripts/benchmark_scan_progress_contention.py` and
   `docs/scan_progress_contention_benchmark_2026-10-12.{json,md}`. This remains a local,
   single-process development result; cold-cache, multi-process, production-scale,
   Range, mission and future PostgreSQL performance remain unclaimed. Final independent
   quality gate: **CLEAR** after the exact-fence, error-classification and deterministic-
   overlap corrections. Novice Operator Guide gate: **CLEAR**. The complete Docker
   regression suite passed **1,502 tests with 15 expected skips** and one existing
   dependency warning; `git diff --check` passed with only line-ending notices. The
   final isolated browser preview showed the visible, keyboard-focusable progress note
   opening its dedicated contextual Guide explanation, with no console warnings or
   errors; the novice live recheck was **CLEAR**. This
   closes the Phase 1 embedded-SQLite development remediation gate. Explicit storage
   maintenance remains governed by its separate singleton lease and recovery-required
   contract, while cold-cache, multi-process, production, Range, mission and the future
   PostgreSQL profile retain their own acceptance gates.
13. [~] Current-state read models.
   - [x] Initial typed scoped-evidence read model and lazy operator explorer. This is
     evidence history only; automatic current-state selection remains planned.
   - [x] Latest supported scoped Nmap observations. Select only successful supported
     records on the current unsuperseded assignment, order by validated source windows,
     keep overlapping and unknown-time evidence visible, and link every displayed
     observation to its exact retained source. This remains an evidence-window view;
     broader current truth and physical-device identity are still open.
   - [x] Scoped device interface/address receipts. An append-only whole-collection
     Network Scope decision now starts a separate durable normalization stage for new
     verified device evidence. The extractor verifies the exact selected configuration
     artifact, retains every supported IPv4/IPv6 address, prefix, interface, raw source
     line and routing context, and publishes immutable receipts with successful job
     completion in one transaction. Mixed or unresolved routing contexts fail closed;
     the completed summary and source remain available. The stage does not read the
     shortened device-summary display list, infer scope, create physical-device
     identity, promote configuration assertions to positive sightings, or treat an
     omitted address as disappearance. Historical adoption remains explicit. See
     `docs/DEVICE_OBSERVATIONS.md`.
   - [x] Source-reported MAC address associations. From one saved Nmap receipt, an
     analyst can open a bounded, read-only list of every eligible IP association for
     the same exact MAC inside the selected Network Scope, with source links, timing
     uncertainty, scope-assignment revision protection and local/private-MAC caution.
     This remains investigation evidence and does not create physical-device identity,
     prove DHCP movement, select a current address or calculate exact Last Seen.

   **2026-10-09 address-association evidence start:** add a bounded, read-only
   Steps 13–14 slice that lets an analyst follow one exact source-reported MAC within
   one Network Scope to every retained supported Nmap address/source association. This
   is evidence that can help investigate possible address reuse or a DHCP-related
   hypothesis; it is not a physical-device merge, current-state decision or exact Last
   Seen claim. Only valid
   unicast MACs directly retained in immutable endpoint receipts may participate.
   Broadcast, multicast, malformed, enriched, inferred, hostname-derived and device-
   configuration identifiers are excluded; locally administered addresses carry a
   randomization/private-address warning. The view must keep distinct observations,
   scopes, overlapping/unknown source windows and multiple addresses in one source
   separate; use current unsuperseded assignments, the supported parser and strictly
   successful completion; bind pages to one assignment-set revision; fail on a reviewed
   candidate-work ceiling; and perform no writes, artifact reads, backfill or inference.
   Physical reconciliation, broader current truth, historical adoption and exact Last
   Seen remain open. Independent architecture start gate: CLEAR.

   **2026-10-09 address-association evidence completion:** the
   `source-reported-mac-address-associations:1` selector and Analyze / Changes Over Time
   view now preserve each address, assignment, assessment and retained source as a
   separate row. Only current unsuperseded assignments, the supported Nmap parser,
   successful completion and directly reported valid unicast MACs are eligible. Exact
   validation accepts plain hex, colon-separated octets, hyphen-separated octets and
   Cisco dotted groups; arbitrary separators, junk, zero, multicast and broadcast
   values are rejected. Unknown, equal and overlapping source windows remain visibly
   uncertain; locally administered values warn about privacy, randomization and reuse.
   Pages bind to one assignment-set revision and conflict after a correction. The
   selector opens the database read-only, never reads artifact bytes, and fails without
   partial output above the reviewed 5,000-candidate ceiling. The page includes exact
   source links, persistent limitations, stale-response protection, full-width opened
   records and contextual Operator Guide help. Focused Docker validation: 126 passed,
   1 skipped because Node is unavailable in the image; the skipped host Node runtime
   regression passed separately. Full Docker suite: 1,143 passed, 13 skipped, with the
   existing Starlette dependency warning. Isolated browser validation confirmed two
   IP associations, source windows, retained-source links, local/private caution,
   full-width wrapping and a clean console. Independent final gate: **CLEAR**. Novice
   wording corrections replaced DHCP certainty with a bounded hypothesis and retained
   the limits on physical identity, current address, absence and exact Last Seen. No
   architecture deviation. This remains foundation-branch development work; it is not
   yet Range-ready, mission-ready or available on `main`.

   **2026-10-04 scoped-device-receipt completion:** Device History now records and
   corrects a reviewed Network Scope for one retained collection, shows durable stage
   status, opens paged source-linked address receipts and prevents their retained source
   from being deleted. Device Overview shows the same collection scope and readiness
   without implying live status or physical identity. The independent gate is **CLEAR —
   DOCUMENTED DEVIATION** after adversarial fixes for generated IPv6 syntax, quoted and
   conflicting routing contexts, unsafe mixed-context publication and changed receipt
   replay. Focused validation: 115 passed; independent validation: 44 passed. A
   1,000-interface disposable benchmark completed extraction in 0.103 seconds,
   publication in 0.170 seconds and 100-row page reads in about 0.003 seconds. Live
   isolated browser checks confirmed assignment, completed normalization, two retained
   receipts, source linkage, Device Overview projection and a clean console. The novice
   operator gate is **CLEAR** after adding the explicit missing-address caution and a
   finished Refresh state to the receipt action. Full Docker suite: 988 passed, 3
   skipped. Device History runtime checks and whitespace validation also passed.
14. [~] Last Seen + evidence receipt model.
   - [x] First last-confirmed observation slice for scoped Nmap addresses. Report a
     source collection window with evidence links, never an invented exact timestamp or
     live-online claim. Device observations, exact Last Seen, and automatic service
     absence remain open.

   **2026-10-12 last-confirmed-open service slice start:** Add one lazy, read-only
   service detail for an exact Network Scope, IP endpoint, transport and port. It will
   select only successful supported Nmap receipts that explicitly reported the exact
   requested port open with eligible coverage, retain tied/touching/overlapping and
   unknown-time source windows without inventing an instant, and keep later closed or
   Not assessed state separate from the earlier positive evidence. Every row must retain
   its exact assignment, assessment, encounter, source link, collection window and
   extraction facts. This slice may not merge IPs, create physical-device identity,
   claim live state, prove disappearance, infer DHCP continuity, read artifact bytes,
   hash or parse XML, create jobs, backfill or write. Candidate ceilings must fail before
   JSON decoding; follow-on pages bind to the exact current assignment-set revision.
   Independent architecture start gate: **CLEAR**. Physical-device reconciliation and
   exact Last Seen remain open pending a separately reviewed stable-identity contract.

   **2026-10-12 quality-gate correction resolved:** Independent final review halted
   this slice before completion because the new selector rejected supported port `0`,
   and because exact-coverage and revision-bound timed/uncertain paging needed direct
   adversarial tests. The selector now follows the existing `0..65535` service
   contract. An authenticated API test proves eligible UDP/0 evidence; malformed
   explicit coverage cannot create a claim; and tied timed plus uncertain-time pages
   are deterministic, nonduplicating and rejected after an assignment correction.
   Independent re-review returned **CLEAR**.

   **2026-10-12 last-confirmed-open service slice completion:**
   `last-confirmed-open-service-observation:1` now provides a lazy detail inside each
   latest source-reported service row for one exact Network Scope, IP address,
   protocol and port. It selects only current unsuperseded, successfully completed
   supported Nmap receipts with strict versioned coverage and an explicit `open`
   state. A later closed or Not assessed result stays visible as the current saved
   state without erasing earlier positive evidence. Tied, touching and transitively
   overlapping source windows remain grouped; any successful open report without a
   trustworthy source window blocks an unqualified last claim and remains separately
   paged. Results preserve assignment, assessment, encounter, extraction location,
   source collection window and direct retained-source links. Reads use one database
   snapshot, bind follow-on pages to the current assignment-set revision, enforce both
   5,000-candidate ceilings before stored JSON decoding, and perform no source-file
   reads, hashing, XML parsing, backfill, jobs, network contact or writes. Focused
   Docker validation: **141 passed**. Complete Docker regression: **1,511 passed,
   15 skipped**, with the existing Starlette dependency warning. Host Node syntax
   validation passed. An isolated browser check confirmed a newest **Not assessed**
   443/tcp row can open its earlier confirmed-open source window, retained-source link,
   cautious explanation and contextual Guide with no browser-console errors. The
   novice operator gate and independent final quality gate are both **CLEAR**. This is
   still a source window rather than live truth, physical-device identity, DHCP
   continuity, disappearance proof or an exact Last Seen timestamp. The capability
   remains foundation-branch development work; it is not Range-ready, mission-ready
   or available on `main`.

   **2026-10-04 nested-slice completion:** `latest-supported-nmap-observations:1`
   now powers a lazy Processed Evidence view for one exact Network Scope and IP address.
   It separately shows the latest supported source window and last confirmed positive
   source window, retains ties and uncertain-time records, and links every displayed
   record to its exact source. The independent gate is **CLEAR — DOCUMENTED
   DEVIATION** after correcting full-payload projection and strict JSON boolean
   validation findings. Focused validation: 115 passed. Full Docker suite: 973 passed,
   3 skipped. Live isolated browser checks confirmed the confirmed-versus-assumed split,
   evidence links, guide text and a clean console; the novice operator gate was CLEAR.
   This completes only the documented nested slices. Broader current truth,
   physical-device reconciliation, scoped device observations, exact Last Seen and
   automatic service disappearance remain open.

   **2026-10-10 current reported service-state start:** Add one bounded read-only view
   for a single scoped IP address that selects the latest defensible source-reported
   state separately for each protocol and port. The selector will use only current,
   unsuperseded, successfully completed `nmap-endpoints:2` records and versioned
   coverage receipts. Strictly later non-overlapping source windows may replace an
   older state. Equal, touching, overlapping or unknown-time evidence remains
   unresolved. When the latest ordered record did not assess a previously reported
   port, the result is **Not assessed** rather than an inherited older state. Every
   determination must link to the exact retained source and explain its coverage basis.
   The API will use saved database receipts only, enforce the source-record ceiling
   before decoding stored JSON, and perform no artifact reads, artifact-content
   hashing, XML parsing, backfill, job creation or writes. A hash of assignment identity
   metadata may bind paging to one read-only selection revision without reading or
   verifying evidence bytes. It will be paged, revision-bound and fail without
   partial output above reviewed candidate bounds. Boundary tests will prove these
   restrictions. The operator view and built-in How NCT Works guide
   will say plainly that this is saved source-reported state, not live truth, physical
   identity, exact Last Seen or proof of disappearance. Independent architecture start
   review recommended this bounded gate. Completion requires focused API, correction,
   timing, coverage, duplicate-encounter, delayed-response, guide and browser checks,
   followed by the full Docker suite and an independent final quality gate.

   **2026-10-10 current reported service-state completion:**
   `current-reported-service-state:1` now provides a lazy, read-only view for one exact
   Network Scope and IP address. It selects each protocol/port result from the latest
   strictly ordered successful source window, reports **Not assessed** when that source
   did not cover an older port, and keeps tied, touching, overlapping or unknown-time
   evidence **Unresolved** with every relevant retained source. TCP, UDP and SCTP remain
   separate. Results are paged, bound to one assignment-set revision and capped before
   stored receipt JSON is decoded; stale paging is rejected. The view reads database
   receipts only and creates no artifacts, jobs, backfill or writes. Focused Docker
   validation: **132 passed**. A fresh complete Docker regression run: **1,212 passed,
   14 skipped**, with the existing Starlette dependency warning; an earlier complete
   run had one transient Phase 0 HTTP benchmark miss, which passed immediately in
   isolation and in the fresh complete rerun. The representative 120-address corpus
   returned the selected address's read-only result in about 39 ms. Live browser checks
   confirmed full-width readable details, retained source expansion, plain-language
   labels, a specific Operator Guide explanation and a clean console. The novice
   operator recheck is **PASS**. This remains saved source-reported evidence rather than
   live truth, physical-device identity, exact Last Seen or proof of disappearance.
   Independent final quality gate: **CLEAR**. The reviewer independently reran the
   three affected test files in a network-disabled container (**132 passed**) and found
   the implementation read-only, bounded, source-linked, revision-safe and consistent
   with the documented no-claim boundaries. No material finding remains.

   **2026-10-10 service-state header-order correction start:** The live operator check
   found that the shared sticky-table rule could hold the service-state headings below
   the first visible result while scrolling. Keep sticky headings for long tables, but
   make this compact per-address result use normal table order so headings always render
   before its first service row. Completion requires a focused contract test and a live
   browser geometry check at the operator's current viewport. Per user direction,
   heading order, alignment, sticky behavior and horizontal overflow are now permanent
   whole-tool novice-operator checks in `docs/NCT_PROJECT_OPERATING_RULES.md`.

   **2026-10-10 whole-tool heading audit follow-up start:** The new standing novice pass
   found that the open resizable Guide can cover rightmost table columns on desktop in
   Hunt, System Health and Current Network, and that one LFA result can place hundreds
   of addresses inline in a single cell until its headings scroll away. Reserve the
   Guide's actual current width in the desktop workspace, update that reservation when
   the pane is resized or closed, and collapse large LFA address lists into a bounded
   scrollable disclosure. Preserve horizontal table scrolling and the Guide's existing
   resize, pin, top/bottom dock and narrow-screen behavior. Completion requires focused
   tests, representative browser geometry with the Guide open and resized, a repeated
   novice pass and independent review.

   **2026-10-10 service-state header and whole-tool heading audit completion:** The
   compact per-address service-state table now renders its headings in normal document
   order. On desktop, the workspace reserves the Guide's measured width in comfortable,
   compact and spacious density, including with the navigation sidebar open or
   collapsed. At narrower desktop widths, the Current Network and Hunt bulk tables use
   labeled, keyboard-focusable internal scroll regions so all columns remain available,
   their headings remain attached during vertical scrolling and no column sits behind
   the Guide. Both pages explain this behavior in visible operator text. Large LFA host
   lists keep all retained addresses but collapse them into a labeled 260-pixel keyboard
   scroll region; the disclosure changes from **show list** to **hide list** while open.
   Browser checks at a 1,400-pixel viewport covered all three density modes and both
   sidebar states. Boundary checks at 1,600 and 1,601 pixels and a large-desktop check
   at 2,000 pixels widened the Guide from 350 to 710 pixels; Current Network and Hunt
   still ended at least 32 pixels before the Guide. Every repaired table ended at least
   26 pixels before the Guide, and keyboard horizontal and vertical scrolling retained
   aligned headings. The repeated
   whole-tool novice audit is **PASS**, including Nmap history, Analyze changes, Hunt,
   Reach, device history, System Health, Current Network and LFA, with a clean browser
   console. Focused Docker validation: **65 passed**. A fresh network-disabled Docker
   regression run: **1,212 passed, 14 skipped**, with only the existing dependency and
   read-only test-cache warnings. The first run in the long-lived preview container
   exceeded the benchmark's whole-container cumulative memory peak; the required fresh
   container stayed within the limit. Independent final quality gate: **CLEAR** after
   confirming the 1,600-pixel cutoff was removed, desktop protection now applies at
   every width above the existing narrow-screen overlay boundary, and the accessibility,
   evidence-preservation and keyboard-scroll contracts remain intact.
15. [~] Benchmark against Phase 0 datasets.

   **2026-10-09 representative-dataset prerequisite start:** build one versioned,
   deterministic synthetic corpus before comparing performance. The corpus will cover
   small TCP-only Nmap, medium UDP-only Nmap, time-separated combined TCP/UDP history
   with known changes and duplicate bytes, four 1,000-host Nmap files across separate
   subnets, representative router/firewall/switch evidence including the existing
   1,000-interface boundary, and a frozen offline enrichment-heavy workload with exact
   cache expectations. Every file must have a retained size and SHA-256 digest plus a
   correctness oracle. Generation and verification must be local, disposable and free
   of operator, Range, mission or production evidence. The generator may not overwrite
   an existing directory. This prerequisite does not complete Step 15: stable `main`
   and foundation must still run the same declared benchmark in clean Linux images,
   retain raw measurements and pass correctness/resource limits chosen before the run.
   Independent architecture start gate: **CLEAR**. Novice documentation direction:
   keep engineering detail in the dated report and do not present a static development
   result as live System Health or Range readiness.

   **2026-10-09 representative-dataset prerequisite completion:**
   `phase0-benchmark-corpus:1` now generates 17 deterministic synthetic files totaling
   about 3.5 MB. The retained manifest fixes the generator version and seed, exact
   SHA-256/size for every input, exact per-file Nmap and device parser counts, known
   history changes, duplicate bytes, and offline candidate/cache expectations. The
   frozen enrichment command, configuration and database path are part of the hashed
   corpus; the real adapter produced 24 cold queries, 24 warm cache hits, 240 candidate
   associations and 24 CVEs as declared. Verification regenerates the canonical bytes
   and full manifest rather than trusting editable recorded hashes, and rejects existing
   output paths, unsafe paths, links, missing files, extra files, changed files and a
   changed file paired with an updated manifest hash. Focused Linux validation: **9
   passed**. Complete Docker regression suite: **1,152 passed, 13 skipped**, with the
   existing Starlette dependency warning. Novice documentation gate: **CLEAR** after
   explicitly separating this developer dataset from live System Health. Independent
   quality gate: **CLEAR** after correcting the initial manifest-trust, incomplete
   enrichment identity and broad-oracle findings. This completes only the shared
   dataset prerequisite; Step 15 remains in progress until exact stable `main` and
   foundation revisions run the retained benchmark procedure under predeclared limits.

   **2026-10-09 core-engine comparison runner start:** add a revision-neutral worker
   for one fresh-process repeat of the directly comparable stable/foundation core:
   every Nmap parser workload, known historical comparison, every device parser
   workload, and the frozen offline enrichment workload. Declare absolute and relative
   limits plus the three-repeat median rule in code before either retained branch run.
   Each retained repeat must use a new network-disabled Linux container, read-only
   source/corpus mounts and a nonexistent data path; record the actual source-tree
   digest, Git revision evidence, container image identity, runner digest, corpus
   manifest digest, wall/CPU time including child work, whole-container peak memory,
   retained cache size, correctness results and every limitation. Stable `main` has no
   persistent query cache, so its repeated query work remains a directly measured
   baseline while foundation cache reuse is a separately asserted capability. HTTP and
   bounded-page endpoints, foundation persistence views, Analyze/Hunt/Reach/Map requests,
   rendered browser timing, multi-process load, Range hardware and mission data remain
   required later Step 15 slices. Independent architecture start gate: **CLEAR**.

   **2026-10-09 core-engine comparison runner completion:** the revision-neutral
   worker and three-repeat summarizer now enforce the canonical corpus rather than
   trusting an editable manifest; reject linked inputs and reused state; verify the
   complete workload and result oracle; and measure parser, history, device and
   offline-enrichment work with predeclared absolute and relative limits. Retained
   reports require external controller evidence for an exact clean Git revision,
   mounted source digest, inspected image, unique fresh container, disabled network
   and read-only source/corpus mounts. Storage accounting includes every file in the
   disposable data root, including SQLite side files. The summary rejects missing
   workloads, cross-branch correctness drift, reused containers and workload-level
   or whole-run wall/CPU/memory regressions. Focused Linux validation: **17 passed**.
   Complete Docker regression suite: **1,169 passed, 13 skipped**, with the existing
   Starlette dependency warning. Independent quality gate: **CLEAR** after the
   initial manifest, identity, workload, retained-storage and whole-run comparison
   findings were corrected. Step 15 remains in progress: retain and summarize three
   isolated stable `main` runs and three isolated foundation runs next, then add the
   still-unmeasured HTTP, persistent-view and rendered-browser slices.

   **2026-10-09 retained core comparison completion:** three fresh isolated runs
   of stable `main` `fc979133634fe068c7dd13b5aa6b0cb873305c0e` and three of
   foundation `aca02905ca29256ff58cca701a74968b1da2bf99` passed the canonical
   correctness oracle and every predeclared absolute and relative limit. All six
   used unique inspected containers from image
   `sha256:1b573eed7a2e0311ee21e3be7c212ef02a288c2cfc1c16516b7bec43ddc15a85`
   with networking disabled and read-only source/corpus mounts. Median whole-run
   wall time was 3.839 seconds on stable and 3.689 seconds on foundation; CPU time
   was 5.498 versus 4.028 seconds; peak memory was 173,367,296 versus 177,496,064
   bytes. Foundation retained a 36,864-byte query cache and converted all 24 warm
   enrichment requests to cache hits; stable repeated all 24 searches. Raw reports
   and the passing machine summary are retained under
   `docs/benchmarks/phase0-core-20261009/`. This closes the retained core-engine
   slice. Step 15 remains **in progress** for HTTP/persistent-view, rendered-browser,
   multi-process, Range-hardware and production-scale measurements; this result does
   not establish Range or mission readiness.

   **2026-10-09 HTTP and persistent-view benchmark start:** extend the retained
   comparison through in-process public HTTP requests against deterministically
   staged canonical evidence. The fixed common capability matrix covers Hunt Network
   Evidence, the complete Current Network response, Reach context and Map; missing
   expected routes fail rather than being skipped. Foundation-only acceptance covers
   bounded Current Network first/last pages, filtered export and LFA plus bounded
   Processed Evidence scope, endpoint, observation and service receipts. Finish all
   staging and foundation processing before timing, freeze source order, stop background
   work, and describe the one fixed ordered request session without relabeling shared
   cache reuse as an independent cold request. Require exact status/content type,
   revision-bound row order/totals, full export/LFA semantics, fixed response-size
   ceilings and unchanged retained evidence/database state after reads. Common endpoints
   use the predeclared three-repeat median relative rule; foundation-only endpoints use
   predeclared absolute limits. These are TestClient in-process HTTP measurements.
   Rendered-browser, multi-process, Range-hardware, production-scale and mission
   performance remain separate later gates. Independent architecture start gate:
   **CLEAR**.

   **2026-10-09 HTTP and persistent-view comparison runner completion:** the
   revision-neutral worker now stages the complete canonical Nmap/device corpus
   before timing and executes one fixed ordered in-process HTTP session. Common
   stable/foundation requests cover complete Current Network, shared Hunt and Map
   reuse, and Reach. Foundation-only requests cover revision-bound Current Network
   pages, full filtered export and LFA, and bounded Processed Evidence catalog,
   endpoint, latest-observation and service receipts. The `10.20.0.0/24` filter has
   an exact 120-address oracle: a 100-row first page, non-overlapping 20-row final
   page, identical complete export and exact LFA membership. The valid 120-host UDP
   input provides the same strict Processed Evidence paging proof; the synthetic
   1,000-host files retain repeated service rows and therefore remain complete-view
   scale inputs rather than strict processed-view inputs. No 1,000-host processed
   scale claim is made. The runner enforces response status/content type, exact
   result/order identities, byte/resource ceilings, external Git/container
   attestations, and unchanged retained evidence. Foundation requests must leave the
   logical database and database file unchanged. Stable `main` may change only its
   existing `device_analysis_cache`, `device_collections` and `scan_analysis_cache`
   tables, and the report names that legacy read-path behavior. Focused Linux
   validation: **24 passed**. Independent quality gate: **CLEAR** after correcting
   cross-branch evidence identity, filter, final-page, row-order and validation-fixture
   findings. Complete Docker regression suite: **1,176 passed, 13 skipped**, with
   the existing Starlette dependency warning. Retained three-repeat branch
   measurements are next. These are in-process TestClient measurements and do not
   establish rendered-browser, multi-process, Range, production-scale or mission
   performance.

   **2026-10-09 retained HTTP and persistent-view comparison completion:** three
   fresh isolated runs of stable `main`
   `fc979133634fe068c7dd13b5aa6b0cb873305c0e` and three of foundation
   `611854cc737a57857da648574bae19144e424426` passed the exact correctness
   oracle and every predeclared absolute and relative limit. All six used unique
   inspected containers from image
   `sha256:1b573eed7a2e0311ee21e3be7c212ef02a288c2cfc1c16516b7bec43ddc15a85`
   with networking disabled and read-only target/corpus mounts. Both revisions
   returned the exact ordered 4,188-host Current Network and 6,125 Hunt findings.
   Foundation also passed the exact 120-address filtered page/export/LFA and
   strict Processed Evidence page oracle and bounded endpoint/latest/service
   requests without changing evidence or its database; stable changed only the
   three declared legacy cache tables.
   Median whole-run wall time was 14.091 seconds on stable and 13.245 seconds on
   foundation; CPU time was 8.066 versus 6.624 seconds; peak memory was
   475,942,912 versus 570,290,176 bytes. The first foundation Current Network
   build was slower at 5.289 versus 3.719 seconds but passed its ceiling; repeated
   Current Network, Hunt, Map and Reach requests were faster in this local run.
   Map results differ materially by revision: stable reports 2 interfaces, 2
   subnets and 47 relationships, while foundation's newer exact topology rules
   report 1,000 interfaces, no synthetic subnets and 1,041 relationships. Each
   exact result repeated three times, so Map timing is a revision comparison rather
   than identical-output work. The initial summary rejected the unmodeled stable
   Map result; the exact branch-specific oracle was added without changing any raw
   run, and independent review returned **CLEAR**. Raw reports, the passing machine
   summary and a plain-language report are retained under
   `docs/benchmarks/phase0-http-20261009/`. This closes the retained HTTP and
   persistent-view slice. Step 15 remains **in progress** for rendered-browser,
   multi-process, Range-hardware and production-scale measurements; this result
   does not establish Range or mission readiness.

   **2026-10-09 rendered-browser benchmark start:** measure the canonical corpus in a
   real Chromium browser with three fresh isolated repeats for each exact stable and
   foundation revision. Direct Analyze, Hunt, Reach and Map loads and same-context
   reloads must reach exact revision-specific rendered results with no page, console
   or request failures; foundation also exercises the 100-row Current Network page,
   its 20-row final page and the corresponding 100/20 Processed Evidence pages. Record
   action-to-ready time, navigation timing, long tasks, DOM size, JavaScript heap,
   transfer size and separate application/browser resource use under limits declared
   before retained runs. Prestage and finish processing before timing, prewarm HTTP,
   start each cold measurement in a fresh browser context, block external requests,
   use fixed browser/viewport/locale/time-zone settings, require two stable animation
   frames, attest every source/image/container/browser/corpus/runner identity and prove
   retained database and evidence bytes do not change after prewarm. Raw JSON,
   screenshots and failure traces remain retained. This slice does not establish human
   workflow, multi-process, GPU, Range, production-scale or mission readiness.
   Independent architecture start gate: **CLEAR**. Live preflight stopped Current
   Network before any rows were shown because the label for analyst-imported hostnames
   was missing. Restore that label and independently confirm the complete roster loads
   before recording benchmark measurements.

   **2026-10-09 rendered-browser preflight repair completion:** restored the shared
   analyst-hostname label used by Current Network and retained scan rows, including its
   scanner-conflict provenance and output escaping. The runtime regression now covers
   absent, normal and conflicting imported-hostname cases. An isolated real-Chrome
   check rendered rows 1-25 of the complete 4,188-host Current Network result where the
   page previously stopped before showing any row. Focused validation passed 65 tests
   with 1 expected skip; the complete Docker suite passed **1,176 tests with 13
   expected skips**; the host JavaScript runtime regression and whitespace check passed.
   Independent quality gate: **CLEAR**. The browser benchmark remains in progress; its
   harness must handle only the predeclared favicon request while treating every other
   page, console and request failure as fatal.

   **2026-10-09 rendered-browser environment deviation:** no Chromium or Playwright
   browser image is installed in the local Docker inventory, and the isolated NCT Linux
   test image contains no browser executable. Use the same SHA-256-identified local
   Chrome executable and Playwright version for all six runs, with a new Chrome process,
   temporary profile and browser context for every repeat. Each application repeat still
   runs in a unique fresh Docker container with disposable data, and every non-loopback
   browser request is blocked. Record separate application and browser process resource
   use, unique process/profile/container identities and cleanup. Independent gate:
   **CLEAR - DOCUMENTED DEVIATION**. This is a same-host Chrome comparison; it is not a
   browser-container, Linux-browser, Range or mission performance result.

   **2026-10-09 rendered-browser runner completion:** a revision-neutral controller now
   creates fresh canonical data, keeps the application on a unique internal-only Docker
   network, and exposes it to the local browser through a disposable loopback relay. It
   externally verifies clean Git, exact source/corpus/image/container/network/browser
   identities, read-only mounts, completed staging/prewarm, fresh data and profile roots,
   and cleanup. The browser attaches failure monitoring to existing and future pages,
   blocks all non-loopback requests, verifies exact revision-specific Analyze, Hunt,
   Reach and Map content and order, rechecks every raw limit in the summary, retains fixed
   success screenshots, and preserves failure screenshots and traces. A complete stable
   `main` rehearsal passed the 4,188-address, 6,125-finding, 47-relationship and Reach
   oracles, resource limits, unchanged-state check, 32-process Chrome tree, eight success
   screenshots and full temporary-resource cleanup. The controller-bound final result
   also retains the exact raw result, before/after evidence state, all seven harness
   component identities, and independently checked screenshot files. Focused regression
   validation passed **18 tests with 1 expected container-Node skip** and the host
   fault-injection self-test passed; the complete Docker suite passed **1,194 tests with
   14 expected skips**. Independent quality gate: **CLEAR - DOCUMENTED DEVIATION** after
   verifying the exact final stable rehearsal, all six previously open evidence controls,
   and the documented same-host Chrome limitation. At that gate, retained three-repeat
   measurements had not started.

   **2026-10-09 retained-run finding:** the first three stable repeats completed, but the
   first foundation repeat stopped at the predeclared browser-memory gate: 2.682 GiB
   observed versus a 2.5 GiB limit. The failed repeat still proved complete removal of its
   app container, relay, internal network, temporary data and browser profile. Do not
   treat the partial matrix as retained evidence. Add per-workload browser-memory sampling
   to identify the responsible page before changing application behavior or any limit.

   **2026-10-09 Hunt bounded-render correction start:** diagnostic sampling isolated the
   peak to Hunt at 2.629 GiB; Analyze was 1.344 GiB, Reach 1.190 GiB, and Map 0.886 GiB.
   Keep the complete loaded Hunt evidence available to filters and exports, but render a
   bounded 25-, 50-, or 100-row table page after applying the active filters. Preserve
   combined host summaries, individual filtered findings, Inventory, saved CVE details,
   full filtered export, exact ordering and Operator Guide explanations. The 2.5 GiB
   browser limit remains unchanged.

   **2026-10-09 Hunt bounded-render implementation and runtime-regression complete;
   memory recheck pending:** Hunt now applies all active filters to the complete loaded
   evidence, then renders a shared 25-, 50-, or 100-row page for combined capability
   summaries, individual filtered findings, and Inventory. The CSV action exports every
   filtered finding across all pages. A retained Chrome benchmark oracle now exercises
   Previous/Next, all page sizes, Inventory, filter-before-page behavior, complete
   filtered export, and CVE/exposure filters spanning pages on both cold and reload
   navigation. The novice review clarified the Quick filter and CSV Operator Guide text.
   The focused isolated suite passed **84 tests with 1 expected environment skip**, and
   the browser-runner syntax/self-test passed. Do not resume retained comparison runs or
   mark this correction complete until the unchanged 2.5 GiB limit passes a fresh
   foundation Chrome rehearsal and the independent reviewer clears the evidence.

   **2026-10-09 controller compatibility correction:** the first retained rehearsal was
   rejected before measurement because Windows PowerShell wrote a byte-order marker into
   the generated JSON configuration. Cleanup removed every disposable resource. The
   runner now accepts either standard UTF-8 or UTF-8 with that marker, and its self-test
   covers both forms. This changes harness input compatibility only; it does not change
   application behavior, the corpus, or any performance limit.

   **2026-10-09 Hunt bounded-render correction complete; quality gate CLEAR —
   DOCUMENTED DEVIATION:** the exact committed Windows Chrome rehearsal exercised all
   four fixed pages plus Hunt Previous/Next, 25/50/100 row sizes, Inventory paging,
   filter-before-page behavior, complete filtered CSV, and CVE/exposure filters across
   multiple pages on cold and reload navigation. Chrome peaked at **1.588 GiB** under the
   unchanged **2.5 GiB** limit, compared with the earlier 2.629 GiB diagnostic. The app
   peaked at **397.8 MiB**; retained state was unchanged; screenshot hashes matched; and
   all disposable containers, network, data and browser profiles were removed. The
   independent reviewer verified the exact commit and seven harness component hashes.
   The complete isolated suite then passed **1,195 tests with 14 skipped**. The accepted
   same-host Windows Chrome limitation remains documented; begin a new six-run retained
   comparison rather than reusing the invalid partial matrix.

   **2026-10-09 retained comparison preparation halt and correction start:** all six new
   runs individually passed, but the strict matrix validator rejected them because fresh
   preparations did not have one exact logical database identity. Investigation showed
   benchmark-only scope, observation and assignment IDs and initialization timestamps
   were generated at run time, while the Artifact Registry retained the controller's
   unique staging path instead of the `/data` path used by the measured container. Keep
   the validator strict. Freeze benchmark-only IDs and clocks during preparation, restore
   process globals afterward, and rewrite registered artifact paths to their correct
   runtime `/data` location. The rejected six-run set is invalid comparison evidence and
   must not be summarized or reused.

   **2026-10-09 deterministic preparation correction complete:**
   two independently created foundation data roots now have the same logical database
   hash, physical database hash, table counts, every per-table digest and evidence hash.
   The preparation context restores the real UUID and clock functions before returning,
   and targeted tests cover restoration, safe path rebasing and the disposable catalog
   timestamp. The focused isolated benchmark suite passed **22 tests with 1 expected
   environment skip**, and the complete isolated suite passed **1,198 tests with 14
   expected skips**. Independent review returned **CLEAR — DOCUMENTED DEVIATION**:
   the prepared files are byte-for-byte repeatable, the registered evidence resolves
   under the measured container's `/data` path, and the remaining same-host Windows
   Chrome limitation is explicit. Begin a new six-run retained matrix; do not
   retroactively bless either rejected matrix.

   **2026-10-09 retained comparison second halt and correction start:** all three stable
   repeats and all three foundation repeats passed their browser oracles and cleanup
   checks, but the strict summary again rejected the set. The earlier proof covered the
   foundation preparation path only. Stable-main cache identities still incorporated
   fresh staging file times and a live SQLite cache timestamp, so repeat databases were
   not identical. Keep the set rejected. Prepare through the same `/data` path used by
   the measured container, normalize benchmark-only evidence file times before cache
   creation, and freeze disposable cache timestamps after prewarming. Prove both stable
   and foundation preparations independently before starting another retained matrix.

   **2026-10-09 second correction complete:** two fresh stable
   preparations now match in logical database hash, physical database hash, table counts
   and evidence hash. Two fresh foundation preparations were then started as complete
   applications, prewarmed through Analysis, Hunt, Reach and Map, and again matched in
   logical database hash, physical database hash, table counts and evidence hash after
   startup. Selector-catalog reconciliation now returns without a write when its current
   rows, schema marker and clean-state marker already match source authority. Focused
   browser, summary and catalog tests passed **35 tests with 1 expected environment
   skip**, and the complete isolated suite passed **1,201 tests with 14 expected skips**.
   A reviewer-identified tied file-time risk was then removed by assigning each synthetic
   device a distinct deterministic order and requiring the exact expected selected device
   ID in the preparation oracle. The corrected two-run stable proof matches at logical
   database hash `dd19340a...`, physical database hash `ae3b05ca...` and evidence hash
   `e2b217c4...`; the corrected two-start foundation proof matches at logical database
   hash `629b15d6...`, physical database hash `42c66c4f...` and evidence hash
   `894afa79...`. The final complete isolated suite passed **1,201 tests with 14 expected
   skips**. Independent review returned **CLEAR — DOCUMENTED DEVIATION** and confirmed
   that both proof pairs are byte-for-byte identical, device selection is explicit, and
   catalog reconciliation preserves the database only after checking complete current
   state. The existing same-host Windows Chrome limitation remains documented. A new
   retained six-run comparison may begin; all earlier rejected matrices remain invalid.

   **2026-10-09 retained rendered-browser comparison complete:** stable main `fc979133`
   and foundation `3a42d6c` each passed three fresh
   Chrome runs. The strict summary confirmed identical starting databases within each
   version, exact retained-state preservation during every run, all page and pagination
   oracles, all declared absolute limits, and complete cleanup. Median browser peak
   memory was **1,787,838,464 bytes** on stable main and **1,741,778,944 bytes** on the
   foundation build; median application peak memory was **263,340,032 bytes** and
   **406,986,752 bytes**, respectively. Foundation Hunt cold readiness was **1,618 ms**
   with **2,096 rendered nodes**, compared with **4,115 ms** and **139,168 nodes** on
   stable main, while preserving all **4,188 hosts** and **6,125 findings**. Retain the
   strict summary, all six run records, cleanup proofs, resource samples and screenshots
   under `docs/benchmarks/phase0-rendered-browser-20261009/`. The result remains limited
   to same-host Windows Chrome; it is not a multi-analyst, Range, production-scale or
   mission-performance claim. Final independent evidence review returned **CLEAR —
   DOCUMENTED DEVIATION**: all six records, identities, screenshots, cleanup hashes,
   limits and summary figures verify, and no rejected matrix is represented as valid.

   **2026-10-09 eight-client single-worker concurrency benchmark start:** exercise the
   actual deployment shape: one normal single-process Uvicorn NCT container under
   eight synchronized, independent OS client processes, each using its own authenticated
   analyst account and session. Run three fresh foundation repeats against the canonical
   synthetic corpus. Use a fixed mixed sequence of bounded Current Network, Hunt, Reach,
   Map and personal-workspace reads plus isolated note, layout, view and filter-preset
   saves. Include one deliberately synchronized same-record version collision; require
   exactly one accepted update and one expected conflict with complete audit history.
   Treat any timeout, unexpected 4xx/409, 5xx, worker exit, malformed response or SQLite
   locked/busy message as failure. Require exact read results and response bounds, reads
   completing while writes overlap, exact per-owner state and audit records, no cross-owner
   visibility or mutation, and an unchanged logical database outside the declared auth and
   workspace rows. Retained evidence files must remain byte-for-byte unchanged. Record
   p50/p95/max latency, throughput, total wall time, separate application/client CPU and
   peak memory, exact source/image/corpus/runner/container/process/data-root identities,
   and cleanup under limits fixed before any retained run. The deployment must be verified
   to contain exactly one Uvicorn application process. Stable `main` is not compared because
   the tested authenticated workspace and bounded foundation endpoints are foundation-only;
   the earlier retained core, HTTP and browser slices provide the cross-version comparisons.
   Independent architecture gate: **CLEAR — DOCUMENTED DEVIATION**. This is multi-process
   analyst-client load against one application process. It does not validate multiple NCT
   server workers, worker leases/checkpoints, multiple application containers, live scans,
   long-duration use, Range hardware, production-scale history or mission readiness.

   **2026-10-09 eight-client single-worker concurrency benchmark complete:** foundation
   `b5ee87c9cd0ec3482d3183bc48ab73f33148c2c0` passed three fresh retained repeats
   using eight independent simulated analyst processes and one verified Uvicorn
   application process. Every repeat completed **394 recorded workload operations**:
   each analyst ran four mixed read/save cycles plus an ownership-isolation check, and
   two synchronized clients produced exactly one accepted same-record update and one
   expected version conflict. Ten additional login requests occurred inside each repeat's
   wall-time measurement but are excluded from its workload latency and throughput
   calculations; account and synthetic-record setup occurred before timing.
   The strict summary independently recalculated response content, request order,
   latency, read/write overlap, fixed limits, raw-file hashes, per-owner final records,
   audit sequences, logical database changes, evidence preservation, resources,
   process/container identity and cleanup with no failures. Median wall time was
   **67.04 seconds**, median throughput **5.877 requests/second**, median read p95
   **5.187 seconds**, and median write p95 **0.281 seconds**. Median application peak
   memory was **933,421,056 bytes** and median client peak memory **1,863,012,352
   bytes**; both stayed below the fixed **2,147,483,648-byte** limits. The harness
   failed closed during rehearsal on direct-helper import and read-only SQLite-open
   defects; both were corrected, regression-tested and independently cleared before
   retained runs began. Retain the summary, all three raw run records, attestations,
   logs, resource/process captures and cleanup proofs under
   `docs/benchmarks/phase0-concurrent-clients-20261009/`. Final independent evidence
   review returned **CLEAR — DOCUMENTED DEVIATION** after verifying every retained
   hash, result binding, count, measurement, identity and cleanup proof. Novice wording
   review returned **CLEAR**, and the final complete Docker suite passed **1,206 tests
   with 14 expected skips**. This is a local synthetic single-worker development
   result, not a multi-worker, live-scan, Range, production, or mission-readiness claim.

## Exit criteria

- Reopening a page does not recreate expensive analysis.
- Duplicate imports do not reproduce work.
- Duplicate service fingerprints do not reproduce enrichment.
- Failed enrichment does not destroy previous valid analysis.
- Last Seen remains traceable.

---

# PHASE 2 — Existing Characterization Refactor

**Purpose:** Move current capabilities onto the persistent engine before adding
high-volume passive evidence.

## Steps

1. Preserve and improve Saved Networks.
   2026-09-27 scan-navigation refinement start: under **Nmap Scans**, group only
   Saved Networks, No-Strike Exclusions and Scan Profiles under one nested,
   collapsible **Scan Details** entry. Keep New Scan, Active Scans, Schedules,
   Scan History and Import Nmap Evidence beside that subgroup. Preserve direct
   task links, current-page highlighting, keyboard disclosure behavior and
   automatic expansion of every ancestor while a contained task is active.
   Scan-navigation refinement completion: the shared shell now supports nested
   disclosures and opens every ancestor for the active task. **Scan Details**
   contains exactly Saved Networks, No-Strike Exclusions and Scan Profiles; all
   other Nmap destinations remain sibling links with unchanged addresses. Direct
   loading, keyboard disclosure, active highlighting, collapsed navigation and
   Operator Guide behavior passed live browser review with no console errors.
   **QUALITY GATE: CLEAR**; full Docker suite **655 passed**, independent focused
   suite **80 passed**, novice operator review **PASS**, and `git diff --check`
   found no whitespace errors.
   - Add an optional, persistent association from a Saved Network to one active
     Network Scope. Analysts may select or deliberately change the association;
     administrators continue to create and archive scope identities.
   - Show the inherited scope during scan review, carry its exact opaque ID into
     each future scan run and artifact observation, and do not ask the analyst to
     select it again for every scan. A later Saved Network change must never rewrite
     the scope retained with earlier runs or evidence.
   - This is an explicit reviewed association, not scope inference from the Saved
     Network name, CIDR or target text. Manual XML without a trustworthy Saved
     Network link continues to require an explicit whole-file decision.
   2026-09-27 Saved Network scope-association implementation start: record each
   analyst choice as an append-only, revision-checked association event instead
   of changing a scope field in place. A scan made only from Saved Networks may
   inherit a scope when every selected network has the same current active scope;
   manual, combined, unassociated and mixed-scope requests remain visibly
   unscoped and are still allowed to collect. At submission NCT must recheck the
   reviewed association under the same write lock that records an immutable run
   scope snapshot. Scoped artifact observations copy that retained snapshot, so
   later Saved Network or scope changes cannot rewrite history. New schedules pin
   the reviewed scope context at creation and stop with an explicit error if that
   scope is later archived. Existing Saved Networks, runs, artifacts and schedules
   remain readable and unscoped; no name, CIDR, target, filename or content-based
   scope inference or backfill is permitted.
   Saved Network scope-association completion: the Saved Network editor now saves
   target details and future-scan context as one transaction, with required reasons
   for assignment, change or clearing and a clear unscoped choice. Submission rechecks
   the exact reviewed association under the run write lock; database rules bind each
   run, schedule and artifact snapshot to its authoritative scope and source rows,
   reject archived scopes, malformed audit data, stale direct-run associations and
   cross-origin mutation, while retaining a schedule's already-reviewed context after
   later Saved Network changes. Scan review and history show the retained context;
   manual, combined, mixed and unassociated targets remain visibly unscoped. The first
   independent review halted on weak direct-write provenance, a local-mode origin gap,
   a schedule error response and partial two-step saves; a second attack pass found
   historical-association and archived-scope insert gaps. All findings were corrected
   and independently reproduced. **QUALITY GATE: CLEAR**; full Docker suite **664
   passed**, independent focused suite **95 passed**, novice operator review **PASS**,
   and live browser save, inherited scan review and console checks passed. No scope is
   inferred and no earlier run or evidence is rewritten. No architecture deviation.
   2026-09-27 finalized-scan foundation processing start: add an explicit, retryable
   Scan History action for the retained aggregate `scan.xml` from a finalized automated
   run whose immutable run and artifact-observation context already carry one reviewed
   Network Scope. Resolve the exact observation and scope server-side, never infer from
   target text or current Saved Network settings, and never process discovery/TCP/UDP
   component XML as separate assessments. Status reads must remain read-only; processing
   must reuse the verified Nmap adapter and atomic coordinator, retain exact replay and
   failure recovery, create no scan or network contact, and leave current Analyze, Hunt,
   Reach and Map consumers unchanged. Unscoped, mixed-context, manual-target and legacy
   runs remain visibly ineligible rather than receiving a guessed scope.
   2026-09-27 finalized-scan foundation processing complete (foundation): Scan History
   now offers analysts and administrators an explicit, retryable action for one completed
   run's registered aggregate `scan.xml`. The server resolves the exact run, artifact
   observation, immutable Network Scope and signed-in actor; component XML and client
   scope/parser/actor claims are excluded. Processing verifies the canonical bytes,
   records durable running/complete/error/interrupted status, preserves corrected
   assignment history and exact replay, and publishes assessment, entity and receipt
   records atomically without network contact or changes to current views. Startup marks
   stranded work retryable, and status reads remain read-only. The first final review
   halted on unsafe file-first scan deletion, nondeterministic same-second retry ordering
   and active work being labeled interrupted. All three were corrected: protected single
   and bulk deletion now fail closed before any file removal, concurrent processing and
   deletion are serialized by the database, true insertion order selects the latest
   attempt, and running work is distinct from restart-recovered interruption. Processed
   or scope-linked scan history is therefore intentionally retained; unprotected scan
   deletion remains available. **QUALITY GATE: CLEAR**; full Docker suite **697 passed**,
   focused deletion/processing suite **44 passed**, novice operator review **PASS**, and
   live browser reload, retained-scope, guide and console checks passed. No architecture
   deviation; No-Strike behavior and current Analyze, Hunt, Reach and Map views remain
   unchanged.
   2026-10-04 novice end-to-end operator-validation start: an entry-level network
   analyst is using only the built-in Operator Guide in an isolated Docker lab to
   create scope and Saved Network context, run authorized Nmap evidence collection,
   perform a real password-prompt SSH configuration pull, and follow the retained
   evidence through Current Network, Network Devices, Changes Over Time, Hunt, Reach,
   Map, exports, and System Health. The gate requires each main workflow to be used at
   least once, exact instruction gaps to be corrected, a clean reload/console check,
   independent quality review, and a novice retest. The first finding is a wording
   contradiction: loopback-only local development is deliberately accepted as a secure
   browser context, while the page stated that every plain-HTTP address was disabled.
   2026-10-04 novice end-to-end operator-validation complete (foundation):
   the novice completed the normal analyst path with only the live UI and Operator
   Guide against an isolated `172.30.77.10/32` lab target: scope and Saved Network
   setup, No-Strike/profile review, direct Nmap scanning, a real password-prompt SSH
   configuration pull, retained history and source files, scoped device receipts,
   Current Network, Network Devices, Changes Over Time, Hunt, Reach, Map, exports, and
   System Health. Findings corrected explicit analyzer-interface selection, the local
   loopback secure-context explanation, an informational Cisco VRF line that had been
   mistaken for unsupported configuration syntax, and automated intake being frozen
   before the aggregate `scan.xml` was registered. Independent review then reproduced
   the remaining restart window between final XML registration and intent creation.
   Startup recovery now closes only that bounded case: the run must have the new immutable
   intake marker, completed status, exactly one registered aggregate `scan.xml`, intact
   canonical content, and no existing intent. Unmarked historical runs remain untouched.
   Run
   `041f8c6a1b5e46e8938d295a4f259a5d` then completed on `eth1` with one directly
   responsive host; automatic processing required no manual queue action, Scan History
   showed Scoped evidence ready, and System Health simultaneously showed Ready with all
   three stages complete. The guide and page wording now explain repeated running/startup
   address receipts, saved-scan confirmation limits, missing source-time ordering,
   unrelated retained evidence in Current Network and Map, and the single-scan HTML
   report. Shared exports provide an accessible visible download-start confirmation.
   The novice used every main workflow and passed the final browser retest. The left
   selector remained usable, with a non-blocking follow-up to consider a clearer linear
   preparation path because Network Scopes and Saved Network/scan-safety setup currently
   require backtracking and `Scan Details` can sound like results rather than setup.
   Final full Docker suite **1006 passed, 4 skipped**; updated focused suite **128
   passed**; crash-window/explicit-route suite **20 passed**; all four
   browser-runtime regression scripts passed; `git diff --check` passed. **QUALITY GATE:
   CLEAR - DOCUMENTED DEVIATION**. Instead of widening final artifact registration into
   a cross-module atomic admission transaction, the accepted restart-safe design uses a
   narrowly bounded startup reconciliation over immutable new-run markers and exact
   finalized aggregate authority. This preserves existing registry transaction boundaries
   while excluding unmarked history and incomplete or ambiguous aggregate evidence. This
   clearance is foundation-development only; it is not Range, mission, or stable-main
   acceptance.
   2026-10-04 authorized home-network validation start (foundation): validate the
   complete live workflow against the user-authorized `10.0.0.0/24` home subnet with
   a dedicated Saved Network, immutable Network Scope association, and scan profile.
   The exact coverage is Nmap top 1,000 TCP ports plus top 100 UDP ports, service
   version detection, and traceroute. The preflight must confirm the analyzer route,
   shared No-Strike state, effective target count, and split TCP/UDP command plan
   before contact. Exploit-DB must be installed into NCT's offline read-only database
   first. Completion requires retained source evidence, automatic foundation intake,
   manual SearchSploit candidate enrichment from the new scan, a second identical
   enrichment request proving persistent-cache reuse, browser review, and independent
   quality review. No address outside `10.0.0.0/24` is authorized by this validation.
   First-run deviation: profile v1 used normal `T3` timing and was cancelled cleanly
   after 37 minutes when the TCP phase remained at 97 percent and projected beyond the
   one-hour run limit, leaving insufficient time for UDP. Its audit record is retained.
   Profile v2 kept the exact authorized targets, port coverage, service detection,
   traceroute, scope and No-Strike state while using NCT's standard fast `T4` timing;
   it was cancelled cleanly at approximately 24 percent after 12 minutes when the user
   redirected local acceptance to common ports and reserved the full top-port run for
   the Range analyzer. UDP retained its bounded retry and per-host timeout controls.
   2026-10-04 Active Scans queue-presentation refinement start: keep the actively
   executing scan as the default and only main progress detail. Waiting scans move to
   a compact expandable list that exposes their retained settings and cancellation
   control without replacing the live scan. When no scan is executing, the main panel
   should clearly report analyzer availability while the waiting list remains usable.
   Completion requires queue-order/cancellation regression coverage, guide updates,
   live browser checks with active and pending work, and novice and independent review.
   2026-10-04 authorized home-network development acceptance complete: the user-approved
   local acceptance profile used common TCP and UDP ports, service detection, fast
   timing and traceroute against only `10.0.0.0/24`. Run
   `f3909b15395f4c0dbccc0dc25125be10` completed both protocol phases in approximately
   nine minutes with exit code zero, retained the aggregate and per-protocol XML,
   standard output/error, packet capture and manifest, and registered the aggregate
   `scan.xml` with SHA-256
   `604c66a1fd039bcbf4fea4a34283e56a78475cb93c5ea0b6865caedaa81ec8a2`.
   Eighteen addresses answered discovery, sixteen returned direct Nmap response
   evidence, and two `-Pn` assumed-up targets were retained without being counted as
   confirmed hosts. Automatic foundation intake completed on its first attempt for the
   explicit Home Network scope without manual processing. Offline SearchSploit then
   searched 26 findings through 14 distinct product/version queries, skipped 14 findings
   without a product, matched six systems to 132 analyst-review candidates, and returned
   39 CVEs, 108 CVE-linked candidates, 24 candidates without CVEs and no warnings. An
   identical repeat returned 14 cache hits and zero misses. The Hunt browser showed the
   same totals and the candidate-not-vulnerability qualification with no browser errors.
   The official Exploit-DB archive is retained as offline read-only version
   `20261004T230037Z-04bbeb489265` with archive SHA-256
   `04bbeb4892650d0332ae2b93c3e7c1187f4c74e6ca4f26cbcad1ae477c7005d0`.
   The originally requested top 1,000 TCP plus top 100 UDP coverage is intentionally
   deferred to the Range acceptance run; the two cancelled local attempts remain in
   the audit history and are not represented as completed evidence.
   2026-10-04 Active Scans queue-presentation refinement implementation complete:
   the main panel follows only the run using the analyzer and otherwise reports that the
   analyzer is available. Pending scans remain in a separate count-bearing dropdown;
   each row exposes the saved target, profile version, protocol/port coverage, interface,
   timeout, owner, requester, queue position and cancellation control. Queue refreshes
   preserve an open row. An isolated live browser acceptance kept the active run visible
   while a pending row remained open across multiple refreshes, cancelled the pending
   scan without changing the active run, then cancelled the active test and returned to
   the idle state. The page and contextual guide explain the separation. Focused UI
   coverage passed **62 tests**. Novice review **PASS** identified one non-blocking
   ambiguity when waiting work exists during an idle transition; the empty state now
   says that waiting scans appear below and start in queue order. The full Docker suite
   passed **1006 tests with 4
   skipped**, all four browser-runtime scripts passed on the host, `git diff --check`
   passed, and the Nmap and Hunt browser consoles remained clear. This is foundation
   development acceptance only; it is not Range, mission, stable-main or production
   acceptance.
   2026-10-04 Active Scans independent-review halt and correction start: the reviewer
   reproduced four gaps that normal-timing browser acceptance did not expose. A queue
   refresh could close a waiting row opened while its request was in flight; an active
   run could disappear after more than 200 newer history records; an older active-status
   response could overwrite a newer response; and opening historical details replaced
   the live Active Scan panel. Downstream completion remains halted until active work is
   queried independently of history limits, asynchronous responses are generation-owned,
   waiting-row state is captured immediately before rendering, and retained details open
   inside Scan History. Actual-handler race regressions, large-history server coverage,
   live browser validation, full-suite validation and independent re-review are required.
   2026-10-04 Hunt exploit-reference consolidation start: remove the manual Find
   potential matches action and the separate Offline exploit matches selector. Hunt
   Network Evidence will automatically compare retained product/version fingerprints
   with the active offline Exploit-DB index after network-wide or focused evidence loads.
   Candidate filters, exposure context, cache behavior, candidate-not-vulnerability
   wording and offline database management remain available in that workspace. A newer
   evidence selection must own the enrichment response so stale results cannot replace
   the current view. The built-in How NCT Works guide and contextual Operator Guide must
   explain the automatic, offline, non-executing analysis.
   2026-10-04 Active Scans correction validation complete, independent re-review
   pending: the queue endpoint now selects every queued or active run before applying
   any history limit. Queue and active-view requests use generation ownership so older
   responses cannot replace newer state, open waiting rows are captured immediately
   before rendering, and retained details expand inside their Scan History row without
   replacing or stopping the live Active Scan view. Actual production-handler runtime
   tests reproduce the in-flight row and response-order races; the server regression
   places one running scan behind 205 newer completed records. Live browser validation
   kept the idle Active Scan state unchanged while opening the completed home-scan
   commands and evidence downloads inline. The earlier quality-gate halt remains in
   force until the independent reviewer reproduces and clears these corrections.
   2026-10-04 Hunt exploit-reference consolidation implementation validation complete,
   independent re-review pending: Network Evidence automatically runs the local offline
   candidate comparison after both network-wide and focused evidence loads. The manual
   button and separate navigation entry are removed; all candidate, CVE, exposure and
   database-management controls remain in Network Evidence. Generation ownership drops
   obsolete enrichment responses. The focused home evidence and combined network view
   each automatically returned the expected 14 queries, six matched systems, 132
   candidates and candidate-not-vulnerability explanation, with no browser console
   errors. The built-in guide and contextual guide describe the automatic local analysis.
   Focused tests passed **78 with 2 skipped** because Node is not installed in the Linux
   container; both production-handler JavaScript regressions passed directly on the host.
   The full Docker suite passed **1007 with 6 skipped**, and `git diff --check` passed.
   These changes remain foundation-development only and are not Range, mission or
   stable-main acceptance.
   Live user acceptance immediately found that the revised Network Evidence task rule
   exposed the overview, filters and automatic candidates but omitted the Systems panel,
   hiding the host rows even though their data had loaded. The task grouping now keeps
   Systems visible with Network Evidence and keeps automatic candidate context visible
   when Systems is selected. This presentation regression requires browser revalidation
   and remains part of the pending independent gate.
   The independent re-review then reproduced two cross-handler races that the first
   generation tests did not cover: an older queue response could clear a newer active
   lookup, and an older focused Hunt request could replace a newer evidence selection
   before starting candidate analysis. Active-state reads now share applied-response
   ownership across queue, lookup and polling while retaining separate poll continuity;
   Hunt uses one evidence-selection generation from initial load through automatic
   candidate association. Cross-handler production-code regressions are required before
   the halt can clear.
   2026-10-04 Hunt candidate-presentation revision start: user acceptance rejected a
   separate candidate-results section. Keep hosts and services in the Systems bulk table,
   associate CVE references with the exact host/service row, and expand titles and links
   in place. Candidate filters and offline database management move under Network Filters.
   Network Evidence must show the Systems table by default. This revision preserves
   automatic offline analysis and candidate-only semantics while removing the extra
   candidate workspace and navigation surface.
   2026-10-04 Hunt candidate-presentation implementation complete, quality gate
   pending: Network Evidence now keeps automatic offline candidate analysis inside
   the Systems bulk tables. The combined Capabilities view has one expandable CVE
   cell per matched host; filtered finding rows keep service-specific expansion, and
   Inventory provides one host-level expansion. The former candidate-results section
   and navigation entry are absent. Candidate and CVE filters plus offline database
   maintenance remain collapsed under Network Filters. Browser validation loaded 18
   systems, associated six matched systems from 14 product/version queries and 132
   candidates, and showed a single combined 28-CVE/86-candidate expansion for the
   multi-service test host. Reviewer-found corrections ensure that a newer no-op active
   scan confirmation owns status over older queue responses, duplicate hostnames across
   Network Scopes cannot share candidates, and CVE/year/status/exposure filters change
   the visible candidate lists in both Capabilities and Inventory. Focused validation
   passed **78 tests with 2 skipped**; the full Docker suite passed **1007 with 6
   skipped**, both production-handler JavaScript regressions passed, browser checks and
   the browser console were clean, and `git diff --check` passed. Novice operator review
   **PASS** found the unified placement and navigation understandable; large candidate
   lists remain deliberately collapsed and filterable. **QUALITY GATE: CLEAR —
   DOCUMENTED DEVIATION.** Full top-port coverage remains deferred to Range acceptance,
   and offline candidate associations remain review leads rather than confirmed
   vulnerabilities. This is foundation development acceptance only; it is not Range,
   mission, stable-main or production acceptance.
   2026-10-04 offline exploit-reference maintenance relocation and Range-package
   preparation start: move full Exploit-DB update, air-gapped upload, saved-version
   activation and rollback controls from Hunt filters to Settings / System Health.
   Keep the active database readiness visible in Hunt and add an obvious shortcut beside
   Refresh network view. The maintenance page must explain staging, activation, rollback,
   and that reference updates neither rescan the network nor change retained evidence.
   After browser, focused, full-suite, novice and independent review, build an immutable
   air-gapped package with the exact tested NCT and Caddy images plus a SHA-256 checksum.
   Package preparation does not establish Range readiness; target installation, HTTPS,
   login, password reset, offline database upload and live device-field acceptance remain
   separate checks on the Range.
   2026-10-04 offline exploit-reference relocation implementation complete and package
   source candidate validated: Hunt keeps database readiness beside its automatic CVE
   filters and adds Manage offline exploit references beside Refresh network view. Full
   online update, air-gapped archive upload, staged activation and saved-version rollback
   now live in the first System Health section with a four-step operator explanation.
   The built-in README, air-gapped guide and contextual Operator Guide use the new path.
   Novice review initially found three generic hover topics; the archive selector,
   previous-version selector and Hunt shortcut were corrected and rechecked **PASS**.
   The independent gate is **CLEAR — DOCUMENTED DEVIATION** because System Health remains
   administrator-only while the existing update API authorization contract is unchanged.
   Focused checks passed **100 tests**, final script/UI/API checks passed **79 tests**, the
   full Docker suite passed **1007 with 6 skipped**, the Hunt runtime regression and every
   Range shell syntax check passed, browser navigation and installed-database status were
   verified, the browser console was clean, and `git diff --check` passed. Included Range
   scripts now agree on `network-characterization-tool:0.16.0-range-20261004-r1`.
   Building and checksumming the immutable image bundle remains the next packaging step;
   target-Range acceptance remains pending.
   2026-10-04 final operator-acceptance corrections start: before sealing the Range
   package candidate, keep each Least Frequency Analysis table header above its first
   result at every scroll position. Also remove the ambiguous Hunt `Port / source`
   wording by labeling the column simply `Port` and naming the detected service and
   product fingerprint separately, with an explanation visible in the Systems
   workspace. Re-run browser, focused, full-suite, novice and independent quality gates
   before packaging.
   2026-10-04 Hunt Inventory CVE disclosure revision start: replace the expanded host's
   flat CVE chips and candidate list with a compact hierarchy grouped first by observed
   port/protocol, then by individual CVE. Keep the complete candidate set available,
   retain candidates without a CVE in a labeled group under the related port, and keep
   every port and CVE collapsed until the analyst chooses to open it. Each port must also
   offer one control to show or collapse all of that port's CVEs at once.
   2026-10-04 final operator-acceptance corrections implemented and independently
   reviewed by the novice operator **PASS**, final quality gate pending: LFA peer-group
   headers now remain in normal table order above their first result at initial load and
   after scrolling. Hunt labels the two evidence columns `Port` and `Service / product
   fingerprint`, explains both directly in Systems, and groups every host's candidate
   references under collapsed port/protocol and CVE levels. A per-port control opens or
   collapses every CVE for that port without opening other ports; candidate references
   lacking a CVE remain in a separate collapsed group. The Operator Guide explains port,
   CVE, show-all and collapse actions. Focused UI checks passed **62 tests**, the Hunt
   runtime regression passed, the full Docker suite passed **1007 with 6 skipped**, live
   browser interaction verified 28 CVEs and 86 candidates grouped across four ports with
   14 CVEs under 80/tcp, both browser consoles were clean, and `git diff --check` passed.
   These are foundation development checks; Range installation and acceptance remain
   pending, and the air-gapped package will be rebuilt only after the final reviewer gate.
   2026-10-04 final Hunt table acceptance revision start: user review found that the CVE
   cell compressed into a narrow, tall column in the Capabilities view and that Dataset
   badges required a trip back to the filter panel. Give candidate cells a readable
   minimum width with controlled wrapping and horizontal table overflow, and make every
   Dataset badge apply the existing Dataset filter in place. Selecting the active badge
   again must clear that filter; the active badge and filter summary must stay in sync.
   2026-10-04 final Hunt table acceptance revision implemented, novice recheck and final
   quality gate pending: Dataset badges now apply or clear the existing filter and update
   its visible summary and pressed state. Live interaction narrowed 18 combined host rows
   to 12 individual Remote Access & Administration findings, then restored all 18 rows on
   the second selection. Candidate cells now reserve at least 340 pixels, use a 1440-pixel
   scrollable table floor, wrap long reference text within the cell, and stretch the
   per-port control across the available width; the measured live example rendered at
   about 400 pixels instead of the earlier narrow stack. The focused UI suite passed
   **62 tests**, the expanded Hunt runtime regression passed, the full Docker suite passed
   **1007 with 6 skipped**, the live browser console was clean, and `git diff --check`
   passed. The Operator Guide explains that Dataset badges change the visible filter only.
   2026-10-04 final operator-acceptance quality gate complete: novice operator recheck
   **PASS** confirmed the Dataset apply/clear cycle, active state, guide explanation,
   readable large and small candidate groups, horizontal scrolling, and clear Port and
   Service / product fingerprint labels in both Capabilities and Inventory. The
   independent reviewer returned **CLEAR — DOCUMENTED DEVIATION** after 67 independent
   tests, the expanded Hunt runtime check and diff checks. The documented deviation is
   the user-directed replacement of the prior flat candidate expansion with nested
   port/CVE disclosure plus direct Dataset badge filtering; exact references, filters,
   candidate-only semantics and retained evidence are preserved. Stable `main` remains
   clean. This source is accepted for the next immutable package build; Range installation
   and operational acceptance remain pending.
   2026-10-04 immutable offline package candidate complete: the local transfer bundle
   `NCT-Air-Gapped-Range-Deployment-0.16.0-20261004-r1.zip` contains the exact
   independently cleared source image from commit `479c332`, the locally retained
   `caddy:2-alpine` image, the agreed Range scripts, an updated operator quickstart,
   an internal SHA-256 checksum and a verification receipt. The exact-image smoke
   reported the expected version, build ID and source commit; Hunt, System Health and
   Analyze loaded successfully. Every packaged shell script passed syntax validation,
   the package image tag was consistent, the extracted inner archive matched its
   checksum, and the outer ZIP has its own adjacent SHA-256 file. This is a locally
   verified transfer candidate only. It has not been pushed or installed on the Range;
   Range HTTPS/login, password reset, offline Exploit-DB upload, live device fields and
   operational acceptance remain pending.
   2026-10-04 Range `r2` release-candidate preparation start: GitHub advanced the same
   foundation branch with reviewed full Cisco history collection and multi-site roadmap
   work before the local `r1` line was pushed. Reconcile both histories without force,
   retain legacy `show history` readability, and issue a distinct `r2` image and transfer
   bundle from the merged, fully tested commit. Preserve `r1` as a prior local candidate;
   do not silently replace its recorded digest or checksum.
   2026-10-04 Range `r2` release-candidate preparation and guarded installation complete:
   the remote work was merged without rewriting history, legacy and full Cisco history
   remain readable. The foundation branch was pushed at `d75fb67`; the exact
   `0.16.0-range-20261004-r2` image from that commit was packaged, checksum-verified
   and installed on the Range. The full suite
   passed **1007 with 6 skipped**, the focused device-history recovery suite passed
   **52 tests**, and the Range-script suite passed **9 tests**. The independent reviewer
   returned **CLEAR — DOCUMENTED DEVIATION** for the dual Cisco-history compatibility
   path and retained multi-site planning boundary. The guarded upgrade preserved the
   `/var/lib/nct/data` bind mount, retained a checksum-backed data backup and the stopped
   prior container for rollback, and reported the exact expected version, build and
   source commit. Pre/post inventories matched at **47,950 files**, **6 analyst users**,
   **12 Saved Networks**, **8 scan runs**, **9 scan profiles** and **1 schedule**; startup
   logs contained no repeated error, and the separate legacy terrain containers remained
   running. Read-only inspection found all eight historical scan runs complete and still
   unregistered in the Artifact Registry. They remain visible and are parsed directly
   from retained XML until the operator explicitly tests storage backfill; no backfill,
   compaction or saved-analysis action was run during installation. Browser login and
   operator feature acceptance remain pending by user direction, so this is an installed,
   backend-verified Range build rather than completed operational acceptance or promotion
   to `main`.
   2026-10-04 Hunt navigation consolidation start: remove the redundant `Systems`
   sidebar destination while retaining its complete Capabilities and Inventory tables
   inside `Network evidence`. Keep the existing `systemsPanel` anchor for compatible
   direct links. The planned Timeline will use related filters to explain when evidence
   appeared or changed; it complements rather than replaces the current-evidence tables.
   2026-10-04 Hunt navigation consolidation complete: the separate `Systems` sidebar
   destination is removed, while the full Capabilities and Inventory views remain under
   `Network evidence` as `Hosts and services`. Existing `#systemsPanel` links still open
   the retained section. Timeline guidance now tells novice analysts that it will answer
   when observations first appeared or changed, while Network Evidence answers what the
   selected evidence currently reports. Validation: 71 focused UI tests and the full
   suite (1007 passed, 6 skipped); browser checks covered both table views, the legacy
   link, final explanatory text, and a clean console. Novice review passed after the
   wording improvement. Independent quality gate: CLEAR (final recheck: 62 UI tests).
   This is committed development work on `foundation/evidence-engine-v2`; the installed
   Range image remains unchanged until the next deliberately packaged release.
2. Preserve/fix global and scan-specific NO-STRIKE enforcement.
   2026-09-27 No-Strike enforcement review start: verify the shared and
   scan-specific exclusions across safety previews, direct queued scans, scheduled
   scans, fallback paths and portable packages. Define and expose the exact timing
   boundary for queued, running and downloaded work; prevent concurrent safety-list
   changes from losing one another; retain the exact exclusions actually certified
   for each run or package; and stop safely when exclusions remove every target.
   Global exclusions remain additive and profiles must never bypass them.
   2026-09-27 No-Strike enforcement complete (foundation): shared exclusions now
   use atomic, append-only numbered revisions with validated addresses, UTC times
   and server-bound operator identity. Queued, recovered, scheduled, discovery,
   TCP, UDP and approved-fallback contact boundaries recertify the current shared
   list plus the run-specific additions and stop safely when no targets remain.
   Intersecting new rules signal every affected active run before attempting audit
   writes, while the revision and intersection are retained whenever storage is
   available. Scheduled recovery keeps the original target batches; older records
   without that saved list pause for review. Portable packages retain one static
   generation-time safety snapshot. Authenticated analysts may add protection,
   administrators remove it after confirmation, fallback decisions remain with the
   owner or an administrator, and local mode uses the server-owned local-operator
   identity. The prior settings row remains an atomic rollback-compatible mirror;
   re-upgrade conservatively combines exclusions added by older software and
   requires reviewed removals to be repeated. Legacy queued commands are upgraded
   without corrupting their terminal wrapper. **QUALITY GATE: CLEAR**; full Docker
   suite **682 passed**, independent focused safety suite **142 passed** plus **9
   authentication regressions**, novice operator review **PASS**, and live browser,
   contextual-guide and console checks passed. No architecture deviation; timing,
   restart, rollback and static-package boundaries are documented in the built-in
   guide.
3. [x] Saved scan profiles:
   - TCP
   - UDP
   - TCP + UDP
   - FPING
   - Traceroute
   - ICS-oriented
   - Custom
4. [x] Retain canonical scan creator, profile, target, protocol and scheduling context.
   Optional callsign display remains Phase 8 presentation and never replaces the
   canonical audit identity.
5. [x] Improve progress and bounded ETA. The Nmap estimate is explicitly scoped to the
   active discovery/TCP/UDP phase; the hard timeout remains a separate complete-run
   safety boundary.
6. [x] Resolve combined TCP/UDP reliability issues. Split phases retain separate
   evidence and an analysis-ready aggregate, preserve a successful protocol when its
   peer fails, and pass deterministic top-1,000 TCP plus top-100 UDP execution. The
   equivalent full live workload remains a Range acceptance check.
7. [x] Make historical Analyze reopen full persisted analysis.
8. [x] Expand scan comparison:
   - hosts
   - ports
   - protocols
   - services
   - versions
   - OS
   - MAC
   - identity
9. Device-config persistence/comparison/deletion.
   - [x] Cisco IOS/IOS XE collection uses `show history all` for retained command-history evidence rather than `show history`, which only reflects the current EXEC-session buffer. Keep vendor/platform history commands separate and preserve legacy collection readability.
   - 2026-10-04 integration validation correction: after reconciling the remote
     Cisco history work with the foundation pipeline branch, full-suite validation found
     that replacing the missing-manifest fallback with only `show history all` broke
     verified summaries for retained legacy evidence labeled `show history`. New
     collections keep the explicit `show history all` command in their manifest. When an
     older manifest has no command identity, the compatibility reader accepts either
     embedded label, preferring `show history all` when both exist. This restores
     file-wrapper/direct-calculation equivalence without reducing new collection coverage.
10. Collapsible/filterable route/config displays.
11. Consolidate TXT/IP-by-OS and related exports into Export Manager.

---

# PHASE 3 — Mission Environment, Tool Access, and Blind Spots

**Purpose:** Teach NCT what collection tools exist, what is authorized, and what
cannot be seen.

**Implementation status (partial Phase 3 declaration, visibility and exact-scope
collection gate completed 2026-10-13):** Foundation-only on
`foundation/evidence-engine-v2`. Settings / Mission
Environment now retains explicit tool availability, version and non-secret access
descriptions; per-Network Scope Nmap, Arkime, Kibana and configuration coverage;
Nmap authorization descriptions; device-evidence depth; fixed blind spots; reasons;
optimistic versions; and immutable before/after audit history. Missing records are
read-only Unknown / Unconfigured values and create no database rows. Authenticated
viewers, analysts and administrators can read bounded pages and history;
administrators (or the trusted local operator when authentication is disabled) make
attributed changes. Archived scopes keep their declarations and history but reject
new changes. The active-scan-prohibited blind spot is derived from the single Nmap
authorization value so the two displays cannot disagree. Schema contract v5 provides
a restart-safe migration from v4 and fails closed on unrecognized drift. New scan
work now rechecks exact selected Saved Network associations and Mission Environment
versions before it can be retained or contact can begin. A reviewed prohibited scope
blocks preview, portable package generation, active-run admission, runnable schedules
and dispatch. Manual and unassociated targets remain explicitly Unknown.

**Accepted authorization boundary:** “Authorized” is an administrator-recorded
description, not permission granted by NCT. “Prohibited” is enforced only after exact
Saved Network, Network Scope and declaration-version review; “Unknown” remains visible
and does not imply permission. Existing scan authorization procedures and No-Strike
controls remain authoritative. The
implementation does not infer authorization from installed software, addresses,
CIDRs, names, Saved Networks, targets, prior evidence, or scan history. Scope-based
scanner warnings, collection enforcement and relevant passive-pivot guidance now use
exact reviewed Saved Network context. Actual Arkime/Kibana queries and ingestion,
evidence-driven coverage, automatic stale/gap detection and broader analysis adaptation
remain later gates. Phase 3, Range readiness and mission readiness remain open.

**Validation:** compile checks and **231 focused Mission Environment, scope, package,
scan-execution, schedule, pipeline, profile and UI checks passed**. The exact-container
full suite passes **1,614 tests with 16 skipped** and one existing dependency warning.
Two deliberate race tests change the reviewed declaration after queue admission and
during portable-package assembly. The final pre-contact transaction blocks the run
before `started_at`, tcpdump or Nmap, releases its leases and retains the reason. The
final package transaction rejects the stale review and writes no ZIP. Browser
validation on the isolated `mission-gate-final2-20261013` build showed the exact scope,
declaration version, prohibited warning and relevant Arkime pivot; disabled Run,
Package and Preview actions; explicit Unknown for manual targets; aligned headers and
readable guidance at desktop and 900-pixel widths; and no console warnings or errors.
Hunt also completed its initial network-evidence load without the legacy `items.map`
failure or timeout. The novice operator gate returned **PASS**. The independent quality
gate first halted for the two race windows above, then returned **CLEAR — DOCUMENTED
DEVIATION** after independently passing 18 final boundary checks. Actual Arkime/Kibana
queries and ingestion, evidence-driven coverage, stale/gap detection and broader
analysis adaptation remain open, so Phase 3, Range readiness and mission readiness
remain open.

## 3.1 Mission Environment settings

- [x] Foundation declaration UI, durable records, bounded history, role controls and
  built-in operator guidance. Tool-specific integration remains open.

Under the settings/hamburger menu, define the hunt environment:

- Arkime version
- Kibana/Elastic version
- Nmap availability/version
- Device-config availability
- Access method
- Network scope
- Authorization constraints

## 3.2 Authorization scope

- [x] Explicit per-Network Scope Nmap authorization description with Unknown default,
  plus exact Saved Network collection warnings and prohibited-scope enforcement.
  Manual/unassociated targets remain Unknown; broader analysis adaptation remains open.

Examples:

```text
10.10.0.0/16 — Nmap authorized
10.20.0.0/16 — Nmap prohibited
10.30.0.0/16 — authorization unknown
```

NCT must never equate tool availability with authorization.

## 3.3 Device evidence availability

- [x] Explicit device-evidence depth declaration with Unknown default. Automatic
  comparison to retained collections remains open.

Examples:

- Full configuration
- Partial configuration
- Command output only
- Analyst-known/manual
- Unavailable

## 3.4 Coverage matrix

- [x] Bounded, scrollable Network Scope matrix with Nmap, Arkime, Kibana and
  configuration columns. Evidence-driven coverage calculation remains open.

Show per-network evidence availability:

| Network | Nmap | Arkime | Kibana | Config |
|---|---|---|---|---|
| Engineering | Available | Available | Available | Partial |
| DMZ | Prohibited | Available | Available | Available |
| Management | Available | None | Available | Partial |

## 3.5 Blind spots

- [x] Fixed reviewed blind-spot declarations, with active-scan-prohibited derived
  from Nmap authorization. Automated stale/gap detection remains open.

Explicitly model:

- No passive coverage
- Active scan prohibited
- Missing configuration
- Unknown NAT
- Partial route knowledge
- Telemetry gap
- Stale evidence
- Unsupported parser/field mapping

## 3.6 Adaptive UI

[x] **Exact-scope adaptive collection gate completed 2026-10-13.** Resolve every
selected Saved Network through its current reviewed Network Scope and Mission
Environment declaration. Relevant passive pivots require both tool availability and
per-scope coverage. A known Nmap-prohibited scope must block runnable previews, active
run admission, portable packages, enabled schedules, manual schedule starts and final
dispatch using one server-side decision. Association and declaration versions are
rechecked before admission/contact and retained with accepted work. Manual,
unassociated and mixed manual portions remain Unknown and never inherit permission
from a matching CIDR. No-Strike and the established operator authorization process
remain separately authoritative. A prohibited paused schedule may be retained as a
clearly blocked planning record, but enabling, manual occurrence creation, cadence
dispatch and a previously prepared waiting occurrence all recheck the live decision
before a worker can start. Actual passive-tool integration and evidence use remain open.

Only show relevant pivots for the configured environment.

If the team has Arkime + Kibana only, do not produce filters for 15 unrelated
products.

---

# PHASE 4 — Manual and Partial Evidence Intake

**Purpose:** Allow analysts to partially fill gaps without pretending the evidence
was machine-collected.

## Intake modes

- Paste configuration
- Paste CLI output
- Structured device form
- Manual interface
- Manual route
- Manual ACL/policy
- Manual NAT relationship
- Manual service
- Manual host relationship
- Analyst observation

## Provenance

Manual evidence records:

- Analyst
- Callsign
- Time
- Source description
- Confidence
- Notes

Manual evidence can participate in Map/Reach/Hunt/etc., but remains visually
distinct from collected evidence.

---

# PHASE 5 — Universal Query and Pivot Engine

**Purpose:** Make every meaningful object a launch point for deeper investigation.

## Common context

- Host
- IP
- Subnet
- Port
- Protocol
- Service
- Source
- Destination
- Time range
- Evidence source

## Contextual actions

- Analyze
- Hunt
- Timeline
- Reach
- Map
- Generate Arkime filter
- Generate Kibana filter
- Add to Lens
- Add to Dashboard
- Pin to Report
- Create Finding
- Create Recommendation

## Filter generation

Provide:

- **Minimal** — shortest useful filter
- **Narrow** — additional context
- **Exact** — isolate specific evidence when practical

Always include the required timeframe when known.

## Kibana profiles

Map logical fields to the environment's actual schema.

---

# PHASE 6 — Arkime and Passive Characterization

**Purpose:** Make passive traffic capable of standing on its own when Nmap is
unavailable or prohibited.

Arkime support must be **tiered**.

- [~] **2026-10-19 — isolated passive-integration test range development started.**
  NCT is being developed and validated in an isolated test range with Arkime and
  Security Onion so passive-evidence integrations can be exercised without treating
  development work as deployed capability.
- [x] **2026-10-20 — bounded Arkime lab validation completed.** Representative
  retained packet evidence was captured and searched successfully, and the lab was
  returned to its prior operating state after the test. Detailed operational evidence
  is retained in `docs/RANGE_OBSERVABILITY_VALIDATION_RECORD.md`.
- [~] **2026-10-20 — Security Onion lab replacement started on verified separate
  local storage.** Hardware-health evidence stopped the planned reuse of the existing
  shared pool. Its volumes remain untouched while replacement manager/search and sensor
  guests are provisioned on separately verified storage. This is a test-range recovery
  decision, not a Security Onion or NCT readiness claim; exact evidence and limits are
  retained in `docs/RANGE_OBSERVABILITY_VALIDATION_RECORD.md`. During manager setup,
  the ISO's default kernel crashed while configuring Fleet. The manager was moved to an
  alternate kernel already present on the same verified ISO; recovery and
  acceptance testing then exposed a separate search-process crash. Host BIOS and
  microcode remain a stability gate before manager acceptance can resume. The prepared
  firmware update was safely deferred without flashing; all replacement Security Onion
  guests remain stopped. Bounded passive-evidence development may continue on the
  separate development workstation with copied exports or isolated fixtures, but the
  host and Security Onion acceptance gates remain open.
- [~] **Arkime and Security Onion integration testing remains in progress.** This work
  does not yet establish Tier A passive-network analysis, full Arkime and Security
  Onion integration, Range readiness, mission readiness, or availability on main.
- [x] **2026-10-21 — FPING fallback compatibility repaired after live home-VLAN
  scans failed before their TCP and UDP phases.** Four operator-started scans retained
  a clear failure reason instead of evidence: FPING reported no responsive hosts, then
  the fallback preview tried to flatten independently selected TCP and UDP top-port
  scopes into one command. NCT now preserves the two exact protocol phases, shows both
  full-target commands before approval, and retains the explicit authorization gate.
  The scan builder, fallback approval panel, Operator Guide, and built-in How NCT Works
  guide explain that FPING is ICMP-only, that zero replies do not prove an empty network,
  and that Nmap discovery is usually clearer for authorized routed-VLAN work. The panel
  labels and displays every separate protocol command before approval. A regression
  test executes the complete zero-host, approval, TCP top-1000, UDP top-100 path with isolated fake
  processes. Docker validation passed with 1,801 tests and 18 skips; the focused scan,
  profile, and UI contract set passed again after the guide update with 96 tests. The
  four earlier failed runs remain accurate failed history and must be replaced by new
  scans; no historical record or source evidence was rewritten.
- [x] **2026-10-21 — dedicated NCT scanner access to the approved home test VLANs
  completed.** The isolated lab now permits only the dedicated NCT scanner to
  initiate active checks toward the five operator-approved VLANs while retaining the
  existing isolation policy for other range systems. The routed firewall preserves
  NCT's exact source identity for those destinations and keeps its automatic outbound
  translation rules for other traffic. A live discovery run from the deployed NCT
  container completed across all five VLANs and reported responsive hosts in every
  one. The deployment now has five named Saved Networks associated with one reviewed
  Home Network scope, whose Mission Environment record marks Nmap coverage available
  and the operator-approved Nmap boundary authorized; passive and configuration
  coverage remain explicitly unknown. Operator guidance now requires selection of a
  named Saved Network, confirmation of the Home Network scope and review of the scan
  profile, timing and No-Strike exclusions before starting; the authorization label
  does not approve arbitrary targets or probes. Exact operational evidence and
  limitations are retained in `docs/RANGE_OBSERVABILITY_VALIDATION_RECORD.md`. This is
  an isolated lab capability and does not establish Range readiness, mission readiness,
  Kubernetes readiness or availability on `main`.
- [~] **2026-10-20 to 2026-10-21 — exact Range Arkime connector acceptance is
  operational with one visual closeout still open.** Read-only
  inventory confirmed that the existing Arkime guest retains separate system and
  capture disks and that Arkime Capture, Viewer and OpenSearch start together on its
  planned isolated management address. The range router was restored for this trial.
  The older NCT/Python guest remains preserved and unchanged because no reachable
  operating system was confirmed. The acceptance plan therefore uses a new
  side-by-side Ubuntu guest on verified separate storage. Docker Compose will run the
  current single-container NCT package for the first live Arkime connector test.
  Kubernetes is not installed or enabled during this connector trial; the guest is
  sized and networked so a single-node Kubernetes runtime can be installed and
  qualified later at its separate roadmap gate. Docker Compose is not being
  represented as a Kubernetes deployment. This is an authorized, bounded exception
  to the unresolved host-firmware stability gate: only the existing Arkime guest,
  range router and the new NCT guest may run; Security Onion guests remain stopped;
  guest autostart remains disabled; and no firmware, capture topology or retained
  evidence is changed. The first connector test is capped at 1,000 records and 10 MiB.
  Stop the trial immediately for an OpenSearch or Arkime crash, a kernel or clock
  error, memory or swap pressure, storage pressure, or repeated service restarts. The
  trial must prove Arkime authentication, bounded Sessions API retrieval, exact-source
  retention, restart behavior and visible NCT receipts before this item can close. The
  existing guests and retained evidence must not be deleted or modified as a shortcut.
  The isolated Compose deployment now runs the exact foundation build and uses a
  dedicated API-only Arkime account over verified HTTPS. A ten-minute pull completed
  with zero records, then a bounded 24-hour pull completed with **69 retained session
  records**. Both attempts retained their exact response, scope and receipt metadata.
  After an intentional NCT container restart, both completed attempts and both retained
  imports remained available through NCT, including the 69-record result. Arkime
  Capture, Viewer and OpenSearch reported no service restarts; the NCT container used
  about 60 MiB during the final check; no swap or storage pressure appeared; and only
  the three guests authorized for this exception were running. The temporary setup key
  and disposable validation scripts were removed after verification. The connector is
  therefore working in the isolated Range through Docker Compose. The final browser
  closeout remains open only because the operator workstation has not yet trusted the
  private NCT web certificate authority. This NCT web CA is separate from the Arkime
  Viewer CA mounted into NCT for API access, and the browser warning must not be
  bypassed. Closeout requires trusting the approved NCT CA and opening both the live
  Arkime page and one retained receipt without a certificate warning. The live health
  and authenticated receipt APIs pass, and the same build's Arkime page already passed
  the local browser runtime check.
  Kubernetes installation, Tier A data, Security Onion integration, host-firmware
  acceptance, mission readiness and promotion to `main` remain separate gates.
- [x] **2026-10-20 — bounded manual Tier D Arkime intake completed on the foundation
  branch.** NCT now accepts a bounded Sessions JSON export, requires explicit Network
  Scope, sensor, query-window, bounding and separate export/capture completeness
  context, retains the exact source through the Artifact Registry, and publishes
  immutable paged session receipts only after whole-file validation. Raw download
  re-verifies the canonical file without following replacement links. The complete
  Docker suite passed 1,767 tests with 18 skips; the final focused suite passed 143
  tests with one environment skip, the browser runtime paging and request-ownership
  checks passed under Node, and the independent gate returned **CLEAR — DOCUMENTED
  DEVIATION**. This development milestone does not ingest PCAP, query Arkime, merge
  overlapping observations, infer coverage, prove an open listener or satisfy the
  still-required Tier A summary path. The actual retained Range export is not present
  on the development workstation, so compatibility remains unverified until that exact
  file is checked without contacting the range. It is development-ready on the
  foundation branch, not Range-ready, mission-ready or available on `main`.
- [x] **2026-10-20 — bounded read-only Arkime API connector implementation and
  validation completed.** Administrators can save
  immutable Network Scope-specific pull definitions, pause or enable their schedules,
  and analysts can run one bounded window, cancel work or explicitly retry the same
  saved window. Deployment settings supply the HTTPS endpoint, Digest user, password
  file and optional CA; credentials never enter saved definitions, receipts or errors.
  One restart-aware worker freezes the exact scope, query and connector identity before
  contact, prevents rapid catch-up, retains accepted responses through the Artifact
  Registry and stops on partial, unknown, failed, cancelled or interrupted results.
  Page reads never contact Arkime. The complete Docker suite passed **1,796 tests with
  18 skipped**; the expanded focused regression passed **171 tests**, the Arkime browser
  runtime check passed, the rebuilt isolated container reported ready, and the novice
  operator returned **PASS** at normal and narrow widths with no console errors. Live
  Range compatibility, Tier A records, PCAP workflows and downstream correlation remain
  open, so this is foundation-only and is not Range-ready, mission-ready or on `main`.
  The first independent closeout returned **HALTED FOR REVIEW** after reproducing five
  boundary failures: manual retries could move the scheduled cursor, definitions after
  the first 100 were hidden, a slow response could exceed the advertised deadline, a
  1,001-row response could bypass the connector ceiling, and queued work did not freeze
  its parser contract. Corrections now preserve retry purpose, reject obsolete scheduled
  retries, page every definition, isolate each HTTPS transfer in a killable helper to
  enforce a hard DNS/authentication/header/body deadline and shutdown bound,
  validate the real row count, and reject incompatible queued work before contact.
  The independent re-review exercised the real slow-header and slow-body paths, worker
  shutdown during transport startup, retry scheduling, paging, row ceilings and frozen
  processing versions; its 56-test closeout returned **CLEAR — DOCUMENTED DEVIATION**.
- [x] **2026-10-20 — novice-oriented Arkime connector deployment runbook completed.**
  The Range procedure now explains Arkime HTTPS, the dedicated API-only `arkimeUser`
  account, verified CA transfer, root-only password handling, the optional Compose
  override, one-row authentication verification, the first bounded pull and ordered
  troubleshooting. The account is not represented as endpoint-scoped because Arkime's
  minimum standard Viewer role can read more than one API; NCT still calls only the
  Sessions endpoint. The optional Compose overlay rendered with every required setting
  and the protected secret mount; its documentation link and path checks passed. The
  independent gate returned **CLEAR — DOCUMENTED DEVIATION**, and the novice operator
  returned **PASS** after verifying the final copyable time-window and deployment
  recovery steps. The runbook does not clear live Range acceptance, Kubernetes or
  host-firmware gates.

## 6.1 Tier A — Summary export

Lowest-cost/manual option.

- [x] **2026-10-21 — bounded Tier A communication-summary intake completed.** NCT now
  accepts one bounded NCT Arkime Summary CSV v1 file with explicit Network Scope,
  observation point, query window, bounding rule, query expression, grouping basis and
  separate operator export/capture declarations. It validates the whole file before
  publishing immutable grouped receipts, retains exact source bytes through the Artifact
  Registry, keeps duplicate-content uploads as separate observations, exposes verified
  raw download and bounded retained-history/detail pages, and preserves 64-bit counts as
  exact decimal text through the API and browser. A ready-to-edit template, dedicated
  Communication summaries and Retained summaries tasks, Operator Guide explanations and
  the built-in How NCT Works guide make the workflow and its limits visible. The complete
  Docker suite passed **1,825 tests with 18 skipped**; the final focused suite passed
  **190 tests with one environment skip**; direct browser runtime checks passed; and the
  isolated preview verified upload/history navigation, aligned contained tables, exact
  `9007199254740993` rendering, zero versus Unknown and error-free normal/narrow Guide
  layouts. The novice operator returned **CLEAR**, and the independent quality gate
  returned **CLEAR — DOCUMENTED DEVIATION** after first halting for browser number
  rounding and overstated completeness. Counts are never added across files; recorded
  completeness remains an operator declaration that NCT cannot independently verify
  from the aggregate CSV. These receipts do not contact Arkime, create current hosts or
  services, establish Last Seen, prove an open listener or feed downstream correlation.
  Native Arkime aggregate compatibility and Range acceptance remain separate gates, so
  Phase 6 is still partial and this is not Range-ready, mission-ready or available on
  `main`.

Support exports such as:

- Destination IP
- Destination port
- Counts
- Source/destination relationship summaries

## 6.2 Tier B — Connections export

Import aggregated connection relationships when available.

## 6.3 Tier C — Sessions CSV

Import selected session metadata such as:

- First packet
- Last packet
- Source IP
- Source port
- Destination IP
- Destination port
- Transport
- Detected protocol/application
- Packets
- Bytes
- Session/reference ID

## 6.4 Tier D — Sessions JSON / structured export

Use machine-readable structured exports where available.

## 6.5 Tier E — Read-only API

Optional. NCT requests only the fields and time windows needed for
characterization.

NCT does **not** ingest full PCAP as part of normal characterization.

## 6.6 Guided access and export instructions

Mission Environment must provide per-method instructions for:

- What Arkime access/role is required
- How to request access from the environment administrator
- Which page/API to use
- Exact filter NCT recommends
- Required timeframe
- Required fields
- Export steps
- Import steps

Manual/offline export remains supported even when API integration exists.

## 6.7 Coverage tracking

- [x] **2026-10-21 — unified retained Arkime window tracking completed.** This slice
  combines the saved query windows from communication summaries, manual Sessions JSON
  and successfully retained API pulls into one read-only, paged view. It preserves the
  Network Scope version, observation-point declaration, method and parser contract,
  query/bounding context, connector identity where available, separate export/capture
  declarations and exact source/import link. Interval comparison is allowed only for an
  exact API stream with complete declarations and unambiguous provenance, and uses the
  maximum preceding eligible end across the complete filtered stream. Every other row
  remains visibly Not comparable. A reported gap means only that NCT lacks a comparable
  retained window; it does not prove a sensor outage, absent collection or missing
  traffic. Failed attempts without retained imports remain outside evidence coverage.
  The completion gate included boundary, nested-interval, paging,
  concurrent-revision, malformed-provenance, read-only, browser, novice and
  independent-review checks.
  The final contract also requires the calculated export result, operator export
  assessment and capture declaration to be Complete before an exact API window can
  participate in continuity. Focused regressions cover nested and touching intervals,
  a noncomparable partial interval inside a real gap, repeated exact bytes retaining
  separate observations, distinct scopes/sensors/queries/contracts, false API linkage,
  a zero-session result, page-boundary continuity, concurrent revision changes,
  missing storage and malformed retained time metadata. The focused Arkime coverage
  and interface suite passed **84 tests**; the executable UI regression passed; and
  the complete Docker suite passed **1,863 tests with 18 environment-dependent
  skips**. The novice gate initially halted because an exact-source link replaced the
  workspace with a browser error; the updated coverage, traffic-analysis and
  Sessions-history source controls now use explicit page-preserving downloads, the
  JSON download was verified in the browser, and the novice retest returned
  **CLEAR**. Independent review initially halted the summary row's calculated-export
  wording; the label was corrected to Recorded export declaration, a rendered-row
  regression was added, and re-review returned **CLEAR — DOCUMENTED DEVIATION**
  because interval continuity is complete here while traffic-observation
  deduplication remains a separate Phase 6.8 contract.

Track:

- Coverage start/end
- Gaps
- Network scope
- Collection method
- Source/import ID

## 6.8 Recommended collection window

- [x] **2026-10-21 — next forward Arkime collection-window recommendation completed.**
  For one exact comparable API stream, derive a read-only UTC window from the complete
  retained stream rather than the visible page. The start is the latest eligible
  retained end minus a bounded nonnegative overlap; the end is an operator-selected
  cutoff or one frozen server time minus a disclosed collection delay. Later partial or
  unknown receipts stay visible but do not advance the anchor. The recommendation must
  expose every contributing anchor receipt, warn that a time window cannot guarantee a
  complete API result, and remain separate from collection authorization or execution.
  It does not repair earlier gaps or claim to be a smallest sufficient capture window.
  Automatic collection, historical-gap repair and traffic-observation deduplication
  remain open and require separate reviewed contracts; no retained traffic counts are
  removed, combined or deduplicated in this slice.
  - The Settings-free Arkime workspace now lists exact retained API streams and lets an
    analyst calculate the next forward window with a bounded overlap, optional explicit
    zoned cutoff, or one frozen server time minus a visible collection delay. The result
    exposes every source receipt that supports the terminal complete segment, calls out
    later incomplete or noncomparable receipts, and warns that the 1,000-session
    connector limit can still make a time-bounded pull incomplete.
  - The calculation stays owned by the exact Network Scope, stream, coverage revision,
    overlap, cutoff and delay that requested it. Changing any planning input clears the
    old answer; delayed successes and errors cannot replace newer work; and a
    recommendation response cannot change the coverage table's revision.
  - The initial independent review halted the scope and delayed-response ownership
    defects, and the novice pass halted an overlapping stream/overlap layout. Both were
    corrected with runtime regressions and a constrained responsive grid. Docker-focused
    verification passed **91 tests**, the browser runtime regression passed, the complete
    Docker suite passed **1,870 tests with 18 environment-dependent skips**, and the live
    browser verified a scope-filtered calculation, immediate input invalidation, zero
    control overlap with the Operator Guide open or closed, and no browser warnings or
    errors. The novice operator returned **CLEAR** and the independent quality gate
    returned **CLEAR — DOCUMENTED DEVIATION** because collection execution,
    historical-gap repair and traffic-observation deduplication remain separate reviewed
    work.

## 6.9 Passive-only characterization

- [x] **2026-10-21 — operator-visible passive-only characterization completed.**
  Reuse the existing read-only, exact-source communication paths in Arkime and Hunt.
  Every individual Sessions path will say **Passively observed** and retain its exact
  receipts and window. When the same frozen Network Scope has no defensible exact
  destination-service assessment, it will also say **Not actively validated** and keep
  the specific missing-endpoint, missing-path-field, missing-coverage or unresolved-time
  reason. Existing reported-open, mismatch and unresolved Nmap explanations remain
  separate. Communication summaries remain excluded because their reported groups can
  overlap. This slice does not create canonical passive hosts or services and does not
  change inventory, CVEs, exports, Reach or Map.
  - Exact-source backend and UI coverage passed **101 focused tests**, both Arkime and
    Hunt JavaScript runtime suites, Python compilation and whitespace checks. A live
    browser walkthrough confirmed the two labels, the retained reason, separate source
    windows and receipts in both views; the aggregate rankings stayed neutral and the
    browser console remained clear. The complete Docker regression suite passed
    **1,870 tests with 18 environment-dependent skips** and one existing warning.
  - The novice operator returned **CLEAR**. The independent quality gate returned
    **CLEAR — DOCUMENTED DEVIATION** because this is intentionally operator-visible
    retained-path characterization; canonical passive host/service creation and live
    active validation remain outside this slice.

A host/port relationship can exist based solely on passive evidence.

Label clearly:

- **Passively observed**
- **Not actively validated**

Do not claim a listener is open unless evidence supports that conclusion.

## 6.10 Communication aggregation

- [x] **2026-10-21 — durable automatic-stream communication history completed.** NCT
  now builds an immutable history generation from a frozen, verified set of complete retained
  automatic Arkime API results for one exact dataset, profile authority, Network Scope/version, sensor,
  query, bounding rule and parser/connector contract. Count a repeated node + session ID
  once only when every normalized retained field agrees, preserve every source encounter
  and receipt, and block publication on conflicting copies. The operator view will show
  the stream identity and retained UTC range first, followed by included, excluded and
  conflicting source/record counts, a paged communication-path table with retained-history
  first/last times, Unknown counts and evidence links, then collapsed rankings. Operators
  can page through older exact streams, communication paths, supporting receipts and
  excluded retained records without loading an unbounded result. The selected stream and
  displayed generation stay synchronized across delayed requests, refreshes and selection
  changes; provenance-mismatched windows cannot offer the history action. Manual
  imports and summary CSVs remain separate. Independent architecture review returned
  **CLEAR — DOCUMENTED DEVIATION** and required this to be described as deduplicated
  retained records rather than unique connections or deduplicated packets. The novice
  pre-review returned **CLEAR** and selected **Communication History** directly after
  **Traffic Patterns**, with a Review stream history action on eligible automatic rows.
  Capture declarations remain independently visible as Complete, Partial or Unknown and
  do not determine retained-result eligibility. Focused container checks passed **104 tests**
  with one existing warning, the executable browser regression passed, and the complete
  Docker suite passed **1,885 tests with 18 environment-dependent skips** and one existing
  warning. Browser verification at desktop and 980 x 900 guide-open widths confirmed aligned,
  contained tables, stream-specific reload behavior and no console warnings or errors. The
  independent final gate returned **CLEAR — DOCUMENTED DEVIATION** after independently
  verifying the integrity, paging and asynchronous-selection corrections; the novice final
  review returned **CLEAR**. This history does not change Phase 6.7
  continuity or Phase 6.8 recommendation eligibility and makes no complete-capture,
  sensor-uptime, absence or whole-network claim. Capture completeness, unique-connection
  claims, packet deduplication, cross-stream aggregation and Range acceptance remain outside
  this milestone.
- [x] **2026-10-21 — exact-source communication summary extension completed.** The
  existing correlated-path view now pages through every grouped path in one explicitly
  selected Sessions source and keeps the source address, destination address, transport,
  destination port, earliest and latest reported packet times in this source, distinct
  detected applications, exact packet and byte totals, Unknown counts, and supporting
  receipts together. Time and application receipts are expandable, disclose when their
  bounded reference lists are truncated, and keep the full supporting-receipt count.
  The same source-bound result is available in Arkime and through its exact-source Hunt
  handoff. Rankings remain secondary and collapsed. Browser checks confirmed aligned,
  contained tables, paging controls and evidence explanations in both workspaces with no
  console warnings or errors; backend and executable-runtime tests covered multi-page
  traversal because the preview contained four paths. The focused container checks passed
  **102 tests** with one existing
  warning, both executable browser regressions passed, and the complete Docker suite
  passed **1,871 tests with 18 environment-dependent skips** and one existing warning.
  The independent final gate returned **CLEAR — DOCUMENTED DEVIATION** after finding and
  verifying the correction for silently truncated tied time receipts; the novice final
  review returned **CLEAR**. This remains the versioned `arkime-exact-source-paths:1`
  read-only calculation over one retained import. It does not merge overlapping windows,
  deduplicate sessions, persist a cross-window traffic identity, or promote potentially
  overlapping communication-summary CSV groups. Durable cross-window summaries remain
  downstream work.
- [~] **2026-10-21 — operator-facing Arkime traffic analysis started.** Build
  bounded, read-only views for exact retained evidence that explain top source and
  destination talkers, frequently contacted external addresses, destination-port
  activity, protocols/applications and VLAN activity. Preserve the exact import,
  Network Scope and export/capture declarations behind every result. Never combine
  overlapping retained windows into one unexplained total, call a reported destination
  port open, infer maliciousness, or present incomplete capture as whole-network truth.
  External-address classification requires explicit reviewed scope CIDRs; otherwise it
  remains Unknown. Architecture review, exact-count handling, browser checks, novice
  workflow review and independent quality-gate approval are required before completion.
- [~] **2026-10-21 — retained-data Arkime expression pivots started.** Every value
  in the traffic ranking's first column will support Arkime-style include and exclude
  actions. Analysts can combine IP, destination port, IP protocol, detected protocol,
  and VLAN clauses with match-all or match-any behavior. NCT must show the exact
  expression, recalculate every related table from the same retained import, preserve
  Unknown values, and make clear that this local drill-down does not send a new query
  to Arkime.
  - [x] **2026-10-21 — typed expression and correlated-path view completed.** Analysts
    can now type a bounded Arkime-style retained-data expression for an exact source
    address, destination address, destination port, IP protocol, detected application or
    VLAN without first finding a ranked row. A visible full example and plain-language
    field/operator guide keep the control usable on narrow screens. Valid input
    recalculates the clause chips, every ranking and a contained correlated path table
    grouped by source address, destination address, transport and destination port, with
    retained-row, exact packet/byte totals and receipt references. Unsupported or
    ambiguous syntax is rejected without replacing the last valid result, and the page
    states that explicitly. Communication-summary rows remain separate because their
    reported groups may overlap. The browser verified valid UDP/53 filtering, preserved
    results after a rejected mixed expression, the full example, aligned contained
    scrolling and the Operator Guide at normal and 980×900 layouts. The focused Arkime
    and interface suite passed **81 tests**, the browser runtime regression passed, and
    the complete Docker suite passed **1,841 tests with 18 environment-dependent
    skips**. The novice operator returned **CLEAR** and the independent quality gate
    returned **CLEAR — DOCUMENTED DEVIATION**. This remains a local calculation over
    one explicitly selected retained source; it does not prove an open port, contact
    Arkime, merge overlapping imports or complete active/passive correlation.
  - [x] **2026-10-21 — compact filter controls corrected and theme-aligned.** Clicking
    a reported value applies the include action; hovering or focusing it reveals the
    include/exclude choices without permanently crowding the table. The action menu now
    directly touches its trigger and remains open briefly while the pointer enters its
    border. Keyboard focus keeps the same controls available. The expression builder,
    clause chips and hover menu now inherit the active NCT theme. Runtime checks,
    focused Docker tests and a rebuilt-browser workflow verified the menu, exclusion
    action, exact displayed expression and filtered result count.
    Independent review returned **CLEAR — DOCUMENTED DEVIATION** because this gate
    covers the compact menu and theme correction rather than all Phase 6 analytics.
    The novice-operator review returned **CLEAR** with no browser errors or layout
    overflow. The complete Docker regression suite passed with 1,837 tests and 18
    environment-dependent skips.
  - [x] **2026-10-21 — full Arkime analytics gate corrections completed.** The
    independent reviewer halted the broader milestone after reproducing four semantic
    edge cases: transport-specific port rows could be filtered as port-only; a literal
    application value named `unknown` could collide with a missing value; malformed
    filter field types could escape validation; and a pull-run link alone could promote
    a manual observation to comparable API provenance. The implementation now uses one
    grouped predicate for transport plus destination port, distinct reported/missing
    application identities, bounded typed filter validation, and exact retained
    observation metadata checks for API continuity. The rebuilt browser verified the
    theme-aligned controls, persistent keyboard-accessible action menu, grouped UDP/53
    include and exclude expressions, and exact two-of-four result counts. The complete
    Docker suite initially exposed an unrelated nondeterministic numeric VLAN search:
    a generated assignment identifier containing the requested digits could return every
    VLAN in that assignment. Numeric searches now select the exact VLAN identifier only,
    and the regression test deliberately places the same digits in the scope label. The
    affected VLAN file passed 37 tests; the focused Arkime tests passed 15 tests; the UI
    runtime check passed; and the complete Docker suite passed 1,840 tests with 18
    environment-dependent skips. Independent re-review then halted on two additional
    malformed-filter boundaries: a non-text grouped match mode and a superscript numeric
    character could escape the normal input-error path. Group modes now require text,
    numeric port/VLAN values require ASCII decimal syntax, and both API regressions return
    a bounded 422 response. The updated focused test passed 9 checks, the UI runtime check
    passed, the complete Docker suite again passed 1,840 tests with 18 environment-dependent
    skips, and the novice-operator review returned **CLEAR** with no browser warnings,
    page overflow or confusing grouped-filter behavior. The built-in How NCT Works guide
    now distinguishes ranked Sessions JSON analysis from communication-summary groups that
    remain separate and are never aggregated into top-talker rankings. Independent final
    review returned **CLEAR — DOCUMENTED DEVIATION**: this correction gate is complete,
    while the parent Phase 6 traffic-analysis and expression-pivot items remain in progress
    until broader roadmap integration is finished.

Collapse repetitive sessions into durable summaries:

```text
10.20.1.17 → 10.20.4.22 TCP/443
First seen
Last seen
Session count
Packet count
Byte count
Detected protocol
Evidence source(s)
```

## 6.11 Active/passive correlation

- [x] **2026-10-21 — exact-scope Arkime/Nmap path context completed.** For each
  bounded communication path from one selected Sessions JSON/API source, join only the
  same frozen Network Scope and exact destination address, transport and destination
  port to NCT's existing latest defensible source-reported Nmap selector. Show source
  and destination endpoint links where processed entities already exist, then label the
  destination service as reported open and observed, Observed / Scan Mismatch, not
  actively assessed, unresolved, or passive-only in this scope. Do not create hosts or
  services from passive rows, infer physical identity, reverse client/server direction,
  merge imports, promote aggregate summary groups, claim live truth or use an address
  from another Network Scope. Preserve both Arkime receipt references and the exact
  retained Nmap source behind every comparison. The Arkime Traffic Patterns workspace
  now shows this context beside each correlated path, keeps Arkime and Nmap collection
  windows separate in UTC, exposes the exact retained source links and processed endpoint
  links, and preserves click and typed-expression filtering across source, destination,
  transport and destination port. Safety-bound failures return a clear request error and
  no partial comparison. The Operator Guide and How NCT Works page explain how to read
  the labels and why they are retained-report comparisons rather than current network
  truth.

  **Validation:** the complete container test suite passed with 1,853 tests, 18 skipped
  and one existing warning; the final focused Arkime, foundation-evidence, guide and UI
  checks passed with 169 tests and one existing warning; the browser runtime regression
  check passed; and the rebuilt container was exercised in the browser with the Operator
  Guide open, contained table scrolling, filters, exact evidence explanations and fully
  readable UTC start/end times. The independent gate returned **CLEAR — DOCUMENTED
  DEVIATION** and the novice-operator gate returned **CLEAR**.

  **Documented deviation / remaining limit:** this milestone correlates saved Arkime
  rows with the latest defensible saved Nmap report for the same scope and exact service.
  It does not establish live service state, connection success, physical-device identity
  or that the two sources describe the same event. Aggregate Arkime summary groups remain
  excluded because overlapping groups cannot be safely treated as individual sessions.
  Nmap services with no passive row, broader Last Seen reasoning, historical state-change
  presentation, and reuse in Reach, Hunt Timeline and Map remain downstream work.

- [x] **2026-10-21 — exact-source Arkime-to-Hunt integration completed.** An operator
  can open one analyzed Sessions JSON/API source in Hunt and keep that exact import,
  Network Scope, sensor, UTC query window, source declarations, bounded path rows,
  truncation state, packet/byte receipts and exact raw/details links visible beside the
  ordinary network-wide evidence. When supported same-scope Nmap evidence exists, each
  destination service shows its separate collection window, selection reason and source
  link without merging the two sources or claiming that they describe the same event.
  Normal refresh preserves the exact passive source; focused-scan selection and Remove
  clear it. A newer selection owns the panel so a delayed earlier request cannot replace
  it. Invalid, deleted and aggregate-summary selections fail inside the passive panel
  while the normal Hunt view remains usable. The Operator Guide and How NCT Works page
  explain the handoff and its evidence boundary.

  **Validation:** focused Arkime, UI and authentication checks passed with **97 tests**
  and one existing warning; the Hunt executable browser regression passed; the complete
  container suite passed with **1,857 tests, 18 skipped** and one existing warning. The
  isolated browser preview verified exact-source handoff, refresh, removal, deleted and
  aggregate-source errors, focused-scan precedence, readable labels, contained scrolling
  and tailored Operator Guide guidance. Review found and resolved one stale Open in
  Arkime link during source replacement, then novice review found and resolved narrow-
  screen Personal Notes drawer and launcher overlap plus ambiguous focused-scan wording.
  The final independent gate returned **CLEAR — DOCUMENTED DEVIATION** and the final
  novice-operator gate returned **CLEAR** at 980 by 900 with the Guide open.

  **Documented deviation / remaining limit:** the selected passive source uses a separate
  `/api/hunting/passive-context` request instead of extending the cached network-wide
  Hunt request. This keeps passive failures and source selection out of current inventory,
  CVE candidates, filters and exports. The feature is exact-source context in Hunt, not
  Timeline, Last Seen, Reach, Map or unified multi-source correlation; aggregate summary
  imports remain excluded because overlapping groups cannot be safely treated as exact
  sessions.

Support:

- Open + observed
- Open + not passively observed
- Closed/filtered + observed
- Not scanned + observed
- Service identity mismatch
- Historical state change

Use neutral terminology such as **Observed / Scan Mismatch**.

---

# PHASE 7 — Hunt Timeline and Investigation Lenses

## 7.1 Hunt Timeline

Timeline lanes may include:

- Nmap
- Arkime
- Kibana
- Device configuration
- Routes
- Policies
- Findings
- Recommendations
- Analyst notes

Selecting a time range filters Hunt evidence.

## 7.2 Hunt categories

Retain and improve groupings such as:

- SSH
- RDP
- FTP
- SFTP
- SMB
- Remote Access
- File Transfer
- Web
- Identity
- Databases
- Network Management

## 7.3 Investigation Lens

A Lens stores:

- Entities
- Networks
- Ports
- Protocols
- Services
- Time range
- Evidence sources
- Filters
- Notes
- Pinned evidence

## 7.4 Lens lifecycle

```text
PRIVATE DRAFT
    ↓
SHARED INVESTIGATION
    ↓
FINDING
    ↓
RECOMMENDATION / REPORT
```

A private investigation does not automatically expose all analyst scratch work.

## 7.5 Sharing

Support:

- Private
- Selected analysts
- Crew
- Crew Lead

Pinned evidence is protected from automatic retention cleanup.

---

# PHASE 8 — Crew Operations and Collaboration

**Purpose:** Support CPT continuity and leadership oversight without building a
general-purpose chat platform.

## 8.1 Roles

Separate:

- Analyst
- Crew Lead
- Administrator

One account may hold multiple roles.

## 8.2 Callsigns

Accounts may have:

- Canonical/professional identity
- Optional callsign/display alias

UI may show the callsign while provenance/audit retains canonical identity.

## 8.3 Crew Lead View

Provide a consolidated view of:

- Analysts
- Areas of responsibility
- Active investigations
- Shared Lenses
- Findings
- Tasks
- Scans
- Uploads
- Imported artifacts
- Recommendations
- Recent activity
- Evidence freshness

This is an oversight and coordination view: show what was done, who did it, and
what still needs attention. It must not turn ordinary analyst actions into a
crew-lead approval queue or hide unassigned work.

Do **not** create opaque productivity scores.

## 8.4 Investigation continuity

Crew Lead can open a shared investigation and understand:

- Scope
- Evidence
- Notes
- Filters
- Uploads
- Findings
- Outstanding tasks
- Last activity

This supports continuity when an analyst is absent or leaves.

## 8.5 Tasking

Replace the current lightweight note concept with structured tasks:

- Rescan network
- Investigate host
- Validate service
- Collect Arkime data
- Collect Kibana data
- Obtain configuration
- Validate route
- Review finding
- Review recommendation
- Custom

Tasks may link directly to evidence and, when authorized, provide an action such
as **Run Scan**.

Tasking is optional coordination, not an execution prerequisite. An analyst who
already has permission to run an authorized scan may do so without first receiving
a task. Creating or assigning a task identifies responsibility and desired work; it
does not grant, remove, or narrow the analyst's existing role permissions. The Crew
Lead view must include both tasked and independently initiated activity.

Task states:

- Assigned
- In Progress
- Blocked
- Complete
- Cancelled

## 8.6 Context comments/mentions

Allow comments tied to a Task, Lens, Finding, or Recommendation.

Do not expand into full instant messaging, channels, calls, or Teams-like features.

---

# PHASE 9 — Reach and Map Evolution

## 9.1 Reach

Reach must reflect selected source, destination, and protocol, and distinguish:

- Route evidence
- Policy evidence
- NAT evidence
- Unknown segments
- Manual evidence

Unknown portions of the path must remain visibly unknown.

## 9.2 Dynamic map workspace

The map should behave like an unbounded camera over a sane graph coordinate space,
not like a fixed sheet of paper.

## 9.3 Initial map behavior

On page entry:

```text
Load graph
  ↓
Complete layout
  ↓
Calculate bounds
  ↓
Fit to viewport with padding
```

## 9.4 Separate camera from node geometry

Panning and zooming move the camera. They must **never** directly alter node
coordinates or inject node velocity.

## 9.5 Runaway-node protection

Current observed defect: objects may dislodge during scroll/pan and shoot toward
the workspace boundary.

Before expanding the map model, implement:

- Maximum frame displacement
- Maximum node velocity
- Last stable coordinate
- Invalid-coordinate detection
- Automatic rollback to last stable position
- Outlier rejection before Fit bounds calculation
- Reset Layout control

An unbounded camera must not turn a runaway-node bug into infinite graph expansion.

## 9.6 Freeze physics

Recommended behavior:

```text
Load
  ↓
Run layout
  ↓
Stabilize
  ↓
Freeze node positions
  ↓
Fit
```

Do not keep global force simulation running indefinitely.

New objects should use local/relevant layout where practical.

## 9.7 Layout lock

Default to a stable/locked layout for investigation.

Explicit Edit/Unlock mode enables node movement.

Persist stable coordinates.

## 9.8 Large-map controls

Support:

- Pan
- Zoom
- Fit
- Center selection
- Focus subnet
- Reset layout
- Clustering/grouping
- Progressive detail
- Reduced labels at low zoom

---

# PHASE 10 — Hardening Recommendation Workflow

## 10.1 Automated recommendations

Start with explainable deterministic rules.

Categories may include:

- Exposure
- Segmentation
- Legacy/Insecure Services
- Management Plane
- Routing
- ACL/Firewall/NAT
- Unexpected Communications
- Service Mismatch
- Configuration Hygiene
- Observability Gaps

## 10.2 Recommendation template

Analyst-generated recommendation fields:

- Title
- Category
- Affected entities
- Observation
- Security concern
- Supporting evidence
- Proposed action
- Expected effect
- Validation method
- Known limitations
- Analyst notes

## 10.3 Approval workflow

```text
DRAFT
  ↓
SUBMITTED
  ↓
CREW LEAD REVIEW
  ├─ Return for revision
  ├─ Reject
  └─ Approve
       ↓
APPROVED RECOMMENDATIONS
```

## 10.4 Evidence linking

Recommendations may link to:

- Scan evidence
- Arkime evidence
- Kibana evidence
- Configurations
- Routes
- Maps
- Timeline events
- Manual evidence
- Analyst observations

## 10.5 Deduplication

Repeated detection updates:

- First seen
- Last seen
- Occurrence count
- Current status

Do not create endless duplicate findings.

## 10.6 Hardening simulation

Simulate proposed controls without modifying production devices.

Retain:

- Before state
- Proposed state
- Predicted affected paths
- Potentially impacted hosts/services
- Unknown impacts

Simulation results may be attached to recommendations and leadership reports.

---

# PHASE 11 — Analyst Dashboard

**Purpose:** Build a focused investigation workspace after the evidence engine is
mature enough to support it efficiently.

## 11.1 Lens-driven dashboard

Every dashboard uses a shared investigation context.

## 11.2 Initial widgets

Candidate widgets:

- Hunt Timeline
- Hosts observed over time
- Services observed over time
- Active vs passive port/service state
- Nmap/Arkime mismatches
- New services
- Lost services
- Communication pairs
- Traffic volume
- Protocol distribution
- Subnet-to-subnet communication
- External communication
- Host/service matrix
- Reachability summary
- Exposure by subnet
- Changes from baseline
- Findings
- Hardening recommendations
- Evidence table
- Mini topology

## 11.3 Cross filtering

Selecting a host, service, port, subnet, or time range should update compatible
widgets.

## 11.4 Saved/shared dashboards

Support:

- Private dashboards
- Shared dashboards
- Crew templates

## 11.5 Pin to Report

Allow entire dashboards or individual widgets to be pinned into Report Composer.

---

# CROSS-CUTTING WORKSTREAM A — Report Composer / Export Manager

This remains a **key leadership-facing capability** and must be developed
throughout the roadmap rather than treated as an afterthought.

## A.1 Goal

Leadership should be able to receive exactly the evidence and visualizations the
team intends to present, in the order and format required.

## A.2 Pin from anywhere

Any relevant object should support **Pin to Report**, including:

- Dashboard
- Dashboard widget
- Graph
- Timeline
- Map
- Table
- Scan comparison
- Hunt evidence
- Reach result
- Route
- Finding
- Recommendation
- Hardening simulation
- Analyst note

## A.3 Report workspace

Allow:

- Add/remove sections
- Drag/reorder
- Section headings
- Analyst-entered narrative
- Snapshot timestamps
- Source/provenance references

Example sections:

- Executive Summary
- Mission Coverage
- Network Overview
- Investigation Timeline
- Key Findings
- Approved Hardening Recommendations
- Simulation Results
- Appendices

## A.4 Snapshot semantics

Pinned material stores:

- Capture time
- Lens/filter state
- Evidence version
- Underlying provenance

Reports should not silently change when new evidence arrives.

Optionally allow **Refresh to Current** with a visible indication of what changed.

## A.5 Export formats

Support where appropriate:

- TXT
- CSV
- JSON
- Markdown
- HTML
- PDF

---

# CROSS-CUTTING WORKSTREAM B — Retention and Compaction

## B.1 Retention classes

### Source artifacts
Unique artifacts retained according to mission policy and compressed where practical.

### Detailed passive telemetry
Configurable retention:
- 7 days
- 14 days
- 30 days
- Mission duration
- Custom

### Aggregated relationships
Retain long-term because they are relatively inexpensive.

### Findings/recommendations
Retain until intentionally removed.

### Pinned evidence
Protect from automatic pruning.

## B.2 Compaction

Detailed telemetry may compact into durable relationship summaries after the
retention threshold.

## B.3 Storage visibility

Show:

- SQLite size
- Artifact size
- Passive telemetry size
- Pinned evidence size
- Retention estimate

---

# CROSS-CUTTING WORKSTREAM C — Investigation Notebook / Obsidian Compatibility

Do **not** make Obsidian a runtime dependency.

Instead support export of a structured Markdown investigation notebook, e.g.:

```text
Investigation.md
Hosts/
Devices/
Findings/
Recommendations/
Evidence/
Attachments/
```

Use normal Markdown links/backlinks so analysts may open the exported workspace in
Obsidian or similar tools without adding runtime bloat to NCT.

---

# CROSS-CUTTING WORKSTREAM D — Deployment and Reliability

Maintain:

- Offline operation
- Constrained-range compatibility
- Older Docker path
- Modern Docker/Compose path
- Default port 8445
- Port-availability checks
- Simple username/password utilities
- Health diagnostics
- Recovery procedures
- Rollback

Health should expose:

- Database state
- Worker state
- Queue
- Failed jobs
- Disk usage
- Retention status
- Analysis versions
- Evidence coverage

---


# CROSS-CUTTING WORKSTREAM E — Offline Mission Portability & Multi-Site Synchronization

**Purpose:** Allow multiple geographically separated NCT kits with no network
connectivity between them to exchange mission evidence and analyst-generated mission
state by removable media and converge on a defensible common operational picture.

This is **not** database backup/restore. Each site may continue working independently
between exchanges. Synchronization must merge independently produced mission state
without silently overwriting another site's evidence, analyst decisions, or history.

## E.1 Operational model

Support at least two package types:

### Full Mission Package

Used for:

- Initial provisioning of another kit.
- Rebuilding a lost/replaced kit.
- Establishing a new site from an existing mission picture.
- Periodic full reconciliation when required.

A full package includes the complete portable mission state selected for export,
subject to retention, classification, size, and operator controls.

### Delta Sync Package

Used for routine site-to-site exchange.

A destination-specific delta should contain only mission records, revisions,
tombstones, receipts, and artifact bytes not already acknowledged by the destination
site.

Example:

```text
Site Alpha
  ↓ export changes since Bravo acknowledgment #42
Removable media
  ↓
Site Bravo
  ↓ verify → preview → merge → acknowledge
```

Re-importing the same valid bundle must be idempotent.

## E.2 Stable site identity

Every NCT installation participating in offline synchronization requires a durable,
randomly generated `site_id`.

Retain:

- Site ID.
- Human-readable site/kit label.
- Site creation time.
- Site public signing identity/fingerprint.
- Site status: active, retired, replaced, compromised.
- Replacement lineage where applicable.

Site identity must survive normal application upgrades, container replacement, and
mission-data export/import.

Cloning a system image must not silently create two active kits with the same logical
site identity. Provide an explicit clone/new-site initialization workflow.

## E.3 Globally stable mission identities

Any mission object that may cross sites must have a globally stable identifier that
does not depend on local SQLite row numbers.

This includes, as applicable:

- Artifact identities.
- Artifact observations/encounters.
- Network Scopes.
- Saved Networks when treated as shared mission objects.
- Hosts/endpoints/services and later reconciled physical devices.
- Device collections/configurations.
- Findings.
- Recommendations.
- Investigation Lenses.
- Tasks.
- Comments.
- Notes.
- Reports/report definitions.
- Pinned evidence.
- Coverage records.
- Hardening simulations.
- Mission-relevant analyst/user identities.
- Archive/tombstone records.
- Synchronization events and acknowledgments.

Local surrogate database keys may still exist internally, but they must never be the
cross-site identity.

## E.4 Analyst identity and authentication separation

Portable analyst identity must be separated from local authentication.

Synchronize mission-relevant identity such as:

- Canonical analyst/person ID.
- Callsign/display alias.
- Authorship and ownership references.
- Role context when needed to understand historical actions.
- Site where the action originated.

Do **not** synchronize by default:

- Password hashes.
- Active sessions.
- API credentials.
- Private keys.
- MFA secrets.
- Local authentication tokens.

Each site authenticates users locally. Historical provenance must still resolve to the
same analyst after import.

Provide an explicit identity-collision workflow for independently created records that
appear to refer to the same person. Never merge analyst identities solely by display
name or callsign.

## E.5 Portable mission-data classes

The synchronization manifest must classify content.

### Portable by default

Include mission truth such as:

- Source artifacts and Artifact Registry metadata.
- Artifact observations and provenance.
- Normalized facts/entities.
- Immutable assessments and evidence receipts.
- Nmap evidence and scan metadata.
- Device configurations and parsed facts.
- Network Scopes and relevant scope history.
- Evidence assignment/correction history.
- Coverage records and blind-spot state.
- Findings and recommendations.
- Investigation Lenses.
- Tasks and mission comments.
- Analyst notes intended as mission records.
- Pinned evidence.
- Report definitions and report snapshots.
- Audit/provenance events required to understand mission history.
- Archive/tombstone events.
- Derived results when their input/version dependencies remain valid.

### Local by default

Exclude machine/site-local state such as:

- Passwords and authentication secrets.
- TLS private keys.
- Session cookies/tokens.
- Host-specific filesystem paths.
- Local deployment configuration.
- Container/runtime state.
- Local port bindings.
- Machine-specific health data.
- Temporary caches that can be rebuilt.
- Local browser/session state.
- Personal UI preferences unless explicitly selected for portability.

The package format must explicitly distinguish these classes rather than relying on
directory-copy exclusions.

## E.6 Event/revision model

Consequential mutable mission objects require revision history suitable for
multi-writer merge.

Each portable change should retain enough information to identify:

- Object ID.
- Revision/event ID.
- Originating site ID.
- Originating site-local monotonic sequence.
- Parent/base revision(s).
- Analyst/actor identity where applicable.
- Wall-clock event time.
- Processing/import time.
- Change type.
- Previous/current state or immutable event payload.
- Provenance/evidence dependencies.

Wall-clock timestamps are evidence and display information; they are **not** sufficient
for ordering or conflict resolution.

A site-local monotonically increasing sequence or equivalent causal marker must allow
NCT to determine what a destination has already received even when site clocks differ.

## E.7 Conflict detection and resolution

Never use unconditional last-writer-wins for consequential mission state.

Automatically merge when operations are provably non-conflicting, such as:

- Two different new artifacts.
- Independent observations of the same artifact.
- Independent comments.
- Independent evidence receipts.
- Append-only history.
- Exact duplicate events already imported.

Raise a conflict when independent branches change the same consequential mutable
state incompatibly.

Examples:

- Site Alpha renames a Network Scope while Site Bravo archives it.
- Two sites independently change the disposition of the same Finding.
- Two sites edit the same report section from the same base revision.
- Two analysts independently reassign the same task.
- Competing evidence-assignment corrections descend from the same prior assignment.

Conflict UI must show:

- Object.
- Common base revision.
- Alpha/source change.
- Bravo/local change.
- Provenance/analyst/site/time for each.
- Evidence affected.
- Merge options.
- Whether both histories can be retained.
- Resulting revision before confirmation.

Conflict resolution itself becomes a new provenance-preserved revision/event.

Do not delete the losing branch from history.

## E.8 Archive, deletion, and tombstones

Absence from a package is not deletion.

Portable mission objects that can be archived/deleted require durable tombstone or
archive events sufficient for disconnected peers to learn the state change later.

Requirements:

- Tombstone has stable object identity and origin.
- Tombstone participates in normal synchronization.
- Receiving a tombstone does not destroy required historical provenance.
- Evidence referenced by retained findings/reports/lenses cannot be physically
  removed merely because another site archived its parent object.
- Tombstone retention must be long enough to cover every participating site's
  synchronization horizon.
- Physical deletion/compaction must remain a separate policy decision.

Where hard deletion is supported, define how a long-offline kit is prevented from
resurrecting deleted state when it later reconnects by removable-media exchange.

## E.9 Artifact transfer and deduplication

Use Artifact Registry SHA-256 identity for exact source-artifact transfer.

For each referenced artifact:

- Include canonical SHA-256.
- Include expected size.
- Include media type/source type.
- Include provenance/observation references.
- Include bytes only when required by the selected package and destination state.

If the destination already holds verified identical bytes, reuse the local canonical
artifact and import only missing observations/references.

Never deduplicate merely similar artifacts.

A bundle must not create a second physical copy solely because the same artifact
arrived from another site.

## E.10 Bundle manifest

Every package requires a machine-readable manifest containing at minimum:

- Bundle format version.
- Bundle ID.
- Bundle type: full or delta.
- Source site ID and label.
- Intended destination site ID when destination-specific.
- Mission/workspace identifier.
- Export sequence/range.
- Creation time.
- NCT application version.
- Schema version(s).
- Parser/analysis versions relevant to included derived data.
- Included record counts by class.
- Included artifact hashes/sizes.
- Dependency graph or dependency references.
- Tombstone/archive count.
- Conflict-relevant revision metadata.
- Previous synchronization acknowledgment/checkpoint.
- Whole-package integrity metadata.
- Signature/certificate/fingerprint metadata.
- Encryption metadata when used.
- Export policy/options used.

The manifest itself must be integrity protected.

## E.11 Integrity, authenticity, and optional confidentiality

Treat removable media and transferred bundles as untrusted until verification
completes.

Before mission data is committed:

1. Validate bundle structure and format version.
2. Validate source site identity/trust.
3. Verify bundle signature when signing is enabled/required.
4. Verify manifest integrity.
5. Verify every included file hash and size.
6. Validate all internal references.
7. Validate schema/version compatibility.
8. Parse content only through bounded, hardened parsers.
9. Generate a read-only import preview.
10. Commit through a transactional/checkpointed merge.

Support site-level digital signing so an operator can verify who produced the package
and that it was not modified.

Support optional package encryption for environments where mission policy requires
confidentiality on removable media. Encryption must not replace signature/integrity
verification.

Private signing/decryption keys must remain local and must never be exported inside
ordinary mission packages.

## E.12 Untrusted archive/media protections

The importer must reject or safely contain:

- Path traversal.
- Absolute paths.
- Symlinks/hardlinks that escape the staging area.
- Device files.
- Executable/autostart behavior.
- Unexpected file types.
- Archive nesting beyond configured limits.
- Decompression bombs.
- Excessive file counts.
- Excessive individual/total extracted size.
- Malformed XML/JSON/CSV/Parquet.
- Oversized fields.
- Duplicate manifest identities with conflicting bytes.
- Hash mismatch.
- Signature mismatch.
- Unsupported schema requiring unsafe downgrade.

Nothing in a package is executed.

Import occurs from a staging area and must not trust removable-media paths as
application storage.

## E.13 Import preview and atomicity

Before merge, show:

- Source site.
- Bundle ID/type.
- Export sequence.
- Signature/trust result.
- NCT/schema compatibility.
- New records by type.
- Already-known records.
- New artifact bytes required.
- Artifact bytes already present.
- Tombstones/archives.
- Automatically mergeable updates.
- Conflicts requiring review.
- Unsupported/deferred records.
- Disk-space requirement.
- Estimated resulting storage use.
- Any condition that will block import.

No mission changes occur during preview.

Import must be:

- Transactional where practical.
- Checkpointed for large artifact transfers.
- Restart-safe.
- Idempotent.
- Recoverable after process/container restart.
- Safe if removable media is removed after staging completes.

A failed merge must not leave half-applied object state.

## E.14 Full versus delta state tracking

Track synchronization state per peer site.

At minimum retain:

- Peer site ID.
- Last package received.
- Last source sequence acknowledged.
- Last package exported for that peer.
- Records/artifacts acknowledged.
- Outstanding/unacknowledged changes.
- Last successful verification/import time.
- Last failed/import-conflict state.

Do not use only "last sync time" to compute deltas.

Support a destination-specific action such as:

```text
Export changes for Site Bravo since acknowledgment #42
```

If peer state is missing or untrustworthy, fall back safely to a full reconciliation
manifest rather than guessing.

## E.15 Clock skew and temporal semantics

Disconnected kits may have inaccurate or divergent clocks.

Therefore retain separately:

- Source observation time.
- Analyst-entered event time.
- Origin-site wall-clock time.
- Origin-site monotonic sequence/causal order.
- Destination import time.

Never silently rewrite source timestamps to destination time.

Clock skew warnings should be visible when a site's reported wall clock differs
materially from other trusted evidence, but skew alone must not invalidate the
mission record.

## E.16 Schema and application-version compatibility

Every bundle declares its schema and feature requirements.

Required behavior:

- Newer NCT should import supported older bundle versions through explicit migrations.
- Older NCT must refuse a bundle requiring unsupported semantics rather than partially
  importing it as if complete.
- Unsupported record classes may only be deferred if the package format preserves
  them losslessly and the operator is clearly told they were not applied.
- No destructive schema downgrade.
- Imported derived results must be marked stale/recomputed when local parser or
  analysis-version dependencies differ.
- Raw/source evidence should remain available so a newer site can re-normalize it.

Publish and test a compatibility matrix before mission-ready acceptance.

## E.17 Large-data and passive-telemetry strategy

Full passive telemetry can make portable bundles impractically large.

Support:

- Artifact/record inventory before export.
- Estimated package size.
- Selectable time windows when policy permits.
- Durable aggregated relationship export.
- Optional omission of locally reproducible caches/derived data.
- Destination-aware artifact byte suppression.
- Multi-volume packages if required.
- Chunked/checkpointed creation and staging.
- Explicit handling of media capacity.
- Clear distinction between "full mission knowledge" and "all raw retained telemetry."

Never claim another site has a complete evidence picture when raw evidence was omitted.
Coverage metadata must show what was and was not transferred.

## E.18 Derived-result portability

Derived results may be imported only when their dependencies are identifiable.

Each portable derived result should retain:

- Input artifact/observation/entity IDs.
- Parser/engine version.
- Analysis version.
- Generation time.
- Dependency hashes/versions.
- Current/stale state.

If dependencies or analysis versions do not match locally, preserve the imported
result as historical provenance but mark it stale and queue/recommend safe local
recomputation.

Never let an incompatible imported cache become authoritative current analysis.

## E.19 Permissions and operator controls

Export/import is a privileged operation.

Define explicit permissions for:

- Create full mission export.
- Create delta export.
- Export sensitive raw evidence.
- Export analyst notes/private lenses.
- Import a package.
- Trust/add/retire a peer site.
- Resolve synchronization conflicts.
- Apply tombstones/archive changes.
- Override compatibility warnings where policy permits.

Export must respect existing evidence visibility and classification/mission policy.

Do not let a user export information merely because it physically exists on the kit
if their role is not authorized to access/export it.

## E.20 Private and personal analyst content

Before implementation, define portability semantics for:

- Private Investigation Lenses.
- Draft notes.
- Personal filter presets.
- Personal dashboards.
- Unsubmitted findings/recommendations.
- Locally saved report drafts.

Default rule: mission records explicitly intended to survive personnel/site movement
should be portable; purely personal convenience state should remain local unless the
user selects it.

Private content must not silently become visible to another site's analysts merely
because it was synchronized.

## E.21 Audit trail

Record every export and import.

Audit should include:

- Operator.
- Site.
- Bundle ID.
- Destination/source site.
- Time.
- Bundle type.
- Export filters/options.
- Record/artifact counts.
- Signature/trust result.
- Import preview result.
- Applied/ignored/deferred counts.
- Conflicts.
- Conflict resolutions.
- Failed integrity/compatibility checks.
- Final status.

Audit records themselves must participate in appropriate mission continuity without
creating recursive unbounded export growth.

## E.22 UI workflow

Add a mission-level workflow such as:

**Mission → Offline Sync**

### Export

Show:

- Destination site.
- Full vs delta.
- Changes since last acknowledged exchange.
- New records/artifacts.
- Estimated transfer size.
- Omitted/local-only classes.
- Warnings.
- Media free-space check where available.
- Create/verify bundle action.

### Import

Show:

- Source site.
- Bundle/sequence.
- Signature/trust.
- Compatibility.
- New/already-known records.
- Artifact transfer savings.
- Tombstones.
- Conflicts.
- Required disk space.
- Preview.
- Import action.

### Conflict Review

Provide a dedicated queue with object-level provenance and explicit resolution.

### Site/Peer Management

Allow authorized operators to:

- Name this site.
- View site ID/fingerprint.
- Add/trust peer identity.
- Retire/replace a site.
- View last exchange/acknowledgment.
- Force full reconciliation when needed.

## E.23 Failure and recovery cases that must be tested

Test at minimum:

- Same bundle imported twice.
- Delta imported before required predecessor.
- Missing predecessor but complete dependency set present.
- Interrupted export.
- Interrupted staging.
- Interrupted database merge.
- Container restart during import.
- Media removal during copy.
- Media removal after staging.
- Full disk.
- Corrupted archive.
- Changed manifest.
- One corrupted artifact among many.
- Invalid signature.
- Unknown/untrusted site.
- Retired/compromised site.
- Wrong destination package.
- Site clone with duplicate site ID.
- Clock skew.
- Future-dated records.
- Same globally stable object created independently at two sites.
- Conflicting revisions.
- Archive versus edit conflict.
- Tombstone followed by stale offline resurrection attempt.
- Analyst identity collision.
- Schema older/newer in both directions.
- Parser/analysis version mismatch.
- Exact duplicate artifact from multiple sites.
- Similar-but-not-identical artifacts.
- Large bundle across multiple media volumes/chunks.
- Partial passive-telemetry transfer.
- Private-content permission boundaries.
- Import by unauthorized role.
- Reconciliation after months offline.

## E.24 Implementation sequence

Implement in this order unless a documented deviation is approved:

1. [ ] Define stable Site identity and trust model.
2. [ ] Inventory all portable mission-data classes and all local-only classes.
3. [ ] Audit every current/new persistent mission entity for globally stable IDs.
4. [ ] Add/confirm causal revision metadata and append-only history where required.
5. [ ] Define archive/tombstone semantics and resurrection prevention.
6. [ ] Define analyst identity portability separate from authentication.
7. [ ] Define bundle manifest/schema and compatibility rules.
8. [ ] Implement deterministic read-only mission inventory.
9. [ ] Implement full export package creation.
10. [ ] Implement hardened staging and package verification.
11. [ ] Implement read-only import preview.
12. [ ] Implement idempotent import of immutable artifacts/observations.
13. [ ] Implement merge of append-only mission records.
14. [ ] Implement mutable-object conflict detection.
15. [ ] Implement conflict-review/resolution workflow.
16. [ ] Implement peer acknowledgment and destination-specific delta calculation.
17. [ ] Implement delta export/import.
18. [ ] Implement tombstone/archive propagation.
19. [ ] Implement schema/analysis-version compatibility and stale-result handling.
20. [ ] Implement package signing/trust workflow.
21. [ ] Implement optional package encryption where mission policy requires it.
22. [ ] Implement large-data/chunking/multi-volume behavior.
23. [ ] Implement Mission → Offline Sync UI.
24. [ ] Add complete audit/provenance reporting.
25. [ ] Run two-site convergence tests with independent changes.
26. [ ] Run three-or-more-site convergence tests with transitive exchanges.
27. [ ] Run long-offline-site resurrection/conflict tests.
28. [ ] Validate on representative disconnected Range hardware and removable media.
29. [ ] Publish operator workflow, recovery procedure, compatibility matrix, and known
    limitations.
30. [ ] Mission-ready acceptance only after the development gate below passes.

## E.25 Key watch points / breakpoints

The independent reviewer must treat these as explicit quality-gate watch points:

- Any new mission entity using only local integer identity.
- Last-writer-wins for consequential mission state.
- Merge ordering based solely on timestamps.
- SQLite database replacement presented as synchronization.
- Missing tombstones for portable mutable objects.
- A deletion that can be resurrected by a long-offline site.
- Credentials/secrets entering ordinary mission packages.
- Private analyst content losing its visibility boundary.
- Artifact observations collapsing into one encounter because bytes are identical.
- Similar-but-nonidentical artifacts being deduplicated.
- Imported derived results becoming current despite version mismatch.
- Missing provenance after merge.
- Silent conflict resolution.
- Package parsing before integrity/structure validation.
- Importing directly from removable-media paths.
- Partial imports reported as complete.
- Delta generation from wall-clock time instead of acknowledgments/sequences.
- Site cloning producing duplicate active site identity.
- Unsupported schema being partially interpreted without warning.
- Full-mission claims when evidence classes were intentionally omitted.
- A failed import leaving partially committed mission state.
- Sync/audit events recursively causing unbounded package growth.
- Package signing keys or authentication secrets being exported.
- Cross-site role/permission assumptions granting unintended access.
- Performance that requires external infrastructure incompatible with disconnected
  constrained kits.

Any one of these requires **HALTED FOR REVIEW** until resolved or explicitly accepted
and documented.

## E.26 Success criteria

Offline Mission Synchronization is successful when:

1. Two disconnected sites can independently work, exchange packages in either order,
   and converge without losing evidence or analyst history.
2. Exact duplicate artifacts transfer/store only once while every encounter remains
   preserved.
3. Conflicting analyst decisions are surfaced rather than silently overwritten.
4. A kit months out of date can safely reconcile without resurrecting retired state.
5. Wall-clock skew does not corrupt ordering.
6. Re-importing a package causes no duplicate logical state.
7. Interrupted import/export resumes or safely restarts.
8. Unsupported versions fail safely and explain why.
9. Every merged conclusion remains traceable to source site, analyst, evidence, and
   revision history.
10. A destination can prove what it has and generate a compact delta acknowledgment.
11. Mission truth can move without moving credentials or machine-local secrets.
12. Operators can understand whether a site has a complete, partial, or stale mission
    picture.
13. Full and delta packages work on representative offline Range hardware and approved
    removable-media workflows.

---

# 12. Product Identity

The working project name is:

# **NCT — Network Correlation & Triage**

This better represents the expanded mission than “Network Characterization Tool”
while retaining the existing NCT identity.

Characterization remains a core capability, but the platform now also encompasses:

- Correlation
- Passive characterization
- Hunt/triage
- Investigation
- Reachability
- Hardening
- Crew workflow
- Reporting

The name may be revisited later, but **Network Correlation & Triage** is the
working expansion and should be used in roadmap/design discussions moving forward.

---

# 13. Development Gates

## Gate 1 — Persistence

Do not begin high-volume passive integration until:

- Deduplication works
- Enrichment cache works
- Persistent jobs work
- Page navigation does not recreate analysis
- SQLite reliability is improved
- Delta processing works
- Last Seen/evidence provenance works

## Gate 2 — Passive Characterization

Do not begin advanced timeline/dashboard work until:

- Arkime works without Nmap
- Passive evidence provenance is reliable
- Aggregation works
- Retention works
- Coverage gaps are explicit
- Summary and richer ingestion modes both work

## Gate 3 — Collaboration

Do not rely on Crew Lead workflow until:

- Lens ownership exists
- Sharing permissions exist
- Canonical identity/provenance exists
- Callsign and canonical identity are separated

## Gate 4 — Dashboard

Dashboard widgets must query normalized/prepared evidence. They may not reparse
source artifacts as part of normal interaction.

## Gate 5 — Offline Mission Synchronization

Do not call multi-site mission synchronization mission-ready until:

- Every portable mission object uses globally stable cross-site identity.
- Site identity and peer trust are explicit and clone-safe.
- Consequential mutable objects have merge-safe revision history.
- Archive/tombstone semantics prevent stale-site resurrection.
- Analyst identity is portable without exporting authentication secrets.
- Full export/import is verified, previewed, idempotent and restart-safe.
- Destination-specific delta exchange uses acknowledgments/sequences rather than only
  timestamps.
- Conflicts are detected and require explicit provenance-preserving resolution.
- Artifact transfer deduplicates only exact verified content.
- Imported derived results honor parser/analysis-version dependencies.
- Bundle integrity/signature checks occur before commit.
- Removable-media/archive hardening tests pass.
- Two-site and multi-site convergence tests pass.
- Long-offline-site reconciliation tests pass.
- Version compatibility matrix is documented and tested.
- Mission-local versus machine-local data boundaries are documented and enforced.
- Range/offline hardware validation and operator recovery procedures are complete.

---

# 14. Development Order

```text
PHASE 0  Protect + Benchmark
   ↓
PHASE 1  Persistent Data / Analysis Engine
   ↓
PHASE 2  Existing Characterization Refactor
   ↓
PHASE 3  Mission Environment + Blind Spots
   ↓
PHASE 4  Manual / Partial Evidence
   ↓
PHASE 5  Universal Query / Pivot Engine
   ↓
PHASE 6  Arkime + Passive Characterization
   ↓
PHASE 7  Hunt Timeline + Lenses
   ↓
PHASE 8  Crew Operations + Tasking
   ↓
PHASE 9  Reach + Map Evolution
   ↓
PHASE 10 Hardening + Simulation
   ↓
PHASE 11 Dashboard
```

The following run horizontally across phases:

- Report Composer / Export Manager
- Retention and compaction
- Offline Mission Portability & Multi-Site Synchronization
- Provenance
- Deployment
- Performance
- Testing
- Documentation

---

# 15. Immediate Next Implementation Target

After this roadmap is accepted, the first implementation milestone is:

## **Data & Analysis Engine v2**

1. Inventory current schema and processing paths.
2. Add artifact hashing/deduplication.
3. Establish canonical host/service entities.
4. Establish observation records.
5. Implement delta detection.
6. Redesign Searchsploit caching.
7. Persist enrichment results.
8. Add analysis versioning.
9. Add dirty-state tracking.
10. Implement persistent jobs.
11. Move expensive operations out of request/page handling.
12. [~] Enable SQLite WAL/busy timeout and reduce contention.
13. Build current-state read models.
14. Implement Last Seen + evidence receipt behavior.
15. Backfill the Artifact Registry from existing Nmap scans, imported XML, device
    collections, and other retained source artifacts.
16. Provide a **read-only storage analysis / dry run** before any compaction:
    - files inspected
    - unique content hashes
    - exact duplicate count
    - current storage footprint
    - estimated reclaimable space
    - references/observations that would be preserved
17. Make backfill restart-safe and resumable without recopying content or adding
    duplicate observations. Integrity verification still rehashes content (documented
    deviation); large-installation hashing performance remains unverified.
18. Verify every historical reference before allowing compaction.
19. Allow optional **exact-content compaction** only after verification. SHA-256
    identical content may share one physical artifact while retaining every scan,
    collection, timestamp, analyst, filename, and evidence reference.
20. Never deduplicate merely similar artifacts. Non-identical source evidence is
    retained and compared through normalized facts/delta processing.
21. Benchmark against Phase 0 datasets.

Only after this foundation behaves reliably should NCT begin high-volume passive
evidence ingestion.

---

# 16. Definition of Success

The redesign succeeds when:

1. An analyst ingests evidence once and can immediately reuse its conclusions
   throughout NCT.
2. NCT remains useful when Nmap is unavailable or prohibited.
3. The system knows the difference between **not present** and **not visible**.
4. Hosts/services can go dark without losing historical truth.
5. Every Last Seen state can lead back to evidence or an evidence receipt.
6. Analysts can leave and return without losing processing or context.
7. Crew Leads can understand team activity and continue another analyst's work.
8. Findings and recommendations retain defensible provenance.
9. Hardening changes can be simulated before recommendation approval.
10. Leadership can compose exact reports from selected evidence and dashboards.
11. More retained knowledge does not automatically mean slower interactive use.
12. NCT becomes progressively more knowledgeable through **incremental learning**,
    not progressively slower through repeated full re-analysis.
13. Multiple disconnected NCT kits can exchange verified mission packages, preserve
    independent evidence and analyst history, surface conflicts, and converge on a
    common mission picture without copying/replacing the database or exposing local
    credentials.
