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

### Deviation history

| Date | Phase | Planned | Revised / Implemented | Reason | Impact / Follow-up |
|---|---|---|---|---|---|
| 2026-09-27 | Phase 1 | Add SQLite WAL/busy-timeout reliability controls | Existing code already had WAL + 30s busy timeout; foundation work is focusing on eliminating repeated schema initialization and long/redundant write paths instead of re-adding WAL | Repository inspection showed WAL was already enabled at startup | Continue auditing storage modules for request-path DDL and lock-heavy patterns |
| 2026-09-27 | Phase 1 | Cache Searchsploit enrichment by normalized service fingerprint | First implementation caches the sanitized Searchsploit query keyed to the active Exploit-DB dataset identity | Current enrichment already deduplicates findings into normalized queries; persisting that boundary provides the same reuse benefit with less invasive change | Later canonical Service entities can reference this cache rather than replacing it |
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
| 2026-09-27 | Phase 1 storage | Replace historical duplicate files during migration | Backfill creates verified canonical copies and checkpoints but retains every historical original; new finalized collections use atomic hard-link replacement with a copy fallback | Existing consumers still depend on run-local paths; deleting historical evidence requires a separate rollback and reference-recheck gate | Backfill can temporarily increase used space. Optional compaction remains unimplemented and disabled |
| 2026-10-04 | Phase 1 supported ingestion completion | Treat separate completed foundation features as a complete ingestion pipeline | Finish one durable staged pipeline for currently supported Nmap and device evidence; keep scope-free calculations separate from scoped observations and require explicit scope where needed | Existing operator actions use different persistence, retry and status models, and planned passive collectors or physical-device reconciliation would expand this gate without a safe identity contract | Missing scope is Needs scope, never inferred. Preserve every completed stage when another fails. Generalize the existing single-process worker through additive, preservation-tested pipeline tables, then connect intake, current-state/Last Seen receipts and acceptance benchmarks. The copied legacy queue becomes a trigger-enforced read-only audit archive. All processes must cut over together; ordinary rollback is unsafe because older code cannot see post-cutover work and cannot write the frozen queue. Historical adoption stays explicit and passive collectors remain later phases. See `docs/DERIVED_RESULTS.md` |
| 2026-10-04 | Phase 1 automatic Nmap admission | Find new eligible work by scanning timestamps or all retained evidence after startup | Mark only new participating manual Nmap observations and scan runs, then commit a frozen admission intent with the authoritative assignment or eligible scan finalization before the durable worker creates a job | Timestamp selection can silently adopt historical evidence, miss work across clock changes, or switch a retry to a corrected assignment or newer parser. Making immediate job creation part of evidence retention would also make a successful import, assignment or scan depend on queue availability | Admission intents preserve the exact source, scope decision, actor and processing contract while allowing queue admission after the source transaction. Startup and worker recovery examine only pending intents from explicitly marked sources. Historical rows keep the explicit Queue action; missing scope remains Needs scope; corrections create new intents and cannot redirect older work. This gate covers new manual and automated Nmap evidence only. Device intake, processing retries, current-state selection and Last Seen remain separate gates. |
| 2026-10-04 | Phase 1 automatic device-summary admission | Calculate verified device summaries while opening a page or silently adopt every active authority after upgrade | Mark only new participating manual uploads and eligible SSH collections, freeze an admission intent when exact device authority activates, then calculate through the shared durable worker | Page-time calculation can race authority changes and makes navigation perform expensive work. Broad startup adoption would silently change historical processing behavior | Device summaries are scope-free reusable calculations. Their intents retain the authority revision, selection contract, semantic manifest and ordered exact inputs. Historical unmarked authorities keep their established on-demand behavior until a separate adoption gate. Failed or interrupted calculation requires explicit local retry and never contacts the device. Normalized device observations, Network Scope assignment, physical-device identity, current-state selection and Last Seen remain later gates. |
| 2026-10-04 | Phase 1 latest supported observations / Last Seen foundation | Build a broad current-state model and exact Last Seen behavior after canonical entity storage | First add a versioned, read-only selector for one scoped Nmap address that separately reports the latest supported source window and the last confirmed positive source window | Existing immutable receipts can safely order scoped Nmap observations by validated source collection windows, but they cannot yet prove physical-device identity, live state, exact per-service time, device-configuration scope, or disappearance | Identity remains Network Scope plus IP address. Only current unsuperseded assignments, the supported parser, successful completion and valid source windows may participate. Equal or transitively overlapping windows remain grouped; successful unknown-time records remain visible and block an unqualified latest claim. Every displayed observation links to its retained evidence. A later assumed or incomplete record cannot erase earlier confirmation. This completes only a nested Steps 13-14 slice; broader current state, physical-device reconciliation, device observations, service absence and exact Last Seen remain open. See `docs/ENTITY_FOUNDATION.md` |
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

No core requirement for PostgreSQL, Elasticsearch, Redis, or Kubernetes.

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
      work interrupted while running requires an explicit local retry from the beginning,
      without a rescan when the retained evidence remains intact. Bulk requests,
      cancellation, automatic retries, automatic stale scheduling, topology jobs,
      device-summary jobs and dependency-driven rebuilds remain separate gates.
      Completed 2026-10-03. Scan History now offers Prepare saved analysis for one
      eligible finalized scan and shows queued, running, completed, failed and
      interrupted outcomes without implying collection success. System Health shows a
      bounded read-only request and attempt history. Queued work resumes after restart;
      an abandoned running attempt is retained as Interrupted and an explicit retry adds
      a new attributed attempt. The runner rejects changed, missing, ambiguous or
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
   scope, corrections cannot redirect older work, and failed or interrupted attempts are
   never retried automatically. A retained activity state distinguishes Waiting,
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
   successful attempt; failed or interrupted calculations require an explicit local
   retry and never contact the device. Device History must distinguish local source
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
12. [~] SQLite WAL/busy-timeout/transaction remediation.
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
   - [~] Review long write transactions and high-contention write paths. Started
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
   - [x] Initial disposable synthetic storage measurements executed for 100 and 1,000
     collections: first dry run, initial backfill, repeated backfill, wall time,
     CPU, peak process memory and bytes. Original-file and observation-count checks
     passed. Reviewer CLEAR; report and reproducible script retained. Production-scale,
     cold-cache, concurrent-workload and note-tree acceptance remain open.

   WAL and a 30-second busy timeout were already present before this redesign; the
   remaining reliability work is focused on eliminating unnecessary writes and
   contention.
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
15. [ ] Benchmark against Phase 0 datasets.

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
3. Saved scan profiles:
   - TCP
   - UDP
   - TCP + UDP
   - FPING
   - Traceroute
   - ICS-oriented
   - Custom
4. Retain scan creator/callsign, profile, target, protocol, scheduling context.
5. Improve progress and bounded ETA.
6. Resolve combined TCP/UDP reliability issues.
7. Make historical Analyze reopen full persisted analysis.
8. Expand scan comparison:
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

## 3.1 Mission Environment settings

Under the settings/hamburger menu, define the hunt environment:

- Arkime version
- Kibana/Elastic version
- Nmap availability/version
- Device-config availability
- Access method
- Network scope
- Authorization constraints

## 3.2 Authorization scope

Examples:

```text
10.10.0.0/16 — Nmap authorized
10.20.0.0/16 — Nmap prohibited
10.30.0.0/16 — authorization unknown
```

NCT must never equate tool availability with authorization.

## 3.3 Device evidence availability

Examples:

- Full configuration
- Partial configuration
- Command output only
- Analyst-known/manual
- Unavailable

## 3.4 Coverage matrix

Show per-network evidence availability:

| Network | Nmap | Arkime | Kibana | Config |
|---|---|---|---|---|
| Engineering | Available | Available | Available | Partial |
| DMZ | Prohibited | Available | Available | Available |
| Management | Available | None | Available | Partial |

## 3.5 Blind spots

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

## 6.1 Tier A — Summary export

Lowest-cost/manual option.

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

Track:

- Coverage start/end
- Gaps
- Network scope
- Collection method
- Source/import ID

## 6.8 Recommended collection window

Generate the smallest useful next window with a configurable overlap buffer to
avoid gaps. NCT deduplicates overlap.

## 6.9 Passive-only characterization

A host/port relationship can exist based solely on passive evidence.

Label clearly:

- **Passively observed**
- **Not actively validated**

Do not claim a listener is open unless evidence supports that conclusion.

## 6.10 Communication aggregation

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
