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
| 2026-09-27 | Phase 1 | Nmap imports remain readable through the existing `/data/imports` path model while Artifact Registry is introduced | New imports are stored in the canonical content-addressed artifact store; the raw-download guard was revised to trust either a verified legacy import path or the exact path registered for that SHA-256 | CI exposed that the legacy download endpoint intentionally rejected paths outside `/data/imports` | Preserves existing download behavior while enabling deduplicated storage; legacy imports remain supported during migration |

| 2026-09-27 | Phase 1 | Introduce Artifact Registry without changing existing import behavior | Artifact Registry integration initially caused the existing raw Nmap download test to reject canonical artifact paths; compatibility validation was updated and the subsequent full CI run passed | Legacy endpoint assumed all imported XML lived directly under `/data/imports` | Treat legacy file-layout assumptions as migration compatibility requirements; no Phase 1 item marked complete until green CI |
| 2026-09-27 | Phase 1 storage | Replace historical duplicate files during migration | Backfill creates verified canonical copies and checkpoints but retains every historical original; new finalized collections use atomic hard-link replacement with a copy fallback | Existing consumers still depend on run-local paths; deleting historical evidence requires a separate rollback and reference-recheck gate | Backfill can temporarily increase used space. Optional compaction remains unimplemented and disabled |
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
5. [ ] Record baseline:
   - CPU
   - RAM
   - disk
   - DB size
   - page load
   - query duration
   - enrichment duration
6. [~] Preserve old-range Docker compatibility and offline operation.

## Exit criteria

- Stable rollback exists.
- Baseline metrics exist.
- Representative regression datasets exist.
- Current architecture is documented.

---

# PHASE 1 — Persistent Data & Analysis Engine v2

**Purpose:** Stop repeated analysis and create the foundation for all later features.

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
   - [ ] Optional exact-content compaction.
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
2. Canonical host/service/network/device entities.
3. Separate observations from entities.
4. Delta detection:
   - new
   - changed
   - unchanged
   - no longer observed
   - not assessed
5. [x] Searchsploit cache redesign.
6. [~] Persistent derived results.
   - [x] Searchsploit query results are now persisted and reused across requests.
   - [x] Cache identity changes with the active Exploit-DB dataset.
   - [ ] Persist remaining analysis families under the common derived-result model.
7. [ ] Dirty-state tracking.
8. [ ] Dependency graph.
9. [ ] Analysis versioning.
10. [ ] Persistent jobs and partial failure.
11. [ ] Lightweight worker.
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
- [~] Started disposable synthetic storage measurements for first dry run, initial
  backfill, and repeated backfill, including wall time, CPU, peak process memory,
  bytes and correctness checks. These do not establish production-scale acceptance.

   WAL and a 30-second busy timeout were already present before this redesign; the
   remaining reliability work is focused on eliminating unnecessary writes and
   contention.
13. [ ] Current-state read models.
14. [ ] Last Seen + evidence receipt model.
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
2. Preserve/fix global and scan-specific NO-STRIKE enforcement.
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
