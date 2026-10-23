# NCT incident repairs and requested-fix handoff

Prepared October 23, 2026 for the **Primary NCT Roadmap Builder**.

## Purpose and scope

This report covers the Teams self-chat beginning immediately after
`********ALL ABOVE HAVE ALREADY BEEN SUBMITTED FOR CORRECTION**********2`
(October 20, 2026, 8:24 AM), through the October 23 notes, plus the user's later
requests for troubleshooting, an unfinished-work reset, and a fresh install.
Earlier Teams requests are outside this handoff unless repeated after that marker.

The user's latest direction is to finish the scheduled-scan incident repairs,
**stop implementation**, and hand remaining work to the Primary NCT Roadmap
Builder and its existing multi-agent process. Recovery/reset/fresh-install tools
are recommendations in this report, not implemented capabilities.

Development is on `foundation/evidence-engine-v2` in `nct-foundation`.
The stable `main` checkout, deployment packages and controller evidence were not
modified. A source fix or local test is not a deployed Range fix.

## What was observed directly

- Read every text note and attached screenshot after the specified Teams marker.
- The startup log shows `sqlite3.IntegrityError: FOREIGN KEY constraint failed` in
  `app/scheduled_work.py`, `migrate_legacy_schedules`, at the chunk insertion.
- Controller inspection confirmed that same failure on the installed
  `0.16.0-range-test-20261019-phase4-r5` image. The NCT container was stopped with
  exit code 3 when inspected. The console also showed an upgrade refusing to
  proceed because active work could not be checked.
- Read-only controller queries found **19 completed scans and one queued scan**,
  one native preparing schedule occurrence and another waiting occurrence.
  `PRAGMA foreign_key_check` returned no violations. The failed startup transaction
  had not left dangling database relationships.
- The queued scan retained a scheduled-chunk ownership claim and had not acquired
  a scan-execution claim. These retained records do not, by themselves, establish
  why the original live queue first stopped progressing.
- The history-edit screenshot says **“This NCT worker no longer owns the saved
  work.”** This is a separate historical-edit problem; the screenshot does not
  mean the feature has intentionally been removed.
- The proposed-policy screenshot uses a forwarding rule while the operator wants
  to block internet SSH access **to the router itself**. That distinction needs
  explicit treatment in the policy workflow.

## Scheduled-scan repairs completed in development

### S1. Startup conversion must not reinterpret existing durable work

**Cause reproduced:** startup could mistake native schedule batch fields for
legacy work. A uniqueness rule prevented inserting a replacement occurrence, but
conversion then tried to insert chunks referring to that missing occurrence.
This reproduced the controller's exact foreign-key failure. Terminal native
history was also vulnerable to inappropriate reinterpretation of stale fields.

**Implemented:** schedules with durable occurrence history are not converted
again. Normal recovery continues to distinguish unstarted work from potentially
interrupted network contact. Genuine older interrupted schedules convert once,
preserving completed chunks and pausing uncertain contact for review.

**Verified:** repeated storage startup; native waiting, preparing, active,
review-required, complete and cancelled states; mixed legacy/native schedules;
preservation of exact schedule/definition/occurrence/chunk records; database
relationship checks. Independent reviewer: **CLEAR**.

### S2. A blocked schedule must not hold up later eligible schedules

**Cause reproduced separately:** dispatch examined the first waiting schedule
and returned after its conflict. A changed Saved Network scope could also escape
the handled errors. Later eligible schedules were never considered on that check.

**Implemented:** preserve each blocker and its explanation, consider later
eligible work, and stop after one successful batch dispatch. A schedule disabled
by a scope/mission blocker stays paused until explicit operator action. Existing
scanner ownership checks remain authoritative. Unexpected scheduler exceptions
are logged instead of silently swallowed.

**Verified:** waiting and newly due schedules; scope, mission and ownership
conflicts; real scope reassignment; all-blocked and repeated-check behavior;
one successful dispatch per check. Independent reviewer: **CLEAR**.

**Limit:** this is a proven queue defect, not a proven explanation for every part
of the original controller stall. Target acceptance still needs the retained
pre-contact queue and schedule state to be exercised with the repaired image.

### S3. Scheduled chunks must retain their selected network and reviewed scope

**Cause reproduced:** the scheduled chunk request omitted its Saved Network
selection. Initial admission obtained scope from the schedule, but the final
pre-contact check used the empty selection and replaced that scope with no scope.
Missing selection also deprived history of the original network label.

**Implemented:** atomically retain the schedule's selected networks, names,
manual-target classification and reviewed scope/mission versions. For durable
chunks, the schedule must still match the occurrence's frozen definition.
These are context records; execution targets remain the exact chunk, rather than
expanding back to the entire selected network.

**Verified:** unchanged context; association changed after admission; mission
authorization changed after admission; mixed saved/manual targets stay unscoped;
changed frozen definition rejected before insertion; exact contacted-address set;
network name unchanged. Independent reviewer: **CLEAR**.

**Limit:** no historical records were silently relabelled or assigned scope.
This repairs new scheduled-run selection. A literal mutation of the Saved Network
record's name, as reported by the user, still needs a separate reproduction and
audit; missing history context alone does not prove that mutation occurred.

### S4. Automatic processing must include reusable saved analysis

**Additional gap found in the browser:** scoped evidence processing could finish
while History still asked the user to select **Prepare from saved scan**.

**Implemented:** the existing background calculation worker also prepares local
reusable Nmap analysis for completed scans marked for the supported pipeline,
once a finalized intake receipt and exactly one registered aggregate XML exist.
Scheduled and unscoped scans participate; this calculation does not assign scope
or authorize traffic. Startup and worker-exit checks recover missed admission.
Existing jobs prevent duplicate preparation or automatic retries of failures.
Unmarked historical scans retain explicit preparation.

The existing administrator repair for a missing scope handoff remains usable after
scope-independent base analysis. Scoped and unfamiliar processing histories still
block that narrow repair.

**Verified:** concurrent admission creates one job; scoped/unscoped and scheduled/
manual completion; actual reusable output; unfinished/missing/ambiguous XML
excluded; unmarked/unknown-policy history excluded; existing attempt states never
silently retried; worker-exit timing gap; failed evidence does not block the next
valid scan; explicit scope repair after base preparation. Independent reviewer:
**CLEAR — DOCUMENTED DEVIATION**. This extra step was required to meet the user's
actual workflow, beyond automatic scoped-foundation admission.

## Remaining requests and recommended fixes

Priorities: **P1** affects correct operation, evidence interpretation or recovery;
**P2** affects operator workflow and clarity; **P3** is a larger capability addition.
The builder should assess current code before accepting a report as a reproduced
defect. Preserve the user's intent even when a request is absorbed by existing work.

| ID | Priority | Observed or requested | Recommended option and completion check |
|---|---|---|---|
| R01 | P1 | Scan Profile deletion does not work; Save has little feedback; repeated clicks create duplicates. | Make save/delete results explicit; prevent duplicate submissions while a request is pending; make the server safely recognize a repeated save. Explain dependencies that prevent deletion. Verify successful save/delete, slow responses, double clicks, failures, and schedules pinned to older versions. |
| R02 | P2 | Map device details list open services without showing the interface/address exposing them. | Group service observations by observed interface IP and interface name. Put observations that cannot be mapped confidently in an explicit unmatched group. Never imply a service is exposed on every interface. Test multi-interface devices, shared ports, aliases and missing interface evidence. |
| R03 | P2 | Port and service/product rows do not line up; port information is repeated. | Render each port/protocol and its matching service/product as one aligned row. Remove duplicate port labels only when association remains unambiguous. Test long fingerprints, multiple ports, narrower screens, scrolling and the Operator Guide. |
| R04 | P2 | Repeated host IPs do not clearly show that ports such as 137, 139 and 445 belong to one host. Keep all existing data. | Add visible host groups with a shared host heading or bracket and individual service rows. Preserve port-level findings and filters. A filtered group must still identify its host, and pagination must not create unexplained fragments. |
| R05 | P2 | Move the filter bar into the table controls next to Rows per page. | Place the quick filter and paging controls together, retaining advanced network filters separately where useful. Test combined filters, reset, keyboard access, page changes and narrow layouts. |
| R06 | P1 | Repeated configuration/history pulls still do not identify commands performed by NCT. | Match retained command execution receipts to the device's observed history using normalized command text, device identity and bounded collection timing. Distinguish confirmed, possible and unmatched attribution. Preserve every pull and command; never classify an unmatched command as malicious or definitely not NCT. Verify repeat pulls, timestamps, prompts, truncation and history retention limits. |
| R07 | P1 | Operator cannot confidently implement and test a proposed rule blocking internet TCP/22 access to the router itself. | Make the operator choose router-local access versus forwarded traffic; select the correct vendor-specific policy path; show interface IPs, rule placement and retained evidence limits. Separate a simulated assessment from an applied-device result. Validate with representative configurations, then an authorized isolated device before claiming a working rule. Do not apply changes automatically. |
| R08 | P1 | Scope is easy to miss during collection. Put it first, mark an empty choice red, and warn before scanning. | Put scope/context review at the start of each applicable collection flow. Clearly show inherited context and why mixed/manual targets are unscoped. Give a visible warning before unscoped collection without silently inventing scope or changing established authorization rules. Verify keyboard and non-color cues as well as visual emphasis. |
| R09 | P2 | Detailed Active Scan content appears on pages where it does not belong. | Keep detailed live execution/discoveries on Active Scans. New Scan gets a compact current/waiting/scheduled overview with queue position and responsible operator. History gets historical results. Test every sidebar/hash route, refresh and direct links. |
| R10 | P2 | Scan History should support alphabetical or newest ordering and should not show Profile Behavior. | Add explicit sorting with alphabetical default as requested; keep paging deterministic. Remove Profile Behavior and unrelated live panels from History. Verify old scans remain reachable inside the correct group. |
| R11 | P2 | Select several saved networks, apply one profile, use `$subnet` in the name, and queue them in selection order. | Create one accountable run per selected network, preserving its scope and profile snapshot; substitute the Saved Network name in `$subnet`. Show generated names and ordering before submission. Make submission transactional or report exactly which runs were accepted. This request describes sequential queue positions; do not assume permission for simultaneous network scans. |
| R12 | P1 | Due schedules and waiting scans stop progressing while the scanner appears available. | Incorporate S1/S2, retain the original incident state, then run target acceptance proving due dispatch, queue progression and restart recovery. Add visible blocked/attention reasons. Do not treat the independently reproduced starvation defect as the only possible cause. |
| R13 | P1 | Scheduled results appear under generated subnet groups; saved network names reportedly change and older scans move. | Incorporate S3 for new runs. Separately trace every Saved Network write and history rename/grouping action to establish whether records are renamed or labels merely change. Keep run names separate from network names. Repair historical labels only with an explicit, attributable decision; never guess from a matching IP or CIDR. |
| R14 | P1 | Scheduled scans lose Network Scope. | Incorporate S3 and verify artifact, run, processing and displayed scope agree after completion/restart. Older affected evidence needs a reviewed correction or assignment, preserving the previous record and reason. No blanket historical reassignment. |
| R15 | P1 | Results still need Prepare from saved scan; user wants automatic preparation. | Incorporate S4. Confirm both automatic scoped processing and reusable saved-analysis completion in History, not just a queued background job. Expose failures and explicit retry. Clearly explain the separate treatment of older unmarked scans and scans lacking scope. |
| R16 | P1 | Edit network on historical scans fails with an ownership error. | Separate analyst metadata changes from active worker updates. A historical edit should validate current operator authority and current metadata revision, rather than reusing a finished worker's expired claim. Preserve evidence and original provenance. Test complete, interrupted, imported and scheduled runs, concurrent edits and stale browser pages. |
| R17 | P2 | The pending-scan dropdown looks like a name-change control and its purpose is unclear. | The screenshot appears to show operator assignment. Confirm the actual action, label it **Assigned operator**, explain the permission/assignment effect and give an explicit save result. If the intended control truly renames runs, give it a separate clear label. |
| R18 | P1 | Restarting NCT and rebooting the controller leave the application unavailable. | Incorporate S1 and add stopped-container recovery acceptance with preserved data and exact installed build. Fix the recovery/upgrade workflow that currently cannot inspect active work when NCT cannot start; use a stopped-data inspection path rather than requiring a running app or blindly bypassing active work checks. |
| R19 | P3 | Add STIG compliance support. | Start with a bounded read-only assessment for explicitly supported device/OS and benchmark versions. Link each finding to its retained evidence and distinguish pass, fail, not applicable and not checked. Keep remediation separate. A configuration review alone must not imply complete device compliance. |
| R20 | P3 | Log in to a first device, discover neighbors, identify their platform, use approved stored credentials, collect compatible evidence and build the map progressively. | Build an operator-reviewed discovery-and-collection plan with a credential reference store, platform-specific read-only command sets, visited-device tracking and a live progress view. Apply scope, allowed-target and No-Strike boundaries before every new contact; bound hops, targets, retries and concurrency. Require explicit handling of unknown platforms or ambiguous credentials. Never follow discovered neighbors beyond authorization automatically. |
| R21 | P3 | Validate the device operating system using a hash or similar integrity information. | Separate platform fingerprinting from integrity verification. For supported devices, compare a collected image digest/signature against a trusted reference for the exact vendor, release and image. Retain the reference, method and evidence. Report unknown when trust or collection is insufficient. A matching image hash does not establish that the entire device is uncompromised. |
| R22 | P1 | Give teams a troubleshooting script so they can investigate without abandoning NCT. | Provide a diagnostic-first command that works with running, stopped or restarting containers. Save a private report with build, container state, saved port/mount configuration, disk space, selected logs and read-only database/work summaries. Avoid exporting secrets or raw device evidence by default. Print actionable next steps and report location. Test stopped-container and restricted-runtime cases. |
| R23 | P1 | Add a hard reset that clears unfinished processes and gets the tool running again. | Add a separate explicit **reset unfinished work** mode: stop every writer/contact process, take and verify a full cold backup including WAL/evidence, record original affected rows, close unfinished work in one transaction, pause schedules/automatic contact producers, then start the same installation and verify health/sign-in/history. Preserve completed scans, collections, accounts, settings and evidence. Refuse unfamiliar active work, incomplete migrations or unresolved compaction; do not simply delete locks or mark interrupted evidence complete. Exercise rollback, double reset, backup failure and unchanged completed-evidence hashes on disposable installations. |
| R24 | P1 | Provide a wipe-and-reinstall option for a genuinely fresh installation. | Keep **fresh install** separate from R23. Show the exact application/data target and everything that will be removed: scans, collections, scopes, saved networks, profiles, users, notes, settings and working state. Verify a separately stored backup, require explicit destructive confirmation, isolate the old installation, initialize the selected verified version with new administrator setup, then verify first sign-in and an empty dataset. Preserve the unrelated legacy installation and do not silently reuse old app data. Document whether TLS/network settings are retained or recreated and how to restore the backup. Test both bind-folder and named-volume deployments. |

## Recommended implementation order

1. Integrate the scheduled incident repair commits and complete exact-target
   recovery/acceptance before calling the controller usable or Range-ready.
2. R22 diagnostics, then R23 evidence-preserving reset and R24 fresh install.
   These are distinct operations with distinct confirmations and acceptance tests.
3. R01 profiles, R06 command attribution, R07 router-local policy, R13 historical
   naming audit and R16 historical metadata editing.
4. R08–R11 collection/navigation/queue workflow, then R02–R05 and R17 presentation.
5. Plan R19–R21 as separately reviewed capabilities after reliability work.

The builder should map these items to current roadmap milestones and record
absorption, dependencies and deviations rather than creating parallel competing
roadmaps. Follow `docs/NCT_PROJECT_OPERATING_RULES.md`; maintain the independent
review gate and operator guide alongside behavior changes.

## Validation and release boundary

- An earlier full source suite for S1–S3 plus scoped automatic admission passed
  **1,906 tests, 18 skipped** before the additional reusable-analysis step.
- Final combined-suite, rebuilt-image, restart and browser results are recorded
  below when complete. Do not substitute the earlier count for final validation.
- The isolated preview uses disposable sample data and has active collection
  disabled. It is not connected to the controller's evidence.
- No release package was generated, no controller reset/reinstall was performed,
  and no change was promoted to `main`.

### Final verification record

- Final combined Linux/Docker suite: **1,923 passed, 18 skipped, one dependency
  deprecation warning**, in 286.16 seconds. `git diff --check` passed.
- Rebuilt application image: `nct-schedule-incident:dev`, image ID
  `sha256:5ac267149b1cb2c611c96a7134a84ad52bb3dc2f0bde9908c4765da68558195f`.
- Isolated preview: `http://127.0.0.1:18129/scans#scanHistory`, container
  `nct-schedule-incident-preview`, disposable volume
  `nct-schedule-incident-preview-data`, active collection disabled.
- Browser verified the distinct original network and scheduled-run names,
  retained scope, **Ready — saved analysis available**, and successful **Analyze**
  navigation into the exact retained scan without selecting Prepare.
- Two preview restarts returned health HTTP 200. There remained one completed
  sample run, one waiting native occurrence and exactly one base-analysis job.
  Foreign-key checks were empty and the retained XML digest stayed
  `993f2752e60eb1ae368ffae20511724d0d5c34728c44c8b1a7f3afe86672c54d`.
- The separate offline SearchSploit candidate stage reports that SearchSploit/
  Exploit-DB has not been staged in this preview. Scoped ingestion and reusable
  Nmap analysis completed. This preview is not a validation of offline candidate
  references or any Range deployment.
- Independent completion gate: **CLEAR — DOCUMENTED DEVIATION**. The reviewer
  checked the exact final changes and report and independently confirmed preview
  health, retained counts, relationship checks and unchanged XML digest.
  The commit identity is recorded in the final handoff message and repository
  history. Implementation stops at this handoff.

### Optional sample acceptance

1. Open the preview's Scan History and expand **Sample Engineering Network**.
2. Confirm the scan is **Sample Scheduled Baseline**, the Network Scope is
   **Disposable incident preview**, and saved analysis is Ready.
3. Select **Analyze**; expect one responsive sample host, `192.0.2.1`, with
   HTTPS on `443/tcp` and the Verified Saved Analysis explanation.
4. Do not use this sample to assess real network coverage or device behavior.
