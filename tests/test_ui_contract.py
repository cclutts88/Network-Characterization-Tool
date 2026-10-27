from __future__ import annotations

import re
from pathlib import Path

from app.analysis_ui import analysis_page
from app.arkime_ui import arkime_page
from app.device_analysis_ui import device_analysis_page
from app.device_ui import device_config_page
from app.hunting_ui import hunting_page
from app.hostname_ui import hostname_page
from app.how_nct_works_ui import how_nct_works_page
from app.mission_environment_ui import mission_environment_page
from app.network_map_ui import network_map_page
from app.network_scope_ui import network_scope_page
from app.reachability_ui import reachability_page
from app.session_ui import SESSION_SCRIPT
from app.shell_ui import SHELL_SCRIPT
from app.storage_ui import storage_page
from app.ui import operator_page


def test_historical_network_context_explains_authority_conflicts_and_recovery():
    html = operator_page().body.decode()

    assert "Who can record this:" in html
    assert 'data-network="${esc(run.run_id)}" data-guide-context="historical-network-context"' in html
    assert "$('applyNetworkAttribution').focus()" in html
    assert "the scan owner or an Administrator" in html
    assert "expected_metadata_revision:Number(pendingAttributionRun.metadata_revision||0)" in html
    assert "attributionStatus.focus()" in html
    assert "Correct one retained scan\\'s network context" in SHELL_SCRIPT
    assert "record the correction.',['Confirm the exact run" in SHELL_SCRIPT
    assert "record the correction.',2,[" not in SHELL_SCRIPT
    assert "reload Scan History" in SHELL_SCRIPT
    assert "Reopen the run and verify the new attributed snapshot." in SHELL_SCRIPT


def test_personal_and_shared_note_panels_are_mutually_exclusive():
    assert "other.panel.classList.remove('open')" in SESSION_SCRIPT
    assert "other.tab.setAttribute('aria-expanded','false')" in SESSION_SCRIPT
    assert "?'shared':'personal'}-notes-open`,'0'" in SESSION_SCRIPT
    assert ".nct-note-panel.personal{left:var(--nct-sidebar-width,278px)" in SESSION_SCRIPT
    assert "transform:translateX(calc(-100% - var(--nct-sidebar-width,278px)))" in SESSION_SCRIPT
    assert "@media(max-width:1100px){.nct-note-tab.personal{left:0" in SESSION_SCRIPT
    assert ".nct-note-tab.personal{left:var(--nct-sidebar-width,278px)" in SESSION_SCRIPT
    assert ".nct-note-tab-content" in SESSION_SCRIPT
    assert "transform:translate(-50%,-50%) rotate(90deg)" in SESSION_SCRIPT
    assert ".nct-note-panel.personal,body.nct-nav-closed .nct-note-panel.personal{left:0}" in SESSION_SCRIPT
    assert "body.nct-notes-personal-open>main" in SESSION_SCRIPT
    assert "body.nct-notes-shared-open>main" in SESSION_SCRIPT


def test_active_scan_has_a_bounded_provisional_discovery_workspace():
    html = operator_page().body.decode()

    assert 'id="liveDiscoveriesPanel"' in html
    assert "Live discoveries" in html
    assert "Provisional host and port observations" in html
    assert "Nmap has fully closed" in SHELL_SCRIPT
    assert 'class="live-discoveries-scroll"' in html
    assert "position:sticky;top:0" in html
    assert ".live-discoveries-scroll{min-height:0;flex:1 1 auto;overflow-y:auto;overflow-x:hidden" in html
    assert "background:var(--nct-surface-muted,var(--panel2,#0a1720))" in html
    assert "background:var(--nct-panel,var(--panel,#102632))" in html
    assert "box-shadow:0 2px 0 var(--nct-line,var(--line,#365268))" in html
    assert ".live-final-link{display:inline-flex;margin-top:8px;color:var(--nct-accent,var(--accent,#8be1d0))}" in html
    assert "/live-discoveries" in html
    assert "function renderLiveDiscoveries" in html
    assert "function renderLiveDiscoveryFinal" in html
    assert "The scan continues unchanged" in html
    assert "loadLiveDiscoveries(runId,revision)" in html
    assert "liveDiscoveryInFlight&&liveDiscoveryRunId===runId" in html
    assert "signal:controller.signal" in html


def test_active_scan_explains_active_targets_and_finalized_host_records():
    html = operator_page().body.decode()

    assert "Active is how many targets Nmap is working on now" in html
    assert "finalized of" in html
    assert "`${active} active; ${completed} finalized of ${total}" in html
    assert "The phase percentage can move while finalized stays at zero" in SHELL_SCRIPT


def test_active_scan_exposes_read_only_self_check_and_confirmed_resume():
    html = operator_page().body.decode()
    assert 'id="scanRecoveryPanel"' in html
    assert 'data-guide-context="scan-queue-self-check"' in html
    assert "Run unfinished work self-check" in html
    assert "The button above already ran the read-only self-check" in html
    assert "No terminal command or record change is required" in html
    assert "const hostRecoveryNeeded=" in html
    assert "loadScanRecovery(keepOpen=false)" in html
    assert "Boolean(keepOpen||pause||blockers.length||issues.length)" in html
    assert "$('checkScanRecovery').onclick=event=>{event.preventDefault();event.stopPropagation();return loadScanRecovery(true)}" in html
    assert "Resume preserved scans" in html
    assert "Resume passive pulls" in html
    assert "Resume device contact" in html
    assert "Resume local processing" in html
    assert "Resume storage maintenance" in html
    assert "/api/system/scan-work-recovery" in html
    assert "/api/system/scan-work-recovery/resume-passive" in html
    assert "create and independently verify a complete backup" in html
    assert "Select Run unfinished work self-check" in SHELL_SCRIPT
    assert "Resume local processing starts retained-data calculations without network contact" in SHELL_SCRIPT
    assert "Resume storage maintenance permits local inspection, backfill, and compaction" in SHELL_SCRIPT
    assert 'class="recovery-host-command"' in html
    assert "No per-item conflicts were found" in html
    assert "closest?.('#scanRecoveryPanel')" in SHELL_SCRIPT


def test_recursive_note_changes_preview_exact_scope_and_report_results():
    assert "/branch-preview`" in SESSION_SCRIPT
    assert "branch_revision:preview.branch_revision" in SESSION_SCRIPT
    assert "['Personal notes',...(preview.path||[preview.title])]" in SESSION_SCRIPT
    assert "Affected: ${scope}." in SESSION_SCRIPT
    assert "This cannot be undone. Download Markdown first if you need a copy." in SESSION_SCRIPT
    assert "setNoteMutationBusy(true)" in SESSION_SCRIPT
    assert "No sharing changes were made." in SESSION_SCRIPT
    assert "Nothing was deleted." in SESSION_SCRIPT
    assert "Deleted “${result.title||preview.title}”" in SESSION_SCRIPT
    assert "sharedImpact(preview)" in SESSION_SCRIPT
    assert "Refresh notes before continuing." in SESSION_SCRIPT
    assert "loadNotes(saved.note_id,true)" in SESSION_SCRIPT
    assert "loadNotes(null,true)" in SESSION_SCRIPT
    assert "completed on the server, but NCT could not refresh" in SESSION_SCRIPT
    assert "noteMutationPending||noteRefreshRequired" in SESSION_SCRIPT
    assert "role=\"status\" aria-live=\"polite\"" in SESSION_SCRIPT


def test_system_health_explains_bounded_calculation_status():
    html = storage_page().body.decode()
    assert "Kubernetes backup and recovery readiness" in html
    assert "Not verified on this installation" in html
    assert "Separate backup and empty restore targets" in html
    assert "The live source and backup are never overwritten" in html
    assert "Failure and replacement package" in html
    assert "Guarded upgrade and rollback package" in html
    assert "externally fenced node loss" in html
    assert "Node loss never triggers automatic failover" in html
    assert "Direct rollback is allowed only when the old image itself proves" in html
    assert "restoring the backup returns NCT to the recorded backup time" in html
    assert "Restore now" not in html
    assert "kubernetesRecoveryPanel:['Kubernetes backup, failure, upgrade, and rollback readiness'" in SHELL_SCRIPT
    assert "kubernetesRecoverySummary:['Administrator cold recovery instructions'" in SHELL_SCRIPT
    assert "kubernetesFailureSummary:['Failure and replacement instructions'" in SHELL_SCRIPT
    assert "kubernetesUpgradeSummary:['Guarded upgrade and rollback instructions'" in SHELL_SCRIPT
    assert 'id="kubernetesRecoverySummary"' in storage_page().body.decode()
    assert 'id="kubernetesFailureSummary"' in storage_page().body.decode()
    assert 'id="kubernetesUpgradeSummary"' in storage_page().body.decode()
    assert "sign-in, readiness, and one evidence download" in SHELL_SCRIPT
    guide = how_nct_works_page().body.decode()
    assert "Kubernetes cold recovery" in guide
    assert "protected file handles into a private snapshot" in guide
    assert "writes a receipt to the Kubernetes termination record" in guide
    assert "Kubernetes failure and replacement testing" in guide
    assert "earlier attempt as Interrupted and create exactly one new protected recovery attempt" in guide
    assert "proves the old node is fenced" in guide
    assert "Kubernetes guarded upgrade and rollback" in guide
    assert "old image's own contract" in guide
    assert "Live performance and reliability" in html
    assert "Unsupported measurements say Unavailable instead of showing zero" in html
    assert "Reading it does not start a scan, contact a network target, or change retained evidence" in html
    assert "Process and container measurements stay separate" in html
    assert 'aria-label="CPU use"' in html
    assert 'aria-label="Memory use"' in html
    assert html.count("<th>Current</th><th>Average</th><th>Maximum</th><th>Time near max</th>") == 2
    assert "/api/system/runtime-health" in html
    assert "document.visibilityState==='visible'&&runtimePanelVisible" in html
    assert "if(!runtimeCanPoll()||runtimeInFlight)return" in html
    assert "requestId!==runtimeRequestId||!runtimeCanPoll()" in html
    assert "runtimeController.abort()" in html
    assert "cache:'no-store'" in html
    assert "Live measurement refresh timed out" in html
    assert "last successful sample" in html
    assert "keeps no long-term telemetry" in html
    assert "'Live performance and reliability'" in SHELL_SCRIPT
    assert "Unavailable does not mean zero" in SHELL_SCRIPT
    assert "Optional Kubernetes status" in html
    assert "Kubernetes is not required for standalone NCT" in html
    assert "Deployment and pods" in html
    assert "Optional pod resource measurements" in html
    assert "Ready does not prove evidence freshness" in html
    assert "Unavailable — this cluster did not provide pod CPU or memory measurements" in html
    assert "kubernetesStatusPanel:['Optional Kubernetes status'" in SHELL_SCRIPT
    assert "kubernetesDeploymentGuide:['Deployment and pods'" in SHELL_SCRIPT
    assert "kubernetesMetricsGuide:['Optional pod resource measurements'" in SHELL_SCRIPT
    assert "kubernetesStatusMeaningSummary:['Kubernetes status terms'" in SHELL_SCRIPT
    assert "summary,[data-guide-context]" in SHELL_SCRIPT
    assert "[data-guide-context=\"safe-diagnostics\"]" in SHELL_SCRIPT
    assert "Diagnose without changing NCT" in SHELL_SCRIPT
    assert "does not stop, restart, reset, repair, migrate, or upload NCT" in SHELL_SCRIPT
    assert "bounded log signal counts" in SHELL_SCRIPT
    assert "Raw log text is excluded" in SHELL_SCRIPT
    assert "partial result appears only in the terminal" in SHELL_SCRIPT
    assert "Opening this disclosure only reveals help text" in SHELL_SCRIPT
    assert "never receives a Kubernetes API token" in guide
    assert "it never means zero Pods or a failed deployment" in guide
    assert "panel?actionGuideFor(panel):null" in SHELL_SCRIPT
    assert "Evidence intake status" in html
    assert "Processing is local and never starts a scan or contacts a device" in html
    assert "/api/system/ingestion-status?limit=${ingestionLimit}&offset=${requestedOffset}" in html
    assert "requestId!==ingestionRequestId" in html
    assert "in original history and" in html
    assert "not included in this processing view" in html
    assert "byId('ingestionNext').onclick" in html
    assert "Saved analysis work" in html
    assert "Waiting work stays saved" in html
    assert "earlier attempt remains Interrupted" in html
    assert "/api/system/analysis-jobs?limit=${jobLimit}&offset=${requestedOffset}" in html
    assert "Waiting, Processing, and Recovering use retained files only" in html
    assert "'saved analysis work':['Saved analysis work'" in SHELL_SCRIPT
    assert "Reusable analysis status" in html
    assert "does not mean the source evidence is recent, intact, or still true" in html
    assert "/api/system/analysis-status?limit=${analysisLimit}&offset=${requestedOffset}" in html
    assert "Showing ${start}-${end} of ${data.total} saved results" in html
    assert "item.reasons.join(' ')" in html
    assert "saved rule version identifies the exact analysis instructions" in html
    assert "requestId!==analysisRequestId" in html
    assert "analysisDisplayedOffset=data.offset" in html
    assert "analysisOffset=analysisDisplayedOffset+analysisLimit" in html
    assert "Inputs and source records" in html
    assert "Source records are provenance, not additional calculation steps" in html
    assert "It does not inspect source files, determine freshness, mark work stale, or rerun analysis" in html
    assert "button.textContent='View inputs'" in html
    assert "detailIdentifier(item.identity)" in html
    assert "textContent=item.source_kind" not in html
    assert "source.textContent=`${item.source_kind} · ${item.source_ref}`" in html
    assert "requestId!==dependencyRequestId" in html
    assert "requestId!==sourceRequestId" in html
    assert "requestId!==impactRequestId" in html
    assert "button.dataset.analysisInputs=''" in html
    assert "button.dataset.analysisSources=''" in html
    assert "impactButton.dataset.analysisImpact=''" in html
    assert "'view inputs':['View calculation inputs'" in SHELL_SCRIPT
    assert "'view source records':['View retained source records'" in SHELL_SCRIPT
    assert "'show calculations using this input':['Saved calculations using this input'" in SHELL_SCRIPT
    assert "direct recorded links only" in html
    assert "It does not change status, mark results stale, or rerun analysis" in html
    assert "Unsupported saved record · recorded role" in html
    assert "page_verified_relationship_count" in html
    assert "page_unsupported_candidate_count" in html
    assert "manifest_semantics:'Collection details'" in html
    assert "selection_shape:'Evidence file choices'" in html
    assert "Saved calculation versions" in html
    assert "not scans, evidence encounters, or jobs that need to run" in html
    assert "matching fingerprints mean the stored settings match exactly" in html
    assert "Show settings fingerprint" in html
    assert "/api/system/analysis-versions?limit=${versionLimit}&offset=${requestedOffset}" in html
    assert "representative_result_id=${encodeURIComponent(representative)}" in html
    assert "requestId!==versionRequestId" in html
    assert "requestId!==versionResultsRequestId" in html
    assert "button.dataset.analysisVersions=''" in html
    assert "These are page counts, not database-wide totals" in html
    assert "closeVersionResults();versionOffset" in html
    assert "function openVersionResults(item){closeDependencies();" in html
    assert "byId('versionResultRows').replaceChildren();byId('versionResultsPage').textContent='Loading exact saved results'" in html
    assert "'view saved results':['View results for this exact saved version'" in SHELL_SCRIPT
    assert "'show settings fingerprint':['Saved settings fingerprint'" in SHELL_SCRIPT
    assert "button,input,select,textarea,a,summary" in SHELL_SCRIPT
    assert "byId('dependencyRows').replaceChildren();byId('dependencyPage').textContent='Loading declared inputs'" in html
    assert "byId('dependencyPrevious').disabled=true;byId('dependencyNext').disabled=true" in html
    assert "byId('sourceRows').replaceChildren();byId('sourcePage').textContent='Loading retained source records'" in html
    assert "byId('sourcePrevious').disabled=true;byId('sourceNext').disabled=true" in html
    assert "byId('impactRows').replaceChildren();byId('impactPage').textContent='Loading saved calculation records'" in html
    assert "byId('impactPrevious').disabled=true;byId('impactNext').disabled=true" in html
    assert "document.body.classList.toggle(side==='personal'?'nct-notes-personal-open':'nct-notes-shared-open',open)" in SESSION_SCRIPT


def test_scan_history_offers_durable_local_saved_analysis_work():
    html = operator_page().body.decode()
    assert "Prepare from saved scan" in html
    assert "does not rerun Nmap or contact the network" in html
    assert "progress stays on this row" in html
    assert "Retry saved analysis" in html
    assert "Recovering after restart" in html
    assert "superseded worker cannot publish" in SHELL_SCRIPT
    assert "Review before retrying from retained scan.xml; a retry does not rescan" in html
    assert "/analysis-jobs`" in html
    assert "/retry`" in html
    assert "'prepare from saved scan':['Prepare from saved scan'" in SHELL_SCRIPT
    assert "Waiting work stays saved" in SHELL_SCRIPT
    assert "'retry saved analysis':['Retry saved analysis'" in SHELL_SCRIPT
    assert "function analysisRequestToken()" in html
    assert "Math.random().toString(36).slice(2)" in html
    assert "request_token:analysisRequestToken()" in html
    assert "Load 25 older scans for this network" in html
    assert "new URLSearchParams({limit:String(limit),offset:String(offset),sort:sortMode})" in html
    assert "params.set('snapshot',snapshot)" in html
    assert 'id="historySort"' in html
    assert "Alphabetical (default)" in html
    assert "Newest activity" in html
    assert "/runs?limit=25${suffix}" in html
    assert "Saved scope handoff needs correction" in html
    assert "data-scope-handoff-correct" in html
    assert "/scope-handoff-corrections" in html
    assert "The original failed decision remains in history" in html
    assert "Repair saved scope handoff" in SHELL_SCRIPT
    assert "does not choose or change a Network Scope" in SHELL_SCRIPT
    assert "cursor=${encodeURIComponent(group.next_cursor)}" in html
    assert "/api/scan-history-visible-runs?${params}" in html
    assert "history_also_covers:run.history_also_covers||[]" in html
    assert "!requested.has(run.run_id)||byId.has(run.run_id)" in html
    assert "revision!==historyRefreshRevision" in html
    assert "historyGroupWindow(group.group_id,loadedTargets.get(group.group_id)||25)" in html
    assert "historyCatalogWindow(catalogTarget,requestedSort)" in html
    assert "item.open=openGroups.has(id)" in html
    assert "Also covers:" in html


def test_theme_cards_and_navigation_icons_match_their_actions():
    assert "dialog.addEventListener('click',event=>{const card=event.target.closest?.('.nct-theme-card[data-preset]')" in SHELL_SCRIPT
    assert "compare:'M12 7v5l3 2 M4 5v5h5" in SHELL_SCRIPT
    assert "reach:'M4 7h13 M14 4l3 3-3 3 M20 17H7" in SHELL_SCRIPT


def test_fun_theme_catalog_includes_distinct_cthulhu_and_arkime_presets():
    assert "cthulhu_depths:{label:'Cthulhu',category:'Fun'" in SHELL_SCRIPT
    assert "arkime_sessions:{label:'Arkime',category:'Fun'" in SHELL_SCRIPT
    assert "html[data-nct-theme=cthulhu_depths] body.nct-shell>header" in SHELL_SCRIPT
    assert "html[data-nct-theme=arkime_sessions] body.nct-shell>header" in SHELL_SCRIPT
    assert 'html[data-nct-theme=arkime_sessions] body.nct-shell>header::after' in SHELL_SCRIPT
    assert "url('/assets/arkime-betrayed-owl.png') center/cover no-repeat" in SHELL_SCRIPT
    assert "Oh. So this is where you've been spending your packets." in SHELL_SCRIPT
    assert "input:-webkit-autofill" in SHELL_SCRIPT
    assert "-webkit-text-fill-color:var(--nct-text)" in SHELL_SCRIPT


def test_active_task_workspace_cannot_be_collapsed_from_its_page_header():
    assert "details.nct-active-task-panel>summary::-webkit-details-marker" in SHELL_SCRIPT
    assert "function setActiveTaskPanel(target)" in SHELL_SCRIPT
    assert "event.preventDefault();panel.open=true" in SHELL_SCRIPT
    assert "setActiveTaskPanel(target)" in SHELL_SCRIPT


def test_active_theme_controls_legacy_inner_surfaces_across_workspaces():
    assert "--nct-surface-subtle:color-mix(" in SHELL_SCRIPT
    for selector in (
        ".finding-summary-row th",
        ".finding-summary-row td",
        ".service-pair-transport",
        ".service-exposure-group",
        ".lfa-threshold-control",
        ".progress-track",
        ".os-review-state",
        ".change-card",
        ".category-card",
        ".reach-path-toggle",
        ".map-layout-completeness",
        ".delete-dialog",
        ".network-dialog",
        ".profile-manager",
        ".quick-links a",
        ".status-card",
        ".storage-card",
        ".truth-card",
        ".action-card",
        ".phase",
        ".callout",
        ".dataset-preview",
        ".contract",
    ):
        assert selector in SHELL_SCRIPT
    assert ":is(.finding-summary-row th,.finding-summary-row td,.service-pair-transport,.service-exposure-group,.progress-track,.os-review-state){background:var(--nct-surface-subtle)!important" in SHELL_SCRIPT
    assert ":is(.nav a,.source-links a,.reach-shortcut){background:var(--nct-control)!important" in SHELL_SCRIPT
    assert ":is(input,select,textarea,option,th){background:var(--nct-background)!important" in SHELL_SCRIPT
    assert ":is(input[type=checkbox],input[type=radio],input[type=range]){accent-color:var(--nct-accent)}" in SHELL_SCRIPT
    assert ":is(fieldset,.scenario-stage,.scenario-flow-context,.scenario-check,.ordered-rules){border-color:var(--nct-line)!important" in SHELL_SCRIPT
    assert "body.nct-shell main #batchSelectionCount{background:var(--nct-surface-raised)!important" in SHELL_SCRIPT
    assert "#nct-operator-guide :is(button,.button-link){background:var(--nct-control)!important" in SHELL_SCRIPT


def test_open_operator_guide_reflows_narrowed_workspaces():
    assert "@media(min-width:851px) and (max-width:1400px)" in SHELL_SCRIPT
    assert "body.nct-shell.nct-guide-open main :is(.grid,.cards,.methods,.collector-grid,.controls,.import-grid,.collection-upload" in SHELL_SCRIPT
    assert "body.nct-shell.nct-guide-open main .batch-network-choices{grid-template-columns:minmax(0,1fr)!important}" in SHELL_SCRIPT
    assert "body.nct-shell.nct-guide-open main :is(.batch-order-row,.batch-preview-row){grid-template-columns:36px minmax(0,1fr)!important" in SHELL_SCRIPT
    assert "body.nct-shell.nct-guide-open main :is(.batch-order-row,.batch-preview-row)>:nth-child(n+3){grid-column:2!important}" in SHELL_SCRIPT


def test_operator_guide_typography_stays_subordinate_and_readable():
    html = operator_page().body.decode()

    assert "#nct-operator-guide h3{margin:0 0 9px;font-size:16px;font-weight:700;line-height:1.35}" in SHELL_SCRIPT
    assert "#nct-operator-guide p{margin:0 0 14px;color:var(--nct-muted);font-size:13px;font-weight:400;line-height:1.55}" in SHELL_SCRIPT
    assert "['Selected queue order','Choose at least two Saved Networks" in SHELL_SCRIPT
    assert "<h3>Selected Queue Order</h3>" in html
    assert 'class="batch-row-label">Generated run name</span>' in html
    assert 'class="batch-run-name">${esc(generatedBatchName(item)' in html
    assert "target IPs after exclusions · ${Number(row.requested_address_count).toLocaleString()} requested" in html
    assert "saveDraft:['Save unfinished scan setup'" in SHELL_SCRIPT
    assert "A personal draft preserves preparation work" not in SHELL_SCRIPT
    assert '>Save unfinished setup</button>' in html
    assert "target IP count after exclusions, and original requested IP count before queueing" in SHELL_SCRIPT


def test_hunt_system_summary_rows_use_theme_palette_not_legacy_blue():
    html = hunting_page().body.decode()
    assert ".finding-summary-row :is(th,td){background:color-mix(in srgb,var(--panel) 68%,var(--bg))}" in html
    assert ".finding-summary-row td{background:#0c1922}" not in html
    assert html.count('data-nct-table-mode="contained"') == 2
    assert "body.nct-shell .table-wrap[data-nct-table-mode=contained]{max-height:none!important;overflow-x:auto!important;overflow-y:visible!important}" in SHELL_SCRIPT
    assert "body.nct-shell .table-wrap[data-nct-table-mode=contained]>table>thead>tr>th{position:static!important;top:auto!important;z-index:auto}" in SHELL_SCRIPT


def test_nmap_analysis_distinguishes_confirmed_hosts_from_pn_assumptions():
    analyze = analysis_page().body.decode()
    scans = operator_page().body.decode()

    assert "confirmed responsive" in analyze
    assert "targets attempted" in analyze
    assert "assumed reachable by -Pn; no direct response" in analyze
    assert "function presenceExplanation(host)" in analyze
    assert "this status alone is not proof that the host responded" in analyze
    assert "Presence explanation" in analyze
    assert "Import and investigate Nmap evidence" in analyze
    assert "Import and open this result" in analyze
    assert "opens this exact result for review below" in analyze
    assert "await loadNmapAssignments(data.artifact_observation_id);$('analysisPanel').scrollIntoView" in analyze
    assert "No target returned direct response evidence in this scan." in analyze
    assert "confirmed responsive hosts" in scans
    assert "run.nmap_assumed_host_count" in scans
    assert "assumed reachable by -Pn · no direct response" in scans
    assert "Open Analyze to verify direct responses" in scans


def test_operator_guide_describes_current_button_behavior_and_side_effects():
    assert "const actionGuideHints=" in SHELL_SCRIPT
    assert "function actionGuideFor(control)" in SHELL_SCRIPT
    assert "guideKey=control?.dataset?.guideKey" in SHELL_SCRIPT
    assert "page[guideKey]||page[control?.id]" in SHELL_SCRIPT
    assert "[data-latest-observations]" in SHELL_SCRIPT
    assert "last confirmed positive observation, with direct evidence links" in SHELL_SCRIPT
    assert "This is not a live check or an exact Last Seen time" in SHELL_SCRIPT
    assert "[data-mac-associations]" in SHELL_SCRIPT
    assert "Review retained IP associations for a reported MAC" in SHELL_SCRIPT
    assert "possible address reuse or a DHCP-related hypothesis" in SHELL_SCRIPT
    assert "does not merge addresses into one device, prove DHCP movement" in SHELL_SCRIPT
    assert "Opening the view sends no traffic and changes no evidence" in SHELL_SCRIPT
    assert "[data-device-scope-assignment]" in SHELL_SCRIPT
    assert "creates traceable interface-address receipts" in SHELL_SCRIPT
    assert "[data-device-scope-receipts]" in SHELL_SCRIPT
    assert "configuration statements, not live checks or exact Last Seen times" in SHELL_SCRIPT
    assert "running and startup configuration each report it" in SHELL_SCRIPT
    assert "Builds and downloads a certified ZIP" in SHELL_SCRIPT
    assert "It does not run Nmap or add evidence to NCT" in SHELL_SCRIPT
    assert "import the completed XML files" in SHELL_SCRIPT
    assert "submits the scan to the local analyzer queue" in SHELL_SCRIPT
    assert "This resumes network activity" in SHELL_SCRIPT
    assert "Starts the accountability capture, connects to the selected device" in SHELL_SCRIPT
    assert "It does not contact the device or start an accountability capture" in SHELL_SCRIPT
    assert "It sends no packets and changes no device" in SHELL_SCRIPT
    assert "It changes no device and sends no traffic" in SHELL_SCRIPT
    assert "This is destructive" in SHELL_SCRIPT
    assert "The action is not complete until the page reports success" in SHELL_SCRIPT
    assert "Export scan report" in SHELL_SCRIPT
    assert "currently open scan analysis and its active host filters" in SHELL_SCRIPT
    assert "Generate Package downloads a protected portable bundle" in SHELL_SCRIPT
    assert "Waiting scans stay in the separate Pending Scans dropdown" in SHELL_SCRIPT
    assert "Reviewing a waiting scan does not replace or change the active scan" in SHELL_SCRIPT
    assert "Opens or closes the waiting-scan list" in SHELL_SCRIPT
    assert "Shows the saved target, profile version" in SHELL_SCRIPT
    assert "Removes this waiting scan before it begins network activity" in SHELL_SCRIPT
    assert "Retained scans for this subnet" in SHELL_SCRIPT
    assert "Prepare this saved scan for Analyze" in SHELL_SCRIPT
    assert "Maximum peer-group frequency" in SHELL_SCRIPT
    assert "Lower percentages show only rarer ports" in SHELL_SCRIPT
    assert "Filter current evidence" in SHELL_SCRIPT
    assert "Current Network subnet" in SHELL_SCRIPT
    assert "Host Inventory rows per page" in SHELL_SCRIPT
    assert "Organize the current inventory" in SHELL_SCRIPT


def test_device_receipt_view_finishes_loading_and_explains_missing_addresses():
    html = device_config_page().body.decode()
    assert "same address can appear more than once" in html
    assert "each row keeps its own source line" in html
    assert "An address missing here is not proof that it was removed." in html
    assert "Refresh scoped address receipts" in html
    assert "approve the Nmap fallback, finish without Nmap, or cancel the run" in SHELL_SCRIPT
    assert "reports assumed targets separately from confirmed responsive hosts" in SHELL_SCRIPT
    assert "A held run also prevents maintenance or an upgrade from starting" in SHELL_SCRIPT
    assert "Start by choosing what the rule protects" in SHELL_SCRIPT
    assert "no route step is used" in SHELL_SCRIPT
    assert "Forwarded traffic uses the route-and-forward-policy workflow" in SHELL_SCRIPT
    assert "An earlier matching rule can decide the traffic first" in SHELL_SCRIPT
    assert "Validation uses the written rule" in SHELL_SCRIPT
    assert 'id="nct-guide-pin"' in SHELL_SCRIPT
    assert "guidePinned||guide.contains(event.target)" in SHELL_SCRIPT
    assert "guidePinned?'Follow hover · Alt+P':'Pin · Alt+P'" in SHELL_SCRIPT
    assert "if(!guidePinned)guideContextTarget=null" in SHELL_SCRIPT
    assert "if(!guidePinned){guideContextTarget=null;showTask(currentTask());}" in SHELL_SCRIPT
    assert "storedGuidePreference===null||storedGuidePreference==='1'" in SHELL_SCRIPT
    assert "hasOwnProperty.call(snapshot,'guide_enabled'))setGuideEnabled" in SHELL_SCRIPT
    assert '<summary>Using this guide</summary>' in SHELL_SCRIPT
    assert '<strong>How to use this</strong>' in SHELL_SCRIPT
    assert '<strong>How NCT uses this</strong>' in SHELL_SCRIPT
    assert '<strong>Limits</strong>' in SHELL_SCRIPT
    assert 'id="nct-guide-data-use"' in SHELL_SCRIPT
    assert 'Why this matters' not in SHELL_SCRIPT
    assert 'function guideDataUseFor(stage=0)' in SHELL_SCRIPT
    assert 'where that information goes next' in SHELL_SCRIPT
    assert 'Individual retained Arkime session receipts can contribute' in SHELL_SCRIPT
    assert 'Aggregate summary groups remain separate' in SHELL_SCRIPT
    assert "Remove verified duplicate copies" in SHELL_SCRIPT
    assert "Recovery records protect interrupted replacements" in SHELL_SCRIPT
    assert 'id="nct-guide-name" tabindex="0"' in SHELL_SCRIPT
    assert 'temporary overlay when you hover over or focus the exact words Operator Guide' in SHELL_SCRIPT
    assert '#nct-guide-help:not([open]){display:none}' in SHELL_SCRIPT
    assert '#nct-guide-help{position:absolute' in SHELL_SCRIPT
    assert 'do not take space from the current topic' in SHELL_SCRIPT
    assert "guideName.addEventListener('mouseenter',showGuideHelpTemporarily)" in SHELL_SCRIPT
    assert "guide.addEventListener('mouseleave',closeTransientGuideHelp)" in SHELL_SCRIPT
    assert 'Enable Operator Guide or Disable Operator Guide' in SHELL_SCRIPT
    assert 'The Guide tab stays halfway down the right edge' in SHELL_SCRIPT
    assert 'Hold Shift for larger keyboard steps' in SHELL_SCRIPT
    assert 'use the scroll bar inside this pane' in SHELL_SCRIPT
    assert 'aria-keyshortcuts="Alt+P"' in SHELL_SCRIPT
    assert "event.key.toLowerCase()!=='p'" in SHELL_SCRIPT
    assert 'id="nct-guide-shortcut"' in SHELL_SCRIPT
    assert "getAttribute?.('aria-keyshortcuts')" in SHELL_SCRIPT
    assert "showGuideShortcut(control)" in SHELL_SCRIPT
    assert ".nct-guide-pinned-target{outline:3px solid" in SHELL_SCRIPT
    assert "pinnedGuideTarget.classList.add('nct-guide-pinned-target')" in SHELL_SCRIPT
    assert "guide.classList.toggle('nct-guide-pinned',guidePinned)" in SHELL_SCRIPT
    assert "body.nct-shell>header{position:sticky!important;top:0!important" in SHELL_SCRIPT
    assert "Waiting scans survive an NCT restart" in SHELL_SCRIPT
    assert "the occurrence becomes Interrupted — Needs attention" in SHELL_SCRIPT
    assert "former scanner or capture process stopped" in SHELL_SCRIPT
    assert "Collection and saved-analysis states remain separate" in SHELL_SCRIPT


def test_network_scope_page_and_guide_explain_operator_decisions_and_limits():
    html = network_scope_page().body.decode()
    assert "guest and office networks, lab and production" in html
    assert "A new scan by itself does not require a new scope" in html
    assert "scope → named subnet → CIDR → IP address" in html
    assert "Development Servers" in html and "10.50.15.0/24" in html
    assert "one exact manual Nmap upload from Analyze" in html
    assert "A Saved Network may also retain an optional reusable scope association" in html
    assert "Every new collection freezes that explicit active scope" in html
    assert "Older retained evidence remains unchanged and may remain unscoped" in html
    assert "cannot currently be undone" in html
    assert "[hidden]{display:none!important}" in html
    assert "$('save').disabled=false" in html
    assert "if(!selected){reset();return}" in html
    assert "'Reason for change'" in SHELL_SCRIPT
    assert "'Show archived scopes'" in SHELL_SCRIPT
    assert "'Manage network scope'" in SHELL_SCRIPT
    assert "Analysts can select an active scope from Saved Networks for future scans" in SHELL_SCRIPT
    assert "AFB Dev can contain Development Servers at 10.50.15.0/24" in SHELL_SCRIPT
    assert "Reusable Network Scope association" in SHELL_SCRIPT


def test_air_gapped_designation_uses_active_theme_palette():
    html = device_config_page().body.decode()
    assert ".air-gap-designation{display:grid" in html
    assert "border:1px solid var(--line)" in html
    assert "background:color-mix(in srgb,var(--panel) 84%,var(--bg) 16%)" in html
    assert ".air-gap-designation:has(input:checked){border-color:var(--accent)" in html
    assert "box-shadow:inset 3px 0 var(--accent)" in html


def test_scan_builder_is_one_page_with_requested_actions():
    html = operator_page().body.decode()
    assert '<nav class="nav"' not in html
    assert 'aria-label="Primary"' not in html
    assert '<script src="/assets/nct-session.js"></script>' in html
    assert "All scan activity originates from the NCT analyzer host" not in html
    assert 'id="trafficOriginValue"' not in html
    assert "updateTrafficOrigin" not in html
    assert 'id="origin"' not in html
    assert "originating_host:location.hostname" in html
    assert 'id="reason"' not in html
    assert "NCT network characterization initiated through the scan workspace" in html
    assert 'id="operator"' not in html
    assert 'id="savedNetworkOperator"' not in html
    assert 'id="noStrikeOperator"' not in html
    assert "function saveScanArtifact(event)" in html
    assert "fetch(url,{credentials:'same-origin'})" in html
    assert "response.blob()" in html
    assert "function historicalTargetDisplay(run)" in html
    assert "function consolidateCompletedHostTargets(values)" in html
    assert "individual host targets were executed and remain retained" in html
    assert 'id="fallbackApprover"' not in html
    assert "function auditActor()" in html
    assert html.index("Build scan") < html.index("Scan history")
    assert "Save as profile" in html
    assert "Run now" in html
    assert "Generate package" in html
    assert "TCP + UDP" in html
    assert "ICS / OT" in html
    assert "Protocol and port scope explanation" in html
    assert '<details id="scopeDetailsPanel" class="scope-details span-12">' in html
    assert "102,502,789,1911,1962,2404" in html
    assert "FPING pre-scan" in html
    assert '<option value="fping" selected>FPING pre-scan</option>' in html
    assert 'id="fpingNote" class="hint"' in html
    assert "$('fpingNote').classList.toggle('hidden',!useFping)" in html
    assert "NCT does not guess when more than one interface is available" in html
    assert '<option value="">Choose an analyzer interface</option>' in html
    assert "interfaces.map(i=>" in html
    assert "Collect traceroute paths" in html
    assert "normalizeCombinedScopes" not in html
    assert 'id="fallbackApproval"' in html
    assert html.index('id="currentRunPanel"') < html.index('id="fallbackApproval"')
    assert html.index('id="fallbackApproval"') < html.index("<h2>Profile behavior</h2>")
    assert 'id="fallbackReason"' in html
    assert "run.fallback_reason" in html
    assert "openScanTask('#queuePanel')" in html
    assert "Full Nmap fallback requires approval" in html
    assert "Authorize full Nmap fallback" in html
    assert "Finish without Nmap" in html
    assert "fallback-decision" in html
    assert "awaiting_fallback_approval" in html
    assert "exact_fallback_command" in html
    assert 'id="fallbackNote" maxlength="500" required' in html
    assert 'id="fallbackDecisionStatus" class="status" role="status" aria-live="assertive"' in html
    assert "Enter the required approval or mission-constraint note before choosing either action." in html
    assert "note.focus();note.reportValidity()" in html
    assert "Recording approval and preparing the full Nmap fallback" in html
    assert "Delete custom profile" in html
    assert 'id="profileStatus" class="status" role="status" aria-live="polite"' in html
    assert "request_token:receipt.token" in html
    assert "expected_version:source.version" in html
    assert "Checking this custom profile for saved schedule dependencies" in html
    assert "Change or delete these saved schedules first" in html
    assert "$('profileScheduleLink').onclick=()=>{location.href='/scans#scheduledScansPanel'}" in html
    assert "Scheduled scans" in html
    assert "Use selected profile" in html
    assert "Addresses per chunk" in html
    assert "Use chunked scan strategy" in html
    assert 'id="chunkSizeBox" class="span-3 hidden"' in html
    assert 'id="scheduleChunkDelayBox" class="span-4 hidden"' in html
    assert "chunking_enabled" in html
    assert "showChunkingOptions" in html
    assert "size===256" in html
    assert "One new unchunked occurrence saved" in html
    assert "Pause between chunks (seconds)" in html
    assert "Custom hours" in html
    assert '<option value="monthly">Monthly</option>' in html
    assert "Hours between scans" in html
    assert "Every few minutes" not in html
    assert "cadence_hours" in html
    assert "Repeated delays — review schedule" in html
    assert "Delayed — scanner busy" in html
    assert "Review occurrences" in html
    assert "occurrences.map" in html
    assert "Getting ready to scan" in html
    assert "Network contact has not started yet" in html
    assert "Started automatically" in html
    assert "Started manually" in html
    assert "Active collection is disabled in this deployment" in html
    assert "On a collection-enabled NCT" in SHELL_SCRIPT
    assert "instead of a backlog" in html
    assert "Technical identity" in html
    assert "conflict_flagged" in html
    assert "Owner / audit" in html
    assert "recorded change" in html
    assert "latest_occurrence" in html
    assert "chunk_delay_seconds" in html
    assert "Chunks never overlap" in html
    assert 'id="currentProgress"' in html
    assert 'id="currentRunPanel"' in html
    assert 'id="activeScanProgressMeaning" data-guide-context tabindex="0"' in html
    assert "A restart can lose only the last few seconds shown here" in html
    assert "activeScanProgressMeaning:['How live scan progress is saved'" in SHELL_SCRIPT
    assert 'id="pendingScansPanel"' in html
    assert "Waiting scans run in order after the active scan" in html
    assert "Cancel pending scan" in html
    assert "Assigned operator:" in html
    assert "Original requestor:" in html
    assert 'data-guide-context="queue-assignment"' in html
    assert "Save assignment" in html
    assert "It does not rename, reorder, start, or change scan settings." in html
    assert "@media(max-width:1200px){.queue-detail{grid-template-columns:1fr}" in html
    assert ".queue-assignment{width:min(100%,260px)}" in html
    assert "expected_assignment_revision:expectedRevision" in html
    assert "The assignment was not saved." in html
    assert "if(error.status===409){queueAssignmentConflictHold=true;queueLoadRevision+=1;clearTimeout(queueTimer);queueTimer=null}" in html
    assert "queueAssignmentConflictHold=false;queueAssignmentFeedback.clear();return Promise.all([loadQueue(),loadScanRecovery()])" in html
    assert "if(!activeScanWorkspace()||queueAssignmentConflictHold)return" in html
    assert "Assigned operator saved as ${data.owner}. Scan name, queue position, targets, settings, authorization, and original requestor are unchanged." in html
    assert "Assign responsibility for one waiting scan" in SHELL_SCRIPT
    assert "reload Active Scans, reopen the same scan" in SHELL_SCRIPT
    assert "waiting=runs.filter(run=>run.status==='queued')" in html
    assert "active=runs.find(run=>['dispatching','running','awaiting_fallback_approval'].includes(run.status))" in html
    assert "openWaiting=new Set" in html
    assert "item.open=openWaiting.has(item.dataset.queueRun)" in html
    assert "Waiting scans are shown below and will start in queue order." in html
    assert "retained waiting scan${waiting.length===1?'':'s'} will not start here" in html
    assert "Retained waiting scans cannot start in this analysis-only deployment" in html
    assert "function showActiveEmpty" in html
    assert "currentLive=false" in html
    assert "currentLive=['dispatching','running','awaiting_fallback_approval'].includes(state)" in html
    assert "currentLive=['queued','running','awaiting_fallback_approval'].includes(state)" not in html
    assert 'role="progressbar"' in html
    assert 'id="currentHostsLabel">confirmed responsive hosts' in html
    assert "addresses in scope" in html
    assert "scan targets completed" in html
    assert "targets currently being scanned" in html
    assert "Broad reset responses can cause this" in html
    assert "FPING discovery" in html
    assert "Nmap discovery" in html
    assert "TCP scan" in html
    assert "UDP scan" in html
    assert "Merging results" in html
    assert "Preparing analysis" in html
    assert "completed · partial" in html
    assert "batch_hosts_completed" in html
    assert 'class="delete-modal hidden"' in html
    assert 'role="dialog"' in html
    assert 'id="deleteStatus"' in html
    assert "Enter the confirmation string shown above" in html
    assert "Built-in profile protected" in html
    assert 'id="noStrikePanel"' not in html
    assert "Add to global No-Strike list" not in html
    assert 'href="/settings/mission-environment#missionScopePanel">Mission Environment</a>' in html
    assert "optional exclusions below apply only to this scan or schedule" in html
    assert "safety summary below counts their effect" in html
    assert "changed_by:auditActor()" in html
    assert "/api/safety/scan-summary" in html
    assert "Pre-launch scope &amp; safety check" in html
    assert "sessionAnalyst.role==='admin'&&data.authentication_enabled" in html
    assert 'id="safetyEffective"' in html
    assert "Preview is advisory; NCT rechecks before active contact" in html
    assert "Pause and require operator approval before Nmap" in html
    assert "Estimated time left in this phase" in html
    assert "Timeout limit in" in html
    assert "Estimated time left in this phase applies only to the active discovery, TCP, or UDP phase" in SHELL_SCRIPT
    assert 'for="timeout">Run timeout (minutes)' in html
    assert 'id="timeout" type="number" min="1" max="60" step="1" value="45"' in html
    assert "You can stop the scan at any time from Current run" in html
    assert "timeout_seconds:timeoutSeconds()" in html
    assert "Live update" in html
    assert 'id="currentRunHeading"' in html
    assert "$('currentRunHeading').textContent='Active scan'" in html
    assert "async function loadActiveRun()" in html
    assert "/api/scan-runs/queue/status" in html
    assert "queueLoadRevision=0,activeViewRevision=0,activeStatusRequestRevision=0,activeStatusAppliedRevision=0" in html
    assert "function claimActiveStatus(revision)" in html
    assert "ownsActiveStatus=claimActiveStatus(statusRevision)" in html
    assert "function startActiveView(run)" in html
    assert "data-history-detail" in html
    assert "loadActiveRun()" in html
    assert "exact_execution_command" in html
    assert 'id="savedNetworkPanel"' in html
    assert 'id="savedNetworkManageSelect"' in html
    assert 'id="savedNetworkSelect"' in html
    assert "Manage Saved Networks" in html
    assert "Add from device configurations" in html
    assert "/api/device-configs/network-candidates" in html
    assert "candidateSavedName" in html
    assert "name:candidateSavedName(item)" in html
    assert 'id="scopeMode"' in html
    assert "Enter an IP or range manually" in html
    assert "Combine saved and manual targets" in html
    assert "manual_targets" in html
    assert "saved_network_ids" in html
    assert "selectedSavedNetworkIds" in html
    assert "/api/saved-networks" in html
    assert "/api/scan-runs-grouped?limit=25&offset=0" in html
    assert "Load more groups in this order" in html
    assert "Load next groups by ${orderLabel}" in html
    assert "Every retained scan stays inside the stable dropdown for its exact recorded subnet" in html
    assert "Status / historical run name" in html
    assert "Executed target / recorded context" in html
    assert "Saved Network at scan time" in html
    assert "Network Scope at scan time" in html
    assert "Review network context" in html
    assert "Review retained network context" in html
    assert "historical run name will not be copied" in html
    assert "renameAndAttributeNetwork" not in html
    assert "networkAttributionRename" not in html
    assert "ensureScanData('saved-networks',loadSavedNetworks)" in html
    assert "editingSavedNetworkRevision={updated_at:item.updated_at" in html
    assert "const editorRevision=editingSavedNetworkRevision" in html
    assert "expected_updated_at:existing?.updated_at" not in html
    assert "Your draft was not applied. Select Edit selected again" in html
    assert 'id="scan-history-responsive-rows"' in html
    assert "@container (max-width:900px)" in html
    assert "Executed target / recorded context'" in html
    assert 'class="history-group"' in html
    assert "localeCompare(NCTScanReference.humanize(b.name||'')" not in html
    assert "const groups=[...historyGroups],orderLabel=" in html
    assert "function newestFirst(runs)" in html
    assert 'data-compare="' in html
    assert "candidateSavedName" in html
    assert "name:candidateSavedName(item)" in html
    assert "Remove selected" in html
    assert "/api/scan-schedules/" in html
    assert ".join('\n')" not in html
    assert r".join('\n')" in html


def test_operator_guides_explain_no_strike_timing_and_static_packages():
    from app.collection_safety_setup_ui import collection_safety_setup_page
    from app.how_nct_works_ui import how_nct_works_page

    readme = how_nct_works_page().body.decode()
    setup = collection_safety_setup_page().body.decode()
    assert "How No-Strike safety is applied" in readme
    assert "TCP, UDP, and an approved full-target fallback are separately rechecked" in readme
    assert "A downloaded package is a static snapshot" in readme
    assert "Broad networks such as <code>10.0.0.0/8</code> are supported" in readme
    assert "requests cancellation promptly" in readme
    assert "original list of target batches" in readme
    assert "A software rollback can still read the current exclusions" in readme
    html = operator_page().body.decode()
    assert "Add to global No-Strike list" not in html
    assert "role:'admin',local:true" in html
    assert "Broad CIDRs are supported, including <code>10.0.0.0/8</code>" in setup
    assert "pre-launch count is advisory" in readme


def test_scan_queue_polling_stops_when_the_session_is_rejected():
    html = operator_page().body.decode()

    assert "response.status===401||response.status===403" in html
    assert "queueTimer=keepPolling&&activeScanWorkspace()?setTimeout(loadQueue,2000):null" in html
    assert "Sign in again to resume queue updates." in html


def test_manual_nmap_admission_polling_stops_after_a_visible_storage_pause():
    html = analysis_page().body.decode()

    assert html.count("function pipelineRequestToken()") == 1
    assert "function assignmentAdmissionActive(intake)" in html
    assert "['waiting','retrying'].includes(intake.activity_state)" in html
    assert "Automatic processing paused" in html
    assert "Automatic processing retrying" in html


def test_enterprise_shell_replaces_legacy_navigation_on_every_primary_page():
    pages = [operator_page(), analysis_page(), device_analysis_page(), hunting_page(), device_config_page(), hostname_page(), reachability_page(), network_map_page()]
    for page in pages:
        html = page.body.decode()
        assert '<div class="nct-brand" aria-label="NCT, Network Characterization Tool"><strong>NCT</strong><span><b>N</b>etwork <b>C</b>haracterization <b>T</b>ool</span></div>' in html
        assert '<script src="/assets/nct-session.js"></script>' in html
        assert '<nav class="nav"' not in html
        assert 'aria-label="Primary"' not in html
        assert 'class="analysis-tabs"' not in html

    assert "#nct-sidebar{position:fixed" in SHELL_SCRIPT
    assert "#nct-sidebar .nct-nav-group>summary::before{content:none!important;display:none!important}" in SHELL_SCRIPT
    assert "#nct-sidebar .nct-nav-group>summary::after{content:'›'" in SHELL_SCRIPT
    assert "body.nct-shell #nct-sidebar{background-color:var(--nct-sidebar)!important;background-image:none!important" in SHELL_SCRIPT
    assert "backdrop-filter:none!important;border-image:none!important" in SHELL_SCRIPT
    assert "#nct-sidebar-edge{position:fixed;left:var(--nct-sidebar-width);top:var(--nct-header-height);width:32px;height:58px" in SHELL_SCRIPT
    assert "#nct-sidebar-edge button{position:absolute;top:10px" in SHELL_SCRIPT
    assert "opacity:1;transform:none" in SHELL_SCRIPT
    assert "{label:'Workspace'" not in SHELL_SCRIPT
    assert "href:'#nct-personal-notes'" not in SHELL_SCRIPT
    assert "html[data-nct-scanlines=on] body.nct-shell::after{position:fixed;inset:0 0 0 var(--nct-sidebar-width)" in SHELL_SCRIPT
    assert "window.NCTOpenTask=openTask" in SHELL_SCRIPT
    assert "const syncTaskScroll=" in SHELL_SCRIPT
    assert "target.scrollIntoView({block:'start'})" in SHELL_SCRIPT
    assert "const resetTaskScroll=" not in SHELL_SCRIPT
    assert "'/arkime':{candidates:'#arkimeCoverageWindows,#arkimeTrafficAnalysis,#arkimeCommunicationHistory,#arkimeSummaryUpload,#arkimeSummaryHistory,#arkimeConnector,#arkimeUpload,#arkimeHistory',support:{arkimeConnector:['arkimeUpload','arkimeHistory']}}" in SHELL_SCRIPT
    assert 'padding-bottom:30px' in SESSION_SCRIPT
    assert 'bottom:9px' in SESSION_SCRIPT


def test_scan_workflow_is_grouped_under_scan_details_navigation():
    collect_group = SHELL_SCRIPT.split("{label:'Collect'", 1)[1].split("{label:'Identify'", 1)[0]

    assert "{title:'Nmap scans',icon:'scan'" in collect_group
    assert "href:'/settings/scope-safety',title:'Scope & Safety Setup'" not in collect_group
    assert "{title:'Mission Environment',icon:'mission'" in SHELL_SCRIPT
    assert "mission:'M12 2a10 10" in SHELL_SCRIPT
    assert "href:'/settings/mission-environment#missionScopePanel',title:'Network Scope'" in SHELL_SCRIPT
    assert "href:'/settings/mission-environment#noStrikePanel',title:'No-Strike'" in SHELL_SCRIPT
    assert "href:'/settings/mission-environment#coveragePanel'" not in SHELL_SCRIPT
    assert "support:{toolPanel:['coveragePanel']}" in SHELL_SCRIPT
    assert 'id="nct-mission-environment-link"' not in SHELL_SCRIPT
    assert "sidebar.append(missionSection)" in SHELL_SCRIPT
    assert SHELL_SCRIPT.index("sidebar.append(missionSection)") < SHELL_SCRIPT.index("for(const group of groups)")
    assert "{title:'Scan Details',description:" in collect_group
    assert "Saved target boundaries and reusable scan profiles" in collect_group
    grouped_tasks = [
        "Saved Networks",
        "Scan profiles",
    ]
    positions = [collect_group.index(f"title:'{title}'") for title in grouped_tasks]
    assert positions == sorted(positions)
    scan_details = collect_group.split("{title:'Scan Details'", 1)[1].split("{href:'/analysis#xmlImport'", 1)[0]
    assert all(f"title:'{title}'" in scan_details for title in grouped_tasks)
    assert "No-Strike exclusions" not in scan_details
    for title in ["New scan", "Active scans", "Schedules", "Scan history"]:
        assert f"title:'{title}'" not in scan_details.split("]},", 1)[0]
        assert f"title:'{title}'" in collect_group
    assert "Import Nmap evidence" not in scan_details
    assert "detail.open=false" in SHELL_SCRIPT
    assert "function appendNavItem" in SHELL_SCRIPT
    assert "while(ancestor&&ancestor!==sidebar)" in SHELL_SCRIPT
    assert "ancestor.open=true" in SHELL_SCRIPT
    assert "link?.setAttribute('aria-current','page')" in SHELL_SCRIPT
    assert "summary.title=item.planned?`${itemLabel} — planned`:(item.description||itemLabel)" in SHELL_SCRIPT


def test_mission_environment_unifies_safety_tools_and_network_level_visibility():
    from app.mission_environment_ui import mission_environment_page

    html = mission_environment_page().body.decode()
    assert html.index('id="missionScopePanel"') < html.index('id="noStrikePanel"') < html.index('id="toolPanel"')
    assert 'id="scopeIdentityForm"' in html
    assert 'id="scopeIdentityList"' in html
    assert 'id="noStrikeScopeContext"' in html
    assert "updateNoStrikeScopeContext()" in html
    assert 'href="/settings/network-scopes"' not in html
    assert 'id="refreshRoleEvidence"' in html
    assert "Ready to add another address" in html
    assert "already has this active role in the selected scope" in html
    assert html.index('id="toolPanel"') < html.index('id="observedCoveragePanel"')
    assert "Active Network Scope" in html
    assert "Global No-Strike" in html
    assert "10.0.0.0/8" in html
    assert "Saved Network" in html
    assert "CIDR range" in html
    assert "Possible matches shown by evidence" in html
    assert "Mission Partner Identified IPs" in html
    assert "Reported addresses" in html
    assert "Mission Partner Identified" in html
    assert "primary, alternate, and backup IP addresses" in html
    assert 'id="roleCatalog" class="role-catalog" open' in html
    assert "Common network and server roles" in html
    assert "Choose a role to start a draft" in html
    assert "does not save, validate, or assign a role" in html
    assert "Typical ports are examples only" in html
    assert "Use this role" in html
    assert "Draft only — not saved" in html
    assert "Saved role declarations and evidence comparison" in html
    assert "Possible matches in retained evidence" in html
    assert "supporting_sources" in html
    assert "Open exact retained source" in html
    assert "source time unavailable" in html
    assert "Scope:" in html
    assert "Other mission-specific role" in html
    assert html.count('id="roleScope"') == 1
    draft_function = html.split("function startRoleDraft", 1)[1].split("function resetRoleForm", 1)[0]
    assert "api(" not in draft_function
    assert "roleAddresses')).focus()" in draft_function
    assert "roleCatalog').open=true" in html
    assert "roleCatalogGrid" in html and "aria-live=\"polite\"" in html
    assert "textContent='Clear draft'" in html
    assert "textContent='Cancel edit'" in html
    assert html.index('id="observedCoveragePanel"') < html.index('id="specialDeviceRolesPanel"')
    assert html.index('id="specialDeviceRolesPanel"') < html.index('id="coveragePanel"')
    assert "Network devices" in html
    assert "Individual IPs contribute to counts but do not become rows" in html
    assert "has no authorization effect" in html
    assert 'data-nct-table-mode="contained"' in html
    assert "No blind spots recorded':'Not reviewed" in html
    assert "Catalog matches are investigation leads with exact retained sources" in SHELL_SCRIPT
    assert "Roles without a reliable generic signal remain declaration-only" in SHELL_SCRIPT


def test_cross_task_actions_reveal_their_destination_in_the_new_shell():
    scan_html = operator_page().body.decode()
    device_html = device_config_page().body.decode()
    analysis_html = analysis_page().body.decode()
    reach_html = reachability_page().body.decode()

    assert "openScanTask('#queuePanel')" in scan_html
    assert "openScanTask('#scanBuilder')" in scan_html
    assert "openScanTask('#savedNetworkPanel')" in scan_html
    assert "window.NCTOpenTask('#wanDesignationPanel')" in device_html
    assert "preparedComparisonDeepLink!==compareRunId&&prepareRunComparison(compareRunId)" in analysis_html
    assert "function prepareRunComparison(runId)" in analysis_html
    assert "NCTOpenTask('#networkChangesPanel')" not in analysis_html
    assert "window.NCTOpenTask('#changeScenarioPanel')" in reach_html
    assert "support:{xmlImport:['analysisPanel']}" in SHELL_SCRIPT
    assert 'id="deviceOverviewSection"' in device_analysis_page().body.decode()
    assert "deviceEvidencePicker:['deviceOverviewSection']" in SHELL_SCRIPT


def test_enterprise_shell_hides_legacy_layout_before_first_paint():
    pages = [
        operator_page(),
        device_config_page(),
        hostname_page(),
        analysis_page(),
        device_analysis_page(),
        hunting_page(),
        reachability_page(),
        network_map_page(),
    ]

    for page in pages:
        html = page.body.decode()
        assert '<html class="nct-shell-loading" lang="en">' in html
        assert 'id="nct-shell-bootstrap"' in html
        assert "html.nct-shell-loading body{visibility:hidden}" in html
        assert html.index('id="nct-shell-bootstrap"') < html.index('<script src="/assets/nct-session.js"')


def test_scan_workflow_pages_share_human_readable_scan_references():
    for page in (operator_page(), analysis_page(), hunting_page()):
        html = page.body.decode()
        assert '<script src="/assets/nct-scan-references.js"></script>' in html
        assert "NCTScanReference" in html


def test_table_headers_use_one_shared_explicit_scroll_contract():
    assert ".table-wrap[data-nct-table-mode=page]{overflow:visible!important}" in SHELL_SCRIPT
    assert "top:calc(var(--nct-header-height) + 6px)!important" in SHELL_SCRIPT
    assert ".table-wrap[data-nct-table-mode=contained]{max-height:none!important;overflow-x:auto!important;overflow-y:visible!important}" in SHELL_SCRIPT
    assert ".table-wrap[data-nct-table-mode=static]{overflow-x:auto!important;overflow-y:visible!important}" in SHELL_SCRIPT
    assert ".table-wrap[data-nct-table-mode=static]>table>thead>tr>th{position:static!important" in SHELL_SCRIPT
    assert ".table-wrap[data-nct-guide-mode=contained]" in SHELL_SCRIPT


def test_ordinary_long_lists_use_the_main_page_for_vertical_navigation():
    hostname = hostname_page().body.decode()
    analysis = analysis_page().body.decode()
    reach = reachability_page().body.decode()
    mission = mission_environment_page().body.decode()
    scans = operator_page().body.decode()

    assert ".table-wrap{max-height:none;overflow-x:auto;overflow-y:visible" in hostname
    assert ".lfa-host-list-body{max-height:none;overflow:visible" in analysis
    assert ".ordered-rules{max-height:none;overflow:visible" in reach
    assert ".history{max-height:none;overflow:visible" in mission
    assert "#nct-operator-guide{position:fixed" in SHELL_SCRIPT
    assert "height:min(46vh,420px);padding:0;overflow:auto" in SHELL_SCRIPT
    assert ".live-discoveries-scroll{min-height:0;flex:1 1 auto;overflow-y:auto" in scans
    assert ".table-wrap[data-nct-narrow-mode=contained]" in SHELL_SCRIPT

    for source in (Path(__file__).parents[1] / "app").glob("*.py"):
        text = source.read_text(encoding="utf-8")
        wrappers = []
        for tag in re.findall(r"<div\b[^>]*>", text):
            class_match = re.search(r'''\bclass=(?:"([^"]*)"|'([^']*)')''', tag)
            classes = (class_match.group(1) or class_match.group(2)).split() if class_match else []
            if "table-wrap" in classes:
                wrappers.append(tag)
        assert all("data-nct-table-mode=" in wrapper for wrapper in wrappers), source.name

    for page in (operator_page(), analysis_page(), device_analysis_page(), hunting_page()):
        html = page.body.decode()
        assert "--table-sticky-offset" not in html
        assert "syncTableStickyOffset" not in html
        assert '.table-wrap{overflow:visible}' not in html
    map_html = network_map_page().body.decode()
    assert "function wrapDetailsTables(root)" in map_html
    assert "wrapper.dataset.nctTableMode='contained'" in map_html
    assert "#details thead th{position:sticky" not in map_html


def test_activity_origin_banner_only_appears_on_outbound_pages():
    outbound_pages = [operator_page(), device_config_page(), hunting_page()]
    passive_pages = [analysis_page(), device_analysis_page(), network_map_page()]
    for page in outbound_pages:
        html = page.body.decode()
        assert 'class="activity-origin-banner"' in html
        assert 'class="activity-origin-host"' in html
        assert "node.textContent=location.hostname" in html
    for page in passive_pages:
        assert 'class="activity-origin-banner"' not in page.body.decode()


def test_device_configs_offer_reviewed_network_candidates():
    html = device_config_page().body.decode()
    assert "Networks identified in configuration files" in html
    assert 'id="configNetworkCandidate"' in html
    assert "Add selected to Saved Networks" in html
    assert "/api/device-configs/network-candidates" in html
    assert "/api/saved-networks" in html
    assert "removed from this pending list" in html
    assert "does not start a scan" in html


def test_device_configs_offer_explainable_multi_interface_wan_designation():
    html = device_config_page().body.decode()
    assert "WAN interface designation" in html
    assert "Analyze saved configs" in html
    assert "does not reprocess large configurations automatically" in html
    assert 'id="wanDeviceCollection"' in html
    assert 'id="wanGatewaySlot"' in html
    assert 'name="wanInterface"' in html
    assert "Save selected WAN interfaces" in html
    assert "Review WAN interfaces" in html
    assert 'id="airGappedNetwork"' in html
    assert "/api/network-semantics/air-gapped" in html
    assert "shared designation tells every operator" in html
    assert "wan_candidates" in html
    assert "candidate.reasons" in html
    assert "candidate.evidence" in html
    assert "networkDemoted" in html
    assert "Likely upstream transit" in html
    assert "View ${candidate.evidence.length} of ${count}" in html
    assert "include_correlations=false" in html
    assert "function wanSemanticNodeId" in html
    assert "interface_names:names" in html
    assert "wanNetworkSuggestionsStarted" in html
    history_loader = html.split("async function loadHistory", 1)[1].split("function discoveredHostName", 1)[0]
    assert "loadNetworkWanSuggestions" not in history_loader
    assert "/api/network-semantics/external-wan-gateway" in html
    assert "/api/network-semantics/wan-candidates" in html
    assert "strongest retained-evidence lead" in html
    assert "does not contact the device" in html
    assert "Primary and Secondary are reserved for separate gateway devices" in html


def test_device_preview_renders_one_ordered_vendor_specific_execution_plan():
    html = device_config_page().body.decode()
    assert "Collection note (optional)" in html
    assert "Reason / authorization note" not in html
    assert "Device address is required before uploading" in html
    assert 'id="operator"' not in html
    assert "operator:auditActor()" in html
    assert "Collection execution preview" in html
    assert "Complete read-only device command set" in html
    assert "Actual ordered execution plan" in html
    assert 'id="executionPlan"' in html
    assert "data.execution_steps" in html
    assert "step.location" in html
    assert "step.kind" in html
    assert "How to read this preview" in html
    assert 'id="preferredScope"' in html
    assert "Leaving this blank uses the reviewed active Mission Environment scope" in html
    assert "Live contact scope and later retained-evidence assignment are separate decisions" in html
    assert "preferred_scope_id:$('preferredScope').value||null" in html
    assert "Reusable collection profiles" in html
    assert "Apply profile" in html
    assert "Save as new profile" in html
    assert "Save new version" in html
    assert "Archive profile" in html
    assert "Copy collection settings" in html
    assert "The copy is not a named profile" in html
    assert "collection_profile_id:collectionProfileExact" in html
    assert "collectionProfile:['Saved device collection profile'" in SHELL_SCRIPT
    assert "preferredScope:['Reviewed live-contact scope and retained-evidence suggestion'" in SHELL_SCRIPT
    assert "(run.additional_commands||[]).join('\\n')" in html
    assert "run.device_scope_assignment?.scope_id||run.preferred_scope_id" in html
    assert "after local analysis, an analyst separately confirms whether the whole retained collection belongs in that scope" in html
    assert "VyOS and pfSense create a named temporary output file" in html
    assert "Cisco, Juniper, and UniFi devices return output directly through SSH and do not run SCP" in html
    assert '<option value="unifi">UniFi</option>' in html
    assert '<option value="switch">Switch</option>' in html
    assert '<select id="type" multiple size="3"' in html
    assert "device_types:deviceTypes" in html
    assert "Router + Firewall selected" in html
    assert "supportsSwitch=['cisco','juniper','unifi'].includes(vendor)" in html
    assert "Switch collection is available for this vendor" in html
    assert "$('type').onchange=()=>{updateVendorHint();markProfileDraftModified()}" in html
    assert "Current consoles and gateways normally use the root SSH account" in html
    assert "EdgeRouter devices should continue to use the VyOS template" in html
    assert 'id="captureCommand"' not in html
    assert 'id="scp"' not in html
    assert 'id="cleanupPlan"' not in html


def test_device_collection_keeps_raw_collection_work_separate_from_analysis():
    html = device_config_page().body.decode()
    assert 'id="deviceHistory"' in html
    assert 'id="historySearch"' in html
    assert "Configuration result file (maximum 100 MB)" in html
    assert 'id="routeFilter"' not in html
    assert "renderStructuredResults" not in html
    assert "/summary`" not in html
    assert "/delete-challenge`" in html


def test_device_evidence_downloads_use_authenticated_page_fetch():
    html = device_config_page().body.decode()
    assert "async function saveArtifact(artifact,link)" in html
    assert "fetch(artifact.url,{credentials:'same-origin'})" in html
    assert "const blob=await response.blob()" in html
    assert "URL.createObjectURL(blob)" in html
    assert "function artifactLink(artifact)" in html
    assert "event.preventDefault();saveArtifact(artifact,link)" in html
    assert 'id="deleteCollectionDialog"' in html
    assert "Load commands and evidence files" in html
    assert "History starts with lightweight metadata only" in html
    assert 'id="completionActions"' in html
    assert 'id="analyzeCollection"' in html
    assert 'id="continueCandidateToNmap"' in html
    assert "showCompletionActions(data)" in html
    assert "Analyze collection" in html
    assert "Analysis readiness" in html
    assert "Retry local verification" in html
    assert "retry-summary-verification" in html
    assert "Continue to Nmap" in html
    assert "/device-analysis?run=" in html
    assert "const orderedGroups=[...groups.entries()].sort" in html
    assert "for(const runs of groups.values()) runs.sort" in html


def test_history_loaders_support_older_range_browsers():
    scan_html = operator_page().body.decode()
    device_html = device_config_page().body.decode()
    for html in (scan_html, device_html):
        assert "AbortSignal.timeout" not in html
        assert "typeof AbortController==='function'" in html
        assert "timeoutError.name='TimeoutError'" in html


def test_network_device_analysis_has_unified_evidence_and_comparison_views():
    html = device_analysis_page().body.decode()
    assert "title:'Network devices'" in SHELL_SCRIPT
    assert "title:'Device configurations'" in SHELL_SCRIPT
    assert 'id="currentRun"' in html
    assert 'id="baselineRun"' in html
    assert "/api/device-analysis/compare" in html
    assert "/api/device-analysis/${encodeURIComponent(id)}" in html
    assert "Routing and interfaces" in html
    assert "Policy, NAT, and network objects" in html
    assert "Saved Networks" in html
    assert "Nmap hosts on device interfaces" in html
    assert "confidence" in html
    assert "Interfaces changed" in html
    assert "Firewall / ACL added" in html
    assert "Device command history and changes" in html
    assert "Confirmed NCT requires a direct occurrence link" in html
    assert "Confirmed NCT" in html
    assert "Possible NCT" in html
    assert "Linked receipts" in html
    assert "A linked receipt is a retained record that NCT sent the matching command" in html
    assert "Unmatched means no defensible NCT link was found" in html
    assert "history-confirmed" in html
    assert "history-possible" in html
    assert "history-unmatched" in html
    assert 'id="loadOlderCollections"' in html
    assert "HISTORY_PAGE_SIZE=100" in html
    assert "Running and startup line comparison" in html
    assert "Startup line" in html
    assert "Running line" in html
    assert "Source line" in html
    assert "CONFIG_DIFF_BATCH=200" in html
    assert 'id="loadMoreConfigDiff"' in html


def test_configuration_activity_is_hunt_while_collection_comparison_stays_compare():
    analyze_group = SHELL_SCRIPT.split("{label:'Analyze'", 1)[1].split("{label:'Compare'", 1)[0]
    compare_group = SHELL_SCRIPT.split("{label:'Compare'", 1)[1].split("{label:'Investigate'", 1)[0]
    hunt_group = SHELL_SCRIPT.split("{title:'Hunt'", 1)[1].split("{title:'Reach'", 1)[0]

    assert "href:'/device-analysis#activityEvidenceSection'" not in analyze_group
    assert "href:'/device-analysis#activityEvidenceSection',title:'Device command history and changes'" in hunt_group
    assert "href:'/device-analysis#comparisonPanel',title:'Device configurations'" in compare_group
    assert "body[data-nct-task=\"activityEvidenceSection\"] #baselineEvidenceControl" in device_analysis_page().body.decode()


def test_arkime_passive_evidence_intake_is_actionable_while_hunt_timeline_remains_planned():
    collect_group = SHELL_SCRIPT.split("{label:'Collect'", 1)[1].split("{label:'Identify'", 1)[0]
    hunt_group = SHELL_SCRIPT.split("{title:'Hunt'", 1)[1].split("{title:'Reach'", 1)[0]

    assert "{title:'Arkime',icon:'arkime',children:" in collect_group
    assert "href:'/arkime#arkimeCoverageWindows',title:'Coverage windows'" in collect_group
    assert "href:'/arkime#arkimeTrafficAnalysis',title:'Traffic patterns'" in collect_group
    assert "href:'/arkime#arkimeConnector',title:'Sessions and API pulls'" in collect_group
    assert "href:'/arkime#arkimeSummaryUpload',title:'Communication summaries'" in collect_group
    assert "href:'/arkime#arkimeSummaryHistory',title:'Retained summaries'" in collect_group
    assert "{title:'Arkime',icon:'arkime',planned:true" not in collect_group
    assert "{title:'Timeline',planned:true" in hunt_group
    assert "if(task.planned)" in SHELL_SCRIPT
    assert "row.setAttribute('aria-disabled','true')" in SHELL_SCRIPT
    assert "nct-hunt-timeline-planned" not in SHELL_SCRIPT
    assert "Timeline will show when retained observations first appeared or changed" in SHELL_SCRIPT
    assert "Network Evidence remains the view of what the selected evidence currently reports" in SHELL_SCRIPT
    assert "Arkime passive-evidence boundary" in SHELL_SCRIPT
    assert "Automatic read-only Arkime pulls" in SHELL_SCRIPT
    assert "Query-result completeness and sensor capture coverage remain separate" in SHELL_SCRIPT


def test_arkime_connector_explains_contact_boundary_and_recovery_controls():
    html = arkime_page().body.decode()

    assert 'id="arkimeConnector"' in html
    assert "Automatic read-only pulls" in html
    assert "Page reads never contact Arkime" in html
    assert "Pull now" in html
    assert "Retry same window" in html
    assert "never launches a rapid catch-up burst" in html
    assert 'aria-label="Automatic Arkime pull definitions"' in html
    assert 'aria-label="Recent automatic Arkime pulls"' in html
    assert "data-nct-table-mode=\"contained\"" in html
    assert 'id="pullProfilePrevious"' in html
    assert 'id="pullProfileNext"' in html
    assert "/api/arkime/pull-profiles?limit=${pullProfileLimit}&offset=${pullProfileOffset}" in html


def test_arkime_summary_intake_keeps_grouped_counts_separate_and_explains_limits():
    html = arkime_page().body.decode()

    assert 'id="arkimeSummaryUpload"' in html
    assert 'id="arkimeCoverageWindows"' in html
    assert 'id="arkimeTrafficAnalysis"' in html
    assert "/api/arkime/coverage-windows" in html
    assert "/api/arkime/traffic-analysis" in html
    assert 'id="trafficExpressionForm"' in html
    assert 'id="trafficExpressionInput"' in html
    assert "Apply typed expression" in html
    assert "Plain-language field guide: source address = ip.src" in html
    assert "destination port = port.dst" in html
    assert "ip.src == 10.50.15.10 &amp;&amp; port.dst == 443" in html
    assert "Last applied clauses" in html
    assert "The last applied clauses and results remain unchanged below" in html
    assert "Communication paths in this retained source" in html
    assert 'aria-label="Communication paths in selected retained Arkime source"' in html
    assert "First / last seen in this source (UTC)" in html
    assert "Detected applications" in html
    assert "first_packet_receipt_count" in html
    assert "first 100" in html
    assert "Rankings from this same source" in html
    assert "path_offset" in html
    assert "Analyze one retained Arkime source" in SHELL_SCRIPT
    assert "Type an exact Arkime-style retained-data expression" in SHELL_SCRIPT
    assert "The paged communication-path table" in SHELL_SCRIPT
    assert "same Network Scope and exact destination service" in SHELL_SCRIPT
    assert "Observed / Scan Mismatch compare retained reports" in SHELL_SCRIPT
    assert "Every individual session path is labeled Passively observed" in SHELL_SCRIPT
    assert "Not actively validated means" in SHELL_SCRIPT
    assert "Retained Nmap context" in html
    assert "Why these labels and when the evidence was collected" in html
    assert "Passively observed" in html
    assert "Not actively validated" in html
    assert "Open exact Nmap source" in html
    assert "A retained-window gap is an NCT evidence gap" in html
    assert 'id="arkimeCommunicationHistory"' in html
    assert 'id="historyPathFilter"' in html
    assert "IP address, port, transport, or application" in html
    assert "Retained-window gaps" in html
    assert "minutes without a comparable retained window" in html
    assert "Complete means the complete API result was retained" in html
    assert "Review communication history" in html
    assert "item.provenance_state==='exact_api_run'" in html
    assert "Load latest saved generation" in html
    assert "stream_identity" in html
    assert "data-history-exclusions-page" in html
    assert "Repeated retained record copies removed" in html
    assert "Retained session records counted once" in html
    assert ".history-identity strong,.history-identity small{display:block}" in html
    assert 'id="coverageRecommendationStream"' in html
    assert 'id="coverageRecommendationOverlap"' in html
    assert 'id="coverageRecommendationCutoff"' in html
    assert 'id="coverageRecommendationDelay"' in html
    assert 'id="coverageRecommend"' in html
    assert "Calculate next forward window" in html
    assert "recommend_stream_identity" in html
    assert "A recommendation never starts collection" in html
    assert "no traffic deduplication" in html
    assert "Use Next forward collection window" in SHELL_SCRIPT
    assert "calculated export, operator assessment, and capture declarations are all Complete" in html
    assert "Recorded export declaration':'Calculated export" in html
    assert "operator assessment ${item.operator_export_assessment}" in html
    assert 'download="arkime-source-${esc(item.import_id)}.' in html
    assert 'download="arkime-source-${esc(data.import_id)}.' in html
    assert "NCT Arkime Summary CSV v1" in html
    assert "it is not a native Arkime export format" in html
    assert "Validate and retain summary" in html
    assert "source_ip,destination_ip,destination_port,transport,detected_protocol,vlan,session_count,packet_count,byte_count" in html
    assert "Traffic addressed to a destination port does not prove" in html
    assert "An empty file does not prove there was no traffic" in html
    assert "A numeric zero is a measured zero; a blank count remains Unknown" in html
    assert "Download a ready-to-edit CSV template" in html
    assert "NCT cannot independently verify it from the CSV" in html
    assert 'id="arkimeSummaryHistory"' in html
    assert "NCT does not add counts across repeated or overlapping summaries" in html
    assert "Recorded from operator declaration" in html
    assert "NCT cannot verify completeness or row membership from this CSV" in html
    assert "Observed destination" in html
    assert "Reported destination port" in html
    assert "/api/arkime/summary-imports" in html
    assert "arkime-summary-upload" in SHELL_SCRIPT
    assert "arkime-summary-history" in SHELL_SCRIPT
    assert "These rows do not create current hosts or services" in SHELL_SCRIPT


def test_device_collections_uses_combined_router_firewall_icon():
    assert "device:'M7 7a5 5 0 1 0 0 10" in SHELL_SCRIPT
    assert "M13 6h8v12h-8z" in SHELL_SCRIPT


def test_arkime_navigation_uses_owl_icon():
    assert "arkime:'M3 3l5 3a7 7 0 0 1 8 0l5-3" in SHELL_SCRIPT
    assert "nct-nav-icon-filled" in SHELL_SCRIPT
    assert "path.setAttribute('fill-rule','evenodd')" in SHELL_SCRIPT


def test_network_device_analysis_bounds_large_route_tables_and_adds_filters():
    html = device_analysis_page().body.decode()
    assert "LARGE_ROUTE_TABLE=50" in html
    assert "ROUTE_DISPLAY_LIMIT=50" in html
    assert "Local / connected routes" in html
    assert "Search this routing table" in html
    assert "matches.slice(0,ROUTE_DISPLAY_LIMIT)" in html
    assert "routeScope=(data.route_analysis?.routes||[]).length>LARGE_ROUTE_TABLE?'local':'all'" in html
    assert "if(routeSearch.trim())routeScope='all'" in html
    assert "Showing the first ${ROUTE_DISPLAY_LIMIT} matching routes" in html


def test_nmap_analysis_labels_direct_and_correlated_mac_provenance():
    html = analysis_page().body.decode()
    assert "mac-provenance" in html
    assert "correlated by IP" in html
    assert "direct Nmap" in html
    assert "dataset.macProvenance" in html
    assert "loadAuthenticatedAnalyst" in html
    assert "Bound to the signed-in analyst" in html
    assert "authenticatedAnalyst?.username" in html


def test_hunting_view_has_categories_combined_filters_and_change_analysis():
    analysis_html = analysis_page().body.decode()
    device_html = device_analysis_page().body.decode()
    html = hunting_page().body.decode()
    storage_html = storage_page().body.decode()
    assert '<a href="/hunting">Hunt</a>' not in analysis_html
    assert '<a href="/hunting">Hunt</a>' not in device_html
    assert "title:'Hunt',icon:'hunt'" in SHELL_SCRIPT
    assert 'id="currentRun"' in html
    assert 'id="baselineRun"' in html
    assert 'id="search"' in html
    assert 'id="category"' in html
    assert 'id="protocol"' in html
    assert 'id="capability"' in html
    assert 'id="nonstandard"' in html
    assert 'id="osFilter"' in html
    assert 'id="subnetFilter"' in html
    assert 'id="deviceTypeFilter"' in html
    assert html.index("Network filters") < html.index("CVE and candidate filters")
    assert "Filters apply to the host and service tables below" in html
    assert 'id="networkFiltersPanel"' in html
    assert '<details class="panel" id="networkFiltersPanel" data-workspace-card="network-filters">' in html
    assert '<details class="panel" id="networkFiltersPanel" data-workspace-card="network-filters" open>' not in html
    assert '<details class="panel" data-workspace-card="network-overview">' in html
    assert '<details class="panel" data-workspace-card="network-overview" open>' not in html
    assert 'id="huntQuickSearch" class="hunt-quick-search-control"' in html
    assert html.index('id="huntQuickSearch"') < html.index('id="systemPageSize"')
    assert html.index('id="systemPageSize"') < html.index('id="systemPagePrevious"')
    assert "service-pair-grid" in html
    assert "grid-template-columns:minmax(110px,.65fr) minmax(220px,1.35fr)" in html
    assert "column-gap:16px;row-gap:6px;align-items:start" in html
    assert ".service-pair-grid>*{min-width:0;padding:0;border:0;background:transparent" in html
    assert ">◆ nonstandard port</span>" not in html
    assert ">◆ ${transport}</code>" not in html
    assert "Loading the newest completed scan for each network scope" in html
    assert "Loading retained network evidence" in html
    assert html.index('id="networkFiltersPanel"') < html.index('id="systemsPanel"') < html.index('id="search"')
    assert "search:['Quick filter hosts and services'" in SHELL_SCRIPT
    assert 'id="activeFilterSummary"' in html
    assert 'id="searchsploitFilterSummary"' in html
    assert "updateFilterSummaries" in html
    assert "searchSploitMatchesNetworkFilters" in html
    assert "annotateSearchSploitNetworkData" in html
    assert "after all active filters" in html
    assert 'id="hostRows"' not in html
    assert 'id="systemsPanel" data-workspace-card="systems"' in html
    assert '<th title="The observed port and protocol. Configuration-only findings say Device configuration instead of showing a port.">Port</th>' in html
    assert '>Service / product fingerprint</th>' in html
    assert "Port / source" not in html
    assert 'id="capabilityView" role="region" aria-label="Hunt capability evidence"' in html
    assert 'href="/analysis#networkOverview">Open complete host inventory</a>' in html
    assert 'id="inventoryView"' not in html
    assert "Network evidence overview" in html
    assert "<h2>Hosts and services</h2>" in html
    assert 'id="sources"' not in html
    assert "$('sources').innerHTML=sourceLinks(source)" not in html
    assert 'class="panel evidence-guide"' in html
    assert '<details class="panel evidence-guide" data-workspace-card="evidence-guide">' in html
    assert '<details class="panel" data-workspace-card="capability-datasets">' in html
    assert 'id="huntContextBar" class="hunt-context hidden"' in html
    assert 'id="datasetPreview"' in html
    assert 'prepareDatasetPreview' in html
    assert '<details class="panel" data-workspace-card="capability-datasets"><summary>Capability datasets</summary>' in html
    assert "Hosts and services stay in one bulk table" in html
    assert html.count('data-nct-table-mode="contained"') == 2
    assert 'data-nct-table-mode="page"' not in html
    assert ".table-wrap{overflow:visible}" not in html
    assert "max-width:1600px" not in html
    assert "body.nct-guide-open #systemsPanel .table-wrap thead th" not in html
    assert 'aria-label="Hunt capability evidence table"' in html
    assert "[...row.cells].reduce((total,cell)=>total+Number(cell.colSpan||1),0)" in html
    assert ".table-wrap[data-nct-table-mode]:focus{outline:2px solid var(--nct-accent,var(--accent))" in SHELL_SCRIPT
    assert "The table grows with the page so vertical navigation uses the main page scrollbar" in html
    assert "use the table's horizontal scrollbar only when extra columns do not fit" in html
    assert "function setSystemView()" in html
    assert "function renderHostInventoryRows()" not in html
    assert "hosts:[],findings:[]" in html
    assert "details.panel>summary::before" in html
    assert "details.panel[open]>summary::before" in html
    assert "position:sticky;top:var(--hunt-header-offset)" in html
    assert "scroll-margin-top:var(--hunt-result-offset" in html
    assert "stickyOffsetObserver.observe(pageHeader)" in html
    assert "stickyOffsetObserver.observe(huntContextBar)" in html
    assert "headerOffset+contextHeight" in html
    assert 'id="resetNetwork" class="source-links hidden"' in html
    assert "function setNetworkResetVisible(active)" in html
    assert "setNetworkResetVisible(!networkWide)" in html
    assert "setNetworkResetVisible(true)" in html
    assert "Exposed" in html
    assert "Inferred" in html
    assert "Why inferred:" in html
    assert "stateChipTitle(item,state)" in html
    assert "basis-inferred" in html
    assert "renderMatchBasis(item)" in html
    assert "if(!(item.evidence_states||[]).includes('inferred'))return[]" in html
    assert 'id="findingSummaryRows"' in html
    assert "renderFindingSummaries(visible.flat())" in html
    assert "activeSystemView==='inventory'" not in html
    assert 'id="systemPageSize"' in html
    assert 'id="systemPagePrevious"' in html
    assert 'id="systemPageNext"' in html
    assert 'id="systemPageSummary"' in html
    assert "function systemPageSlice(items,noun='host groups')" in html
    assert "function itemMatches(item)" in html
    assert "renderFindingSummaries(visible.flat())" in html
    assert "matching=(current.findings||[]).filter" in html
    assert "groups=findingGroups(matching),visible=systemPageSlice(groups)" in html
    assert "group.map((item,index)=>findingRowMarkup(item,index,group.length))" in html
    assert 'data-host-continuation="true"' in html
    assert "matching service${groupSize===1?'':'s'} on this host" in html
    assert "Hunt rows per page" in SHELL_SCRIPT
    assert "Filters apply to the complete loaded evidence before NCT chooses the page" in SHELL_SCRIPT
    assert "function anyHuntFilterActive()" in html
    assert ".finding-summary-row.hidden-row{display:none}" in html
    assert "content-visibility:auto" in html
    assert "finding${Number(item.finding_count||0)===1?'':'s'}" in html
    assert "capability classification${group.length===1?'':'s'} across" in html
    assert "Ports and service fingerprints stay aligned inside this host group." in html
    assert "Combined view · one entry per IP with all ports visible." in html
    assert "Filtered view · individual matching findings kept together by host." in html
    assert "function osIdentity(item)" in html
    assert "item.os_inference?.evidence" in html
    assert "os-inferred-label" in html
    assert "Observed" in html
    assert "Correlated" in html
    assert "Configuration" in html
    assert "They do not, by themselves, prove a vulnerability or compromise" in html
    assert "/api/hunting/network" in html
    assert "correlated by IP" in html
    assert "direct Nmap" in html
    assert "/api/hunting/compare" in html
    assert "/api/hunting/${encodeURIComponent(id)}" in html
    assert "function label(item){return scanRef(item).selection}" in html
    assert "title=\"${esc(reference.detail)}\"" in html
    assert "${index===0?' · Latest':''}" in html
    assert "Findings added" in html
    assert "Capability datasets" in html
    assert '<label for="category">Dataset</label>' in html
    assert "All datasets" in html
    assert "data.datasets||data.categories||[]" in html
    assert "Host dataset changes" in html
    assert "CVE and candidate filters" in html
    assert 'id="searchsploitPanel"' not in html
    assert 'id="searchsploitRun"' not in html
    assert "candidate assessment saved during supported ingestion" in html
    assert "Opening Hunt does not recalculate it" in html
    assert 'id="matchedOnly"' in html
    assert 'id="cveFilter"' in html
    assert 'id="cveYearFilter"' in html
    assert 'id="cveStatusFilter"' in html
    assert 'id="exposureFilter"' in html
    assert "Matched-service exposure" in html
    assert "Service exposure evidence" in html
    assert "data.exposure_disclaimer" in html
    assert 'id="cveSummary"' in html
    assert "Hosts and services stay in one bulk table" in html
    assert "CVE candidates" in html
    assert "candidateInlineMarkup" in html
    assert "Network Evidence row does not match its eight visible headings" in html
    assert 'data-hostkey="${esc(item.host_key||\'\')}" data-ip=' in html
    assert "Saved CVE grouping is unavailable because this retained row has no canonical host identity" in html
    assert "const related=matches.filter(match=>String(match.host_key||'')===slot.dataset.hostkey)" in html
    assert "inline-cve-detail" in html
    assert "cve-port-group" in html
    assert "cve-reference-group" in html
    assert "Open a port, then a CVE" in html
    assert "Candidates without CVE" in html
    assert "candidatePortGroupMarkup" in html
    assert "Show all CVEs for this port" in html
    assert "Collapse all CVEs for this port" in html
    assert "togglePortCves" in html
    assert "event.target.closest?.('[data-cve-port-toggle]')" in html
    assert "Review CVE candidates for one port" in SHELL_SCRIPT
    assert "Review references for one CVE" in SHELL_SCRIPT
    assert "function datasetFilterButton(value,item=null)" in html
    assert "function datasetPreviewKey(value,item=null)" in html
    assert "data-dataset-preview" in html
    assert "data-dataset-filter" in html
    assert "function applyDatasetFilter(button)" in html
    assert "syncDatasetFilterButtons" in html
    assert "Select the active Dataset badge again to clear it" in SHELL_SCRIPT
    assert ".finding-match-slot,.finding-host-match-slot,.host-cve-slot{min-width:0;max-width:100%}" in html
    assert "#capabilityView table{min-width:1440px;table-layout:fixed}" in html
    assert "#capabilityView th:nth-child(7),#capabilityView td:nth-child(7){width:360px}" in html
    assert "function findingRowMarkup(item,groupIndex=0,groupSize=1)" in html
    assert "function findingGroupKey(item,index)" in html
    assert "configureCveFilters" in html
    assert "applySearchSploitFilters" in html
    assert "renderHostCveDropdowns" in html
    assert "/api/searchsploit/status" in html
    assert "/api/searchsploit/hunting/network" not in html
    assert "renderSearchSploit(data.searchsploit" in html
    assert "runSearchSploit" not in html
    assert "function beginHuntSelection()" in html
    assert "Loading retained Network Evidence — read only; no network contact" in html
    assert "if(huntRequestController)huntRequestController.abort()" in html
    assert "did not finish within" in html
    assert "Your retained evidence was not changed" in html
    assert "loadedViewReceipt" in html
    assert "remains visible" in html
    assert "Retry network view" in html
    assert 'id="candidateStatus" class="status" role="status"' in html
    assert "comparisonCandidateItems(data)" in html
    assert "/api/scan-comparisons/candidates?limit=100&offset=0" in html
    assert ".status.loading::after" in html
    assert "searchsploitRevision" in html
    assert "await loadSearchSploitStatus()" in html
    assert "function responseJson(response,label='Request')" in html
    assert "returned an empty server response" in html
    assert "returned an unreadable server response" in html
    assert "Historical evidence is not recalculated when Hunt opens" in html
    assert 'id="manageExploitReferences"' in html
    assert 'href="/settings/system-health#offlineExploitDb"' in html
    assert "manageExploitReferences:['Manage offline exploit references'" in SHELL_SCRIPT
    assert "Refresh Hunt evidence" in SHELL_SCRIPT
    assert "Only one network-wide Hunt load remains active in this browser" in SHELL_SCRIPT
    assert "'/hunt':{" not in SHELL_SCRIPT
    assert "'/hunting':{" in SHELL_SCRIPT
    assert "This shortcut only opens settings" in SHELL_SCRIPT
    assert 'id="searchsploitOnline"' not in html
    assert 'id="searchsploitUpload"' not in html
    assert 'id="searchsploitRollback"' not in html
    assert 'id="offlineExploitDb"' in storage_html
    assert 'id="searchsploitOnline"' in storage_html
    assert 'id="searchsploitUpload"' in storage_html
    assert 'id="searchsploitRollback"' in storage_html
    assert "/api/searchsploit/database/update-online" in storage_html
    assert "/api/searchsploit/database/upload" in storage_html
    assert "/api/searchsploit/database/rollback/" in storage_html
    assert "No rescan or device contact occurs" in storage_html
    assert "searchsploitUploadFile:['Choose an offline Exploit-DB archive'" in SHELL_SCRIPT
    assert "Choosing a file alone does not upload or activate it" in SHELL_SCRIPT
    assert "searchsploitVersions:['Choose an earlier reference version'" in SHELL_SCRIPT
    assert "Selection alone changes nothing" in SHELL_SCRIPT
    assert "keeps earlier versions for rollback" in open("docs/AIR_GAPPED_RANGE_QUICKSTART.md", encoding="utf-8").read()
    assert "analyst-review leads, not proof of a vulnerability" in html
    assert 'class="finding-match-slot"' in html
    assert "finding-host-match-slot" in html
    assert "Offline product/version associations for analyst review" in html
    assert "openSearchSploitMatch" not in html
    assert "contains no specific product/version fingerprints" in html
    assert "Service/version detection in the scan profile" in html
    assert '/hunting?run=${encodeURIComponent(runId)}' in analysis_html
    assert "function reachUrl(item)" in html
    assert "Evaluate host in Reach" in html
    assert "Open Reach with this destination and service; Source remains for you to choose." in html
    assert "renderSearchSploitReachBase" in html
    assert "target='_blank'" in html


def test_hunt_can_open_one_exact_arkime_source_without_merging_it_into_inventory():
    hunt = hunting_page().body.decode()
    arkime = arkime_page().body.decode()
    guide = how_nct_works_page().body.decode()

    assert 'id="passiveContextPanel"' in hunt
    assert 'data-guide-context="hunt-passive-context"' in hunt
    assert "/api/hunting/passive-context?import_id=" in hunt
    assert "Selected Arkime communication context" in hunt
    assert "Retained Nmap context" in hunt
    assert "Passively observed" in hunt
    assert "Not actively validated" in hunt
    assert "Why these labels and which sources support them" in hunt
    assert "Exact evidence" in hunt
    assert "Network Evidence remains independent" in hunt
    assert "did not substitute another import" in hunt
    assert "params.delete('run')" in hunt
    assert "params.delete('arkime')" in hunt
    assert "Promise.allSettled([loadNetwork(),arkime?loadPassiveContext(arkime)" in hunt
    assert "$('refreshNetwork').onclick=refreshWorkspace" in hunt
    assert "Investigate this retained source in Hunt" in arkime
    assert "/hunting?arkime=${encodeURIComponent(data.import_id)}#huntOverview" in arkime
    assert "requestedAnalysis" in arkime
    assert "Review one Arkime source in Hunt" in SHELL_SCRIPT
    assert "earliest and latest packet time in this source" in SHELL_SCRIPT
    assert "The paged communication-path table" in SHELL_SCRIPT
    assert "not network-wide First Seen or Last Seen" in SHELL_SCRIPT
    assert "Separate or overlapping imports are not merged or deduplicated" in SHELL_SCRIPT
    assert "Choosing a focused scan in Hunt removes the passive selection" in SHELL_SCRIPT
    assert "huntOverview:['passiveContextPanel','huntEvidenceOverview'" in SHELL_SCRIPT
    assert "separate communication-context panel" in guide
    assert "A missing, deleted, or unsupported source reports its own error" in guide


def test_reachability_view_has_grouped_source_exposure_reports():
    html = reachability_page().body.decode()
    assert '<button id="evaluate">Assess Path</button>' in html
    assert 'id="sourceExternal"' in html
    assert "External address / range" in html
    assert "source_external:$('sourceExternal').checked" in html
    assert 'id="changeScenarioPanel"' in html
    assert 'id="useAssessmentInScenario"' in html
    assert "Use In Proposed Changes" in html
    assert 'id="scenarioFlowContext"' in html
    assert 'id="scenarioSource"' in html
    assert 'id="scenarioSourceExternal"' in html
    assert 'id="scenarioDestination"' in html
    assert 'id="scenarioProtocol"' in html
    assert 'id="scenarioPort"' in html
    assert 'id="scenarioFlowState"' in html
    assert 'id="copyAssessmentToScenario"' in html
    assert 'id="scenarioDeviceScope"' in html
    assert 'id="showAllScenarioDevices"' in html
    assert "function assessmentPathDevices" in html
    assert "scopeScenarioDevicesToAssessment(latestReachResult)" in html
    assert "Choose a device identified on this path" in html
    assert "First choose whether the traffic ends on the selected router/firewall" in html
    assert 'id="scenarioTrafficTarget"' in html
    assert 'value="router_local"' in html
    assert 'id="scenarioRouteStage" class="scenario-stage hidden"' in html
    assert "Position in this interface and policy plane" in html
    assert "Retained rules for this interface and policy plane" in html
    assert "policyContextRequestRevision" in html
    assert "policyTemplateRequestRevision" in html
    assert "encounter!==JSON.stringify(policyTemplateBody())" in html
    assert "function invalidateScenarioResult" in html
    assert "scenarioRequestRevision" in html
    assert "revision!==scenarioRequestRevision||encounter!==JSON.stringify" in html
    assert "Scenario inputs changed. The previous result is no longer current" in html
    assert "Reassess proposed scenario" in html
    assert "body.nct-guide-open .scenario-traffic-grid" in html
    assert "invalidateScenarioResult();$('simulationRule').value=data.rule_text" in html
    assert "nct-reach-latest-assessment-v1" in html
    assert "function restoreLatestAssessment" in html
    assert "source:$('scenarioSource').value.trim()" in html
    assert "target==='router_local'?$('simulationLocalAddress').value:$('scenarioDestination').value.trim()" in html
    assert "port:Number($('scenarioPort').value)" in html
    assert "function useAssessmentInScenario" in html
    assert html.count("function useAssessmentInScenario") == 1
    assert html.count("function applyIncomingContext") == 1
    assert html.count("function copyLatestAssessment") == 1
    assert "routeSimulationNetwork').value=routeNetwork" in html
    assert 'id="simulationDevice"' in html
    assert 'id="simulationInterface"' in html
    assert 'id="simulationLocalAddress"' in html
    assert 'id="simulationAction"' in html
    assert 'id="simulationTemplate"' in html
    assert 'id="simulationPosition"' in html
    assert 'id="simulationRule"' in html
    assert 'id="simulationExistingRules"' in html
    assert 'id="generatePolicyRule"' in html
    assert 'id="scenarioPath"' in html
    assert 'id="scenarioImpact"' in html
    assert 'id="scenarioValidation"' in html
    assert 'id="exportScenario"' in html
    assert 'id="showScenarioOnMap"' in html
    assert "/api/reachability/simulate-change-scenario" in html
    assert "/api/reachability/policy-context/" in html
    assert "/api/reachability/policy-template" in html
    assert "changes no device configuration" in html
    assert "background:var(--nct-surface-subtle,var(--panel))" in html
    assert "background:var(--nct-control,#0b1520)" in html
    assert ".result-head{align-items:stretch;flex-direction:column}" in html
    assert 'id="routeSimulationDevice"' in html
    assert 'id="routeSimulationNetwork"' in html
    assert 'id="routeSimulationInterface"' in html
    assert "device?.interface_details" in html
    assert "item.address||item.network" in html
    assert 'id="routeSimulationPriorityKind"' in html
    assert 'id="routeSimulationPriorityValue"' in html
    assert 'id="routePriorityKindControl" class="hidden"' in html
    assert "Route priority values are not needed for this action" in html
    assert "classList.toggle('hidden',!priority)" in html
    assert 'value="set_priority"' in html
    assert 'id="simulateScenario"' in html
    assert "NCT_Proposed_Change_" in html
    assert "policy device on projected path" in html
    assert "Local input / management" in html
    assert "NOT APPLIED" in html
    assert "showSimulationOnMap" in html
    assert "version:2" in html
    assert 'id="exposureReportPanel"' in html
    assert 'id="reportCatalog"' in html
    assert 'id="reportLoading"' in html
    assert 'role="progressbar"' in html
    assert "Loading Saved Networks and checking report freshness" in html
    assert "Building this subnet report from retained evidence" in html
    assert "prefers-reduced-motion:reduce" in html
    assert 'class="generate-network-report"' in html
    assert html.count('id="regenerateReport"') == 1
    assert "Use the single Regenerate report action inside the open report" in html
    assert "reportRequestRevision" in html
    assert "clearExposureWorkspace" in html
    assert 'id="exportReport"' in html
    assert "/api/reachability/exposure-reports" in html
    assert "No report yet" in html
    assert "out of date" in html
    assert "Retained route, policy, and NAT objects" in html
    assert "function evidenceCard(item)" in html
    assert "Read this assessment in order" in html
    assert html.index("Traffic and likely path:") < html.index("Evidence used:</") < html.index("Limits and uncertainty:</") < html.index("Supported outcome:</")
    assert "Unknown</b> means NCT assessed the saved evidence" in html
    assert "Not assessed</b> means required coverage was never available" in html
    assert html.index('<div id="evidence"></div>') < html.index('class="panel result-conclusion"')
    assert "function reportEvidence(items){return assessmentEvidence(items).map(evidenceCard)" in html
    assert "network context, translation, selected routes, switching, ordered policy" in html
    assert "function assessmentEvidence(items)" in html
    assert "rank={source_network:0,destination_network:0,nat:1,route:2,switching:3,policy:4,service:5,coverage:5}" in html
    assert "View supporting evidence" in html
    assert "Open source in Analyze ↗" in html
    assert 'target="_blank" rel="noopener"' in html
    assert ".evidence.policy.deny" in html
    assert 'id="rangeCoverage"' in html
    assert "function renderRange(data)" in html
    assert "Evidence-backed target discovery" in html
    assert "Unique retained evidence in this selected range" in html
    assert "Broad and default routes were not expanded into theoretical targets" in html
    assert 'class="secondary range-drill"' in html
    assert 'class="secondary range-map"' in html
    assert "function rangeHostResult(data,row)" in html
    assert "network.endsWith('/32')?network.slice(0,-3):network" in html
    assert "function rangeRowAction(row,index,hostLevel)" in html
    assert "View ${hops.length} hop" in html
    assert "Host path" in html
    assert "Known targets inside a broad range have different route or policy results" in html
    assert "The target is known to exist, but no retained route" in html


def test_reachability_empty_state_routes_novices_to_required_evidence():
    html = reachability_page().body.decode()

    assert 'id="emptyContext"' in html
    assert "Reach needs retained network context first" in html
    assert 'href="/scans#savedNetworkPanel"' in html
    assert 'href="/scans#scanBuilder"' in html
    assert 'href="/analysis#xmlImport"' in html
    assert "run a new scan" in html
    assert "import Nmap evidence" in html
    assert 'href="/device-config#collectionPlan"' in html
    assert "classList.toggle('hidden',Boolean(hasContext))" in html
    assert "Use this as the network roster" in SHELL_SCRIPT
    assert "Investigate the roster’s observed services" in SHELL_SCRIPT


def test_range_results_explain_evidence_coverage_once():
    html = reachability_page().body.decode()

    assert "Evidence coverage" in html
    assert "share of addresses in each CIDR backed by retained evidence" in html
    assert "It is not a reachability success rate" in html
    assert "row.identified_percent" in html
    assert "row.routed_percent" not in html
    assert "row.routed_address_count" not in html


def test_reachability_query_fields_have_clear_buttons():
    html = reachability_page().body.decode()

    assert 'id="clearSource"' in html
    assert 'aria-label="Clear Source"' in html
    assert 'id="clearDestination"' in html
    assert 'aria-label="Clear Destination"' in html
    assert "bindClearButton('source','clearSource')" in html
    assert "bindClearButton('destination','clearDestination')" in html
    assert "function applyIncomingContext()" in html
    assert "params.get('destination')" in html
    assert "Choose a Source, then select Assess Path." in html


def test_async_evidence_pages_show_explicit_loading_states():
    analyze = analysis_page().body.decode()
    device = device_analysis_page().body.decode()
    hunt = hunting_page().body.decode()
    reach = reachability_page().body.decode()
    map_html = network_map_page().body.decode()

    assert 'id="pageLoading"' in analyze
    assert "Loading retained Analyze workspace" in analyze
    assert "aria-busy" in analyze
    assert "Loading retained device collections" in device
    assert "Loading retained network evidence" in hunt
    assert "Loading retained network context" in reach
    assert "Loading saved topology evidence" in map_html


def test_search_fields_receive_consistent_clear_controls():
    assert "function installClearableInputs()" in SESSION_SCRIPT
    assert 'input[type="search"],input[data-nct-clearable="true"]' in SESSION_SCRIPT
    assert "nct-input-clear" in SESSION_SCRIPT
    assert "::-webkit-search-cancel-button" in SESSION_SCRIPT
    assert ".network-search-control" in SESSION_SCRIPT
    assert "new MutationObserver" in SESSION_SCRIPT
    assert "input.dispatchEvent(new Event('input'" in SESSION_SCRIPT


def test_every_analysis_stage_has_a_local_export_path_including_map():
    analyze = analysis_page().body.decode()
    device = device_analysis_page().body.decode()
    hunt = hunting_page().body.decode()
    reach = reachability_page().body.decode()
    map_html = network_map_page().body.decode()

    assert "window.NCTExport" in SESSION_SCRIPT
    assert "Download started:" in SESSION_SCRIPT
    assert "nct:export-started" in SESSION_SCRIPT
    assert "document.body.append(link)" in SESSION_SCRIPT
    assert "Export report HTML" in analyze
    assert "function exportHtml()" in analyze
    assert 'id="exportDeviceAnalysis"' in device
    assert "function exportDeviceAnalysis()" in device
    assert 'id="exportHuntJson"' in hunt
    assert 'id="exportHuntCsv"' in hunt
    assert "function exportHuntJson()" in hunt
    assert "function exportHuntCsv()" in hunt
    assert 'id="exportReachResult"' in reach
    assert "function exportReachResult()" in reach
    assert 'id="exportMapSvg"' in map_html
    assert 'id="exportMapJson"' in map_html
    assert "function exportMapImage()" in map_html
    assert "function exportMapData()" in map_html
    assert "topology,presentation:" in map_html


def test_evidence_links_deep_link_to_expanded_analyze_sections():
    reach_html = reachability_page().body.decode()
    analyze_html = analysis_page().body.decode()
    device_html = device_analysis_page().body.decode()

    assert 'target="_blank" rel="noopener"' in reach_html
    assert "focusRequestedEvidence" in analyze_html
    assert "params.get('focus')!=='host'" in analyze_html
    assert 'id="routingEvidenceSection"' in device_html
    assert 'id="policyEvidenceSection"' in device_html
    assert "for(const item of section.querySelectorAll('details'))item.open=true" in device_html


def test_reachability_can_compare_the_same_flow_from_internet():
    html = reachability_page().body.decode()

    assert 'id="checkExternalPath"' in html
    assert 'id="externalResult"' in html
    assert 'id="showExternalOnMap"' in html
    assert "async function evaluateExternal()" in html
    assert "source:'Internet'" in html
    assert "latestExternalResult" in html
    assert "External path check" in html
    assert "No network traffic was sent." in html


def test_reachability_results_can_open_a_temporary_map_focus():
    reach_html = reachability_page().body.decode()
    map_html = network_map_page().body.decode()

    assert 'id="showResultOnMap"' in reach_html
    assert 'class="secondary show-report-on-map"' in reach_html
    assert "sessionStorage.setItem(reachMapStorageKey" in reach_html
    assert "location.href='/network-map?reach-focus=1'" in reach_html
    assert 'id="reachFocusPanel"' in map_html
    assert 'id="exitReachFocus"' in map_html
    assert "function resolveReachFocusNodes" in map_html
    assert "function ipv4InCidr" in map_html
    assert "endpointSubnetIds.has(edge.target)" in map_html
    assert "function applyReachFocus" in map_html
    assert "reach-focus-match" in map_html
    assert "reach-focus-dim" in map_html
    assert "Temporary investigation overlay" in map_html
    assert "saved map positions and layouts are unchanged" in map_html
    assert "Temporary proposed-path comparison" in map_html
    assert "Bounded collateral scope" in map_html


def test_reachability_paths_have_color_key_and_visibility_toggles():
    reach_html = reachability_page().body.decode()
    map_html = network_map_page().body.decode()

    assert 'id="pathOptions"' in reach_html
    assert "function renderPathOptions" in reach_html
    assert "Only the assessed path is shown by default" in reach_html
    assert "Selections carry to Map" in reach_html
    assert "Show all paths" in reach_html
    assert "Assessed path only" in reach_html
    assert "data-path-action" in reach_html
    assert "Show only this path on Map" not in reach_html
    assert "visible_path_ids" in reach_html
    assert ".role-equal_cost" in reach_html
    assert ".role-standby" in reach_html
    assert ".role-blocked" in reach_html
    assert 'id="reachPathKey"' in map_html
    assert "function visibleReachPathOptions" in map_html
    assert "reachPathColors" in map_html
    assert "reachPathPalette" in map_html
    assert "function reachPathColorAssignments" in map_html
    assert "reach-path-toggle" in map_html
    assert "Show all paths" in map_html
    assert "Assessed path only" in map_html
    assert "function setReachPathVisibility" in map_html
    assert "--reach-focus-color" in map_html
    assert "reachFocusPathNodeIds" in map_html
    assert "reach-focus-shared" in map_html
    assert "Shared by selected paths" in map_html
    assert "data-edge-relation" in map_html


def test_primary_navigation_follows_the_operator_workflow():
    expected = [
        "title:'Device collections'",
        "title:'Nmap scans'",
        "title:'Hostname evidence'",
        "title:'Current network'",
        "title:'Network devices'",
        "title:'Changes over time'",
        "title:'Hunt',icon:'hunt'",
        "title:'Reach',icon:'reach'",
        "title:'Map',icon:'map'",
    ]
    positions = [SHELL_SCRIPT.index(label) for label in expected]
    assert positions == sorted(positions)
    assert "href:'/network-map#mapFilesPanel',title:'Files & export'" in SHELL_SCRIPT
    assert "href:'/device-config#wanDesignationPanel',title:'WAN designation'" in SHELL_SCRIPT
    assert "title:'WAN gateway evidence'" not in SHELL_SCRIPT
    assert "href:'/network-map#mapFaqPanel'" not in SHELL_SCRIPT
    assert "mapWorkspace:['mapSummary','mapLayoutPanel']" in SHELL_SCRIPT
    nmap_group = SHELL_SCRIPT.split("{title:'Nmap scans'", 1)[1].split("{label:'Identify'", 1)[0]
    current_network_group = SHELL_SCRIPT.split("{title:'Current network'", 1)[1].split("{title:'Network devices'", 1)[0]
    assert "href:'/analysis#xmlImport',title:'Import & investigate'" in nmap_group
    assert "href:'/analysis#nmapScopeAssignments'" not in nmap_group
    assert "href:'/analysis#xmlImport'" not in current_network_group
    assert "upload authorized nmap xml, open that exact result for review" in SHELL_SCRIPT.lower()
    assert "opens that result for investigation below" in SHELL_SCRIPT.lower()
    assert "loopback-only development address on the same computer" in SHELL_SCRIPT
    assert "unrelated-scope evidence from the same installation" in SHELL_SCRIPT
    assert "does not mean every object belongs to the last scan you opened" in SHELL_SCRIPT


def test_manual_nmap_scope_assignment_ui_is_explicit_accessible_and_recoverable():
    html = analysis_page().body.decode()
    assert 'id="nmapScopeAssignments"' in html
    assert '<section id="xmlImport" class="panel">' in html
    assert '<div id="nmapScopeAssignments" class="assignment-workspace">' in html
    assert "Next: optionally assign network context" in html
    assert "NCT never selects one from a Saved Network, CIDR, scan target, filename, hash, or previous upload" in html
    assert "If the file combines different isolated network contexts, do not assign it" in html
    assert '<option value="">Choose an active Network Scope</option>' in html
    assert 'label for="${scopeId}"' in html
    assert 'label for="${reasonId}"' in html
    assert '<div class="assignment-confirm"><input id="${confirmId}"' in html
    assert '<label for="${confirmId}">${confirmation}' in html
    assert 'class="status assignment-process-status" role="status"' in html
    assert "card.querySelector('.assignment-process-status')" in html
    assert "creates scoped address, service, assessment, and evidence-receipt records" in html
    assert "Completion appears in this history" in html
    assert "The scope decision is retained, but processing could not be queued" in html
    assert "Queued and safe to leave" in html
    assert "Retry scoped processing" in html
    assert "it does not change current analysis views" in html.lower()
    assert "does not change the current Analyze, Hunt, Reach, or Map results" in html
    assert "does not grant scan authority, require analysts to be tasked" in SHELL_SCRIPT


def test_scan_history_uses_open_details_for_retained_evidence_files():
    html = operator_page().body.decode()
    assert ".history-run-actions{display:flex;flex-wrap:nowrap" in html
    assert '<div class="history-run-actions"><button class="secondary" data-preset=' in html
    assert '>Use preset</button><button class="secondary" data-network=' in html
    assert 'title="Open retained run details and evidence files here">Open details</button>' in html
    assert "async function selectRun(id,button)" in html
    assert "It does not replace the live Active Scan view or rerun Nmap" in SHELL_SCRIPT
    assert "Load evidence files" not in html
    assert "data-evidence=" not in html
    assert "Analysis-ready scan evidence (XML)" in html
    assert "TCP evidence (XML)" in html
    assert "UDP evidence (XML)" in html
    assert "This TCP + UDP run is partial." in html
    assert "The analysis-ready XML merges both completed phases." in html
    assert "async function loadScanEvidence" not in html
    assert 'data-hunt="${esc(run.run_id)}">Hunt</button>' in html
    assert '/hunting?run=${encodeURIComponent(b.dataset.hunt)}#huntOverview' in html
    assert '#scanFocus' not in html


def test_network_map_surfaces_mac_arp_pcap_and_offline_oui_evidence():
    html = network_map_page().body.decode()
    assert 'id="macObservationCount"' in html
    assert 'id="arpNeighborCount"' in html
    assert "MAC evidence" in html
    assert "Multiple MAC addresses were observed for this IP" in html
    assert "Offline OUI database" in html
    assert "Routed endpoint MACs are learned from router/firewall neighbor-table evidence" in html
    assert "Scanned infrastructure" in html
    assert "0 observations · characterization needed" in html
    assert "infrastructure_count" in html
    assert "observed_count" in html
    assert "collapseTransitSegments" in html


def test_network_map_groups_services_by_observed_interface_or_explicit_unmatched_state():
    html = network_map_page().body.decode()
    assert "Open services by interface / address" in html
    assert "function serviceExposureGroup" in html
    assert "addressMatches.length===1" in html
    assert "explicitMatches.length===1" in html
    assert "Interface / address not established" in html
    assert "cannot confidently name the exposing interface" in html
    assert "Port / protocol" in html
    assert "Service / product fingerprint" in html
    assert "service.sources" in html
    assert ".service-exposure-table{min-width:680px;table-layout:fixed}" in html


def test_map_gap_prepares_existing_scan_builder_without_direct_network_contact():
    map_html = network_map_page().body.decode()
    scan_html = operator_page().body.decode()

    assert "function mapScanPreparation(node)" in map_html
    assert "function appendMapScanPreparation(node)" in map_html
    assert "No retained Nmap observation supports this" in map_html
    assert "Prepare scan in Nmap Scans" in map_html
    assert "It does not start or queue a scan" in map_html
    assert "map_saved_network_id" in map_html
    assert "saved_network_cidr===target" in map_html
    assert "['device','gateway'].includes(node.kind)" in map_html
    assert "node.kind==='subnet'" in map_html
    assert "node.kind==='subnet_group'" not in map_html.split("function mapScanPreparation(node)", 1)[1].split("function mapScanHref", 1)[0]
    assert "fetch('/api/scan-runs'" not in map_html
    assert 'id="mapScanHandoff"' in scan_html
    assert "function applyMapScanHandoff()" in scan_html
    assert "item.saved_network_id===requestedId&&item.cidr===target" in scan_html
    assert "This target was prepared as a manual target" in scan_html
    assert "reviewed Mission Environment scope is shown below" in scan_html
    assert "label.includes(target)?`Selected ${kind}: ${label}`" in scan_html
    assert "if(ownsTask())applyMapScanHandoff()" in scan_html
    assert 'section.dataset.guideContext=\'map-scan-preparation\'' in map_html
    assert "aside#details .map-scan-preparation a.map-scan-action" in map_html
    assert "color:#07171b!important" in map_html
    assert "Prepare a scan from this Map gap" in SHELL_SCRIPT
    assert "control?.closest?.('[data-map-scan-preparation]')" in SHELL_SCRIPT
    assert "control?.matches?.('[data-node]')" in SHELL_SCRIPT
    assert "Review this Map object" in SHELL_SCRIPT
    assert 'data-guide-context="map-object-details"' in map_html
    assert "control?.closest?.('#details')" in SHELL_SCRIPT
    assert "[data-guide-context],[data-node]" in SHELL_SCRIPT
    assert "Map position and labels never grant permission" in SHELL_SCRIPT


def test_scan_builder_has_reviewed_atomic_saved_network_batch_workflow():
    html = operator_page().body.decode()

    assert '<option value="batch">Queue Separate Scans for Multiple Networks</option>' in html
    assert 'id="batchNetworkChoices"' in html
    assert 'id="batchOrderPanel"' in html
    assert 'id="reviewBatch"' in html
    assert 'id="queueBatch"' in html
    assert "'/api/scan-runs/batch-preview'" in html
    assert "'/api/scan-runs/batch'" in html
    assert "name_template:template" in html
    assert "preview_digest:batchPreview.preview_digest" in html
    assert "expected_global_no_strike_revision" in html
    assert "batchSubmitInFlight" in html
    assert "request_replayed?'Recovered from the saved receipt after a retry.'" in html
    assert "Only one scan uses the analyzer at a time." in html
    assert "location.hash='queuePanel'" not in html.split(
        "async function queueReviewedBatch", 1
    )[1].split("function", 1)[0]


def test_large_route_tables_are_filtered_and_map_details_stay_compact():
    analyze_html = analysis_page().body.decode()
    map_html = network_map_page().body.decode()

    assert "LARGE_ROUTE_TABLE=50" in analyze_html
    assert "Local / connected routes" in analyze_html
    assert "Search this routing table" in analyze_html
    assert "ROUTE_DISPLAY_LIMIT=50" in analyze_html
    assert "Search and route view are applied before results are sent to this page" in analyze_html
    assert "if(filter.term.trim()){filter.scope='all'" in analyze_html
    assert "loadNetworkDeviceRoutes" in analyze_html
    assert "renderRouteFreeDetailsBase" in map_html
    assert "heading.textContent!=='Parsed routes'" in map_html


def test_map_connection_points_show_interface_ips_and_grouped_shapes_share_one_fill():
    html = network_map_page().body.decode()

    assert "source_interface_address" in html
    assert "target_interface_address" in html
    assert "edge-endpoint-label" in html
    assert "function positionEndpointLabel" in html
    assert "function resolveEndpointLabelCollisions" in html
    assert "function endpointLabelBounds" in html
    assert "function edgeMidpointLabelBounds" in html
    assert "function suppressRedundantTransitDecorations" in html
    assert "suppress_endpoint_labels:true" in html
    assert "showEndpointLabels=!edge.suppress_endpoint_labels" in html
    assert "function interfaceAddressIdentity" in html
    assert "!endpointAddresses.has(interfaceAddressIdentity(address))" in html
    assert "label.dataset.labelOffset" in html
    assert "Interface IP addresses" in html
    assert "composite-annotation-fill" in html
    assert "annotationUnionFill" in html
    assert "Grouped ${merged.size} touching shapes with one constant fill color" in html
    assert "transit_segment" in html
    assert "webLayout" in html
    assert "Spider-web network topology" in html
    assert "Labeled transit subnet" in html
    assert 'id="mapLegendItems"' in html
    assert "function renderLegend(view)" in html
    assert "deviceTypes.has(key)" in html
    assert "osFamilies.has(key)" in html
    assert "vendors.has(key)" in html
    assert "renderLegend(view)" in html
    assert 'data-legend="mission-special"' in html
    assert "Mission Partner Identified special-device role" in html
    assert "node.mission_partner_identified||(node.grouped_hosts||[]).some(host=>host.mission_partner_identified)" in html
    assert "showMissionOnGroup=mode==='collapsed'&&!query&&groupedMissionRoles.length>0" in html
    assert "mission_special_roles:showMissionOnGroup?groupedMissionRoles:[]" in html
    assert "x:isPortalWan?pos.w-28:pos.w-10,y:isGroup?21:isPortalWan?32:pos.h-9,class:'mission-role-marker'" in html
    assert "titleRightSpace=isGroup&&node.mission_partner_identified?65:12" in html
    assert "Mission Partner Identified Special Device Roles" in html
    assert "They are identification records, not a recommendation or proof of live operation." in html
    assert "Shift-click boxes to select and move them together" not in html
    assert "Use subnet toggles to select the endpoint view" not in html
    assert "placeLevel(" not in html
    assert 'id="resetLayout"' in html
    assert '<details class="evidence-files-drawer"><summary>Evidence files</summary>' in html
    assert html.index('id="fileNavigator"') > html.index('<summary>Evidence files</summary>')
    assert html.index('id="fileNavigator"') > html.index('</div><details class="evidence-files-drawer">')
    assert "enableNodeDrag" in html
    assert "function edgePanVelocity" in html
    assert "if(!event.ctrlKey&&!event.metaKey)return" not in html
    assert "syncLockedPresentationGeometry" not in html
    assert "Reset zoom · Use the wheel to zoom" in html
    assert "parentParkedHosts" in html
    assert "(!editMode||node.kind!=='host')" not in html
    assert "if(editMode){buildGroups();for" not in html
    assert "const autoPanDrag=" in html
    assert "requestAnimationFrame(autoPanDrag)" in html
    assert "canvas.scrollLeft+=panX" in html
    assert "canvas.scrollTop+=panY" in html
    assert "cancelAnimationFrame(panFrame)" in html
    assert "manualPositions" in html
    assert "updateEdgeGeometry" in html
    assert 'id="edgeStyle"' in html
    assert "Lines: Right-angle trunks" in html
    assert "function selectedEdgeIsOrthogonal" in html
    assert "edgeStyle=snapshot.edgeStyle||'direct'" in html
    assert "connection line style" in html
    assert "Lines: Hybrid backbone" in html
    assert 'id="edgeTools"' in html
    assert 'id="edgeRouteStyle"' in html
    assert "function effectiveConnectionStyle" in html
    assert "function enableEdgeRouteHandle" in html
    assert "edgeRoutes=new Map()" in html
    assert 'id="gridSnap"' in html
    assert "Grid: 20 px" in html
    assert "Grid: 40 px" in html
    assert "function snapCoordinate" in html
    assert "gridSize" in html
    assert 'id="lineMagnet"' in html
    assert "lineMagnet" in html
    assert 'id="annotationTools"' in html
    assert 'id="addLabel"' not in html
    assert 'id="addText"' in html
    assert 'id="addBox"' in html
    assert 'id="addEllipse"' in html
    assert "annotations=new Map()" in html
    assert "function renderAnnotations" in html
    assert 'id="annotationRotation"' in html
    assert "function enableAnnotationRotation" in html
    assert "annotationTransform(item)" in html
    assert 'class:\'annotation-rotate\'' in html
    assert 'id="mergeAnnotations"' in html
    assert "function mergeOverlappingAnnotations" in html
    assert "Group touching shapes" in html
    assert "function annotationGroupEntries" in html
    assert "function annotationFollowersForNodeMove" in html
    assert "contained.filter(id=>moving.has(id)).length<=contained.length/2" in html
    assert "function nearestShapeForLabel" in html
    assert "const attached of attachedLabelsForShapes(ids)" in html
    assert "function rotateAnnotationEntries" in html
    assert "function renderCompositeAnnotationOutlines" in html
    assert "feMorphology" in html
    assert "operator:'out'" in html
    assert ".map-annotation.region.grouped .annotation-shape{fill-opacity:0}" in html
    assert "function enableMapControlsDragging" in html
    assert "function setMapControlsCorner" in html
    assert "function updateMapControlsCanvasBounds" in html
    assert "nct-map-controls-corner-v1" in html
    assert "Map controls · drag to move" in html
    assert 'id="mapFilesPanel"' in html
    assert 'id="exportControlGrid"' in html
    assert 'id="mapFilesButton"' not in html
    assert 'id="mapFilesDialog"' not in html
    assert ".map-annotation.region .annotation-text{display:none}" in html
    assert 'id="gatewayGrouping"' in html
    assert "Gateway groups: Joined" in html
    assert "Gateway groups: Separate" in html
    assert "function applyGatewayCompoundLayout" in html
    assert "function renderGatewayCompounds" in html
    assert "function expandGatewayCompanions" in html
    assert 'id="toggleEditMode"' in html
    assert 'id="parkingLot"' in html
    assert 'id="mapControlSidebar"' in html
    assert 'id="toggleMapControls"' in html
    assert 'id="mapLegendOverlay"' in html
    assert 'id="toggleLegend"' in html
    assert 'id="mapFaqPanel"' not in html
    assert "Map Controls explains and manages point-to-point labels" in SHELL_SCRIPT
    assert 'id="connectionQueue"' in html
    assert 'id="parkSelection"' in html
    assert "Start with blank canvas" in html
    assert "Endpoints stay grouped inside their subnet" in html
    assert "parkedNodeIds=new Set()" in html
    assert "function renderParkingLot" in html
    assert "function stagedMapView" in html
    assert "function relationshipDirection" in html
    assert "function dependencyEntries" in html
    assert "function parkMapObjects" in html
    assert "function placeMapObjects" in html
    assert "function startBlankMap" in html
    assert 'id="parkAllUnlocked"' in html
    assert "function parkAllUnlockedObjects" in html
    assert "New infrastructure is parked automatically when a saved layout has locked objects" in html
    assert "if(!editMode)return" in html
    assert "event.key==='Delete'||event.key==='Backspace'" in html
    assert "const selectedNodeIds=new Set()" in html
    assert "function selectMapNode" in html
    assert "function selectionBranchIds" in html
    assert "endpointModes.get(id)==='individual'" in html
    assert "groupHosts.get(id)||[]" in html
    assert "targets.every(target=>selectedNodeIds.has(target))" in html
    assert "Shift-click a subnet to select its full host branch" not in html
    assert "function clearMapSelection" in html
    assert 'id="selectionTools"' in html
    assert 'id="toggleSelectionLock"' in html
    assert "function toggleSelectedLocks" in html
    assert "function alignSelection" in html
    assert "function distributeSelectedNodes" in html
    assert "function arrangeSelectedNodes" in html
    assert "lockedNodeIds=new Set()" in html
    assert "lockedNodeIds.has(node.id)" in html
    assert "knownNodeIds:[...topologyParkingUnitIds()]" in html
    assert "snapshot.knownNodeIds||[...(snapshot.manualPositions||[]).map(entry=>entry[0])" in html
    assert "function protectLockedLayoutFromNewObjects" in html
    assert "moved to the parking lot to protect the locked layout" in html
    assert "function clearUnlockedManualPositions" in html
    assert "manualPositions.set(id,{x:box.x,y:box.y})" in html
    assert "function ensureLockedNodePositions" in html
    assert "ensureLockedNodePositions();svg.replaceChildren()" in html
    assert "ensureLockedNodePositions(positions);currentPositions=positions" in html
    assert "WAN / outside interface" in html
    assert "Anchor WAN at top center" in html
    assert "function suggestedWanInterface" in html
    assert "function setWanAnchor" in html
    assert "function clearWanAnchor" in html
    assert "wanAnchor:wanAnchor?{...wanAnchor}:null" in html
    assert 'id="wanBoundaryMarker"' in html
    assert 'id="wanBoundaryInterface"' in html
    assert "wanBoundaryRail.id='wanBoundaryRail'" in html
    assert "function updateWanBoundaryMarker" in html
    assert "externalPortal=Boolean(wanAnchor&&externalWanGatewayId===wanAnchor.nodeId&&wanGatewayPresentation==='portal')" in html
    assert "active=Boolean(wanAnchor&&!externalPortal&&!hiddenNodeIds.has(wanAnchor.nodeId)" in html
    assert "function updateWanUplinkGeometry" in html
    assert "function externalWanAttachmentId" in html
    assert "function wanUplinkSourceId" in html
    assert "function wanGatewayIdsForView" in html
    assert "function applyExternalGatewaySemantics" in html
    assert "externalWanGatewayIds=new Set()" in html
    assert 'id="wanReadinessNotice"' in html
    assert "WAN gateway not identified" in html
    assert 'href="/device-config#wanDesignationPanel"' in html
    assert "gateways.length||semantic?.air_gapped" in html
    assert "Use as secondary External WAN gateway" in html
    assert "class:'wan-uplink'" in html
    assert "WAN through ${wanAnchor.label}" in html
    assert "idealScreenX=originX+sourceX*zoomLevel" in html
    assert "targetX=(targetScreenX-originX)/zoomLevel" in html
    assert "deviceVisible=!isolated" in html
    assert "searchMatches.includes(sourceId)" in html
    assert "rail.hidden=!deviceVisible" in html
    assert "addEventListener('scroll',updateWanUplinkGeometry" in html
    assert 'data-context-action="wan"' in html
    assert 'data-context-action="external-wan"' in html
    assert "Mark as External WAN gateway" in html
    assert "function setExternalWanGateway" in html
    assert "function clearExternalWanGateway" in html
    assert "externalWanGatewayId" in html
    assert "function appendExternalWanOrb" in html
    assert "class:'external-wan-ring'" in html
    assert "class:'external-wan-device-core'" in html
    assert "svgEl('textPath'" in html
    assert "external-wan-top-${safeId}" in html
    assert "external-wan-bottom-${safeId}" in html
    assert "externalWanGatewayId!==wanAnchor.nodeId" in html
    assert 'id="hideSelection"' in html
    assert 'id="hiddenObjectsPanel"' in html
    assert 'id="hiddenObjectsList"' in html
    assert 'id="restoreAllHidden"' in html
    assert "function hideMapObjects" in html
    assert "function restoreHiddenObjects" in html
    assert "hiddenNodeIds:[...hiddenNodeIds]" in html
    assert 'id="layoutName"' in html
    assert 'id="savedLayouts"' in html
    assert 'id="saveLayout"' in html
    assert 'id="loadLayout"' in html
    assert 'id="setDefaultLayout"' in html
    assert 'id="deleteLayout"' in html
    assert 'id="shareLayout"' in html
    assert "layoutStorageKey='nct-map-layouts-v1'" in html
    assert "function readNamedLayouts" in html
    assert "function saveNamedLayout" in html
    assert "function loadNamedLayout" in html
    assert "private browser layout" in html
    assert "function initializeNamedLayouts" in html
    assert "function setSelectedLayoutDefault" in html
    assert "defaultLayoutStorageKey='nct-map-default-layout-v1'" in html
    assert "if(editMode)for(const [id,box] of currentPositions)" in html
    assert "manual.x+size.w+30" in html
    assert "manual.y+size.h+30" in html
    assert "'/api/workspaces/layouts'" in html
    assert "serverWorkspaceAnalyst" in html
    assert "expected_version" in html
    assert "function publishSelectedLayout" in html
    assert 'id="overlayMode"' in html
    assert 'id="transitVisibility"' in html
    assert "/30 and /31 labels: Hidden" in html
    assert "hide_label:!showPointToPointTransit" in html
    assert "&& !edge.hide_label".replace(" ", "") in html.replace(" ", "")
    assert 'id="overlayLegend"' in html
    assert "function overlayClass" in html
    assert "function updateOverlayLegend" in html
    assert "function networkDeviceVendor" in html
    assert "vendor-${deviceVendor}" in html
    assert "vendor-swatch vendor-${key}" in html
    assert "overlay-exposure-dense" in html
    assert "overlay-gap-conflict" in html
    assert "dragIds=expandGatewayCompanions(selectedNodeIds.has(node.id)" in html
    assert "currentNodeElements.get(id)?.setAttribute" in html
    assert 'id="selectionStatus"' in html
    assert "Config zone" in html
    assert "node.zone_names" in html
    assert 'id="zoomOut"' in html
    assert 'id="zoomIn"' in html
    assert 'id="zoomFit"' in html
    assert ">Fit devices</button>" in html
    assert "function setZoom" in html
    assert "function fitMap" in html
    assert "function currentContentBounds" in html
    assert "currentPositions=new Map()" in html
    assert "currentPositions=positions" in html
    assert "function enableCanvasNavigation" in html
    assert 'id="searchResultCount"' in html
    assert 'id="searchPrevious"' in html
    assert 'id="searchNext"' in html
    assert 'id="toggleIsolate"' in html
    assert "function navigateSearch" in html
    assert "classList.toggle('search-match'" in html
    assert "classList.toggle('isolated-out'" in html
    assert "function zoomDetailLevel" in html
    assert "lod-overview" in html
    assert "lod-summary" in html
    assert "lod-evidence" in html
    assert 'id="detailLevel"' in html
    assert "function nodeZoomDetail" in html
    assert "class:'node-zoom-detail'" in html
    assert 'id="miniMap"' in html
    assert 'class="minimap-title"' not in html
    assert "id:'miniViewport'" in html
    assert "function renderMinimap" in html
    assert "function navigateFromMinimap" in html
    assert "canvas.addEventListener('scroll',updateMinimapViewport" in html
    assert 'id="minimapSize"' in html
    assert 'id="toggleMinimap"' in html
    assert "function setMinimapSize" in html
    assert "function setMinimapVisibility" in html
    assert "event.deltaY<0?1.12:.89" in html
    assert "contentX=(canvas.scrollLeft+point.x)/previous" in html
    assert "canvas.classList.add('panning')" in html
    assert "requestAnimationFrame(centerMap)" in html
    assert 'id="undoLayout"' in html
    assert 'id="redoLayout"' in html
    assert "function capturePresentation" in html
    assert "minimapSize:$('minimapSize')?.value||'medium'" in html
    assert "defaultEndpointSort" in html
    assert "function undoPresentation" in html
    assert "function redoPresentation" in html
    assert "undoStack.length>50" in html
    assert 'id="layoutPreset"' in html
    assert "function gridLayout" in html
    assert "function hierarchyLayout" in html
    assert "function layoutForView" in html
    assert "layoutMode==='grid'" in html
    assert 'id="toggleLasso"' in html
    assert "class:'lasso-box'" in html
    assert "function setLassoMode" in html
    assert "lassoState={start,current:start,rect" in html
    assert 'id="mapContextMenu"' in html
    assert "function showContextMenu" in html
    assert "function runContextAction" in html
    assert "group.oncontextmenu" in html
    assert "function handleMapKeydown" in html
    assert "ArrowLeft:[-1,0]" in html
    assert "event.shiftKey&&key==='r'" in html
    assert "alignSelection('row')" in html
    assert "event.shiftKey&&key==='c'" in html
    assert "alignSelection('column')" in html
    assert 'title="Shift+R"' in html
    assert 'title="Shift+C"' in html
    assert 'aria-keyshortcuts="Shift+R"' in html
    assert 'aria-keyshortcuts="Shift+C"' in html
    assert 'id="fitSelection" class="secondary" title="F" aria-keyshortcuts="F"' in html
    assert 'id="toggleSelectionLock" class="secondary" title="L" aria-keyshortcuts="L"' in html
    assert "selectedNodeIds.size?fitSelectedNodes():fitMap()" in html
    assert "key==='l'&&!event.shiftKey&&selectedNodeIds.size" in html
    assert "$('toggleLasso').title='B'" in html
    assert "Ctrl+Z · Undo" in html
    assert 'aria-label="Map scaling controls"' in html
    assert "function deviceAddressLines" in html
    assert "Primary / observed MAC" in html
    assert "iface.mac" in html
    assert "...addresses,iface.mac" not in html
    assert "i.mac_vendor" in html
    assert "No IPv4 address" in html
    assert "function networkDeviceType" in html
    assert "function networkDeviceEvidence" in html
    assert "function appendDeviceSymbol" in html
    assert "symbol-router" in html
    assert "M7 15h16M15 7v16M7 15l3-2" in html
    assert "symbol-firewall" in html
    assert "symbol-switch" in html
    assert "Switch-port placement evidence" in html
    assert "switchport_learning" in html
    assert "Learned forwarding entries" in html
    assert "symbol-wireless" in html
    assert "device-identity-inferred" in html
    assert "Confirmed from collected device configuration" in html
    assert 'title="Previous search result"' in html
    assert 'title="Next search result"' in html
    assert "Restore all devices, hosts, and connections" in html
    assert "function connectionLabelLines" in html
    assert "edge-label-line edge-label-detail" in html
    assert "#map.lod-summary .edge-label-detail" in html
    assert "cursor:help; pointer-events:auto" in html
    assert "function nodeDimensions" in html
    assert "w:250,h:68" in html
    assert "interfaceCount" in html
    assert 'class="map-inventory-bar" id="mapSummary"' in html
    assert 'id="summaryCompact"' in html
    assert '.map-inventory-bar{position:relative' in html
    assert '.map-inventory-bar{position:sticky' not in html
    assert '<summary>Network inventory' not in html
    assert 'id="edgeCount"' not in html
    assert 'id="sourceCount"' not in html
    assert ".workspace>aside { display:none; }" in html
    assert ".workspace.map-expanded .map-shell>#details { display:block;" in html
    assert 'id="toggleWorkspace"' in html
    assert '.zoom-controls #toggleWorkspace{margin-left:auto}' in html
    assert 'id="mapLayoutPanel"' in html
    assert 'id="layoutControlGrid" class="map-layout-grid"' in html
    assert "map-layout-field-action new-layout-group" in html
    assert "newLayoutGroup.append($('layoutName'),$('saveLayout'))" in html
    assert "savedLayoutGroup.append($('savedLayouts'),$('loadLayout'),$('setDefaultLayout'))" in html
    assert 'id="currentLayoutName">Unsaved working layout' in html
    assert 'id="mapMissingCount">0' in html
    assert 'id="parkingCountCompact">0' in html
    assert 'id="hiddenCountCompact">0' in html
    assert "function updateLayoutWorkspaceStatus()" in html
    assert '<h2>Layout</h2>' not in html
    assert 'class="workspace-toggle-dock"' not in html
    assert 'id="expandedWorkspaceControls" class="expanded-workspace-controls"' in html
    assert "expandedControls.append(fitButton,mapControlsButton,button)" in html
    assert "scaleControls.insertBefore(editButton,$('detailLevel'))" in html
    assert "layoutGrid.insertBefore(editButton,$('layoutPreset'))" in html
    assert "scaleControls.insertBefore(fitButton,$('gridSnap'))" in html
    assert "scaleControls.insertBefore(mapControlsButton,$('toggleLegend'))" in html
    assert "#detailLevel,#overlayLegend{display:none!important}" in html
    assert "--expanded-safe-top" in html
    assert "function expandedControlSafeTop" in html
    assert "controlsRect.bottom-shellRect.top+8" in html
    assert ".workspace.map-expanded .zoom-controls #toggleEditMode" in html
    assert "button.textContent='↙'" in html
    assert ".workspace.map-expanded #zoomFit{border-color:var(--accent);background:var(--accent)" in html
    assert "scaleControls.append(button)" in html
    assert "workspaceExpandButton.textContent='↗'" in html
    assert ".map-layout-actions:empty{display:none}" in html
    assert "body[data-nct-task=mapWorkspace] #nct-page-context{display:none}" in SHELL_SCRIPT
    assert 'id="toggleDetails"' in html
    assert 'id="selectedObjectSummary"' in html
    assert "function renderSelectedObjectSummary(node)" in html
    assert "Open full details" in html
    assert "function openSelectedObjectDetails(){detailsSuppressed=false;toggleWorkspace(true);syncDetailsVisibility(true);requestAnimationFrame" in html
    assert "open.onclick=openSelectedObjectDetails" in html
    assert "section.dataset.guideContext='mission-special-role-details'" in html
    assert "section.tabIndex=0" in html
    assert "target.focus({preventScroll:true})" in html
    assert "IP / network" in html
    assert "Hostname" in html
    assert "Ports" in html
    assert "Operating system" in html
    assert "Map object actions and WAN / Reach roles" in html
    assert "Display only:" in html
    assert "Use WAN Designation to choose the gateway used by Reach" in html
    assert "object-evidence" in html
    assert "Evidence (${(node?.sources||[]).length})" in html
    assert "openSelectedDetails:['Open full object details'" in SHELL_SCRIPT
    assert "Mission Partner Identified special-device role" in SHELL_SCRIPT
    assert "turn an evidence-only possible match into an identified device" in SHELL_SCRIPT
    assert "control?.matches?.('.object-evidence > summary')" in SHELL_SCRIPT
    assert "control?.matches?.('.map-role-controls > summary')" in SHELL_SCRIPT
    assert "The counts stay in normal page flow" in SHELL_SCRIPT
    assert 'class="details-control"' in html
    assert ".details-control{display:none}.workspace.map-expanded .details-control{display:flex}" in html
    assert 'id="workspaceSize"' in html
    assert "Large network · 4× area" in html
    assert ".workspace.map-expanded .details-control" in html
    assert ".workspace.map-expanded .map-shell { display:flex; flex:1 1 auto" in html
    assert ".workspace.map-expanded{inset:0}" in html
    assert ".workspace.map-expanded>.map-panel>:not(.map-shell){display:none!important}" in html
    assert ".workspace.map-expanded .canvas{border:0;border-radius:0}" in html
    assert "body.map-expanded #nct-operator-guide{z-index:360}" in html
    assert "body.map-expanded #nct-guide-toggle{z-index:380}" in html
    assert 'id="wanGatewayPresentation"' in html
    assert "WAN gateway: Portal" in html
    assert "WAN gateway: Top anchor" in html
    assert "wanGatewayPresentation==='top'" in html
    assert "wanGatewayPresentation==='portal'" in html
    assert "wanGatewayPresentation," in html
    assert ".workspace.map-expanded .canvas { flex:1 1 auto; height:auto; min-height:0" in html
    assert "workspace.map-expanded" in html
    assert "workspace.map-expanded.details-collapsed" in html
    assert "workspace.map-expanded.details-collapsed .map-shell>#details" in html
    assert ".workspace.map-expanded.details-collapsed .selected-object-summary{margin:var(--expanded-safe-top,70px) 12px 8px}" in html
    assert ".workspace.map-expanded.details-collapsed #openSelectedDetails{grid-column:1;grid-row:2;justify-self:start}" in html
    assert ".workspace.map-expanded .map-shell>#details" in html
    assert "function syncExpandedDetailsBounds" in html
    assert "function expandedFloatingControlsSafeTop" in html
    assert "scaleRect?scaleRect.bottom-shellRect.top+8:inset" in html
    assert "--expanded-safe-top',`${expandedSafeTop}px`" in html
    assert "shell.appendChild(details)" in html
    assert "workspace.appendChild(details)" in html
    assert "function toggleDetailsVisibility" in html
    assert "function syncDetailsVisibility" in html
    assert "detailsSuppressed=false" in html
    assert "workspace.classList.toggle('details-empty',!hasSelection)" in html
    assert "workspace.classList.toggle('details-collapsed',detailsSuppressed)" in html
    assert ".workspace.details-empty,.workspace.details-collapsed" in html
    assert "Details: Auto" in html
    assert "requestAnimationFrame(syncExpandedDetailsBounds)" in html
    assert "availableWidth=Math.max(canvas.clientWidth-22,1)" in html
    assert "width=Math.max(width,availableWidth)" in html
    assert "height=Math.max(height,availableHeight)" in html
    assert "if(width/height<canvasRatio)width=Math.ceil(height*canvasRatio)" in html
    assert "expandedMapExtent=null" in html
    assert "workspaceAreaScale=4" in html
    assert "Screen · 1× area" not in html
    assert "dimensionScale=Math.sqrt(workspaceAreaScale)" in html
    assert "$('workspaceSize').onchange" in html
    assert "expandedMapExtent={width,height}" in html
    assert "else if(expandedMapExtent)" in html
    assert "function fitWorkspace" in html
    assert "function preserveLockedNodePositions" in html
    assert "if(!expanded){preserveLockedNodePositions();expandedMapExtent={...mapSize};}" in html
    assert "if(expanded){setZoom(1);centerMap();}else fitMap()" in html
    assert ".canvas.map-centered-x { justify-content:center; }" in html
    assert ".canvas.map-centered-y { align-items:center; }" in html
    assert "renderedWidth<=canvas.clientWidth" in html
    assert "renderedHeight<=canvas.clientHeight" in html
    assert "svgRect.left-canvasRect.left" in html
    assert "renderMap();setZoom(zoomLevel);" in html
    assert "Show details" in html
    assert "Hide details" in html
    assert "Exit expanded workspace" in html
    assert "event.key==='Escape'" in html
    assert 'id="groupAll"' not in html
    assert 'id="expandAll" class="secondary">Expand all' in html
    assert 'id="collapseAll" class="secondary">Collapse all' in html
    assert 'id="endpointSort"' in html
    assert "endpointModes=new Map()" in html
    assert "endpointStyles=new Map()" in html
    assert "mode==='collapsed'" in html
    assert "Individual connection lines" in html
    assert "Grouped inside subnet" in html
    assert "function groupedEndpointSections" in html
    assert "numeric:true,sensitivity:'base'" in html
    assert "function groupedNodeDimensions" in html
    assert "return [...grouped].map" in html
    assert "return 'IP addresses'" in html
    assert "const showHeadings=sort!=='ip'&&grouped.size>1" in html
    assert "showHeading:showHeadings" in html
    assert "'text-anchor':'middle'" in html
    assert "Math.floor(index/section.rows)" in html
    assert "(continued)" not in html
    assert "group-host-row" in html
    assert "function appendEndpointNodeControls" in html
    assert "View: ${style==='grouped'?'Grouped':'Individual'}" in html
    assert "function toggleGroupVisibility" in html
    assert "function setAllEndpointVisibility" in html
    assert "IP address (one sorted pool)" in html
    assert "function endpointOsFamily" in html
    assert "group-host-row os-${endpointOsFamily(host)}" in html
    assert "rowTip.textContent=osInferenceTitle(host)" in html
    assert "function osIdentityHtml(host)" in html
    assert "host.os_inference?' os-inferred':''" in html
    assert "Windows host" in html
    assert "Linux host" in html
    assert "Unknown OS" in html
    assert ".group-host-row.os-windows rect" in html
    assert ".group-host-row.os-linux rect" in html
    assert ".group-host-row.os-unknown rect" in html
    assert "function enableGroupedResize" in html
    assert "group-resize-handle" in html
    assert "Resize grouped boxes from the lower-right corner" not in html
    assert "groupedSizes.clear()" in html
    assert ">Sort by IP</option>" in html
    assert "Group / sort by hostname" in html
    assert "Group / sort by OS" in html
    assert "local to the current analyst browser" in html
    assert "does not change shared evidence or another analyst's view" in html
    refresh_group = html.split("function refreshGroupPresentation", 1)[1].split("function setGroupStyle", 1)[0]
    all_visibility = html.split("function setAllEndpointVisibility", 1)[1].split("function syncExpandedDetailsBounds", 1)[0]
    endpoint_sort = html.split("$('endpointSort').onchange", 1)[1].split("$('workspaceSize').onchange", 1)[0]
    assert "clearUnlockedManualPositions" not in refresh_group
    assert "clearUnlockedManualPositions" not in all_visibility
    assert "clearUnlockedManualPositions" not in endpoint_sort
    layout_preset = html.split("$('layoutPreset').onchange", 1)[1].split("$('resetLayout').onclick", 1)[0]
    assert "clearUnlockedManualPositions" in layout_preset
    assert "function edgeAnchor" in html
    assert "No interface IPs parsed" in html
    assert 'id="topologyNeighborCount"' in html
    assert "Confirmed identity" in html
    assert "LLDP/CDP identity" in html
    assert "edge.relation==='topology_neighbor'" in html


def test_automated_and_imported_results_share_the_same_renderer():
    html = analysis_page().body.decode()
    assert "renderAnalysis(item.analysis" in html
    assert "renderAnalysis(data.analysis" in html
    assert 'id="analysisWarnings"' in html
    assert "renderAnalysisWarnings" in html
    assert "Analysis cautions" in html
    assert "prepareRunComparison" in html
    assert "Comparison opened with the selected scan as the later scan" in html
    assert "$('networkChangesPanel').scrollIntoView({behavior:'smooth',block:'start'})" in html
    assert "Export host summary CSV" in html
    assert "Export port-level CSV" in html
    assert "compactExportLabel" in html
    assert "function readableScope" in html
    assert "function analysisScopeLabel" in html
    assert "const reference=scanRef" in html
    assert "display_name:reference.primary" in html
    assert "title=\"${esc(reference.detail)}\"" in html
    assert "metadata.saved_networks" in html
    assert "metadata.group?.scope?.excluded_address_count" in html
    assert "function comparisonLabel(item){return scanRef(item).selection}" in html
    assert "`${currentLabel}-hosts.csv`" in html
    assert "`${currentLabel}-ports.csv`" in html
    assert "MAC / vendor" in html
    assert "Network changes and scan comparison" in html
    assert 'id="comparisonBaseline"' in html
    assert 'id="comparisonCurrent"' in html
    assert "Compare two specific scans" in html
    assert "if(runId)await openRun(runId)" in html
    assert "focusRequestedEvidence()" in html
    assert "coverage_warnings" in html
    assert 'id="comparisonResult"' in html
    assert ">Compare scans</button>" in html
    assert "/api/scan-comparisons/candidates" in html
    assert "/api/scan-comparisons/compare" in html
    assert "Previous scans" not in html
    assert 'id="automatedHistory"' not in html
    assert 'class="panel previous-scans-panel"' not in html
    assert "Affected addresses and evidence" in html
    assert "Explicit source-reported port, service, product, or version changes" in html
    assert "Traceroute path change" in html
    assert "renderComparisonDetails" in html


def test_analyze_opens_with_a_paginated_network_wide_current_evidence_view():
    html = analysis_page().body.decode()

    assert 'id="networkOverview"' in html
    assert "Current network evidence" in html
    assert "Newest retained Nmap results and device configuration evidence" in html
    assert "/api/analysis/network/page?${params}" in html
    assert "/api/analysis/network/outliers?${params}" in html
    assert "/api/analysis/network/ips?${params}" in html
    assert 'id="networkFocus"' in html
    assert 'value="ip">IP address</option>' in html
    assert 'value="port">Lowest observed port</option>' in html
    assert 'value="service">Service name</option>' in html
    assert 'value="mac">MAC address</option>' in html
    assert 'value="hostname">Hostname</option>' in html
    assert 'value="os">Operating system</option>' in html
    assert 'value="last">Last observed</option>' in html
    assert 'id="networkHostRows"' in html
    assert 'id="networkPageSize"' in html
    assert 'class="network-workflow" aria-label="Inventory organization controls"' in html
    assert 'class="network-table-controls" aria-label="Host Inventory table controls"' in html
    assert html.index('id="networkSearch"') < html.index('id="networkPageSize"')
    assert html.index('id="networkPageSize"') < html.index('id="networkPrevious"')
    assert "renderNetworkInventory" in html
    assert "networkEvidenceDetails" in html
    assert "Evidence and history" in html
    assert "if(task==='networkOverview'){if(!analysisLoadedTasks.has(task)){const loaded=await loadNetworkOverview();if(loaded&&ownsTask())" in html
    assert "scanRef(item).primary" in html
    assert "Open one specific retained scan" in html
    assert 'id="retainedScanSelect"' in html
    assert "currentNetwork.hosts" in html
    assert 'id="networkOutliersPanel"' in html
    assert "Least Frequency Analysis (LFA)" in html
    assert "The Subnet filter in Host Inventory recalculates this view" in html
    assert 'id="lfaThreshold"' in html
    assert 'min="1" max="50" step="1" value="20"' in html
    assert 'id="lfaThresholdValue"' in html
    assert "Number(item.affected_count||0)/Math.max(1,Number(group.member_count||0))" in html
    assert "$('lfaThreshold').oninput=updateLfaThreshold" in html
    assert "renderNetworkOutliers" in html
    assert "function lfaAffectedHosts(item)" in html
    assert 'class="lfa-host-list"' in html
    assert 'class="lfa-list-closed">show list' in html
    assert 'class="lfa-list-open">hide list' in html
    assert ".lfa-host-list-body{max-height:none;overflow:visible" in html
    assert '.lfa-host-list-body:focus{outline:2px solid var(--accent)' in html
    assert 'role="region" tabindex="0" aria-label="${esc(label)}"' in html
    assert "Affected addresses for ${item.port||'unknown'}/${item.protocol||'unknown'}" in html
    assert 'data-nct-table-mode="page" data-nct-guide-mode="contained" data-nct-narrow-mode="contained"' in html
    assert "@media(min-width:851px){body.nct-shell.nct-guide-open .table-wrap[data-nct-guide-mode=contained]" in SHELL_SCRIPT
    assert "max-width:1600px" not in html
    assert ".table-wrap[data-nct-guide-mode=contained]>table>thead>tr>th{position:static!important;top:auto!important;z-index:auto}" in SHELL_SCRIPT
    assert "@media(max-width:1400px){body.nct-shell .table-wrap[data-nct-narrow-mode=contained]" in SHELL_SCRIPT
    assert ".table-wrap[data-nct-narrow-mode=contained]>table>thead>tr>th{position:static!important;top:auto!important;z-index:auto}" in SHELL_SCRIPT
    assert 'aria-label="Current network evidence table"' in html
    assert ".table-wrap[data-nct-table-mode]:focus{outline:2px solid var(--nct-accent,var(--accent))" in SHELL_SCRIPT
    assert "The table grows with the page so vertical navigation uses the main page scrollbar" in html
    assert "use the table's horizontal scrollbar only when extra columns do not fit" in html
    assert '<div class="table-wrap" data-nct-table-mode="static"><table><thead><tr><th>Uncommon port</th>' in html
    assert html.index("<thead><tr><th>Uncommon port</th>") < html.index("<tbody>${group.unusual.map")
    assert 'id="networkChangesPanel"' in html
    assert 'id="loadNetworkChanges"' in html
    assert "/api/analysis/network-changes" in html
    assert "renderNetworkChanges" in html
    assert "Some traceroute paths were not assessed" in html
    assert "paths not assessed" in html
    assert "Processed evidence by Network Scope" in html
    assert 'id="processedEvidenceScope"' in html
    assert 'id="loadProcessedEvidence"' in html
    assert "/api/foundation-evidence/scopes" in html
    assert "Open saved source records" in html
    assert "Open latest supported observations" in html
    assert "/latest-observations?${params}" in html
    assert "Open latest source-reported service state" in html
    assert "/current-service-states?${params}" in html
    assert "Open last confirmed open source window" in html
    assert "/last-confirmed-open?${params}" in html
    assert "The saved Nmap source explicitly reported this port" in html
    assert "not a live check or exact Last Seen time" in html
    assert "data-last-open-service" in html
    assert "target.dataset.lastOpenRequest!==request" in html
    assert "data-last-open-page" in html
    assert "A later scan that did not assess a port shows Not assessed" in html
    assert "Why this source was selected" in html
    current_service_renderer = html.split("function renderCurrentServiceStates", 1)[1].split(
        "async function openCurrentServiceStates", 1
    )[0]
    assert "Selection contract:" not in current_service_renderer
    assert "target.dataset.currentServiceRequest!==request" in html
    assert "data-current-service-states" in html
    assert ".processed-evidence-endpoint.current-services-open{grid-column:1/-1}" in html
    assert ".processed-evidence-current-services thead th{position:static;top:auto}" in html
    assert "card.classList.add('current-services-open')" in html
    assert "Open supporting source evidence" in SHELL_SCRIPT
    assert ".processed-evidence-current-services details > summary" in SHELL_SCRIPT
    assert "collection window and the retained evidence link" in SHELL_SCRIPT
    assert "Last confirmed open source window" in SHELL_SCRIPT
    assert "[data-last-open-service]" in SHELL_SCRIPT
    assert "A later closed result or narrower scan does not erase" in SHELL_SCRIPT
    assert "body.nct-shell.nct-guide-open>main" in SHELL_SCRIPT
    assert "@media(min-width:1101px){body.nct-shell.nct-guide-open>main" in SHELL_SCRIPT
    assert "@media(min-width:851px) and (max-width:1100px)" in SHELL_SCRIPT
    assert "body.nct-shell.nct-guide-open #nct-sidebar{display:none}" in SHELL_SCRIPT
    assert "margin-right:calc(var(--nct-guide-reserve,350px) + 28px)" in SHELL_SCRIPT
    assert "html[data-nct-density=compact] body.nct-shell.nct-guide-open>main" in SHELL_SCRIPT
    assert "html[data-nct-density=spacious] body.nct-shell.nct-guide-open>main" in SHELL_SCRIPT
    assert "--nct-guide-reserve" in SHELL_SCRIPT
    assert "Build network change view" in SHELL_SCRIPT
    assert "Loads the first five Network Scopes" in SHELL_SCRIPT
    assert "loaded counts cover only the scopes shown so far" in SHELL_SCRIPT
    assert "Compare the selected saved analyses" in SHELL_SCRIPT
    assert "Review affected hosts" in SHELL_SCRIPT
    assert "Last confirmed observation" in html
    assert "Latest supported observation" in html
    assert "Successful records whose order is uncertain" in html
    assert "At least one successful record has no trustworthy collection window" in html
    assert "That missing time could fall before, between, or after the displayed rows" in html
    assert "They do not prove a live device joined, left, or changed identity" in html
    assert "confirmed only later" in html
    assert "Saved evidence windows, not live status" in html
    assert "processedEvidenceSource(record.source)" in html
    assert "data-latest-page" in html
    assert "Open ${serviceCount} reported service" in html
    assert "Follow address evidence for ${esc(item.normalized)}" in html
    assert "Reported IP associations for this MAC" in html
    assert "They do not prove one physical device, DHCP movement" in html
    assert "No match does not prove absence" in html
    assert "/mac-associations?${params}" in html
    assert "selection_revision" in html
    assert "target.dataset.macRequest!==signature" in html
    assert "bindMacAssociations(target)" in html
    assert ".processed-evidence-endpoint.receipts-open{grid-column:1/-1}" in html
    assert "card.classList.add('receipts-open')" in html
    assert ".processed-evidence-mac-item .meta{overflow-wrap:anywhere}" in html
    assert "Processed source records for this scope" in html
    assert "Use as Record A" in html
    assert "Use as Record B" in html
    assert "Compare reported service states" in html
    assert "/service-comparison?${params}" in html
    assert "Lifecycle labels are used only when exact coverage supports the historical state transition" in html
    assert "Coverage-aware change" in html
    assert "Evidence result</strong> describes what each file reported" in html
    assert "what the files and their coverage allow us to conclude" in html
    assert "Not recorded</strong> means there is no individual service row" in html
    assert "the completed scan summary accounts for that exact port" in html
    assert "processedEvidenceLifecycleLabel" in html
    assert "does not prove the service is gone now" in html
    assert "Coverage-aware historical comparison complete" in html
    assert "processedEvidenceSelectionSignature" in html
    assert "comparison=historical?'':" in html
    assert "if(!run)return" in html
    assert "if(allowComparison)bindProcessedEvidenceComparisonRecords" in html
    assert "className='processed-evidence-comparison-status status good'" in html
    assert "className='processed-evidence-comparison-status status bad'" in html
    assert "Source reported presence" in html
    assert "File-reported coverage" in html
    assert "Coverage receipt ${esc(contract)}" in html
    assert "missing-service coverage" in html
    assert "No versioned coverage receipt is available" in html
    assert "aggregate timing and does not precisely date every service observation" in html
    assert "Addresses with separate history" in html
    assert 'id="loadMoreProcessedScopes"' in html
    assert "request!==processedEvidenceRequest" in html
    assert "do not claim live network truth" in html
    assert "loadProcessedEvidenceScopes" in html
    assert 'id="networkControlsPanel"' not in html
    assert '<span>Routes and policy</span>' not in html
    assert 'id="comparisonBaseline"' in html
    assert 'id="comparisonCurrent"' in html


def test_hunt_and_analyze_use_their_built_in_controls_without_global_table_toolbar():
    hunt_html = hunting_page().body.decode()
    analyze_html = analysis_page().body.decode()
    for html in (hunt_html, analyze_html):
        assert '/assets/nct-view-preferences.js' not in html
        assert 'data-workspace-card=' in html
    assert 'data-workspace-card="network-filters"' in hunt_html
    assert 'data-workspace-card="network-changes"' in analyze_html
    assert 'id="analysisHostRows"' in analyze_html
    assert 'id="networkPageSize"' in analyze_html
    assert 'id="networkFocus"' in analyze_html
    assert 'id="networkSearch"' in analyze_html
    assert "Table display" not in analyze_html
    assert "Table display" not in hunt_html


def test_expandable_sections_share_one_left_chevron_language():
    pages = {
        "nmap": operator_page().body.decode(),
        "device": device_config_page().body.decode(),
        "analyze": analysis_page().body.decode(),
        "device-analysis": device_analysis_page().body.decode(),
        "hunt": hunting_page().body.decode(),
        "reach": reachability_page().body.decode(),
        "map": network_map_page().body.decode(),
    }
    for html in pages.values():
        assert "content:'▶'" in html
        assert "rotate(90deg)" in html
        assert "::-webkit-details-marker" in html

    assert ".management-card>summary::after,.history-group>summary::after{content:none}" in pages["nmap"]
    assert ".management-card>summary::before,.history-group>summary::before" in pages["nmap"]
    assert ".advanced-drawer>summary::before,.advanced-panel>summary::before" in pages["nmap"]
    assert "details.device-history>summary::before,details.run-card>summary::before,.result-section>summary::before" in pages["device"]
    assert ".comparison-panel>summary::after{content:none}" in pages["analyze"]
    assert ".comparison-panel>summary::before,.comparison-host>summary::before" in pages["analyze"]
    assert "details>summary::before" in pages["device-analysis"]
    assert ".searchsploit-result>summary::before,.exposure-detail>summary::before" in pages["hunt"]
    assert ".report-source>summary::before,.report-destination>summary::before,.report-result>summary::before" in pages["reach"]
    assert 'class="report-destination"' in pages["reach"]
    assert "reportDestinationGroups" in pages["reach"]
    assert ".hidden-objects>summary::before" in pages["map"]
    assert ".evidence-files-drawer>summary::before" in pages["map"]


def test_collapsible_workspaces_shrink_to_the_available_width():
    nmap = operator_page().body.decode()
    device = device_config_page().body.decode()
    analyze = analysis_page().body.decode()

    assert 'id="responsive-collapsible-workspaces"' in nmap
    assert ".history-groups{grid-template-columns:minmax(0,1fr)}" in nmap
    assert ".history-body .table-wrap{min-width:0;max-width:100%;overflow-x:auto" in nmap
    assert ".history-table thead th{position:static}" in nmap
    assert ".history-run-actions{flex-wrap:wrap;white-space:normal}" in nmap
    assert 'id="responsive-collapsible-workspaces"' in device
    assert ".history-list,.run-list,.structured-results{grid-template-columns:minmax(0,1fr)}" in device
    assert "details.device-history,details.run-card,.result-section,.run-body{overflow:hidden}" in device
    assert 'id="responsive-collapsible-workspaces"' in analyze
    assert ".comparison-body-panel .table-wrap,.comparison-body .table-wrap{min-width:0;max-width:100%;overflow-x:auto" in analyze
    assert "body.nct-shell>main,body.nct-shell>main>*{min-width:0;max-width:100%}" in SHELL_SCRIPT
    assert "body.nct-shell main details>summary{box-sizing:border-box;min-width:0;max-width:100%;overflow-wrap:anywhere}" in SHELL_SCRIPT


def test_scan_history_distinguishes_scoped_evidence_from_saved_analysis():
    html = operator_page().body.decode()

    assert "This is separate from scoped evidence, which is ready." in html
    assert "run.foundation_status?.state==='foundation_complete'" in html


def test_nmap_advanced_operations_are_collapsed_without_removing_capability():
    html = operator_page().body.decode()

    assert 'id="scanPrerequisiteNotice"' in html
    assert 'id="scanBasicFields"' in html
    assert '<details id="availablePresetsPanel"' in html
    assert 'id="availablePresets"' in html
    assert '<details id="scanAdvancedOptions" class="advanced-drawer">' in html
    assert '<summary>Advanced scan options and pre-launch safety check</summary>' in html
    assert '<details class="advanced-drawer" id="profileManagementPanel">' in html
    assert '<summary>Scan profile management</summary>' in html
    assert '<details class="advanced-drawer" id="scheduledScansPanel">' in html
    assert '<summary>Scheduled scans</summary>' in html
    assert html.index('id="scheduledScansPanel"') < html.index('id="runNow"')


def test_scan_monitoring_workspace_is_only_visible_on_active_scans():
    assert "body[data-nct-task]:not([data-nct-task=queuePanel]) #queuePanel{display:none!important}" in SHELL_SCRIPT
    assert "support:{queuePanel:['currentRunPanel']}" in SHELL_SCRIPT


def test_scan_workspace_loads_only_the_selected_task_and_stops_hidden_work():
    html = operator_page().body.decode()

    assert "async function activateScanTask(" in html
    assert "async function ensureScanData(" in html
    assert "if(task==='profileManagementPanel'){await ensureScanData('profiles',loadProfiles);return}" in html
    assert "if(task==='queuePanel'){await syncActiveScanWorkspace();return}" in html
    assert "function stopHiddenScanWork()" in html
    assert "if(liveDiscoveryController){liveDiscoveryController.abort()" in html
    assert "if(scanDataLoaded.has('history'))await loadHistory(true)" in html
    assert "window.addEventListener('nct:taskchange',requestScanTaskActivation)" in html
    assert "await Promise.all([loadProfiles(),loadNetworkScopes(),loadSavedNetworks()" not in html


def test_scan_profile_workspace_removes_unrelated_scan_builder_controls():
    assert "body[data-nct-task=profileManagementPanel]" in SHELL_SCRIPT
    for selector in (
        ".builder-heading",
        "#scopeModeField",
        "#scanNameField",
        "#scopeSavedBox",
        "#scopeManualBox",
        "#networkScopeReview",
        "#scanLaunchActions",
        "#scheduledScansPanel",
    ):
        assert selector in SHELL_SCRIPT


def test_tcp_udp_top_scopes_are_allowed_and_split_by_the_backend():
    html = operator_page().body.decode()

    assert "normalizeCombinedScopes" not in html
    assert "TCP + UDP needs independent" not in html
    assert "$('protocol').addEventListener('change',()=>{showOptions();setDirty()})" in html
    assert "run.fallback_execution_phases" in html
    assert "FPING uses ICMP only" in html
    assert "Exact full-target commands awaiting authorization" in html
    assert "run.fallback_command_note" in html
    assert "zero replies do not prove that the subnet is empty" in html
    guide = how_nct_works_page().body.decode()
    assert "shows every separate TCP and UDP command for review" in guide
    assert html.index('id="runNow"') < html.index('id="profileManagementPanel"')
    for control_id in (
        "profileName",
        "saveProfile",
        "saveVersion",
        "cloneProfile",
        "deleteProfile",
        "saveSchedule",
        "refreshSchedules",
    ):
        assert f'id="{control_id}"' in html
def test_map_editing_exposes_safe_save_choices_and_direct_text_editing():
    html = network_map_page().body.decode()

    assert 'id="layoutDirtyBar"' in html
    assert 'id="saveCurrentLayout"' in html
    assert 'id="discardLayoutChanges"' in html
    assert 'id="unsavedLayoutDialog"' in html
    assert 'id="unsavedOverwrite"' in html
    assert 'id="unsavedSaveAsNew"' in html
    assert 'id="unsavedDiscard"' in html
    assert 'id="unsavedStay"' in html
    assert "function presentationFingerprint" in html
    assert "function layoutSaveBlocks" in html
    assert "function syncLayoutDirtyState" in html
    assert "function markLayoutClean" in html
    assert "function persistNamedLayout" in html
    assert "payload.layout_id=existing.layout_id" in html
    assert "payload.expected_version=existing.version" in html
    assert "newer map changes still need to be saved" in html
    assert "Map changes were not saved" in html
    assert "loading another layout" in html
    assert "starting another save" in html
    assert "visible map still has unsaved changes" in html
    assert "function openUnsavedLayoutDialog" in html
    assert "function saveBeforeLayoutTransition" in html
    assert "window.addEventListener('beforeunload'" in html
    assert "Leaving Map for" in html
    assert "event.stopImmediatePropagation()" in html
    assert 'id="expandedSaveCurrent"' in html
    assert 'id="expandedSaveAsNew"' in html
    assert 'id="expandedAddText"' in html
    assert 'id="reviewHiddenObjects"' in html
    assert "function beginAnnotationTextEdit" in html
    assert "group.ondblclick" in html
    assert "annotationClickRenderTimer=setTimeout" in html
    assert "Enter saves; Escape cancels" in html
    assert "event.key==='Escape'" in html
    assert "Device icons are currently inferred from retained evidence" in SHELL_SCRIPT


def test_scoped_vlan_context_is_shared_without_changing_other_results():
    for path in (
        "'/device-analysis'", "'/device-config'", "'/analysis'", "'/hunting'",
        "'/reachability'", "'/network-map'",
    ):
        assert path in SHELL_SCRIPT
    assert "panel.id='nct-scoped-vlan-context'" in SHELL_SCRIPT
    assert "if(location.pathname!=='/device-analysis')" in SHELL_SCRIPT
    assert "compact.id='nct-vlan-context-link'" in SHELL_SCRIPT
    assert "Open VLAN evidence" in SHELL_SCRIPT
    assert "Retained scoped VLAN evidence" in SHELL_SCRIPT
    assert "NCT does not attach it to an Nmap host by matching an IP address" in SHELL_SCRIPT
    assert "VLAN evidence does not change a Reach result" in SHELL_SCRIPT
    assert "NCT does not create Map segments or links" in SHELL_SCRIPT
    assert "It does not create a capability, CVE candidate, host identity" in SHELL_SCRIPT
    assert "does not claim a VLAN was added, removed, or changed" in SHELL_SCRIPT
    assert "tableWrap.dataset.nctTableMode='contained'" in SHELL_SCRIPT
    assert "for(const label of ['Network Scope','Reporting device','Coverage','Retained VLAN evidence','Source'])" in SHELL_SCRIPT
    assert "textContent=pageNotes()" in SHELL_SCRIPT
    assert "sourceLine.source_line" in SHELL_SCRIPT
    assert "safeSourceUrl" in SHELL_SCRIPT
    assert "Refresh retained evidence" in SHELL_SCRIPT
    assert "/api/evidence/vlans/export.json" in SHELL_SCRIPT
    assert "/api/evidence/vlans/export.csv" in SHELL_SCRIPT
    assert "Missing evidence stays Unknown; explicitly unsupported evidence stays Unsupported" in SHELL_SCRIPT
    assert "Neither state proves a VLAN is absent" in SHELL_SCRIPT
    assert "No supported retained VLAN receipts" in SHELL_SCRIPT
    assert "['unknown','Unknown']" in SHELL_SCRIPT
    assert "Unknown / not assessed" not in SHELL_SCRIPT
    assert "Define Saved Networks and connect them to the reviewed Network Scope" in SHELL_SCRIPT
    assert "Define authorized network scopes first" not in SHELL_SCRIPT


def test_shared_shell_loads_only_the_selected_task_and_stops_hidden_polling():
    scan = operator_page().body.decode()
    analysis = analysis_page().body.decode()
    devices = device_config_page().body.decode()
    arkime = arkime_page().body.decode()
    reach = reachability_page().body.decode()
    map_html = network_map_page().body.decode()

    assert "function activateScanTask" in scan
    assert "function stopHiddenScanWork" in scan
    assert "window.addEventListener('nct:taskchange',requestScanTaskActivation)" in scan
    assert "function activateAnalysisTask" in analysis
    assert "function stopHiddenAnalysisWork" in analysis
    assert "if(currentAnalysisTask()!=='xmlImport')return false;const request=++nmapAssignmentRequest" in analysis
    assert "request!==nmapAssignmentRequest||currentAnalysisTask()!=='xmlImport'" in analysis
    assert "if(currentAnalysisTask()!=='xmlImport'){nmapAssignmentRequest++;clearTimeout(nmapAssignmentPoll)" in analysis
    assert "window.addEventListener('nct:taskchange',requestAnalysisTaskActivation)" in analysis
    assert "function activateDeviceTask" in devices
    assert "function stopHiddenDeviceWork" in devices
    assert "currentDeviceTask()!=='deviceHistory'" in devices
    assert "window.addEventListener('nct:taskchange',requestDeviceTaskActivation)" in devices
    assert "function activateArkimeTask" in arkime
    assert "window.addEventListener('nct:taskchange',requestArkimeTaskActivation)" in arkime
    assert "function activateMapTask" in map_html
    assert "window.addEventListener('nct:taskchange',requestMapTaskActivation)" in map_html
    assert "function activateReachTask" in reach
    assert "window.addEventListener('nct:taskchange',requestReachTaskActivation)" in reach
    assert "if(task==='exposureReportPanel')" in reach
    assert "await ensureReachContext()" in reach
    assert "bindClearButton('source','clearSource');bindClearButton('destination','clearDestination');loadContext();" not in reach
    assert "window.dispatchEvent(new CustomEvent('nct:taskchange'" in SHELL_SCRIPT


def test_operator_readme_explains_scope_continuity_and_scoped_vlan_limits():
    html = how_nct_works_page(
        app_version="test", build_id="test", build_commit="test",
    ).body.decode()

    assert "A scope carried by a profile remains a suggestion" in html
    assert "It separately records supported VLAN statements" in html
    assert "Scoped VLAN evidence appears in Network Devices, Current Network" in html
    assert "do not turn them into host identity, routing, Reach, CVE, or Map-link claims" in html
    assert "<summary>Scoped VLAN evidence</summary>" in html
