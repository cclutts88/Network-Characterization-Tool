from __future__ import annotations

from app.analysis_ui import analysis_page
from app.device_analysis_ui import device_analysis_page
from app.device_ui import device_config_page
from app.hunting_ui import hunting_page
from app.network_map_ui import network_map_page
from app.reachability_ui import reachability_page
from app.session_ui import SESSION_SCRIPT
from app.ui import operator_page


def test_scan_builder_is_one_page_with_requested_actions():
    html = operator_page().body.decode()
    assert '<h1 class="sr-only">Nmap</h1>' in html
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
    assert "Collect traceroute paths" in html
    assert "normalizeCombinedScopes" in html
    assert 'id="fallbackApproval"' in html
    assert html.index("<h2>Profile behavior</h2>") < html.index('id="fallbackApproval"')
    assert "Full Nmap fallback requires approval" in html
    assert "Authorize full Nmap fallback" in html
    assert "Finish without Nmap" in html
    assert "fallback-decision" in html
    assert "awaiting_fallback_approval" in html
    assert "exact_fallback_command" in html
    assert "Delete profile" in html
    assert "Scheduled scans" in html
    assert "Use selected profile" in html
    assert "Addresses per chunk" in html
    assert "Use chunked scan strategy" in html
    assert 'id="chunkSizeBox" class="span-3 hidden"' in html
    assert 'id="scheduleChunkDelayBox" class="span-4 hidden"' in html
    assert "chunking_enabled" in html
    assert "showChunkingOptions" in html
    assert "size===256" in html
    assert "One continuous unchunked scan queued" in html
    assert "Pause between chunks (seconds)" in html
    assert "Custom hours" in html
    assert '<option value="monthly">Monthly</option>' in html
    assert "Hours between scans" in html
    assert "Every few minutes" not in html
    assert "cadence_hours" in html
    assert "Scheduling conflict" in html
    assert "Delayed occurrences" in html
    assert "Consider changing this schedule time" in html
    assert "conflict_flagged" in html
    assert "Owner / audit" in html
    assert "recorded change" in html
    assert "last_occurrence_status" in html
    assert "chunk_delay_seconds" in html
    assert "Chunks never overlap" in html
    assert 'id="currentProgress"' in html
    assert 'id="currentRunPanel"' in html
    assert "currentLive=false" in html
    assert "if(!currentLive)loadActiveRun()" in html
    assert "$('currentRunPanel').classList.add('hidden')" in html
    assert 'role="progressbar"' in html
    assert 'id="currentHostsLabel">Nmap-reported hosts' in html
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
    assert 'id="noStrikePanel"' in html
    assert "Global No-Strikes are excluded addresses" in html
    assert "Profiles cannot turn them off" in html
    assert "changed_by:auditActor()" in html
    assert 'id="globalNoStrikeStatus" class="status" role="status"' in html
    assert "setGlobalSafetyStatus(error.message,'bad')" in html
    assert "/api/safety/no-strike" in html
    assert "/api/safety/scan-summary" in html
    assert "Pre-launch scope &amp; safety check" in html
    assert 'id="safetyEffective"' in html
    assert "globalNoStrikeSummary').textContent=`${entries.length} excluded`" in html
    assert "Remove a global No-Strike exclusion" in html
    assert "Pause and require operator approval before Nmap" in html
    assert "Estimated time left" in html
    assert "Timeout limit in" in html
    assert 'for="timeout">Run timeout (minutes)' in html
    assert 'id="timeout" type="number" min="1" max="60" step="1" value="45"' in html
    assert "You can stop the scan at any time from Current run" in html
    assert "timeout_seconds:timeoutSeconds()" in html
    assert "Live update" in html
    assert 'id="currentRunHeading"' in html
    assert "'Active run':'Current run'" in html
    assert "async function loadActiveRun()" in html
    assert "/api/scan-runs?limit=200" in html
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
    assert "Combine saved and manual scopes" in html
    assert "manual_targets" in html
    assert "saved_network_ids" in html
    assert "selectedSavedNetworkIds" in html
    assert "/api/saved-networks" in html
    assert "/api/scan-runs-grouped?limit=25&offset=" in html
    assert 'class="history-group"' in html
    assert "localeCompare(NCTScanReference.humanize(b.name||'')" in html
    assert "function newestFirst(runs)" in html
    assert 'data-compare="' in html
    assert "candidateSavedName" in html
    assert "name:candidateSavedName(item)" in html
    assert "Remove selected" in html
    assert "/api/scan-schedules/" in html
    assert ".join('\n')" not in html
    assert r".join('\n')" in html


def test_navigation_is_sticky_on_every_primary_page():
    pages = [operator_page(), analysis_page(), device_analysis_page(), hunting_page(), device_config_page(), network_map_page()]
    for page in pages:
        html = page.body.decode()
        assert "position:sticky" in html
        assert "aria-label=\"Primary\"" in html
        assert '<div class="nct-brand" aria-label="NCT, Network Characterization Tool"><strong>NCT</strong><span><b>N</b>etwork <b>C</b>haracterization <b>T</b>ool</span></div>' in html
        assert "border-top:1px solid var(--accent)" in html
        assert "font-size:40px" in html
        assert "padding-top:6px!important" in html
        assert '<script src="/assets/nct-session.js" defer></script>' in html


def test_scan_workflow_pages_share_human_readable_scan_references():
    for page in (operator_page(), analysis_page(), hunting_page()):
        html = page.body.decode()
        assert '<script src="/assets/nct-scan-references.js"></script>' in html
        assert "NCTScanReference" in html


def test_table_headers_stay_visible_without_overlapping_sticky_page_content():
    page_tables = [operator_page(), analysis_page(), device_analysis_page(), hunting_page()]
    for page in page_tables:
        html = page.body.decode()
        assert "thead th{position:sticky" in html
        assert "table-wrap" in html
    for page in (operator_page(), analysis_page(), device_analysis_page()):
        html = page.body.decode()
        assert "--table-sticky-offset" in html
        assert "syncTableStickyOffset" in html
        assert "ResizeObserver(syncTableStickyOffset)" in html
    assert "top:var(--hunt-result-offset" in hunting_page().body.decode()
    assert "#details thead th{position:sticky;top:0" in network_map_page().body.decode()


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
    assert "VyOS and pfSense create a named temporary output file" in html
    assert "Cisco, Juniper, and UniFi devices return output directly through SSH and do not run SCP" in html
    assert '<option value="unifi">UniFi</option>' in html
    assert '<option value="switch">Switch</option>' in html
    assert '<select id="type" multiple size="3"' in html
    assert "device_types:deviceTypes" in html
    assert "Router + Firewall selected" in html
    assert "supportsSwitch=['cisco','juniper','unifi'].includes(vendor)" in html
    assert "Switch collection is available for this vendor" in html
    assert "$('type').onchange=updateVendorHint" in html
    assert "Current consoles and gateways normally use the root SSH account" in html
    assert "EdgeRouter devices should continue to use the VyOS template" in html
    assert 'id="captureCommand"' not in html
    assert 'id="scp"' not in html
    assert 'id="cleanupPlan"' not in html


def test_device_collection_keeps_raw_collection_work_separate_from_analysis():
    html = device_config_page().body.decode()
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
    assert "Continue to Nmap" in html
    assert "/device-analysis?run=" in html
    assert "const orderedGroups=[...groups.entries()].sort" in html
    assert "for(const runs of groups.values()) runs.sort" in html


def test_network_device_analysis_has_unified_evidence_and_comparison_views():
    nmap_html = analysis_page().body.decode()
    html = device_analysis_page().body.decode()
    assert "Network Device Analysis" in nmap_html
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
    assert '<a href="/hunting">Hunt</a>' in analysis_html
    assert '<a href="/hunting">Hunt</a>' in device_html
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
    assert html.index("Network filters") < html.index("SearchSploit enrichment")
    assert "Filters apply to SearchSploit results" in html
    assert 'id="networkFiltersPanel"' in html
    assert 'id="activeFilterSummary"' in html
    assert 'id="searchsploitFilterSummary"' in html
    assert "updateFilterSummaries" in html
    assert "searchSploitMatchesNetworkFilters" in html
    assert "annotateSearchSploitNetworkData" in html
    assert "after all active filters" in html
    assert 'id="hostRows"' in html
    assert 'id="systemsPanel" data-workspace-card="systems"' in html
    assert 'id="capabilityViewTab"' in html
    assert 'id="inventoryViewTab"' in html
    assert 'id="capabilityView" role="tabpanel"' in html
    assert 'id="inventoryView" role="tabpanel"' in html
    assert 'id="inventorySummary"' in html
    assert "Network evidence overview" in html
    assert 'id="sources"' not in html
    assert "$('sources').innerHTML=sourceLinks(source)" not in html
    assert 'class="panel evidence-guide"' in html
    assert '<details class="panel evidence-guide" data-workspace-card="evidence-guide" open>' in html
    assert '<details class="panel" data-workspace-card="capability-datasets" open><summary>Capability datasets</summary>' in html
    assert "One active list at a time" in html
    assert "function setSystemView(view)" in html
    assert "function renderHostInventoryRows()" in html
    assert "hosts:[],findings:[]" in html
    assert "details.panel>summary::before" in html
    assert "details.panel[open]>summary::before" in html
    assert "position:sticky;top:var(--hunt-header-offset)" in html
    assert "scroll-margin-top:var(--hunt-result-offset" in html
    assert "stickyOffsetObserver.observe(pageHeader)" in html
    assert "stickyOffsetObserver.observe(evidenceGuide)" in html
    assert "headerOffset+guideHeight+14" in html
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
    assert "renderFindingSummaries(data.findings||[])" in html
    assert "activeSystemView==='capabilities'" in html
    assert "function anyHuntFilterActive()" in html
    assert ".finding-summary-row.hidden-row{display:none}" in html
    assert "content-visibility:auto" in html
    assert "finding${Number(item.finding_count||0)===1?'':'s'}" in html
    assert "capability classification${group.length===1?'':'s'} across" in html
    assert "Apply a network filter to show one classification per row." in html
    assert "Combined view · one entry per IP with all ports visible." in html
    assert "Filtered view · individual matching findings." in html
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
    assert "SearchSploit enrichment" in html
    assert 'id="searchsploitRun"' in html
    assert 'id="matchedOnly"' in html
    assert 'id="cveFilter"' in html
    assert 'id="cveYearFilter"' in html
    assert 'id="cveStatusFilter"' in html
    assert 'id="exposureFilter"' in html
    assert "Matched-service exposure" in html
    assert "Service exposure evidence" in html
    assert "data.exposure_disclaimer" in html
    assert 'id="cveSummary"' in html
    assert "SearchSploit CVEs / common names" in html
    assert "SearchSploit candidate title" in html
    assert "configureCveFilters" in html
    assert "applySearchSploitFilters" in html
    assert "renderHostCveDropdowns" in html
    assert "/api/searchsploit/status" in html
    assert "/api/searchsploit/hunting/network" in html
    assert "function responseJson(response,label='Request')" in html
    assert "returned an empty server response" in html
    assert "returned an unreadable server response" in html
    assert "await timedJson(endpoint,{method:'POST'},'SearchSploit enrichment',180000)" in html
    assert 'id="searchsploitOnline"' in html
    assert 'id="searchsploitUpload"' in html
    assert 'id="searchsploitRollback"' in html
    assert "/api/searchsploit/database/update-online" in html
    assert "/api/searchsploit/database/upload" in html
    assert "/api/searchsploit/database/rollback/" in html
    assert "Potential product/version matches require analyst validation" in html
    assert 'class="finding-match-slot"' in html
    assert "Potential matches: ${Number(match.candidate_count||0)}" in html
    assert "openSearchSploitMatch" in html
    assert "contains no specific product/version fingerprints to search" in html
    assert "Service/version detection enabled" in html
    assert '/hunting?run=${encodeURIComponent(runId)}' in analysis_html
    assert "function reachUrl(item)" in html
    assert "Evaluate host in Reach" in html
    assert "Open Reach with this destination and service; Source remains for you to choose." in html
    assert "renderSearchSploitReachBase" in html
    assert "target='_blank'" in html


def test_reachability_view_has_grouped_source_exposure_reports():
    html = reachability_page().body.decode()
    assert 'id="sourceExternal"' in html
    assert "External address / range" in html
    assert "source_external:$('sourceExternal').checked" in html
    assert 'id="policySimulationPanel"' in html
    assert 'id="simulationDevice"' in html
    assert 'id="simulationInterface"' in html
    assert 'id="simulationAction"' in html
    assert 'id="simulationTemplate"' in html
    assert 'id="simulationPosition"' in html
    assert 'id="simulationRule"' in html
    assert 'id="simulationExistingRules"' in html
    assert 'id="generatePolicyRule"' in html
    assert 'id="simulationPath"' in html
    assert 'id="simulationImpact"' in html
    assert 'id="exportSimulation"' in html
    assert 'id="showPolicySimulationOnMap"' in html
    assert "/api/reachability/simulate-policy" in html
    assert "/api/reachability/policy-context/" in html
    assert "/api/reachability/policy-template" in html
    assert "changes no device configuration" in html
    assert 'id="routeSimulationPanel"' in html
    assert 'id="routeSimulationDevice"' in html
    assert 'id="routeSimulationNetwork"' in html
    assert 'id="routeSimulationInterface"' in html
    assert 'id="routeSimulationPriorityKind"' in html
    assert 'id="routeSimulationPriorityValue"' in html
    assert 'id="routeSimulationPath"' in html
    assert 'id="routeSimulationAlternates"' in html
    assert 'id="routeSimulationImpact"' in html
    assert 'value="set_priority"' in html
    assert 'id="exportRouteSimulation"' in html
    assert 'id="showRouteSimulationOnMap"' in html
    assert "/api/reachability/simulate-route" in html
    assert "NCT_RouteWhatIf_" in html
    assert "showSimulationOnMap" in html
    assert "version:2" in html
    assert 'id="exposureReportPanel"' in html
    assert 'id="generateReport"' in html
    assert 'id="exportReport"' in html
    assert "/api/reachability/exposure-report" in html
    assert "Retained route, policy, and NAT objects" in html
    assert "function evidenceCard(item)" in html
    assert "View supporting evidence" in html
    assert "Open source in Analyze ↗" in html
    assert 'target="_blank" rel="noopener"' in html
    assert ".evidence.policy.deny" in html


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
    assert "Choose a Source, then evaluate." in html


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
    assert "new MutationObserver" in SESSION_SCRIPT
    assert "input.dispatchEvent(new Event('input'" in SESSION_SCRIPT


def test_every_analysis_stage_has_a_local_export_path_including_map():
    analyze = analysis_page().body.decode()
    device = device_analysis_page().body.decode()
    hunt = hunting_page().body.decode()
    reach = reachability_page().body.decode()
    map_html = network_map_page().body.decode()

    assert "window.NCTExport" in SESSION_SCRIPT
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
    assert "function applyReachFocus" in map_html
    assert "reach-focus-match" in map_html
    assert "reach-focus-dim" in map_html
    assert "Temporary investigation overlay" in map_html
    assert "saved map positions and layouts are unchanged" in map_html
    assert "Temporary proposed-path comparison" in map_html
    assert "Bounded collateral scope" in map_html


def test_primary_navigation_orders_device_nmap_analyze_hunt_and_map():
    expected = [">Device</a>", ">Nmap</a>", ">Analyze</a>", ">Hunt</a>", ">Map</a>"]
    for page in (operator_page(), analysis_page(), device_config_page(), hunting_page(), network_map_page()):
        html = page.body.decode()
        positions = [html.index(label) for label in expected]
        assert positions == sorted(positions)


def test_scan_history_keeps_run_actions_on_one_line():
    html = operator_page().body.decode()
    assert ".history-run-actions{display:flex;flex-wrap:nowrap" in html
    assert '<div class="history-run-actions"><button class="secondary" data-preset=' in html
    assert '>Use preset</button><button class="secondary" data-network=' in html
    assert 'data-hunt="${esc(run.run_id)}">Hunt</button>' in html
    assert '/hunting?run=${encodeURIComponent(b.dataset.hunt)}' in html


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
    assert 'id="mapFilesButton"' in html
    assert 'id="mapFilesDialog"' in html
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
    assert 'id="mapFaqButton"' in html
    assert 'id="mapFaqDialog"' in html
    assert "Why did new scan results go to the parking lot?" in html
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
    assert "externalOrb=Boolean(wanAnchor&&externalWanGatewayId===wanAnchor.nodeId)" in html
    assert "active=Boolean(wanAnchor&&!externalOrb&&!hiddenNodeIds.has(wanAnchor.nodeId)" in html
    assert "function updateWanUplinkGeometry" in html
    assert "function externalWanAttachmentId" in html
    assert "function wanUplinkSourceId" in html
    assert "function wanGatewayIdsForView" in html
    assert "function applyExternalGatewaySemantics" in html
    assert "externalWanGatewayIds=new Set()" in html
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
    assert 'id="mapSummary" open' in html
    assert 'id="summaryCompact"' in html
    assert '.summary-panel>summary::before' in html
    assert '.summary-panel[open]>summary::before' in html
    assert 'id="edgeCount"' not in html
    assert 'id="sourceCount"' not in html
    assert ".workspace>aside { display:none; }" in html
    assert ".workspace.map-expanded .map-shell>#details { display:block;" in html
    assert 'id="toggleWorkspace"' in html
    assert 'class="workspace-toggle-dock"' in html
    assert '.workspace-toggle-dock{position:sticky;top:126px' in html
    assert 'body.map-expanded .workspace-toggle-dock{position:fixed;top:14px;left:50%' in html
    assert 'id="toggleDetails"' in html
    assert 'class="details-control"' in html
    assert ".details-control{display:none}.workspace.map-expanded .details-control{display:flex}" in html
    assert 'id="workspaceSize"' in html
    assert "Large network · 4× area" in html
    assert ".workspace.map-expanded .details-control" in html
    assert ".workspace.map-expanded .map-shell { display:flex; flex:1 1 auto" in html
    assert ".workspace.map-expanded .canvas { flex:1 1 auto; height:auto; min-height:0" in html
    assert "workspace.map-expanded" in html
    assert "workspace.map-expanded.details-collapsed" in html
    assert "workspace.map-expanded.details-collapsed .map-shell>#details" in html
    assert ".workspace.map-expanded .map-shell>#details" in html
    assert "function syncExpandedDetailsBounds" in html
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
    assert "await openRun(runId);focusRequestedEvidence()" in html
    assert "coverage_warnings" in html
    assert 'id="comparisonResult"' in html
    assert ">Compare scans</button>" in html
    assert "/api/scan-comparisons/candidates" in html
    assert "/api/scan-comparisons/compare" in html
    assert "Previous scans" not in html
    assert 'id="automatedHistory"' not in html
    assert 'class="panel previous-scans-panel"' not in html
    assert "Affected hosts and evidence" in html
    assert "Port state, service, product, or version changes" in html
    assert "Traceroute path change" in html
    assert "renderComparisonDetails" in html


def test_analyze_opens_with_a_paginated_network_wide_current_evidence_view():
    html = analysis_page().body.decode()

    assert 'id="networkOverview"' in html
    assert "Current network evidence" in html
    assert "Newest retained Nmap results and device configuration evidence" in html
    assert "/api/analysis/network" in html
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
    assert "renderNetworkInventory" in html
    assert "networkEvidenceDetails" in html
    assert "Evidence and history" in html
    assert "else{await loadNetworkOverview()}" in html
    assert "scanRef(item).primary" in html
    assert "Open one specific retained scan" in html
    assert 'id="retainedScanSelect"' in html
    assert "currentNetwork.hosts" in html
    assert 'id="networkOutliersPanel"' in html
    assert "Uncommon ports by OS" in html
    assert "The Subnet filter above recalculates this view" in html
    assert "renderNetworkOutliers" in html
    assert 'id="networkChangesPanel"' in html
    assert 'id="loadNetworkChanges"' in html
    assert "/api/analysis/network-changes" in html
    assert "renderNetworkChanges" in html
    assert 'id="networkControlsPanel"' not in html
    assert '<span>Routes and policy</span>' not in html
    assert 'id="comparisonBaseline"' in html
    assert 'id="comparisonCurrent"' in html


def test_hunt_and_analyze_include_simple_table_controls_without_personal_presets():
    hunt_html = hunting_page().body.decode()
    analyze_html = analysis_page().body.decode()
    for html in (hunt_html, analyze_html):
        assert '/assets/nct-view-preferences.js' in html
        assert 'data-workspace-card=' in html
    assert 'data-workspace-card="network-filters"' in hunt_html
    assert 'data-workspace-card="network-changes"' in analyze_html
    assert 'id="analysisHostRows"' in analyze_html
    from app.view_preferences_ui import VIEW_PREFERENCES_SCRIPT

    assert "pageNode.textContent!==pageLabel" in VIEW_PREFERENCES_SCRIPT
    assert "if(pagerOnly)return" in VIEW_PREFERENCES_SCRIPT
    assert "Table density" not in VIEW_PREFERENCES_SCRIPT
    assert '<span class="nct-view-status">Table display</span>' in VIEW_PREFERENCES_SCRIPT
    assert '<option value="50" selected>50</option>' in VIEW_PREFERENCES_SCRIPT
    assert '<label>Personal preset' not in VIEW_PREFERENCES_SCRIPT
    assert 'data-preset-name' not in VIEW_PREFERENCES_SCRIPT.split('function captureFilters', 1)[0]


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
    assert ".report-source>summary::before,.report-result>summary::before" in pages["reach"]
    assert ".summary-panel>summary::before,.hidden-objects>summary::before" in pages["map"]
    assert ".evidence-files-drawer>summary::before" in pages["map"]


def test_nmap_advanced_operations_are_collapsed_without_removing_capability():
    html = operator_page().body.decode()

    assert '<details class="advanced-drawer" id="profileManagementPanel">' in html
    assert '<summary>Advanced profile management</summary>' in html
    assert '<details class="advanced-drawer" id="scheduledScansPanel">' in html
    assert '<summary>Scheduled scans</summary>' in html
    assert html.index('id="scheduledScansPanel"') < html.index('id="runNow"')
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
