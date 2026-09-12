from __future__ import annotations

from app.analysis_ui import analysis_page
from app.device_analysis_ui import device_analysis_page
from app.device_ui import device_config_page
from app.hunting_ui import hunting_page
from app.network_map_ui import network_map_page
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
    assert "NCT network characterization initiated through the operator workspace" in html
    assert html.index("Build scan") < html.index("Scan history")
    assert "Save as profile" in html
    assert "Run now" in html
    assert "Generate package" in html
    assert "TCP + UDP" in html
    assert "ICS / OT" in html
    assert "What this port scope includes" in html
    assert "102,502,789,1911,1962,2404" in html
    assert "FPING pre-scan" in html
    assert 'id="fpingNote" class="hint hidden"' in html
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
    assert 'id="noStrikeOperator"' in html
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
    assert "/api/scan-runs-grouped?limit=200" in html
    assert 'class="history-group"' in html
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


def test_device_collection_history_has_structured_review_and_confirmed_delete():
    html = device_config_page().body.decode()
    assert 'id="historySearch"' in html
    assert 'id="routeFilter"' in html
    assert "All routes" in html
    assert "Connected routes" in html
    assert "/summary`" in html
    assert "/delete-challenge`" in html
    assert 'id="deleteCollectionDialog"' in html
    for section in (
        "Interfaces",
        "Routes",
        "Neighbors",
        "VLANs",
        "Firewall / ACL",
        "NAT",
        "Network objects",
        "Commands",
        "Configuration",
        "Raw output",
    ):
        assert section in html
    assert "Showing ${shown.length} of ${availableTotal} rows" in html
    assert "Analyze" in html
    assert "/device-analysis?run=" in html


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


def test_nmap_analysis_labels_direct_and_correlated_mac_provenance():
    html = analysis_page().body.decode()
    assert "mac-provenance" in html
    assert "correlated by IP" in html
    assert "direct Nmap" in html
    assert "dataset.macProvenance" in html


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
    assert '<details class="panel" id="inventoryPanel">' in html
    assert 'id="inventorySummary"' in html
    assert 'class="panel evidence-guide"' in html
    assert '<details class="panel evidence-guide" open>' in html
    assert '<details class="panel" open><summary>Capability datasets</summary>' in html
    assert '<details class="panel" open><summary>Capability findings</summary>' in html
    assert "details.panel>summary::before" in html
    assert "details.panel[open]>summary::before" in html
    assert "position:sticky;top:var(--hunt-header-offset)" in html
    assert "scroll-margin-top:var(--hunt-result-offset" in html
    assert "stickyOffsetObserver.observe(pageHeader)" in html
    assert "stickyOffsetObserver.observe(evidenceGuide)" in html
    assert "headerOffset+guideHeight+14" in html
    assert "Exposed" in html
    assert "Inferred" in html
    assert "Observed" in html
    assert "Correlated" in html
    assert "Configuration" in html
    assert "They do not, by themselves, prove a vulnerability or compromise" in html
    assert "/api/hunting/network" in html
    assert "correlated by IP" in html
    assert "direct Nmap" in html
    assert "/api/hunting/compare" in html
    assert "/api/hunting/${encodeURIComponent(id)}" in html
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
    assert 'id="cveSummary"' in html
    assert "SearchSploit CVEs / common names" in html
    assert "SearchSploit candidate title" in html
    assert "configureCveFilters" in html
    assert "applySearchSploitFilters" in html
    assert "renderHostCveDropdowns" in html
    assert "/api/searchsploit/status" in html
    assert "/api/searchsploit/hunting/network" in html
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
    assert '/hunting?run=${encodeURIComponent(item.selection_run_id)}' in analysis_html


def test_primary_navigation_orders_nmap_device_analyze_hunt_and_map():
    expected = [">Nmap</a>", ">Device</a>", ">Analyze</a>", ">Hunt</a>", ">Map</a>"]
    for page in (operator_page(), analysis_page(), device_config_page(), hunting_page(), network_map_page()):
        html = page.body.decode()
        positions = [html.index(label) for label in expected]
        assert positions == sorted(positions)


def test_scan_history_keeps_run_actions_on_one_line():
    html = operator_page().body.decode()
    assert ".history-run-actions{display:flex;flex-wrap:nowrap" in html
    assert '<div class="history-run-actions"><button class="secondary" data-open=' in html
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
    assert "transit_segment" in html
    assert "webLayout" in html
    assert "Spider-web network topology" in html
    assert "Labeled transit subnet" in html
    assert "placeLevel(" not in html
    assert 'id="resetLayout"' in html
    assert "enableNodeDrag" in html
    assert "manualPositions" in html
    assert "updateEdgeGeometry" in html
    assert "Drag any box to reposition it" in html
    assert "Config zone" in html
    assert "node.zone_names" in html
    assert 'id="zoomOut"' in html
    assert 'id="zoomIn"' in html
    assert 'id="zoomFit"' in html
    assert "function setZoom" in html
    assert "function fitMap" in html
    assert "function enableCanvasNavigation" in html
    assert "event.deltaY<0?1.12:.89" in html
    assert "contentX=(canvas.scrollLeft+point.x)/previous" in html
    assert "canvas.classList.add('panning')" in html
    assert "requestAnimationFrame(centerMap)" in html
    assert 'aria-label="Map scaling controls"' in html
    assert "function deviceAddressLines" in html
    assert "Primary / observed MAC" in html
    assert "iface.mac" in html
    assert "...addresses,iface.mac" not in html
    assert "i.mac_vendor" in html
    assert "No IPv4 address" in html
    assert "function nodeDimensions" in html
    assert "w:250,h:68" in html
    assert "interfaceCount" in html
    assert ".workspace>aside { position:sticky" in html
    assert 'id="toggleWorkspace"' in html
    assert "workspace.map-expanded" in html
    assert "Exit expanded workspace" in html
    assert "event.key==='Escape'" in html
    assert 'id="groupAll"' in html
    assert 'id="endpointSort"' in html
    assert "const endpointModes=new Map()" in html
    assert "mode==='collapsed'" in html
    assert "Individual connection lines" in html
    assert "Organized inside subnet" in html
    assert "function groupedEndpointSections" in html
    assert "function groupedNodeDimensions" in html
    assert "return [...grouped].map" in html
    assert "'text-anchor':'middle'" in html
    assert "Math.floor(index/section.rows)" in html
    assert "(continued)" not in html
    assert "group-host-row" in html
    assert "const endpointModes=new Map(),endpointSortModes=new Map(),manualPositions=new Map(),groupedSizes=new Map()" in html
    assert "function enableGroupedResize" in html
    assert "group-resize-handle" in html
    assert "Resize grouped boxes from the lower-right corner" in html
    assert "groupedSizes.clear()" in html
    assert "Group / sort by IP" in html
    assert "Group / sort by hostname" in html
    assert "Group / sort by OS" in html
    assert "local to the current analyst browser" in html
    assert "does not change shared evidence or another analyst's view" in html
    assert "function edgeAnchor" in html
    assert "No interface IPs parsed" in html
    assert 'id="topologyNeighborCount"' in html
    assert "Confirmed LLDP/CDP neighbor" in html
    assert "LLDP/CDP identity" in html
    assert "edge.relation==='topology_neighbor'" in html


def test_new_and_historical_results_share_the_same_renderer():
    html = analysis_page().body.decode()
    assert "renderAnalysis(item.analysis" in html
    assert "renderAnalysis(data.analysis" in html
    assert 'id="analysisWarnings"' in html
    assert "renderAnalysisWarnings" in html
    assert "Analysis cautions" in html
    assert "prepareRunComparison" in html
    assert "Select one more automated scan" in html
    assert "Export host summary CSV" in html
    assert "Export port-level CSV" in html
    assert "compactExportLabel" in html
    assert "`${currentLabel}-hosts.csv`" in html
    assert "`${currentLabel}-ports.csv`" in html
    assert "MAC / vendor" in html
    assert "Automatic same-scope comparison" in html
    assert 'id="autoCompareResult"' in html
    assert "/comparison" in html
    assert "coverage_warnings" in html
    assert 'id="automatedHistory"' in html
    assert "Compare selected automated scans" in html
    assert "/api/scan-comparisons/candidates" in html
    assert "/api/scan-comparisons/compare" in html
    assert 'class="panel previous-scans-panel"' in html
    assert ".previous-scans-panel{height:560px;overflow-y:auto" in html
    assert "Scroll within this window for older scans" in html
    assert "Affected hosts and evidence" in html
    assert "Port state, service, product, or version changes" in html
    assert "Traceroute path change" in html
    assert "renderComparisonDetails" in html
