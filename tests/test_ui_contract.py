from __future__ import annotations

from app.analysis_ui import analysis_page
from app.device_ui import device_config_page
from app.network_map_ui import network_map_page
from app.ui import operator_page


def test_scan_builder_is_one_page_with_requested_actions():
    html = operator_page().body.decode()
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
    assert "FPING discovery" in html
    assert "batch_hosts_completed" in html
    assert 'class="delete-modal hidden"' in html
    assert 'role="dialog"' in html
    assert 'id="deleteStatus"' in html
    assert "Enter the confirmation string shown above" in html
    assert "Built-in profile protected" in html
    assert "Global no-strike safety list" in html
    assert "Profiles cannot turn this protection off" in html
    assert "/api/safety/no-strike" in html
    assert "Remove a global no-strike entry" in html
    assert "Pause and require operator approval before Nmap" in html
    assert "/api/scan-schedules/" in html
    assert ".join('\n')" not in html
    assert r".join('\n')" in html


def test_navigation_is_sticky_on_every_primary_page():
    pages = [operator_page(), analysis_page(), device_config_page(), network_map_page()]
    for page in pages:
        html = page.body.decode()
        assert "position:sticky" in html
        assert "aria-label=\"Primary\"" in html


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
    assert 'aria-label="Map scaling controls"' in html
    assert "function deviceAddressLines" in html
    assert "Primary / observed MAC" in html
    assert "iface.mac" in html
    assert "...addresses,iface.mac" not in html
    assert "i.mac_vendor" in html
    assert "No IPv4 address" in html
    assert "function nodeDimensions" in html
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
    assert "Export host summary CSV" in html
    assert "Export port-level CSV" in html
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
