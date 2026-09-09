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
    assert "Collect traceroute paths" in html
    assert "normalizeCombinedScopes" in html
    assert 'id="fallbackApproval"' in html
    assert "Full Nmap fallback requires approval" in html
    assert "Authorize full Nmap fallback" in html
    assert "Finish without Nmap" in html
    assert "fallback-decision" in html
    assert "awaiting_fallback_approval" in html
    assert "exact_fallback_command" in html


def test_navigation_is_sticky_on_every_primary_page():
    pages = [operator_page(), analysis_page(), device_config_page(), network_map_page()]
    for page in pages:
        html = page.body.decode()
        assert "position:sticky" in html
        assert "aria-label=\"Primary\"" in html


def test_new_and_historical_results_share_the_same_renderer():
    html = analysis_page().body.decode()
    assert "renderAnalysis(item.analysis" in html
    assert "renderAnalysis(data.analysis" in html
    assert "Export host summary CSV" in html
    assert "Export port-level CSV" in html
    assert "MAC / vendor" in html
