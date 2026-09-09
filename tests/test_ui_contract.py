from __future__ import annotations

from app.analysis_ui import analysis_page
from app.ui import operator_page


def test_scan_builder_is_one_page_with_requested_actions():
    html = operator_page().body.decode()
    assert html.index("Build scan") < html.index("Scan history")
    assert "Save as profile" in html
    assert "Run now" in html
    assert "Generate package" in html
    assert "TCP + UDP" in html
    assert "ICS / OT" in html


def test_new_and_historical_results_share_the_same_renderer():
    html = analysis_page().body.decode()
    assert "renderAnalysis(item.analysis" in html
    assert "renderAnalysis(data.analysis" in html
    assert "Export host summary CSV" in html
    assert "Export port-level CSV" in html
    assert "MAC / vendor" in html
