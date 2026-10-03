from fastapi.testclient import TestClient

from app.how_nct_works_ui import how_nct_works_page
from app.shell_ui import SHELL_SCRIPT


def test_built_in_readme_explains_pipeline_storage_and_current_limits():
    html = how_nct_works_page().body.decode()

    assert "Built-in README · Living operator guide" in html
    assert "The ingestion pipeline" in html
    for phase in (
        "Collect or import", "Retain original evidence", "Record the observation",
        "Assign network context", "Verify and parse", "Build scoped observations",
        "Analyze and correlate", "Compare and explain change",
    ):
        assert phase in html
    for storage in ("Artifact storage", "SQLite database", "Derived-result storage", "This browser"):
        assert storage in html
    assert "does not guess from a CIDR or filename" in html
    assert "associate a Saved Network with one active Network Scope" in html
    assert "Mixed, combined, manual, and unassociated scan targets" in html
    assert "New schedules pin the reviewed context" in html
    assert "Optionally assign manual Nmap context" in html
    assert "Optionally process automated scan evidence" in html
    assert "Unscoped or mixed-context scans remain unavailable" in html
    assert "Several subnets may share one scope" in html
    assert "saves the analysis and its source and scope links all at once" in html
    assert "If any part fails, none of those new processing records is published" in html
    assert "will not grant scan authority" in html
    assert "require every scan to be assigned first" in html
    assert "Planned optional tasking will help a lead coordinate work" in html
    assert "not observed in this collection" in html
    assert "Automatic compaction remains disabled" in html
    assert "A dry run reports only" in html
    assert "Nmap scan — active network contact" in html
    assert "password is used only for the short-lived SSH session" in html
    assert "Uploading existing Nmap XML" in html
    assert "Saved Network" in html and "Network Scope" in html
    assert "choose the Network Scope that gives future scans" in html
    assert "affects future scans only" in html
    assert "offline Exploit-DB matches are candidates for analyst validation" in html
    assert "Viewer accounts can read shared evidence" in html
    assert "Current scan and device-configuration comparisons are available" in html
    assert "Processed evidence by Network Scope" in html
    assert "Inspect and compare processed receipts" in html
    assert "neutral Record A and Record B" in html
    assert "Coverage-aware historical service classification" in html
    assert "outside the other record's selected ports is Not assessed" in html
    assert "unambiguous closed result" in html
    assert "does not say the service is gone now" in html
    assert "does not create a service change" in html
    assert "Versioned coverage receipts retain successful completion" in html
    assert "does not treat the most recently processed file as automatic truth" in html
    assert "Planned: passive activity summaries" in html
    assert "Build details · version" in html
    assert "registered Nmap and device artifacts" in html
    assert "operator hostname upload" in html
    assert "does not retain the uploaded file bytes as an Artifact Registry artifact" in html
    assert "common analysis versioning is planned" in html
    assert "foundation/evidence-engine-v2" in html
    assert 'href="/settings/system-health"' in html
    assert 'href="/settings/network-scopes"' in html


def test_readme_escapes_build_identity():
    html = how_nct_works_page(
        app_version="<script>bad()</script>", build_id='bad"id', build_commit="<bad>",
    ).body.decode()
    assert "<script>bad()</script>" not in html
    assert "&lt;script&gt;bad()&lt;/script&gt;" in html
    assert "bad&quot;id" in html
    assert "&lt;bad&gt;" in html


def test_hamburger_menu_links_to_built_in_readme_and_guide_knows_the_page():
    assert 'id="nct-readme-link" href="/help/how-nct-works">How NCT Works</a>' in SHELL_SCRIPT
    assert "location.pathname==='/help/how-nct-works'" in SHELL_SCRIPT
    assert "Status labels distinguish available behavior from foundation work and planned capability" in SHELL_SCRIPT


def test_readme_route_is_available_to_every_authenticated_role(tmp_path, monkeypatch):
    import app.main as main

    monkeypatch.setattr(main, "DB_PATH", tmp_path / "analyzer.db")
    monkeypatch.setattr(main, "auth_enabled", lambda: True)
    for role in ("viewer", "analyst", "admin"):
        monkeypatch.setattr(
            main, "session_identity",
            lambda *args, selected_role=role: {
                "username": "test", "display_name": "Test", "role": selected_role,
            },
        )
        with TestClient(main.app) as client:
            response = client.get("/help/how-nct-works")
            assert response.status_code == 200
            assert "How NCT works" in response.text


def test_readme_route_redirects_an_unauthenticated_user(tmp_path, monkeypatch):
    import app.main as main

    monkeypatch.setattr(main, "DB_PATH", tmp_path / "analyzer.db")
    monkeypatch.setattr(main, "auth_enabled", lambda: True)
    monkeypatch.setattr(main, "session_identity", lambda *args: None)
    with TestClient(main.app, follow_redirects=False) as client:
        response = client.get("/help/how-nct-works")
        assert response.status_code == 303
        assert response.headers["location"] == "/login?next=/help/how-nct-works"
