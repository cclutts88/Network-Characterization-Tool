from __future__ import annotations

from app.host_identities import (
    apply_analysis_host_identities,
    apply_topology_host_identities,
    import_host_identities,
    list_host_identities,
    parse_host_identity_file,
)


def test_csv_template_format_imports_ip_and_hostname_rows():
    parsed = parse_host_identity_file(
        b"ip,hostname\n10.10.10.1,core-router.example.mil\n10.10.10.20,workstation-20\n",
        "hostnames.csv",
    )

    assert parsed["valid_count"] == 2
    assert parsed["errors"] == []
    assert parsed["identities"] == [
        {"ip": "10.10.10.1", "hostname": "core-router.example.mil", "line": 2},
        {"ip": "10.10.10.20", "hostname": "workstation-20", "line": 3},
    ]


def test_txt_template_ignores_comments_and_reports_invalid_rows():
    parsed = parse_host_identity_file(
        b"# NCT hostname template\n10.10.10.1 core-router\nnot-an-ip bad\n10.10.10.2\tworkstation-2\n",
        "hostnames.txt",
    )

    assert parsed["valid_count"] == 2
    assert parsed["skipped_count"] == 1
    assert parsed["errors"] == [{"line": 3, "reason": "invalid IP address"}]


def test_import_updates_retained_hostname_and_keeps_audit_fields(tmp_path):
    db_path = tmp_path / "analyzer.db"
    first = import_host_identities(
        db_path,
        b"10.10.10.1 core-router\n",
        filename="first.txt",
        imported_by="range-admin-2",
    )
    second = import_host_identities(
        db_path,
        b"10.10.10.1 mako-eng-core-rtr\n",
        filename="corrected.txt",
        imported_by="range-admin-2",
    )

    assert first["created_count"] == 1
    assert second["updated_count"] == 1
    retained = list_host_identities(db_path)
    assert retained[0]["hostname"] == "mako-eng-core-rtr"
    assert retained[0]["source_filename"] == "corrected.txt"
    assert retained[0]["imported_by"] == "range-admin-2"
    assert retained[0]["version"] == 2


def test_imported_hostname_fills_blank_but_does_not_replace_scanner_name(tmp_path):
    db_path = tmp_path / "analyzer.db"
    import_host_identities(
        db_path,
        b"10.10.10.1 mako-eng-core-rtr\n10.10.10.2 analyst-name\n",
        filename="hostnames.txt",
        imported_by="range-admin-2",
    )
    analysis = {"hosts": [
        {"ip": "10.10.10.1", "hostname": ""},
        {"ip": "10.10.10.2", "hostname": "scanner-name"},
    ]}

    apply_analysis_host_identities(analysis, db_path)

    assert analysis["hosts"][0]["hostname"] == "mako-eng-core-rtr"
    assert analysis["hosts"][0]["hostname_origin"] == "analyst_import"
    assert analysis["hosts"][1]["hostname"] == "scanner-name"
    assert analysis["hosts"][1]["hostname_conflict"] is True
    assert analysis["hosts"][1]["hostname_aliases"] == ["analyst-name"]


def test_topology_uses_imported_name_for_an_unnamed_observed_host(tmp_path):
    db_path = tmp_path / "analyzer.db"
    import_host_identities(
        db_path,
        b"10.10.10.1 mako-eng-core-rtr\n",
        filename="hostnames.txt",
        imported_by="range-admin-2",
    )
    nodes = {"ip:10.10.10.1": {
        "kind": "host", "ip": "10.10.10.1", "label": "10.10.10.1", "sources": []
    }}

    apply_topology_host_identities(nodes, db_path)

    node = nodes["ip:10.10.10.1"]
    assert node["hostname"] == "mako-eng-core-rtr"
    assert node["label"] == "mako-eng-core-rtr"
    assert node["sources"][0]["kind"] == "analyst_host_identity"
