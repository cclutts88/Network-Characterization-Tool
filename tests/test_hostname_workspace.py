from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.device_configs import TEMPLATES
from app.evidence_retirement import (
    EvidenceRetirementError,
    init_evidence_retirement_storage,
    retirement_record,
    retire_evidence,
)
from app.evidence_retirement_sources import (
    HOSTNAME_EVIDENCE_UPLOAD,
    hostname_evidence_upload_adapter,
)
from app.host_identities import list_host_identities, select_host_identity
from app.hostname_evidence import (
    build_hostname_workspace,
    parse_retained_hostname_evidence,
)
from app.hostname_imports import (
    hostname_accountability_file,
    hostname_evidence_file,
    list_hostname_evidence,
    parse_hostname_evidence_file,
    store_hostname_evidence,
)
from app.hostname_ui import hostname_page
from app.shell_ui import SHELL_SCRIPT
from app.main import app


def test_retained_hostname_parser_reads_dns_dhcp_and_config_sources():
    expiry = int((datetime.now(timezone.utc) + timedelta(hours=2)).timestamp())
    evidence = parse_retained_hostname_evidence(
        f"""
===== show hosts =====
core-dns.example          None  (perm, OK)  0   IP    10.20.30.5
===== show running-config =====
hostname edge-router
ip host app-static.example 10.20.30.10
===== cat /run/dnsmasq.leases =====
{expiry} aa:bb:cc:dd:ee:ff 10.20.30.20 workstation-20 01:aa:bb
""",
        device_ip="10.20.30.1",
    )

    by_source = {(item["source"], item["ip"]): item for item in evidence}
    assert by_source[("dns", "10.20.30.5")]["hostname"] == "core-dns.example"
    assert by_source[("dns", "10.20.30.10")]["hostname"] == "app-static.example"
    assert by_source[("dhcp", "10.20.30.20")]["hostname"] == "workstation-20"
    assert by_source[("dhcp", "10.20.30.20")]["lease_time_left_seconds"] > 0
    assert by_source[("config", "10.20.30.1")]["hostname"] == "edge-router"


def test_hostname_workspace_reuses_topology_device_output_and_operator_selection(tmp_path):
    db_path = tmp_path / "analyzer.db"
    init_evidence_retirement_storage(db_path)
    config_dir = tmp_path / "device-configs"
    run_dir = config_dir / ("a" * 32)
    run_dir.mkdir(parents=True)
    (run_dir / "manifest.json").write_text(json.dumps({
        "run_id": "a" * 32,
        "vendor": "cisco",
        "device_address": "10.20.30.1",
        "completed_at": "2026-09-24T20:00:00+00:00",
    }))
    (run_dir / "stdout.txt").write_text(
        "hostname edge-router\nip host dns-name.example 10.20.30.9\n"
    )
    topology = {"nodes": [
        {
            "kind": "host",
            "ip": "10.20.30.9",
            "addresses": ["10.20.30.9"],
            "hostname": "nmap-name.example",
            "sources": [{
                "kind": "automated_nmap",
                "timestamp": "2026-09-24T19:00:00+00:00",
                "url": "/evidence/nmap.xml",
            }],
        },
        {
            "kind": "device",
            "ip": "10.20.30.2",
            "addresses": ["10.20.30.2"],
            "hostname": "switch-from-lldp",
            "sources": [],
            "topology_observations": [{
                "protocol": "lldp",
                "management_ip": "10.20.30.2",
                "neighbor_name": "switch-from-lldp",
            }],
        },
    ]}
    select_host_identity(
        db_path,
        ip="10.20.30.9",
        hostname="approved-name.example",
        selection_source="operator_input",
        imported_by="analyst",
    )

    result = build_hostname_workspace(
        db_path, topology=topology, config_dir=config_dir
    )
    rows = {item["ip"]: item for item in result["rows"]}

    assert result["network_contacted"] is False
    assert rows["10.20.30.9"]["candidates"]["nmap"][0]["hostname"] == "nmap-name.example"
    assert rows["10.20.30.9"]["candidates"]["dns"][0]["hostname"] == "dns-name.example"
    assert rows["10.20.30.9"]["selected_hostname"] == "approved-name.example"
    assert rows["10.20.30.9"]["selection_persisted"] is True
    assert rows["10.20.30.2"]["candidates"]["lldp"][0]["hostname"] == "switch-from-lldp"
    assert rows["10.20.30.1"]["candidates"]["config"][0]["hostname"] == "edge-router"


def test_hostname_selection_keeps_source_and_version_history(tmp_path):
    db_path = tmp_path / "analyzer.db"
    first = select_host_identity(
        db_path,
        ip="10.10.10.1",
        hostname="dhcp-name",
        selection_source="dhcp",
        imported_by="analyst",
    )
    second = select_host_identity(
        db_path,
        ip="10.10.10.1",
        hostname="dns-name",
        selection_source="dns",
        imported_by="analyst",
    )

    retained = list_host_identities(db_path)[0]
    assert first["version"] == 1
    assert second["version"] == 2
    assert retained["hostname"] == "dns-name"
    assert retained["selection_source"] == "dns"


def test_hostname_page_moves_import_and_explains_zero_touch_refresh():
    html = hostname_page().body.decode()

    assert '<nav class="nav"' not in html
    assert 'aria-label="Primary"' not in html
    assert SHELL_SCRIPT.index("title:'Nmap scans'") < SHELL_SCRIPT.index("title:'Hostname evidence'") < SHELL_SCRIPT.index("title:'Current network'")
    assert "No network contact" in html
    assert "Hostname Upload" in html
    assert 'id="identityFile"' in html
    assert "/api/hostnames/import" in html
    assert "/api/hostnames/select" in html
    assert "@media(max-width:1100px){.methods,.collector-grid{grid-template-columns:1fr 1fr}" in html
    assert "/api/hostnames/select-source" in html
    assert "DHCP / lease" in html
    assert "LLDP / CDP" in html
    assert "SNMP" not in html
    assert "Use source where available" in html
    assert "operator_input:'Operator'" in html
    assert "Collect from DHCP and DNS servers" in html
    assert "Windows Server 2012 and newer" in html
    assert '<summary data-guide-key="windowsModern">Windows Server 2012 and newer</summary>' in html
    assert 'data-copy-target="windowsModern" data-guide-key="windowsModern"' in html
    assert "every IPv4 DHCP scope and every forward DNS zone" in html
    assert "An unexpected zero is a warning" in html
    assert 'Import-Module DhcpServer -ErrorAction Stop' in html
    assert 'Import-Module DnsServer -ErrorAction Stop' in html
    assert 'Get-DhcpServerv4Scope -ComputerName $Server -ErrorAction Stop' in html
    assert 'Get-DnsServerZone -ComputerName $Server -ErrorAction Stop' in html
    assert 'if ($Completed.Count -eq 0) { throw "No hostname collector completed.' in html
    assert 'Write-Warning "Partial collection:' in html
    assert "Verify permissions and expected source coverage" in html
    assert "Inspect it before transfer and upload" in html
    assert 'if ($LASTEXITCODE -ne 0) { $Failures += "DHCP scope' in html
    assert 'if ($LASTEXITCODE -ne 0) { $Failures += "DNS zone' in html
    assert 'throw "Legacy hostname collection failed.' in html
    assert "Legacy Windows Server fallback" in html
    assert "Linux DHCP and DNS servers" in html
    assert "netsh dhcp server" in html
    assert "dnscmd $Server /enumrecords" in html
    assert "kea-leases4.csv" in html
    assert "tcpdump -i any -nn -s 0" in html
    assert "Collection outputs may be up to 50 MB" in html
    assert 'id="accountabilityFile"' in html
    assert "/api/hostnames/evidence/import" in html


def test_server_evidence_csv_preserves_dhcp_dns_and_lease_time():
    parsed = parse_hostname_evidence_file(
        b"source,ip,hostname,lease_expires_at,observed_at\n"
        b"dhcp,10.20.30.40,leased-host,2030-01-02T03:04:05Z,2026-09-24T20:00:00Z\n"
        b"dns,10.20.30.40,dns-host.example,,,\n",
        "nct-hostname-evidence-windows.csv",
    )

    assert parsed["valid_count"] == 2
    assert parsed["source_counts"] == {"dhcp": 1, "dns": 1}
    dhcp = next(item for item in parsed["records"] if item["source"] == "dhcp")
    assert dhcp["lease_expires_at"].startswith("2030-01-02T03:04:05")


def test_server_evidence_understands_legacy_windows_and_linux_formats():
    parsed = parse_hostname_evidence_file(
        b"""===== DHCP scope 10.30.0.0 =====
10.30.0.15 - 255.255.255.0 - aa-bb-cc-dd-ee-ff - active - legacy-client
===== DNS zone example.local =====
legacy-dns 3600 IN A 10.30.0.25
===== DHCP ISC leases =====
lease 10.30.0.35 {
  ends 3 2030/01/02 03:04:05;
  client-hostname \"linux-client\";
}
""",
        "nct-hostname-evidence-legacy.txt",
    )

    found = {(item["source"], item["ip"], item["hostname"]) for item in parsed["records"]}
    assert ("dhcp", "10.30.0.15", "legacy-client") in found
    assert ("dns", "10.30.0.25", "legacy-dns.example.local") in found
    assert ("dhcp", "10.30.0.35", "linux-client") in found


def test_server_evidence_accepts_kea_memfile_csv_directly():
    parsed = parse_hostname_evidence_file(
        b"address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname\n"
        b"10.31.0.15,aa:bb:cc:dd:ee:ff,,3600,1893553445,1,1,1,kea-client\n",
        "kea-leases4.csv",
    )

    assert parsed["source_counts"] == {"dhcp": 1, "dns": 0}
    assert parsed["records"][0]["hostname"] == "kea-client"
    assert parsed["records"][0]["lease_expires_at"].startswith("2030-01-02")


def test_server_evidence_is_retained_with_optional_accountability_pcap(tmp_path):
    evidence_dir = tmp_path / "hostname-evidence"
    result = store_hostname_evidence(
        evidence_dir,
        b"source,ip,hostname,lease_expires_at\n"
        b"dhcp,10.40.0.10,workstation-10,2030-01-02T03:04:05Z\n"
        b"dns,10.40.0.10,workstation-10.example,\n",
        filename="windows.csv",
        imported_by="analyst",
        accountability_pcap=b"pcap-bytes",
        accountability_filename="collection.pcap",
    )

    retained = list_hostname_evidence(evidence_dir)
    assert len(retained) == 2
    assert {item["source"] for item in retained} == {"dhcp", "dns"}
    assert all(item["accountability_url"] for item in retained)
    pcap = hostname_accountability_file(evidence_dir, result["evidence_id"])
    assert pcap is not None
    assert pcap[0].read_bytes() == b"pcap-bytes"

    db_path = tmp_path / "analyzer.db"
    init_evidence_retirement_storage(db_path)
    workspace = build_hostname_workspace(
        db_path,
        topology={"nodes": []},
        config_dir=tmp_path / "device-configs",
        evidence_dir=evidence_dir,
    )
    row = workspace["rows"][0]
    assert row["candidates"]["dhcp"][0]["hostname"] == "workstation-10"
    assert row["candidates"]["dns"][0]["hostname"] == "workstation-10.example"
    assert row["candidates"]["dhcp"][0]["accountability_url"].endswith("/accountability")


def test_retired_hostname_upload_is_hidden_but_identical_sibling_and_bytes_remain(tmp_path):
    db_path = tmp_path / "analyzer.db"
    evidence_dir = tmp_path / "hostname-evidence"
    init_evidence_retirement_storage(db_path)
    content = (
        b"source,ip,hostname,lease_expires_at\n"
        b"dns,10.40.0.20,dns-20.example,\n"
    )
    first = store_hostname_evidence(
        evidence_dir,
        content,
        filename="dns.csv",
        imported_by="analyst-one",
        accountability_pcap=b"first-accountability",
        accountability_filename="first.pcap",
    )
    sibling = store_hostname_evidence(
        evidence_dir,
        content,
        filename="dns.csv",
        imported_by="analyst-two",
        accountability_pcap=b"second-accountability",
        accountability_filename="second.pcap",
    )

    retire_evidence(
        db_path,
        source_family=HOSTNAME_EVIDENCE_UPLOAD,
        encounter_id=first["evidence_id"],
        actor="reviewer",
        reason="Incorrect source context",
        adapter=hostname_evidence_upload_adapter(evidence_dir),
    )

    retained = list_hostname_evidence(evidence_dir, db_path=db_path)
    assert {item["evidence_id"] for item in retained} == {sibling["evidence_id"]}
    assert hostname_evidence_file(
        evidence_dir, first["evidence_id"], db_path=db_path,
    ) is None
    assert hostname_accountability_file(
        evidence_dir, first["evidence_id"], db_path=db_path,
    ) is None
    assert hostname_evidence_file(
        evidence_dir, sibling["evidence_id"], db_path=db_path,
    ) is not None
    assert (evidence_dir / first["evidence_id"] / "uploaded-dns.csv").read_bytes() == content
    assert (evidence_dir / first["evidence_id"] / "accountability.pcap").read_bytes() == b"first-accountability"
    with sqlite3.connect(db_path) as db:
        record = retirement_record(
            db,
            source_family=HOSTNAME_EVIDENCE_UPLOAD,
            encounter_id=first["evidence_id"],
        )
    assert record is not None
    assert record["reason"] == "Incorrect source context"


def test_retiring_hostname_upload_keeps_existing_analyst_selection(tmp_path):
    db_path = tmp_path / "analyzer.db"
    evidence_dir = tmp_path / "hostname-evidence"
    init_evidence_retirement_storage(db_path)
    upload = store_hostname_evidence(
        evidence_dir,
        b"source,ip,hostname,lease_expires_at\n"
        b"dhcp,10.40.0.30,approved-before-retirement,\n",
        filename="dhcp.csv",
        imported_by="analyst",
    )
    select_host_identity(
        db_path,
        ip="10.40.0.30",
        hostname="approved-before-retirement",
        selection_source="dhcp",
        imported_by="analyst",
    )

    retire_evidence(
        db_path,
        source_family=HOSTNAME_EVIDENCE_UPLOAD,
        encounter_id=upload["evidence_id"],
        actor="reviewer",
        reason="Retire supporting upload without rewriting analyst decision",
        adapter=hostname_evidence_upload_adapter(evidence_dir),
    )

    workspace = build_hostname_workspace(
        db_path,
        topology={"nodes": []},
        config_dir=tmp_path / "device-configs",
        evidence_dir=evidence_dir,
    )
    assert workspace["row_count"] == 1
    row = workspace["rows"][0]
    assert row["selected_hostname"] == "approved-before-retirement"
    assert row["selection_persisted"] is True
    assert row["candidates"]["dhcp"] == []


def test_hostname_upload_reads_fail_closed_without_retirement_authority(tmp_path):
    db_path = tmp_path / "analyzer.db"
    db_path.touch()
    evidence_dir = tmp_path / "hostname-evidence"
    upload = store_hostname_evidence(
        evidence_dir,
        b"source,ip,hostname,lease_expires_at\n"
        b"dns,10.40.0.40,dns-40.example,\n",
        filename="dns.csv",
        imported_by="analyst",
    )

    with pytest.raises(EvidenceRetirementError):
        list_hostname_evidence(evidence_dir, db_path=db_path)
    with pytest.raises(EvidenceRetirementError):
        hostname_evidence_file(
            evidence_dir, upload["evidence_id"], db_path=db_path,
        )


@pytest.mark.parametrize("damage", ["events", "lineage"])
def test_hostname_upload_reads_fail_closed_for_partial_retirement_authority(
    tmp_path, damage,
):
    db_path = tmp_path / "analyzer.db"
    evidence_dir = tmp_path / "hostname-evidence"
    init_evidence_retirement_storage(db_path)
    upload = store_hostname_evidence(
        evidence_dir,
        b"source,ip,hostname,lease_expires_at\n"
        b"dns,10.40.0.41,dns-41.example,\n",
        filename="dns.csv",
        imported_by="analyst",
    )
    with sqlite3.connect(db_path) as db:
        if damage == "events":
            db.execute("DROP TABLE evidence_retirement_identities")
            db.execute("DROP TABLE evidence_retirement_events")
        else:
            db.execute("DROP TRIGGER evidence_retirement_lineage_no_delete")
            db.execute("DELETE FROM evidence_retirement_lineage")
        db.commit()

    with pytest.raises(EvidenceRetirementError):
        list_hostname_evidence(evidence_dir, db_path=db_path)
    with pytest.raises(EvidenceRetirementError):
        hostname_evidence_file(
            evidence_dir, upload["evidence_id"], db_path=db_path,
        )


def test_hostname_manifest_cannot_claim_another_upload_identity(tmp_path):
    db_path = tmp_path / "analyzer.db"
    evidence_dir = tmp_path / "hostname-evidence"
    init_evidence_retirement_storage(db_path)
    upload = store_hostname_evidence(
        evidence_dir,
        b"source,ip,hostname,lease_expires_at\n"
        b"dns,10.40.0.42,dns-42.example,\n",
        filename="dns.csv",
        imported_by="analyst",
        accountability_pcap=b"pcap",
        accountability_filename="dns.pcap",
    )
    manifest_path = evidence_dir / upload["evidence_id"] / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["evidence_id"] = "f" * 32
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    assert list_hostname_evidence(evidence_dir, db_path=db_path) == []
    assert hostname_evidence_file(
        evidence_dir, upload["evidence_id"], db_path=db_path,
    ) is None
    assert hostname_accountability_file(
        evidence_dir, upload["evidence_id"], db_path=db_path,
    ) is None


def test_server_evidence_upload_and_download_routes(tmp_path, monkeypatch):
    evidence_dir = tmp_path / "hostname-evidence"
    monkeypatch.setattr("app.main.HOSTNAME_EVIDENCE_DIR", evidence_dir)
    with TestClient(app) as client:
        response = client.post(
            "/api/hostnames/evidence/import",
            files={
                "file": (
                    "windows.csv",
                    b"source,ip,hostname,lease_expires_at\n"
                    b"dhcp,10.50.0.10,desktop-10,2030-01-02T03:04:05Z\n",
                    "text/csv",
                ),
                "accountability": (
                    "collection.pcap", b"pcap-route-bytes", "application/vnd.tcpdump.pcap"
                ),
            },
        )
        assert response.status_code == 200
        payload = response.json()
        assert payload["valid_count"] == 1
        assert payload["source_counts"] == {"dhcp": 1, "dns": 0}

        evidence = client.get(payload["evidence_url"])
        accountability = client.get(payload["accountability_url"])
        assert evidence.status_code == 200
        assert b"desktop-10" in evidence.content
        assert accountability.status_code == 200
        assert accountability.content == b"pcap-route-bytes"

        large_content = (
            b"source,ip,hostname,lease_expires_at\n"
            + (b"#" + (b"x" * 1022) + b"\n") * 5200
            + b"dns,10.50.0.20,beyond-five-megabytes.example,\n"
        )
        assert len(large_content) > 5 * 1024 * 1024
        large_response = client.post(
            "/api/hostnames/evidence/import",
            files={"file": ("large-dns.csv", large_content, "text/csv")},
        )
        assert large_response.status_code == 200
        assert large_response.json()["source_counts"] == {"dhcp": 0, "dns": 1}


def test_retired_hostname_upload_is_not_available_from_workspace_or_download_routes(
    tmp_path, monkeypatch,
):
    db_path = tmp_path / "analyzer.db"
    evidence_dir = tmp_path / "hostname-evidence"
    monkeypatch.setattr("app.main.DB_PATH", db_path)
    monkeypatch.setattr("app.main.HOSTNAME_EVIDENCE_DIR", evidence_dir)

    with TestClient(app) as client:
        upload = store_hostname_evidence(
            evidence_dir,
            b"source,ip,hostname,lease_expires_at\n"
            b"dns,10.50.0.30,retired-dns.example,\n",
            filename="retired.csv",
            imported_by="analyst",
            accountability_pcap=b"retired-pcap",
            accountability_filename="retired.pcap",
        )
        retire_evidence(
            db_path,
            source_family=HOSTNAME_EVIDENCE_UPLOAD,
            encounter_id=upload["evidence_id"],
            actor="reviewer",
            reason="Incorrect upload",
            adapter=hostname_evidence_upload_adapter(evidence_dir),
        )

        workspace = client.get("/api/hostnames")
        source = client.get(upload["evidence_url"])
        accountability = client.get(upload["accountability_url"])

        assert workspace.status_code == 200
        assert workspace.json()["row_count"] == 0
        assert source.status_code == 404
        assert accountability.status_code == 404
        assert (evidence_dir / upload["evidence_id"] / "manifest.json").is_file()
        assert (evidence_dir / upload["evidence_id"] / "accountability.pcap").is_file()


def test_normal_device_pulls_include_hostname_recovery_commands():
    assert "show ip dhcp binding" in TEMPLATES["cisco"]["router"]
    assert "show hosts" in TEMPLATES["cisco"]["router"]
    assert "show dhcp server leases" in TEMPLATES["vyos"]["router"]
    assert "cat /var/dhcpd/var/db/dhcpd.leases" in TEMPLATES["pfsense"]["firewall"]
    assert "cat /run/dnsmasq.leases" in TEMPLATES["unifi"]["router"]
