from app.evidence_retirement_contract import (
    APPLICABLE_ROUTES,
    AUDIT_ONLY_ROUTES,
    PROJECTION_ROUTES,
    ROUTE_COVERAGE,
    SOURCE_CONTRACTS,
    source_contract,
)


EXPECTED_FAMILIES = {
    "nmap_scan_run",
    "nmap_import",
    "device_collection",
    "arkime_sessions_import",
    "arkime_summary_import",
    "hostname_evidence_upload",
}


def test_cross_evidence_contract_names_every_supported_encounter_family():
    families = [item.source_family for item in SOURCE_CONTRACTS]
    assert set(families) == EXPECTED_FAMILIES
    assert len(families) == len(set(families))
    assert set(ROUTE_COVERAGE) == EXPECTED_FAMILIES
    assert set(APPLICABLE_ROUTES) == EXPECTED_FAMILIES
    assert all(item.encounter_identity for item in SOURCE_CONTRACTS)
    assert source_contract("nmap_import").encounter_identity == "observation_id"


def test_route_inventory_is_unique_and_coverage_never_invents_routes():
    assert len(PROJECTION_ROUTES) == len(set(PROJECTION_ROUTES))
    assert len(PROJECTION_ROUTES) >= 20
    allowed = set(PROJECTION_ROUTES)
    assert all(set(routes) <= allowed for routes in ROUTE_COVERAGE.values())
    assert ROUTE_COVERAGE == APPLICABLE_ROUTES
    assert set(AUDIT_ONLY_ROUTES) == {"derived-result-status"}
    assert all(
        route not in routes
        for route in AUDIT_ONLY_ROUTES
        for routes in ROUTE_COVERAGE.values()
    )
    boundary = AUDIT_ONLY_ROUTES["derived-result-status"]
    assert "no payload" in boundary
    assert "download" in boundary


def test_ingestion_status_is_claimed_only_for_supported_pipeline_sources():
    assert "ingestion-status" in ROUTE_COVERAGE["nmap_scan_run"]
    assert "ingestion-status" in ROUTE_COVERAGE["nmap_import"]
    assert "ingestion-status" in ROUTE_COVERAGE["device_collection"]
    assert all(
        "ingestion-status" not in ROUTE_COVERAGE[source_family]
        for source_family in (
            "arkime_sessions_import",
            "arkime_summary_import",
            "hostname_evidence_upload",
        )
    )


def test_evidence_library_route_is_claimed_only_for_cataloged_source_families():
    assert "evidence-library" in ROUTE_COVERAGE["nmap_scan_run"]
    assert "evidence-library" in ROUTE_COVERAGE["nmap_import"]
    assert "evidence-library" in ROUTE_COVERAGE["device_collection"]
    assert all(
        "evidence-library" not in ROUTE_COVERAGE[source_family]
        for source_family in (
            "arkime_sessions_import",
            "arkime_summary_import",
            "hostname_evidence_upload",
        )
    )


def test_nmap_import_shared_content_gateway_claims_only_completed_routes():
    assert {
        "source-history", "raw-evidence-download", "operator-exports",
    } <= ROUTE_COVERAGE["nmap_import"]
    assert "current-network" in ROUTE_COVERAGE["nmap_import"]
    assert {"map-topology", "map", "reach"} <= ROUTE_COVERAGE["nmap_import"]


def test_map_workspace_and_topology_are_closed_for_map_source_families():
    for source_family in ("nmap_scan_run", "nmap_import", "device_collection"):
        assert "map-topology" in ROUTE_COVERAGE[source_family]
        assert "map" in ROUTE_COVERAGE[source_family]


def test_current_network_and_hunt_claim_only_integrated_source_families():
    for source_family in ("nmap_scan_run", "nmap_import", "device_collection"):
        assert {"current-network", "hunt"} <= ROUTE_COVERAGE[source_family]
    assert "hunt" in ROUTE_COVERAGE["arkime_sessions_import"]
    assert "hunt" not in ROUTE_COVERAGE["arkime_summary_import"]
    for source_family in ("arkime_summary_import",):
        assert "current-network" not in ROUTE_COVERAGE[source_family]
        assert "hunt" not in ROUTE_COVERAGE[source_family]
    assert {"current-network", "hunt"} <= ROUTE_COVERAGE["hostname_evidence_upload"]

