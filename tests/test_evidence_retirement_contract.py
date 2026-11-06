from app.evidence_retirement_contract import (
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
    assert all(item.encounter_identity for item in SOURCE_CONTRACTS)
    assert source_contract("nmap_import").encounter_identity == "observation_id"


def test_route_inventory_is_unique_and_coverage_never_invents_routes():
    assert len(PROJECTION_ROUTES) == len(set(PROJECTION_ROUTES))
    assert len(PROJECTION_ROUTES) >= 20
    allowed = set(PROJECTION_ROUTES)
    assert all(set(routes) <= allowed for routes in ROUTE_COVERAGE.values())

