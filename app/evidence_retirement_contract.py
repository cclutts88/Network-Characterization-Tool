"""Auditable coverage contract for cross-evidence retirement integration.

This file is intentionally data, not runtime policy.  Tests and the independent
review gate use it to keep every source family and projection route visible while
the integrations are implemented one gate at a time.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RetirementSourceContract:
    source_family: str
    encounter_identity: str
    producer: str
    inherited_children: tuple[str, ...] = ()


SOURCE_CONTRACTS = (
    RetirementSourceContract(
        "nmap_scan_run", "run_id", "automated Nmap scan completion",
        ("scan capture", "registered scan artifacts"),
    ),
    RetirementSourceContract(
        "nmap_import", "observation_id", "manual Nmap XML import",
        ("registered import artifact",),
    ),
    RetirementSourceContract(
        "device_collection", "run_id", "device configuration collection or upload",
        ("configuration output", "accountability capture", "registered artifacts"),
    ),
    RetirementSourceContract(
        "arkime_sessions_import", "import_id", "Arkime Sessions import or connector pull",
        ("registered source artifact", "session receipts"),
    ),
    RetirementSourceContract(
        "arkime_summary_import", "import_id", "Arkime Summary CSV import",
        ("registered source artifact", "summary receipts"),
    ),
    RetirementSourceContract(
        "hostname_evidence_upload", "evidence_id", "hostname evidence upload",
        ("accountability capture", "hostname records"),
    ),
)


# Each route is a separate acceptance obligation.  A route may be marked covered
# only by a focused retirement test that proves retired sources are excluded while
# retained audit/provenance remains readable.
PROJECTION_ROUTES = (
    "source-history",
    "raw-evidence-download",
    "evidence-library",
    "ingestion-status",
    "derived-result-status",
    "background-admission",
    "background-retry",
    "prepared-nmap-analysis",
    "device-analysis",
    "arkime-coverage",
    "arkime-analytics",
    "arkime-history",
    "searchsploit-enrichment",
    "exposure-reports",
    "current-network",
    "network-devices",
    "changes-over-time",
    "hunt",
    "reach",
    "map-topology",
    "map",
    "operator-exports",
    "cache-revisions",
)


# Foundation state: no route is claimed until the corresponding integration and
# regression tests exist.  This mapping is deliberately exhaustive and is updated
# in the same change that implements each route.
ROUTE_COVERAGE: dict[str, frozenset[str]] = {
    source.source_family: frozenset() for source in SOURCE_CONTRACTS
}
ROUTE_COVERAGE.update({
    "nmap_scan_run": frozenset({
        "evidence-library", "current-network", "hunt", "map-topology",
    }),
    "nmap_import": frozenset({
        "evidence-library", "source-history", "raw-evidence-download",
        "operator-exports", "current-network", "hunt", "map-topology",
    }),
    "device_collection": frozenset({
        "evidence-library", "current-network", "hunt", "map-topology",
    }),
    "arkime_sessions_import": frozenset({"hunt"}),
})


def source_contract(source_family: str) -> RetirementSourceContract:
    for contract in SOURCE_CONTRACTS:
        if contract.source_family == source_family:
            return contract
    raise KeyError(f"Unsupported evidence source family: {source_family}")

