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


# Source-specific obligations avoid pretending that every evidence family feeds
# every projection. A release may enable retirement controls only when coverage is
# exactly equal to these applicable routes and each claim has a focused test.
APPLICABLE_ROUTES: dict[str, frozenset[str]] = {
    "nmap_scan_run": frozenset({
        "source-history", "raw-evidence-download", "evidence-library",
        "ingestion-status", "background-admission",
        "background-retry", "prepared-nmap-analysis", "searchsploit-enrichment",
        "exposure-reports", "current-network", "changes-over-time", "hunt",
        "reach", "map-topology", "map", "operator-exports", "cache-revisions",
    }),
    "nmap_import": frozenset({
        "evidence-library", "source-history", "raw-evidence-download", "ingestion-status",
        "prepared-nmap-analysis", "exposure-reports", "operator-exports",
        "current-network", "hunt", "reach", "map-topology", "map",
        "cache-revisions",
    }),
    "device_collection": frozenset({
        "source-history", "raw-evidence-download", "evidence-library",
        "ingestion-status", "background-admission",
        "background-retry", "device-analysis", "exposure-reports",
        "current-network", "network-devices", "changes-over-time", "hunt",
        "reach", "map-topology", "map", "operator-exports", "cache-revisions",
    }),
    "arkime_sessions_import": frozenset({
        "source-history", "raw-evidence-download",
        "background-admission", "background-retry",
        "arkime-coverage", "arkime-analytics", "arkime-history", "hunt",
        "operator-exports", "cache-revisions",
    }),
    "arkime_summary_import": frozenset({
        "source-history", "raw-evidence-download",
        "arkime-coverage", "arkime-analytics", "arkime-history",
        "operator-exports", "cache-revisions",
    }),
    "hostname_evidence_upload": frozenset({
        "source-history", "raw-evidence-download",
        "current-network", "hunt", "map-topology", "map", "operator-exports",
        "cache-revisions",
    }),
}


# Calculation-contract status is an administrator-only, metadata-only audit of
# immutable result format/version records. It exposes no result payload, source
# bytes, ordinary analysis link, selection action, or download. Results derived
# from retired sources may remain in this bounded audit because it is not an
# ordinary evidence projection.
AUDIT_ONLY_ROUTES: dict[str, str] = {
    "derived-result-status": (
        "administrator-only calculation contract metadata; no payload, source "
        "link, selection action, analysis action, or download"
    ),
}


# Independently maintained implementation claims. Do not derive this mapping
# from APPLICABLE_ROUTES: reviewers must see an explicit omission whenever an
# ordinary consumer has not been qualified.
ROUTE_COVERAGE: dict[str, frozenset[str]] = {
    "nmap_scan_run": frozenset({
        "source-history", "raw-evidence-download", "evidence-library",
        "ingestion-status", "background-admission", "background-retry",
        "prepared-nmap-analysis", "searchsploit-enrichment", "exposure-reports",
        "current-network", "changes-over-time", "hunt", "reach",
        "map-topology", "map", "operator-exports", "cache-revisions",
    }),
    "nmap_import": frozenset({
        "evidence-library", "source-history", "raw-evidence-download", "ingestion-status",
        "prepared-nmap-analysis", "exposure-reports", "operator-exports",
        "current-network", "hunt", "reach", "map-topology", "map",
        "cache-revisions",
    }),
    "device_collection": frozenset({
        "source-history", "raw-evidence-download", "evidence-library",
        "ingestion-status", "background-admission", "background-retry",
        "device-analysis", "exposure-reports", "current-network",
        "network-devices", "changes-over-time", "hunt", "reach",
        "map-topology", "map", "operator-exports", "cache-revisions",
    }),
    "arkime_sessions_import": frozenset({
        "source-history", "raw-evidence-download", "background-admission",
        "background-retry", "arkime-coverage", "arkime-analytics",
        "arkime-history", "hunt", "operator-exports", "cache-revisions",
    }),
    "arkime_summary_import": frozenset({
        "source-history", "raw-evidence-download", "arkime-coverage",
        "arkime-analytics", "arkime-history", "operator-exports",
        "cache-revisions",
    }),
    "hostname_evidence_upload": frozenset({
        "source-history", "raw-evidence-download", "current-network", "hunt",
        "map-topology", "map", "operator-exports", "cache-revisions",
    }),
}


def source_contract(source_family: str) -> RetirementSourceContract:
    for contract in SOURCE_CONTRACTS:
        if contract.source_family == source_family:
            return contract
    raise KeyError(f"Unsupported evidence source family: {source_family}")

