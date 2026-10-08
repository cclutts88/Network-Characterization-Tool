"""Trusted calculation contracts shared by reusable adapters and status readers."""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from app.device_limits import (
    MAX_RESPONSE_OUTPUT_CHARS,
    MAX_SUMMARY_ITEMS,
    MAX_SUMMARY_TEXT_BYTES,
)


@dataclass(frozen=True)
class DerivedResultContract:
    family: str
    label: str
    analysis_version: str
    payload_schema_version: int
    parameters: Mapping[str, object]
    input_kinds: Mapping[str, tuple[str, ...]]


NMAP_BASE_ANALYSIS_FAMILY = "nmap_base_analysis"
NMAP_BASE_ANALYSIS_VERSION = "nmap-base-analysis:1"
NMAP_BASE_PAYLOAD_SCHEMA_VERSION = 1
NMAP_BASE_PARAMETERS = MappingProxyType({
    "parser": "nct.parse_xml",
    "coverage_presence_os_inference_contract": 1,
})

NMAP_TOPOLOGY_FAMILY = "nmap_topology_hosts"
NMAP_TOPOLOGY_VERSION = "nmap-topology-hosts:1"
NMAP_TOPOLOGY_PAYLOAD_SCHEMA_VERSION = 1
NMAP_TOPOLOGY_PARAMETERS = MappingProxyType({
    "parser": "nct.network_map.parse_nmap_xml",
    "legacy_topology_contract": 1,
})

DEVICE_SUMMARY_FAMILY = "device_collection_summary"
DEVICE_SUMMARY_VERSION = "device-collection-summary:1"
DEVICE_SUMMARY_SCHEMA_VERSION = 1
DEVICE_SUMMARY_PARAMETERS = MappingProxyType({
    "snapshot_contract": 1,
    "configuration_selection": "sorted-uploaded_then_sorted-collected_then-stdout",
    "raw_selection": "stdout_then_configuration-order",
    "utf8_errors": "replace",
    "max_summary_text_bytes": MAX_SUMMARY_TEXT_BYTES,
    "max_history_text_chars": MAX_RESPONSE_OUTPUT_CHARS,
    "max_summary_items": MAX_SUMMARY_ITEMS,
    "parser_bundle": "device-summary-parsers:1",
})

SEARCHSPLOIT_CANDIDATES_FAMILY = "nmap_searchsploit_candidates"
SEARCHSPLOIT_CANDIDATES_VERSION = "nmap-searchsploit-candidates:1"
SEARCHSPLOIT_CANDIDATES_SCHEMA_VERSION = 1
SEARCHSPLOIT_CANDIDATES_PARAMETERS = MappingProxyType({
    "matching_contract": 1,
    "query_source": "retained_nmap_product_version_fingerprints",
    "max_distinct_queries": 40,
    "max_candidates_per_query": 25,
})


SUPPORTED_DERIVED_RESULT_CONTRACTS = MappingProxyType({
    NMAP_BASE_ANALYSIS_FAMILY: DerivedResultContract(
        family=NMAP_BASE_ANALYSIS_FAMILY,
        label="Nmap analysis",
        analysis_version=NMAP_BASE_ANALYSIS_VERSION,
        payload_schema_version=NMAP_BASE_PAYLOAD_SCHEMA_VERSION,
        parameters=NMAP_BASE_PARAMETERS,
        input_kinds=MappingProxyType({"nmap_xml": ("artifact_sha256",)}),
    ),
    NMAP_TOPOLOGY_FAMILY: DerivedResultContract(
        family=NMAP_TOPOLOGY_FAMILY,
        label="Nmap topology",
        analysis_version=NMAP_TOPOLOGY_VERSION,
        payload_schema_version=NMAP_TOPOLOGY_PAYLOAD_SCHEMA_VERSION,
        parameters=NMAP_TOPOLOGY_PARAMETERS,
        input_kinds=MappingProxyType({"nmap_xml": ("artifact_sha256",)}),
    ),
    DEVICE_SUMMARY_FAMILY: DerivedResultContract(
        family=DEVICE_SUMMARY_FAMILY,
        label="Device summary",
        analysis_version=DEVICE_SUMMARY_VERSION,
        payload_schema_version=DEVICE_SUMMARY_SCHEMA_VERSION,
        parameters=DEVICE_SUMMARY_PARAMETERS,
        input_kinds=MappingProxyType({
            "configuration": ("artifact_sha256",),
            "raw_output": ("artifact_sha256",),
            "command_history": (
                "artifact_sha256", "embedded_config_section", "absence_descriptor",
            ),
            "manifest_semantics": ("canonical_json_sha256",),
            "selection_shape": ("canonical_json_sha256",),
        }),
    ),
    SEARCHSPLOIT_CANDIDATES_FAMILY: DerivedResultContract(
        family=SEARCHSPLOIT_CANDIDATES_FAMILY,
        label="Offline CVE candidate assessment",
        analysis_version=SEARCHSPLOIT_CANDIDATES_VERSION,
        payload_schema_version=SEARCHSPLOIT_CANDIDATES_SCHEMA_VERSION,
        parameters=SEARCHSPLOIT_CANDIDATES_PARAMETERS,
        input_kinds=MappingProxyType({
            "nmap_xml": ("artifact_sha256",),
            "offline_dataset": ("searchsploit_dataset_sha256",),
        }),
    ),
})
