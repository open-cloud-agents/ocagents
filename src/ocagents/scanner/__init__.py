"""
Open Cloud Agents: Deterministic Scanner & Pre-Flight Sensor Ingestion (v1.5+).

Provides scanner catalogs, file mapping registries, tool requirement enforcement,
and pre-flight sensor ingestion in accordance with ADR-002 (Pillar 3).
"""

from ocagents.scanner.registry import (
    RequirementLevel,
    ScannerCategory,
    ScannerDefinition,
    ScannerRegistry,
    get_advisory_scanners,
    get_default_registry,
    get_required_scanners,
    get_scanners_for_changeset,
    get_scanners_for_file,
    is_k8s_or_iac_manifest,
)

__all__ = [
    "RequirementLevel",
    "ScannerCategory",
    "ScannerDefinition",
    "ScannerRegistry",
    "get_advisory_scanners",
    "get_default_registry",
    "get_required_scanners",
    "get_scanners_for_changeset",
    "get_scanners_for_file",
    "is_k8s_or_iac_manifest",
]
