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
from ocagents.scanner.diff_filter import (
    filter_findings_by_diff,
    is_finding_in_diff,
    parse_diff_modified_lines,
)
from ocagents.scanner.checkov import CheckovAdapter, parse_checkov_output
from ocagents.scanner.trivy import TrivyAdapter, parse_trivy_output
from ocagents.scanner.opa import OpaEvaluator, evaluate_manifest, evaluate_terraform_plan
from ocagents.scanner.exceptions import ExceptionRecord, ExceptionsManifest
from ocagents.scanner.availability import (
    AvailabilityReport,
    AvailabilityStatus,
    ScannerAvailabilityProtocol,
)
from ocagents.scanner.preflight import (
    PreflightEngine,
    PreflightResult,
    audit_diff_heuristics,
    parse_diff_target_files,
    run_preflight,
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
    "parse_diff_modified_lines",
    "is_finding_in_diff",
    "filter_findings_by_diff",
    "CheckovAdapter",
    "parse_checkov_output",
    "TrivyAdapter",
    "parse_trivy_output",
    "OpaEvaluator",
    "evaluate_manifest",
    "evaluate_terraform_plan",
    "ExceptionRecord",
    "ExceptionsManifest",
    "AvailabilityReport",
    "AvailabilityStatus",
    "ScannerAvailabilityProtocol",
    "PreflightEngine",
    "PreflightResult",
    "run_preflight",
    "audit_diff_heuristics",
    "parse_diff_target_files",
]
