"""Open Cloud Agents: Structured Findings & Provenance Validation Engine.

Provides JSON schema validation, rule catalog integrity verification, and
multi-target evidence anchor corroboration (v1.4+).
"""

from ocagents.findings.schema_validator import SchemaValidator
from ocagents.findings.provenance import ProvenanceVerifier, resolve_default_repo_root
from ocagents.findings.validator import FindingValidator, ValidationResult
from ocagents.findings.normalizer import (
    SarifNormalizer,
    normalize_sarif,
    compute_finding_id,
    map_rule_id,
    map_severity,
    map_category,
)

__all__ = [
    "SchemaValidator",
    "ProvenanceVerifier",
    "FindingValidator",
    "ValidationResult",
    "resolve_default_repo_root",
    "SarifNormalizer",
    "normalize_sarif",
    "compute_finding_id",
    "map_rule_id",
    "map_severity",
    "map_category",
]
