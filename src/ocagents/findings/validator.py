"""Unified Finding Validator for Open Cloud Agents.

Orchestrates JSON Schema validation, rule catalog integrity verification,
and multi-target evidence anchor corroboration.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ocagents.findings.schema_validator import SchemaValidator
from ocagents.findings.provenance import ProvenanceVerifier


@dataclass
class ValidationResult:
    """Encapsulates the result of finding validation and corroboration."""

    is_valid: bool
    schema_errors: list[str] = field(default_factory=list)
    provenance_errors: list[str] = field(default_factory=list)
    finding_id: str | None = None
    rule_id: str | None = None
    corroboration_status: str | None = None

    @property
    def all_errors(self) -> list[str]:
        return self.schema_errors + self.provenance_errors

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "corroboration_status": self.corroboration_status,
            "schema_errors": self.schema_errors,
            "provenance_errors": self.provenance_errors,
        }


class FindingValidator:
    """Unified validator combining JSON Schema and Provenance anchor verification."""

    def __init__(self, repo_root: Path | None = None) -> None:
        self.repo_root = (repo_root or Path.cwd()).resolve()
        self.schema_validator = SchemaValidator()
        self.provenance_verifier = ProvenanceVerifier(repo_root=self.repo_root)

    def validate_dict(
        self,
        finding_data: dict[str, Any],
        diff_text: str | None = None,
        check_provenance: bool = True,
    ) -> ValidationResult:
        """Validate an in-memory finding dictionary."""
        schema_valid, schema_errors = self.schema_validator.validate(finding_data)
        if not schema_valid:
            return ValidationResult(
                is_valid=False,
                schema_errors=schema_errors,
                finding_id=finding_data.get("id") if isinstance(finding_data, dict) else None,
                rule_id=finding_data.get("rule_id") if isinstance(finding_data, dict) else None,
            )

        provenance_errors: list[str] = []
        finding_id = finding_data["id"]
        rule_id = finding_data["rule_id"]
        evidence = finding_data["evidence"]
        status = finding_data["corroboration_status"]

        if check_provenance:
            # 1. Rule Catalog check
            rule_ok, rule_err = self.provenance_verifier.verify_rule(rule_id)
            if not rule_ok and rule_err:
                provenance_errors.append(rule_err)

            # 2. Evidence Anchor check
            ev_ok, ev_err = self.provenance_verifier.verify_evidence(
                evidence, diff_text=diff_text
            )
            if not ev_ok and ev_err:
                provenance_errors.append(ev_err)

        is_valid = len(provenance_errors) == 0
        return ValidationResult(
            is_valid=is_valid,
            schema_errors=[],
            provenance_errors=provenance_errors,
            finding_id=finding_id,
            rule_id=rule_id,
            corroboration_status=status,
        )

    def validate_file(
        self,
        file_path: Path | str,
        diff_text: str | None = None,
        check_provenance: bool = True,
    ) -> ValidationResult:
        """Read and validate a finding JSON file from disk."""
        target_path = Path(file_path).resolve()
        if not target_path.is_file():
            return ValidationResult(
                is_valid=False,
                schema_errors=[f"Finding file not found: {target_path}"],
            )

        try:
            with target_path.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as exc:
            return ValidationResult(
                is_valid=False,
                schema_errors=[f"Malformed JSON syntax in '{target_path.name}': {exc}"],
            )
        except Exception as exc:
            return ValidationResult(
                is_valid=False,
                schema_errors=[f"Failed to read finding file: {exc}"],
            )

        return self.validate_dict(
            data, diff_text=diff_text, check_provenance=check_provenance
        )

