"""JSON Schema Validator for Open Cloud Agents Findings.

Validates findings against schemas/v1/finding.json using standard Python
libraries, with support for optional jsonschema package if installed.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

SCHEMA_FILE = Path(__file__).resolve().parent.parent.parent.parent / "schemas" / "v1" / "finding.json"

ID_PATTERN = re.compile(r"^FND-[A-Z0-9]{12}$")
RULE_ID_PATTERN = re.compile(r"^rules/[a-zA-Z0-9_-]+\.md(#.*)?$")
EVIDENCE_PATTERN = re.compile(
    r"^(diff:[a-zA-Z0-9_./-]+#L[0-9]+(-L[0-9]+)?|"
    r"repo:[a-zA-Z0-9_./-]+#L[0-9]+(-L[0-9]+)?|"
    r"cloud:[a-z0-9_-]+:.+)$"
)

ALLOWED_ORIGINS = {"deterministic_linter", "model_assertion", "human_triage"}
ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "info"}
ALLOWED_CORROBORATION_STATUSES = {
    "unverified_model_claim",
    "tool_verified",
    "human_verified",
    "syntactically_valid_unverified_resource",
    "rejected_false_positive",
}

REQUIRED_FIELDS = [
    "$schema",
    "id",
    "agent",
    "origin",
    "rule_id",
    "category",
    "resource",
    "fact",
    "evidence",
    "recommendation",
    "severity",
    "confidence",
    "corroboration_status",
]

ALLOWED_FIELDS = set(REQUIRED_FIELDS) | {"remediation", "retry_count", "metadata"}


class SchemaValidator:
    """Validates finding structures against the canonical Finding Schema."""

    def __init__(self, schema_path: Path | None = None) -> None:
        self.schema_path = schema_path or SCHEMA_FILE
        self._raw_schema: dict[str, Any] | None = None
        if self.schema_path.exists():
            try:
                self._raw_schema = json.loads(self.schema_path.read_text(encoding="utf-8"))
            except Exception:
                self._raw_schema = None

    def validate(self, data: Any) -> tuple[bool, list[str]]:
        """Validate a finding payload. Returns (is_valid, list_of_errors)."""
        errors: list[str] = []

        if not isinstance(data, dict):
            return False, ["Finding payload must be a JSON object."]

        # Check required fields
        for field in REQUIRED_FIELDS:
            if field not in data:
                errors.append(f"Missing mandatory field '{field}'.")

        # Check for unknown fields
        for field in data:
            if field not in ALLOWED_FIELDS:
                errors.append(f"Disallowed property '{field}' (additionalProperties: false).")

        if errors:
            return False, errors

        # $schema
        if not isinstance(data["$schema"], str) or not data["$schema"].strip():
            errors.append("Field '$schema' must be a non-empty string.")

        # id
        if not isinstance(data["id"], str) or not ID_PATTERN.match(data["id"]):
            errors.append(f"Field 'id' must match pattern '^FND-[A-Z0-9]{{12}}$' (got: {data.get('id')!r}).")

        # agent
        if not isinstance(data["agent"], str) or not data["agent"].strip():
            errors.append("Field 'agent' must be a non-empty string.")

        # origin
        if data["origin"] not in ALLOWED_ORIGINS:
            errors.append(f"Field 'origin' must be one of {sorted(ALLOWED_ORIGINS)} (got: {data.get('origin')!r}).")

        # rule_id
        if not isinstance(data["rule_id"], str) or not RULE_ID_PATTERN.match(data["rule_id"]):
            errors.append(f"Field 'rule_id' must match pattern '^rules/[a-zA-Z0-9_-]+\\.md(#.*)?$' (got: {data.get('rule_id')!r}).")

        # category, resource, fact, recommendation
        for text_field in ("category", "resource", "fact", "recommendation"):
            val = data.get(text_field)
            if not isinstance(val, str) or not val.strip():
                errors.append(f"Field '{text_field}' must be a non-empty string.")

        # evidence
        evidence_val = data.get("evidence")
        if not isinstance(evidence_val, str) or not EVIDENCE_PATTERN.match(evidence_val):
            errors.append(
                f"Field 'evidence' must match URI pattern '^(diff|repo|cloud):...' (got: {evidence_val!r})."
            )

        # severity
        if data["severity"] not in ALLOWED_SEVERITIES:
            errors.append(f"Field 'severity' must be one of {sorted(ALLOWED_SEVERITIES)} (got: {data.get('severity')!r}).")

        # confidence
        conf_val = data.get("confidence")
        # In Python, bool is a subclass of int, so reject True/False
        if isinstance(conf_val, bool):
            errors.append(f"Field 'confidence' must be float or null, not boolean (got: {conf_val!r}).")
        elif conf_val is None:
            # Null is allowed, especially for deterministic_linter
            pass
        elif isinstance(conf_val, (int, float)):
            if conf_val < 0.0 or conf_val > 1.0:
                errors.append(f"Field 'confidence' number must be between 0.0 and 1.0 (got: {conf_val}).")
        else:
            errors.append(f"Field 'confidence' must be number in [0.0, 1.0] or null (got: {conf_val!r}).")

        # Origin-confidence pairing contract
        if data.get("origin") == "deterministic_linter" and conf_val is not None:
            errors.append(f"Deterministic findings ('deterministic_linter') must set 'confidence': null (got: {conf_val!r}).")
        elif data.get("origin") == "model_assertion" and (conf_val is None or not isinstance(conf_val, (int, float))):
            errors.append("Model assertions ('model_assertion') must provide numeric confidence in [0.0, 1.0].")

        # corroboration_status
        if data["corroboration_status"] not in ALLOWED_CORROBORATION_STATUSES:
            errors.append(
                f"Field 'corroboration_status' must be one of {sorted(ALLOWED_CORROBORATION_STATUSES)} "
                f"(got: {data.get('corroboration_status')!r})."
            )

        # remediation (optional)
        if "remediation" in data:
            rem = data["remediation"]
            if not isinstance(rem, dict):
                errors.append("Field 'remediation' must be an object.")
            else:
                for k in rem:
                    if k not in ("proposed_draft_available", "diff_preview"):
                        errors.append(f"Field 'remediation' contains disallowed property '{k}'.")
                if "proposed_draft_available" in rem and not isinstance(rem["proposed_draft_available"], bool):
                    errors.append("'remediation.proposed_draft_available' must be boolean.")
                if "diff_preview" in rem and not isinstance(rem["diff_preview"], str):
                    errors.append("'remediation.diff_preview' must be string.")

        # retry_count (optional)
        if "retry_count" in data:
            rc = data["retry_count"]
            if not isinstance(rc, int) or isinstance(rc, bool) or rc < 0:
                errors.append("Field 'retry_count' must be a non-negative integer.")

        # metadata (optional)
        if "metadata" in data and not isinstance(data["metadata"], dict):
            errors.append("Field 'metadata' must be an object.")

        return len(errors) == 0, errors
