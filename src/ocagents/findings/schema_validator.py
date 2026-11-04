"""JSON Schema Validator for Open Cloud Agents Findings.

Validates findings against schemas/v1/finding.json using schema-driven constraints,
with support for optional jsonschema package if installed.
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

        self.required_fields = list(REQUIRED_FIELDS)
        self.allowed_fields = set(ALLOWED_FIELDS)
        self.allowed_origins = set(ALLOWED_ORIGINS)
        self.allowed_severities = set(ALLOWED_SEVERITIES)
        self.allowed_corroborations = set(ALLOWED_CORROBORATION_STATUSES)

        if self.schema_path.exists():
            try:
                self._raw_schema = json.loads(self.schema_path.read_text(encoding="utf-8"))
                if isinstance(self._raw_schema, dict):
                    if "required" in self._raw_schema and isinstance(self._raw_schema["required"], list):
                        self.required_fields = self._raw_schema["required"]
                    props = self._raw_schema.get("properties", {})
                    if props:
                        self.allowed_fields = set(props.keys())
                        if "origin" in props and "enum" in props["origin"]:
                            self.allowed_origins = set(props["origin"]["enum"])
                        if "severity" in props and "enum" in props["severity"]:
                            self.allowed_severities = set(props["severity"]["enum"])
                        if "corroboration_status" in props and "enum" in props["corroboration_status"]:
                            self.allowed_corroborations = set(props["corroboration_status"]["enum"])
            except Exception:
                self._raw_schema = None

    def validate(self, data: Any) -> tuple[bool, list[str]]:
        """Validate a finding payload. Returns (is_valid, list_of_errors)."""
        errors: list[str] = []

        if not isinstance(data, dict):
            return False, ["Finding payload must be a JSON object."]

        # Check required fields
        for field in self.required_fields:
            if field not in data:
                errors.append(f"Missing mandatory field '{field}'.")

        # Check for unknown fields (additionalProperties: false)
        for field in data:
            if field not in self.allowed_fields:
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
        if data["origin"] not in self.allowed_origins:
            errors.append(f"Field 'origin' must be one of {sorted(self.allowed_origins)} (got: {data.get('origin')!r}).")

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
        if data["severity"] not in self.allowed_severities:
            errors.append(f"Field 'severity' must be one of {sorted(self.allowed_severities)} (got: {data.get('severity')!r}).")

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
                errors.append(f"Field 'confidence' must be within [0.0, 1.0] or null (got: {conf_val}).")
        else:
            errors.append(f"Field 'confidence' must be float or null (got: {type(conf_val).__name__}).")

        # Origin-confidence pairing contract
        if data.get("origin") == "deterministic_linter" and conf_val is not None:
            errors.append(f"Deterministic findings ('deterministic_linter') must set 'confidence': null (got: {conf_val!r}).")
        elif data.get("origin") == "model_assertion" and (conf_val is None or not isinstance(conf_val, (int, float))):
            errors.append("Model assertions ('model_assertion') must provide numeric confidence in [0.0, 1.0].")

        # corroboration_status
        if data["corroboration_status"] not in self.allowed_corroborations:
            errors.append(
                f"Field 'corroboration_status' must be one of {sorted(self.allowed_corroborations)} (got: {data.get('corroboration_status')!r})."
            )

        # Optional remediation
        if "remediation" in data:
            rem = data["remediation"]
            if not isinstance(rem, dict):
                errors.append("Field 'remediation' must be an object if present.")
            else:
                rem_props = {"proposed_draft_available", "diff_preview"}
                for k in rem:
                    if k not in rem_props:
                        errors.append(f"Disallowed property 'remediation.{k}' (additionalProperties: false).")
                if "proposed_draft_available" in rem and not isinstance(rem["proposed_draft_available"], bool):
                    errors.append("Field 'remediation.proposed_draft_available' must be a boolean.")
                if "diff_preview" in rem and not isinstance(rem["diff_preview"], str):
                    errors.append("Field 'remediation.diff_preview' must be a string.")

        # Optional retry_count
        if "retry_count" in data:
            rc = data["retry_count"]
            if isinstance(rc, bool) or not isinstance(rc, int) or rc < 0:
                errors.append(f"Field 'retry_count' must be an integer >= 0 (got: {rc!r}).")

        # Optional metadata
        if "metadata" in data and not isinstance(data["metadata"], dict):
            errors.append("Field 'metadata' must be an object if present.")

        return (len(errors) == 0), errors
