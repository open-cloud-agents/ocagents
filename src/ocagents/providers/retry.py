"""
Open Cloud Agents: Bounded Retry Engine with Schema Feedback (Milestone v2.0 - TASK-4.1).

Orchestrates model invocation, JSON Schema validation against schemas/v1/finding.json,
bounded error feedback retries, and session token budget enforcement.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ocagents.blackboard.dedup import ensure_finding_id
from ocagents.findings.schema_validator import SchemaValidator
from ocagents.providers.base import (
    ConstrainedDecodingError,
    ModelProvider,
    ProviderResponse,
    TokenBudgetExceededError,
)

logger = logging.getLogger("ocagents.providers.retry")

DEFAULT_SCHEMA_PATH = Path(__file__).resolve().parent.parent.parent.parent / "schemas" / "v1" / "finding.json"


def load_finding_schema(path: Path | None = None) -> dict[str, Any]:
    """Loads the canonical finding schema dictionary."""
    schema_file = path or DEFAULT_SCHEMA_PATH
    if schema_file.exists():
        try:
            return json.loads(schema_file.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("Failed to load schema from %s: %s", schema_file, exc)

    # Return minimal inline fallback schema if file unavailable
    return {
        "type": "object",
        "required": [
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
        ],
    }


def get_findings_batch_schema(item_schema: dict[str, Any] | None = None) -> dict[str, Any]:
    """Wraps the individual finding schema into a batch schema for model output."""
    raw_item = item_schema or load_finding_schema()
    return {
        "type": "object",
        "properties": {
            "findings": {
                "type": "array",
                "items": raw_item,
                "description": "List of structured findings discovered in the changeset or architecture.",
            }
        },
        "required": ["findings"],
        "additionalProperties": False,
    }


@dataclass
class RetryExecutionResult:
    """Encapsulates the output of a bounded retry execution loop."""

    findings: list[dict[str, Any]]
    attempts: int
    total_tokens: int
    prompt_tokens: int
    completion_tokens: int
    responses: list[ProviderResponse] = field(default_factory=list)


class BoundedRetryEngine:
    """
    Executes model generation with constrained decoding, schema validation,
    and bounded feedback retries respecting agent token budgets.
    """

    def __init__(
        self,
        provider: ModelProvider,
        schema: dict[str, Any] | None = None,
        max_retries: int = 3,
        max_total_tokens: int | None = None,
        schema_validator: SchemaValidator | None = None,
    ) -> None:
        self.provider = provider
        self.raw_finding_schema = schema or load_finding_schema()
        self.batch_schema = get_findings_batch_schema(self.raw_finding_schema)
        self.max_retries = max_retries
        self.max_total_tokens = max_total_tokens
        self.validator = schema_validator or SchemaValidator()

    def execute(
        self,
        prompt: str,
        system_prompt: str | None = None,
        agent_name: str = "specialist-agent",
    ) -> RetryExecutionResult:
        """
        Executes generation with schema-error feedback loop up to max_retries or token budget.
        """
        current_prompt = prompt
        attempts = 0
        total_tokens = 0
        total_prompt_tokens = 0
        total_completion_tokens = 0
        responses: list[ProviderResponse] = []
        last_errors: list[str] = []

        while attempts <= self.max_retries:
            attempts += 1
            response = self.provider.generate(
                prompt=current_prompt,
                system_prompt=system_prompt,
                schema=self.batch_schema,
            )
            responses.append(response)

            total_prompt_tokens += response.prompt_tokens
            total_completion_tokens += response.completion_tokens
            total_tokens += response.total_tokens

            # Budget check
            if self.max_total_tokens and total_tokens > self.max_total_tokens:
                raise TokenBudgetExceededError(
                    f"Agent '{agent_name}' exceeded maximum session token budget "
                    f"({total_tokens} > {self.max_total_tokens} tokens consumed across {attempts} attempt(s))."
                )

            # Extract payload
            payload = response.parsed_json
            if payload is None and response.content:
                try:
                    payload = json.loads(response.content)
                except json.JSONDecodeError as exc:
                    last_errors = [f"Payload is not valid JSON: {exc}"]
                    if attempts <= self.max_retries:
                        current_prompt = self._build_retry_prompt(prompt, last_errors, attempts)
                        continue
                    raise ConstrainedDecodingError(
                        f"Failed to decode valid JSON after {attempts} attempts: {exc}"
                    ) from exc

            # Normalize into list of findings
            findings_list = self._normalize_findings(payload, agent_name, retry_count=attempts - 1)

            # Validate each finding against canonical schema
            validation_errors: list[str] = []
            for idx, finding in enumerate(findings_list, start=1):
                is_valid, errors = self.validator.validate(finding)
                if not is_valid:
                    for err in errors:
                        validation_errors.append(f"Finding #{idx} ({finding.get('resource', 'unknown')}): {err}")

            if not validation_errors:
                # Successfully validated!
                return RetryExecutionResult(
                    findings=findings_list,
                    attempts=attempts,
                    total_tokens=total_tokens,
                    prompt_tokens=total_prompt_tokens,
                    completion_tokens=total_completion_tokens,
                    responses=responses,
                )

            last_errors = validation_errors
            logger.warning(
                "Attempt %d/%d produced %d schema error(s). Retrying with error feedback...",
                attempts,
                self.max_retries + 1,
                len(validation_errors),
            )

            if attempts <= self.max_retries:
                current_prompt = self._build_retry_prompt(prompt, last_errors, attempts)

        raise ConstrainedDecodingError(
            f"Failed to produce schema-valid findings after {attempts} attempts. "
            f"Validation errors on final attempt:\n" + "\n".join(f"  • {e}" for e in last_errors)
        )

    def _normalize_findings(
        self,
        payload: Any,
        agent_name: str,
        retry_count: int,
    ) -> list[dict[str, Any]]:
        """Extracts and normalizes finding dictionaries with canonical defaults."""
        raw_items: list[Any] = []
        if isinstance(payload, dict):
            if "findings" in payload and isinstance(payload["findings"], list):
                raw_items = payload["findings"]
            else:
                raw_items = [payload]
        elif isinstance(payload, list):
            raw_items = payload

        normalized: list[dict[str, Any]] = []
        for item in raw_items:
            if not isinstance(item, dict):
                continue
            f = dict(item)
            # Default required properties if omitted
            f.setdefault("$schema", "https://open-cloud-agents.github.io/schemas/v1/finding.json")
            f.setdefault("agent", agent_name)
            f.setdefault("origin", "model_assertion")
            f.setdefault("corroboration_status", "unverified_model_claim")
            f.setdefault("confidence", 0.85)
            f["retry_count"] = retry_count

            # Ensure deterministic ID
            f = ensure_finding_id(f)
            normalized.append(f)

        return normalized

    def _build_retry_prompt(self, base_prompt: str, errors: list[str], attempt: int) -> str:
        """Constructs feedback prompt containing the exact schema violations to correct."""
        error_summary = "\n".join(f"- {e}" for e in errors[:10])
        return (
            f"{base_prompt}\n\n"
            f"[SYSTEM FEEDBACK - RETRY ATTEMPT #{attempt + 1}]\n"
            f"Your previous output failed JSON Schema validation with the following violations:\n"
            f"{error_summary}\n\n"
            f"Please correct these violations. Emit strictly valid JSON adhering to schemas/v1/finding.json. "
            f"Do not include conversational prose or Markdown fences outside the JSON object."
        )
