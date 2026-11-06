"""Checkov Native JSON Ingest Bridge for Open Cloud Agents.

Parses Checkov JSON outputs and transforms failed checks into canonical findings
conforming to schemas/v1/finding.json and ADR-002 specifications.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ocagents.findings.normalizer import (
    CANONICAL_SCHEMA_URI,
    RULE_TO_DEFAULT_RECOMMENDATION,
    clean_artifact_uri,
    compute_finding_id,
    map_category,
    map_rule_id,
    map_severity,
)
from ocagents.findings.provenance import resolve_default_repo_root
from ocagents.scanner.diff_filter import filter_findings_by_diff


class CheckovAdapter:
    """Ingest adapter for Checkov native JSON execution outputs."""

    def __init__(
        self,
        repo_root: Path | None = None,
        default_agent: str = "checkov",
        rule_map: dict[str, str] | None = None,
        evidence_scheme: str = "repo",
    ) -> None:
        self.repo_root = (repo_root or resolve_default_repo_root()).resolve()
        self.default_agent = default_agent
        self.rule_map = rule_map or {}
        self.evidence_scheme = evidence_scheme if evidence_scheme in {"repo", "diff"} else "repo"

    def parse(
        self,
        payload: dict[str, Any] | list[dict[str, Any]] | str | Path,
        diff_text: str | None = None,
    ) -> list[dict[str, Any]]:
        """Parses Checkov JSON payload and returns canonical findings.

        Args:
            payload: Checkov JSON dict, list of check type dicts, JSON string, or Path.
            diff_text: Optional unified Git diff. When provided, findings are filtered
                strictly to lines modified in the diff.

        Returns:
            list[dict[str, Any]]: List of canonical finding dictionaries.
        """
        raw_data = self._load_json(payload)
        check_groups = raw_data if isinstance(raw_data, list) else [raw_data]

        findings: list[dict[str, Any]] = []
        seen_ids: set[str] = set()

        for group in check_groups:
            if not isinstance(group, dict):
                continue

            check_type = group.get("check_type", "iac")
            results = group.get("results", {})
            failed_checks = results.get("failed_checks", [])
            if not isinstance(failed_checks, list):
                continue

            for check in failed_checks:
                if not isinstance(check, dict):
                    continue
                finding = self._convert_check(check, check_type=check_type)
                if finding:
                    f_id = finding["id"]
                    if f_id not in seen_ids:
                        seen_ids.add(f_id)
                        findings.append(finding)

        if diff_text:
            findings = filter_findings_by_diff(
                findings,
                diff_text,
                convert_to_diff_scheme=(self.evidence_scheme == "diff"),
            )

        return findings

    def parse_file(
        self,
        file_path: str | Path,
        diff_text: str | None = None,
    ) -> list[dict[str, Any]]:
        """Reads Checkov JSON from file and converts into canonical findings."""
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Checkov JSON output file not found: '{path}'")
        return self.parse(path, diff_text=diff_text)

    def _convert_check(self, check: dict[str, Any], check_type: str) -> dict[str, Any] | None:
        """Converts an individual Checkov failed check dictionary into canonical finding."""
        check_id = check.get("check_id", "CKV_UNKNOWN")
        check_name = check.get("check_name", f"Checkov rule {check_id} failed.")
        resource = check.get("resource") or check.get("resource_address") or "unknown-resource"

        raw_path = check.get("file_path") or check.get("repo_file_path") or "unknown"
        clean_path = clean_artifact_uri(raw_path, repo_root=self.repo_root)

        line_range = check.get("file_line_range", [1, 1])
        start_line = line_range[0] if len(line_range) >= 1 and isinstance(line_range[0], int) else 1
        end_line = line_range[1] if len(line_range) >= 2 and isinstance(line_range[1], int) else start_line
        if end_line < start_line:
            end_line = start_line

        # Map to canonical repository rule
        canonical_rule_id = map_rule_id(
            sarif_rule_id=check_id,
            message=check_name,
            rule_metadata={"name": check_name, "check_type": check_type},
            custom_map=self.rule_map,
        )

        # Build evidence locator
        if end_line > start_line:
            evidence = f"{self.evidence_scheme}:{clean_path}#L{start_line}-L{end_line}"
        else:
            evidence = f"{self.evidence_scheme}:{clean_path}#L{start_line}"

        # Severity
        severity = map_severity(
            level=None,
            properties={"severity": check.get("severity")},
        )

        # Recommendation
        guideline = check.get("guideline")
        if guideline and isinstance(guideline, str) and guideline.strip():
            recommendation = f"Remediate according to guidance: {guideline.strip()}"
        else:
            recommendation = RULE_TO_DEFAULT_RECOMMENDATION.get(
                canonical_rule_id,
                f"Remediate {check_id} in accordance with {canonical_rule_id}.",
            )

        # Compute deterministic ID
        fnd_id = compute_finding_id(
            rule_id=canonical_rule_id,
            resource=resource,
            evidence=evidence,
        )

        category = map_category(
            rule_id=canonical_rule_id,
            driver_name=self.default_agent,
        )

        metadata: dict[str, Any] = {
            "check_id": check_id,
            "checkov_check_type": check_type,
        }
        if check.get("bc_check_id"):
            metadata["bc_check_id"] = check["bc_check_id"]
        if check.get("evaluated_keys"):
            metadata["evaluated_keys"] = check["evaluated_keys"]
        if guideline:
            metadata["guideline"] = guideline

        return {
            "$schema": CANONICAL_SCHEMA_URI,
            "id": fnd_id,
            "agent": self.default_agent,
            "origin": "deterministic_linter",
            "rule_id": canonical_rule_id,
            "category": category,
            "resource": resource,
            "fact": check_name.strip(),
            "evidence": evidence,
            "recommendation": recommendation,
            "severity": severity,
            "confidence": None,
            "corroboration_status": "tool_verified",
            "metadata": metadata,
        }

    def _load_json(self, payload: Any) -> Any:
        if isinstance(payload, (dict, list)):
            return payload
        if isinstance(payload, Path) or (isinstance(payload, str) and not payload.strip().startswith(("{", "["))):
            p = Path(payload)
            if not p.is_file():
                raise FileNotFoundError(f"Checkov input file not found: '{p}'")
            return json.loads(p.read_text(encoding="utf-8"))
        if isinstance(payload, str):
            return json.loads(payload)
        raise TypeError(f"Unsupported payload type: {type(payload).__name__}")


def parse_checkov_output(
    payload: dict[str, Any] | list[dict[str, Any]] | str | Path,
    diff_text: str | None = None,
    repo_root: Path | None = None,
) -> list[dict[str, Any]]:
    """Functional convenience wrapper to parse Checkov output into canonical findings."""
    adapter = CheckovAdapter(repo_root=repo_root)
    return adapter.parse(payload, diff_text=diff_text)
