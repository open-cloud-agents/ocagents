"""Trivy Ingest Bridge for Open Cloud Agents.

Parses Trivy native JSON and SARIF outputs and converts misconfigurations and
vulnerabilities into canonical findings conforming to schemas/v1/finding.json and ADR-002.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ocagents.findings.normalizer import (
    CANONICAL_SCHEMA_URI,
    RULE_TO_DEFAULT_RECOMMENDATION,
    SarifNormalizer,
    clean_artifact_uri,
    compute_finding_id,
    map_category,
    map_rule_id,
    map_severity,
)
from ocagents.findings.provenance import resolve_default_repo_root
from ocagents.scanner.diff_filter import filter_findings_by_diff


class TrivyAdapter:
    """Ingest adapter for Trivy filesystem, IaC, and container scans."""

    def __init__(
        self,
        repo_root: Path | None = None,
        default_agent: str = "trivy",
        rule_map: dict[str, str] | None = None,
        evidence_scheme: str = "repo",
    ) -> None:
        self.repo_root = (repo_root or resolve_default_repo_root()).resolve()
        self.default_agent = default_agent
        self.rule_map = rule_map or {}
        self.evidence_scheme = evidence_scheme if evidence_scheme in {"repo", "diff"} else "repo"
        self._sarif_normalizer = SarifNormalizer(
            repo_root=self.repo_root,
            default_agent=self.default_agent,
            rule_map=self.rule_map,
            evidence_scheme=self.evidence_scheme,
        )

    def parse(
        self,
        payload: dict[str, Any] | str | Path,
        diff_text: str | None = None,
    ) -> list[dict[str, Any]]:
        """Parses Trivy output (JSON or SARIF) into canonical findings."""
        raw_data = self._load_json(payload)

        # 1. Detect if input is standard SARIF
        if isinstance(raw_data, dict) and "runs" in raw_data and isinstance(raw_data.get("runs"), list):
            findings = self._sarif_normalizer.normalize(raw_data)
        elif isinstance(raw_data, dict) and ("Results" in raw_data or "SchemaVersion" in raw_data):
            findings = self._parse_trivy_native_json(raw_data)
        elif isinstance(raw_data, list):
            # List of results
            findings = []
            for item in raw_data:
                if isinstance(item, dict):
                    findings.extend(self._parse_trivy_native_json(item))
        else:
            findings = []

        # 2. Filter findings to modified lines if active PR diff is supplied
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
        """Reads Trivy output from file and converts into canonical findings."""
        p = Path(file_path)
        if not p.is_file():
            raise FileNotFoundError(f"Trivy output file not found: '{p}'")
        return self.parse(p, diff_text=diff_text)

    def _parse_trivy_native_json(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        """Parses Trivy SchemaVersion 2 JSON structure."""
        results = data.get("Results", [])
        if not isinstance(results, list):
            return []

        findings: list[dict[str, Any]] = []
        seen_ids: set[str] = set()

        for res in results:
            if not isinstance(res, dict):
                continue
            target = res.get("Target", "unknown")
            clean_target = clean_artifact_uri(target, repo_root=self.repo_root)

            # 1. Misconfigurations (IaC & Dockerfile defects)
            misconfigs = res.get("Misconfigurations", [])
            if isinstance(misconfigs, list):
                for m in misconfigs:
                    if not isinstance(m, dict):
                        continue
                    f = self._convert_misconfig(m, clean_target=clean_target)
                    if f and f["id"] not in seen_ids:
                        seen_ids.add(f["id"])
                        findings.append(f)

            # 2. Vulnerabilities (CVE package defects)
            vulns = res.get("Vulnerabilities", [])
            if isinstance(vulns, list):
                for v in vulns:
                    if not isinstance(v, dict):
                        continue
                    f = self._convert_vulnerability(v, clean_target=clean_target)
                    if f and f["id"] not in seen_ids:
                        seen_ids.add(f["id"])
                        findings.append(f)

        return findings

    def _convert_misconfig(self, m: dict[str, Any], clean_target: str) -> dict[str, Any] | None:
        """Converts a Trivy Misconfiguration into a canonical finding."""
        rule_id_raw = m.get("ID") or m.get("RuleID") or "AVD_UNKNOWN"
        title = m.get("Title") or m.get("Description") or f"Trivy misconfiguration {rule_id_raw}"

        cause = m.get("CauseMetadata", {})
        start_line = cause.get("StartLine", 1) if isinstance(cause.get("StartLine"), int) else 1
        end_line = cause.get("EndLine", start_line) if isinstance(cause.get("EndLine"), int) else start_line
        if end_line < start_line:
            end_line = start_line

        resource = cause.get("Resource") or f"{clean_target}:{start_line}"

        # Evidence locator
        if end_line > start_line:
            evidence = f"{self.evidence_scheme}:{clean_target}#L{start_line}-L{end_line}"
        else:
            evidence = f"{self.evidence_scheme}:{clean_target}#L{start_line}"

        # Map to canonical repository rule
        canonical_rule_id = map_rule_id(
            sarif_rule_id=rule_id_raw,
            message=f"{title} {m.get('Description', '')}",
            rule_metadata={"title": title, "resolution": m.get("Resolution")},
            custom_map=self.rule_map,
        )

        severity = map_severity(
            level=None,
            properties={"severity": m.get("Severity")},
        )

        resolution = m.get("Resolution")
        primary_url = m.get("PrimaryURL")
        if resolution and isinstance(resolution, str) and resolution.strip():
            recommendation = resolution.strip()
        elif primary_url:
            recommendation = f"Remediate according to vendor security guidance: {primary_url}"
        else:
            recommendation = RULE_TO_DEFAULT_RECOMMENDATION.get(
                canonical_rule_id,
                f"Remediate {rule_id_raw} in accordance with {canonical_rule_id}.",
            )

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
            "trivy_id": rule_id_raw,
            "target": clean_target,
        }
        if primary_url:
            metadata["primary_url"] = primary_url
        if m.get("Status"):
            metadata["status"] = m["Status"]

        return {
            "$schema": CANONICAL_SCHEMA_URI,
            "id": fnd_id,
            "agent": self.default_agent,
            "origin": "deterministic_linter",
            "rule_id": canonical_rule_id,
            "category": category,
            "resource": resource,
            "fact": title.strip(),
            "evidence": evidence,
            "recommendation": recommendation,
            "severity": severity,
            "confidence": None,
            "corroboration_status": "tool_verified",
            "metadata": metadata,
        }

    def _convert_vulnerability(self, v: dict[str, Any], clean_target: str) -> dict[str, Any] | None:
        """Converts a Trivy package Vulnerability into a canonical finding."""
        cve_id = v.get("VulnerabilityID", "CVE-UNKNOWN")
        pkg_name = v.get("PkgName", "unknown-pkg")
        installed_ver = v.get("InstalledVersion", "unknown")
        fixed_ver = v.get("FixedVersion")

        resource = f"{clean_target}:{pkg_name}@{installed_ver}"
        evidence = f"{self.evidence_scheme}:{clean_target}#L1"

        title = v.get("Title") or v.get("Description") or f"{cve_id} detected in {pkg_name}"
        fact = f"{cve_id} detected in {pkg_name}@{installed_ver}: {title.strip()}"

        canonical_rule_id = map_rule_id(
            sarif_rule_id=cve_id,
            message=fact,
            rule_metadata={"title": title, "pkg": pkg_name},
            custom_map=self.rule_map,
        )

        severity = map_severity(
            level=None,
            properties={"severity": v.get("Severity")},
        )

        if fixed_ver:
            recommendation = f"Upgrade {pkg_name} to version {fixed_ver} or higher to resolve {cve_id}."
        else:
            primary_url = v.get("PrimaryURL")
            if primary_url:
                recommendation = f"Mitigate {cve_id} in {pkg_name} per advisory: {primary_url}"
            else:
                recommendation = RULE_TO_DEFAULT_RECOMMENDATION.get(
                    canonical_rule_id,
                    f"Mitigate vulnerability {cve_id} in {pkg_name}.",
                )

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
            "vulnerability_id": cve_id,
            "package_name": pkg_name,
            "installed_version": installed_ver,
        }
        if fixed_ver:
            metadata["fixed_version"] = fixed_ver
        if v.get("PrimaryURL"):
            metadata["primary_url"] = v["PrimaryURL"]

        return {
            "$schema": CANONICAL_SCHEMA_URI,
            "id": fnd_id,
            "agent": self.default_agent,
            "origin": "deterministic_linter",
            "rule_id": canonical_rule_id,
            "category": category,
            "resource": resource,
            "fact": fact,
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
                raise FileNotFoundError(f"Trivy input file not found: '{p}'")
            return json.loads(p.read_text(encoding="utf-8"))
        if isinstance(payload, str):
            return json.loads(payload)
        raise TypeError(f"Unsupported payload type: {type(payload).__name__}")


def parse_trivy_output(
    payload: dict[str, Any] | str | Path,
    diff_text: str | None = None,
    repo_root: Path | None = None,
) -> list[dict[str, Any]]:
    """Functional convenience wrapper to parse Trivy output into canonical findings."""
    adapter = TrivyAdapter(repo_root=repo_root)
    return adapter.parse(payload, diff_text=diff_text)
