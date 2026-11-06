"""Universal SARIF v2.1.0 Normalizer for Open Cloud Agents.

Parses standard SARIF outputs produced by static analysis and vulnerability scanners
(CodeQL, Trivy, Checkov, Semgrep) and normalizes results into canonical findings
conforming to schemas/v1/finding.json and ADR-002 specifications.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any, Callable
from urllib.parse import unquote, urlparse

from ocagents.findings.provenance import resolve_default_repo_root

CANONICAL_SCHEMA_URI = "https://open-cloud-agents.github.io/schemas/v1/finding.json"

# Canonical Repository Rule IDs in rules/
RULE_DESTRUCTIVE = "rules/01-destructive-actions.md"
RULE_SECRETS = "rules/02-secrets-and-identity.md"
RULE_SCOPE = "rules/03-surgical-scope-discipline.md"
RULE_WELL_ARCHITECTED = "rules/04-cloud-well-architected-invariants.md"
RULE_HYGIENE = "rules/05-repository-and-path-hygiene.md"

RULE_TO_CATEGORY = {
    RULE_DESTRUCTIVE: "Zero Unplanned Destruction",
    RULE_SECRETS: "Zero-Trust Secrets & Identity",
    RULE_SCOPE: "Surgical Scope Discipline",
    RULE_WELL_ARCHITECTED: "Well-Architected Infrastructure & Security",
    RULE_HYGIENE: "Repository Hygiene & Path Safety",
}

RULE_TO_DEFAULT_RECOMMENDATION = {
    RULE_DESTRUCTIVE: (
        "Ensure infrastructure resources cannot be inadvertently destroyed; "
        "remove force_destroy and configure lifecycle prevent_destroy guardrails."
    ),
    RULE_SECRETS: (
        "Eliminate hardcoded credentials and overly broad permissions; "
        "enforce secret managers, least privilege, and restrict open ingress."
    ),
    RULE_SCOPE: (
        "Constrain code and infrastructure changes strictly to the approved task boundaries."
    ),
    RULE_WELL_ARCHITECTED: (
        "Enforce cloud well-architected invariants including encryption at rest and in transit, "
        "multi-AZ disaster recovery, and automated health probing."
    ),
    RULE_HYGIENE: (
        "Eliminate machine-specific paths, broken links, and preserve script and spec hygiene."
    ),
}

# Explicit mapping from common scanner rule identifiers to canonical repository rules
EXPLICIT_RULE_MAP: dict[str, str] = {
    # Checkov IaC rules
    "CKV_AWS_1": RULE_DESTRUCTIVE,  # S3 bucket force destroy
    "CKV_AWS_20": RULE_WELL_ARCHITECTED,  # S3 bucket public access
    "CKV_AWS_21": RULE_WELL_ARCHITECTED,  # S3 bucket versioning
    "CKV_AWS_18": RULE_WELL_ARCHITECTED,  # S3 access logging
    "CKV_AWS_19": RULE_WELL_ARCHITECTED,  # S3 bucket encryption
    "CKV_AWS_144": RULE_WELL_ARCHITECTED,  # Cross-region replication
    "CKV_AWS_145": RULE_WELL_ARCHITECTED,  # KMS encryption at rest
    "CKV_AWS_28": RULE_SECRETS,  # Wildcard IAM actions
    "CKV_AWS_41": RULE_SECRETS,  # Hardcoded credentials
    "CKV_AWS_45": RULE_SECRETS,  # Plaintext secrets in EC2 user data
    "CKV_AWS_60": RULE_SECRETS,  # IAM full admin policy
    "CKV_AWS_61": RULE_SECRETS,  # IAM inline policy
    "CKV_AWS_260": RULE_SECRETS,  # Ingress from 0.0.0.0/0
    "CKV_AWS_277": RULE_SECRETS,  # Egress 0.0.0.0/0
    "CKV_GCP_13": RULE_WELL_ARCHITECTED,  # Storage bucket encryption
    "CKV_AZURE_2": RULE_WELL_ARCHITECTED,  # Storage container encryption
    "CKV_K8S_14": RULE_WELL_ARCHITECTED,  # Privileged container
    "CKV_K8S_15": RULE_WELL_ARCHITECTED,  # Read-only root filesystem
    "CKV_K8S_40": RULE_SECRETS,  # Kubernetes secrets in env vars
    # Trivy vulnerability & config rules
    "AVD-AWS-0086": RULE_WELL_ARCHITECTED,  # S3 bucket public access block
    "AVD-AWS-0089": RULE_WELL_ARCHITECTED,  # S3 unencrypted
    "AVD-AWS-0057": RULE_SECRETS,  # IAM wildcard permissions
    "AVD-AWS-0107": RULE_SECRETS,  # Security group unrestricted ingress
    "DS002": RULE_WELL_ARCHITECTED,  # Container root user
    "DS005": RULE_WELL_ARCHITECTED,  # Container privileged flag
    # CodeQL SAST rules
    "py/cleartext-storage-sensitive-data": RULE_SECRETS,
    "py/hardcoded-credentials": RULE_SECRETS,
    "py/weak-sensitive-data-hashing": RULE_SECRETS,
    "py/sql-injection": RULE_WELL_ARCHITECTED,
    "py/command-line-injection": RULE_WELL_ARCHITECTED,
    "py/path-injection": RULE_HYGIENE,
    "py/reflective-xss": RULE_WELL_ARCHITECTED,
    # Semgrep rules
    "generic.secrets.security.detected-private-key": RULE_SECRETS,
    "generic.secrets.security.detected-api-key": RULE_SECRETS,
    "terraform.aws.security.aws-s3-bucket-unencrypted": RULE_WELL_ARCHITECTED,
    "terraform.aws.security.iam-wildcard-role": RULE_SECRETS,
}

# Heuristic keyword matchers for classifying unmapped scanner rules
KEYWORD_RULE_HEURISTICS: list[tuple[re.Pattern, str]] = [
    (
        re.compile(
            r"(destroy|drop|truncate|delete|terminate|dismantle|force_destroy|forces replacement)",
            re.IGNORECASE,
        ),
        RULE_DESTRUCTIVE,
    ),
    (
        re.compile(
            r"(secret|credential|password|token|api_?key|private_?key|auth|jwt|bearer|hardcoded|"
            r"wildcard|admin|permissive|0\.0\.0\.0|ingress|security_?group|iam|rbac|least_?privilege)",
            re.IGNORECASE,
        ),
        RULE_SECRETS,
    ),
    (
        re.compile(
            r"(path|traversal|confusable|trojan|shebang|relative_?link|link_?rot|hygiene|filename)",
            re.IGNORECASE,
        ),
        RULE_HYGIENE,
    ),
    (
        re.compile(
            r"(scope|boundary|unconstrained|unsolicited|refactor|version_?bump)",
            re.IGNORECASE,
        ),
        RULE_SCOPE,
    ),
    (
        re.compile(
            r"(encrypt|kms|tls|ssl|backup|multi_?az|replica|health|probe|liveness|readiness|"
            r"logging|audit|monitor|cve|vulnerability|iac|cloud|s3|k8s|container|docker)",
            re.IGNORECASE,
        ),
        RULE_WELL_ARCHITECTED,
    ),
]


def compute_finding_id(rule_id: str, resource: str, evidence: str) -> str:
    """Computes a deterministic, collision-resistant finding identifier.

    Derived per ADR-002:
        id = "FND-" + SHA256(rule_id + ":" + resource + ":" + evidence)[0:12].upper()
    """
    key = f"{rule_id}:{resource}:{evidence}".encode("utf-8")
    digest = hashlib.sha256(key).hexdigest()[:12].upper()
    return f"FND-{digest}"


def map_rule_id(
    sarif_rule_id: str,
    message: str = "",
    rule_metadata: dict[str, Any] | None = None,
    custom_map: dict[str, str] | None = None,
    custom_mapper: Callable[[str, dict[str, Any]], str] | None = None,
) -> str:
    """Maps an external SARIF rule ID to a canonical repository rule in rules/."""
    # 1. Custom callable mapper if provided
    if custom_mapper:
        try:
            mapped = custom_mapper(sarif_rule_id, rule_metadata or {})
            if mapped:
                return mapped
        except Exception:
            pass

    # 2. Custom lookup dictionary
    if custom_map and sarif_rule_id in custom_map:
        return custom_map[sarif_rule_id]

    # 3. Already a canonical repository rule path
    if re.match(r"^rules/[a-zA-Z0-9_-]+\.md(#.*)?$", sarif_rule_id):
        return sarif_rule_id

    # 4. Explicit known rule mapping
    if sarif_rule_id in EXPLICIT_RULE_MAP:
        return EXPLICIT_RULE_MAP[sarif_rule_id]

    # 5. Search rule metadata (name, tags, description)
    text_corpus = f"{sarif_rule_id} {message}"
    if rule_metadata:
        name = rule_metadata.get("name", "")
        desc = (
            rule_metadata.get("shortDescription", {}).get("text", "")
            or rule_metadata.get("fullDescription", {}).get("text", "")
        )
        tags = " ".join(rule_metadata.get("properties", {}).get("tags", []))
        text_corpus = f"{text_corpus} {name} {desc} {tags}"

    # 6. Keyword heuristics
    for pattern, canonical_rule in KEYWORD_RULE_HEURISTICS:
        if pattern.search(text_corpus):
            return canonical_rule

    # 7. Default fallback to Cloud Well-Architected Invariants
    return RULE_WELL_ARCHITECTED


def map_severity(
    level: str | None,
    properties: dict[str, Any] | None = None,
) -> str:
    """Maps SARIF level and property scores to canonical finding severity.

    Canonical severities: "critical", "high", "medium", "low", "info".
    """
    props = properties or {}

    # 1. Check explicit severity in properties (common in Trivy & Checkov)
    prop_sev = props.get("severity") or props.get("problem.severity")
    if prop_sev and isinstance(prop_sev, str):
        normalized_prop = prop_sev.lower().strip()
        if normalized_prop in {"critical", "high", "medium", "low", "info"}:
            return normalized_prop

    # 2. Check CVSS / security-severity numeric score (common in CodeQL & GitHub)
    sec_score = props.get("security-severity")
    if sec_score is not None:
        try:
            score = float(sec_score)
            if score >= 9.0:
                return "critical"
            if score >= 7.0:
                return "high"
            if score >= 4.0:
                return "medium"
            if score > 0.0:
                return "low"
            return "info"
        except (ValueError, TypeError):
            pass

    # 3. Map standard SARIF level
    lvl = (level or "").lower().strip()
    if lvl == "error":
        return "high"
    if lvl == "warning":
        return "medium"
    if lvl == "note":
        return "low"
    if lvl in {"none", "info"}:
        return "info"

    return "medium"


def map_category(
    rule_id: str,
    properties: dict[str, Any] | None = None,
    driver_name: str | None = None,
) -> str:
    """Determines functional category string for the finding."""
    # 1. Category from properties if explicitly declared
    if properties:
        explicit_cat = properties.get("category")
        if explicit_cat and isinstance(explicit_cat, str) and explicit_cat.strip():
            return explicit_cat.strip()

    # 2. Category derived from canonical rule
    if rule_id in RULE_TO_CATEGORY:
        return RULE_TO_CATEGORY[rule_id]

    # 3. Fallback based on driver tool
    if driver_name:
        drv = driver_name.lower()
        if "checkov" in drv:
            return "Infrastructure as Code (IaC) Security"
        if "trivy" in drv:
            return "Vulnerability & Container Security"
        if "codeql" in drv:
            return "Application Security Testing (SAST)"
        if "semgrep" in drv:
            return "Static Code Analysis & Security"

    return "Static Analysis Defect"


def clean_artifact_uri(uri: str, repo_root: Path | None = None) -> str:
    """Normalizes a SARIF artifact URI to a clean, repo-relative POSIX path."""
    if not uri:
        return "unknown"

    # 1. Parse URI scheme
    parsed = urlparse(uri)
    path_str = parsed.path if parsed.scheme == "file" else uri

    # 2. Unquote URL entities (e.g. %20 -> space)
    path_str = unquote(path_str)

    # 3. Strip common SARIF roots and prefix tokens
    path_str = path_str.replace("%SRCROOT%", "").replace("${SRCROOT}", "")
    path_str = path_str.lstrip("/").replace("\\", "/")

    # 4. Strip absolute repo_root prefix if present
    if repo_root:
        repo_prefix = repo_root.as_posix().lstrip("/") + "/"
        if path_str.startswith(repo_prefix):
            path_str = path_str[len(repo_prefix):]

    # 5. Remove any leading ./
    while path_str.startswith("./"):
        path_str = path_str[2:]

    # 6. Reject or sanitize dangerous path traversal
    clean_parts = [p for p in path_str.split("/") if p and p != "." and p != ".."]
    if not clean_parts:
        return "unknown"

    return "/".join(clean_parts)


class SarifNormalizer:
    """Universal normalizer transforming SARIF v2.1.0 data into canonical findings."""

    def __init__(
        self,
        repo_root: Path | None = None,
        default_agent: str | None = None,
        rule_map: dict[str, str] | None = None,
        custom_rule_mapper: Callable[[str, dict[str, Any]], str] | None = None,
        evidence_scheme: str = "repo",
    ) -> None:
        self.repo_root = (repo_root or resolve_default_repo_root()).resolve()
        self.default_agent = default_agent
        self.rule_map = rule_map or {}
        self.custom_rule_mapper = custom_rule_mapper
        self.evidence_scheme = evidence_scheme if evidence_scheme in {"repo", "diff"} else "repo"

    def normalize(self, sarif_payload: dict[str, Any] | str | Path) -> list[dict[str, Any]]:
        """Ingests SARIF data and returns a list of canonical finding dictionaries."""
        data = self._load_sarif_dict(sarif_payload)

        runs = data.get("runs", [])
        if not isinstance(runs, list):
            return []

        findings: list[dict[str, Any]] = []
        seen_ids: set[str] = set()

        for run in runs:
            if not isinstance(run, dict):
                continue
            run_findings = self._normalize_run(run)
            for f in run_findings:
                f_id = f["id"]
                if f_id not in seen_ids:
                    seen_ids.add(f_id)
                    findings.append(f)

        return findings

    def normalize_file(self, file_path: str | Path) -> list[dict[str, Any]]:
        """Convenience helper to read and normalize a SARIF file from disk."""
        p = Path(file_path)
        if not p.is_file():
            raise FileNotFoundError(f"SARIF file not found: '{p}'")
        return self.normalize(p)

    def _load_sarif_dict(self, payload: dict[str, Any] | str | Path) -> dict[str, Any]:
        """Loads and parses raw input into a SARIF JSON dictionary."""
        if isinstance(payload, dict):
            return payload

        if isinstance(payload, Path) or (
            isinstance(payload, str) and not payload.strip().startswith("{")
        ):
            path = Path(payload)
            if not path.is_file():
                raise FileNotFoundError(f"SARIF input file does not exist: '{path}'")
            try:
                content = path.read_text(encoding="utf-8")
                return json.loads(content)
            except json.JSONDecodeError as e:
                raise ValueError(f"Malformed SARIF JSON in file '{path}': {e}") from e

        if isinstance(payload, str):
            try:
                return json.loads(payload)
            except json.JSONDecodeError as e:
                raise ValueError(f"Malformed SARIF JSON payload string: {e}") from e

        raise TypeError(f"Unsupported SARIF payload type: {type(payload).__name__}")

    def _normalize_run(self, run: dict[str, Any]) -> list[dict[str, Any]]:
        """Normalizes a single SARIF run object."""
        tool = run.get("tool", {})
        driver = tool.get("driver", {})
        driver_name = driver.get("name", self.default_agent or "deterministic_linter")
        driver_version = driver.get("semanticVersion") or driver.get("version")

        agent_slug = self._slugify_agent(driver_name)

        # Index rules by ID and by numerical index
        rules_list = driver.get("rules", [])
        rules_by_id: dict[str, dict[str, Any]] = {}
        rules_by_index: list[dict[str, Any]] = []

        if isinstance(rules_list, list):
            for idx, r in enumerate(rules_list):
                if isinstance(r, dict):
                    rules_by_index.append(r)
                    r_id = r.get("id")
                    if r_id:
                        rules_by_id[r_id] = r

        results = run.get("results", [])
        if not isinstance(results, list):
            return []

        findings: list[dict[str, Any]] = []
        for result in results:
            if not isinstance(result, dict):
                continue
            finding = self._normalize_result(
                result=result,
                driver_name=driver_name,
                agent_slug=agent_slug,
                driver_version=driver_version,
                rules_by_id=rules_by_id,
                rules_by_index=rules_by_index,
            )
            if finding:
                findings.append(finding)

        return findings

    def _normalize_result(
        self,
        result: dict[str, Any],
        driver_name: str,
        agent_slug: str,
        driver_version: str | None,
        rules_by_id: dict[str, dict[str, Any]],
        rules_by_index: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        """Normalizes a single SARIF result object into a canonical finding."""
        sarif_rule_id = result.get("ruleId", "")
        rule_index = result.get("ruleIndex")

        # Resolve rule metadata
        rule_meta: dict[str, Any] = {}
        if sarif_rule_id and sarif_rule_id in rules_by_id:
            rule_meta = rules_by_id[sarif_rule_id]
        elif (
            rule_index is not None
            and isinstance(rule_index, int)
            and 0 <= rule_index < len(rules_by_index)
        ):
            rule_meta = rules_by_index[rule_index]
            if not sarif_rule_id:
                sarif_rule_id = rule_meta.get("id", "")

        # Fallback rule ID if omitted
        if not sarif_rule_id:
            sarif_rule_id = f"{agent_slug}-finding"

        # 1. Fact / Message
        msg_obj = result.get("message", {})
        fact_text = msg_obj.get("text") or msg_obj.get("markdown")
        if not fact_text and rule_meta:
            fact_text = (
                rule_meta.get("shortDescription", {}).get("text")
                or rule_meta.get("fullDescription", {}).get("text")
            )
        if not fact_text:
            fact_text = f"Static analysis violation reported by {driver_name} for rule {sarif_rule_id}."
        fact_text = fact_text.strip()

        # 2. Location & Evidence
        locations = result.get("locations", [])
        clean_path = "unknown"
        start_line = 1
        end_line = 1
        resource_candidate: str | None = None

        if locations and isinstance(locations, list) and isinstance(locations[0], dict):
            loc = locations[0]
            phys = loc.get("physicalLocation", {})
            artifact_loc = phys.get("artifactLocation", {})
            raw_uri = artifact_loc.get("uri", "")
            clean_path = clean_artifact_uri(raw_uri, repo_root=self.repo_root)

            region = phys.get("region", {})
            s_line = region.get("startLine")
            e_line = region.get("endLine")
            if s_line is not None and isinstance(s_line, int) and s_line > 0:
                start_line = s_line
            if e_line is not None and isinstance(e_line, int) and e_line >= start_line:
                end_line = e_line
            else:
                end_line = start_line

            # Check logical locations for resource names (e.g., terraform resource address)
            logical_locs = loc.get("logicalLocations", [])
            if logical_locs and isinstance(logical_locs, list) and isinstance(logical_locs[0], dict):
                first_logical = logical_locs[0]
                resource_candidate = (
                    first_logical.get("fullyQualifiedName") or first_logical.get("name")
                )

        # 3. Canonical Rule ID
        canonical_rule_id = map_rule_id(
            sarif_rule_id=sarif_rule_id,
            message=fact_text,
            rule_metadata=rule_meta,
            custom_map=self.rule_map,
            custom_mapper=self.custom_rule_mapper,
        )

        # 4. Resource Name
        res_prop = (
            result.get("properties", {}).get("resource")
            or result.get("properties", {}).get("target")
            or result.get("properties", {}).get("resourceName")
        )
        if res_prop and isinstance(res_prop, str) and res_prop.strip():
            resource_name = res_prop.strip()
        elif resource_candidate and resource_candidate.strip():
            resource_name = resource_candidate.strip()
        else:
            resource_name = (
                f"{clean_path}:{start_line}" if clean_path != "unknown" else "unknown-resource"
            )

        # 5. Evidence Locator
        if end_line > start_line:
            evidence_locator = f"{self.evidence_scheme}:{clean_path}#L{start_line}-L{end_line}"
        else:
            evidence_locator = f"{self.evidence_scheme}:{clean_path}#L{start_line}"

        # 6. Recommendation
        recommendation_text: str | None = None
        fixes = result.get("fixes", [])
        if fixes and isinstance(fixes, list) and isinstance(fixes[0], dict):
            fix_desc = fixes[0].get("description", {}).get("text")
            if fix_desc:
                recommendation_text = fix_desc.strip()

        if not recommendation_text and rule_meta:
            help_obj = rule_meta.get("help", {})
            help_text = help_obj.get("text") or help_obj.get("markdown")
            if help_text:
                # Take first non-empty line / sentence
                first_para = help_text.strip().split("\n\n")[0].strip()
                recommendation_text = first_para

        if not recommendation_text:
            recommendation_text = RULE_TO_DEFAULT_RECOMMENDATION.get(
                canonical_rule_id,
                f"Remediate {sarif_rule_id} in accordance with {canonical_rule_id}.",
            )

        # 7. Severity
        combined_props = {**rule_meta.get("properties", {}), **result.get("properties", {})}
        severity = map_severity(
            level=result.get("level"),
            properties=combined_props,
        )

        # 8. Category
        category = map_category(
            rule_id=canonical_rule_id,
            properties=combined_props,
            driver_name=driver_name,
        )

        # 9. Deterministic Finding ID
        fnd_id = compute_finding_id(
            rule_id=canonical_rule_id,
            resource=resource_name,
            evidence=evidence_locator,
        )

        # 10. Metadata envelope
        metadata: dict[str, Any] = {
            "sarif_rule_id": sarif_rule_id,
            "driver_name": driver_name,
        }
        if driver_version:
            metadata["driver_version"] = str(driver_version)
        rule_name = rule_meta.get("name")
        if rule_name:
            metadata["rule_name"] = rule_name
        help_uri = rule_meta.get("helpUri")
        if help_uri:
            metadata["help_uri"] = help_uri

        finding: dict[str, Any] = {
            "$schema": CANONICAL_SCHEMA_URI,
            "id": fnd_id,
            "agent": agent_slug,
            "origin": "deterministic_linter",
            "rule_id": canonical_rule_id,
            "category": category,
            "resource": resource_name,
            "fact": fact_text,
            "evidence": evidence_locator,
            "recommendation": recommendation_text,
            "severity": severity,
            "confidence": None,
            "corroboration_status": "tool_verified",
            "metadata": metadata,
        }

        return finding

    def _slugify_agent(self, driver_name: str) -> str:
        """Slugifies a tool driver name into a clean agent identifier."""
        if self.default_agent:
            return self.default_agent
        clean = re.sub(r"[^a-zA-Z0-9_-]", "-", driver_name).lower().strip("-")
        return clean or "deterministic_linter"


def normalize_sarif(
    sarif_data: dict[str, Any] | str | Path,
    repo_root: Path | None = None,
    default_agent: str | None = None,
    rule_map: dict[str, str] | None = None,
    evidence_scheme: str = "repo",
) -> list[dict[str, Any]]:
    """Functional convenience wrapper around SarifNormalizer."""
    normalizer = SarifNormalizer(
        repo_root=repo_root,
        default_agent=default_agent,
        rule_map=rule_map,
        evidence_scheme=evidence_scheme,
    )
    return normalizer.normalize(sarif_data)
