"""
Open Cloud Agents: Adaptive Change-Set Risk Classifier (Milestone v2.0 - Issue #102).

Evaluates Git changesets, AST modifications, and diff content to categorize risk into
four operational tiers:
  - Tier 0: No-Op / Documentation & Non-Code Assets (LLM Bypass, 0 tokens)
  - Tier 1: Low Risk - Scripting, Packaging & Utilities (DevSecOps Engineer)
  - Tier 2: Medium Risk - Workflows & Core Runtime (Security Commander + Reviewer)
  - Tier 3: High Risk - IaC, IAM, Cloud Topology, DB & Destructive Operations (Master Suite)
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ocagents.triage.matrix import (
    ALL_MASTER_AGENTS,
    RiskTier,
    TIER_ACTIVATED_AGENTS,
    TIER_NAMES,
    TIER_RATIONALES,
    InvocationPlan,
    resolve_invocation_plan,
)

# Backward-compatibility alias
TIER_AGENTS = TIER_ACTIVATED_AGENTS

# --- File Classification Patterns ---

# High-risk infrastructure directories (all yaml/json/hcl/tf inside are Tier 3)
_INFRA_DIR_PATTERNS = [
    "terraform",
    "k8s",
    "kubernetes",
    "helm",
    "kustomize",
    "infra",
    "infrastructure",
    "cloudformation",
    "cdk",
    "pulumi",
    "deploy",
    "deployments",
    "manifests",
]

# High-risk CI/CD workflow directory prefixes or files (Tier 2)
_CICD_PATTERNS = [
    ".github/workflows",
    ".gitlab-ci.yml",
    "azure-pipelines.yml",
    "azure-pipelines.yaml",
    "jenkinsfile",
    ".circleci",
    ".buildkite",
    "bitbucket-pipelines.yml",
    "cloudbuild.yaml",
    "cloudbuild.yml",
    "buildspec.yml",
    "gitea-workflow.yml",
    "gitea-workflow.yaml",
]

# IaC extensions (Tier 3)
_IAC_EXTENSIONS = {
    ".tf",
    ".tfvars",
    ".bicep",
    ".arm",
    ".pulumi",
    ".cdk",
    ".hcl",
}

# Container files (Tier 3)
_CONTAINER_FILENAMES = {
    "dockerfile",
    "containerfile",
    "vagrantfile",
}

# Security, governance, and institutional rules (Tier 3)
_SECURITY_GOVERNANCE_PATTERNS = [
    "rules/",
    ".ocagents/exceptions.json",
    ".ocagents/",
    ".rego",
    "policy/",
    "policies/",
]

# Database migrations and schema definitions (Tier 3)
_DATABASE_MIGRATION_PATTERNS = [
    "migrations/",
    "db/migrations/",
    "schema.sql",
    "database/",
]

# Tier 0 file extensions (documentation, media, non-executable metadata)
_TIER_0_EXTENSIONS = {
    ".md",
    ".markdown",
    ".txt",
    ".rst",
    ".adoc",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".webp",
    ".pdf",
    ".eps",
    ".tiff",
    ".bmp",
    ".drawio",
    ".csv",
    ".tsv",
    ".sample",
}

# Tier 0 exact filenames (case-insensitive)
_TIER_0_FILENAMES = {
    "license",
    "licence",
    "notice",
    "authors",
    "contributors",
    "security.md",
    "code_of_conduct.md",
    ".gitignore",
    ".gitattributes",
    ".editorconfig",
    ".prettierrc",
    ".prettierignore",
    ".eslintignore",
    "mkdocs.yml",
}

# Tier 1 scripting and shell extensions
_TIER_1_SCRIPT_EXTENSIONS = {
    ".sh",
    ".bash",
    ".zsh",
}

# Tier 1 packaging and dependency manifests
_TIER_1_PACKAGING_FILENAMES = {
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "go.mod",
    "go.sum",
    "cargo.toml",
    "cargo.lock",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
}

# Core application logic extensions (Tier 2 when in core app/src dirs)
_CORE_APP_EXTENSIONS = {
    ".py",
    ".pyi",
    ".go",
    ".java",
    ".kt",
    ".scala",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".rs",
    ".c",
    ".cpp",
    ".cs",
    ".rb",
}

# High-risk content patterns inside diffs (Immediate escalation to Tier 3)
_HIGH_RISK_DIFF_PATTERNS = [
    # 1. IaC destruction & forced replacements
    (re.compile(r"^\+\s*force[_-]destroy\s*=\s*(?:true|1)", re.IGNORECASE | re.MULTILINE), "IaC resource deletion attribute enabled (force-destroy)"),
    (re.compile(r"forces\s+replacement", re.IGNORECASE), "IaC resource recreation directive (replacement forced)"),

    # 2. Database destructive statements & schema drops
    (re.compile(r"^\+\s*(?:DROP|TRUNCATE)\s+(?:TABLE|DATABASE|INDEX|SCHEMA)\b", re.IGNORECASE | re.MULTILINE), "Destructive database DDL operation (DROP/TRUNCATE)"),
    (re.compile(r"^\+\s*DELETE\s+FROM\s+\w+\s*(?:;|\n|\Z)", re.IGNORECASE | re.MULTILINE), "Unbounded database DELETE operation without WHERE clause"),
    (re.compile(r"^\+\s*ALTER\s+TABLE\s+\w+\s+DROP\s+COLUMN\b", re.IGNORECASE | re.MULTILINE), "Destructive database column drop (ALTER TABLE DROP COLUMN)"),

    # 3. IAM wildcard and overly permissive escalation
    (re.compile(r"[\"']?\*[\"']?\s*:\s*[\"']?\*[\"']?", re.IGNORECASE), "Full wildcard IAM action and resource (*:*)"),
    (re.compile(r"[\"']Action[\"']\s*:\s*[\"']\*[\"']", re.IGNORECASE), "Unbounded wildcard IAM Action (*)"),
    (re.compile(r"[\"']Resource[\"']\s*:\s*[\"']\*[\"']", re.IGNORECASE), "Unbounded wildcard IAM Resource (*)"),
    (re.compile(r"AdministratorAccess", re.IGNORECASE), "Superuser IAM policy attachment (AdministratorAccess)"),
    (re.compile(r"roles/owner", re.IGNORECASE), "Primitive cloud superuser role grant (roles/owner)"),

    # 4. Network and CIDR exposure
    (re.compile(r"0\.0\.0\.0/0", re.IGNORECASE), "Unbounded CIDR 0.0.0.0/0 route or security group policy exposure"),
    (re.compile(r"::/0", re.IGNORECASE), "Unbounded IPv6 ::/0 route or firewall policy exposure"),

    # 5. Overly permissive file permissions
    (re.compile(r"chmod\s+(?:-R\s+)?777", re.IGNORECASE), "Permissive mode-777 execution permissions (chmod 777)"),

    # 6. Kubernetes API definitions
    (re.compile(r"apiVersion:\s*[\w\.\/]+", re.IGNORECASE), "Kubernetes API manifest definition"),

    # 7. Cloud provider infrastructure resource blocks
    (re.compile(r"resource\s+\"(?:aws_|google_|azurerm_)", re.IGNORECASE), "Cloud provider infrastructure resource block"),

    # 8. Plaintext credential / private key exposure
    (re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE), "Potential plaintext AWS access key ID"),
    (re.compile(r"-----BEGIN\s+(?:[A-Z0-9_-]+\s+)*PRIVATE\s+KEY", re.IGNORECASE), "Potential plaintext private key block"),
    (re.compile(r"ghp_[a-zA-Z0-9]{36}", re.IGNORECASE), "Potential plaintext GitHub token"),
]


@dataclass
class TriageResult:
    """Encapsulates the blast radius classification result for a changeset."""
    risk_tier: int
    tier_name: str
    activated_agents: list[str]
    file_classifications: dict[str, int]
    file_reasons: dict[str, list[str]]
    reasons: list[str]
    files_by_tier: dict[int, list[str]]
    diff_summary: dict[str, int]
    skipped_agents: list[str] = field(default_factory=list)
    high_risk_triggers: list[str] = field(default_factory=list)
    invocation_plan: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serializes the triage result to a clean dictionary."""
        return {
            "risk_tier": int(self.risk_tier),
            "tier_name": self.tier_name,
            "activated_agents": list(self.activated_agents),
            "skipped_agents": list(self.skipped_agents),
            "file_classifications": dict(self.file_classifications),
            "file_reasons": dict(self.file_reasons),
            "reasons": list(self.reasons),
            "files_by_tier": {str(k): list(v) for k, v in self.files_by_tier.items()},
            "diff_summary": dict(self.diff_summary),
            "high_risk_triggers": list(self.high_risk_triggers),
            "invocation_plan": dict(self.invocation_plan),
        }


def parse_diff_files_with_chunks(diff_text: str) -> dict[str, str]:
    """
    Parses a unified git diff into a mapping of file_path -> diff_chunk.
    """
    files: dict[str, list[str]] = {}
    current_file: str | None = None

    for line in diff_text.splitlines():
        if line.startswith("diff --git"):
            parts = line.split()
            if len(parts) >= 4:
                b_path = parts[3]
                clean = b_path.removeprefix("b/")
                if clean != "/dev/null":
                    current_file = clean
                    if current_file not in files:
                        files[current_file] = [line]
                else:
                    current_file = None
            else:
                current_file = None
        elif line.startswith("+++ b/"):
            clean = line[6:].strip()
            if clean != "/dev/null":
                current_file = clean
                if current_file not in files:
                    files[current_file] = [line]
        elif current_file is not None:
            files[current_file].append(line)

    return {f: "\n".join(lines) for f, lines in files.items()}


def scan_diff_for_high_risk_triggers(diff_text: str | None) -> list[str]:
    """
    Screens unified diff text for high-risk AST and pattern triggers.
    Returns a list of human-readable trigger descriptions.
    """
    if not diff_text:
        return []

    triggers: list[str] = []
    for pattern, desc in _HIGH_RISK_DIFF_PATTERNS:
        if pattern.search(diff_text):
            triggers.append(desc)
    return triggers


def classify_file(file_path: str, file_diff: str | None = None) -> tuple[int, list[str]]:
    """
    Classifies a single file path (and its optional diff content) into a risk tier:
      - Tier 0: Documentation & Non-Code Assets
      - Tier 1: Scripting, Packaging & Utilities
      - Tier 2: CI/CD Workflows & Core Application Runtime
      - Tier 3: IaC, IAM, Cloud Topology, DB & Destructive Operations
    Returns (tier, list_of_reasons).
    """
    # Normalize separators
    normalized = file_path.replace("\\", "/").strip()
    if not normalized:
        return RiskTier.TIER_0, ["Empty file path"]

    lower_path = normalized.lower()
    path_obj = Path(normalized)
    name = path_obj.name.lower()
    ext = path_obj.suffix.lower()
    path_parts = [p.lower() for p in path_obj.parts]
    reasons: list[str] = []

    # 1. High-risk Diff Content Screening (Immediate Tier 3 escalation)
    if file_diff:
        triggers = scan_diff_for_high_risk_triggers(file_diff)
        if triggers:
            for t in triggers:
                reasons.append(f"High-risk diff trigger: {t}")
            return RiskTier.TIER_3, reasons

    # 2. Check Security, Invariants, and Governance (Tier 3)
    for sec_pat in _SECURITY_GOVERNANCE_PATTERNS:
        if sec_pat in lower_path or lower_path.startswith(sec_pat):
            reasons.append(f"Security invariant / governance rule: matches '{sec_pat}'")
            return RiskTier.TIER_3, reasons

    # 3. Check IaC extensions (Tier 3)
    if ext in _IAC_EXTENSIONS:
        reasons.append(f"Infrastructure as Code (IaC) extension '{ext}'")
        return RiskTier.TIER_3, reasons

    # 4. Check Container filenames (Tier 3)
    if name in _CONTAINER_FILENAMES or name.startswith(("dockerfile", "containerfile")):
        reasons.append(f"Container configuration: '{path_obj.name}'")
        return RiskTier.TIER_3, reasons

    if name.startswith(("docker-compose", "compose")) and ext in {".yml", ".yaml"}:
        reasons.append(f"Container compose manifest: '{path_obj.name}'")
        return RiskTier.TIER_3, reasons

    # 5. Check Helm & Kustomize manifests (Tier 3)
    if name in {"chart.yaml", "chart.yml", "values.yaml", "values.yml", "kustomization.yaml", "kustomization.yml"}:
        reasons.append(f"Kubernetes orchestration manifest: '{path_obj.name}'")
        return RiskTier.TIER_3, reasons

    if name.startswith("values-") and ext in {".yml", ".yaml"}:
        reasons.append(f"Helm values overlay manifest: '{path_obj.name}'")
        return RiskTier.TIER_3, reasons

    # 6. Check Infrastructure Directories (Tier 3 for config / YAML / JSON)
    for infra_dir in _INFRA_DIR_PATTERNS:
        if infra_dir in path_parts and ext in {".yaml", ".yml", ".json", ".hcl", ".env", ".conf", ".sh", ".tf"}:
            reasons.append(f"Infrastructure directory '{infra_dir}' with configuration file")
            return RiskTier.TIER_3, reasons

    # 7. Check Database Migrations and Schemas (Tier 3)
    for db_pat in _DATABASE_MIGRATION_PATTERNS:
        if db_pat in lower_path:
            reasons.append(f"Database migration or schema definition: matches '{db_pat}'")
            return RiskTier.TIER_3, reasons

    if ext == ".sql" and ("migration" in lower_path or "schema" in lower_path):
        reasons.append(f"Database SQL migration file: '{path_obj.name}'")
        return RiskTier.TIER_3, reasons

    # 8. Check Environment & Secret files (Tier 3)
    if name == ".env" or name.startswith(".env."):
        reasons.append("Environment / secrets file")
        return RiskTier.TIER_3, reasons

    # 9. Check CI/CD workflow patterns (Tier 2)
    for cicd in _CICD_PATTERNS:
        if cicd in lower_path:
            reasons.append(f"CI/CD workflow configuration: matches '{cicd}'")
            return RiskTier.TIER_2, reasons

    if "templates/" in lower_path and ext in {".yml", ".yaml"}:
        reasons.append(f"CI/CD workflow template: '{normalized}'")
        return RiskTier.TIER_2, reasons

    # 10. Check Core Application Runtime Logic (Tier 2)
    if lower_path.startswith("src/ocagents/") or "/src/ocagents/" in lower_path or lower_path.startswith("src/"):
        reasons.append(f"Core application runtime logic: '{normalized}'")
        return RiskTier.TIER_2, reasons

    # 11. Check Tier 0 (Documentation & Non-Code Assets)
    if (lower_path.startswith("docs/") or "/docs/" in lower_path) and (ext in _TIER_0_EXTENSIONS or ext == ""):
        reasons.append(f"Documentation asset under docs/: '{normalized}'")
        return RiskTier.TIER_0, reasons

    if lower_path.startswith(("images/", "media/")) or "/images/" in lower_path or "/media/" in lower_path:
        reasons.append(f"Media asset: '{normalized}'")
        return RiskTier.TIER_0, reasons

    if name in _TIER_0_FILENAMES:
        reasons.append(f"Repository metadata / license: '{path_obj.name}'")
        return RiskTier.TIER_0, reasons

    if name.startswith("changelog"):
        reasons.append(f"Changelog file: '{path_obj.name}'")
        return RiskTier.TIER_0, reasons

    if ext in _TIER_0_EXTENSIONS:
        reasons.append(f"Documentation / non-code extension '{ext}'")
        return RiskTier.TIER_0, reasons

    # 12. Check Tier 1 (Scripting, Packaging & Utilities)
    if ext in _TIER_1_SCRIPT_EXTENSIONS:
        reasons.append(f"Shell script / automation tooling extension '{ext}'")
        return RiskTier.TIER_1, reasons

    if lower_path.startswith("scripts/") or "/scripts/" in lower_path:
        reasons.append(f"Utility helper script: '{normalized}'")
        return RiskTier.TIER_1, reasons

    if lower_path.startswith("formula/") or "/formula/" in lower_path:
        reasons.append(f"Homebrew packaging formula: '{normalized}'")
        return RiskTier.TIER_1, reasons

    if name in _TIER_1_PACKAGING_FILENAMES or lower_path.startswith("packaging/"):
        reasons.append(f"Packaging / build dependency manifest '{path_obj.name}'")
        return RiskTier.TIER_1, reasons

    # 13. General Application Source Code (Tier 2)
    if ext in _CORE_APP_EXTENSIONS:
        reasons.append(f"Application source code extension '{ext}'")
        return RiskTier.TIER_2, reasons

    # 14. Fallback: Default unrecognized files safely to Tier 1
    reasons.append(f"Unrecognized file type '{ext or path_obj.name}', default safe route to Scripting & Utility Review")
    return RiskTier.TIER_1, reasons


def classify_changeset(files: list[str], diff_text: str | None = None) -> TriageResult:
    """
    Classifies a list of changed files (and optional unified diff text) into an overall risk tier (0 to 3).
    """
    file_diffs: dict[str, str] = {}
    high_risk_triggers: list[str] = []

    if diff_text:
        file_diffs = parse_diff_files_with_chunks(diff_text)
        high_risk_triggers = scan_diff_for_high_risk_triggers(diff_text)
        # If files list was empty, extract them from diff
        if not files:
            files = list(file_diffs.keys())

    # Empty changeset defaults to Tier 0
    if not files:
        plan = resolve_invocation_plan(RiskTier.TIER_0)
        return TriageResult(
            risk_tier=int(RiskTier.TIER_0),
            tier_name=plan.tier_name,
            activated_agents=plan.activated_agents,
            file_classifications={},
            file_reasons={},
            reasons=["No modified files detected in changeset"],
            files_by_tier={0: [], 1: [], 2: [], 3: []},
            diff_summary={"total_files": 0, "tier_0": 0, "tier_1": 0, "tier_2": 0, "tier_3": 0},
            skipped_agents=plan.skipped_agents,
            high_risk_triggers=[],
            invocation_plan=plan.to_dict(),
        )

    file_classifications: dict[str, int] = {}
    file_reasons: dict[str, list[str]] = {}
    files_by_tier: dict[int, list[str]] = {0: [], 1: [], 2: [], 3: []}
    highest_tier = RiskTier.TIER_0

    for f in sorted(files):
        tier, reasons = classify_file(f, file_diff=file_diffs.get(f))
        file_classifications[f] = int(tier)
        file_reasons[f] = reasons
        files_by_tier[int(tier)].append(f)
        highest_tier = max(highest_tier, tier)

    # If diff text triggered high-risk patterns, enforce Tier 3
    if high_risk_triggers and highest_tier < RiskTier.TIER_3:
        highest_tier = RiskTier.TIER_3

    plan = resolve_invocation_plan(highest_tier, high_risk_triggers=high_risk_triggers)

    # Synthesize overall reasons
    overall_reasons: list[str] = []
    if high_risk_triggers:
        overall_reasons.append(
            f"Detected {len(high_risk_triggers)} high-risk AST diff trigger(s) escalating changeset to Tier 3"
        )
        for tr in high_risk_triggers[:5]:
            overall_reasons.append(f"  ⚠️ {tr}")

    if highest_tier == RiskTier.TIER_3:
        tier_3_files = files_by_tier[3]
        overall_reasons.append(
            f"Detected {len(tier_3_files)} high blast radius file(s) requiring full Master Suite blackboard review"
        )
        for f in tier_3_files[:5]:
            reasons_str = "; ".join(file_reasons[f])
            overall_reasons.append(f"  • {f} -> {reasons_str}")
        if len(tier_3_files) > 5:
            overall_reasons.append(f"  • ... and {len(tier_3_files) - 5} more Tier 3 files")
    elif highest_tier == RiskTier.TIER_2:
        tier_2_files = files_by_tier[2]
        overall_reasons.append(
            f"Detected {len(tier_2_files)} medium blast radius workflow/runtime file(s); activating Security Commander & Reviewer"
        )
        for f in tier_2_files[:3]:
            reasons_str = "; ".join(file_reasons[f])
            overall_reasons.append(f"  • {f} -> {reasons_str}")
    elif highest_tier == RiskTier.TIER_1:
        tier_1_files = files_by_tier[1]
        overall_reasons.append(
            f"Detected {len(tier_1_files)} scripting/packaging utility file(s); routing to DevSecOps Engineer"
        )
        for f in tier_1_files[:3]:
            reasons_str = "; ".join(file_reasons[f])
            overall_reasons.append(f"  • {f} -> {reasons_str}")
    else:
        overall_reasons.append(
            f"All {len(files)} file(s) are documentation or non-code assets; bypassing specialist LLM review"
        )

    diff_summary = {
        "total_files": len(files),
        "tier_0": len(files_by_tier[0]),
        "tier_1": len(files_by_tier[1]),
        "tier_2": len(files_by_tier[2]),
        "tier_3": len(files_by_tier[3]),
    }

    return TriageResult(
        risk_tier=int(highest_tier),
        tier_name=plan.tier_name,
        activated_agents=plan.activated_agents,
        file_classifications=file_classifications,
        file_reasons=file_reasons,
        reasons=overall_reasons,
        files_by_tier=files_by_tier,
        diff_summary=diff_summary,
        skipped_agents=plan.skipped_agents,
        high_risk_triggers=high_risk_triggers,
        invocation_plan=plan.to_dict(),
    )


def classify_diff(diff_text: str) -> TriageResult:
    """Classifies a unified git diff text."""
    file_diffs = parse_diff_files_with_chunks(diff_text)
    files = list(file_diffs.keys())
    return classify_changeset(files, diff_text=diff_text)


def classify_git_ref(
    base_ref: str,
    head_ref: str = "HEAD",
    repo_root: str | Path | None = None,
) -> TriageResult:
    """
    Computes git diff between base_ref and head_ref and classifies the changeset.
    Fails closed if the git command fails.
    """
    root = Path(repo_root or os.getcwd()).resolve()
    cmd = ["git", "diff", f"{base_ref}...{head_ref}"]

    proc = subprocess.run(
        cmd,
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )

    if proc.returncode != 0:
        # Retry with two dots if three dots failed
        cmd_fallback = ["git", "diff", f"{base_ref}..{head_ref}"]
        proc = subprocess.run(
            cmd_fallback,
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            err_msg = proc.stderr.strip() or f"Failed to compute git diff between {base_ref} and {head_ref}"
            raise RuntimeError(f"Git diff failed (exit {proc.returncode}): {err_msg}")

    diff_text = proc.stdout
    return classify_diff(diff_text)
