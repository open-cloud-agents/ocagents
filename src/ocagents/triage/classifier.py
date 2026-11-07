"""
Open Cloud Agents: Blast Radius Risk Tier Classifier (Milestone v1.6 - TASK-3.1).

Evaluates Git changesets and diffs to categorize risk into three operational tiers:
  - Tier 0: Documentation & Non-Code Assets (LLM Bypass, 0 tokens)
  - Tier 1: Application Logic Only (DevSecOps Reviewer)
  - Tier 2: High Blast Radius Infrastructure (Master Suite Blackboard)
"""

from __future__ import annotations

import enum
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class RiskTier(enum.IntEnum):
    """Blast radius risk tiers defined in ADR-002 and Roadmap v1.6."""
    TIER_0 = 0  # Docs & Non-Code Assets (LLM Bypass)
    TIER_1 = 1  # Application Logic Only (DevSecOps Reviewer)
    TIER_2 = 2  # High Blast Radius Infrastructure (Master Suite Blackboard)


TIER_NAMES: dict[int, str] = {
    RiskTier.TIER_0: "Tier 0: Docs & Non-Code Assets (LLM Bypass)",
    RiskTier.TIER_1: "Tier 1: Application Logic Only (DevSecOps Reviewer)",
    RiskTier.TIER_2: "Tier 2: High Blast Radius Infrastructure (Master Suite Blackboard)",
}

TIER_AGENTS: dict[int, list[str]] = {
    RiskTier.TIER_0: [],
    RiskTier.TIER_1: ["devsecops-reviewer"],
    RiskTier.TIER_2: [
        "principal-cloud-architect",
        "security-compliance-commander",
        "finops-cloud-cost-optimizer",
        "sre-reliability-engineer",
        "devsecops-reviewer",
    ],
}

# --- File Classification Patterns ---

# High-risk infrastructure directories (all yaml/json inside are Tier 2)
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

# High-risk CI/CD workflow directory prefixes or files
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
]

# IaC extensions
_IAC_EXTENSIONS = {
    ".tf",
    ".tfvars",
    ".bicep",
    ".arm",
    ".pulumi",
    ".cdk",
    ".hcl",
}

# Container files
_CONTAINER_FILENAMES = {
    "dockerfile",
    "containerfile",
    "vagrantfile",
}

# Security, governance, and institutional rules
_SECURITY_GOVERNANCE_PATTERNS = [
    "rules/",
    ".ocagents/exceptions.json",
    ".ocagents/",
    ".rego",
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
}

# Tier 1 source code extensions (application logic)
_TIER_1_EXTENSIONS = {
    ".py",
    ".pyi",
    ".go",
    ".java",
    ".kt",
    ".scala",
    ".groovy",
    ".clj",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".rs",
    ".c",
    ".cpp",
    ".cc",
    ".cxx",
    ".h",
    ".hpp",
    ".hxx",
    ".cs",
    ".rb",
    ".php",
    ".swift",
    ".sh",
    ".bash",
    ".zsh",
}

# High-risk content patterns inside diffs
_HIGH_RISK_DIFF_PATTERNS = [
    (re.compile(r"^\+\s*force[_-]destroy\s*=\s*(?:true|1)", re.IGNORECASE | re.MULTILINE), "IaC resource deletion attribute enabled (force-destroy)"),
    (re.compile(r"forces\s+replacement", re.IGNORECASE), "IaC resource recreation directive (replacement forced)"),
    (re.compile(r"0\.0\.0\.0/0", re.IGNORECASE), "Unbounded CIDR 0.0.0.0/0 route or policy exposure"),
    (re.compile(r"chmod\s+777", re.IGNORECASE), "Permissive mode-777 execution permissions"),
    (re.compile(r"apiVersion:\s*[\w\.\/]+", re.IGNORECASE), "Kubernetes API manifest definition"),
    (re.compile(r"resource\s+\"(aws_|google_|azurerm_)", re.IGNORECASE), "Cloud provider infrastructure resource block"),
    (re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE), "Potential plaintext AWS access key ID"),
    (re.compile(r"-----BEGIN\s+(RSA|EC|OPENSSH|PGP|PRIVATE)\s+KEY-----", re.IGNORECASE), "Potential plaintext private key"),
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

    def to_dict(self) -> dict[str, Any]:
        """Serializes the triage result to a clean dictionary."""
        return {
            "risk_tier": self.risk_tier,
            "tier_name": self.tier_name,
            "activated_agents": list(self.activated_agents),
            "file_classifications": dict(self.file_classifications),
            "file_reasons": dict(self.file_reasons),
            "reasons": list(self.reasons),
            "files_by_tier": {str(k): list(v) for k, v in self.files_by_tier.items()},
            "diff_summary": dict(self.diff_summary),
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


def classify_file(file_path: str, file_diff: str | None = None) -> tuple[int, list[str]]:
    """
    Classifies a single file path (and its optional diff content) into a risk tier.
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
    reasons: list[str] = []

    # 1. Check CI/CD workflow patterns (Tier 2)
    for cicd in _CICD_PATTERNS:
        if cicd in lower_path:
            reasons.append(f"CI/CD workflow configuration: matches '{cicd}'")
            return RiskTier.TIER_2, reasons

    # 2. Check Security, Invariants, and Governance (Tier 2)
    for sec_pat in _SECURITY_GOVERNANCE_PATTERNS:
        if sec_pat in lower_path or lower_path.startswith(sec_pat):
            reasons.append(f"Security invariant / governance rule: matches '{sec_pat}'")
            return RiskTier.TIER_2, reasons

    # 3. Check IaC extensions (Tier 2)
    if ext in _IAC_EXTENSIONS:
        reasons.append(f"Infrastructure as Code (IaC) extension '{ext}'")
        return RiskTier.TIER_2, reasons

    # 4. Check Container filenames (Tier 2)
    if name in _CONTAINER_FILENAMES or name.startswith(("dockerfile", "containerfile")):
        reasons.append(f"Container configuration: '{path_obj.name}'")
        return RiskTier.TIER_2, reasons

    if name.startswith(("docker-compose", "compose")) and ext in {".yml", ".yaml"}:
        reasons.append(f"Container compose manifest: '{path_obj.name}'")
        return RiskTier.TIER_2, reasons

    # 5. Check Helm & Kustomize manifests (Tier 2)
    if name in {"chart.yaml", "chart.yml", "values.yaml", "values.yml", "kustomization.yaml", "kustomization.yml"}:
        reasons.append(f"Kubernetes orchestration manifest: '{path_obj.name}'")
        return RiskTier.TIER_2, reasons

    if name.startswith("values-") and ext in {".yml", ".yaml"}:
        reasons.append(f"Helm values overlay manifest: '{path_obj.name}'")
        return RiskTier.TIER_2, reasons

    # 6. Check Infrastructure Directories (Tier 2 for config / YAML / JSON)
    path_parts = [p.lower() for p in path_obj.parts]
    for infra_dir in _INFRA_DIR_PATTERNS:
        if infra_dir in path_parts and ext in {".yaml", ".yml", ".json", ".hcl", ".env", ".conf", ".sh"}:
            reasons.append(f"Infrastructure directory '{infra_dir}' with configuration file")
            return RiskTier.TIER_2, reasons

    # 7. Check Environment & Secret files (Tier 2)
    if name == ".env" or name.startswith(".env."):
        reasons.append("Environment / secrets file")
        return RiskTier.TIER_2, reasons

    # 8. Check Diff Content Inspection (High risk patterns inside diff)
    if file_diff:
        for pattern, desc in _HIGH_RISK_DIFF_PATTERNS:
            if pattern.search(file_diff):
                reasons.append(f"Diff content inspection: {desc}")
                return RiskTier.TIER_2, reasons

    # 9. Check Tier 0 (Documentation & Non-Code Assets)
    if (lower_path.startswith("docs/") or "/docs/" in lower_path) and (ext in _TIER_0_EXTENSIONS or ext == ""):
        reasons.append(f"Documentation asset under docs/: '{normalized}'")
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

    # 10. Check Tier 1 (Application Code Only)
    if ext in _TIER_1_EXTENSIONS:
        reasons.append(f"Application source code extension '{ext}'")
        return RiskTier.TIER_1, reasons

    # Common build & package manifests
    if name in {
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
    }:
        reasons.append(f"Application dependency / build manifest '{path_obj.name}'")
        return RiskTier.TIER_1, reasons

    # 11. Fallback: Default unrecognized files safely to Tier 1
    reasons.append(f"Unrecognized file type '{ext or path_obj.name}', default safe route to Application Review")
    return RiskTier.TIER_1, reasons


def classify_changeset(files: list[str], diff_text: str | None = None) -> TriageResult:
    """
    Classifies a list of changed files (and optional unified diff text) into an overall risk tier.
    """
    file_diffs: dict[str, str] = {}
    if diff_text:
        file_diffs = parse_diff_files_with_chunks(diff_text)
        # If files list was empty, extract them from diff
        if not files:
            files = list(file_diffs.keys())

    # Empty changeset defaults to Tier 0
    if not files:
        return TriageResult(
            risk_tier=RiskTier.TIER_0,
            tier_name=TIER_NAMES[RiskTier.TIER_0],
            activated_agents=TIER_AGENTS[RiskTier.TIER_0],
            file_classifications={},
            file_reasons={},
            reasons=["No modified files detected in changeset"],
            files_by_tier={0: [], 1: [], 2: []},
            diff_summary={"total_files": 0, "tier_0": 0, "tier_1": 0, "tier_2": 0},
        )

    file_classifications: dict[str, int] = {}
    file_reasons: dict[str, list[str]] = {}
    files_by_tier: dict[int, list[str]] = {0: [], 1: [], 2: []}
    highest_tier = RiskTier.TIER_0

    for f in sorted(files):
        tier, reasons = classify_file(f, file_diff=file_diffs.get(f))
        file_classifications[f] = int(tier)
        file_reasons[f] = reasons
        files_by_tier[int(tier)].append(f)
        highest_tier = max(highest_tier, tier)

    # Synthesize overall reasons
    overall_reasons: list[str] = []
    if highest_tier == RiskTier.TIER_2:
        tier_2_files = files_by_tier[2]
        overall_reasons.append(
            f"Detected {len(tier_2_files)} high blast radius file(s) requiring Master Suite blackboard review"
        )
        for f in tier_2_files[:5]:
            reasons_str = "; ".join(file_reasons[f])
            overall_reasons.append(f"  • {f} -> {reasons_str}")
        if len(tier_2_files) > 5:
            overall_reasons.append(f"  • ... and {len(tier_2_files) - 5} more Tier 2 files")
    elif highest_tier == RiskTier.TIER_1:
        tier_1_files = files_by_tier[1]
        overall_reasons.append(
            f"Detected {len(tier_1_files)} application logic file(s) without IaC or security policy changes; routing to DevSecOps Reviewer"
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
    }

    return TriageResult(
        risk_tier=int(highest_tier),
        tier_name=TIER_NAMES[highest_tier],
        activated_agents=TIER_AGENTS[highest_tier],
        file_classifications=file_classifications,
        file_reasons=file_reasons,
        reasons=overall_reasons,
        files_by_tier=files_by_tier,
        diff_summary=diff_summary,
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

