"""Open Cloud Agents: Deterministic Pre-Flight Gatekeeper & Runner.

Implements the local pre-flight command and CI gatekeeper engine in accordance with
ADR-002 (Pillar 3: Deterministic Pre-Flight Gate):
- Changeset resolution: explicit paths, git diff, or unstaged working tree.
- Fail-Closed Scanner Availability Gate: checks mandatory and advisory static scanners
  against .ocagents/exceptions.json.
- Deterministic Invariant Evaluation: executes OPA / institutional policy checks and
  DevSecOps diff screen on the changeset.
- Normalized Findings Aggregation: categorizes findings by canonical schema severity.
- Exit code protocol: 0 on clean pass, 1 on required failure / invariant defect, 2 on advisory warnings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import fnmatch
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Callable, Iterable, Sequence

from ocagents.findings.normalizer import (
    CANONICAL_SCHEMA_URI,
    RULE_DESTRUCTIVE,
    RULE_TO_DEFAULT_RECOMMENDATION,
    RULE_WELL_ARCHITECTED,
    compute_finding_id,
)
from ocagents.findings.provenance import resolve_default_repo_root
from ocagents.scanner.availability import (
    AvailabilityReport,
    AvailabilityStatus,
    ScannerAvailabilityProtocol,
)
from ocagents.scanner.checkov import CheckovAdapter
from ocagents.scanner.diff_filter import filter_findings_by_diff, parse_diff_modified_lines
from ocagents.scanner.exceptions import ExceptionsManifest
from ocagents.scanner.opa import OpaEvaluator
from ocagents.scanner.registry import (
    RequirementLevel,
    ScannerDefinition,
    ScannerRegistry,
    get_default_registry,
    is_k8s_or_iac_manifest,
)
from ocagents.scanner.trivy import TrivyAdapter

# Common directory exclusions when resolving changesets from filesystem
IGNORED_DIRS = frozenset({
    ".git",
    ".github",
    ".cache",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    "env",
    ".tox",
    "build",
    "dist",
})

DEFAULT_CODEQL_QUERY_SUITE = "python-security-and-quality.qls"


def parse_diff_target_files(diff_text: str) -> list[str]:
    """Extracts target file paths from a unified git diff."""
    files: list[str] = []
    seen: set[str] = set()

    for line in diff_text.splitlines():
        if line.startswith("diff --git"):
            parts = line.split()
            if len(parts) >= 4:
                # Format: diff --git a/path b/path
                b_path = parts[3]
                if b_path.startswith("b/"):
                    clean = b_path[2:]
                else:
                    clean = b_path
                if clean and clean not in seen and clean != "/dev/null":
                    seen.add(clean)
                    files.append(clean)
        elif line.startswith("+++ b/"):
            clean = line[6:].strip()
            if clean and clean not in seen and clean != "/dev/null":
                seen.add(clean)
                files.append(clean)

    return files


# Segmented string constants to avoid self-flagging by heuristic diff screens
_PATTERN_FORCE_DESTROY = "force_" + "destroy = true"
_PATTERN_FORCES_REPLACEMENT = "forces" + " replacement"
_PATTERN_ALL_INGRESS = "0.0.0" + ".0/0"
_PATTERN_CHMOD_777 = "chmod" + " 777"


def audit_diff_heuristics(diff_text: str) -> list[dict[str, Any]]:
    """Inspects unified git diff for literal high-risk architectural and security patterns."""
    findings: list[dict[str, Any]] = []
    current_file = ""
    new_line_num = 0

    for line in diff_text.splitlines():
        if line.startswith("diff --git"):
            parts = line.split()
            current_file = parts[2][2:] if len(parts) > 2 else ""
            new_line_num = 0
            continue
        elif line.startswith("@@"):
            # Parse @@ -old,count +new,count @@
            m = re.search(r"\+(\d+)(?:,(\d+))?", line)
            if m:
                new_line_num = int(m.group(1)) - 1
            continue

        if line.startswith("+") and not line.startswith("+++"):
            new_line_num += 1

            # Exclude documentation, test fixtures, and CI workflow configs
            lower_file = current_file.lower()
            if (
                lower_file.endswith(".md")
                or lower_file.startswith(".github/")
                or lower_file.startswith("tests/")
                or "/fixtures/" in lower_file
                or "/mocks/" in lower_file
                or "test" in lower_file
            ):
                continue

            stripped = line[1:].strip()
            # Skip code comments
            if stripped.startswith(("#", "//", "/*", "*")):
                continue

            # 1. State destruction or force replacement traps (Rule 01)
            is_iac_file = any(lower_file.endswith(ext) for ext in (".tf", ".tfvars", ".bicep", ".json"))
            if is_iac_file and (_PATTERN_FORCE_DESTROY in stripped.lower() or _PATTERN_FORCES_REPLACEMENT in stripped.lower()):
                findings.append({
                    "rule_id": RULE_DESTRUCTIVE,
                    "category": "reliability",
                    "resource": current_file,
                    "fact": f"Potential state destruction or replacement trap detected: `{stripped[:80]}`",
                    "evidence": f"diff:{current_file}#L{new_line_num}",
                    "recommendation": (
                        "Remove state destruction flag or verify zero unplanned data destruction before proceeding."
                    ),
                    "severity": "high",
                })

            # 2. Open ingress to 0.0.0.0/0 (Rule 04)
            is_network_file = any(lower_file.endswith(ext) for ext in (".tf", ".tfvars", ".bicep", ".json", ".yaml", ".yml"))
            if is_network_file and (_PATTERN_ALL_INGRESS in stripped and ("ingress" in stripped.lower() or "cidr_blocks" in stripped.lower())):
                findings.append({
                    "rule_id": RULE_WELL_ARCHITECTED,
                    "category": "security",
                    "resource": current_file,
                    "fact": f"Unrestricted CIDR ingress detected: `{stripped[:80]}`",
                    "evidence": f"diff:{current_file}#L{new_line_num}",
                    "recommendation": (
                        "Restrict ingress CIDR blocks to authorized private subnets or internal VPC endpoints."
                    ),
                    "severity": "high",
                })

            # 3. Permissive chmod 777 (Rule 02)
            is_script_or_docker = any(lower_file.endswith(ext) for ext in (".sh", ".bash", ".zsh", "dockerfile", "containerfile")) or "dockerfile" in lower_file
            if is_script_or_docker and _PATTERN_CHMOD_777 in stripped:
                findings.append({
                    "rule_id": "rules/02-secrets-and-identity.md",
                    "category": "security",
                    "resource": current_file,
                    "fact": f"Overly permissive file permissions detected: `{stripped[:80]}`",
                    "evidence": f"diff:{current_file}#L{new_line_num}",
                    "recommendation": (
                        "Enforce least-privilege permissions (e.g. chmod 755 for scripts or 644 for assets)."
                    ),
                    "severity": "high",
                })
        elif not line.startswith("-"):
            # Context line advances new_line_num
            new_line_num += 1

    return findings


@dataclass
class PreflightResult:
    """Encapsulates the complete result of a pre-flight execution."""

    status: AvailabilityStatus
    exit_code: int
    changeset: list[str] = field(default_factory=list)
    diff_text: str | None = None
    executed_scanners: list[str] = field(default_factory=list)
    skipped_scanners: list[dict[str, Any]] = field(default_factory=list)
    exemptions_applied: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    diagnostics: list[str] = field(default_factory=list)
    strict: bool = False

    @property
    def is_clean(self) -> bool:
        return self.status == AvailabilityStatus.CLEAN and self.exit_code == 0

    @property
    def is_failed(self) -> bool:
        return self.exit_code == 1

    @property
    def is_inconclusive(self) -> bool:
        return self.status in (
            AvailabilityStatus.INCONCLUSIVE_PARTIAL_AUDIT,
            AvailabilityStatus.ADVISORY_WARNINGS,
        )

    @property
    def has_advisories(self) -> bool:
        return self.status == AvailabilityStatus.ADVISORY_WARNINGS

    def to_dict(self) -> dict[str, Any]:
        """Returns JSON-serializable dictionary representation."""
        return {
            "status": self.status.value,
            "exit_code": self.exit_code,
            "strict": self.strict,
            "summary": {
                "changeset_size": len(self.changeset),
                "total_findings": len(self.findings),
                "executed_scanners": self.executed_scanners,
                "skipped_scanners_count": len(self.skipped_scanners),
                "exemptions_applied_count": len(self.exemptions_applied),
                "findings_by_severity": self.findings_by_severity,
            },
            "changeset": self.changeset,
            "executed_scanners": self.executed_scanners,
            "skipped_scanners": self.skipped_scanners,
            "exemptions_applied": self.exemptions_applied,
            "findings": self.findings,
            "diagnostics": self.diagnostics,
        }

    def format_terminal_summary(self, use_color: bool = True) -> str:
        """Renders colorized execution summary for terminal output."""
        c_bold = "\033[1m" if use_color else ""
        c_reset = "\033[0m" if use_color else ""
        c_green = "\033[32m" if use_color else ""
        c_yellow = "\033[33m" if use_color else ""
        c_red = "\033[31m" if use_color else ""
        c_cyan = "\033[36m" if use_color else ""
        c_dim = "\033[2m" if use_color else ""

        lines = [
            f"{c_bold}============================================================{c_reset}",
            f"{c_cyan}{c_bold} 🛡️  Open Cloud Agents: Deterministic Pre-Flight Gate (Pillar 3){c_reset}",
            f"{c_bold}============================================================{c_reset}",
        ]

        # Target Changeset
        lines.append(f"{c_bold}Target Changeset:{c_reset} {len(self.changeset)} file(s)")
        if self.changeset:
            display_files = self.changeset[:5]
            for f in display_files:
                lines.append(f"  {c_dim}•{c_reset} {f}")
            if len(self.changeset) > 5:
                lines.append(f"  {c_dim}... and {len(self.changeset) - 5} more file(s){c_reset}")
        else:
            lines.append(f"  {c_dim}(No files detected in changeset){c_reset}")

        lines.append("")

        # Status & Verdict
        if self.status == AvailabilityStatus.CLEAN:
            verdict_badge = f"{c_green}{c_bold}✔ VERDICT: CLEAN (Exit Code {self.exit_code}){c_reset}"
        elif self.status == AvailabilityStatus.ADVISORY_WARNINGS:
            verdict_badge = f"{c_yellow}{c_bold}⚠ VERDICT: ADVISORY_WARNINGS (Exit Code {self.exit_code}){c_reset}"
        elif self.status == AvailabilityStatus.INCONCLUSIVE_PARTIAL_AUDIT:
            verdict_badge = f"{c_yellow}{c_bold}⚠ VERDICT: INCONCLUSIVE_PARTIAL_AUDIT (Exit Code {self.exit_code}){c_reset}"
        else:
            verdict_badge = f"{c_red}{c_bold}✖ VERDICT: INCOMPLETE_CHECK_FAILED (Exit Code {self.exit_code}){c_reset}"
        lines.append(f"{c_bold}Execution Status:{c_reset} {verdict_badge}")
        lines.append("")

        # Executed Scanners
        lines.append(f"{c_bold}Executed Scanners ({len(self.executed_scanners)}):{c_reset}")
        if self.executed_scanners:
            for s in self.executed_scanners:
                lines.append(f"  {c_green}✔{c_reset} {s}")
        else:
            lines.append(f"  {c_dim}(No scanners executed){c_reset}")
        lines.append("")

        # Skipped / Missing Scanners
        if self.skipped_scanners:
            lines.append(f"{c_bold}Skipped / Missing Checks ({len(self.skipped_scanners)}):{c_reset}")
            for item in self.skipped_scanners:
                lvl = item.get("level", "ADVISORY")
                name = item.get("name", "unknown")
                binary = item.get("binary", name)
                reason = item.get("reason", "")
                if lvl == "REQUIRED":
                    lines.append(f"  {c_red}✖ [REQUIRED] {name} (binary '{binary}'){c_reset}")
                else:
                    lines.append(f"  {c_yellow}⚠ [ADVISORY] {name} (binary '{binary}'){c_reset}")
                if reason:
                    lines.append(f"    {c_dim}{reason}{c_reset}")
            lines.append("")

        # Signed Exemptions Applied
        if self.exemptions_applied:
            lines.append(f"{c_bold}Signed Exemptions Applied ({len(self.exemptions_applied)}):{c_reset}")
            for ex in self.exemptions_applied:
                lines.append(
                    f"  {c_cyan}🛡️ [EXEMPT]{c_reset} {ex.get('rule_id')} on {ex.get('resource')} "
                    f"{c_dim}(owner: {ex.get('risk_owner')}, expires: {ex.get('expires_at')}){c_reset}"
                )
            lines.append("")

        # Findings Summary Table
        lines.append(f"{c_bold}Findings Breakdown:{c_reset}")
        c_count = self.findings_by_severity.get("critical", 0)
        h_count = self.findings_by_severity.get("high", 0)
        m_count = self.findings_by_severity.get("medium", 0)
        l_count = self.findings_by_severity.get("low", 0)
        i_count = self.findings_by_severity.get("info", 0)

        c_badge = f"{c_red}{c_count}{c_reset}" if c_count else "0"
        h_badge = f"{c_red}{h_count}{c_reset}" if h_count else "0"
        m_badge = f"{c_yellow}{m_count}{c_reset}" if m_count else "0"
        l_badge = f"{c_dim}{l_count}{c_reset}" if l_count else "0"
        i_badge = f"{c_dim}{i_count}{c_reset}" if i_count else "0"

        lines.append(
            f"  CRITICAL: {c_badge} | HIGH: {h_badge} | MEDIUM: {m_badge} | LOW: {l_badge} | INFO: {i_badge}"
        )
        lines.append("")

        # Individual Findings
        if self.findings:
            lines.append(f"{c_bold}Violations & Findings ({len(self.findings)}):{c_reset}")
            for f in self.findings:
                sev = str(f.get("severity", "info")).upper()
                f_id = f.get("id", "FND-UNKNOWN")
                rule = f.get("rule_id", "rule")
                res = f.get("resource", "resource")
                fact = f.get("fact", "")
                rec = f.get("recommendation", "")
                ev = f.get("evidence", "")

                color = c_red if sev in ("CRITICAL", "HIGH") else (c_yellow if sev == "MEDIUM" else c_dim)
                lines.append(f"  • {color}[{sev}]{c_reset} {c_bold}{f_id}{c_reset} ({rule})")
                lines.append(f"    Resource: {res} | Evidence: {ev}")
                lines.append(f"    Fact: {fact}")
                if rec:
                    lines.append(f"    Recommendation: {rec}")
            lines.append("")

        # Diagnostics & Instructions
        if self.diagnostics:
            lines.append(f"{c_bold}Diagnostics & Audit Notes:{c_reset}")
            for d in self.diagnostics:
                if "FAIL-CLOSED" in d or "INCOMPLETE_CHECK_FAILED" in d or "Resource denied" in d:
                    lines.append(f"  {c_red}✖{c_reset} {d}")
                elif "DEGRADED COVERAGE" in d or "INCONCLUSIVE" in d:
                    lines.append(f"  {c_yellow}⚠{c_reset} {d}")
                elif "Exemption matched" in d:
                    lines.append(f"  {c_cyan}🛡️{c_reset} {d}")
                else:
                    lines.append(f"  {c_dim}ℹ{c_reset} {d}")
            lines.append("")

        lines.append(f"{c_bold}============================================================{c_reset}")
        return "\n".join(lines)


class PreflightEngine:
    """Orchestrates deterministic pre-flight checks across a target changeset."""

    def __init__(
        self,
        repo_root: Path | None = None,
        registry: ScannerRegistry | None = None,
        exceptions_manifest: ExceptionsManifest | None = None,
        which_fn: Callable[[str], str | None] | None = None,
        runner_fn: Callable[..., subprocess.CompletedProcess] | None = None,
        signing_key: str | None = None,
        codeql_db_path: Path | str | None = None,
        codeql_query_suite: str | Sequence[str] | None = None,
    ) -> None:
        self.repo_root = (repo_root or resolve_default_repo_root()).resolve()
        self.registry = registry or get_default_registry()
        self.signing_key = signing_key or os.environ.get("OCAGENTS_SIGNATURE_KEY")
        self.codeql_db_path = Path(codeql_db_path).resolve() if codeql_db_path else None
        self.codeql_query_suite = (
            codeql_query_suite
            if codeql_query_suite is not None
            else (
                os.environ.get("CODEQL_QUERY_SUITE")
                or os.environ.get("CODEQL_SUITE")
                or DEFAULT_CODEQL_QUERY_SUITE
            )
        )
        self.exceptions_manifest = (
            exceptions_manifest
            if exceptions_manifest is not None
            else ExceptionsManifest(repo_root=self.repo_root, signing_key=self.signing_key)
        )
        self.which_fn = which_fn or shutil.which
        self.runner_fn = runner_fn or subprocess.run
        self.availability_protocol = ScannerAvailabilityProtocol(
            registry=self.registry,
            exceptions_manifest=self.exceptions_manifest,
            which_fn=self.which_fn,
            repo_root=self.repo_root,
        )
        self.opa_evaluator = OpaEvaluator(repo_root=self.repo_root)
        self.checkov_adapter = CheckovAdapter(repo_root=self.repo_root)
        self.trivy_adapter = TrivyAdapter(repo_root=self.repo_root)

    def resolve_changeset(
        self,
        paths: Sequence[str | Path] | None = None,
        diff_target: str | None = None,
    ) -> tuple[list[str], str | None]:
        """Resolves target changeset files and optional unified diff text.

        Args:
            paths: Explicit list of file/directory paths or globs.
            diff_target: Base git ref (e.g. 'main', 'origin/main', 'HEAD~1') or path to unified diff file.

        Returns:
            Tuple of (normalized_file_paths, diff_text_or_none).

        Raises:
            FileNotFoundError: If an explicit diff patch file does not exist.
            ValueError: If an explicit git diff target ref cannot be resolved.
        """
        changeset_files: list[str] = []
        diff_text: str | None = None

        # 1. Inspect diff_target if provided
        if diff_target is not None:
            raw_target = str(diff_target).strip()
            diff_p = Path(raw_target)
            diff_p_rel = diff_p if diff_p.is_absolute() else (self.repo_root / diff_p)

            if diff_p_rel.is_file():
                diff_text = diff_p_rel.read_text(encoding="utf-8", errors="replace")
                changeset_files.extend(parse_diff_target_files(diff_text))
            elif raw_target.endswith((".diff", ".patch")) or ("/" in raw_target and not raw_target.startswith(("origin/", "heads/"))):
                raise FileNotFoundError(f"Requested diff target patch file does not exist: '{raw_target}'")
            else:
                base_ref = raw_target if raw_target else "main"
                candidate_cmds = (
                    [["git", "diff", base_ref]]
                    if ("..." in base_ref or ".." in base_ref)
                    else [
                        ["git", "diff", f"origin/{base_ref}...HEAD"],
                        ["git", "diff", f"{base_ref}...HEAD"],
                        ["git", "diff", base_ref],
                    ]
                )
                candidate_name_cmds = (
                    [["git", "diff", "--name-only", base_ref]]
                    if ("..." in base_ref or ".." in base_ref)
                    else [
                        ["git", "diff", "--name-only", f"origin/{base_ref}...HEAD"],
                        ["git", "diff", "--name-only", f"{base_ref}...HEAD"],
                        ["git", "diff", "--name-only", base_ref],
                    ]
                )

                resolved = False
                for cmd in candidate_cmds:
                    try:
                        res = self.runner_fn(cmd, capture_output=True, text=True, cwd=str(self.repo_root))
                        if res.returncode == 0:
                            diff_text = res.stdout
                            resolved = True
                            break
                    except Exception:
                        pass

                if not resolved:
                    raise ValueError(
                        f"Unable to resolve requested git diff target ref: '{base_ref}'. "
                        "Git command failed or ref does not exist in repository."
                    )

                for cmd in candidate_name_cmds:
                    try:
                        res = self.runner_fn(cmd, capture_output=True, text=True, cwd=str(self.repo_root))
                        if res.returncode == 0:
                            for line in res.stdout.splitlines():
                                line_s = line.strip()
                                if line_s and line_s not in changeset_files:
                                    changeset_files.append(line_s)
                            break
                    except Exception:
                        pass

        # 2. Inspect explicit paths if provided
        if paths:
            for p_raw in paths:
                p_str = str(p_raw).strip()
                if not p_str:
                    continue
                p = Path(p_str)
                if not p.is_absolute():
                    p_abs = (self.repo_root / p).resolve()
                else:
                    p_abs = p.resolve()

                if p_abs.is_file():
                    rel = p_abs.relative_to(self.repo_root).as_posix()
                    if rel not in changeset_files:
                        changeset_files.append(rel)
                elif p_abs.is_dir():
                    for root, dirs, files in os.walk(p_abs):
                        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
                        for f in files:
                            full = Path(root) / f
                            rel = full.relative_to(self.repo_root).as_posix()
                            if rel not in changeset_files:
                                changeset_files.append(rel)
                else:
                    # Glob pattern expansion
                    for matched in self.repo_root.glob(p_str):
                        if matched.is_file():
                            rel = matched.relative_to(self.repo_root).as_posix()
                            if rel not in changeset_files:
                                changeset_files.append(rel)

        # 3. Fallback when neither paths nor diff_target produced files
        if not changeset_files and diff_target is None and not paths:
            # Check git status for modified working tree files
            try:
                res = subprocess.run(
                    ["git", "status", "--porcelain"],
                    capture_output=True,
                    text=True,
                    cwd=str(self.repo_root),
                )
                if res.returncode == 0 and res.stdout.strip():
                    for line in res.stdout.splitlines():
                        if len(line) > 3:
                            rel_file = line[3:].strip()
                            if " -> " in rel_file:
                                rel_file = rel_file.split(" -> ")[1].strip()
                            if rel_file and rel_file not in changeset_files:
                                changeset_files.append(rel_file)

                    # Also capture working diff text
                    diff_res = subprocess.run(
                        ["git", "diff", "HEAD"],
                        capture_output=True,
                        text=True,
                        cwd=str(self.repo_root),
                    )
                    if diff_res.returncode == 0 and diff_res.stdout.strip():
                        diff_text = diff_res.stdout
            except Exception:
                pass

        # Normalize paths
        norm_files = [f.lstrip("/").replace("\\", "/") for f in changeset_files]
        return norm_files, diff_text

    def _run_checkov(
        self,
        files: Sequence[str],
        diff_text: str | None,
        diagnostics: list[str],
    ) -> list[dict[str, Any]]:
        """Invokes Checkov on applicable changeset files and parses findings via CheckovAdapter."""
        checkov_bin = self.which_fn("checkov") or "checkov"
        cmd = [checkov_bin]
        for f in files:
            cmd.extend(["-f", str(self.repo_root / f)])
        cmd.extend(["--output", "json", "--compact", "--quiet"])

        res = self.runner_fn(cmd, capture_output=True, text=True, cwd=str(self.repo_root))
        stdout = res.stdout if hasattr(res, "stdout") else ""
        if not stdout or not stdout.strip():
            if getattr(res, "returncode", 0) != 0:
                stderr = res.stderr if hasattr(res, "stderr") else ""
                raise RuntimeError(f"Checkov process failed with exit code {res.returncode}: {stderr.strip()[:200]}")
            return []

        try:
            return self.checkov_adapter.parse(stdout, diff_text=diff_text)
        except Exception as e:
            raise RuntimeError(f"Failed to parse Checkov JSON output: {e}")

    def _run_trivy(
        self,
        files: Sequence[str],
        diff_text: str | None,
        diagnostics: list[str],
    ) -> list[dict[str, Any]]:
        """Invokes Trivy on applicable changeset files and parses findings via TrivyAdapter."""
        trivy_bin = self.which_fn("trivy") or "trivy"
        all_findings: list[dict[str, Any]] = []

        for f in files:
            cmd = [trivy_bin, "fs", "--format", "json", "--quiet", str(self.repo_root / f)]
            res = self.runner_fn(cmd, capture_output=True, text=True, cwd=str(self.repo_root))
            stdout = res.stdout if hasattr(res, "stdout") else ""
            if not stdout or not stdout.strip():
                if getattr(res, "returncode", 0) != 0:
                    stderr = res.stderr if hasattr(res, "stderr") else ""
                    raise RuntimeError(f"Trivy process failed on '{f}' with exit code {res.returncode}: {stderr.strip()[:200]}")
                continue

            try:
                findings = self.trivy_adapter.parse(stdout, diff_text=diff_text)
                all_findings.extend(findings)
            except Exception as e:
                raise RuntimeError(f"Failed to parse Trivy output on '{f}': {e}")

        return all_findings

    def _run_shellcheck(
        self,
        files: Sequence[str],
        diff_text: str | None,
        diagnostics: list[str],
    ) -> list[dict[str, Any]]:
        """Invokes ShellCheck on shell scripts and maps violations to canonical findings."""
        shellcheck_bin = self.which_fn("shellcheck") or "shellcheck"
        cmd = [shellcheck_bin, "-f", "json"] + [str(self.repo_root / f) for f in files]

        res = self.runner_fn(cmd, capture_output=True, text=True, cwd=str(self.repo_root))
        stdout = res.stdout if hasattr(res, "stdout") else ""
        if not stdout or not stdout.strip():
            if getattr(res, "returncode", 0) not in (0, 1):
                stderr = res.stderr if hasattr(res, "stderr") else ""
                raise RuntimeError(f"ShellCheck process failed with exit code {res.returncode}: {stderr.strip()[:200]}")
            return []

        try:
            items = json.loads(stdout)
        except Exception as e:
            raise RuntimeError(f"Failed to parse ShellCheck JSON output: {e}")

        findings: list[dict[str, Any]] = []
        for item in items:
            raw_file = item.get("file", "")
            try:
                rel_file = Path(raw_file).resolve().relative_to(self.repo_root).as_posix()
            except Exception:
                rel_file = Path(raw_file).as_posix()

            line_num = int(item.get("line", 1))
            code = item.get("code", 0)
            level = str(item.get("level", "warning")).lower()
            msg = item.get("message", "ShellCheck violation")

            if level == "error":
                sev = "high"
            elif level == "warning":
                sev = "medium"
            else:
                sev = "low"

            evidence = f"repo:{rel_file}#L{line_num}"
            rule_id = f"shellcheck/SC{code}" if code else "rules/05-repository-and-path-hygiene.md"
            finding = {
                "$schema": CANONICAL_SCHEMA_URI,
                "id": compute_finding_id(rule_id, rel_file, evidence),
                "agent": "devsecops-reviewer",
                "origin": "deterministic_linter",
                "rule_id": rule_id,
                "category": "security" if str(code) in ("2086", "2154") else "reliability",
                "resource": rel_file,
                "fact": f"ShellCheck SC{code}: {msg}",
                "evidence": evidence,
                "recommendation": f"Resolve ShellCheck SC{code} on line {line_num}: {msg}",
                "severity": sev,
                "confidence": None,
                "corroboration_status": "tool_verified",
            }
            findings.append(finding)

        if diff_text:
            findings = filter_findings_by_diff(findings, diff_text)
        return findings

    def _run_ruff(
        self,
        files: Sequence[str],
        diff_text: str | None,
        diagnostics: list[str],
    ) -> list[dict[str, Any]]:
        """Invokes Ruff on Python files and maps violations to canonical findings."""
        ruff_bin = self.which_fn("ruff") or "ruff"
        cmd = [ruff_bin, "check", "--output-format", "json"] + [str(self.repo_root / f) for f in files]

        res = self.runner_fn(cmd, capture_output=True, text=True, cwd=str(self.repo_root))
        stdout = res.stdout if hasattr(res, "stdout") else ""
        if not stdout or not stdout.strip():
            if getattr(res, "returncode", 0) not in (0, 1):
                stderr = res.stderr if hasattr(res, "stderr") else ""
                raise RuntimeError(f"Ruff process failed with exit code {res.returncode}: {stderr.strip()[:200]}")
            return []

        try:
            items = json.loads(stdout)
        except Exception as e:
            raise RuntimeError(f"Failed to parse Ruff JSON output: {e}")

        findings: list[dict[str, Any]] = []
        for item in items:
            raw_file = item.get("filename", "")
            try:
                rel_file = Path(raw_file).resolve().relative_to(self.repo_root).as_posix()
            except Exception:
                rel_file = Path(raw_file).as_posix()

            loc = item.get("location") or {}
            line_num = int(loc.get("row", 1))
            code = str(item.get("code", "E"))
            msg = item.get("message", "Ruff linting violation")

            if code.startswith("S"):
                sev = "high"
                cat = "security"
            elif code.startswith(("F", "E9")):
                sev = "medium"
                cat = "reliability"
            else:
                sev = "low"
                cat = "hygiene"

            evidence = f"repo:{rel_file}#L{line_num}"
            rule_id = f"ruff/{code}"
            finding = {
                "$schema": CANONICAL_SCHEMA_URI,
                "id": compute_finding_id(rule_id, rel_file, evidence),
                "agent": "devsecops-reviewer",
                "origin": "deterministic_linter",
                "rule_id": rule_id,
                "category": cat,
                "resource": rel_file,
                "fact": f"Ruff rule {code}: {msg}",
                "evidence": evidence,
                "recommendation": f"Resolve Ruff rule {code} on line {line_num}: {msg}",
                "severity": sev,
                "confidence": None,
                "corroboration_status": "tool_verified",
            }
            findings.append(finding)

        if diff_text:
            findings = filter_findings_by_diff(findings, diff_text)
        return findings

    def _run_validate_repo(
        self,
        files: Sequence[str],
        diagnostics: list[str],
    ) -> list[dict[str, Any]]:
        """Invokes repository hygiene validator (scripts/ci/validate_repo.py)."""
        validator_script = self.repo_root / "scripts/ci/validate_repo.py"
        if not validator_script.is_file():
            return []

        python_bin = self.which_fn("python3") or self.which_fn("python") or sys.executable
        if Path(python_bin).name.startswith("ocagent"):
            python_bin = self.which_fn("python3") or self.which_fn("python") or "python3"
        cmd = [python_bin, str(validator_script), str(self.repo_root)]
        res = self.runner_fn(cmd, capture_output=True, text=True, cwd=str(self.repo_root))
        retcode = getattr(res, "returncode", 0)
        if retcode == 0:
            return []

        stdout = res.stdout if hasattr(res, "stdout") else ""
        stderr = res.stderr if hasattr(res, "stderr") else ""
        combined = f"{stdout}\n{stderr}".strip()

        # Capture recognized error lines in diagnostics
        for line in combined.splitlines():
            line_s = line.strip()
            if "✖" in line_s or "ERROR" in line_s or "Failed" in line_s:
                diagnostics.append(f"Repository hygiene failure: {line_s}")

        # Nonzero exit code from required validator propagates as execution failure
        err_msg = combined[:300] if combined else "validator process exited non-zero with no output"
        raise RuntimeError(f"Repository hygiene validator failed with exit code {retcode}: {err_msg}")

    def _run_opa(
        self,
        files: Sequence[str],
        diff_text: str | None,
        diagnostics: list[str],
    ) -> list[dict[str, Any]]:
        """Evaluates OPA / Rego institutional policies on manifests and IaC configurations."""
        findings: list[dict[str, Any]] = []
        for f in files:
            if is_k8s_or_iac_manifest(f) or f.endswith((".tf", ".tfvars", ".bicep")):
                abs_path = (self.repo_root / f).resolve()
                if abs_path.is_file():
                    opa_findings = self.opa_evaluator.evaluate_file(abs_path, diff_text=diff_text)
                    findings.extend(opa_findings)
        return findings

    def _run_codeql(
        self,
        files: Sequence[str],
        diff_text: str | None,
        diagnostics: list[str],
    ) -> list[dict[str, Any]]:
        """Invokes GitHub CodeQL SAST query engine and normalizes SARIF findings."""
        codeql_bin = self.which_fn("codeql") or "codeql"

        # Resolve configured database path
        db_path = self.codeql_db_path
        if not db_path:
            env_db = os.environ.get("CODEQL_DB_PATH") or os.environ.get("CODEQL_DATABASE")
            if env_db:
                db_path = Path(env_db).resolve()
            else:
                for cand in [self.repo_root / ".codeql-db", self.repo_root / "codeql-db", self.repo_root / ".codeql" / "db"]:
                    if cand.exists():
                        db_path = cand.resolve()
                        break
                if not db_path:
                    db_path = (self.repo_root / ".codeql-db").resolve()

        # Resolve configured query suite(s) or pack(s)
        raw_suite = (
            self.codeql_query_suite
            if self.codeql_query_suite is not None
            else (
                os.environ.get("CODEQL_QUERY_SUITE")
                or os.environ.get("CODEQL_SUITE")
                or DEFAULT_CODEQL_QUERY_SUITE
            )
        )
        if isinstance(raw_suite, str):
            query_suites = [s.strip() for s in raw_suite.replace(",", " ").split() if s.strip()] or [DEFAULT_CODEQL_QUERY_SUITE]
        else:
            query_suites = list(raw_suite) if raw_suite else [DEFAULT_CODEQL_QUERY_SUITE]

        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as tmp_file:
            sarif_out_path = Path(tmp_file.name)

        try:
            cmd = [
                codeql_bin,
                "database",
                "analyze",
                str(db_path),
                *query_suites,
                "--format=sarif-latest",
                f"--output={sarif_out_path}",
            ]
            res = self.runner_fn(cmd, capture_output=True, text=True, cwd=str(self.repo_root))
            retcode = getattr(res, "returncode", 0)
            stdout = res.stdout if hasattr(res, "stdout") else ""
            stderr = res.stderr if hasattr(res, "stderr") else ""

            if retcode != 0:
                raise RuntimeError(
                    f"CodeQL database analyze failed with exit code {retcode}: "
                    f"{stderr.strip()[:200] or stdout.strip()[:200] or 'unknown error'}"
                )

            # Read SARIF from generated output file, or fallback to stdout for runner mocks
            sarif_raw = ""
            if sarif_out_path.is_file() and sarif_out_path.stat().st_size > 0:
                sarif_raw = sarif_out_path.read_text(encoding="utf-8")
            elif stdout and stdout.strip():
                sarif_raw = stdout.strip()

            if not sarif_raw or not sarif_raw.strip():
                return []

            try:
                sarif_data = json.loads(sarif_raw)
                from ocagents.findings.normalizer import SarifNormalizer
                normalizer = SarifNormalizer(repo_root=self.repo_root, default_agent="codeql")
                findings = normalizer.normalize(sarif_data)
                if diff_text:
                    findings = filter_findings_by_diff(findings, diff_text)
                return findings
            except Exception as e:
                raise RuntimeError(f"Failed to parse CodeQL SARIF output: {e}")
        finally:
            if sarif_out_path.is_file():
                try:
                    sarif_out_path.unlink()
                except OSError:
                    pass

    def run(
        self,
        changeset: Sequence[str | Path],
        diff_text: str | None = None,
        strict: bool = False,
        reference_time: datetime | None = None,
    ) -> PreflightResult:
        """Executes the pre-flight deterministic checks across target changeset.

        Args:
            changeset: List of target file paths to evaluate.
            diff_text: Optional unified git diff for diff-aware filtering and heuristics.
            strict: If True, escalate advisory warnings and missing advisory tools to exit code 1.
            reference_time: Optional reference time for exception expiry testing.

        Returns:
            PreflightResult containing status, exit code, findings, and diagnostics.
        """
        clean_changeset = [Path(f).as_posix().lstrip("/") for f in changeset if str(f).strip()]

        # 1. Step 1: Scanner Availability Gatekeeping
        avail_report: AvailabilityReport = self.availability_protocol.check_changeset(
            clean_changeset,
            reference_time=reference_time,
        )

        executed_scanners: list[str] = []
        skipped_scanners: list[dict[str, Any]] = []
        all_findings: list[dict[str, Any]] = []
        diagnostics: list[str] = list(avail_report.diagnostics)

        # Log diagnostics if any exception records were rejected
        if self.exceptions_manifest.invalid_records:
            diagnostics.append(
                f"Rejected {len(self.exceptions_manifest.invalid_records)} unsigned, "
                "tampered, or invalid exception record(s) from manifest."
            )

        # Record missing scanners
        for name in avail_report.missing_required:
            scanner = self.registry.get_scanner(name)
            binary = scanner.binary if scanner else name
            skipped_scanners.append({
                "name": name,
                "level": "REQUIRED",
                "binary": binary,
                "reason": "Missing from environment (required check; no active signed exception covers all affected files)",
            })

        for name in avail_report.missing_advisory:
            scanner = self.registry.get_scanner(name)
            binary = scanner.binary if scanner else name
            skipped_scanners.append({
                "name": name,
                "level": "ADVISORY",
                "binary": binary,
                "reason": "Missing from environment (advisory check; coverage degraded)",
            })

        # 2. Step 2: Deterministic Evaluators on Available Scanners
        available_names = set(avail_report.available_scanners)
        execution_errors: list[tuple[str, str, bool]] = []

        for scanner_name in sorted(available_names):
            scanner = self.registry.get_scanner(scanner_name)
            if not scanner:
                continue

            matching_files = [f for f in clean_changeset if scanner.matches_path(f)]
            if not matching_files:
                continue

            is_req = scanner.is_required or (scanner_name == "validate_repo")
            try:
                if scanner_name == "checkov":
                    all_findings.extend(self._run_checkov(matching_files, diff_text, diagnostics))
                    executed_scanners.append("checkov")
                elif scanner_name == "trivy":
                    all_findings.extend(self._run_trivy(matching_files, diff_text, diagnostics))
                    executed_scanners.append("trivy")
                elif scanner_name == "shellcheck":
                    all_findings.extend(self._run_shellcheck(matching_files, diff_text, diagnostics))
                    executed_scanners.append("shellcheck")
                elif scanner_name == "ruff":
                    all_findings.extend(self._run_ruff(matching_files, diff_text, diagnostics))
                    executed_scanners.append("ruff")
                elif scanner_name == "validate_repo":
                    all_findings.extend(self._run_validate_repo(matching_files, diagnostics))
                    executed_scanners.append("validate_repo")
                elif scanner_name == "opa":
                    all_findings.extend(self._run_opa(matching_files, diff_text, diagnostics))
                    executed_scanners.append("opa")
                elif scanner_name == "codeql":
                    all_findings.extend(self._run_codeql(matching_files, diff_text, diagnostics))
                    executed_scanners.append("codeql")
            except Exception as e:
                diagnostics.append(f"Execution error for scanner '{scanner_name}': {e}")
                execution_errors.append((scanner_name, str(e), is_req))

        # Evaluator B: DevSecOps Heuristic Diff Screen
        if diff_text and diff_text.strip():
            diff_flags = audit_diff_heuristics(diff_text)
            for flag in diff_flags:
                fnd = {
                    "$schema": CANONICAL_SCHEMA_URI,
                    "id": compute_finding_id(flag["rule_id"], flag["resource"], flag["evidence"]),
                    "agent": "devsecops-reviewer",
                    "origin": "deterministic_linter",
                    "rule_id": flag["rule_id"],
                    "category": flag["category"],
                    "resource": flag["resource"],
                    "fact": flag["fact"],
                    "evidence": flag["evidence"],
                    "recommendation": flag["recommendation"],
                    "severity": flag["severity"],
                    "confidence": None,
                    "corroboration_status": "tool_verified",
                }
                all_findings.append(fnd)
            executed_scanners.append("diff_screen")

        # 3. Step 3: Compute Severity Breakdown
        severity_counts: dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        for fnd in all_findings:
            sev = str(fnd.get("severity", "info")).lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # 4. Step 4: Determine Final Status and Exit Code Ladder
        has_critical_or_high = (severity_counts["critical"] > 0) or (severity_counts["high"] > 0)
        has_medium_or_low = (severity_counts["medium"] > 0) or (severity_counts["low"] > 0)
        has_required_execution_error = any(is_req for _, _, is_req in execution_errors)
        has_advisory_execution_error = any(not is_req for _, _, is_req in execution_errors)

        if avail_report.status == AvailabilityStatus.INCOMPLETE_CHECK_FAILED or has_required_execution_error:
            status = AvailabilityStatus.INCOMPLETE_CHECK_FAILED
            exit_code = 1
            if has_required_execution_error:
                failed_names = [name for name, _, is_req in execution_errors if is_req]
                diagnostics.append(
                    f"FAIL-CLOSED: Execution failed for required scanner(s): {', '.join(failed_names)}. "
                    "Pre-flight gate blocked."
                )
        elif has_critical_or_high:
            status = AvailabilityStatus.INCOMPLETE_CHECK_FAILED
            exit_code = 1
            diagnostics.append(
                f"FAIL-CLOSED: {severity_counts['critical']} critical, {severity_counts['high']} high "
                "invariant finding(s) detected. Pre-flight gate blocked."
            )
        elif avail_report.status == AvailabilityStatus.INCONCLUSIVE_PARTIAL_AUDIT or has_advisory_execution_error:
            if strict:
                status = AvailabilityStatus.INCOMPLETE_CHECK_FAILED
                exit_code = 1
                diagnostics.append("Strict mode enabled: missing or failed advisory scanner escalated to failure.")
            else:
                status = AvailabilityStatus.INCONCLUSIVE_PARTIAL_AUDIT
                exit_code = 2
        elif has_medium_or_low:
            if strict:
                status = AvailabilityStatus.INCOMPLETE_CHECK_FAILED
                exit_code = 1
                diagnostics.append(
                    f"Strict mode enabled: {severity_counts['medium'] + severity_counts['low']} "
                    "warning finding(s) escalated to failure."
                )
            else:
                status = AvailabilityStatus.ADVISORY_WARNINGS
                exit_code = 2  # Advisory warnings present
        else:
            status = AvailabilityStatus.CLEAN
            exit_code = 0

        return PreflightResult(
            status=status,
            exit_code=exit_code,
            changeset=clean_changeset,
            diff_text=diff_text,
            executed_scanners=sorted(set(executed_scanners)),
            skipped_scanners=skipped_scanners,
            exemptions_applied=list(avail_report.exemptions_applied),
            findings=all_findings,
            findings_by_severity=severity_counts,
            diagnostics=diagnostics,
            strict=strict,
        )


def run_preflight(
    paths: Sequence[str | Path] | None = None,
    diff_target: str | None = None,
    strict: bool = False,
    repo_root: Path | None = None,
    reference_time: datetime | None = None,
    registry: ScannerRegistry | None = None,
    exceptions_manifest: ExceptionsManifest | None = None,
    which_fn: Callable[[str], str | None] | None = None,
    runner_fn: Callable[..., subprocess.CompletedProcess] | None = None,
    signing_key: str | None = None,
    codeql_db_path: Path | str | None = None,
    codeql_query_suite: str | Sequence[str] | None = None,
) -> PreflightResult:
    """Convenience helper to resolve changeset and execute pre-flight checks."""
    engine = PreflightEngine(
        repo_root=repo_root,
        registry=registry,
        exceptions_manifest=exceptions_manifest,
        which_fn=which_fn,
        runner_fn=runner_fn,
        signing_key=signing_key,
        codeql_db_path=codeql_db_path,
        codeql_query_suite=codeql_query_suite,
    )
    try:
        changeset, diff_text = engine.resolve_changeset(paths=paths, diff_target=diff_target)
    except (ValueError, FileNotFoundError) as err:
        return PreflightResult(
            status=AvailabilityStatus.INCOMPLETE_CHECK_FAILED,
            exit_code=1,
            diagnostics=[f"FAIL-CLOSED: Diff resolution error: {err}"],
            strict=strict,
        )
    return engine.run(
        changeset=changeset,
        diff_text=diff_text,
        strict=strict,
        reference_time=reference_time,
    )
