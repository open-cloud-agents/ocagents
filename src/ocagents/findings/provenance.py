"""Provenance and Evidence Anchor Corroboration Engine for Open Cloud Agents.

Verifies rule catalog existence and corroborates multi-target evidence locators
(diff:, repo:, cloud:).
"""

from __future__ import annotations

import re
from pathlib import Path

DIFF_LOCATOR_PATTERN = re.compile(r"^diff:([a-zA-Z0-9_./-]+)#L([0-9]+)(?:-L([0-9]+))?$")
REPO_LOCATOR_PATTERN = re.compile(r"^repo:([a-zA-Z0-9_./-]+)#L([0-9]+)(?:-L([0-9]+))?$")
CLOUD_LOCATOR_PATTERN = re.compile(r"^cloud:([a-z0-9_-]+):(.+)$")

HUNK_HEADER_PATTERN = re.compile(r"^@@\s+-[0-9]+(?:,[0-9]+)?\s+\+([0-9]+)(?:,([0-9]+))?\s+@@")


def resolve_default_repo_root(
    explicit_root: Path | str | None = None,
    target_path: Path | str | None = None,
    asset_root: Path | None = None,
) -> Path:
    """Resolve the target repository root.

    Order of precedence:
    1. Explicit override passed by user (--repo-root).
    2. Check if Path.cwd() has repository structure (.git, rules/, schemas/).
    3. Check target_path directory and ancestors for .git.
    4. Check cwd ancestors for .git.
    5. Fall back to asset_root or Path.cwd().
    """
    if explicit_root:
        return Path(explicit_root).resolve()

    cwd = Path.cwd().resolve()
    if (cwd / ".git").exists() or (cwd / "rules").is_dir() or (cwd / "schemas").is_dir():
        return cwd

    # Check target_path directory and ancestors for .git
    candidate = Path(target_path).resolve() if target_path else cwd
    if candidate.is_file():
        candidate = candidate.parent
    for parent in [candidate, *candidate.parents]:
        if (parent / ".git").exists():
            return parent

    # Check cwd ancestors for .git
    for parent in cwd.parents:
        if (parent / ".git").exists():
            return parent

    return asset_root.resolve() if asset_root else cwd


class ProvenanceVerifier:
    """Verifies rule catalog integrity and corroborates evidence anchors."""

    def __init__(self, repo_root: Path | None = None) -> None:
        self.repo_root = (repo_root or resolve_default_repo_root()).resolve()

    def verify_rule(self, rule_id: str) -> tuple[bool, str | None]:
        """Verify that rule_id exists in the repository rules catalog."""
        # Strip internal section anchors e.g. #L1-L10
        base_rule = rule_id.split("#", 1)[0].strip()

        # Reject path traversal
        if ".." in Path(base_rule).parts:
            return (
                False,
                f"Rule specification '{rule_id}' contains path traversal (resolves outside repository root).",
            )

        rule_path = (self.repo_root / base_rule).resolve()
        try:
            rule_path.relative_to(self.repo_root)
        except ValueError:
            return (
                False,
                f"Rule specification '{rule_id}' resolves outside repository root.",
            )

        if not rule_path.is_file():
            return (
                False,
                f"Rule specification '{rule_id}' not found in rules catalog at '{base_rule}'.",
            )

        return True, None

    def verify_evidence(
        self, evidence: str, diff_text: str | None = None
    ) -> tuple[bool, str | None]:
        """Corroborate an evidence locator against repo files or diff hunks."""
        # Case 1: diff:<relative_path>#L<start>[-L<end>]
        diff_match = DIFF_LOCATOR_PATTERN.match(evidence)
        if diff_match:
            rel_path, start_s, end_s = diff_match.groups()
            start_line = int(start_s)
            end_line = int(end_s) if end_s else start_line

            if start_line > end_line:
                return False, f"Invalid diff line range: start line {start_line} > end line {end_line}."

            if ".." in Path(rel_path).parts:
                return (
                    False,
                    f"Diff anchor file '{rel_path}' contains path traversal (resolves outside repository root).",
                )

            if diff_text is not None:
                modified_lines = self._extract_modified_lines_from_diff(diff_text, rel_path)
                if modified_lines is None:
                    return (
                        False,
                        f"Diff evidence file '{rel_path}' not found in active pull request diff.",
                    )
                # Verify that [start_line, end_line] intersects modified lines
                requested_range = set(range(start_line, end_line + 1))
                if not (requested_range & modified_lines):
                    return (
                        False,
                        f"Diff line range L{start_line}-L{end_line} in '{rel_path}' does not intersect modified diff lines.",
                    )
                return True, None

            # Fallback when diff_text is not explicitly supplied: verify file exists on filesystem
            target_file = (self.repo_root / rel_path).resolve()
            try:
                target_file.relative_to(self.repo_root)
            except ValueError:
                return (
                    False,
                    f"Diff anchor file '{rel_path}' resolves outside repository root.",
                )

            if not target_file.is_file():
                return False, f"Diff anchor file '{rel_path}' not found in workspace tree."

            line_count = self._count_lines(target_file)
            if start_line < 1 or end_line > line_count:
                return (
                    False,
                    f"Diff line range L{start_line}-L{end_line} exceeds file line count ({line_count}) in '{rel_path}'.",
                )

            return True, None

        # Case 2: repo:<relative_path>#L<start>[-L<end>]
        repo_match = REPO_LOCATOR_PATTERN.match(evidence)
        if repo_match:
            rel_path, start_s, end_s = repo_match.groups()
            start_line = int(start_s)
            end_line = int(end_s) if end_s else start_line

            if start_line > end_line:
                return False, f"Invalid repository line range: start line {start_line} > end line {end_line}."

            if ".." in Path(rel_path).parts:
                return (
                    False,
                    f"Repository evidence file '{rel_path}' contains path traversal (resolves outside repository root).",
                )

            target_file = (self.repo_root / rel_path).resolve()
            try:
                target_file.relative_to(self.repo_root)
            except ValueError:
                return (
                    False,
                    f"Repository evidence file '{rel_path}' resolves outside repository root.",
                )

            if not target_file.is_file():
                return False, f"Repository evidence file '{rel_path}' not found in workspace tree."

            line_count = self._count_lines(target_file)
            if start_line < 1 or end_line > line_count:
                return (
                    False,
                    f"Repository line range L{start_line}-L{end_line} exceeds file line count ({line_count}) in '{rel_path}'.",
                )

            return True, None

        # Case 3: cloud:<provider>:<resource_identifier>
        cloud_match = CLOUD_LOCATOR_PATTERN.match(evidence)
        if cloud_match:
            provider, resource_id = cloud_match.groups()
            if provider not in ("azure", "aws", "gcp"):
                return False, f"Unsupported cloud provider '{provider}' in evidence locator '{evidence}'."
            if not resource_id.strip():
                return False, f"Empty cloud resource identifier in evidence locator '{evidence}'."

            # Live cloud API authentication is deferred as a v2.0 integration; syntax is valid.
            return True, None

        return False, f"Evidence locator '{evidence}' does not match any supported locator scheme (diff:, repo:, cloud:)."

    def _count_lines(self, file_path: Path) -> int:
        try:
            with file_path.open("r", encoding="utf-8", errors="replace") as f:
                return sum(1 for _ in f)
        except Exception:
            return 0

    def _extract_modified_lines_from_diff(
        self, diff_text: str, target_rel_path: str
    ) -> set[int] | None:
        """Parse unified diff text and extract modified (added) line numbers for target_rel_path."""
        current_file: str | None = None
        modified_lines: set[int] = set()
        file_found = False
        in_target_hunk = False
        current_line_num = 0

        for line in diff_text.splitlines():
            if line.startswith("diff --git "):
                parts = line.split(" ")
                if len(parts) >= 4:
                    b_path = parts[3]
                    current_file = b_path[2:] if b_path.startswith("b/") else b_path
                    if current_file == target_rel_path:
                        file_found = True
                        in_target_hunk = False
                    elif file_found:
                        # Left target file block
                        break
                continue

            if not file_found:
                continue

            if line.startswith("--- ") or line.startswith("+++ "):
                in_target_hunk = False
                continue

            hunk_match = HUNK_HEADER_PATTERN.match(line)
            if hunk_match:
                in_target_hunk = True
                current_line_num = int(hunk_match.group(1))
                continue

            if in_target_hunk:
                if line.startswith("+"):
                    modified_lines.add(current_line_num)
                    current_line_num += 1
                elif line.startswith(" "):
                    current_line_num += 1
                elif line.startswith("-"):
                    # Deletion from old file; does not advance new file line counter
                    pass
                elif line.startswith("\\"):
                    # "\ No newline at end of file"
                    pass

        return modified_lines if file_found else None
