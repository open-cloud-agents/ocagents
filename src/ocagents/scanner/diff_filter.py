"""Unified Diff Parser and Finding Filter for Open Cloud Agents.

Parses unified diff outputs from Git and filters findings so only defects
intersecting modified lines in an active pull request diff are retained.
"""

from __future__ import annotations

import re
from typing import Any

HUNK_HEADER_PATTERN = re.compile(
    r"^@@\s+-[0-9]+(?:,[0-9]+)?\s+\+([0-9]+)(?:,([0-9]+))?\s+@@"
)
EVIDENCE_LOCATION_PATTERN = re.compile(
    r"^(?:diff|repo):([a-zA-Z0-9_./-]+)#L([0-9]+)(?:-L([0-9]+))?$"
)


def parse_diff_modified_lines(diff_text: str) -> dict[str, set[int]]:
    """Parses a unified diff and extracts newly added line numbers for each file.

    Returns:
        dict[str, set[int]]: Mapping of normalized relative file path to set of modified lines.
    """
    modified_by_file: dict[str, set[int]] = {}
    current_file: str | None = None
    in_hunk = False
    current_line_num = 0

    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            parts = line.split(" ")
            if len(parts) >= 4:
                b_path = parts[3]
                current_file = b_path[2:] if b_path.startswith("b/") else b_path
                current_file = current_file.lstrip("/").replace("\\", "/")
                if current_file not in modified_by_file:
                    modified_by_file[current_file] = set()
                in_hunk = False
            continue

        if current_file is None:
            continue

        if line.startswith("--- ") or line.startswith("+++ "):
            in_hunk = False
            continue

        hunk_match = HUNK_HEADER_PATTERN.match(line)
        if hunk_match:
            in_hunk = True
            current_line_num = int(hunk_match.group(1))
            continue

        if in_hunk:
            if line.startswith("+"):
                modified_by_file[current_file].add(current_line_num)
                current_line_num += 1
            elif line.startswith(" "):
                current_line_num += 1
            elif line.startswith("-"):
                # Deletion from old side does not advance new side counter
                pass
            elif line.startswith("\\"):
                pass

    return modified_by_file


def is_finding_in_diff(
    finding: dict[str, Any],
    modified_lines_by_file: dict[str, set[int]],
) -> bool:
    """Evaluates whether a finding's evidence line range intersects the modified lines in diff."""
    evidence = finding.get("evidence", "")
    match = EVIDENCE_LOCATION_PATTERN.match(evidence)
    if not match:
        # Non-file or cloud: locators do not intersect file diffs
        return False

    rel_path, start_s, end_s = match.groups()
    rel_path = rel_path.lstrip("/").replace("\\", "/")
    start_line = int(start_s)
    end_line = int(end_s) if end_s else start_line

    if rel_path not in modified_lines_by_file:
        return False

    file_modified_lines = modified_lines_by_file[rel_path]
    finding_range = set(range(start_line, end_line + 1))

    return bool(finding_range & file_modified_lines)


def filter_findings_by_diff(
    findings: list[dict[str, Any]],
    diff_text: str,
    convert_to_diff_scheme: bool = False,
) -> list[dict[str, Any]]:
    """Filters findings to only those that intersect modified diff lines.

    Args:
        findings: List of canonical finding dictionaries.
        diff_text: Unified git diff string.
        convert_to_diff_scheme: If True, mutates evidence from 'repo:' to 'diff:'
            for retained findings.

    Returns:
        list[dict[str, Any]]: Retained findings intersecting modified diff hunks.
    """
    if not diff_text or not diff_text.strip():
        return []

    modified_by_file = parse_diff_modified_lines(diff_text)
    retained: list[dict[str, Any]] = []

    for f in findings:
        if is_finding_in_diff(f, modified_by_file):
            if convert_to_diff_scheme:
                ev = f.get("evidence", "")
                if ev.startswith("repo:"):
                    updated_f = dict(f)
                    updated_f["evidence"] = "diff:" + ev[5:]
                    retained.append(updated_f)
                    continue
            retained.append(f)

    return retained
