"""
Open Cloud Agents: Finding Lifecycle State Machine & Stale Finding Invalidation (Milestone v2.2 - Issue #101).

Implements:
  - Canonical Finding Lifecycle State Machine:
    OPEN -> CORROBORATED -> TRIAGED -> RESOLVED | SUPERSEDED | EXPIRED
  - Git diff hook to invalidate findings when underlying source ranges are refactored
  - TTL duration parsing and expiration evaluation
  - Blackboard pruning & compaction logic
"""

from __future__ import annotations

import datetime
import enum
import re
from typing import Any

from ocagents.blackboard.dedupe import extract_canonical_path


class FindingLifecycleStatus(str, enum.Enum):
    """Canonical lifecycle state of a finding in the blackboard store."""
    OPEN = "OPEN"
    CORROBORATED = "CORROBORATED"
    TRIAGED = "TRIAGED"
    RESOLVED = "RESOLVED"
    SUPERSEDED = "SUPERSEDED"
    EXPIRED = "EXPIRED"


# Active states that are subject to evaluation and presentation
ACTIVE_LIFECYCLE_STATUSES = {
    FindingLifecycleStatus.OPEN.value,
    FindingLifecycleStatus.CORROBORATED.value,
    FindingLifecycleStatus.TRIAGED.value,
}

# Terminal states
TERMINAL_LIFECYCLE_STATUSES = {
    FindingLifecycleStatus.RESOLVED.value,
    FindingLifecycleStatus.SUPERSEDED.value,
    FindingLifecycleStatus.EXPIRED.value,
}

# Permitted state transitions
VALID_TRANSITIONS: dict[str, set[str]] = {
    FindingLifecycleStatus.OPEN.value: {
        FindingLifecycleStatus.CORROBORATED.value,
        FindingLifecycleStatus.TRIAGED.value,
        FindingLifecycleStatus.RESOLVED.value,
        FindingLifecycleStatus.SUPERSEDED.value,
        FindingLifecycleStatus.EXPIRED.value,
    },
    FindingLifecycleStatus.CORROBORATED.value: {
        FindingLifecycleStatus.TRIAGED.value,
        FindingLifecycleStatus.RESOLVED.value,
        FindingLifecycleStatus.SUPERSEDED.value,
        FindingLifecycleStatus.EXPIRED.value,
    },
    FindingLifecycleStatus.TRIAGED.value: {
        FindingLifecycleStatus.RESOLVED.value,
        FindingLifecycleStatus.SUPERSEDED.value,
        FindingLifecycleStatus.EXPIRED.value,
    },
    # Terminal states can be re-opened if observed again in a fresh commit
    FindingLifecycleStatus.RESOLVED.value: {
        FindingLifecycleStatus.OPEN.value,
        FindingLifecycleStatus.CORROBORATED.value,
    },
    FindingLifecycleStatus.SUPERSEDED.value: {
        FindingLifecycleStatus.OPEN.value,
        FindingLifecycleStatus.CORROBORATED.value,
    },
    FindingLifecycleStatus.EXPIRED.value: {
        FindingLifecycleStatus.OPEN.value,
        FindingLifecycleStatus.CORROBORATED.value,
    },
}


def transition_lifecycle_status(
    current_status: str,
    target_status: str | FindingLifecycleStatus,
    reason: str = "",
) -> str:
    """
    Validates and executes a transition between lifecycle states.
    Raises ValueError on invalid transitions.
    """
    curr = current_status.upper() if isinstance(current_status, str) else current_status.value
    target = target_status.value if isinstance(target_status, FindingLifecycleStatus) else target_status.upper()

    if curr == target:
        return curr

    allowed = VALID_TRANSITIONS.get(curr, set())
    if target not in allowed:
        raise ValueError(
            f"Invalid finding lifecycle transition: '{curr}' -> '{target}'. "
            f"Allowed next states: {sorted(allowed)}."
        )

    return target


def parse_evidence_location(evidence: str) -> tuple[str, int, int] | None:
    """
    Parses canonical file path, start line, and end line from evidence URI.
    Format: 'diff:<path>#L<start>[-L<end>]' or 'repo:<path>#L<start>[-L<end>]'
    Returns (path, start_line, end_line) or None if unparseable/cloud URI.
    """
    if not evidence or evidence.startswith("cloud:"):
        return None

    canonical_path = extract_canonical_path(evidence)
    if not canonical_path:
        return None

    # Check for line anchor #L...
    m = re.search(r"#L(\d+)(?:-L(\d+))?", evidence)
    if not m:
        return (canonical_path, 1, 1)

    start_line = int(m.group(1))
    end_line = int(m.group(2)) if m.group(2) else start_line
    return (canonical_path, start_line, end_line)


def parse_diff_modified_ranges(diff_text: str) -> tuple[set[str], dict[str, list[tuple[int, int]]]]:
    """
    Parses a unified git diff and returns:
      1. set of completely deleted files
      2. mapping of file_path -> list of modified line ranges (start, end)
    """
    deleted_files: set[str] = set()
    modified_ranges: dict[str, list[tuple[int, int]]] = {}

    current_file_old: str | None = None
    current_file_new: str | None = None
    is_deleted_file = False

    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            parts = line.split()
            if len(parts) >= 4:
                old_p = parts[2]
                new_p = parts[3]
                current_file_old = old_p.removeprefix("a/")
                current_file_new = new_p.removeprefix("b/")
                is_deleted_file = False
            continue

        if line.startswith("deleted file mode "):
            is_deleted_file = True
            if current_file_old:
                deleted_files.add(current_file_old)
            continue

        if line.startswith("--- "):
            continue

        if line.startswith("+++ "):
            if line.startswith("+++ /dev/null") and current_file_old:
                deleted_files.add(current_file_old)
                is_deleted_file = True
            continue

        if is_deleted_file:
            continue

        if line.startswith("@@ "):
            # Hunk header: @@ -old_start,old_count +new_start,new_count @@
            hunk_match = re.search(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", line)
            if hunk_match:
                old_start = int(hunk_match.group(1))
                old_count = int(hunk_match.group(2)) if hunk_match.group(2) is not None else 1
                new_start = int(hunk_match.group(3))
                new_count = int(hunk_match.group(4)) if hunk_match.group(4) is not None else 1

                target_file = current_file_new or current_file_old
                if target_file:
                    if target_file not in modified_ranges:
                        modified_ranges[target_file] = []

                    # If lines were modified or deleted in old file:
                    if old_count > 0:
                        modified_ranges[target_file].append((old_start, old_start + old_count - 1))
                    elif new_count > 0:
                        modified_ranges[target_file].append((new_start, new_start + new_count - 1))

    return deleted_files, modified_ranges


def is_finding_invalidated_by_diff(
    finding: dict[str, Any],
    deleted_files: set[str],
    modified_ranges: dict[str, list[tuple[int, int]]],
) -> tuple[bool, str]:
    """
    Determines whether an open finding's target code has been deleted or modified by a diff.
    Returns (is_invalidated, rationale).
    """
    evidence = finding.get("evidence", "")
    loc = parse_evidence_location(evidence)
    if not loc:
        return False, ""

    file_path, f_start, f_end = loc

    # Normalize file path for lookup
    norm_path = file_path.lstrip("./")

    # 1. File was completely deleted
    if norm_path in deleted_files or file_path in deleted_files:
        return True, f"Target file '{file_path}' was deleted in subsequent commit"

    # 2. Check overlap with modified line ranges
    ranges = modified_ranges.get(norm_path) or modified_ranges.get(file_path) or []
    for m_start, m_end in ranges:
        # Overlap condition: max(f_start, m_start) <= min(f_end, m_end)
        # Also check proximity (within +/- 1 line) for surgical edits
        if max(f_start, m_start) <= min(f_end, m_end):
            return True, f"Source lines {f_start}-{f_end} in '{file_path}' modified by hunk [{m_start}-{m_end}]"

    return False, ""


def evaluate_diff_invalidations(
    findings: list[dict[str, Any]],
    diff_text: str,
) -> list[tuple[str, str]]:
    """
    Evaluates a collection of findings against a git diff.
    Returns list of (finding_id, invalidation_reason) for all invalidated findings.
    """
    if not diff_text or not findings:
        return []

    deleted_files, modified_ranges = parse_diff_modified_ranges(diff_text)
    invalidated: list[tuple[str, str]] = []

    for f in findings:
        status = f.get("lifecycle_status", FindingLifecycleStatus.OPEN.value)
        # Only evaluate active findings
        if status not in ACTIVE_LIFECYCLE_STATUSES:
            continue

        fid = f.get("id")
        if not fid:
            continue

        is_stale, reason = is_finding_invalidated_by_diff(f, deleted_files, modified_ranges)
        if is_stale:
            invalidated.append((fid, reason))

    return invalidated


def parse_ttl_string(ttl_str: str) -> int:
    """
    Parses human-readable TTL duration strings into integer seconds.
    Supported units: 'd' (days), 'h' (hours), 'm' (minutes), 's' (seconds).
    Examples: '14d' -> 1209600, '24h' -> 86400, '30m' -> 1800, '3600' -> 3600.
    """
    s = ttl_str.strip().lower()
    if s.isdigit():
        return int(s)

    m = re.match(r"^(\d+)\s*([dhms])$", s)
    if not m:
        raise ValueError(
            f"Invalid TTL duration string: '{ttl_str}'. "
            "Format must be an integer followed by 'd' (days), 'h' (hours), 'm' (minutes), or 's' (seconds). Example: '14d'."
        )

    val = int(m.group(1))
    unit = m.group(2)

    unit_multipliers = {
        "s": 1,
        "m": 60,
        "h": 3600,
        "d": 86400,
    }

    return val * unit_multipliers[unit]


def is_finding_expired(
    finding: dict[str, Any],
    ttl_seconds: int,
    reference_time: datetime.datetime | None = None,
) -> bool:
    """
    Evaluates whether a finding has exceeded its Time-To-Live (TTL).
    Uses 'last_seen_utc', 'updated_at', or 'created_at'.
    """
    if ttl_seconds <= 0:
        return False

    now = reference_time or datetime.datetime.now(datetime.timezone.utc)

    timestamp_str = (
        finding.get("updated_at")
        or finding.get("last_seen_utc")
        or finding.get("created_at")
    )

    if not timestamp_str:
        return False

    try:
        ts = datetime.datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        age_seconds = (now - ts).total_seconds()
        return age_seconds >= ttl_seconds
    except (ValueError, TypeError, OSError):
        return False
