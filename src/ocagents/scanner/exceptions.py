"""Exceptions Manifest Engine for Open Cloud Agents.

Parses and validates signed scanner and rule exceptions declared in
.ocagents/exceptions.json according to ADR-002 governance specifications.
Enforces mandatory risk ownership, business justification, strict 90-day maximum lifespan,
and automated expiry detection.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import fnmatch
import json
from pathlib import Path
from typing import Any

from ocagents.findings.provenance import resolve_default_repo_root

DEFAULT_EXCEPTIONS_PATH = Path(".ocagents/exceptions.json")
MAX_EXCEPTION_LIFESPAN_DAYS = 90
MAX_EXCEPTION_LIFESPAN_SECONDS = MAX_EXCEPTION_LIFESPAN_DAYS * 86400


def parse_iso_timestamp(ts_str: str) -> datetime:
    """Parses an ISO 8601 timestamp string into a timezone-aware UTC datetime."""
    # Normalize trailing Z to +00:00 for fromisoformat compatibility in Python 3.10
    normalized = ts_str.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


@dataclass(frozen=True)
class ExceptionRecord:
    """Represents a signed, bounded exception to a scanner or security rule."""

    rule_id: str
    resource_pattern: str
    reason: str
    risk_owner: str
    created_at: str
    expires_at: str
    signature: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def created_dt(self) -> datetime:
        return parse_iso_timestamp(self.created_at)

    @property
    def expires_dt(self) -> datetime:
        return parse_iso_timestamp(self.expires_at)

    def is_expired(self, reference_time: datetime | None = None) -> bool:
        """Evaluates whether the exception has expired relative to reference_time."""
        now = reference_time or datetime.now(timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        return now >= self.expires_dt

    def exceeds_max_lifespan(self) -> bool:
        """Enforces ADR-002 rule: exception duration cannot exceed 90 days from created_at."""
        duration_seconds = (self.expires_dt - self.created_dt).total_seconds()
        return duration_seconds > MAX_EXCEPTION_LIFESPAN_SECONDS

    def is_valid_structure(self) -> tuple[bool, str | None]:
        """Validates all mandatory fields, timestamp validity, and lifespan boundary."""
        if not self.rule_id or not self.rule_id.strip():
            return False, "Field 'rule_id' must be a non-empty string"
        if not self.resource_pattern or not self.resource_pattern.strip():
            return False, "Field 'resource_pattern' must be a non-empty string"
        if not self.reason or not self.reason.strip():
            return False, "Field 'reason' must provide a verifiable business justification"
        if not self.risk_owner or not self.risk_owner.strip():
            return False, "Field 'risk_owner' must identify an accountable maintainer or handle"

        try:
            c_dt = self.created_dt
            e_dt = self.expires_dt
        except Exception as e:
            return False, f"Invalid ISO 8601 timestamp in created_at or expires_at: {e}"

        if e_dt <= c_dt:
            return False, f"'expires_at' ({self.expires_at}) must be after 'created_at' ({self.created_at})"

        if self.exceeds_max_lifespan():
            return (
                False,
                f"Exception lifespan exceeds canonical maximum limit of {MAX_EXCEPTION_LIFESPAN_DAYS} days",
            )

        return True, None

    def matches(self, rule_or_scanner: str, resource_path: str) -> bool:
        """Evaluates whether this exception applies to the target rule/scanner and file path."""
        # Normalize paths and identifiers
        target_rule = rule_or_scanner.strip().lower()
        my_rule = self.rule_id.strip().lower()

        rule_match = (
            my_rule == "*"
            or my_rule == target_rule
            or fnmatch.fnmatch(target_rule, my_rule)
            or my_rule in target_rule
        )
        if not rule_match:
            return False

        norm_resource = resource_path.strip().lstrip("/").replace("\\", "/")
        norm_pattern = self.resource_pattern.strip().lstrip("/").replace("\\", "/")

        if norm_pattern in ("*", "**"):
            return True

        if fnmatch.fnmatch(norm_resource, norm_pattern):
            return True

        # Support directory prefix match
        if norm_pattern.endswith("/") and norm_resource.startswith(norm_pattern):
            return True

        return False


class ExceptionsManifest:
    """Loads, validates, and queries repository exceptions."""

    def __init__(
        self,
        records: list[ExceptionRecord] | None = None,
        manifest_path: Path | None = None,
        repo_root: Path | None = None,
    ) -> None:
        self.repo_root = (repo_root or resolve_default_repo_root()).resolve()
        self.manifest_path = (
            Path(manifest_path).resolve()
            if manifest_path
            else (self.repo_root / DEFAULT_EXCEPTIONS_PATH)
        )
        self._records: list[ExceptionRecord] = []
        self._invalid_records: list[tuple[dict[str, Any], str]] = []

        if records is not None:
            for rec in records:
                ok, err = rec.is_valid_structure()
                if ok:
                    self._records.append(rec)
                else:
                    self._invalid_records.append((rec.__dict__, err or "Invalid structure"))
        elif self.manifest_path.is_file():
            self._load_from_disk(self.manifest_path)

    @classmethod
    def from_json(
        cls,
        json_data: str | dict[str, Any] | list[dict[str, Any]],
        repo_root: Path | None = None,
    ) -> ExceptionsManifest:
        """Instantiates ExceptionsManifest from an in-memory JSON payload or dictionary."""
        manifest = cls(records=[], repo_root=repo_root)
        manifest._parse_data(json_data)
        return manifest

    def _load_from_disk(self, path: Path) -> None:
        """Parses manifest JSON file from disk."""
        try:
            content = path.read_text(encoding="utf-8")
            data = json.loads(content)
            self._parse_data(data)
        except Exception as e:
            self._invalid_records.append(({"source_file": str(path)}, f"Failed to parse JSON: {e}"))

    def _parse_data(self, data: Any) -> None:
        """Parses array or dictionary containing exceptions."""
        items: list[Any] = []
        if isinstance(data, dict):
            items = data.get("exceptions", [])
        elif isinstance(data, list):
            items = data
        else:
            self._invalid_records.append(({"raw": str(data)}, "Payload must be a dict or list"))
            return

        for item in items:
            if not isinstance(item, dict):
                self._invalid_records.append(({"raw": str(item)}, "Exception item must be a JSON object"))
                continue

            rec = ExceptionRecord(
                rule_id=str(item.get("rule_id", "")),
                resource_pattern=str(item.get("resource_pattern", "")),
                reason=str(item.get("reason", "")),
                risk_owner=str(item.get("risk_owner", "")),
                created_at=str(item.get("created_at", "")),
                expires_at=str(item.get("expires_at", "")),
                signature=item.get("signature"),
                metadata=item.get("metadata") or {},
            )
            ok, err = rec.is_valid_structure()
            if ok:
                self._records.append(rec)
            else:
                self._invalid_records.append((item, err or "Invalid exception structure"))

    @property
    def total_count(self) -> int:
        return len(self._records)

    @property
    def invalid_records(self) -> list[tuple[dict[str, Any], str]]:
        return list(self._invalid_records)

    def active_exceptions(self, reference_time: datetime | None = None) -> list[ExceptionRecord]:
        """Returns all structurally valid exceptions that have not yet expired."""
        return [r for r in self._records if not r.is_expired(reference_time)]

    def expired_exceptions(self, reference_time: datetime | None = None) -> list[ExceptionRecord]:
        """Returns all exceptions whose expires_at timestamp is in the past."""
        return [r for r in self._records if r.is_expired(reference_time)]

    def find_matching_exception(
        self,
        rule_or_scanner: str,
        resource_path: str,
        reference_time: datetime | None = None,
    ) -> ExceptionRecord | None:
        """Finds the first active, unexpired exception matching the target rule and resource."""
        for rec in self.active_exceptions(reference_time=reference_time):
            if rec.matches(rule_or_scanner, resource_path):
                return rec
        return None

    def is_exempt(
        self,
        rule_or_scanner: str,
        resource_path: str,
        reference_time: datetime | None = None,
    ) -> bool:
        """Convenience predicate: returns True if an active, unexpired exception matches."""
        return self.find_matching_exception(rule_or_scanner, resource_path, reference_time) is not None
