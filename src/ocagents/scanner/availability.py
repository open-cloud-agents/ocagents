"""Fail-Closed Scanner Availability Protocol for Open Cloud Agents.

Enforces strict pre-flight gatekeeping in accordance with ADR-002:
- Missing required scanner -> halt immediately before LLM execution, emit INCOMPLETE_CHECK_FAILED (exit code 1).
- Missing advisory scanner -> emit SKIPPED_SCANNER_UNAVAILABLE, mark run INCONCLUSIVE_PARTIAL_AUDIT (exit code 2).
- Zero false-clean invariant: uninspected files or unavailable scanners never yield a clean verdict unless exempt.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
import shutil
from typing import Any, Callable, Iterable, Sequence

from ocagents.findings.provenance import resolve_default_repo_root
from ocagents.scanner.exceptions import ExceptionsManifest
from ocagents.scanner.registry import (
    RequirementLevel,
    ScannerDefinition,
    ScannerRegistry,
    get_default_registry,
)


class AvailabilityStatus(str, Enum):
    """Execution status resulting from fail-closed scanner availability protocol."""
    CLEAN = "CLEAN"
    INCONCLUSIVE_PARTIAL_AUDIT = "INCONCLUSIVE_PARTIAL_AUDIT"
    INCOMPLETE_CHECK_FAILED = "INCOMPLETE_CHECK_FAILED"
    ADVISORY_WARNINGS = "ADVISORY_WARNINGS"


@dataclass(frozen=True)
class AvailabilityReport:
    """Structured report produced by ScannerAvailabilityProtocol."""

    status: AvailabilityStatus
    exit_code: int
    missing_required: tuple[str, ...] = field(default_factory=tuple)
    missing_advisory: tuple[str, ...] = field(default_factory=tuple)
    available_scanners: tuple[str, ...] = field(default_factory=tuple)
    exemptions_applied: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    diagnostics: tuple[str, ...] = field(default_factory=tuple)

    @property
    def is_clean(self) -> bool:
        return self.status == AvailabilityStatus.CLEAN

    @property
    def is_failed(self) -> bool:
        return self.status == AvailabilityStatus.INCOMPLETE_CHECK_FAILED

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
        """Returns JSON-serializable dictionary representation of the availability report."""
        return {
            "status": self.status.value,
            "exit_code": self.exit_code,
            "missing_required": list(self.missing_required),
            "missing_advisory": list(self.missing_advisory),
            "available_scanners": list(self.available_scanners),
            "exemptions_applied": list(self.exemptions_applied),
            "diagnostics": list(self.diagnostics),
        }


class ScannerAvailabilityProtocol:
    """
    Evaluates required and advisory static analysis tools against an active changeset.
    Enforces fail-closed outcomes when mandatory scanners are absent.
    """

    def __init__(
        self,
        registry: ScannerRegistry | None = None,
        exceptions_manifest: ExceptionsManifest | None = None,
        which_fn: Callable[[str], str | None] | None = None,
        repo_root: Path | None = None,
    ) -> None:
        self.repo_root = (repo_root or resolve_default_repo_root()).resolve()
        self.registry = registry or get_default_registry()
        self.exceptions_manifest = (
            exceptions_manifest
            if exceptions_manifest is not None
            else ExceptionsManifest(repo_root=self.repo_root)
        )
        self._which_fn = which_fn or shutil.which

    def is_scanner_available(self, scanner: ScannerDefinition) -> bool:
        """Determines whether the specified scanner binary or script is present and executable."""
        cmd = scanner.binary
        # Special-case built-in python scripts
        if cmd.endswith(".py") or "/" in cmd:
            script_path = (self.repo_root / cmd).resolve()
            if script_path.is_file():
                return True

        return self._which_fn(cmd) is not None

    def check_changeset(
        self,
        files: Iterable[str | Path],
        reference_time: datetime | None = None,
    ) -> AvailabilityReport:
        """
        Evaluates tool availability for all files in the changeset.
        Returns AvailabilityReport with fail-closed status and exit code.
        """
        file_list = [Path(f).as_posix().lstrip("/") for f in files if str(f).strip()]
        if not file_list:
            return AvailabilityReport(
                status=AvailabilityStatus.CLEAN,
                exit_code=0,
                diagnostics=("Changeset is empty; no static scanners required.",),
            )

        changeset_mapping = self.registry.get_scanners_for_changeset(file_list)

        # Collect unique scanners mapped to any file in the changeset
        scanners_needed: dict[str, ScannerDefinition] = {}
        files_by_scanner: dict[str, list[str]] = {}

        for file_path, scanners in changeset_mapping.items():
            for s in scanners:
                key = s.name.lower()
                scanners_needed[key] = s
                if key not in files_by_scanner:
                    files_by_scanner[key] = []
                files_by_scanner[key].append(file_path)

        missing_required: list[str] = []
        missing_advisory: list[str] = []
        available: list[str] = []
        exemptions: list[dict[str, Any]] = []
        diagnostics: list[str] = []

        for name_key, scanner in sorted(scanners_needed.items(), key=lambda x: x[1].name):
            is_present = self.is_scanner_available(scanner)
            req_files = files_by_scanner.get(name_key, [])

            if is_present:
                available.append(scanner.name)
                continue

            # Scanner is missing from environment. Check if all target files are exempt.
            unexempt_files: list[str] = []
            for f in req_files:
                exempt_rec = self.exceptions_manifest.find_matching_exception(
                    rule_or_scanner=scanner.name,
                    resource_path=f,
                    reference_time=reference_time,
                )
                if not exempt_rec:
                    exempt_rec = self.exceptions_manifest.find_matching_exception(
                        rule_or_scanner=scanner.category.value,
                        resource_path=f,
                        reference_time=reference_time,
                    )

                if exempt_rec:
                    exemptions.append({
                        "scanner": scanner.name,
                        "resource": f,
                        "rule_id": exempt_rec.rule_id,
                        "risk_owner": exempt_rec.risk_owner,
                        "reason": exempt_rec.reason,
                        "expires_at": exempt_rec.expires_at,
                    })
                    diagnostics.append(
                        f"Exemption matched: rule '{exempt_rec.rule_id}' granted for scanner '{scanner.name}' on resource '{f}' "
                        f"(owner: {exempt_rec.risk_owner}, expires: {exempt_rec.expires_at})."
                    )
                else:
                    unexempt_files.append(f)
                    diagnostics.append(
                        f"Resource denied / unexempt: '{f}' requires missing scanner '{scanner.name}' ({scanner.binary}) with no active exception."
                    )

            if not unexempt_files:
                # Fully covered by active valid exceptions
                diagnostics.append(
                    f"Scanner '{scanner.name}' is missing but all {len(req_files)} affected files have active signed exceptions."
                )
                continue

            # Scanner is missing and NOT exempt
            if scanner.is_required:
                missing_required.append(scanner.name)
                diagnostics.append(
                    f"REQUIRED scanner '{scanner.name}' (binary '{scanner.binary}') is missing from environment. "
                    f"Required by {len(unexempt_files)} file(s): {', '.join(unexempt_files[:3])}"
                    + ("..." if len(unexempt_files) > 3 else "")
                )
            else:
                missing_advisory.append(scanner.name)
                diagnostics.append(
                    f"ADVISORY scanner '{scanner.name}' (binary '{scanner.binary}') is missing from environment. "
                    f"Applicable to {len(unexempt_files)} file(s): {', '.join(unexempt_files[:3])}"
                    + ("..." if len(unexempt_files) > 3 else "")
                )

        # Fail-closed outcome ladder
        if missing_required:
            status = AvailabilityStatus.INCOMPLETE_CHECK_FAILED
            exit_code = 1
            summary_diag = (
                f"FAIL-CLOSED: Halting execution before LLM review. "
                f"Missing {len(missing_required)} required scanner(s): {', '.join(missing_required)}. "
                f"Status: INCOMPLETE_CHECK_FAILED."
            )
            diagnostics.insert(0, summary_diag)
        elif missing_advisory:
            status = AvailabilityStatus.INCONCLUSIVE_PARTIAL_AUDIT
            exit_code = 2
            summary_diag = (
                f"DEGRADED COVERAGE: Run marked INCONCLUSIVE_PARTIAL_AUDIT. "
                f"Missing {len(missing_advisory)} advisory scanner(s): {', '.join(missing_advisory)}."
            )
            diagnostics.insert(0, summary_diag)
        else:
            status = AvailabilityStatus.CLEAN
            exit_code = 0
            diagnostics.insert(
                0,
                f"All {len(available)} required and advisory scanners for changeset are available and ready."
            )

        return AvailabilityReport(
            status=status,
            exit_code=exit_code,
            missing_required=tuple(missing_required),
            missing_advisory=tuple(missing_advisory),
            available_scanners=tuple(available),
            exemptions_applied=tuple(exemptions),
            diagnostics=tuple(diagnostics),
        )
