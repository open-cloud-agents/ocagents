"""
Open Cloud Agents: Bounded Execution DAG (Milestone v2.2 - Issue #100).

Provides declarative execution graph definition, topological sort, cycle detection,
phase progression validation, and canonical review flow DAGs.
"""

from __future__ import annotations

import enum
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ocagents.orchestration.circuit_breaker import CircuitBreakerPolicy

logger = logging.getLogger("ocagents.orchestration.dag")

DEFAULT_DAG_SCHEMA_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent / "schemas" / "v1" / "orchestration_dag.json"
)

STAGE_ID_PATTERN = re.compile(r"^[a-z0-9_-]+$")
DAG_ID_PATTERN = re.compile(r"^[a-z0-9_-]+$")
VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9._-]+)?$")


class DAGError(Exception):
    """Base exception for all execution DAG errors."""


class DAGValidationError(DAGError):
    """Raised when an execution DAG fails schema or specification validation."""


class DAGCycleError(DAGError):
    """Raised when a circular dependency is detected in an execution DAG."""


class DAGPhaseOrderError(DAGError):
    """Raised when a stage dependency violates architectural phase precedence."""


class DAGStageNotFoundError(DAGError):
    """Raised when a stage references a prerequisite dependency that does not exist."""


class DAGPhase(str, enum.Enum):
    """Canonical architectural execution phases in chronological order."""

    PREFLIGHT = "preflight"
    ASSESSMENT = "assessment"
    VERIFICATION = "verification"
    RELEASE = "release"
    TRIAGE = "triage"


# Phase ordering: stages can only depend on earlier or concurrent phases
PHASE_PRECEDENCE: dict[DAGPhase, int] = {
    DAGPhase.PREFLIGHT: 0,
    DAGPhase.ASSESSMENT: 1,
    DAGPhase.VERIFICATION: 2,
    DAGPhase.RELEASE: 3,
    DAGPhase.TRIAGE: 4,
}


@dataclass
class DAGStage:
    """A discrete execution stage within an orchestration DAG."""

    stage_id: str
    name: str
    phase: DAGPhase
    agents: list[str]
    depends_on: list[str] = field(default_factory=list)
    inputs: dict[str, Any] = field(default_factory=dict)
    produces: dict[str, Any] = field(default_factory=dict)
    timeout_seconds: int = 120
    required: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Serializes stage to JSON-compatible dictionary."""
        d: dict[str, Any] = {
            "stage_id": self.stage_id,
            "name": self.name,
            "phase": self.phase.value,
            "agents": list(self.agents),
            "depends_on": list(self.depends_on),
            "timeout_seconds": self.timeout_seconds,
            "required": self.required,
        }
        if self.inputs:
            d["inputs"] = dict(self.inputs)
        if self.produces:
            d["produces"] = dict(self.produces)
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DAGStage:
        """Constructs DAGStage from dictionary."""
        phase_str = str(data.get("phase", "assessment")).lower()
        try:
            phase = DAGPhase(phase_str)
        except ValueError:
            valid_phases = [p.value for p in DAGPhase]
            raise DAGValidationError(f"Invalid phase '{phase_str}'. Must be one of {valid_phases}.") from None

        return cls(
            stage_id=str(data.get("stage_id", "")),
            name=str(data.get("name", "")),
            phase=phase,
            agents=list(data.get("agents", [])),
            depends_on=list(data.get("depends_on", [])),
            inputs=dict(data.get("inputs", {})),
            produces=dict(data.get("produces", {})),
            timeout_seconds=int(data.get("timeout_seconds", 120)),
            required=bool(data.get("required", True)),
        )


@dataclass
class ExecutionDAG:
    """
    Bounded Directed Acyclic Execution Graph governing multi-agent review flows,
    deterministic tool execution, and anti-proliferation circuit breakers.
    """

    dag_id: str
    name: str
    version: str
    circuit_breaker: CircuitBreakerPolicy
    stages: dict[str, DAGStage]
    description: str = ""
    schema_uri: str = "https://open-cloud-agents.github.io/schemas/v1/orchestration_dag.json"

    def get_stage(self, stage_id: str) -> DAGStage:
        """Retrieves a stage by identifier or raises DAGStageNotFoundError."""
        if stage_id not in self.stages:
            raise DAGStageNotFoundError(f"Stage '{stage_id}' not found in DAG '{self.dag_id}'.")
        return self.stages[stage_id]

    def validate(self) -> list[str]:
        """
        Validates DAG structure, stage IDs, version formats, phase constraints,
        and ensures no circular dependencies exist. Returns list of error strings.
        """
        errors: list[str] = []

        # 1. DAG Metadata checks
        if not DAG_ID_PATTERN.match(self.dag_id):
            errors.append(f"Invalid dag_id '{self.dag_id}'. Must match pattern '^[a-z0-9_-]+$'.")

        if not self.name.strip():
            errors.append("DAG name must not be empty.")

        if not VERSION_PATTERN.match(self.version):
            errors.append(f"Invalid semantic version '{self.version}'. Must match semver pattern.")

        if not self.stages:
            errors.append("DAG must define at least one execution stage.")
            return errors

        # 2. Stage-level structure checks
        for sid, stage in self.stages.items():
            if sid != stage.stage_id:
                errors.append(f"Stage key '{sid}' does not match stage.stage_id '{stage.stage_id}'.")
            if not STAGE_ID_PATTERN.match(stage.stage_id):
                errors.append(f"Invalid stage_id '{stage.stage_id}'. Must match pattern '^[a-z0-9_-]+$'.")
            if not stage.name.strip():
                errors.append(f"Stage '{stage.stage_id}' has an empty name.")
            if not stage.agents:
                errors.append(f"Stage '{stage.stage_id}' must specify at least one agent or tool.")

            # Validate dependencies exist
            for dep in stage.depends_on:
                if dep not in self.stages:
                    errors.append(f"Stage '{stage.stage_id}' depends on undefined stage '{dep}'.")
                elif dep == stage.stage_id:
                    errors.append(f"Stage '{stage.stage_id}' cannot depend on itself.")
                else:
                    dep_stage = self.stages[dep]
                    # Validate phase precedence: cannot depend on a stage in a later phase
                    if PHASE_PRECEDENCE[dep_stage.phase] > PHASE_PRECEDENCE[stage.phase]:
                        errors.append(
                            f"Stage '{stage.stage_id}' in phase '{stage.phase.value}' "
                            f"cannot depend on stage '{dep}' in later phase '{dep_stage.phase.value}'."
                        )

        # 3. Cycle Detection via Topological Sort
        try:
            self.topological_sort()
        except DAGError as exc:
            errors.append(str(exc))

        return errors

    def topological_sort(self) -> list[DAGStage]:
        """
        Computes a deterministic topological ordering of DAG stages.
        Raises DAGCycleError if circular dependencies exist.
        Raises DAGStageNotFoundError if dependencies are missing.
        Raises DAGPhaseOrderError if phase precedence is violated.
        """
        # Validate dependency presence and phase precedence
        for sid, stage in self.stages.items():
            for dep in stage.depends_on:
                if dep not in self.stages:
                    raise DAGStageNotFoundError(
                        f"Stage '{sid}' references non-existent prerequisite stage '{dep}'."
                    )
                dep_stage = self.stages[dep]
                if PHASE_PRECEDENCE[dep_stage.phase] > PHASE_PRECEDENCE[stage.phase]:
                    raise DAGPhaseOrderError(
                        f"Phase order violation: Stage '{sid}' ({stage.phase.value}) "
                        f"cannot depend on stage '{dep}' ({dep_stage.phase.value})."
                    )

        # Build in-degree map and adjacency list (dep -> list of stages that depend on dep)
        in_degrees: dict[str, int] = {sid: 0 for sid in self.stages}
        dependents: dict[str, list[str]] = {sid: [] for sid in self.stages}

        for sid, stage in self.stages.items():
            in_degrees[sid] = len(stage.depends_on)
            for dep in stage.depends_on:
                dependents[dep].append(sid)

        # Priority sort for initial zero in-degree stages (phase precedence first, then ID)
        ready = [
            sid
            for sid, deg in in_degrees.items()
            if deg == 0
        ]
        ready.sort(key=lambda s: (PHASE_PRECEDENCE[self.stages[s].phase], s))

        ordered: list[DAGStage] = []

        while ready:
            curr_id = ready.pop(0)
            ordered.append(self.stages[curr_id])

            for nxt_id in sorted(dependents[curr_id], key=lambda s: (PHASE_PRECEDENCE[self.stages[s].phase], s)):
                in_degrees[nxt_id] -= 1
                if in_degrees[nxt_id] == 0:
                    ready.append(nxt_id)
                    ready.sort(key=lambda s: (PHASE_PRECEDENCE[self.stages[s].phase], s))

        if len(ordered) != len(self.stages):
            # Circular dependency detected
            unresolved = [sid for sid, deg in in_degrees.items() if deg > 0]
            cycle_desc = " -> ".join(unresolved)
            raise DAGCycleError(
                f"Circular dependency detected among execution stages: {cycle_desc}."
            )

        return ordered

    def to_dict(self) -> dict[str, Any]:
        """Serializes the ExecutionDAG to match schemas/v1/orchestration_dag.json."""
        return {
            "$schema": self.schema_uri,
            "dag_id": self.dag_id,
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "circuit_breaker": {
                "max_corroboration_hops": self.circuit_breaker.max_corroboration_hops,
                "max_total_workflow_tokens": self.circuit_breaker.max_total_workflow_tokens,
                "max_per_agent_tokens": self.circuit_breaker.max_per_agent_tokens,
                "fail_closed_on_trip": self.circuit_breaker.fail_closed,
                "prohibit_peer_to_peer": self.circuit_breaker.prohibit_peer_to_peer,
            },
            "stages": [stage.to_dict() for stage in self.stages.values()],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ExecutionDAG:
        """Parses an ExecutionDAG from a dictionary."""
        if not isinstance(data, dict):
            raise DAGValidationError("Execution DAG payload must be a JSON dictionary.")

        dag_id = str(data.get("dag_id", ""))
        name = str(data.get("name", ""))
        version = str(data.get("version", "1.0.0"))
        desc = str(data.get("description", ""))
        schema_uri = str(data.get("$schema", "https://open-cloud-agents.github.io/schemas/v1/orchestration_dag.json"))

        cb_data = data.get("circuit_breaker", {})
        circuit_breaker = CircuitBreakerPolicy.from_dict(cb_data)

        raw_stages = data.get("stages", [])
        if not isinstance(raw_stages, list):
            raise DAGValidationError("Field 'stages' must be a list of stage objects.")

        stages: dict[str, DAGStage] = {}
        for item in raw_stages:
            if not isinstance(item, dict):
                raise DAGValidationError("Each stage entry must be a dictionary.")
            stage = DAGStage.from_dict(item)
            stages[stage.stage_id] = stage

        dag = cls(
            dag_id=dag_id,
            name=name,
            version=version,
            circuit_breaker=circuit_breaker,
            stages=stages,
            description=desc,
            schema_uri=schema_uri,
        )

        validation_errors = dag.validate()
        if validation_errors:
            raise DAGValidationError(f"Invalid DAG definition: {'; '.join(validation_errors)}")

        return dag

    @classmethod
    def from_file(cls, path: Path | str) -> ExecutionDAG:
        """Loads and parses an ExecutionDAG from a JSON file."""
        p = Path(path).resolve()
        if not p.exists():
            raise FileNotFoundError(f"DAG definition file not found at: {p}")
        try:
            content = p.read_text(encoding="utf-8")
            data = json.loads(content)
        except (OSError, json.JSONDecodeError) as exc:
            raise DAGValidationError(f"Failed to read or parse DAG JSON at {p}: {exc}") from exc

        return cls.from_dict(data)


def get_canonical_dag() -> ExecutionDAG:
    """
    Returns the canonical Open Cloud Agents 4-phase enterprise review DAG:
      1. preflight-gate (preflight)
      2. architecture-security-assessment (assessment)
      3. verification-cost-optimization (verification)
      4. release-human-triage (release)
    """
    stages = {
        "preflight-gate": DAGStage(
            stage_id="preflight-gate",
            name="Deterministic Pre-Flight Gate",
            phase=DAGPhase.PREFLIGHT,
            agents=["checkov", "trivy", "opa", "shellcheck", "ruff"],
            depends_on=[],
            inputs={"requires_changeset": True},
            produces={"finding_categories": ["security", "governance", "syntax"], "output_target": "blackboard"},
            timeout_seconds=60,
            required=True,
        ),
        "architecture-security-assessment": DAGStage(
            stage_id="architecture-security-assessment",
            name="Architecture and Security Assessment",
            phase=DAGPhase.ASSESSMENT,
            agents=["principal-cloud-architect", "security-compliance-commander"],
            depends_on=["preflight-gate"],
            inputs={"requires_changeset": True, "subscribed_categories": ["security", "governance"]},
            produces={"finding_categories": ["architecture", "security", "compliance"], "output_target": "blackboard"},
            timeout_seconds=180,
            required=True,
        ),
        "verification-cost-optimization": DAGStage(
            stage_id="verification-cost-optimization",
            name="Verification and Cost Optimization",
            phase=DAGPhase.VERIFICATION,
            agents=["finops-cloud-cost-optimizer", "sre-reliability-engineer", "devsecops-reviewer"],
            depends_on=["architecture-security-assessment"],
            inputs={"requires_changeset": True, "subscribed_categories": ["architecture", "security"]},
            produces={"finding_categories": ["cost", "reliability", "review"], "output_target": "blackboard"},
            timeout_seconds=180,
            required=True,
        ),
        "release-human-triage": DAGStage(
            stage_id="release-human-triage",
            name="Release Management and Human Sign-off Triage",
            phase=DAGPhase.RELEASE,
            agents=["gitops-release-manager"],
            depends_on=["verification-cost-optimization"],
            inputs={"requires_changeset": True},
            produces={"finding_categories": ["release", "audit"], "output_target": "blackboard"},
            timeout_seconds=120,
            required=True,
        ),
    }

    return ExecutionDAG(
        dag_id="canonical-enterprise-review-dag",
        name="Canonical Enterprise Multi-Agent Review Flow",
        version="1.0.0",
        description=(
            "Bounded 4-phase review DAG coordinating deterministic pre-flight checks, "
            "specialist architectural assessments, cost/reliability verification, and human release triage."
        ),
        circuit_breaker=CircuitBreakerPolicy(
            max_corroboration_hops=2,
            max_total_workflow_tokens=50000,
            max_per_agent_tokens=12000,
            fail_closed=True,
            prohibit_peer_to_peer=True,
        ),
        stages=stages,
    )
