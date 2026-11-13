"""
Open Cloud Agents: Specialist Agent Blackboard Execution Loop (Milestone v2.0 - TASK-4.2).

Orchestrates multi-agent parallel execution of Tier 2 specialists against the append-only
Blackboard findings store, subscribing to risk-tiered diffs and existing findings via TOON.
"""

from __future__ import annotations

import concurrent.futures
import datetime
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ocagents.blackboard.envelope import (
    RunEnvelope,
    detect_git_environment,
    generate_deterministic_run_id,
)
from ocagents.blackboard.projections import estimate_token_count, project_findings_toon
from ocagents.blackboard.store import BlackboardStore
from ocagents.frontmatter import parse_frontmatter
from ocagents.providers import (
    BoundedRetryEngine,
    ConstrainedDecodingError,
    ModelProvider,
    ProviderError,
    TokenBudgetExceededError,
    get_provider,
    load_finding_schema,
)
from ocagents.triage.classifier import RiskTier, TriageResult, classify_diff

logger = logging.getLogger("ocagents.orchestration")

DEFAULT_AGENTS_DIR = Path(__file__).resolve().parent.parent.parent.parent / "agents" / "7-agent-master-suite"

# Canonical Tier 2 specialists to run in parallel
TIER_2_SPECIALISTS = [
    "principal-cloud-architect",
    "security-compliance-commander",
    "finops-cloud-cost-optimizer",
    "sre-reliability-engineer",
    "devsecops-reviewer",
]


def resolve_agents_dir(custom_path: Path | str | None = None) -> Path:
    """Resolves the canonical directory containing agent Markdown specifications."""
    if custom_path:
        p = Path(custom_path).resolve()
        if p.exists() and p.is_dir():
            return p

    candidates = [
        DEFAULT_AGENTS_DIR,
        Path.cwd() / "agents" / "7-agent-master-suite",
        Path.home() / ".open-cloud-agents" / "agents" / "7-agent-master-suite",
        Path("/opt/homebrew/share/ocagents/agents/7-agent-master-suite"),
        Path("/usr/local/share/ocagents/agents/7-agent-master-suite"),
        Path("/usr/share/ocagents/agents/7-agent-master-suite"),
    ]

    for cand in candidates:
        if cand.exists() and cand.is_dir():
            return cand.resolve()

    return DEFAULT_AGENTS_DIR.resolve()


@dataclass
class SpecialistMetadata:
    """Metadata, token budget limits, and system prompt for a single agent."""

    agent_id: str
    name: str
    description: str
    tools: list[str] = field(default_factory=list)
    skills: list[str] = field(default_factory=list)
    max_context_tokens: int = 5000
    max_output_tokens: int = 1200
    max_session_total_tokens: int = 9000
    system_prompt: str = ""


def load_specialist_metadata(agent_id: str, agents_dir: Path | None = None) -> SpecialistMetadata:
    """
    Parses frontmatter and system prompt instructions from the agent specification Markdown.
    """
    directory = resolve_agents_dir(agents_dir)
    file_path = directory / f"{agent_id}.md"

    if not file_path.exists():
        # Fallback minimal spec if file is not on disk
        return SpecialistMetadata(
            agent_id=agent_id,
            name=agent_id.replace("-", " ").title(),
            description=f"Specialist agent {agent_id}",
            max_context_tokens=5000,
            max_output_tokens=1200,
            max_session_total_tokens=9000,
            system_prompt=f"You are the {agent_id.replace('-', ' ').title()} specialist.",
        )

    content = file_path.read_text(encoding="utf-8")
    meta, body = parse_frontmatter(content)

    token_budget = meta.get("token_budget", {})
    if not isinstance(token_budget, dict):
        token_budget = {}

    max_ctx = int(token_budget.get("max_context_tokens") or 5000)
    max_out = int(token_budget.get("max_output_tokens") or 1200)
    max_total = int(token_budget.get("max_session_total_tokens") or 9000)

    tools = meta.get("tools", [])
    if isinstance(tools, str):
        tools = [tools]

    skills = meta.get("skills", [])
    if isinstance(skills, str):
        skills = [skills]

    return SpecialistMetadata(
        agent_id=agent_id,
        name=str(meta.get("name") or agent_id.replace("-", " ").title()),
        description=str(meta.get("description") or ""),
        tools=list(tools),
        skills=list(skills),
        max_context_tokens=max_ctx,
        max_output_tokens=max_out,
        max_session_total_tokens=max_total,
        system_prompt=body.strip(),
    )


@dataclass
class SpecialistExecutionResult:
    """Execution telemetry and emitted findings for an individual specialist."""

    agent_id: str
    status: str  # "success", "failed", "budget_exceeded", "skipped"
    findings: list[dict[str, Any]] = field(default_factory=list)
    published_ids: list[str] = field(default_factory=list)
    attempts: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    duration_ms: int = 0
    error_message: str | None = None


@dataclass
class BlackboardRunSummary:
    """Consolidated summary of a multi-agent blackboard orchestration run."""

    run_id: str
    risk_tier: int
    tier_name: str
    agents_activated: list[str]
    agent_results: dict[str, SpecialistExecutionResult] = field(default_factory=dict)
    total_findings_published: int = 0
    total_tokens_consumed: int = 0
    execution_time_seconds: float = 0.0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serializes the summary to a JSON-compatible dictionary."""
        return {
            "run_id": self.run_id,
            "risk_tier": self.risk_tier,
            "tier_name": self.tier_name,
            "agents_activated": self.agents_activated,
            "total_findings_published": self.total_findings_published,
            "total_tokens_consumed": self.total_tokens_consumed,
            "execution_time_seconds": round(self.execution_time_seconds, 3),
            "errors": self.errors,
            "agent_results": {
                aid: {
                    "status": res.status,
                    "attempts": res.attempts,
                    "findings_count": len(res.findings),
                    "prompt_tokens": res.prompt_tokens,
                    "completion_tokens": res.completion_tokens,
                    "total_tokens": res.total_tokens,
                    "duration_ms": res.duration_ms,
                    "error_message": res.error_message,
                }
                for aid, res in self.agent_results.items()
            },
        }


class BlackboardRunner:
    """
    Executes parallel specialist loops against the Blackboard findings store,
    enforcing risk triage, per-agent token limits, and TOON upstream projections.
    """

    def __init__(
        self,
        blackboard: BlackboardStore | None = None,
        provider: ModelProvider | None = None,
        agents_dir: Path | None = None,
        max_retries: int = 2,
        parallel: bool = True,
        max_workers: int = 4,
    ) -> None:
        self.blackboard = blackboard or BlackboardStore()
        self.provider = provider or get_provider()
        self.agents_dir = resolve_agents_dir(agents_dir)
        self.max_retries = max_retries
        self.parallel = parallel
        self.max_workers = max_workers
        self.schema = load_finding_schema()

    def run(
        self,
        diff: str,
        run_envelope: RunEnvelope | dict[str, Any] | None = None,
        triage_result: TriageResult | dict[str, Any] | None = None,
        target_agents: list[str] | None = None,
        repo_root: Path | None = None,
    ) -> BlackboardRunSummary:
        """
        Executes the multi-agent specialist loop on a unified changeset diff.
        """
        start_time = time.time()

        # 1. Resolve Risk Triage
        triage: TriageResult
        if isinstance(triage_result, TriageResult):
            triage = triage_result
        elif isinstance(triage_result, dict):
            tier_val = triage_result.get("risk_tier", 2)
            triage = TriageResult(
                risk_tier=tier_val,
                tier_name=triage_result.get("tier_name", f"Tier {tier_val}"),
                activated_agents=list(triage_result.get("activated_agents", TIER_2_SPECIALISTS)),
                file_classifications={},
                file_reasons={},
                reasons=[],
                files_by_tier={},
                diff_summary={},
            )
        else:
            triage = classify_diff(diff)

        # 2. Resolve / Create Run Envelope
        envelope: RunEnvelope
        if isinstance(run_envelope, RunEnvelope):
            envelope = run_envelope
        elif isinstance(run_envelope, dict):
            envelope = RunEnvelope.from_dict(run_envelope)
        else:
            git_env = detect_git_environment(repo_root)
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
            run_id = generate_deterministic_run_id(
                repo_url=git_env.get("repo_url"),
                commit_sha=git_env.get("commit_sha", "000000000000"),
                pr_number=None,
                timestamp_utc=now_iso,
            )
            envelope = RunEnvelope(
                run_id=run_id,
                commit_sha=git_env.get("commit_sha", "000000000000"),
                risk_tier=int(triage.risk_tier),
                repo=git_env.get("repo"),
                repo_url=git_env.get("repo_url"),
                head_ref=git_env.get("head_ref"),
                timestamp_utc=now_iso,
            )

        self.blackboard.save_run(envelope)
        run_id = envelope.run_id

        # 3. Resolve Activated Specialists
        if target_agents is not None:
            activated_agents = list(target_agents)
        elif triage.risk_tier == RiskTier.TIER_0:
            # Tier 0: LLM Bypass (Zero token spend)
            activated_agents = []
        elif triage.risk_tier == RiskTier.TIER_1:
            activated_agents = ["devsecops-reviewer"]
        else:
            # Tier 2: Master Suite Specialists
            activated_agents = list(triage.activated_agents or TIER_2_SPECIALISTS)

        summary = BlackboardRunSummary(
            run_id=run_id,
            risk_tier=int(triage.risk_tier),
            tier_name=triage.tier_name,
            agents_activated=activated_agents,
        )

        if not activated_agents or not diff.strip():
            summary.execution_time_seconds = time.time() - start_time
            return summary

        # 4. Fetch Existing Findings on Blackboard for TOON Projection
        existing_findings = self.blackboard.get_findings(run_id=run_id)

        # 5. Execute Specialists
        agent_results: dict[str, SpecialistExecutionResult] = {}
        total_tokens = 0
        total_published = 0

        if self.parallel and len(activated_agents) > 1:
            workers = min(len(activated_agents), self.max_workers)
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
                future_to_agent = {
                    executor.submit(
                        self._execute_single_specialist,
                        agent_id=aid,
                        diff=diff,
                        existing_findings=existing_findings,
                        run_id=run_id,
                    ): aid
                    for aid in activated_agents
                }

                for future in concurrent.futures.as_completed(future_to_agent):
                    aid = future_to_agent[future]
                    try:
                        res = future.result()
                        agent_results[aid] = res
                        total_tokens += res.total_tokens
                        total_published += len(res.published_ids)
                        if res.status == "failed" and res.error_message:
                            summary.errors.append(f"{aid}: {res.error_message}")
                    except Exception as exc:
                        logger.error("Unhandled error executing specialist %s: %s", aid, exc, exc_info=True)
                        err_res = SpecialistExecutionResult(
                            agent_id=aid,
                            status="failed",
                            error_message=str(exc),
                        )
                        agent_results[aid] = err_res
                        summary.errors.append(f"{aid}: {exc}")
        else:
            for aid in activated_agents:
                try:
                    res = self._execute_single_specialist(
                        agent_id=aid,
                        diff=diff,
                        existing_findings=existing_findings,
                        run_id=run_id,
                    )
                    agent_results[aid] = res
                    total_tokens += res.total_tokens
                    total_published += len(res.published_ids)
                    if res.status == "failed" and res.error_message:
                        summary.errors.append(f"{aid}: {res.error_message}")
                except Exception as exc:
                    logger.error("Unhandled error executing specialist %s: %s", aid, exc, exc_info=True)
                    err_res = SpecialistExecutionResult(
                        agent_id=aid,
                        status="failed",
                        error_message=str(exc),
                    )
                    agent_results[aid] = err_res
                    summary.errors.append(f"{aid}: {exc}")

        summary.agent_results = agent_results
        summary.total_findings_published = total_published
        summary.total_tokens_consumed = total_tokens
        summary.execution_time_seconds = time.time() - start_time
        return summary

    def _execute_single_specialist(
        self,
        agent_id: str,
        diff: str,
        existing_findings: list[dict[str, Any]],
        run_id: str,
    ) -> SpecialistExecutionResult:
        """Executes a single specialist agent with TOON context and bounded retry logic."""
        t0 = time.time()
        meta = load_specialist_metadata(agent_id, self.agents_dir)

        # Assemble prompt respecting context token budget
        user_prompt = self._build_specialist_prompt(
            agent_meta=meta,
            diff=diff,
            existing_findings=existing_findings,
        )

        engine = BoundedRetryEngine(
            provider=self.provider,
            schema=self.schema,
            max_retries=self.max_retries,
            max_total_tokens=meta.max_session_total_tokens,
        )

        try:
            retry_result = engine.execute(
                prompt=user_prompt,
                system_prompt=meta.system_prompt,
                agent_name=agent_id,
            )

            # Publish valid findings to Blackboard
            published_ids: list[str] = []
            for f in retry_result.findings:
                # Ensure provenance markers
                f["agent"] = agent_id
                f.setdefault("origin", "model_assertion")
                f.setdefault("corroboration_status", "unverified_model_claim")
                fid = self.blackboard.publish_finding(finding=f, run_id=run_id)
                published_ids.append(fid)

            duration_ms = int((time.time() - t0) * 1000)

            # Record telemetry in database
            self.blackboard.record_execution(
                run_id=run_id,
                agent=agent_id,
                prompt_tokens=retry_result.prompt_tokens,
                output_tokens=retry_result.completion_tokens,
                duration_ms=duration_ms,
                status="success",
            )

            return SpecialistExecutionResult(
                agent_id=agent_id,
                status="success",
                findings=retry_result.findings,
                published_ids=published_ids,
                attempts=retry_result.attempts,
                prompt_tokens=retry_result.prompt_tokens,
                completion_tokens=retry_result.completion_tokens,
                total_tokens=retry_result.total_tokens,
                duration_ms=duration_ms,
            )

        except TokenBudgetExceededError as exc:
            duration_ms = int((time.time() - t0) * 1000)
            logger.warning("Agent '%s' exceeded token budget: %s", agent_id, exc)
            self.blackboard.record_execution(
                run_id=run_id,
                agent=agent_id,
                status="budget_exceeded",
                duration_ms=duration_ms,
                error_message=str(exc),
            )
            return SpecialistExecutionResult(
                agent_id=agent_id,
                status="budget_exceeded",
                duration_ms=duration_ms,
                error_message=str(exc),
            )

        except (ConstrainedDecodingError, ProviderError) as exc:
            duration_ms = int((time.time() - t0) * 1000)
            logger.error("Agent '%s' failed execution: %s", agent_id, exc)
            self.blackboard.record_execution(
                run_id=run_id,
                agent=agent_id,
                status="failed",
                duration_ms=duration_ms,
                error_message=str(exc),
            )
            return SpecialistExecutionResult(
                agent_id=agent_id,
                status="failed",
                duration_ms=duration_ms,
                error_message=str(exc),
            )

    def _build_specialist_prompt(
        self,
        agent_meta: SpecialistMetadata,
        diff: str,
        existing_findings: list[dict[str, Any]],
    ) -> str:
        """
        Builds user prompt containing diff and TOON-projected existing findings,
        truncating content if necessary to stay within max_context_tokens.
        """
        # Reserve ~800 tokens for instructions and system framing
        budget = max(1000, agent_meta.max_context_tokens - 800)

        # TOON projection allocation (max 25% of context or 800 tokens)
        toon_budget = min(800, budget // 4)
        toon_table = project_findings_toon(existing_findings, max_tokens=toon_budget)
        toon_tokens = estimate_token_count(toon_table)

        # Remaining budget is allocated to the diff
        diff_budget = max(500, budget - toon_tokens)
        trimmed_diff = diff
        if estimate_token_count(diff) > diff_budget:
            char_limit = diff_budget * 4
            trimmed_diff = diff[:char_limit] + "\n... [CHANGESET DIFF TRUNCATED TO CONTEXT TOKEN LIMIT] ..."

        return (
            f"You are conducting a specialist cloud architecture and security review as '{agent_meta.name}'.\n\n"
            f"=== TARGET CHANGESET DIFF ===\n"
            f"{trimmed_diff}\n"
            f"=== END CHANGESET DIFF ===\n\n"
            f"=== CURRENT BLACKBOARD FINDINGS (UPSTREAM CONTEXT) ===\n"
            f"{toon_table}\n"
            f"=== END BLACKBOARD FINDINGS ===\n\n"
            f"OPERATIONAL MANDATE & INSTRUCTIONS:\n"
            f"1. Audit the changeset diff strictly adhering to your persona ({agent_meta.name}) and declared skills.\n"
            f"2. Inspect for Well-Architected invariants, security controls, destructive operations, and cost waste.\n"
            f"3. If an existing finding on the Blackboard is confirmed or refuted by your analysis, corroborate it "
            f"by referencing the exact rule_id, resource, and evidence locator.\n"
            f"4. If you identify new architectural defects or compliance risks, emit them as new findings.\n"
            f"5. Emit your findings strictly adhering to schemas/v1/finding.json within the 'findings' array. "
            f"Do not output conversational filler."
        )
