"""
Open Cloud Agents: Run Metadata Envelope Engine (Milestone v1.6 - TASK-3.2).

Generates deterministic, immutable session envelopes capturing audit execution metadata:
  - run_id derivation: "run-" + sha256(repo_url:commit_sha:pr_number:timestamp_utc)[0:16]
  - Commit provenance: commit_sha, base_sha, base_ref, head_ref, repo
  - Execution manifests: agent_manifest, tool_manifest, token_budget_allocated, risk_tier
  - Zero-dependency schema validation against schemas/v1/run_envelope.json
"""

from __future__ import annotations

import datetime
import hashlib
import json
import logging
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ocagents import __version__ as ENGINE_VERSION

logger = logging.getLogger(__name__)

SCHEMA_VERSION = "1.0.0"
SCHEMA_URI = "https://open-cloud-agents.github.io/schemas/v1/run_envelope.json"

RUN_ID_REGEX = re.compile(r"^run-[a-zA-Z0-9_-]{12,64}$")
SHA_REGEX = re.compile(r"^[0-9a-fA-F]{7,40}$")


@dataclass
class RunEnvelope:
    """Represents an immutable execution audit envelope."""
    run_id: str
    commit_sha: str
    risk_tier: int
    schema_version: str = SCHEMA_VERSION
    engine_version: str = ENGINE_VERSION
    timestamp_utc: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    )
    repo: str | None = None
    repo_url: str | None = None
    base_sha: str | None = None
    base_ref: str | None = None
    head_ref: str | None = None
    pr_number: int | None = None
    invoked_by: str = "cli"
    token_budget_allocated: dict[str, int] | None = None
    agent_manifest: dict[str, str] = field(default_factory=dict)
    tool_manifest: dict[str, str] = field(default_factory=dict)
    schema_uri: str = SCHEMA_URI

    def to_dict(self) -> dict[str, Any]:
        """Serializes the envelope to a JSON-compatible dictionary conforming to schema."""
        d: dict[str, Any] = {
            "$schema": self.schema_uri,
            "run_id": self.run_id,
            "commit_sha": self.commit_sha,
            "schema_version": self.schema_version,
            "engine_version": self.engine_version,
            "timestamp_utc": self.timestamp_utc,
            "risk_tier": self.risk_tier,
        }
        if self.repo is not None:
            d["repo"] = self.repo
        if self.repo_url is not None:
            d["repo_url"] = self.repo_url
        if self.base_sha is not None:
            d["base_sha"] = self.base_sha
        if self.base_ref is not None:
            d["base_ref"] = self.base_ref
        if self.head_ref is not None:
            d["head_ref"] = self.head_ref
        if self.pr_number is not None:
            d["pr_number"] = self.pr_number
        if self.invoked_by is not None:
            d["invoked_by"] = self.invoked_by
        if self.token_budget_allocated is not None:
            d["token_budget_allocated"] = dict(self.token_budget_allocated)
        if self.agent_manifest:
            d["agent_manifest"] = dict(self.agent_manifest)
        if self.tool_manifest:
            d["tool_manifest"] = dict(self.tool_manifest)
        return d

    def to_json(self, indent: int = 2) -> str:
        """Serializes the envelope to a formatted JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RunEnvelope:
        """Constructs and validates a RunEnvelope from a dictionary."""
        valid, errors = validate_run_envelope(data)
        if not valid:
            raise ValueError(f"Invalid RunEnvelope schema: {'; '.join(errors)}")

        return cls(
            run_id=data["run_id"],
            commit_sha=data["commit_sha"],
            risk_tier=data["risk_tier"],
            schema_version=data.get("schema_version", SCHEMA_VERSION),
            engine_version=data.get("engine_version", ENGINE_VERSION),
            timestamp_utc=data.get("timestamp_utc", ""),
            repo=data.get("repo"),
            repo_url=data.get("repo_url"),
            base_sha=data.get("base_sha"),
            base_ref=data.get("base_ref"),
            head_ref=data.get("head_ref"),
            pr_number=data.get("pr_number"),
            invoked_by=data.get("invoked_by", "cli"),
            token_budget_allocated=data.get("token_budget_allocated"),
            agent_manifest=data.get("agent_manifest", {}),
            tool_manifest=data.get("tool_manifest", {}),
            schema_uri=data.get("$schema", SCHEMA_URI),
        )


def generate_deterministic_run_id(
    repo_url: str | None,
    commit_sha: str,
    pr_number: int | None,
    timestamp_utc: str,
) -> str:
    """
    Derives deterministic run_id = "run-" + sha256(repo_url:commit_sha:pr_number:timestamp_utc)[0:16].
    Guarantees idempotency and traceability across distributed CI workers.
    """
    key = f"{repo_url or 'local'}:{commit_sha}:{pr_number or 'none'}:{timestamp_utc}"
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
    return f"run-{digest}"


def detect_git_environment(repo_root: str | Path | None = None) -> dict[str, Any]:
    """Detects current git commit, remote URL, and repository name."""
    root = Path(repo_root or os.getcwd()).resolve()
    info: dict[str, Any] = {
        "commit_sha": "0000000000000000000000000000000000000000",
        "repo": None,
        "repo_url": None,
        "head_ref": None,
    }

    try:
        # Commit SHA
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
        if res.returncode == 0 and res.stdout.strip():
            info["commit_sha"] = res.stdout.strip()

        # Head Ref / Branch
        res_ref = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
        if res_ref.returncode == 0 and res_ref.stdout.strip():
            branch = res_ref.stdout.strip()
            if branch != "HEAD":
                info["head_ref"] = branch

        # Remote URL
        res_url = subprocess.run(
            ["git", "config", "--get", "remote.origin.url"],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
        if res_url.returncode == 0 and res_url.stdout.strip():
            url = res_url.stdout.strip()
            info["repo_url"] = url
            # Extract owner/repo from URL
            m = re.search(r"[:/]([a-zA-Z0-9_-]+/[a-zA-Z0-9_.-]+?)(?:\.git)?$", url)
            if m:
                info["repo"] = m.group(1)
    except (subprocess.SubprocessError, OSError, ValueError) as exc:
        logger.debug("Git environment detection error: %s", exc)

    return info


def create_run_envelope(
    risk_tier: int,
    commit_sha: str | None = None,
    repo: str | None = None,
    repo_url: str | None = None,
    base_sha: str | None = None,
    base_ref: str | None = None,
    head_ref: str | None = None,
    pr_number: int | None = None,
    invoked_by: str = "cli",
    token_budget_allocated: dict[str, int] | None = None,
    agent_manifest: dict[str, str] | None = None,
    tool_manifest: dict[str, str] | None = None,
    timestamp_utc: str | None = None,
    repo_root: str | Path | None = None,
) -> RunEnvelope:
    """
    Factory creating a fully populated and validated RunEnvelope.
    Automatically detects local git properties when not explicitly passed.
    """
    git_info = detect_git_environment(repo_root)

    resolved_commit = commit_sha or os.environ.get("GITHUB_SHA") or git_info.get("commit_sha", "0000000000000000000000000000000000000000")
    resolved_repo_url = repo_url or os.environ.get("GITHUB_SERVER_URL", "") + "/" + os.environ.get("GITHUB_REPOSITORY", "") if os.environ.get("GITHUB_REPOSITORY") else git_info.get("repo_url")
    resolved_repo = repo or os.environ.get("GITHUB_REPOSITORY") or git_info.get("repo")
    resolved_head_ref = head_ref or os.environ.get("GITHUB_HEAD_REF") or git_info.get("head_ref")
    resolved_base_ref = base_ref or os.environ.get("GITHUB_BASE_REF")

    # If in GitHub Actions PR
    if pr_number is None and os.environ.get("GITHUB_EVENT_NAME") == "pull_request":
        # Extract PR number from GITHUB_REF (refs/pull/123/merge)
        ref = os.environ.get("GITHUB_REF", "")
        m = re.match(r"^refs/pull/(\d+)/", ref)
        if m:
            pr_number = int(m.group(1))

    resolved_timestamp = timestamp_utc or datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    run_id = generate_deterministic_run_id(
        repo_url=resolved_repo_url,
        commit_sha=resolved_commit,
        pr_number=pr_number,
        timestamp_utc=resolved_timestamp,
    )

    envelope = RunEnvelope(
        run_id=run_id,
        commit_sha=resolved_commit,
        risk_tier=risk_tier,
        schema_version=SCHEMA_VERSION,
        engine_version=ENGINE_VERSION,
        timestamp_utc=resolved_timestamp,
        repo=resolved_repo,
        repo_url=resolved_repo_url,
        base_sha=base_sha,
        base_ref=resolved_base_ref,
        head_ref=resolved_head_ref,
        pr_number=pr_number,
        invoked_by=invoked_by,
        token_budget_allocated=token_budget_allocated,
        agent_manifest=agent_manifest or {},
        tool_manifest=tool_manifest or {},
        schema_uri=SCHEMA_URI,
    )

    valid, errors = validate_run_envelope(envelope.to_dict())
    if not valid:
        raise ValueError(f"Run envelope failed validation: {'; '.join(errors)}")

    return envelope


def validate_run_envelope(data: dict[str, Any]) -> tuple[bool, list[str]]:
    """
    Zero-dependency schema validation for RunEnvelope objects.
    Enforces required fields, types, enum limits, regex patterns, and additionalProperties: false.
    """
    errors: list[str] = []

    if not isinstance(data, dict):
        return False, ["Run envelope must be a JSON object"]

    # Allowed keys
    allowed_keys = {
        "$schema",
        "run_id",
        "repo",
        "repo_url",
        "commit_sha",
        "base_sha",
        "base_ref",
        "head_ref",
        "pr_number",
        "schema_version",
        "engine_version",
        "timestamp_utc",
        "risk_tier",
        "invoked_by",
        "token_budget_allocated",
        "agent_manifest",
        "tool_manifest",
    }

    extra_keys = set(data.keys()) - allowed_keys
    if extra_keys:
        errors.append(f"Forbidden extra properties found: {sorted(extra_keys)}")

    # Required fields
    required_fields = [
        "$schema",
        "run_id",
        "commit_sha",
        "schema_version",
        "engine_version",
        "timestamp_utc",
        "risk_tier",
    ]
    for rf in required_fields:
        if rf not in data or data[rf] is None:
            errors.append(f"Missing required field: '{rf}'")

    if errors:
        return False, errors

    # Field validations
    run_id = data["run_id"]
    if not isinstance(run_id, str) or not RUN_ID_REGEX.match(run_id):
        errors.append(f"Field 'run_id' does not match pattern '^run-[a-zA-Z0-9_-]{{12,64}}$': got '{run_id}'")

    commit_sha = data["commit_sha"]
    if not isinstance(commit_sha, str) or not SHA_REGEX.match(commit_sha):
        errors.append(f"Field 'commit_sha' must be 7-40 hex chars: got '{commit_sha}'")

    if data.get("base_sha") is not None:
        base_sha = data["base_sha"]
        if not isinstance(base_sha, str) or not SHA_REGEX.match(base_sha):
            errors.append(f"Field 'base_sha' must be 7-40 hex chars: got '{base_sha}'")

    risk_tier = data["risk_tier"]
    if not isinstance(risk_tier, int) or risk_tier not in (0, 1, 2) or isinstance(risk_tier, bool):
        errors.append(f"Field 'risk_tier' must be integer enum [0, 1, 2]: got '{risk_tier}'")

    if data.get("pr_number") is not None:
        pr_number = data["pr_number"]
        if not isinstance(pr_number, int) or pr_number < 1 or isinstance(pr_number, bool):
            errors.append(f"Field 'pr_number' must be a positive integer: got '{pr_number}'")

    if data.get("token_budget_allocated") is not None:
        tb = data["token_budget_allocated"]
        if not isinstance(tb, dict):
            errors.append("Field 'token_budget_allocated' must be an object")
        else:
            tb_allowed = {"max_context_tokens", "max_output_tokens", "max_session_total_tokens"}
            tb_extra = set(tb.keys()) - tb_allowed
            if tb_extra:
                errors.append(f"Forbidden extra keys in 'token_budget_allocated': {sorted(tb_extra)}")
            for k in tb_allowed:
                if k in tb:
                    val = tb[k]
                    if not isinstance(val, int) or val < 0 or isinstance(val, bool):
                        errors.append(f"Token budget '{k}' must be non-negative integer: got '{val}'")

    for manifest_field in ["agent_manifest", "tool_manifest"]:
        if manifest_field in data:
            manifest = data[manifest_field]
            if not isinstance(manifest, dict):
                errors.append(f"Field '{manifest_field}' must be an object")
            else:
                for k, v in manifest.items():
                    if not isinstance(v, str):
                        errors.append(f"Manifest '{manifest_field}[{k}]' must be a string value")

    return len(errors) == 0, errors

