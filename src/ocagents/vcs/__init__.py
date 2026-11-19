"""
Open Cloud Agents: Multi-VCS Provider Adapter Engine (ADR-003).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ocagents.vcs.base import DEFAULT_STATUS_CONTEXT, VALID_COMMIT_STATES, VCSProvider
from ocagents.vcs.detector import (
    DetectionSource,
    Forge,
    ForgeDetection,
    detect_forge,
    detect_forge_from_env,
    detect_forge_from_remote_url,
    get_origin_remote_url,
    remote_host,
)
from ocagents.vcs.gitlab import GL_ARTIFACT_NAME, GitLabAdapter
from ocagents.vcs.gitlab_quality import (
    findings_to_gitlab_code_quality,
    findings_to_gitlab_code_quality_json,
)
from ocagents.vcs.local import LocalGitAdapter


def get_vcs_adapter(
    forge: Forge | str | None = None,
    repo_root: str | Path | None = None,
    **kwargs: Any,
) -> VCSProvider:
    """Instantiates the appropriate VCSProvider adapter for the detected or specified forge."""
    if forge is None:
        detection = detect_forge(repo_root=repo_root)
        target_forge = detection.forge
    elif isinstance(forge, Forge):
        target_forge = forge
    else:
        try:
            target_forge = Forge(str(forge).lower())
        except ValueError:
            target_forge = Forge.LOCAL

    if target_forge == Forge.GITLAB:
        return GitLabAdapter(repo_root=repo_root, **kwargs)
    return LocalGitAdapter(repo_root=repo_root, **kwargs)


__all__ = [
    "DEFAULT_STATUS_CONTEXT",
    "GL_ARTIFACT_NAME",
    "VALID_COMMIT_STATES",
    "DetectionSource",
    "Forge",
    "ForgeDetection",
    "GitLabAdapter",
    "LocalGitAdapter",
    "VCSProvider",
    "detect_forge",
    "detect_forge_from_env",
    "detect_forge_from_remote_url",
    "findings_to_gitlab_code_quality",
    "findings_to_gitlab_code_quality_json",
    "get_origin_remote_url",
    "get_vcs_adapter",
    "remote_host",
]
