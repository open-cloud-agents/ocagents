"""
Open Cloud Agents: Multi-VCS Provider Adapter Engine (ADR-003).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ocagents.vcs.azure_devops import ADO_ARTIFACT_NAME, AzureDevOpsAdapter
from ocagents.vcs.base import DEFAULT_STATUS_CONTEXT, VALID_COMMIT_STATES, VCSProvider
from ocagents.vcs.bitbucket import (
    BB_ARTIFACT_NAME,
    BitbucketAdapter,
    findings_to_bitbucket_insights,
    findings_to_bitbucket_insights_json,
)
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
from ocagents.vcs.gitea import (
    GT_ARTIFACT_NAME,
    GiteaAdapter,
    findings_to_gitea_quality,
    findings_to_gitea_quality_json,
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
        norm = str(forge).lower().strip()
        if norm in ("ado", "azure-devops", "azure_devops", "azure"):
            target_forge = Forge.AZURE_DEVOPS
        elif norm in ("bb", "bitbucket", "bitbucket-cloud", "bitbucket-server"):
            target_forge = Forge.BITBUCKET
        elif norm in ("gitea", "forgejo", "codeberg"):
            target_forge = Forge.GITEA
        else:
            try:
                target_forge = Forge(norm)
            except ValueError:
                target_forge = Forge.LOCAL

    if target_forge == Forge.GITLAB:
        return GitLabAdapter(repo_root=repo_root, **kwargs)
    if target_forge == Forge.AZURE_DEVOPS:
        return AzureDevOpsAdapter(repo_root=repo_root, **kwargs)
    if target_forge == Forge.BITBUCKET:
        return BitbucketAdapter(repo_root=repo_root, **kwargs)
    if target_forge == Forge.GITEA:
        return GiteaAdapter(repo_root=repo_root, **kwargs)
    return LocalGitAdapter(repo_root=repo_root, **kwargs)


__all__ = [
    "ADO_ARTIFACT_NAME",
    "BB_ARTIFACT_NAME",
    "DEFAULT_STATUS_CONTEXT",
    "GL_ARTIFACT_NAME",
    "GT_ARTIFACT_NAME",
    "VALID_COMMIT_STATES",
    "AzureDevOpsAdapter",
    "BitbucketAdapter",
    "DetectionSource",
    "Forge",
    "ForgeDetection",
    "GiteaAdapter",
    "GitLabAdapter",
    "LocalGitAdapter",
    "VCSProvider",
    "detect_forge",
    "detect_forge_from_env",
    "detect_forge_from_remote_url",
    "findings_to_bitbucket_insights",
    "findings_to_bitbucket_insights_json",
    "findings_to_gitea_quality",
    "findings_to_gitea_quality_json",
    "findings_to_gitlab_code_quality",
    "findings_to_gitlab_code_quality_json",
    "get_origin_remote_url",
    "get_vcs_adapter",
    "remote_host",
]
