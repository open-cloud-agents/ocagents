"""
Open Cloud Agents: Multi-VCS Provider Adapter Engine (ADR-003).
"""

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
from ocagents.vcs.local import LocalGitAdapter

__all__ = [
    "DEFAULT_STATUS_CONTEXT",
    "VALID_COMMIT_STATES",
    "DetectionSource",
    "Forge",
    "ForgeDetection",
    "LocalGitAdapter",
    "VCSProvider",
    "detect_forge",
    "detect_forge_from_env",
    "detect_forge_from_remote_url",
    "get_origin_remote_url",
    "remote_host",
]
