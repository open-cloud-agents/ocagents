"""
Open Cloud Agents: Dynamic Forge Detection Engine (ADR-003, Multi-VCS Phase 1).

Identifies which version control forge the CLI is running against, so the
matching VCSProvider adapter can be selected. Detection runs in three steps:

  1. CI environment variables set by the forge's pipeline runner (most reliable).
  2. The URL of the ``origin`` git remote (local shells and unrecognised runners).
  3. Fallback to the local developer shell, which makes no remote API calls.
"""

from __future__ import annotations

import enum
import os
import re
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

GIT_TIMEOUT_SECONDS = 5


class Forge(str, enum.Enum):
    """Supported version control forges."""

    GITHUB = "github"
    GITLAB = "gitlab"
    AZURE_DEVOPS = "azure_devops"
    BITBUCKET = "bitbucket"
    GITEA = "gitea"  # Gitea and its fork Forgejo share the same API
    LOCAL = "local"


class DetectionSource(str, enum.Enum):
    """Where the detection result came from."""

    ENVIRONMENT = "environment"
    GIT_REMOTE = "git_remote"
    FALLBACK = "fallback"


@dataclass(frozen=True)
class ForgeDetection:
    """Result of forge detection.

    ``evidence`` explains the decision (for example ``GITLAB_CI=true`` or
    ``remote host gitlab.com``). It never contains credentials.
    """

    forge: Forge
    source: DetectionSource
    evidence: str

    @property
    def is_ci(self) -> bool:
        """True when the forge was identified from a CI pipeline environment."""
        return self.source is DetectionSource.ENVIRONMENT


# (variable, required value or None for "any non-empty value", forge)
#
# Order matters: the Gitea and Forgejo runners are built on nektos/act, which also
# sets GITHUB_ACTIONS=true for compatibility, so their own variables must be
# checked before GitHub's.
_ENV_RULES: tuple[tuple[str, str | None, Forge], ...] = (
    ("GITEA_ACTIONS", "true", Forge.GITEA),
    ("FORGEJO_ACTIONS", "true", Forge.GITEA),
    ("GITLAB_CI", "true", Forge.GITLAB),
    ("TF_BUILD", "true", Forge.AZURE_DEVOPS),  # Azure Pipelines sets "True"
    ("BITBUCKET_BUILD_NUMBER", None, Forge.BITBUCKET),
    ("GITHUB_ACTIONS", "true", Forge.GITHUB),
)

# Exact hosts (or parent domains) of the hosted forges.
_HOST_SUFFIX_RULES: tuple[tuple[str, Forge], ...] = (
    ("github.com", Forge.GITHUB),
    ("ghe.com", Forge.GITHUB),  # GitHub Enterprise Cloud with data residency
    ("gitlab.com", Forge.GITLAB),
    ("dev.azure.com", Forge.AZURE_DEVOPS),
    ("visualstudio.com", Forge.AZURE_DEVOPS),  # legacy Azure DevOps URLs
    ("bitbucket.org", Forge.BITBUCKET),
    ("codeberg.org", Forge.GITEA),  # public Forgejo instance
)

# Hostname words that identify common self-hosted installs, e.g. gitlab.corp.example.
# This only chooses which adapter to use; it is not a trust decision about the host.
_HOST_LABEL_RULES: tuple[tuple[str, Forge], ...] = (
    ("gitlab", Forge.GITLAB),
    ("bitbucket", Forge.BITBUCKET),
    ("gitea", Forge.GITEA),
    ("forgejo", Forge.GITEA),
    ("github", Forge.GITHUB),  # GitHub Enterprise Server, e.g. github.corp.example
)

# scp-like SSH syntax: [user@]host:path (no scheme)
_SCP_LIKE = re.compile(r"^(?:[^@/\s]+@)?(?P<host>[^:/\s]+):(?!//)")


def detect_forge_from_env(env: Mapping[str, str] | None = None) -> ForgeDetection | None:
    """Identifies the forge from CI environment variables, or returns None."""
    env = os.environ if env is None else env
    for name, expected, forge in _ENV_RULES:
        value = (env.get(name) or "").strip()
        if not value:
            continue
        if expected is None or value.lower() == expected:
            shown = value if expected is not None else "<set>"
            return ForgeDetection(forge, DetectionSource.ENVIRONMENT, f"{name}={shown}")
    return None


def remote_host(url: str) -> str | None:
    """Extracts the lower-case host name from a git remote URL.

    Supports ``https://``, ``ssh://`` and scp-like ``git@host:owner/repo`` forms.
    User names and passwords embedded in the URL are discarded.
    """
    url = (url or "").strip()
    if not url:
        return None
    if "://" in url:
        try:
            host = urlsplit(url).hostname
        except ValueError:
            return None
    else:
        match = _SCP_LIKE.match(url)
        host = match.group("host") if match else None
    return host.lower().rstrip(".") if host else None


def detect_forge_from_remote_url(url: str) -> Forge | None:
    """Identifies the forge from a git remote URL, or returns None if unknown."""
    host = remote_host(url)
    if not host:
        return None
    for suffix, forge in _HOST_SUFFIX_RULES:
        if host == suffix or host.endswith("." + suffix):
            return forge
    labels = set(re.split(r"[.\-]", host))
    for label, forge in _HOST_LABEL_RULES:
        if label in labels:
            return forge
    return None


def get_origin_remote_url(repo_root: str | Path | None = None) -> str | None:
    """Returns the URL of the ``origin`` remote, or None if it cannot be read.

    Never raises: a missing git binary, a directory that is not a repository,
    a missing ``origin`` remote, or a timeout all return None.
    """
    root = Path(repo_root) if repo_root is not None else Path.cwd()
    try:
        proc = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    url = proc.stdout.strip()
    return url or None


def detect_forge(
    env: Mapping[str, str] | None = None,
    repo_root: str | Path | None = None,
) -> ForgeDetection:
    """Detects the forge: CI environment first, then the origin remote, else local."""
    from_env = detect_forge_from_env(env)
    if from_env is not None:
        return from_env

    url = get_origin_remote_url(repo_root)
    if url:
        forge = detect_forge_from_remote_url(url)
        if forge is not None:
            return ForgeDetection(forge, DetectionSource.GIT_REMOTE, f"remote host {remote_host(url)}")

    return ForgeDetection(Forge.LOCAL, DetectionSource.FALLBACK, "no CI environment or recognised git remote")
