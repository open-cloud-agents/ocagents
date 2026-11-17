"""
Unit tests for Open Cloud Agents: Dynamic Forge Detection Engine (ADR-003, Multi-VCS Phase 1).
"""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ocagents.vcs import (
    DetectionSource,
    Forge,
    VCSProvider,
    detect_forge,
    detect_forge_from_env,
    detect_forge_from_remote_url,
    get_origin_remote_url,
    remote_host,
)
from ocagents.vcs import detector as detector_module

HAS_GIT = shutil.which("git") is not None


class TestEnvironmentDetection(unittest.TestCase):
    """CI environment variable matrix across all supported forges."""

    def test_env_matrix(self):
        cases = [
            ({"GITHUB_ACTIONS": "true"}, Forge.GITHUB, "GITHUB_ACTIONS=true"),
            ({"GITLAB_CI": "true"}, Forge.GITLAB, "GITLAB_CI=true"),
            ({"TF_BUILD": "True"}, Forge.AZURE_DEVOPS, "TF_BUILD=True"),
            ({"BITBUCKET_BUILD_NUMBER": "42"}, Forge.BITBUCKET, "BITBUCKET_BUILD_NUMBER=<set>"),
            ({"GITEA_ACTIONS": "true"}, Forge.GITEA, "GITEA_ACTIONS=true"),
            ({"FORGEJO_ACTIONS": "true"}, Forge.GITEA, "FORGEJO_ACTIONS=true"),
        ]
        for env, forge, evidence in cases:
            with self.subTest(env=env):
                result = detect_forge_from_env(env)
                self.assertIsNotNone(result)
                self.assertEqual(result.forge, forge)
                self.assertEqual(result.source, DetectionSource.ENVIRONMENT)
                self.assertEqual(result.evidence, evidence)
                self.assertTrue(result.is_ci)

    def test_gitea_and_forgejo_win_over_github_compat_variable(self):
        """act-based runners also set GITHUB_ACTIONS=true; the specific forge must win."""
        for specific in ("GITEA_ACTIONS", "FORGEJO_ACTIONS"):
            with self.subTest(variable=specific):
                result = detect_forge_from_env({"GITHUB_ACTIONS": "true", specific: "true"})
                self.assertEqual(result.forge, Forge.GITEA)

    def test_values_are_case_insensitive_and_trimmed(self):
        self.assertEqual(detect_forge_from_env({"TF_BUILD": " TRUE "}).forge, Forge.AZURE_DEVOPS)
        self.assertEqual(detect_forge_from_env({"GITLAB_CI": "True"}).forge, Forge.GITLAB)

    def test_false_or_empty_values_are_ignored(self):
        for env in (
            {"GITLAB_CI": "false"},
            {"GITHUB_ACTIONS": ""},
            {"BITBUCKET_BUILD_NUMBER": "   "},
            {"TF_BUILD": "0"},
            {},
        ):
            with self.subTest(env=env):
                self.assertIsNone(detect_forge_from_env(env))

    def test_unrelated_ci_variables_do_not_match(self):
        self.assertIsNone(detect_forge_from_env({"CI": "true", "JENKINS_URL": "http://jenkins"}))


class TestRemoteUrlDetection(unittest.TestCase):
    """Git remote URL parsing for hosted and self-hosted forges."""

    def test_remote_url_matrix(self):
        cases = [
            ("https://github.com/open-cloud-agents/ocagents.git", Forge.GITHUB),
            ("git@github.com:open-cloud-agents/ocagents.git", Forge.GITHUB),
            ("ssh://git@github.com/open-cloud-agents/ocagents.git", Forge.GITHUB),
            ("https://octo.ghe.com/team/repo.git", Forge.GITHUB),
            ("https://github.corp.example/team/repo.git", Forge.GITHUB),
            ("https://gitlab.com/group/sub/project.git", Forge.GITLAB),
            ("ssh://git@gitlab.example.com:2222/group/project.git", Forge.GITLAB),
            ("git@gitlab-ee.corp.example:group/project.git", Forge.GITLAB),
            ("https://myorg@dev.azure.com/myorg/project/_git/repo", Forge.AZURE_DEVOPS),
            ("git@ssh.dev.azure.com:v3/myorg/project/repo", Forge.AZURE_DEVOPS),
            ("https://myorg.visualstudio.com/project/_git/repo", Forge.AZURE_DEVOPS),
            ("https://bitbucket.org/team/repo.git", Forge.BITBUCKET),
            ("git@bitbucket.org:team/repo.git", Forge.BITBUCKET),
            ("https://bitbucket.corp.example/scm/team/repo.git", Forge.BITBUCKET),
            ("https://codeberg.org/user/repo.git", Forge.GITEA),
            ("https://gitea.example.org/user/repo.git", Forge.GITEA),
            ("git@forgejo.example.org:user/repo.git", Forge.GITEA),
        ]
        for url, forge in cases:
            with self.subTest(url=url):
                self.assertEqual(detect_forge_from_remote_url(url), forge)

    def test_unknown_or_invalid_remotes_return_none(self):
        for url in (
            "",
            "   ",
            "https://git.example.com/team/repo.git",
            "/srv/git/repo.git",
            "file:///srv/git/repo.git",
            "not a url",
            "https://notgithub.com/team/repo.git",
        ):
            with self.subTest(url=url):
                self.assertIsNone(detect_forge_from_remote_url(url))

    def test_lookalike_domains_are_not_trusted(self):
        """A suffix match must be on a dot boundary: evilgitlab.com is not gitlab.com."""
        self.assertIsNone(detect_forge_from_remote_url("https://evilgitlab.com/x/y.git"))
        self.assertIsNone(detect_forge_from_remote_url("https://mydev.azure.com.example/x"))

    def test_remote_host_strips_credentials(self):
        url = "https://user:ghp_SECRETTOKEN@github.com/team/repo.git"
        self.assertEqual(remote_host(url), "github.com")


class TestDetectForge(unittest.TestCase):
    """End-to-end precedence: environment, then git remote, then local fallback."""

    def test_environment_takes_precedence_over_remote(self):
        with mock.patch.object(detector_module, "get_origin_remote_url", return_value="https://gitlab.com/g/p.git") as remote:
            result = detect_forge(env={"GITHUB_ACTIONS": "true"})
        self.assertEqual(result.forge, Forge.GITHUB)
        remote.assert_not_called()

    def test_falls_back_to_git_remote(self):
        with mock.patch.object(detector_module, "get_origin_remote_url", return_value="git@gitlab.com:g/p.git"):
            result = detect_forge(env={})
        self.assertEqual(result.forge, Forge.GITLAB)
        self.assertEqual(result.source, DetectionSource.GIT_REMOTE)
        self.assertEqual(result.evidence, "remote host gitlab.com")
        self.assertFalse(result.is_ci)

    def test_evidence_never_contains_credentials(self):
        url = "https://oauth2:glpat-SECRETTOKEN@gitlab.com/g/p.git"
        with mock.patch.object(detector_module, "get_origin_remote_url", return_value=url):
            result = detect_forge(env={})
        self.assertEqual(result.forge, Forge.GITLAB)
        self.assertNotIn("SECRET", result.evidence)
        self.assertNotIn("oauth2", result.evidence)

    def test_falls_back_to_local_when_nothing_matches(self):
        for remote in (None, "https://git.example.com/team/repo.git"):
            with self.subTest(remote=remote):
                with mock.patch.object(detector_module, "get_origin_remote_url", return_value=remote):
                    result = detect_forge(env={})
                self.assertEqual(result.forge, Forge.LOCAL)
                self.assertEqual(result.source, DetectionSource.FALLBACK)


class TestOriginRemoteUrl(unittest.TestCase):
    """Reading the origin remote must never raise."""

    def test_missing_git_binary_returns_none(self):
        with mock.patch.object(detector_module.subprocess, "run", side_effect=FileNotFoundError("git")):
            self.assertIsNone(get_origin_remote_url("."))

    def test_timeout_returns_none(self):
        timeout = subprocess.TimeoutExpired(cmd="git", timeout=5)
        with mock.patch.object(detector_module.subprocess, "run", side_effect=timeout):
            self.assertIsNone(get_origin_remote_url("."))

    def test_non_zero_exit_returns_none(self):
        failed = subprocess.CompletedProcess(args=["git"], returncode=2, stdout="", stderr="error: No such remote 'origin'")
        with mock.patch.object(detector_module.subprocess, "run", return_value=failed):
            self.assertIsNone(get_origin_remote_url("."))

    @unittest.skipUnless(HAS_GIT, "git is not installed")
    def test_reads_origin_from_real_repository(self):
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(["git", "init", "-q", tmp], check=True)
            self.assertIsNone(get_origin_remote_url(tmp))
            subprocess.run(
                ["git", "-C", tmp, "remote", "add", "origin", "git@codeberg.org:user/repo.git"], check=True
            )
            self.assertEqual(get_origin_remote_url(tmp), "git@codeberg.org:user/repo.git")
            result = detect_forge(env={}, repo_root=tmp)
            self.assertEqual(result.forge, Forge.GITEA)

    @unittest.skipUnless(HAS_GIT, "git is not installed")
    def test_directory_outside_a_repository_returns_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            outside = Path(tmp) / "plain"
            outside.mkdir()
            with mock.patch.dict("os.environ", {"GIT_CEILING_DIRECTORIES": tmp}):
                self.assertIsNone(get_origin_remote_url(outside))


class TestProviderContract(unittest.TestCase):
    def test_vcs_provider_is_abstract(self):
        with self.assertRaises(TypeError):
            VCSProvider()


if __name__ == "__main__":
    unittest.main()
