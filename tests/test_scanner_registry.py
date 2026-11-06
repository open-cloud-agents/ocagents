"""Unit tests for Scanner Requirement & Target Mapping Catalog (v1.5 TASK-2.1)."""

from dataclasses import FrozenInstanceError
import unittest
from pathlib import Path

from ocagents.scanner import (
    RequirementLevel,
    ScannerCategory,
    ScannerDefinition,
    ScannerRegistry,
    get_advisory_scanners,
    get_default_registry,
    get_required_scanners,
    get_scanners_for_changeset,
    get_scanners_for_file,
    is_k8s_or_iac_manifest,
)


class TestScannerRegistry(unittest.TestCase):
    """Verifies scanner registration, file mappings, deep immutability, and requirement classifications."""

    def setUp(self):
        self.registry = get_default_registry()

    def test_default_registry_has_canonical_scanners(self):
        scanners = {s.name: s for s in self.registry.list_scanners()}
        expected_names = {"checkov", "trivy", "shellcheck", "ruff", "codeql", "opa", "validate_repo"}
        self.assertTrue(expected_names.issubset(set(scanners.keys())))

    def test_iac_target_mapping(self):
        """Map .tf, .tfvars, .bicep -> Checkov (required), Trivy (advisory)."""
        for filename in ("main.tf", "prod.tfvars", "infra.bicep"):
            scanners = {s.name: s for s in self.registry.get_scanners_for_file(filename)}
            self.assertIn("checkov", scanners, f"Expected Checkov for {filename}")
            self.assertIn("trivy", scanners, f"Expected Trivy for {filename}")
            self.assertTrue(scanners["checkov"].is_required)
            self.assertTrue(scanners["trivy"].is_advisory)

    def test_kubernetes_and_helm_manifest_mapping(self):
        """Map .yaml, .yml (K8s/Helm) -> Checkov, Trivy, OPA/Rego."""
        for filename in ("k8s/deployment.yaml", "manifests/service.yml", "charts/values.yaml", "overlays/prod/app.yaml"):
            scanners = {s.name: s for s in self.registry.get_scanners_for_file(filename)}
            self.assertIn("checkov", scanners, f"Expected Checkov for {filename}")
            self.assertIn("trivy", scanners, f"Expected Trivy for {filename}")
            self.assertIn("opa", scanners, f"Expected OPA for {filename}")

    def test_non_iac_yaml_and_json_do_not_require_checkov(self):
        """Arbitrary JSON/YAML (package metadata, CI configs, docs, schemas) must NOT trigger Checkov or OPA."""
        non_iac_files = [
            "package.json",
            "package-lock.json",
            "tsconfig.json",
            ".github/workflows/ci.yml",
            ".github/workflows/autonomous-gatekeeper.yaml",
            "mkdocs.yml",
            ".pre-commit-config.yaml",
            "schemas/v1/finding.json",
            "docs/config.json",
        ]
        for filename in non_iac_files:
            scanners = {s.name: s for s in self.registry.get_scanners_for_file(filename)}
            self.assertNotIn(
                "checkov",
                scanners,
                f"Non-IaC file '{filename}' must not trigger Checkov as a required scanner",
            )
            self.assertNotIn(
                "opa",
                scanners,
                f"Non-IaC file '{filename}' must not trigger OPA manifest policy evaluation",
            )
            # Generic JSON/YAML, CI configs, schemas, and docs must not trigger any required scanner gate
            required_scanners = [s.name for s in self.registry.get_scanners_for_file(filename) if s.is_required]
            self.assertEqual(
                required_scanners,
                [],
                f"Non-IaC/config file '{filename}' must not trigger any required scanner gate: {required_scanners}",
            )

    def test_is_k8s_or_iac_manifest_helper(self):
        self.assertTrue(is_k8s_or_iac_manifest("main.tf"))
        self.assertTrue(is_k8s_or_iac_manifest("k8s/deployment.yaml"))
        self.assertTrue(is_k8s_or_iac_manifest("charts/app/values.yaml"))
        self.assertTrue(is_k8s_or_iac_manifest("cloudformation/network.json"))
        self.assertTrue(is_k8s_or_iac_manifest("service.yaml"))

        self.assertFalse(is_k8s_or_iac_manifest("package.json"))
        self.assertFalse(is_k8s_or_iac_manifest(".github/workflows/ci.yml"))
        self.assertFalse(is_k8s_or_iac_manifest("docs/index.md"))
        self.assertFalse(is_k8s_or_iac_manifest("schemas/v1/finding.json"))
        self.assertFalse(is_k8s_or_iac_manifest("random.yaml"))

    def test_shell_script_mapping(self):
        """Map .sh, .bash -> ShellCheck (required)."""
        for filename in ("deploy.sh", "scripts/ci/audit.bash"):
            scanners = {s.name: s for s in self.registry.get_scanners_for_file(filename)}
            self.assertIn("shellcheck", scanners, f"Expected ShellCheck for {filename}")
            self.assertTrue(scanners["shellcheck"].is_required)
            self.assertEqual(scanners["shellcheck"].category, ScannerCategory.LINTER)

    def test_python_source_mapping(self):
        """Map .py -> Ruff (required), CodeQL (advisory)."""
        scanners = {s.name: s for s in self.registry.get_scanners_for_file("app/main.py")}
        self.assertIn("ruff", scanners)
        self.assertIn("codeql", scanners)
        self.assertTrue(scanners["ruff"].is_required)
        self.assertTrue(scanners["codeql"].is_advisory)

    def test_containerfile_mapping(self):
        """Map Dockerfile, Containerfile -> Trivy."""
        for filename in ("Dockerfile", "Containerfile", "services/web/Dockerfile.prod"):
            scanners = {s.name: s for s in self.registry.get_scanners_for_file(filename)}
            self.assertIn("trivy", scanners, f"Expected Trivy for {filename}")

    def test_deep_immutability(self):
        """Verify ScannerDefinition collections are frozenset/tuple and reject mutation."""
        checkov = self.registry.get_scanner("checkov")
        self.assertIsNotNone(checkov)
        self.assertIsInstance(checkov.extensions, frozenset)
        self.assertIsInstance(checkov.filenames, frozenset)
        self.assertIsInstance(checkov.patterns, tuple)

        # 1. Attempting in-place mutation of collection
        with self.assertRaises(AttributeError):
            checkov.extensions.add(".new")  # frozenset has no add

        # 2. Attempting field reassignment on frozen dataclass
        with self.assertRaises(FrozenInstanceError):
            checkov.extensions = frozenset({".other"})

    def test_duplicate_registration_rejected(self):
        """ScannerRegistry rejects duplicate scanner names unless allow_override is set."""
        registry = ScannerRegistry()
        scanner = ScannerDefinition(
            name="test-scanner",
            display_name="Test Scanner",
            binary="test",
            requirement_level=RequirementLevel.REQUIRED,
            category=ScannerCategory.LINTER,
            description="Test",
        )
        registry.register(scanner)

        # Duplicate without override must fail
        with self.assertRaises(ValueError) as ctx:
            registry.register(scanner)
        self.assertIn("already registered", str(ctx.exception))

        # Duplicate with allow_override=True must succeed
        scanner_v2 = ScannerDefinition(
            name="test-scanner",
            display_name="Test Scanner v2",
            binary="test",
            requirement_level=RequirementLevel.ADVISORY,
            category=ScannerCategory.LINTER,
            description="Test v2",
        )
        registry.register(scanner_v2, allow_override=True)
        self.assertEqual(registry.get_scanner("test-scanner").display_name, "Test Scanner v2")

    def test_requirement_level_filtering(self):
        changeset = ["infra/main.tf", "scripts/setup.sh", "app/api.py", "README.md", "package.json"]
        required = {s.name for s in get_required_scanners(changeset)}
        advisory = {s.name for s in get_advisory_scanners(changeset)}

        # Required set should contain only genuine code/IaC scanners: checkov, shellcheck, ruff
        self.assertIn("checkov", required)
        self.assertIn("shellcheck", required)
        self.assertIn("ruff", required)
        self.assertNotIn("validate_repo", required)
        self.assertNotIn("trivy", required)
        self.assertNotIn("codeql", required)

        # Advisory set should contain trivy, codeql, validate_repo
        self.assertIn("trivy", advisory)
        self.assertIn("codeql", advisory)
        self.assertIn("validate_repo", advisory)
        self.assertNotIn("checkov", advisory)
        self.assertNotIn("shellcheck", advisory)

    def test_docs_and_configs_do_not_trigger_required_gates(self):
        """Docs, schemas, templates, and config files must never trigger required gates."""
        doc_and_config_files = [
            "docs/index.md",
            "docs/roadmap.md",
            "schemas/v1/finding.json",
            "package.json",
            "mkdocs.yml",
            ".pre-commit-config.yaml",
            "templates/notice.tmpl",
        ]
        required = get_required_scanners(doc_and_config_files)
        self.assertEqual(
            required,
            [],
            f"Expected 0 required scanners for doc/config/schema changeset, got: {[s.name for s in required]}",
        )

    def test_changeset_mapping_structure(self):
        changeset = ["main.tf", "deploy.sh", "package.json"]
        mapping = get_scanners_for_changeset(changeset)
        self.assertIn("main.tf", mapping)
        self.assertIn("deploy.sh", mapping)
        self.assertIn("package.json", mapping)

        tf_tool_names = {s.name for s in mapping["main.tf"]}
        self.assertIn("checkov", tf_tool_names)
        self.assertIn("trivy", tf_tool_names)

        sh_tool_names = {s.name for s in mapping["deploy.sh"]}
        self.assertIn("shellcheck", sh_tool_names)

        pkg_tool_names = {s.name for s in mapping["package.json"]}
        self.assertNotIn("checkov", pkg_tool_names)
        self.assertNotIn("opa", pkg_tool_names)
        self.assertNotIn("validate_repo", pkg_tool_names)


if __name__ == "__main__":
    unittest.main()
