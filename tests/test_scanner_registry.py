"""Unit tests for Scanner Requirement & Target Mapping Catalog (v1.5 TASK-2.1)."""

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
)


class TestScannerRegistry(unittest.TestCase):
    """Verifies scanner registration, file mappings, and requirement classifications."""

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
        for filename in ("deployment.yaml", "service.yml", "charts/values.yaml"):
            scanners = {s.name: s for s in self.registry.get_scanners_for_file(filename)}
            self.assertIn("checkov", scanners, f"Expected Checkov for {filename}")
            self.assertIn("trivy", scanners, f"Expected Trivy for {filename}")
            self.assertIn("opa", scanners, f"Expected OPA for {filename}")

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

    def test_requirement_level_filtering(self):
        changeset = ["infra/main.tf", "scripts/setup.sh", "app/api.py", "README.md"]
        required = {s.name for s in get_required_scanners(changeset)}
        advisory = {s.name for s in get_advisory_scanners(changeset)}

        # Required set should contain checkov, shellcheck, ruff, validate_repo
        self.assertIn("checkov", required)
        self.assertIn("shellcheck", required)
        self.assertIn("ruff", required)
        self.assertIn("validate_repo", required)
        self.assertNotIn("trivy", required)
        self.assertNotIn("codeql", required)

        # Advisory set should contain trivy, codeql
        self.assertIn("trivy", advisory)
        self.assertIn("codeql", advisory)
        self.assertNotIn("checkov", advisory)
        self.assertNotIn("shellcheck", advisory)

    def test_changeset_mapping_structure(self):
        changeset = ["main.tf", "deploy.sh"]
        mapping = get_scanners_for_changeset(changeset)
        self.assertIn("main.tf", mapping)
        self.assertIn("deploy.sh", mapping)

        tf_tool_names = {s.name for s in mapping["main.tf"]}
        self.assertIn("checkov", tf_tool_names)
        self.assertIn("trivy", tf_tool_names)

        sh_tool_names = {s.name for s in mapping["deploy.sh"]}
        self.assertIn("shellcheck", sh_tool_names)

    def test_custom_scanner_registration(self):
        custom_registry = ScannerRegistry()
        custom_scanner = ScannerDefinition(
            name="custom-linter",
            display_name="Custom Linter",
            binary="custom-lint",
            requirement_level=RequirementLevel.REQUIRED,
            category=ScannerCategory.LINTER,
            description="Custom project linter",
            extensions={".custom"},
        )
        custom_registry.register(custom_scanner)

        matched = custom_registry.get_scanners_for_file("test.custom")
        self.assertEqual(len(matched), 1)
        self.assertEqual(matched[0].name, "custom-linter")
        self.assertTrue(matched[0].is_required)

        # Non-matching file
        self.assertEqual(len(custom_registry.get_scanners_for_file("test.py")), 0)


if __name__ == "__main__":
    unittest.main()
