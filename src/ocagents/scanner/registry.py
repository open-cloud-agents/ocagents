"""
Open Cloud Agents: Scanner Requirement & Target Mapping Catalog.

Defines the static scanner catalog, file pattern associations, and requirement
levels (required vs. advisory) in accordance with ADR-002 (Pillar 3:
Deterministic Pre-Flight Gate).
"""

from dataclasses import dataclass, field
from enum import Enum
import fnmatch
from pathlib import Path
from typing import Callable, Iterable, Sequence


class RequirementLevel(str, Enum):
    """Classification of scanner execution requirement."""
    REQUIRED = "required"
    ADVISORY = "advisory"


class ScannerCategory(str, Enum):
    """Domain classification for static analysis tools."""
    IAC = "iac"
    LINTER = "linter"
    SAST = "sast"
    VULNERABILITY = "vulnerability"
    POLICY = "policy"
    HYGIENE = "hygiene"


# Directories commonly containing Kubernetes, Helm, CloudFormation, or IaC configurations
IAC_OR_K8S_DIR_PARTS = frozenset({
    "k8s",
    "kubernetes",
    "helm",
    "charts",
    "manifests",
    "deploy",
    "deployment",
    "overlays",
    "base",
    "crds",
    "templates",
    "cloudformation",
    "cfn",
    "arm",
    "iac",
})

# Path segments strictly classified as non-IaC configuration/assets
NON_IAC_DIR_PARTS = frozenset({
    ".github",
    ".gitea",
    ".gitlab",
    "docs",
    "documentation",
    "site",
    "schemas",
    "node_modules",
    ".venv",
    "venv",
})

# Explicit non-IaC configuration files that must not trigger IaC scanners
NON_IAC_FILENAMES = frozenset({
    "package.json",
    "package-lock.json",
    "tsconfig.json",
    "tsconfig.base.json",
    "pyproject.toml",
    ".pre-commit-config.yaml",
    "mkdocs.yml",
    "mkdocs.yaml",
    "dependabot.yml",
    "dependabot.yaml",
    "csp-manifest.json",
    "upstream-sync.json",
    "exceptions.json",
})

# Filename tokens indicating a Kubernetes, Helm, or CloudFormation resource manifest
K8S_IAC_FILE_KEYWORDS = (
    "k8s",
    "kubernetes",
    "deployment",
    "service",
    "ingress",
    "configmap",
    "daemonset",
    "statefulset",
    "helm",
    "values",
    "chart",
    "cloudformation",
    "crd",
)


def is_k8s_or_iac_manifest(path: str | Path) -> bool:
    """
    Evaluates whether a JSON or YAML file represents an IaC, Kubernetes, or Helm manifest.
    Differentiates infrastructure manifests from package metadata, schemas, docs, and CI configs.
    """
    p = Path(path)
    name = p.name.lower()
    suffix = p.suffix.lower()

    # 1. Unambiguous IaC extensions always qualify
    if suffix in {".tf", ".tfvars", ".bicep"}:
        return True

    # 2. Only .yaml, .yml, and .json can be manifests
    if suffix not in {".yaml", ".yml", ".json"}:
        return False

    # 3. Known non-IaC files are excluded
    if name in NON_IAC_FILENAMES:
        return False

    # 4. Check for excluded directory paths (.github, docs, schemas)
    lower_parts = {part.lower() for part in p.parts}
    if lower_parts & NON_IAC_DIR_PARTS:
        return False

    # 5. Check if file is placed in an IaC / Kubernetes directory
    if lower_parts & IAC_OR_K8S_DIR_PARTS:
        return True

    # 6. Check for Kubernetes / Helm / IaC filename patterns
    stem = p.stem.lower()
    if any(keyword in stem for keyword in K8S_IAC_FILE_KEYWORDS):
        return True

    return False


@dataclass(frozen=True)
class ScannerDefinition:
    """Immutable specification of a static scanner and its target mapping."""
    name: str
    display_name: str
    binary: str
    requirement_level: RequirementLevel
    category: ScannerCategory
    description: str
    extensions: frozenset[str] = field(default_factory=frozenset)
    filenames: frozenset[str] = field(default_factory=frozenset)
    patterns: tuple[str, ...] = field(default_factory=tuple)
    excluded_patterns: tuple[str, ...] = field(default_factory=tuple)
    target_predicate: Callable[[Path], bool] | None = field(default=None, repr=False)
    output_format: str = "sarif"

    def __post_init__(self):
        # Enforce deep immutability on collections
        if not isinstance(self.extensions, frozenset):
            object.__setattr__(
                self, "extensions", frozenset(ext.lower() for ext in self.extensions)
            )
        if not isinstance(self.filenames, frozenset):
            object.__setattr__(
                self, "filenames", frozenset(fn.lower() for fn in self.filenames)
            )
        if not isinstance(self.patterns, tuple):
            object.__setattr__(self, "patterns", tuple(self.patterns))
        if not isinstance(self.excluded_patterns, tuple):
            object.__setattr__(self, "excluded_patterns", tuple(self.excluded_patterns))

    def matches_path(self, path: str | Path) -> bool:
        """
        Determines whether this scanner applies to a given file path.
        Checks explicit file names, normalized extensions, glob patterns, and predicates.
        """
        p = Path(path)
        name = p.name.lower()
        suffix = p.suffix.lower()
        posix_path = p.as_posix().lower()

        # 1. Excluded patterns take precedence
        for exc in self.excluded_patterns:
            if fnmatch.fnmatch(name, exc.lower()) or fnmatch.fnmatch(posix_path, exc.lower()):
                return False

        # 2. Explicit filename match (e.g. Dockerfile, Containerfile)
        if any(name == fn.lower() for fn in self.filenames):
            return True

        # 3. Direct unambiguous extension match (e.g. .tf, .sh, .py)
        if suffix and suffix in self.extensions:
            return True

        # 4. Glob pattern match
        for pat in self.patterns:
            if fnmatch.fnmatch(name, pat.lower()) or fnmatch.fnmatch(posix_path, pat.lower()):
                return True

        # 5. Targeted path predicate match (e.g. K8s / Helm manifest detection)
        if self.target_predicate is not None and self.target_predicate(p):
            return True

        return False

    @property
    def is_required(self) -> bool:
        """Convenience property for required gate enforcement."""
        return self.requirement_level == RequirementLevel.REQUIRED

    @property
    def is_advisory(self) -> bool:
        """Convenience property for advisory notification."""
        return self.requirement_level == RequirementLevel.ADVISORY


class ScannerRegistry:
    """Registry maintaining active static scanners and target file mappings."""

    def __init__(self, scanners: Sequence[ScannerDefinition] | None = None) -> None:
        self._scanners: dict[str, ScannerDefinition] = {}
        if scanners:
            for s in scanners:
                self.register(s)

    def register(self, scanner: ScannerDefinition, allow_override: bool = False) -> None:
        """
        Register a scanner definition in the catalog.
        Rejects duplicate scanner names unless allow_override=True is specified.
        """
        key = scanner.name.lower()
        if key in self._scanners and not allow_override:
            raise ValueError(
                f"Scanner '{scanner.name}' is already registered in this registry. "
                "Pass allow_override=True to explicitly replace an existing scanner definition."
            )
        self._scanners[key] = scanner

    def get_scanner(self, name: str) -> ScannerDefinition | None:
        """Retrieve a scanner by unique name."""
        return self._scanners.get(name.lower())

    def list_scanners(self) -> list[ScannerDefinition]:
        """List all registered scanners sorted by name."""
        return sorted(self._scanners.values(), key=lambda s: s.name)

    def get_scanners_for_file(self, file_path: str | Path) -> list[ScannerDefinition]:
        """Returns all scanners applicable to a single file path."""
        return [s for s in self.list_scanners() if s.matches_path(file_path)]

    def get_scanners_for_changeset(
        self, files: Iterable[str | Path]
    ) -> dict[str, list[ScannerDefinition]]:
        """
        Returns a mapping of each file in the changeset to its matching scanners.
        Files with no matching scanners map to an empty list.
        """
        mapping: dict[str, list[ScannerDefinition]] = {}
        for f in files:
            p_str = Path(f).as_posix()
            mapping[p_str] = self.get_scanners_for_file(f)
        return mapping

    def get_all_scanners_for_changeset(
        self, files: Iterable[str | Path]
    ) -> list[ScannerDefinition]:
        """Returns a deduplicated, sorted list of all scanners matching any file in the changeset."""
        matched: dict[str, ScannerDefinition] = {}
        for f in files:
            for s in self.get_scanners_for_file(f):
                matched[s.name] = s
        return sorted(matched.values(), key=lambda s: s.name)

    def get_required_scanners(
        self, files: Iterable[str | Path]
    ) -> list[ScannerDefinition]:
        """Returns deduplicated required scanners applicable to the changeset."""
        return [s for s in self.get_all_scanners_for_changeset(files) if s.is_required]

    def get_advisory_scanners(
        self, files: Iterable[str | Path]
    ) -> list[ScannerDefinition]:
        """Returns deduplicated advisory scanners applicable to the changeset."""
        return [s for s in self.get_all_scanners_for_changeset(files) if s.is_advisory]

    @classmethod
    def create_default(cls) -> "ScannerRegistry":
        """
        Creates and returns the canonical Open Cloud Agents scanner registry
        configured in accordance with ADR-002 specifications.
        """
        registry = cls()

        # 1. Checkov (Required for IaC & Kubernetes manifests)
        registry.register(
            ScannerDefinition(
                name="checkov",
                display_name="Checkov IaC Security Scanner",
                binary="checkov",
                requirement_level=RequirementLevel.REQUIRED,
                category=ScannerCategory.IAC,
                description="Static code analysis for infrastructure-as-code (IaC) security and compliance.",
                extensions=frozenset({".tf", ".tfvars", ".bicep"}),
                patterns=("*.tf", "*.tfvars", "*.bicep"),
                target_predicate=is_k8s_or_iac_manifest,
                output_format="sarif",
            )
        )

        # 2. Trivy (Advisory vulnerability & misconfiguration scanner for containers & IaC)
        registry.register(
            ScannerDefinition(
                name="trivy",
                display_name="Trivy Vulnerability & IaC Scanner",
                binary="trivy",
                requirement_level=RequirementLevel.ADVISORY,
                category=ScannerCategory.VULNERABILITY,
                description="Vulnerability and misconfiguration scanner for container images, Dockerfiles, and IaC.",
                extensions=frozenset({".tf", ".tfvars", ".bicep"}),
                filenames=frozenset({"Dockerfile", "Containerfile"}),
                patterns=("*Dockerfile*", "*Containerfile*", "*.tf", "*.tfvars", "*.bicep"),
                target_predicate=is_k8s_or_iac_manifest,
                output_format="sarif",
            )
        )

        # 3. ShellCheck (Required linter for POSIX / Bash shell scripts)
        registry.register(
            ScannerDefinition(
                name="shellcheck",
                display_name="ShellCheck Script Linter",
                binary="shellcheck",
                requirement_level=RequirementLevel.REQUIRED,
                category=ScannerCategory.LINTER,
                description="Static analysis and POSIX/bash linting for shell scripts.",
                extensions=frozenset({".sh", ".bash"}),
                patterns=("*.sh", "*.bash"),
                output_format="json",
            )
        )

        # 4. Ruff (Required linter & AST checker for Python source)
        registry.register(
            ScannerDefinition(
                name="ruff",
                display_name="Ruff Python Linter",
                binary="ruff",
                requirement_level=RequirementLevel.REQUIRED,
                category=ScannerCategory.LINTER,
                description="High-performance Python linter enforcing PEP 8 and static code standards.",
                extensions=frozenset({".py"}),
                patterns=("*.py",),
                output_format="sarif",
            )
        )

        # 5. CodeQL (Advisory SAST query engine for application source)
        registry.register(
            ScannerDefinition(
                name="codeql",
                display_name="GitHub CodeQL SAST Engine",
                binary="codeql",
                requirement_level=RequirementLevel.ADVISORY,
                category=ScannerCategory.SAST,
                description="Semantic Static Application Security Testing (SAST) query engine.",
                extensions=frozenset({".py"}),
                patterns=("*.py",),
                output_format="sarif",
            )
        )

        # 6. OPA / Rego (Advisory institutional policy evaluator for K8s manifests & IaC)
        registry.register(
            ScannerDefinition(
                name="opa",
                display_name="Open Policy Agent (Rego)",
                binary="opa",
                requirement_level=RequirementLevel.ADVISORY,
                category=ScannerCategory.POLICY,
                description="Institutional policy evaluator enforcing organizational guardrails on manifests.",
                target_predicate=is_k8s_or_iac_manifest,
                output_format="json",
            )
        )

        # 7. Repository Hygiene (Advisory validator for repository assets & specs)
        registry.register(
            ScannerDefinition(
                name="validate_repo",
                display_name="Repository Hygiene Validator",
                binary="python3",
                requirement_level=RequirementLevel.ADVISORY,
                category=ScannerCategory.HYGIENE,
                description="Open Cloud Agents repository hygiene, link integrity, and spec validator.",
                extensions=frozenset({".md", ".sh"}),
                patterns=("skills/**", "agents/**", "rules/**", "docs/**", "*.md", "*.sh"),
                filenames=frozenset(
                    {"SKILL.md", "AGENTS.md", "README.md", "CONTRIBUTING.md", "SECURITY.md", "LICENSE"}
                ),
                output_format="json",
            )
        )

        return registry


# Module-level default singleton registry
_DEFAULT_REGISTRY = ScannerRegistry.create_default()


def get_default_registry() -> ScannerRegistry:
    """Access the global default ScannerRegistry instance."""
    return _DEFAULT_REGISTRY


def get_scanners_for_file(path: str | Path) -> list[ScannerDefinition]:
    """Convenience helper: get scanners matching a single file path."""
    return _DEFAULT_REGISTRY.get_scanners_for_file(path)


def get_scanners_for_changeset(files: Iterable[str | Path]) -> dict[str, list[ScannerDefinition]]:
    """Convenience helper: get mapping of files to matching scanners."""
    return _DEFAULT_REGISTRY.get_scanners_for_changeset(files)


def get_required_scanners(files: Iterable[str | Path]) -> list[ScannerDefinition]:
    """Convenience helper: get deduplicated required scanners for a changeset."""
    return _DEFAULT_REGISTRY.get_required_scanners(files)


def get_advisory_scanners(files: Iterable[str | Path]) -> list[ScannerDefinition]:
    """Convenience helper: get deduplicated advisory scanners for a changeset."""
    return _DEFAULT_REGISTRY.get_advisory_scanners(files)
