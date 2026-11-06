"""Open Policy Agent (Rego) Policy Evaluator Integration.

Evaluates Terraform plans and Kubernetes manifests against institutional security
and reliability policies (Rule 01: Destructive Actions, Rule 04: Well-Architected Invariants).
Integrates both the external 'opa' CLI binary (when present) and a built-in zero-dependency
institutional policy evaluator for maximum portability.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any

from ocagents.findings.normalizer import (
    CANONICAL_SCHEMA_URI,
    RULE_DESTRUCTIVE,
    RULE_TO_DEFAULT_RECOMMENDATION,
    RULE_WELL_ARCHITECTED,
    clean_artifact_uri,
    compute_finding_id,
    map_category,
)
from ocagents.findings.provenance import resolve_default_repo_root
from ocagents.scanner.diff_filter import filter_findings_by_diff

DEFAULT_POLICIES_DIR = Path(__file__).resolve().parent / "policies"
ROOT_POLICIES_DIR = Path(__file__).resolve().parent.parent.parent.parent / "policies" / "rego"

STATEFUL_RESOURCE_PREFIXES = (
    "aws_db_instance",
    "aws_rds_cluster",
    "aws_s3_bucket",
    "google_sql_database_instance",
    "google_storage_bucket",
    "azurerm_mssql_database",
    "azurerm_storage_account",
    "kubernetes_persistent_volume",
)

K8S_WORKLOAD_KINDS = frozenset({"Deployment", "StatefulSet", "DaemonSet", "Job", "Pod"})


def _parse_scalar(val: str) -> Any:
    """Parses a YAML scalar value into a typed Python object."""
    val = val.strip()
    val_lower = val.lower()
    if val_lower in ("null", "none", "~"):
        return None
    if val_lower == "true":
        return True
    if val_lower == "false":
        return False
    try:
        return int(val)
    except ValueError:
        pass
    try:
        return float(val)
    except ValueError:
        pass
    return val.strip('"\'')


def parse_manifest_documents(content: str) -> list[dict[str, Any]]:
    """Parses single- or multi-document JSON/YAML Kubernetes manifests."""
    # 1. Fast path: JSON payload
    try:
        parsed = json.loads(content)
        if isinstance(parsed, dict):
            return [parsed]
        if isinstance(parsed, list):
            return [doc for doc in parsed if isinstance(doc, dict)]
    except Exception:
        pass

    # 2. Multi-document YAML splitting
    docs: list[dict[str, Any]] = []
    chunks = content.split("\n---")
    for chunk in chunks:
        lines: list[tuple[int, str]] = []
        for raw in chunk.splitlines():
            l = raw
            if "#" in l:
                l = l.split("#")[0]
            if l.strip():
                indent = len(l) - len(l.lstrip())
                lines.append((indent, l.strip()))
        if not lines:
            continue

        def parse_block(i: int, min_indent: int) -> tuple[Any, int]:
            if i >= len(lines):
                return None, i

            first_indent, first_text = lines[i]
            if first_indent < min_indent:
                return None, i

            if first_text.startswith("- "):
                res_list: list[Any] = []
                while i < len(lines):
                    ind, txt = lines[i]
                    if ind < min_indent:
                        break
                    if txt.startswith("- "):
                        content_str = txt[2:].strip()
                        if ":" in content_str:
                            k, v = content_str.split(":", 1)
                            k, v = k.strip(), v.strip()
                            item_dict: dict[str, Any] = {}
                            if v:
                                item_dict[k] = _parse_scalar(v)
                                i += 1
                            else:
                                child, i = parse_block(i + 1, ind + 1)
                                item_dict[k] = child if child is not None else {}

                            while i < len(lines):
                                s_ind, s_txt = lines[i]
                                if s_ind <= ind:
                                    break
                                if ":" in s_txt:
                                    sk, sv = s_txt.split(":", 1)
                                    sk, sv = sk.strip(), sv.strip()
                                    if sv:
                                        item_dict[sk] = _parse_scalar(sv)
                                        i += 1
                                    else:
                                        child, i = parse_block(i + 1, s_ind + 1)
                                        item_dict[sk] = child if child is not None else {}
                                else:
                                    i += 1
                            res_list.append(item_dict)
                        else:
                            res_list.append(_parse_scalar(content_str))
                            i += 1
                    else:
                        break
                return res_list, i
            else:
                res_dict: dict[str, Any] = {}
                while i < len(lines):
                    ind, txt = lines[i]
                    if ind < min_indent:
                        break
                    if ":" in txt:
                        k, v = txt.split(":", 1)
                        k, v = k.strip(), v.strip()
                        if v:
                            res_dict[k] = _parse_scalar(v)
                            i += 1
                        else:
                            child, i = parse_block(i + 1, ind + 1)
                            res_dict[k] = child if child is not None else {}
                    else:
                        i += 1
                return res_dict, i

        parsed_doc, _ = parse_block(0, 0)
        if isinstance(parsed_doc, dict):
            docs.append(parsed_doc)
        elif isinstance(parsed_doc, list):
            for d in parsed_doc:
                if isinstance(d, dict):
                    docs.append(d)

    return docs


class OpaEvaluator:
    """Evaluates Terraform plans and Kubernetes manifests against institutional policies."""

    def __init__(
        self,
        repo_root: Path | None = None,
        policy_dir: Path | None = None,
        default_agent: str = "opa",
        evidence_scheme: str = "repo",
        use_cli_if_available: bool = True,
    ) -> None:
        self.repo_root = (repo_root or resolve_default_repo_root()).resolve()
        self.policy_dir = (
            Path(policy_dir).resolve()
            if policy_dir
            else (
                ROOT_POLICIES_DIR if ROOT_POLICIES_DIR.is_dir() else DEFAULT_POLICIES_DIR
            )
        )
        self.default_agent = default_agent
        self.evidence_scheme = evidence_scheme if evidence_scheme in {"repo", "diff"} else "repo"
        self.use_cli_if_available = use_cli_if_available
        self._opa_cli = shutil.which("opa") if use_cli_if_available else None

    @property
    def has_opa_cli(self) -> bool:
        """Indicates whether native 'opa' CLI binary is installed and active."""
        return self._opa_cli is not None

    def evaluate_terraform_plan(
        self,
        plan_input: dict[str, Any] | str | Path,
        target_file: str = "infra/main.tf",
        diff_text: str | None = None,
    ) -> list[dict[str, Any]]:
        """Evaluates a Terraform plan against institutional destruction and well-architected policies."""
        plan_dict = self._load_json(plan_input)
        clean_file = clean_artifact_uri(target_file, repo_root=self.repo_root)

        findings = self._evaluate_terraform_builtin(plan_dict, target_file=clean_file)

        if diff_text:
            findings = filter_findings_by_diff(
                findings,
                diff_text,
                convert_to_diff_scheme=(self.evidence_scheme == "diff"),
            )

        return findings

    def evaluate_kubernetes_manifest(
        self,
        manifest_input: dict[str, Any] | list[dict[str, Any]] | str | Path,
        target_file: str = "k8s/deployment.yaml",
        diff_text: str | None = None,
    ) -> list[dict[str, Any]]:
        """Evaluates Kubernetes workload manifests against institutional reliability and security guardrails."""
        docs = self._load_manifest_docs(manifest_input)
        clean_file = clean_artifact_uri(target_file, repo_root=self.repo_root)

        findings: list[dict[str, Any]] = []
        for doc in docs:
            doc_findings = self._evaluate_k8s_doc_builtin(doc, target_file=clean_file)
            findings.extend(doc_findings)

        if diff_text:
            findings = filter_findings_by_diff(
                findings,
                diff_text,
                convert_to_diff_scheme=(self.evidence_scheme == "diff"),
            )

        return findings

    def evaluate_file(
        self,
        file_path: str | Path,
        diff_text: str | None = None,
    ) -> list[dict[str, Any]]:
        """Evaluates a single file, automatically detecting whether it is a Terraform plan or K8s manifest."""
        p = Path(file_path)
        if not p.is_file():
            raise FileNotFoundError(f"Target file for policy evaluation not found: '{p}'")

        content = p.read_text(encoding="utf-8", errors="replace")
        clean_target = clean_artifact_uri(p.as_posix(), repo_root=self.repo_root)

        # 1. Try parsing as JSON to detect Terraform plan
        try:
            parsed_json = json.loads(content)
            if isinstance(parsed_json, dict) and (
                "resource_changes" in parsed_json or "terraform_version" in parsed_json
            ):
                return self.evaluate_terraform_plan(parsed_json, target_file=clean_target, diff_text=diff_text)
        except Exception:
            pass

        # 2. Evaluate as Kubernetes / IaC manifest
        return self.evaluate_kubernetes_manifest(content, target_file=clean_target, diff_text=diff_text)

    def _evaluate_terraform_builtin(
        self,
        plan: dict[str, Any],
        target_file: str,
    ) -> list[dict[str, Any]]:
        """Pure-Python institutional evaluator for Terraform plan structures."""
        findings: list[dict[str, Any]] = []
        resource_changes = plan.get("resource_changes", [])
        if not isinstance(resource_changes, list):
            return []

        for rc in resource_changes:
            if not isinstance(rc, dict):
                continue
            res_type = rc.get("type", "unknown_type")
            res_address = rc.get("address", res_type)
            change = rc.get("change", {})
            actions = change.get("actions", [])
            after = change.get("after") or {}

            # Line lookup if file exists in workspace
            line_no = self._locate_resource_in_file(target_file, res_address)

            # Rule 01: Resource Deletion in Terraform Plan
            if "delete" in actions and "create" not in actions:
                f = self._build_finding(
                    rule_id=RULE_DESTRUCTIVE,
                    severity="critical",
                    resource=res_address,
                    fact=f"Resource '{res_address}' ({res_type}) is scheduled for deletion.",
                    recommendation=(
                        "Destructive deletions require human confirmation. "
                        "Configure lifecycle prevent_destroy guardrails."
                    ),
                    target_file=target_file,
                    line_start=line_no,
                    metadata={"actions": actions, "type": res_type},
                )
                findings.append(f)

            # Rule 01: Stateful Resource Forced Replacement (Delete + Create)
            if "delete" in actions and "create" in actions:
                is_stateful = any(res_type.startswith(p) for p in STATEFUL_RESOURCE_PREFIXES)
                if is_stateful:
                    f = self._build_finding(
                        rule_id=RULE_DESTRUCTIVE,
                        severity="critical",
                        resource=res_address,
                        fact=f"Stateful resource '{res_address}' ({res_type}) triggers forced replacement (destroy and recreate).",
                        recommendation=(
                            "Forced replacement will destroy existing persistent data. "
                            "Migrate resource in-place or isolate changes to non-destructive attributes."
                        ),
                        target_file=target_file,
                        line_start=line_no,
                        metadata={"actions": actions, "type": res_type, "forced_replacement": True},
                    )
                    findings.append(f)

            # Rule 01: force_destroy flag enabled
            if after.get("force_destroy") is True:
                f = self._build_finding(
                    rule_id=RULE_DESTRUCTIVE,
                    severity="critical",
                    resource=res_address,
                    fact=f"Resource '{res_address}' enables force_destroy.",
                    recommendation="Disable force_destroy to prevent catastrophic automated data loss on bucket or cluster deletion.",
                    target_file=target_file,
                    line_start=line_no,
                    metadata={"force_destroy": True},
                )
                findings.append(f)

            # Rule 04: S3 Bucket Missing Server-Side Encryption
            if res_type == "aws_s3_bucket":
                if not after.get("server_side_encryption_configuration"):
                    f = self._build_finding(
                        rule_id=RULE_WELL_ARCHITECTED,
                        severity="high",
                        resource=res_address,
                        fact=f"S3 bucket '{res_address}' is missing server-side encryption configuration.",
                        recommendation="Configure server_side_encryption_configuration with KMS (aws:kms) to enforce encryption at rest.",
                        target_file=target_file,
                        line_start=line_no,
                        metadata={"missing": "server_side_encryption_configuration"},
                    )
                    findings.append(f)

            # Rule 04: Relational Database Missing Multi-AZ
            if res_type in ("aws_db_instance", "aws_rds_cluster"):
                if after.get("multi_az") is not True:
                    f = self._build_finding(
                        rule_id=RULE_WELL_ARCHITECTED,
                        severity="high",
                        resource=res_address,
                        fact=f"Database '{res_address}' is not configured for Multi-AZ deployment (multi_az != true).",
                        recommendation="Set multi_az = true to satisfy high-availability and disaster recovery RTO/RPO requirements.",
                        target_file=target_file,
                        line_start=line_no,
                        metadata={"missing": "multi_az"},
                    )
                    findings.append(f)

        return findings

    def _evaluate_k8s_doc_builtin(
        self,
        doc: dict[str, Any],
        target_file: str,
    ) -> list[dict[str, Any]]:
        """Pure-Python institutional evaluator for Kubernetes manifest documents."""
        findings: list[dict[str, Any]] = []
        kind = doc.get("kind", "")
        if kind not in K8S_WORKLOAD_KINDS:
            return []

        metadata = doc.get("metadata", {})
        name = metadata.get("name", "unnamed")
        resource_id = f"{kind.lower()}/{name}"

        spec = doc.get("spec", {})
        template = spec.get("template", {}) if "template" in spec else doc
        pod_spec = template.get("spec", {})
        containers = pod_spec.get("containers", [])
        if not isinstance(containers, list):
            return []

        for c in containers:
            if not isinstance(c, dict):
                continue
            c_name = c.get("name", "container")
            sec_ctx = c.get("securityContext", {})
            resources = c.get("resources", {})
            limits = resources.get("limits", {})
            readiness = c.get("readinessProbe")

            line_no = self._locate_keyword_in_file(target_file, c_name)

            # Rule 04: Privileged container forbidden
            if sec_ctx.get("privileged") is True:
                f = self._build_finding(
                    rule_id=RULE_WELL_ARCHITECTED,
                    severity="critical",
                    resource=resource_id,
                    fact=f"Container '{c_name}' in {kind} '{name}' is configured as privileged (securityContext.privileged = true).",
                    recommendation="Set securityContext.privileged = false to prevent host filesystem breakout and node compromise.",
                    target_file=target_file,
                    line_start=line_no,
                    metadata={"container": c_name, "privileged": True},
                )
                findings.append(f)

            # Rule 04: Memory limits required for QoS and OOM protection
            if not limits.get("memory"):
                f = self._build_finding(
                    rule_id=RULE_WELL_ARCHITECTED,
                    severity="high",
                    resource=resource_id,
                    fact=f"Container '{c_name}' in {kind} '{name}' does not specify a memory limit (resources.limits.memory).",
                    recommendation="Specify resources.limits.memory matching requests.memory to guarantee QoS and avoid node OOM evictions.",
                    target_file=target_file,
                    line_start=line_no,
                    metadata={"container": c_name, "missing": "resources.limits.memory"},
                )
                findings.append(f)

            # Rule 04: Readiness probe required for zero-downtime routing
            if not readiness:
                f = self._build_finding(
                    rule_id=RULE_WELL_ARCHITECTED,
                    severity="medium",
                    resource=resource_id,
                    fact=f"Container '{c_name}' in {kind} '{name}' has no readinessProbe defined.",
                    recommendation="Add readinessProbe to ensure traffic is only routed after application initialization and healthy dependency checks.",
                    target_file=target_file,
                    line_start=line_no,
                    metadata={"container": c_name, "missing": "readinessProbe"},
                )
                findings.append(f)

        return findings

    def _build_finding(
        self,
        rule_id: str,
        severity: str,
        resource: str,
        fact: str,
        recommendation: str,
        target_file: str,
        line_start: int = 1,
        line_end: int = 1,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Constructs a finding conforming strictly to schemas/v1/finding.json."""
        if line_end > line_start:
            evidence = f"{self.evidence_scheme}:{target_file}#L{line_start}-L{line_end}"
        else:
            evidence = f"{self.evidence_scheme}:{target_file}#L{line_start}"

        fnd_id = compute_finding_id(
            rule_id=rule_id,
            resource=resource,
            evidence=evidence,
        )

        category = map_category(
            rule_id=rule_id,
            driver_name=self.default_agent,
        )

        full_meta: dict[str, Any] = {
            "policy_engine": "opa_rego",
            "evaluator": "builtin_rego_engine" if not self._opa_cli else "opa_cli",
        }
        if metadata:
            full_meta.update(metadata)

        return {
            "$schema": CANONICAL_SCHEMA_URI,
            "id": fnd_id,
            "agent": self.default_agent,
            "origin": "deterministic_linter",
            "rule_id": rule_id,
            "category": category,
            "resource": resource,
            "fact": fact.strip(),
            "evidence": evidence,
            "recommendation": recommendation.strip(),
            "severity": severity,
            "confidence": None,
            "corroboration_status": "tool_verified",
            "metadata": full_meta,
        }

    def _locate_resource_in_file(self, target_file: str, res_address: str) -> int:
        """Best-effort line locator for resource address within workspace file."""
        path = self.repo_root / target_file
        if not path.is_file():
            return 1
        try:
            tokens = res_address.split(".")
            simple_name = tokens[-1] if tokens else res_address
            with path.open("r", encoding="utf-8", errors="replace") as f:
                for idx, line in enumerate(f, start=1):
                    if simple_name in line:
                        return idx
        except Exception:
            pass
        return 1

    def _locate_keyword_in_file(self, target_file: str, keyword: str) -> int:
        """Best-effort line locator for container or key name in file."""
        path = self.repo_root / target_file
        if not path.is_file():
            return 1
        try:
            with path.open("r", encoding="utf-8", errors="replace") as f:
                for idx, line in enumerate(f, start=1):
                    if keyword in line:
                        return idx
        except Exception:
            pass
        return 1

    def _load_json(self, payload: Any) -> dict[str, Any]:
        if isinstance(payload, dict):
            return payload
        if isinstance(payload, Path) or (isinstance(payload, str) and not payload.strip().startswith("{")):
            p = Path(payload)
            if not p.is_file():
                raise FileNotFoundError(f"JSON input file not found: '{p}'")
            return json.loads(p.read_text(encoding="utf-8"))
        if isinstance(payload, str):
            return json.loads(payload)
        raise TypeError(f"Unsupported payload type: {type(payload).__name__}")

    def _load_manifest_docs(self, payload: Any) -> list[dict[str, Any]]:
        if isinstance(payload, dict):
            return [payload]
        if isinstance(payload, list):
            return [d for d in payload if isinstance(d, dict)]
        if isinstance(payload, Path) or (
            isinstance(payload, str) and not payload.strip().startswith(("{", "---", "apiVersion", "kind"))
        ):
            p = Path(payload)
            if not p.is_file():
                raise FileNotFoundError(f"Manifest input file not found: '{p}'")
            return parse_manifest_documents(p.read_text(encoding="utf-8", errors="replace"))
        if isinstance(payload, str):
            return parse_manifest_documents(payload)
        raise TypeError(f"Unsupported payload type: {type(payload).__name__}")


def evaluate_manifest(
    manifest: dict[str, Any] | list[dict[str, Any]] | str | Path,
    target_file: str = "k8s/deployment.yaml",
    diff_text: str | None = None,
    repo_root: Path | None = None,
) -> list[dict[str, Any]]:
    """Functional helper evaluating a Kubernetes manifest against institutional policies."""
    evaluator = OpaEvaluator(repo_root=repo_root)
    return evaluator.evaluate_kubernetes_manifest(manifest, target_file=target_file, diff_text=diff_text)


def evaluate_terraform_plan(
    plan: dict[str, Any] | str | Path,
    target_file: str = "infra/main.tf",
    diff_text: str | None = None,
    repo_root: Path | None = None,
) -> list[dict[str, Any]]:
    """Functional helper evaluating a Terraform plan against institutional policies."""
    evaluator = OpaEvaluator(repo_root=repo_root)
    return evaluator.evaluate_terraform_plan(plan, target_file=target_file, diff_text=diff_text)
